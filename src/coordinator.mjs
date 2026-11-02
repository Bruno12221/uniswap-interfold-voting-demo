// SPDX-License-Identifier: LGPL-3.0-only
import { Contract, toBeHex } from 'ethers'
import { address, canonical, keys } from './format.mjs'
import { assertRoundManifest, readBoundRound } from './round.mjs'
import { transcriptRoot } from './transcript.mjs'
import { assertCoordinatorPolicy, verifyDeployment } from './coordinator-policy.mjs'
import { assertProofBundle, verifyRoundProofs } from './coordinator-proofs.mjs'
import { PROGRAM_ABI, PROTOCOL_ABI, EVENT_TOPICS, SCHEME, normalizeLog, inputId, phaseAt,
  requireThat, CoordinationError, isRpcError } from './coordinator-protocol.mjs'

const initial = config => ({ schemaVersion: 1, manifestHash: config.manifest.manifestHash, policyHash: config.policy.policyHash,
  cursor: null, events: [], status: 'initialized', reason: null, counts: null, result: null })

export function validateCoordinatorConfig(config) {
  keys(config, ['schemaVersion', 'manifest', 'approvedManifestHash', 'census', 'approvedCensusHash', 'policy', 'approvedPolicyHash'])
  requireThat(config.schemaVersion === 1, 'UNSUPPORTED_STATE_VERSION')
  assertRoundManifest(config.manifest, config.approvedManifestHash, config.census, config.approvedCensusHash)
  assertCoordinatorPolicy(config.policy, config.approvedPolicyHash, config.manifest)
  return config
}

export function readCoordinatorState(store, config) {
  const state = store.get('state')
  requireThat(state?.schemaVersion === 1 && state.manifestHash === config.manifest.manifestHash &&
    state.policyHash === config.policy.policyHash && Array.isArray(state.events), 'UNSUPPORTED_STATE_VERSION')
  return state
}

export async function initializeCoordinator(store, config) {
  validateCoordinatorConfig(config)
  await store.transaction(() => {
    requireThat(store.get('config') === undefined, 'ROUND_ALREADY_INITIALIZED')
    store.put('config', config); store.put('state', initial(config))
  })
}

export function mergeEvents(existing, incoming) {
  const events = new Map()
  for (const event of [...existing, ...incoming]) {
    const key = event.blockNumber + ':' + event.logIndex
    requireThat(!events.has(key) || canonical(events.get(key)) === canonical(event), 'CONFLICTING_LOG')
    events.set(key, event)
  }
  return [...events.values()].sort((a, b) => Number(BigInt(a.blockNumber) - BigInt(b.blockNumber)) || a.logIndex - b.logIndex)
}

export function rebuildLedger(events, manifest, census) {
  const ledger = [], ids = new Set()
  let output = null, plaintext = null
  const tuple = e => canonical([e.index, e.slot, e.commitment, e.ciphertextHash, e.parentIndexPlusOne])
  for (const event of events) {
    if (event.event === 'InputCommitted') {
      requireThat(!output && event.index === String(ledger.length) && !ids.has(event.inputId) &&
        event.inputId === inputId(manifest, event) && census.eligible.some(x => x.address === event.slot), 'INVALID_COMMITMENT_LEDGER')
      ids.add(event.inputId)
      ledger.push({ index: event.index, slot: event.slot, commitment: event.commitment, ciphertextHash: event.ciphertextHash,
        parentIndexPlusOne: event.parentIndexPlusOne, transactionHash: event.transactionHash, availability: null })
    } else if (event.event === 'InputPublished') {
      const entry = ledger[Number(event.index)]
      requireThat(entry && !entry.availability && !output && tuple(entry) === tuple(event), 'UNMATCHED_AVAILABILITY')
      entry.availability = { block: event.availabilityBlock, leafIndex: event.availabilityLeafIndex, transactionHash: event.transactionHash }
    } else if (event.event === 'CiphertextOutputReferencePublished') {
      requireThat(!output && ledger.every(x => x.availability), 'INVALID_OUTPUT_ORDER')
      output = event
    } else if (event.event === 'PlaintextOutputPublished') {
      requireThat(output && !plaintext, 'INVALID_PLAINTEXT_ORDER')
      plaintext = event
    } else throw new CoordinationError('UNKNOWN_PERSISTED_EVENT')
  }
  requireThat(ledger.length <= Number(manifest.hardAdmissionLimit), 'ADMISSION_LIMIT_EXCEEDED')
  return { ledger, output, plaintext }
}

export async function importProofBundle(store, bundle) {
  const config = validateCoordinatorConfig(store.get('config'))
  assertProofBundle(bundle, config.manifest, config.policy)
  await store.transaction(() => {
    const state = readCoordinatorState(store, config)
    store.put('proof-bundle', bundle)
    state.result = null
    if (state.status !== 'replay-required') state.status = 'proof-bundle-imported'
    store.put('state', state)
  })
}

export async function replayCoordinator(store) {
  await store.transaction(() => {
    const config = validateCoordinatorConfig(store.get('config'))
    readCoordinatorState(store, config)
    store.put('state', initial(config))
  })
}

async function confirmedLogs(provider, manifest, fromBlock, toBlock) {
  const logs = await provider.getLogs({ address: [...new Set([manifest.programAddress, manifest.interfoldAddress])],
    topics: [EVENT_TOPICS, toBeHex(BigInt(manifest.e3Id), 32)], fromBlock, toBlock })
  const receipts = new Map(), blocks = new Map()
  const normalized = []
  for (const log of logs) {
    requireThat(log.blockNumber >= fromBlock && log.blockNumber <= toBlock, 'LOG_OUTSIDE_SCAN')
    if (!receipts.has(log.transactionHash)) receipts.set(log.transactionHash, await provider.getTransactionReceipt(log.transactionHash))
    if (!blocks.has(log.blockNumber)) blocks.set(log.blockNumber, await provider.getBlock(log.blockNumber))
    const receipt = receipts.get(log.transactionHash), block = blocks.get(log.blockNumber)
    requireThat(receipt?.status === 1 && block && receipt.blockHash === block.hash && log.blockHash === block.hash &&
      receipt.logs.some(x => x.index === log.index && x.address.toLowerCase() === log.address.toLowerCase() &&
        x.data === log.data && canonical(x.topics) === canonical(log.topics)), 'NONCANONICAL_LOG')
    normalized.push(normalizeLog(log, manifest))
  }
  return normalized
}

export async function syncCoordinator(store, provider) {
  return store.transaction(async () => {
    const config = validateCoordinatorConfig(store.get('config')), old = readCoordinatorState(store, config)
    const { manifest, census, policy } = config
    const next = structuredClone(old); next.result = null; next.reason = null
    try {
      requireThat(BigInt(await provider.send('eth_chainId', [])) === BigInt(manifest.chainId), 'WRONG_APPLICATION_CHAIN')
      const anchor = await provider.getBlock(Number(policy.anchor.number))
      requireThat(anchor?.hash === policy.anchor.hash, 'ANCHOR_REORG')
      if (old.cursor) requireThat((await provider.getBlock(Number(old.cursor.number)))?.hash === old.cursor.hash, 'CURSOR_REORG')
      if (old.status === 'replay-required') throw new CoordinationError('REPLAY_REQUIRED')
      const head = await provider.getBlockNumber(), confirmed = head - policy.confirmations + 1
      const from = old.cursor ? Number(old.cursor.number) + 1 : Number(policy.anchor.number)
      if (confirmed < Number(policy.anchor.number)) { next.status = 'awaiting-confirmations'; store.put('state', next); return next }
      const target = Math.min(confirmed, from + policy.scanBatchSize - 1)
      requireThat(!old.cursor || confirmed >= Number(old.cursor.number), 'CURSOR_REORG')
      const block = await provider.getBlock(target)
      requireThat(block, 'MISSING_CONFIRMED_BLOCK')
      const incoming = target >= from ? await confirmedLogs(provider, manifest, from, target) : []
      const events = mergeEvents(old.events, incoming)
      const { ledger, output, plaintext } = rebuildLedger(events, manifest, census)
      if (target < confirmed) {
        requireThat((await provider.getBlock(target))?.hash === block.hash, 'CURSOR_REORG')
        next.status = 'catching-up'; next.cursor = { number: String(target), hash: block.hash }; next.events = events
        next.lastCheckedAt = new Date().toISOString(); store.put('state', next); return next
      }
      const snapshot = await readBoundRound(provider, manifest, undefined, { blockTag: target })
      snapshot.census = census
      // Despite its name, this release stores an EIP-6372 timestamp in requestBlock.
      requireThat(BigInt(anchor.timestamp) <= snapshot.e3.requestBlock, 'ANCHOR_AFTER_REQUEST')
      requireThat(snapshot.e3.encryptionSchemeId === SCHEME && address(snapshot.e3.pkVerifier) === policy.contracts.pkVerifier.address &&
        address(snapshot.e3.decryptionVerifier) === policy.contracts.decryptionVerifier.address, 'WRONG_ENCRYPTION_CONTEXT')
      await verifyDeployment(provider, policy, target)
      const program = new Contract(manifest.programAddress, PROGRAM_ABI, provider)
      const protocol = new Contract(manifest.interfoldAddress, PROTOCOL_ABI, provider)
      const at = { blockTag: target }
      const pending = await program.pendingInputCount(manifest.e3Id, at)
      requireThat(ledger.length === Number(snapshot.round.numberOfVotes) &&
        transcriptRoot(ledger) === snapshot.round.inputRoot.toString() && BigInt(ledger.filter(x => !x.availability).length) === pending, 'INCOMPLETE_CHAIN_LEDGER')
      const stage = Number(await protocol.getE3Stage(manifest.e3Id, at)), deadlines = await protocol.getDeadlines(manifest.e3Id, at)
      const commitmentDeadline = await program.inputCommitmentDeadline(manifest.e3Id, at)
      requireThat(BigInt(manifest.inputStart) < commitmentDeadline && commitmentDeadline <= BigInt(manifest.inputEnd) &&
        deadlines.computeDeadline >= BigInt(manifest.inputEnd), 'INVALID_PROTOCOL_DEADLINES')
      next.status = phaseAt(stage, block.timestamp, manifest.inputStart, commitmentDeadline, manifest.inputEnd, deadlines.computeDeadline, deadlines.decryptionDeadline, Number(pending))
      next.counts = { committed: ledger.length, available: ledger.filter(x => x.availability).length,
        missingCiphertexts: ledger.filter(x => !store.getCiphertext(x.ciphertextHash)).length }
      if (next.status === 'checking-result') {
        requireThat(pending === 0n && output && plaintext, 'MISSING_RESULT_EVIDENCE')
        const bundle = store.get('proof-bundle')
        if (!bundle) next.status = 'awaiting-proof-bundle'
        else if (next.counts.missingCiphertexts) next.status = 'awaiting-ciphertexts'
        else {
          next.result = await verifyRoundProofs({ provider, manifest, policy, bundle, ledger, output, plaintext, snapshot,
            getCiphertext: hash => store.getCiphertext(hash), blockTag: target })
          next.status = policy.assurance === 'development' ? 'development-complete' : 'verified'
        }
      }
      requireThat((await provider.getBlock(target))?.hash === block.hash, 'CURSOR_REORG')
      next.cursor = { number: String(target), hash: block.hash }; next.events = events
    } catch (error) {
      // Keep the last committed cursor on every failed scan. Never retain a previous result.
      next.cursor = old.cursor; next.events = old.events; next.counts = old.counts; next.result = null
      next.reason = error instanceof CoordinationError ? error.code : isRpcError(error) ? 'RPC_UNAVAILABLE' : 'CHECK_FAILED'
      next.status = ['CURSOR_REORG', 'ANCHOR_REORG', 'REPLAY_REQUIRED'].includes(next.reason) ? 'replay-required' :
        next.reason === 'RPC_UNAVAILABLE' ? 'pending-rpc' : 'blocked-check'
    }
    next.lastCheckedAt = new Date().toISOString()
    store.put('state', next)
    return next
  })
}
