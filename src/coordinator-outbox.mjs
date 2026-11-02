// SPDX-License-Identifier: LGPL-3.0-only
import { Contract, Transaction } from 'ethers'
import { address, digest } from './format.mjs'
import { decodeAggregate } from './transcript.mjs'
import { validateCoordinatorConfig, readCoordinatorState } from './coordinator.mjs'
import { verifyDeployment } from './coordinator-policy.mjs'
import { PROGRAM_ABI, PROTOCOL_ABI, programInterface, protocolInterface, abi, requireThat, CoordinationError, isRpcError } from './coordinator-protocol.mjs'

export function inspectOperatorTransaction(raw, config) {
  const { manifest } = config
  const tx = Transaction.from(raw)
  requireThat(tx.isSigned() && tx.chainId === 31337n && tx.value === 0n && tx.to && tx.from, 'UNSUPPORTED_OPERATOR_TRANSACTION')
  const target = address(tx.to)
  let call
  if (target === manifest.programAddress) {
    try { call = programInterface.parseTransaction({ data: tx.data }) } catch {}
  }
  if (!call && target === manifest.interfoldAddress) {
    try { call = protocolInterface.parseTransaction({ data: tx.data }) } catch {}
  }
  requireThat(call && ['finalizeInput', 'publishCiphertextOutput', 'publishPlaintextOutput'].includes(call.name) &&
    call.args[0].toString() === manifest.e3Id, 'WRONG_OPERATOR_CALL')
  const iface = call.name === 'finalizeInput' ? programInterface : protocolInterface
  requireThat(iface.encodeFunctionData(call.fragment, call.args) === tx.data, 'NONCANONICAL_OPERATOR_CALL')
  let identity
  if (call.name === 'finalizeInput') identity = [...call.args].slice(0, 5).map(String)
  if (call.name === 'publishCiphertextOutput') {
    const [ref] = abi.decode(['tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes computeProof,bytes availabilityProof)'], call.args[1])
    const [, params] = abi.decode(['bytes', 'bytes32', 'bytes32'], ref.computeProof)
    requireThat(params === manifest.paramsHash && ref.availabilityProof !== '0x', 'WRONG_COMPUTE_TRANSACTION')
    // One ciphertext publication per round, independent of nonce or claimed hash.
    identity = [manifest.e3Id]
  }
  if (call.name === 'publishPlaintextOutput') {
    decodeAggregate(call.args[1], manifest.choices.length, Number(manifest.maxEffectiveTotal))
    requireThat(call.args[2] !== '0x', 'MISSING_DECRYPTION_PROOF')
    identity = [manifest.e3Id]
  }
  const operationId = digest({ manifestHash: manifest.manifestHash, method: call.name, identity })
  return { hash: tx.hash, raw: tx.serialized, from: address(tx.from), nonce: tx.nonce, method: call.name, operationId }
}

export async function queueOperatorTransaction(store, raw) {
  return store.transaction(() => {
    const config = validateCoordinatorConfig(store.get('config'))
    readCoordinatorState(store, config)
    const tx = inspectOperatorTransaction(raw, config), name = 'job:' + tx.operationId
    const existing = store.get(name)
    requireThat(!existing || existing.hash === tx.hash, 'OPERATION_ALREADY_QUEUED')
    for (const [, job] of store.list('job:')) requireThat(job.hash === tx.hash || job.from !== tx.from || job.nonce !== tx.nonce, 'OPERATOR_NONCE_CONFLICT')
    if (existing) return existing
    const job = { schemaVersion: 1, manifestHash: config.manifest.manifestHash, ...tx, attempts: 0, status: 'queued', reason: null }
    store.put(name, job); return job
  })
}

async function sendWindow(provider, config, method) {
  const { manifest, policy } = config, block = await provider.getBlock('latest'), at = { blockTag: block.number }
  requireThat(BigInt(await provider.send('eth_chainId', [])) === 31337n, 'WRONG_OPERATOR_CHAIN')
  await verifyDeployment(provider, policy, block.number)
  const registry = new Contract(manifest.registryAddress, ['function getManifestHash(address,address,uint256) view returns (bytes32)'], provider)
  requireThat(await registry.getManifestHash(manifest.interfoldAddress, manifest.programAddress, manifest.e3Id, at) === manifest.manifestHash, 'UNFROZEN_OPERATOR_CONTEXT')
  const program = new Contract(manifest.programAddress, PROGRAM_ABI, provider)
  const protocol = new Contract(manifest.interfoldAddress, PROTOCOL_ABI, provider)
  const stage = Number(await protocol.getE3Stage(manifest.e3Id, at)), deadlines = await protocol.getDeadlines(manifest.e3Id, at)
  if (method === 'publishPlaintextOutput') {
    requireThat(stage === 4 && BigInt(block.timestamp) <= deadlines.decryptionDeadline, 'DECRYPTION_SEND_WINDOW_CLOSED')
  } else {
    requireThat(stage === 3 && BigInt(block.timestamp) <= deadlines.computeDeadline &&
      BigInt(block.timestamp) >= BigInt(manifest.inputStart), 'COMPUTE_SEND_WINDOW_CLOSED')
    if (method === 'publishCiphertextOutput') requireThat(BigInt(block.timestamp) >= BigInt(manifest.inputEnd) &&
      await program.pendingInputCount(manifest.e3Id, at) === 0n, 'COMPUTE_NOT_READY')
  }
}

export async function pumpOperatorTransactions(store, provider) {
  const config = validateCoordinatorConfig(store.get('config')), results = []
  readCoordinatorState(store, config)
  for (const [name, saved] of store.list('job:')) {
    const inspected = inspectOperatorTransaction(saved.raw, config)
    requireThat(saved.schemaVersion === 1 && saved.manifestHash === config.manifest.manifestHash && saved.hash === inspected.hash &&
      saved.operationId === inspected.operationId && name === 'job:' + inspected.operationId && saved.nonce === inspected.nonce &&
      saved.from === inspected.from && saved.method === inspected.method, 'OUTBOX_RECORD_CHANGED')
    let job = { ...saved, reason: null }
    try {
      const receipt = await provider.getTransactionReceipt(job.hash)
      if (receipt) {
        const block = await provider.getBlock(receipt.blockNumber)
        requireThat(block?.hash === receipt.blockHash, 'TRANSACTION_REORG')
        const head = await provider.getBlockNumber()
        job.status = head - receipt.blockNumber + 1 < config.policy.confirmations ? 'confirming' : receipt.status === 1 ? 'confirmed' : 'reverted'
      } else {
        requireThat(BigInt(await provider.getTransactionCount(job.from, 'latest')) <= BigInt(job.nonce), 'NONCE_USED_BY_UNKNOWN_TRANSACTION')
        await sendWindow(provider, config, job.method)
        const transaction = Transaction.from(job.raw)
        try { await provider.call({ to: transaction.to, from: job.from, data: transaction.data, value: 0n }) }
        catch (error) { if (isRpcError(error)) throw error; throw new CoordinationError('OPERATOR_PREFLIGHT_REJECTED') }
        // Commit the exact signed public bytes/hash before the network side effect.
        await store.transaction(() => {
          const current = store.get(name)
          requireThat(current.attempts < 5, 'RETRY_LIMIT')
          job.attempts = current.attempts + 1; job.status = 'broadcasting'
          store.put(name, job)
        })
        const sent = await provider.broadcastTransaction(job.raw)
        requireThat(sent.hash === job.hash, 'BROADCAST_HASH_MISMATCH')
        job.status = 'submitted'
      }
    } catch (error) {
      job.reason = error instanceof CoordinationError ? error.code : isRpcError(error) ? 'RPC_UNAVAILABLE' : 'BROADCAST_UNCERTAIN'
      job.status = job.reason === 'RPC_UNAVAILABLE' || job.reason === 'BROADCAST_UNCERTAIN' ? 'pending-rpc' : 'needs-attention'
    }
    await store.transaction(() => { job.attempts = Math.max(job.attempts, store.get(name).attempts); store.put(name, job) })
    results.push({ hash: job.hash, status: job.status, reason: job.reason, attempts: job.attempts })
  }
  return results
}
