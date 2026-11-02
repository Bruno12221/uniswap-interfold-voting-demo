// SPDX-License-Identifier: LGPL-3.0-only
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { Wallet, keccak256, toBeHex, toUtf8Bytes } from 'ethers'
import { buildCensus } from '../src/census.mjs'
import { digest } from '../src/format.mjs'
import { makeRoundManifest, profile, assertInputCommitmentWindow } from '../src/round.mjs'
import { makeCoordinatorPolicy, assertCoordinatorPolicy } from '../src/coordinator-policy.mjs'
import { CoordinatorStore } from '../src/coordinator-store.mjs'
import { initializeCoordinator, syncCoordinator, replayCoordinator, mergeEvents, rebuildLedger } from '../src/coordinator.mjs'
import { queueOperatorTransaction, inspectOperatorTransaction } from '../src/coordinator-outbox.mjs'
import { abi, inputId, phaseAt, programInterface, protocolInterface } from '../src/coordinator-protocol.mjs'

const root = resolve(new URL('../', import.meta.url).pathname)
const template = JSON.parse(readFileSync(resolve(root, 'fixtures/t04-synthetic.json')))
const census = buildCensus(template.context, template.records)
const addr = n => toBeHex(n, 20), hash = n => toBeHex(n, 32)
const manifest = makeRoundManifest(census, census.manifestHash, { chainId: '31337', interfoldAddress: addr(1), programAddress: addr(2),
  registryAddress: addr(3), e3Id: '17', preset: 'insecure-512', paramsHash: profile.presets['insecure-512'].paramsHash,
  committeeKeyCommitment: hash(9), inputStart: '100', inputEnd: '200', artifactsHash: digest(JSON.parse(readFileSync(resolve(root, 'config/t05-artifacts.json')))) })
const contracts = Object.fromEntries(['protocol', 'program', 'contextRegistry', 'committeeRegistry', 'pkVerifier', 'decryptionVerifier',
  'receiptVerifier', 'halo2Verifier', 'dataAvailabilityVerifier'].map((name, i) => [name, { address: addr(i + 1), runtimeHash: hash(44), implementation: null }]))
const guest = { appExeCommit: hash(1), appVmCommit: hash(2) }
guest.imageId = keccak256(abi.encode(['bytes32', 'address', 'bytes32', 'bytes32'],
  [keccak256(toUtf8Bytes('INTERFOLD_OPENVM_RECEIPT_V1')), contracts.halo2Verifier.address, guest.appExeCommit, guest.appVmCommit]))
const policy = makeCoordinatorPolicy({ schemaVersion: 1, manifestHash: manifest.manifestHash, assurance: 'development',
  anchor: { number: '0', hash: hash(55) }, confirmations: 2, scanBatchSize: 100, contracts, guest,
  edges: [['program', 'interfold', 'protocol'], ['program', 'openVmVerifier', 'receiptVerifier'],
    ['program', 'dataAvailabilityVerifier', 'dataAvailabilityVerifier'], ['receiptVerifier', 'verifier', 'halo2Verifier'],
    ['decryptionVerifier', 'ciphernodeRegistry', 'committeeRegistry']].map(([from, getter, to]) => ({ from, getter, to })) }, manifest)
const config = { schemaVersion: 1, manifest, approvedManifestHash: manifest.manifestHash, census,
  approvedCensusHash: census.manifestHash, policy, approvedPolicyHash: policy.policyHash }
function database(t) {
  mkdirSync(resolve(root, '.local/tests'), { recursive: true })
  const directory = mkdtempSync(resolve(root, '.local/tests/t06-')), path = resolve(directory, 'state.db')
  const store = new CoordinatorStore(path)
  t.after(() => { try { store.close() } catch {} rmSync(directory, { recursive: true, force: true }) })
  return { store, path }
}

test('SQLite rolls back interrupted writes, releases crash locks and preserves committed state', async t => {
  const { store, path } = database(t)
  await initializeCoordinator(store, config)
  const before = store.get('state')
  const code = `import {CoordinatorStore} from ${JSON.stringify(new URL('../src/coordinator-store.mjs', import.meta.url).href)};
    const s=new CoordinatorStore(process.argv[1]);s.db.exec('BEGIN IMMEDIATE');s.put('state',{broken:true});process.kill(process.pid,'SIGKILL');`
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', code, path])
  assert.equal(child.signal, 'SIGKILL')
  assert.deepEqual(store.get('state'), before)
  await store.transaction(() => store.put('public-check', { ok: true }))
  const restarted = new CoordinatorStore(path)
  assert.deepEqual(restarted.get('public-check'), { ok: true }); restarted.close()
})

test('concurrent writers are refused and an exception rolls back the complete update', async t => {
  const { store, path } = database(t), other = new CoordinatorStore(path)
  try {
    await store.transaction(async () => {
      store.put('row', { before: true })
      await assert.rejects(other.transaction(() => other.put('row', { other: true })), /locked/)
    })
    await assert.rejects(store.transaction(() => { store.put('row', { after: true }); throw new Error('interrupted') }))
    assert.deepEqual(store.get('row'), { before: true })
  } finally { other.close() }
})

test('duplicate logs are idempotent, ordering is canonical and conflicting positions fail', () => {
  const a = { event: 'x', blockNumber: '7', logIndex: 2, transactionHash: hash(1) }
  const b = { event: 'y', blockNumber: '8', logIndex: 0, transactionHash: hash(2) }
  assert.deepEqual(mergeEvents([b], [a, b, a]), [a, b])
  assert.throws(() => mergeEvents([a], [{ ...a, transactionHash: hash(3) }]), /CONFLICTING_LOG/)
})

test('a published input must match its existing commitment exactly and never adds a new index', () => {
  const entry = { event: 'InputCommitted', index: '0', slot: census.eligible[0].address, commitment: hash(7),
    ciphertextHash: hash(8), parentIndexPlusOne: '0', transactionHash: hash(9) }
  entry.inputId = inputId(manifest, entry)
  const publication = { ...entry, event: 'InputPublished', availabilityBlock: '4', availabilityLeafIndex: '2' }
  assert.equal(rebuildLedger([entry], manifest, census).ledger[0].availability, null)
  assert.equal(rebuildLedger([entry, publication], manifest, census).ledger.length, 1)
  for (const events of [[publication], [entry, { ...publication, commitment: hash(10) }], [entry, entry],
    [{ ...entry, index: '1' }], [entry, publication, publication]]) assert.throws(() => rebuildLedger(events, manifest, census))
})

test('deadline boundaries preserve delayed availability through the inclusive compute deadline', () => {
  const phase = (now, pending = 0, stage = 3) => phaseAt(stage, now, 100, 150, 200, 300, 400, pending)
  assert.equal(phase(99), 'awaiting-input-window'); assert.equal(phase(100), 'voting-open')
  assert.equal(phase(149), 'voting-open'); assert.equal(phase(150), 'commitments-closed')
  assert.equal(phase(200, 1), 'awaiting-availability'); assert.equal(phase(300, 1), 'awaiting-availability')
  assert.equal(phase(301, 1), 'failed-availability-deadline'); assert.equal(phase(301), 'failed-compute-deadline')
  assert.equal(phase(200), 'computing'); assert.equal(phase(400, 0, 4), 'decrypting')
  assert.equal(phase(401, 0, 4), 'failed-decryption-deadline'); assert.equal(phase(401, 0, 6), 'failed-protocol')
  assert.equal(phase(401, 0, 5), 'checking-result')
})

test('policy approval binds deployment and guest; unreviewed secure policies cannot run', () => {
  assertCoordinatorPolicy(policy, policy.policyHash, manifest)
  const changed = structuredClone(policy); changed.contracts.program.runtimeHash = hash(99)
  assert.throws(() => assertCoordinatorPolicy(changed, policy.policyHash, manifest))
  const { policyHash, ...raw } = policy
  assert.throws(() => makeCoordinatorPolicy({ ...raw, guest: { ...raw.guest, appExeCommit: hash(9) } }, manifest), /WRONG_GUEST/)
  const secure = makeCoordinatorPolicy({ ...raw, assurance: 'secure-candidate' }, manifest)
  assert.throws(() => assertCoordinatorPolicy(secure, secure.policyHash, manifest), /SECURE_POLICY_NOT_REVIEWED/)
})

test('RPC outage clears an old result while preserving its durable cursor and ledger', async t => {
  const { store, path } = database(t); await initializeCoordinator(store, config)
  const before = store.get('state'); before.cursor = { number: '3', hash: hash(3) }; before.result = { totals: ['1', '0'] }
  store.put('state', before)
  const error = Object.assign(new Error('endpoint must not enter state'), { code: 'SERVER_ERROR' })
  const state = await syncCoordinator(store, { send: async () => '0x7a69', getBlock: async () => { throw error } })
  assert.equal(state.status, 'pending-rpc'); assert.equal(state.result, null); assert.deepEqual(state.cursor, before.cursor)
  assert(!JSON.stringify(state).includes('endpoint'))
  const restarted = new CoordinatorStore(path); assert.deepEqual(restarted.get('state'), state); restarted.close()
  await replayCoordinator(store); assert.equal(store.get('state').cursor, null)
})

test('outbox persists exact signed bytes, deduplicates operations and rejects wrong chain, round, transfer or nonce reuse', async t => {
  const { store } = database(t); await initializeCoordinator(store, config)
  const wallet = Wallet.createRandom()
  const data = programInterface.encodeFunctionData('finalizeInput', [17, census.eligible[0].address, hash(7), hash(8), 0, '0x11'])
  const sign = overrides => wallet.signTransaction({ chainId: 31337, to: manifest.programAddress, data, nonce: 0,
    gasLimit: 200000, gasPrice: 1000000000, ...overrides })
  const raw = await sign({}), job = await queueOperatorTransaction(store, raw)
  assert.equal((await queueOperatorTransaction(store, raw)).hash, job.hash)
  assert.equal(store.list('job:').length, 1); assert.equal(store.list('job:')[0][1].raw, raw)
  await assert.rejects(queueOperatorTransaction(store, await sign({ nonce: 1 })), /OPERATION_ALREADY_QUEUED/)
  const different = programInterface.encodeFunctionData('finalizeInput', [17, census.eligible[1].address, hash(7), hash(8), 0, '0x11'])
  await assert.rejects(queueOperatorTransaction(store, await sign({ data: different })), /NONCE_CONFLICT/)
  for (const rawBad of [await sign({ chainId: 1 }), await sign({ value: 1 }), await sign({ data: '0x' }),
    await sign({ data: programInterface.encodeFunctionData('finalizeInput', [18, census.eligible[0].address, hash(7), hash(8), 0, '0x11']) }),
    await sign({ data: data + '00' }),
    await sign({ to: manifest.interfoldAddress, data: protocolInterface.encodeFunctionData('publishPlaintextOutput', [17, '0x00', '0x11']) })])
    assert.throws(() => inspectOperatorTransaction(rawBad, config))
  await replayCoordinator(store); assert.equal(store.list('job:')[0][1].hash, job.hash)
})

test('ballot preparation uses the exclusive commitment cutoff at a concrete block', async () => {
  let now = 149
  const provider = { getBlock: async () => ({ timestamp: now, number: 7 }) }
  const program = { inputCommitmentDeadline: async (id, at) => { assert.equal(id, '17'); assert.deepEqual(at, { blockTag: 7 }); return 150n } }
  await assertInputCommitmentWindow(provider, manifest, program)
  now = 150; await assert.rejects(assertInputCommitmentWindow(provider, manifest, program), /commitment window/)
  now = 99; await assert.rejects(assertInputCommitmentWindow(provider, manifest, program), /commitment window/)
  const noTail = { inputCommitmentDeadline: async () => 200n }
  now = 199; await assertInputCommitmentWindow(provider, manifest, noTail)
  now = 200; await assert.rejects(assertInputCommitmentWindow(provider, manifest, noTail), /commitment window/)
})

test('unknown state versions cannot sync or reset themselves through replay', async t => {
  const { store } = database(t); await initializeCoordinator(store, config)
  const future = { ...store.get('state'), schemaVersion: 2 }; store.put('state', future)
  await assert.rejects(syncCoordinator(store, {}), /UNSUPPORTED_STATE_VERSION/)
  await assert.rejects(replayCoordinator(store), /UNSUPPORTED_STATE_VERSION/)
  assert.deepEqual(store.get('state'), future)
})
