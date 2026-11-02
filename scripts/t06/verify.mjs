// SPDX-License-Identifier: LGPL-3.0-only
// Local orchestration exercise. Cryptographic committee/DA/threshold proofs are explicit fixtures.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs'
import { spawn, execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import net from 'node:net'
import { ContractFactory, JsonRpcProvider, Wallet, hexlify, keccak256, sha256, toBeHex, parseEther } from 'ethers'
import { ROOT, loadProofRuntime, checkLockedArtifacts } from '../../src/upstream.mjs'
import { buildCensus } from '../../src/census.mjs'
import { address } from '../../src/format.mjs'
import { makeRoundManifest, profile } from '../../src/round.mjs'
import { makeCoordinatorPolicy } from '../../src/coordinator-policy.mjs'
import { CoordinatorStore } from '../../src/coordinator-store.mjs'
import { initializeCoordinator, syncCoordinator, importProofBundle, replayCoordinator } from '../../src/coordinator.mjs'
import { queueOperatorTransaction, pumpOperatorTransactions } from '../../src/coordinator-outbox.mjs'
import { abi, computeJournal, decryptionDomain, programInterface, protocolInterface } from '../../src/coordinator-protocol.mjs'
import { prepareBoundBallot } from '../../src/ballot.mjs'
import { compileComponents, linkedBytecode, ensurePoseidon } from '../t05/compile.mjs'

const run = resolve(ROOT, '.local/runs/t06-' + new Date().toISOString().replace(/[-:.]/g, ''))
mkdirSync(run, { recursive: true })
const report = { schemaVersion: 1, task: 'T06', sourceRevision: profile.sourceRevision,
  scope: 'Local coordinator on a real EVM with native ciphertexts and original OpenVM receipt adapter. Admissions, Halo2, committee, DA and decryption proofs are explicit mutable fixtures.', checks: [] }
let child, provider, runtime, store, fd
async function cleanup() {
  store?.close(); store = undefined; runtime?.sdk.destroyBBApi(); provider?.destroy()
  if (child && child.exitCode === null) {
    child.kill('SIGTERM'); await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(5000)])
    if (child.exitCode === null) child.kill('SIGKILL')
  }
  if (fd !== undefined) { closeSync(fd); fd = undefined }
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void cleanup().finally(() => process.exit(130)) })
const rpcError = () => Object.assign(new Error('simulated transport outage'), { code: 'SERVER_ERROR' })
function wrap(overrides) {
  return new Proxy(provider, { get(target, property) {
    if (property in overrides) return overrides[property]
    const value = Reflect.get(target, property, target); return typeof value === 'function' ? value.bind(target) : value
  } })
}

async function main() {
  console.log('T06 ignored run directory: ' + run)
  await new Promise((resolve, reject) => { const s = net.createServer(); s.once('error', reject); s.listen(18546, '127.0.0.1', () => s.close(resolve)) })
  const compiled = compileComponents(['contracts/FrozenRoundRegistry.sol', 'tests/contracts/T06Fixture.sol'])
  fd = openSync(resolve(run, 'anvil.log'), 'w')
  child = spawn('anvil', ['--host', '127.0.0.1', '--port', '18546', '--chain-id', '31337', '--silent'], { stdio: ['ignore', fd, fd] })
  writeFileSync(resolve(run, 'process.json'), JSON.stringify({ ownedAnvilPid: child.pid }) + '\n')
  provider = new JsonRpcProvider('http://127.0.0.1:18546', 31337, { staticNetwork: true, cacheTimeout: -1, batchMaxCount: 1 })
  let ready = false
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error('Owned Anvil exited')
    try { ready = await provider.send('eth_chainId', []) === '0x7a69' } catch {}
    if (ready) break; await delay(100)
  }
  assert(ready)
  const publisher = await provider.getSigner(0), other = await provider.getSigner(1)
  const operator = Wallet.createRandom().connect(provider)
  await (await publisher.sendTransaction({ to: operator.address, value: parseEther('1') })).wait()
  async function deploy(artifact, args = [], libraries = {}) {
    const c = await new ContractFactory(artifact.abi, linkedBytecode(artifact, libraries), publisher).deploy(...args)
    await c.waitForDeployment(); return c
  }
  const poseidon = await ensurePoseidon(provider, publisher)
  const fixtures = compiled['tests/contracts/T06Fixture.sol']
  const fixture = await deploy(fixtures.T06Fixture, [], { 'poseidon-solidity/PoseidonT3.sol:PoseidonT3': poseidon })
  const frozen = await deploy(compiled['contracts/FrozenRoundRegistry.sol'].FrozenRoundRegistry, [await publisher.getAddress()])
  const halo = await deploy(fixtures.T06Halo2Fixture)
  const receipt = await deploy(compiled['.local/upstream/interfold/packages/interfold-contracts/contracts/verifiers/OpenVmReceiptVerifier.sol'].OpenVmReceiptVerifier,
    [await halo.getAddress(), toBeHex(1n, 32), toBeHex(2n, 32)])
  const nodes = [await publisher.getAddress(), await other.getAddress()]
  const committee = await deploy(fixtures.T06CommitteeFixture, [nodes])
  const pk = await deploy(fixtures.T06ProofFixture, [await committee.getAddress()])
  const decrypt = await deploy(fixtures.T06ProofFixture, [await committee.getAddress()])
  const da = await deploy(fixtures.T06AvailabilityFixture)
  runtime = await loadProofRuntime('insecure-512')
  const { publicKey, secretKey } = runtime.sdk.generateBFVKeys()
  const key = hexlify(runtime.core.compute_pk_commitment(publicKey, runtime.params.degree, runtime.params.plaintextModulus, BigUint64Array.from(runtime.params.moduli)))
  const template = JSON.parse(readFileSync(resolve(ROOT, 'fixtures/t04-synthetic.json')))
  template.context.choices.push('Synthetic option C')
  const census = buildCensus(template.context, template.records), now = await provider.getBlock('latest')
  const manifest = makeRoundManifest(census, census.manifestHash, { chainId: '31337', interfoldAddress: address(await fixture.getAddress()),
    programAddress: address(await fixture.getAddress()), registryAddress: address(await frozen.getAddress()), e3Id: '17', preset: 'insecure-512',
    paramsHash: profile.presets['insecure-512'].paramsHash, committeeKeyCommitment: key, inputStart: String(now.timestamp),
    inputEnd: String(now.timestamp + 180), artifactsHash: await checkLockedArtifacts() })
  runtime = await loadProofRuntime('insecure-512')
  await (await fixture.configure(census.root, manifest.paramsHash, 3, key, 0, manifest.inputStart, manifest.inputEnd)).wait()
  const setup = await (await fixture.configureCoordinator(await receipt.getAddress(), await da.getAddress(), await committee.getAddress(),
    await pk.getAddress(), await decrypt.getAddress(), BigInt(manifest.inputEnd) - 60n, BigInt(manifest.inputEnd) + 600n)).wait()
  await (await frozen.freeze({ interfold: manifest.interfoldAddress, program: manifest.programAddress, e3Id: 17,
    manifestHash: manifest.manifestHash, censusRoot: census.root, paramsHash: manifest.paramsHash, committeeKey: key, numOptions: 3 })).wait()
  const contracts = {}
  for (const [role, contract] of Object.entries({ protocol: fixture, program: fixture, contextRegistry: frozen, committeeRegistry: committee,
    pkVerifier: pk, decryptionVerifier: decrypt, receiptVerifier: receipt, halo2Verifier: halo, dataAvailabilityVerifier: da })) {
    const a = address(await contract.getAddress()); contracts[role] = { address: a, runtimeHash: keccak256(await provider.getCode(a)), implementation: null }
  }
  contracts.poseidon = { address: address(poseidon), runtimeHash: keccak256(await provider.getCode(poseidon)), implementation: null }
  const anchor = await provider.getBlock(setup.blockNumber)
  const policy = makeCoordinatorPolicy({ schemaVersion: 1, manifestHash: manifest.manifestHash, assurance: 'development',
    anchor: { number: String(anchor.number), hash: anchor.hash }, confirmations: 2, scanBatchSize: 100, contracts,
    guest: { imageId: await receipt.imageId(), appExeCommit: await receipt.appExeCommit(), appVmCommit: await receipt.appVmCommit() },
    edges: [['program', 'interfold', 'protocol'], ['program', 'openVmVerifier', 'receiptVerifier'],
      ['program', 'dataAvailabilityVerifier', 'dataAvailabilityVerifier'], ['receiptVerifier', 'verifier', 'halo2Verifier'],
      ['decryptionVerifier', 'ciphernodeRegistry', 'committeeRegistry']].map(([from, getter, to]) => ({ from, getter, to })) }, manifest)
  const config = { schemaVersion: 1, manifest, approvedManifestHash: manifest.manifestHash, census, approvedCensusHash: census.manifestHash,
    policy, approvedPolicyHash: policy.policyHash }
  writeFileSync(resolve(run, 'config.json'), JSON.stringify(config, null, 2) + '\n')
  const path = resolve(run, 'state.db'); store = new CoordinatorStore(path)
  await initializeCoordinator(store, config)
  const mine = () => provider.send('evm_mine', [])
  await mine()
  let state = await syncCoordinator(store, provider)
  assert.equal(state.status, 'voting-open', JSON.stringify(state))
  const entries = []
  for (const [index, vote] of [[0, [1, 0, 0]], [1, [0, 1, 0]]]) {
    const bytes = runtime.sdk.encryptVote(vote, publicKey)
    const entry = { index: String(index), slot: census.eligible[index].address, ciphertextHash: keccak256(bytes),
      commitment: hexlify(runtime.generator.computeCtCommitment(bytes)), parentIndexPlusOne: '0', bytes }
    entries.push(entry)
    await (await fixture.commitInput(17, entry.slot, entry.commitment, entry.ciphertextHash, 0)).wait()
    if (index === 0) { store.putCiphertext(bytes); await mine() }
  }
  state = await syncCoordinator(store, provider)
  assert.equal(state.counts.committed, 1, 'Unconfirmed input must remain excluded')
  report.checks.push('confirmation depth excludes an unconfirmed commitment')
  await mine()
  const before = store.get('state')
  const omitted = wrap({ getLogs: async filter => (await provider.getLogs(filter)).slice(1) })
  state = await syncCoordinator(store, omitted)
  assert.equal(state.reason, 'INCOMPLETE_CHAIN_LEDGER'); assert.deepEqual(state.cursor, before.cursor)
  const repeated = wrap({ getLogs: async filter => { const logs = await provider.getLogs(filter); return [...logs].reverse().concat(logs) } })
  state = await syncCoordinator(store, repeated)
  assert.equal(state.counts.committed, 2); assert.equal(state.counts.available, 0); assert.equal(state.counts.missingCiphertexts, 1)
  report.checks.push('omitted commitment blocks cursor advancement', 'duplicate and reordered RPC logs rebuild the same complete ledger')

  await provider.send('evm_setNextBlockTimestamp', [Number(manifest.inputEnd) - 30]); await mine(); await mine()
  await assert.rejects(prepareBoundBallot({ provider, manifest, approvedHash: manifest.manifestHash, census,
    approvedCensusHash: census.manifestHash, publicKey, slot: census.eligible[0].address, vote: [1, 0, 0] }), /Input commitment window/)
  report.checks.push('client refuses preparation during the reserved availability tail')
  await provider.send('evm_setNextBlockTimestamp', [Number(manifest.inputEnd) + 10]); await mine(); await mine()
  state = await syncCoordinator(store, provider); assert.equal(state.status, 'awaiting-availability')
  const availability = (hash, block, leaf) => abi.encode(['tuple(bytes32 contentHash,uint32 blockNumber,uint128 leafIndex)'], [[hash, block, leaf]])
  let nonce = await provider.getTransactionCount(operator.address)
  const sign = data => operator.signTransaction({ type: 2, chainId: 31337, to: manifest.programAddress, value: 0,
    data, nonce: nonce++, gasLimit: 5000000, maxFeePerGas: 2000000000n, maxPriorityFeePerGas: 1000000000n })
  for (const entry of entries) {
    entry.availabilityProof = availability(entry.ciphertextHash, 100 + Number(entry.index), 2)
    const data = programInterface.encodeFunctionData('finalizeInput', [17, entry.slot, entry.commitment, entry.ciphertextHash, 0, entry.availabilityProof])
    await queueOperatorTransaction(store, await sign(data))
  }
  let dropResponse = true
  const uncertain = wrap({ broadcastTransaction: async raw => {
    const sent = await provider.broadcastTransaction(raw)
    if (dropResponse) { dropResponse = false; throw rpcError() }
    return sent
  } })
  const jobs = await pumpOperatorTransactions(store, uncertain)
  assert(jobs.some(x => x.status === 'pending-rpc'))
  const sentNonce = await provider.getTransactionCount(operator.address)
  store.close(); store = new CoordinatorStore(path); await mine()
  assert((await pumpOperatorTransactions(store, provider)).every(x => x.status === 'confirmed'))
  assert.equal(await provider.getTransactionCount(operator.address), sentNonce)
  state = await syncCoordinator(store, provider)
  assert.equal(state.counts.available, 2); assert.equal(state.status, 'computing')
  report.checks.push('delayed availability recovers after input end before compute deadline',
    'restart after accepted transaction and lost RPC response recovers by exact hash without another nonce')

  const rejectedData = programInterface.encodeFunctionData('finalizeInput', [17, census.eligible[2].address, toBeHex(7, 32),
    toBeHex(8, 32), 0, availability(toBeHex(8, 32), 1, 1)])
  const rejectedRaw = await sign(rejectedData)
  const rejectedJob = await queueOperatorTransaction(store, rejectedRaw)
  // Simulate a crash after broadcast: the durable row still says queued when the reverted receipt arrives.
  await provider.broadcastTransaction(rejectedRaw); await mine()
  assert.equal((await pumpOperatorTransactions(store, provider)).find(x => x.hash === rejectedJob.hash).status, 'reverted')
  report.checks.push('reverted transaction is recovered as reverted, never as completed work')

  const output = runtime.generator.generateInputs(entries[0].bytes, publicKey, BigInt64Array.from([0n, 1n, 0n]), true).encryptedVote
  const decrypted = Array.from(runtime.generator.decryptVote(secretKey, output), BigInt)
  assert.deepEqual(decrypted.slice(0, 3), [1n, 1n, 0n]); assert(decrypted.slice(3).every(x => x === 0n))
  const outputHash = keccak256(output), outputCommitment = hexlify(runtime.generator.computeCtCommitment(output))
  const round = await fixture.getRoundData(17)
  const proofData = new Uint8Array(55 * 32).fill(0x42), seal = abi.encode(['uint8', 'bytes'], [1, proofData])
  const computeProof = abi.encode(['bytes', 'bytes32', 'bytes32'], [seal, manifest.paramsHash, toBeHex(round[4], 32)])
  const journalDigest = sha256(computeJournal(manifest, outputHash, outputCommitment, round[4].toString()))
  await (await halo.expect(journalDigest, keccak256(proofData))).wait()
  const committeeHash = await committee.getCommitteeHash(17), pkProof = '0x1111', decryptionProof = '0x2222'
  await (await pk.expect(keccak256(abi.encode(['uint256', 'uint256', 'address[]', 'bytes32', 'bytes32', 'bytes'], [17, 777, nodes, key, committeeHash, pkProof])))).wait()
  const plaintext = new Uint8Array(400), view = new DataView(plaintext.buffer)
  view.setBigUint64(0, 1n, true); view.setBigUint64(8, 1n, true)
  const expectedDecryption = keccak256(abi.encode(['uint256', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes'],
    [17, decryptionDomain(manifest, committeeHash, outputHash), keccak256(plaintext), committeeHash, outputCommitment, decryptionProof]))
  await (await decrypt.expect(expectedDecryption)).wait()
  const outputAvailabilityProof = availability(outputHash, 500, 3)
  const reference = abi.encode(['tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes computeProof,bytes availabilityProof)'],
    [[outputHash, outputCommitment, computeProof, outputAvailabilityProof]])
  const computeJob = await queueOperatorTransaction(store, await sign(protocolInterface.encodeFunctionData('publishCiphertextOutput', [17, reference])))
  assert.equal((await pumpOperatorTransactions(store, provider)).find(x => x.hash === computeJob.hash).status, 'submitted')
  await mine()
  const decryptJob = await queueOperatorTransaction(store, await sign(protocolInterface.encodeFunctionData('publishPlaintextOutput', [17, plaintext, decryptionProof])))
  assert.equal((await pumpOperatorTransactions(store, provider)).find(x => x.hash === decryptJob.hash).status, 'submitted')
  await mine()
  assert((await pumpOperatorTransactions(store, provider)).filter(x => x.hash === computeJob.hash || x.hash === decryptJob.hash).every(x => x.status === 'confirmed'))
  report.checks.push('outbox publishes computation and decryption once and confirms their receipts')
  const bundle = { schemaVersion: 1, manifestHash: manifest.manifestHash, policyHash: policy.policyHash, publicKey: hexlify(publicKey), pkProof,
    computeProof, outputCiphertext: hexlify(output), outputAvailabilityProof,
    inputAvailabilityProofs: entries.map(x => ({ index: x.index, proof: x.availabilityProof })), decryptionProof }
  await importProofBundle(store, bundle)
  state = await syncCoordinator(store, provider)
  assert.equal(state.status, 'awaiting-ciphertexts'); assert.equal(state.result, null)
  store.putCiphertext(entries[1].bytes)
  state = await syncCoordinator(store, provider)
  assert.equal(state.status, 'development-complete', JSON.stringify(state))
  assert.deepEqual(state.result.totals, ['1', '1', '0'])
  assert(!state.result.assurance.includes('reviewed deployment'))
  report.checks.push('missing ciphertext blocks result without removing its committed input',
    'complete bundle rechecks key, exact journal, all DA receipts, decryption and aggregate bytes', 'fixture result stays development-only')

  async function invalidBundle(label, mutate, expected) {
    const changed = structuredClone(bundle); mutate(changed); await importProofBundle(store, changed)
    const bad = await syncCoordinator(store, provider)
    assert.equal(bad.result, null, label); assert.equal(bad.reason, expected, JSON.stringify(bad))
    await importProofBundle(store, bundle); report.checks.push(label)
  }
  await invalidBundle('changed committee proof rejected', x => x.pkProof = '0x11', 'INVALID_COMMITTEE_PROOF')
  await invalidBundle('wrong input DA coordinates rejected', x => x.inputAvailabilityProofs[0].proof = availability(entries[0].ciphertextHash, 999, 2), 'INPUT_AVAILABILITY_MISMATCH')
  await invalidBundle('invalid input DA proof rejected', x => x.inputAvailabilityProofs[0].proof = availability(toBeHex(1, 32), 100, 2), 'INVALID_INPUT_AVAILABILITY')
  await invalidBundle('missing input receipt rejected', x => x.inputAvailabilityProofs.pop(), 'INCOMPLETE_INPUT_RECEIPTS')
  await invalidBundle('changed output ciphertext rejected', x => x.outputCiphertext = hexlify(entries[0].bytes), 'OUTPUT_CIPHERTEXT_MISMATCH')
  await invalidBundle('wrong compute root rejected', x => x.computeProof = abi.encode(['bytes', 'bytes32', 'bytes32'], [seal, manifest.paramsHash, toBeHex(1, 32)]), 'COMPUTE_ENVELOPE_MISMATCH')
  await invalidBundle('invalid compute seal rejected by original receipt adapter', x => x.computeProof = abi.encode(['bytes', 'bytes32', 'bytes32'],
    [abi.encode(['uint8', 'bytes'], [1, new Uint8Array(55 * 32).fill(0x43)]), manifest.paramsHash, toBeHex(round[4], 32)]), 'INVALID_COMPUTATION_PROOF')
  await invalidBundle('wrong output DA coordinates rejected', x => x.outputAvailabilityProof = availability(outputHash, 999, 3), 'OUTPUT_AVAILABILITY_MISMATCH')
  await (await decrypt.expect(toBeHex(1, 32))).wait(); await mine()
  assert.equal((await syncCoordinator(store, provider)).reason, 'INVALID_DECRYPTION_PROOF')
  await (await decrypt.expect(expectedDecryption)).wait(); await mine()
  report.checks.push('invalid decryption proof suppresses result')
  const receiptCode = await provider.getCode(await receipt.getAddress())
  await provider.send('anvil_setCode', [await receipt.getAddress(), '0x00']); await mine(); await mine()
  assert.equal((await syncCoordinator(store, provider)).reason, 'DEPLOYMENT_CODE_CHANGED')
  await provider.send('anvil_setCode', [await receipt.getAddress(), receiptCode]); await mine(); await mine()
  assert.equal((await syncCoordinator(store, provider)).status, 'development-complete')
  report.checks.push('changed verifier runtime suppresses result')
  const savedCursor = store.get('state').cursor
  state = await syncCoordinator(store, wrap({ getBlock: async () => { throw rpcError() } }))
  assert.equal(state.status, 'pending-rpc'); assert.equal(state.result, null); assert.deepEqual(state.cursor, savedCursor)
  assert.equal((await syncCoordinator(store, provider)).status, 'development-complete')
  report.checks.push('RPC outage clears stale result and preserves cursor for recovery')
  await (await fixture.setStage(6)).wait(); await mine()
  state = await syncCoordinator(store, provider); assert.equal(state.status, 'failed-protocol'); assert.equal(state.result, null)
  await (await fixture.setStage(5)).wait(); await mine()
  assert.equal((await syncCoordinator(store, provider)).status, 'development-complete')
  report.checks.push('failed protocol stage suppresses a previously accepted development result')
  const checkpoint = await provider.send('evm_snapshot', [])
  await mine(); await mine(); assert.equal((await syncCoordinator(store, provider)).status, 'development-complete')
  assert(await provider.send('evm_revert', [checkpoint]))
  state = await syncCoordinator(store, provider); assert.equal(state.status, 'replay-required'); assert.equal(state.result, null)
  await replayCoordinator(store)
  assert.equal((await syncCoordinator(store, provider)).status, 'development-complete')
  report.checks.push('real chain rollback requires replay from approved anchor; signed outbox remains intact')
  const { policyHash: oldPolicyHash, ...rawPolicy } = policy
  const pagedPolicy = makeCoordinatorPolicy({ ...rawPolicy, scanBatchSize: 2 }, manifest)
  const pagedConfig = { ...config, policy: pagedPolicy, approvedPolicyHash: pagedPolicy.policyHash }
  const paged = new CoordinatorStore(resolve(run, 'paged-state.db'))
  try {
    await initializeCoordinator(paged, pagedConfig)
    entries.forEach(x => paged.putCiphertext(x.bytes))
    await importProofBundle(paged, { ...bundle, policyHash: pagedPolicy.policyHash })
    let recovered, batches = 0
    do { recovered = await syncCoordinator(paged, provider); batches++ } while (recovered.status === 'catching-up' && batches < 100)
    assert(batches > 1); assert.equal(recovered.status, 'development-complete', JSON.stringify(recovered))
    report.checks.push('bounded historical batches recover across the pre-freeze anchor')
  } finally { paged.close() }
  // Exercise the actual CLI against the still-running local fixture, in its own round database.
  const configFile = resolve(run, 'config.json'), bundleFile = resolve(run, 'public-proofs.json'), txFile = resolve(run, 'public-operator-tx.txt')
  writeFileSync(bundleFile, JSON.stringify(bundle) + '\n')
  const knownJob = store.list('job:').map(([, x]) => x).find(x => x.status === 'confirmed')
  writeFileSync(txFile, knownJob.raw + '\n')
  const cli = (...args) => execFileSync(process.execPath, [resolve(ROOT, 'scripts/t06/coordinator.mjs'), ...args],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 1024 * 1024, env: { ...process.env, COORDINATOR_RPC_URL: 'http://127.0.0.1:18546' }, stdio: ['ignore', 'pipe', 'pipe'] })
  assert(cli('init', configFile).includes('Initialized local round'))
  for (const entry of entries) {
    const path = resolve(run, 'public-ciphertext-' + entry.index + '.bin'); writeFileSync(path, entry.bytes)
    assert(cli('ciphertext', manifest.manifestHash, path).includes(entry.ciphertextHash))
  }
  assert(cli('proofs', manifest.manifestHash, bundleFile).includes('Imported public proof'))
  assert.equal(JSON.parse(cli('sync', manifest.manifestHash)).status, 'development-complete')
  assert.equal(JSON.parse(cli('status', manifest.manifestHash)).cached, true)
  assert.equal(JSON.parse(cli('queue', manifest.manifestHash, txFile)).hash, knownJob.hash)
  assert.equal(JSON.parse(cli('pump', manifest.manifestHash))[0].status, 'confirmed')
  assert(cli('replay', manifest.manifestHash).includes('signed transactions retained'))
  assert.equal(JSON.parse(cli('status', manifest.manifestHash)).result, null)
  report.checks.push('actual CLI initializes, imports, syncs, reports cached status, queues, polls receipts and replays')
  state = store.get('state')
  report.result = state.result; report.counts = state.counts; report.policyHash = policy.policyHash
  report.journalDigest = journalDigest; report.outbox = (await pumpOperatorTransactions(store, provider)).map(x => ({ status: x.status, attempts: x.attempts }))
  report.limits = ['All committee/Halo2/DA/decryption proofs and input admissions were mutable fixtures.',
    'Secure policy allowlist remains empty. No secure round, Sepolia deployment or live operator was qualified.',
    'PK circuit domain limitation requires security review. Coordinator does not strengthen the circuit.',
    'Existing CRISP services still produce admissions, availability publications and computation/decryption jobs.']
  writeFileSync(resolve(run, 'coordination.json'), JSON.stringify(report, null, 2) + '\n')
  writeFileSync(resolve(ROOT, '.local/latest-t06-run'), run + '\n')
  console.log('T06 EVM coordination checks passed: ' + report.checks.length)
}
try { await main() }
catch (error) { console.error('T06 failed:', error.shortMessage ?? error.message); console.error(error.stack?.split('\n').slice(1, 12).join('\n')); process.exitCode = 1 }
finally { await cleanup() }
