// SPDX-License-Identifier: LGPL-3.0-only
// Disposable component exercise. Private keys/witnesses remain in memory; outputs are public metadata only.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import net from 'node:net'
import { ContractFactory, JsonRpcProvider, Wallet, getBytes, hexlify, keccak256, sha256, toBeHex } from 'ethers'
import { buildCensus } from '../../src/census.mjs'
import { address, digest } from '../../src/format.mjs'
import { profile, makeRoundManifest, ballotDigest, expectedPublicInputs } from '../../src/round.mjs'
import { authenticatePublicKey, prepareBoundBallot, finishBoundBallot } from '../../src/ballot.mjs'
import { checkPublicResult, checkTranscript, inputLeaf, transcriptRoot } from '../../src/transcript.mjs'
import { verifyWalletSignature } from '../../src/wallet.mjs'
import { ROOT, CRISP, checkLockedArtifacts, loadProofRuntime } from '../../src/upstream.mjs'
import { compileComponents, linkedBytecode, ensurePoseidon } from './compile.mjs'

const run = resolve(ROOT, '.local/runs/t05-' + new Date().toISOString().replace(/[-:.]/g, ''))
mkdirSync(run, { recursive: true })
const report = { schemaVersion: 1, task: 'T05', scope: 'Synthetic local component checks with real client proofs and an EVM Honk verifier. Protocol state/availability/result are explicit mutable fixtures, not a secure Interfold round.',
  sourceRevision: profile.sourceRevision, chainId: 31337, preset: 'insecure-512', checks: [], proofs: [] }
let child, provider, runtime, logFd

async function cleanup() {
  runtime?.sdk.destroyBBApi()
  provider?.destroy()
  if (child && child.exitCode === null) {
    child.kill('SIGTERM')
    await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(5000)])
    if (child.exitCode === null) child.kill('SIGKILL')
  }
  if (logFd !== undefined) { closeSync(logFd); logFd = undefined }
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void cleanup().finally(() => process.exit(130)) })

async function rejectedCall(fn, label) {
  let rejected = false
  try { rejected = !(await fn()) }
  catch (e) { rejected = e.code === 'CALL_EXCEPTION' && typeof e.data === 'string' && e.data !== '0x' }
  assert(rejected, label + ' was not rejected by the EVM')
  report.checks.push(label)
}

async function main() {
  console.log('T05 ignored run directory: ' + run)
  const artifactsHash = await checkLockedArtifacts()
  const contracts = compileComponents()
  await new Promise((resolve, reject) => {
    const server = net.createServer(); server.once('error', reject)
    server.listen(18545, '127.0.0.1', () => server.close(resolve))
  })
  logFd = openSync(resolve(run, 'anvil.log'), 'w')
  child = spawn('anvil', ['--host', '127.0.0.1', '--port', '18545', '--chain-id', '31337', '--silent'],
    { stdio: ['ignore', logFd, logFd] })
  writeFileSync(resolve(run, 'process.json'), JSON.stringify({ ownedAnvilPid: child.pid }) + '\n')
  provider = new JsonRpcProvider('http://127.0.0.1:18545', 31337, { staticNetwork: true, batchMaxCount: 1, cacheTimeout: -1 })
  let ready = false
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error('Owned Anvil exited')
    try { ready = await provider.send('eth_chainId', []) === '0x7a69' } catch {}
    if (ready) break
    await delay(100)
  }
  assert(ready, 'Local chain is unavailable')
  const publisher = await provider.getSigner(0), outsider = await provider.getSigner(1)
  const wallet = Wallet.createRandom()
  async function deploy(artifact, args = [], libraries = {}) {
    const contract = await new ContractFactory(artifact.abi, linkedBytecode(artifact, libraries), publisher).deploy(...args)
    await contract.waitForDeployment(); return contract
  }
  const poseidon = await ensurePoseidon(provider, publisher)
  const fixture = await deploy(contracts['tests/contracts/T05Fixture.sol'].T05Fixture, [],
    { 'poseidon-solidity/PoseidonT3.sol:PoseidonT3': poseidon })
  const registryArtifact = contracts['contracts/FrozenRoundRegistry.sol'].FrozenRoundRegistry
  const registry = await deploy(registryArtifact, [await publisher.getAddress()])
  const contractWallet = await deploy(contracts['tests/contracts/T05Fixture.sol'].T05ContractWallet, [wallet.address])
  const authHash = digest({ task: 'T05', kind: 'disposable contract authorization' })
  const authSig = wallet.signingKey.sign(authHash).serialized
  assert(await verifyWalletSignature(provider, await contractWallet.getAddress(), authHash, authSig, 'latest'))
  assert.equal(await verifyWalletSignature(provider, await contractWallet.getAddress(), digest({ other: 'digest' }), authSig, 'latest'), false)
  report.checks.push('real ERC-1271 transport valid/invalid control')

  const template = JSON.parse(readFileSync(resolve(ROOT, 'fixtures/t04-synthetic.json')))
  template.context.choices.push('Synthetic option C')
  const old = template.records[0].address
  template.records[0].address = address(wallet.address)
  template.context.candidateAddresses = template.context.candidateAddresses.map(x => x === old ? address(wallet.address) : x)
  const census = buildCensus(template.context, template.records)
  runtime = await loadProofRuntime('insecure-512')
  const { publicKey } = runtime.sdk.generateBFVKeys()
  const committeeKeyCommitment = hexlify(runtime.core.compute_pk_commitment(publicKey, runtime.params.degree,
    runtime.params.plaintextModulus, BigUint64Array.from(runtime.params.moduli)))
  const now = await provider.getBlock('latest')
  const p = profile.presets['insecure-512']
  const manifest = makeRoundManifest(census, census.manifestHash, { chainId: '31337',
    interfoldAddress: address(await fixture.getAddress()), programAddress: address(await fixture.getAddress()),
    registryAddress: address(await registry.getAddress()), e3Id: '17', preset: 'insecure-512', paramsHash: p.paramsHash,
    committeeKeyCommitment, inputStart: String(now.timestamp), inputEnd: String(now.timestamp + 14400), artifactsHash })
  await (await fixture.configure(census.root, p.paramsHash, 3, committeeKeyCommitment, 0, manifest.inputStart, manifest.inputEnd)).wait()
  const freeze = { interfold: manifest.interfoldAddress, program: manifest.programAddress, e3Id: '17',
    manifestHash: manifest.manifestHash, censusRoot: census.root, paramsHash: p.paramsHash, committeeKey: committeeKeyCommitment, numOptions: 3 }
  await rejectedCall(() => registry.connect(outsider).freeze.staticCall(freeze), 'unauthorized publisher')
  await rejectedCall(() => registry.freeze.staticCall({ ...freeze, censusRoot: BigInt(census.root) + 1n }), 'wrong census root')
  await rejectedCall(() => registry.freeze.staticCall({ ...freeze, committeeKey: toBeHex(1n, 32) }), 'wrong published key')
  await (await fixture.setCount(1)).wait()
  await rejectedCall(() => registry.freeze.staticCall(freeze), 'late context freeze after admission')
  await (await fixture.setCount(0)).wait()
  await (await registry.freeze(freeze)).wait()
  await rejectedCall(() => registry.freeze.staticCall({ ...freeze, manifestHash: digest({ changed: 'proposal' }) }), 'context replacement')
  report.checks.push('manifest frozen before the first input')
  const otherKey = runtime.sdk.generateBFVKeys().publicKey
  assert.throws(() => authenticatePublicKey(runtime, otherKey, committeeKeyCommitment))
  report.checks.push('substituted valid public key rejected before encryption')

  const honkArtifact = JSON.parse(readFileSync(resolve(CRISP, 'packages/crisp-contracts/artifacts/contracts/verifiers/CRISPVerifier.sol/HonkVerifier.json')))
  const verifierLibraries = {}
  for (const name of ['RelationsLib', 'ZKTranscriptLib']) {
    const artifact = JSON.parse(readFileSync(resolve(CRISP, `packages/crisp-contracts/artifacts/contracts/verifiers/CRISPVerifier.sol/${name}.json`)))
    const library = await deploy(artifact)
    verifierLibraries[`project/contracts/verifiers/CRISPVerifier.sol:${name}`] = await library.getAddress()
  }
  const honk = await deploy(honkArtifact, [], verifierLibraries)
  const entries = []
  const actions = [
    { vote: [0, 1, 0], mask: false },
    { vote: [0, 0, 0], mask: true, parent: 0 },
    { vote: [0, 0, 0], mask: true },
    { vote: [1, 0, 0], mask: false, parent: 1 },
  ]
  for (const [ordinal, action] of actions.entries()) {
    const started = performance.now()
    const previous = action.parent === undefined ? {} : { previousCiphertext: getBytes(entries[action.parent].ciphertext), previousIndex: action.parent }
    const session = await prepareBoundBallot({ provider, manifest, approvedHash: manifest.manifestHash,
      census, approvedCensusHash: census.manifestHash, publicKey, slot: wallet.address,
      vote: action.vote, isMask: action.mask, ...previous })
    const proof = await finishBoundBallot(provider, manifest, session, wallet)
    const inputs = proof.publicInputs.map(x => toBeHex(BigInt(x), 32))
    assert(await honk.verify.staticCall(proof.proof, inputs), 'Valid component proof failed the EVM verifier')
    report.proofs.push({ ordinal: ordinal + 1, preparationProofAndVerificationMs: Math.round(performance.now() - started), proofBytes: proof.proof.length })
    if (ordinal === 0) {
      const changed = Uint8Array.from(proof.proof); changed[changed.length - 1] ^= 1
      await rejectedCall(() => honk.verify.staticCall(changed, inputs), 'changed proof')
      for (const [label, changedManifest] of [
        ['wrong round digest', { ...manifest, e3Id: '18' }], ['wrong chain digest', { ...manifest, chainId: '1' }],
        ['wrong program digest', { ...manifest, programAddress: address(await registry.getAddress()) }]]) {
        const expected = expectedPublicInputs(changedManifest, wallet.address, session.prepared.ctCommitment, 0n, true)
        await rejectedCall(() => honk.verify.staticCall(proof.proof, expected), label)
      }
      for (const [label, index, value] of [['wrong census proof statement', 4, toBeHex(1n, 32)],
        ['wrong key proof statement', 8, toBeHex(1n, 32)], ['wrong option count', 6, toBeHex(2n, 32)],
        ['wrong slot proof statement', 3, toBeHex(BigInt(census.eligible.find(x => x.address !== address(wallet.address)).address), 32)]]) {
        const altered = [...inputs]; altered[index] = value
        await rejectedCall(() => honk.verify.staticCall(proof.proof, altered), label)
      }
    }
    const entry = { index: String(ordinal), slot: address(wallet.address), commitment: session.prepared.ctCommitment,
      ciphertextHash: keccak256(proof.encryptedVote), parentIndexPlusOne: String(proof.parentIndexPlusOne), ciphertext: hexlify(proof.encryptedVote) }
    entries.push(entry)
    await (await fixture.append(inputLeaf(entry), entry.slot, entry.commitment)).wait()
    const chain = await fixture.getRoundData(17)
    assert.equal(transcriptRoot(entries), chain[4].toString(), 'LazyIMT root differs from the contract library')
    console.log('T05 EVM-verified synthetic input ' + (ordinal + 1))
  }
  const transcript = checkTranscript(entries, census, manifest, transcriptRoot(entries), '4', runtime)
  assert.deepEqual(transcript.dispositions, ['superseded', 'superseded', 'stale-parent', 'selected'])
  assert.equal(transcript.selectedSlots, 1)
  report.checks.push('original LazyIMT roots match for one through four inputs', 'stale input remains in the authenticated transcript', 'replacement and mask preserve one effective slot')

  // Execute the actual Noir ballot witness without paying for redundant full proofs.
  const require = createRequire(resolve(CRISP, 'packages/crisp-sdk/package.json'))
  const { Noir } = require('@noir-lang/noir_js')
  const { attachSignatureImpl } = await import(pathToFileURL(resolve(CRISP, 'packages/crisp-sdk/src/circuitInputs.ts')).href)
  async function prepared(vote) {
    return runtime.sdk.prepareCircuitInputs({ publicKey, slotAddress: address(wallet.address), isMaskVote: false,
      numOptions: 3, vote, censusMode: 'merkle', balance: 1n, merkleLeaves: census.eligible.map(x => BigInt(x.leaf)) })
  }
  async function execute(prep, signer = wallet) {
    const hash = ballotDigest(manifest, wallet.address, prep.ctCommitment)
    const signed = signer.signingKey.sign(hash).serialized
    const all = await attachSignatureImpl(prep, hash, signed)
    const inputs = Object.fromEntries(runtime.circuits.crisp.abi.parameters.map(x => [x.name, all[x.name]]))
    return new Noir(runtime.circuits.crisp).execute(inputs)
  }
  await execute(await prepared([0, 0, 0]))
  report.checks.push('signed zero withdrawal satisfies the actual Noir circuit')
  const mutations = [
    ['split unit', async () => prepared([1, 1, 0])], ['excess weight', async () => prepared([2, 0, 0])],
    ['extra option', async () => { const x = await prepared([0, 0, 0, 1]); x.circuitInputs.num_options = '3'; return x }],
    ['wrong census witness', async () => { const x = await prepared([1, 0, 0]); x.circuitInputs.merkle_root = '0'; return x }],
  ]
  for (const [label, build] of mutations) {
    let refused = false
    try { await execute(await build()) } catch (e) { refused = /Cannot satisfy constraint|Assertion failed|assertion failed/.test(String(e.message)) }
    assert(refused, 'Expected an actual Noir constraint failure: ' + label)
    report.checks.push('Noir rejected ' + label)
  }
  const altered = entries.map(x => ({ ...x }))
  altered[0].ciphertext = hexlify(runtime.sdk.encryptVote([0, 0, 0], publicKey))
  altered[0].ciphertextHash = keccak256(altered[0].ciphertext)
  assert.throws(() => checkTranscript(altered, census, manifest, transcriptRoot(altered), '4', runtime))
  report.checks.push('substituted valid ciphertext rejected by real SAFE commitment check')

  const bytes = new Uint8Array(400); new DataView(bytes.buffer).setBigUint64(0, 1n, true)
  await (await fixture.setResult(bytes)).wait()
  const args = { provider, manifest, approvedHash: manifest.manifestHash, census, approvedCensusHash: census.manifestHash, entries }
  const result = await checkPublicResult(args)
  assert.deepEqual(result.totals, ['1', '0', '0'])
  await assert.rejects(checkPublicResult({ ...args, entries: entries.slice(1) }))
  await (await fixture.setPending(1)).wait(); await assert.rejects(checkPublicResult(args))
  await (await fixture.setPending(0)).wait()
  await (await fixture.setStage(6)).wait(); await assert.rejects(checkPublicResult(args))
  report.checks.push('missing input, pending availability and failed round reject result metadata')
  const upstreamFixture = JSON.parse(readFileSync(resolve(CRISP, 'packages/crisp-contracts/tests/fixtures/input-tree.json')))
  const known = upstreamFixture.inputs.map((x, i) => ({ index: String(i), slot: x.slot.toLowerCase(), commitment: x.commitment,
    ciphertextHash: keccak256(x.encryptedVote), parentIndexPlusOne: String(x.parentIndexPlusOne), ciphertext: x.encryptedVote }))
  assert.equal(transcriptRoot(known), BigInt(upstreamFixture.inputRoot).toString())
  report.checks.push('root matches upstream real CRISP admission fixture')
  report.result = result
  report.artifactsHash = artifactsHash
  report.registryCreationSha256 = sha256(linkedBytecode(registryArtifact))
  report.verifierRuntimeKeccak256 = keccak256(await provider.getCode(await honk.getAddress()))
  report.limits = ['Protocol state and result were explicit fixtures, not a complete new Interfold round.',
    'The client used a fresh single-party key and insecure parameters.', 'Real secure committee, computation, decryption and Avail verification remain untested.',
    'Independent security review and real-UNI design approval remain outstanding.']
  writeFileSync(resolve(run, 'components.json'), JSON.stringify(report, null, 2) + '\n')
  writeFileSync(resolve(ROOT, '.local/latest-t05-run'), run + '\n')
  console.log('T05 component checks passed.')
}

try { await main() }
catch (error) {
  console.error('T05 failed:', error.shortMessage ?? error.message)
  console.error(error.stack?.split('\n').slice(1, 16).join('\n'))
  process.exitCode = 1
}
finally { await cleanup() }
