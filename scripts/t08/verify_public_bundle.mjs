// SPDX-License-Identifier: LGPL-3.0-only
// Verification only: ordinary JS dependencies and Anvil; no SDK, Rust, setup keys or prover.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, realpathSync, openSync, closeSync, statSync } from 'node:fs'
import { resolve, join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn, execFileSync } from 'node:child_process'
import { setTimeout as delay } from 'node:timers/promises'
import net from 'node:net'
import { AbiCoder, Contract, Interface, JsonRpcProvider, getBytes, hexlify, keccak256, sha256, toBeHex, concat, ZeroHash, TypedDataEncoder } from 'ethers'
import { transcriptRoot, decodeAggregate } from '../../src/transcript.mjs'
import { computeJournal, decryptionDomain } from '../../src/coordinator-protocol.mjs'
import pinned from '../../config/t08-public-verifier.json' with { type: 'json' }
import recursiveVk from '../../config/t08-recursive-vk.json' with { type: 'json' }

const root = fileURLToPath(new URL('../../', import.meta.url))
assert(process.argv[2], 'Supply the extracted public evidence bundle')
assert(process.versions.node.startsWith('22.23.'), 'Use the pinned Node 22.23 runtime')
assert.match(execFileSync('anvil', ['--version'], { encoding: 'utf8' }), /1\.5\.1/, 'Use pinned Anvil 1.5.1')
const bundle = realpathSync(process.argv[2]), output = resolve(process.argv[3] ?? join(root, '.local/runs/t08-public-verification-' + Date.now()))
mkdirSync(dirname(output), { recursive: true })
mkdirSync(output, { recursive: false, mode: 0o700 })
const json = file => JSON.parse(readFileSync(file, 'utf8')), manifest = json(join(bundle, 'bundle-manifest.json'))
const expectedFiles = ['public-chain.json', 'result.json', 'recovery-native.journal.bin', 'recovery-native.compute-envelope.bin',
  'recovery-native.ciphertext.bin', 'verification.json', 'PROVENANCE.json', 'README.md', 'saved/chain.json',
  'saved/result.json', 'saved/admissions.json', 'saved/deployment-check.json', 'saved/package-manifest.json',
  'saved/public-source.json', 'saved/deployed_contracts.json', 'saved/export-manifest.json']
assert.deepEqual(Object.keys(manifest.files).sort(), expectedFiles.sort(), 'Unexpected public bundle inventory')
for (const [name, item] of Object.entries(manifest.files)) {
  const path = resolve(bundle, name)
  assert(path.startsWith(bundle + '/') && realpathSync(path) === path, 'Unsafe bundle member')
  assert(statSync(path).size <= 128 * 1024 * 1024, 'Oversized public evidence file')
  const bytes = readFileSync(path); assert.equal(bytes.length, item.bytes); assert.equal(sha256(bytes).slice(2), item.sha256, 'Changed bundle file: ' + name)
}
const chain = json(join(bundle, 'public-chain.json')), result = json(join(bundle, 'result.json')), abi = AbiCoder.defaultAbiCoder()
assert.equal(chain.chainId, pinned.chainId); assert.equal(result.e3Id, pinned.e3Id); assert.deepEqual(result.tally, ['1', '2', '2'])
const interfaces = Object.fromEntries(Object.entries(pinned.abis).map(([name, entries]) => [name, new Interface(entries)]))
const parsed = []
for (const item of chain.transactions) for (const name of ['protocol', 'program', 'committee']) {
  try { const call = interfaces[name].parseTransaction({ data: item.transaction.input }); if (call) { parsed.push({ ...item, call }); break } } catch {}
}
const one = name => { const found = parsed.filter(x => x.call.name === name); assert.equal(found.length, 1); return found[0] }
const roles = pinned.roles, e3Id = BigInt(pinned.e3Id), gas = { gasLimit: 50000000 }, checks = []
let provider, child, fd
async function rejects(label, operation) {
  let rejected = false
  try { rejected = await operation() === false } catch (error) { assert.equal(error.code, 'CALL_EXCEPTION'); assert(!/out of gas/i.test(error.message)); rejected = true }
  assert(rejected, label); checks.push(label)
}
try {
  await new Promise((r, reject) => { const socket = net.createServer(); socket.once('error', reject); socket.listen(18592, '127.0.0.1', () => socket.close(r)) })
  fd = openSync(join(output, 'anvil.log'), 'w')
  child = spawn('anvil', ['--host', '127.0.0.1', '--port', '18592', '--chain-id', '31337', '--silent', '--load-state', join(bundle, 'saved/chain.json')], { stdio: ['ignore', fd, fd] })
  provider = new JsonRpcProvider('http://127.0.0.1:18592', 31337, { staticNetwork: true, cacheTimeout: -1, batchMaxCount: 1 })
  let ready = false
  for (let i = 0; i < 100; i++) { try { ready = await provider.send('eth_chainId', []) === '0x7a69' } catch {} if (ready) break; assert.equal(child.exitCode, null); await delay(100) }
  assert(ready)
  for (const [address, hash] of Object.entries(pinned.runtimes)) assert.equal(keccak256(await provider.getCode(address)), hash, 'Unreviewed verifier/runtime: ' + address)
  for (const [proxy, implementation] of Object.entries(pinned.proxyImplementations))
    assert.equal('0x' + (await provider.getStorage(proxy, '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc')).slice(-40), implementation, 'Proxy implementation differs')
  checks.push('all-review-pinned-implementation-library-wrapper-proxy-and-halo2-runtime-hashes-match')
  const protocol = new Contract(roles.Interfold, pinned.abis.protocol, provider), program = new Contract(roles.CRISPProgram, pinned.abis.program, provider)
  const committee = new Contract(roles.CiphernodeRegistryOwnable, pinned.abis.committee, provider)
  const e3 = await protocol.getE3(e3Id), round = await program.getRoundData(e3Id)
  assert.equal(await protocol.getE3Stage(e3Id), 5n); assert.equal(e3.paramSet, 2n); assert.equal(round.numberOfVotes, 6n); assert.equal(round.numOptions, 3n)
  assert.equal(String(round.merkleRoot), pinned.censusRoot); assert.equal(round.paramsHash, pinned.paramsHash)
  assert.equal(e3.committeePublicKey, pinned.committeeKeyCommitment); assert.equal(round.creditMode, 0n)
  const custom = abi.decode(['address', 'uint256', 'uint256', 'uint8', 'uint256', 'uint256', 'uint256'], e3.customParams)
  assert.equal(custom[2], 3n); assert.equal(custom[3], 0n); assert.equal(custom[4], 1n); assert(custom[5] <= 1n)
  assert.equal(await program.pendingInputCount(e3Id), 0n); assert.equal(e3.e3Program.toLowerCase(), roles.CRISPProgram)
  assert.equal(e3.pkVerifier.toLowerCase(), roles.BfvPkVerifier); assert.equal(e3.decryptionVerifier.toLowerCase(), roles.BfvDecryptionVerifier)
  const entries = []
  for (const log of chain.logs) { try { const event = interfaces.program.parseLog(log); if (event?.name === 'InputPublished') {
    assert.equal(log.address.toLowerCase(), roles.CRISPProgram); assert.equal(event.args.e3Id, e3Id)
    entries.push({ index: String(event.args.index), slot: event.args.slotAddress.toLowerCase(), commitment: event.args.encryptedVoteCommitment,
      ciphertextHash: event.args.encryptedVoteHash, parentIndexPlusOne: String(event.args.parentIndexPlusOne) })
  } } catch (error) { if (error.code === 'ERR_ASSERTION') throw error } }
  entries.sort((a, b) => Number(a.index) - Number(b.index)); assert.equal(entries.length, 6)
  entries.forEach((x, i) => assert.equal(x.index, String(i))); const inputRoot = transcriptRoot(entries)
  assert.equal(BigInt(inputRoot), round.inputRoot)
  checks.push('six-admitted-public-input-identities-rebuild-exact-proof-bound-root')
  const honk = new Contract(roles.HonkVerifier, ['function verify(bytes,bytes32[]) view returns(bool)'], provider)
  const admissions = parsed.filter(x => x.call.name === 'publishInput').sort((a, b) => Number(BigInt(a.transaction.blockNumber) - BigInt(b.transaction.blockNumber)))
  assert.equal(admissions.length, 6)
  for (let i = 0; i < 6; i++) {
    const [proof, slot, commitment, hash, parent] = abi.decode(['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'uint64', 'bytes'], admissions[i].call.args.data)
    assert.equal(admissions[i].transaction.to.toLowerCase(), roles.CRISPProgram)
    assert.equal(slot.toLowerCase(), entries[i].slot); assert.equal(commitment, entries[i].commitment); assert.equal(hash, entries[i].ciphertextHash)
    assert.equal(String(parent), entries[i].parentIndexPlusOne)
    const parentCommitment = parent === 0n ? ZeroHash : await program.inputCommitmentOf(e3Id, slot, parent - 1n)
    const domain = { name: 'CRISP', version: '1', chainId: 31337, verifyingContract: roles.CRISPProgram }
    const types = { Ballot: [{ name: 'e3Id', type: 'uint256' }, { name: 'slot', type: 'address' }, { name: 'ciphertextCommitment', type: 'bytes32' }] }
    const digest = BigInt(TypedDataEncoder.hash(domain, types, { e3Id, slot, ciphertextCommitment: commitment }))
    assert.equal(digest, BigInt(await program.ballotDigest(e3Id, slot, commitment)))
    const inputs = [parentCommitment, toBeHex(digest >> 128n, 32), toBeHex(digest & ((1n << 128n) - 1n), 32), toBeHex(BigInt(slot), 32),
      toBeHex(round.merkleRoot, 32), toBeHex(parent === 0n ? 1 : 0, 32), toBeHex(3, 32), commitment, e3.committeePublicKey]
    assert.equal(await honk.verify(proof, inputs, gas), true); checks.push('original-secure-client-proof-' + (i + 1) + '-verified')
    if (!i) await rejects('client-wrong-committee-key-rejected', () => honk.verify(proof, inputs.with(8, ZeroHash), gas))
  }
  const nodes = Array.from(await committee.getCommitteeNodes(e3Id)), committeeHash = await committee.getCommitteeHash(e3Id)
  assert.equal(nodes.length, 3); assert.equal(keccak256(concat(nodes)), committeeHash)
  const wrapperGetters = ['function circuitVerifier() view returns(address)', 'function expectedNodesFoldKeyHash() view returns(bytes32)',
    'function expectedC5KeyHash() view returns(bytes32)', 'function expectedC6FoldKeyHash() view returns(bytes32)', 'function expectedC7KeyHash() view returns(bytes32)']
  const pk = new Contract(roles.BfvPkVerifier, [...wrapperGetters, 'function h() view returns(uint256)',
    'function verify(uint256,uint256,address[],bytes32,bytes32,bytes) view returns(bool)'], provider)
  assert.equal(await pk.h(), 2n); assert.equal((await pk.circuitVerifier()).toLowerCase(), roles.DkgAggregatorVerifier)
  for (const name of ['expectedNodesFoldKeyHash', 'expectedC5KeyHash']) assert.equal(await pk[name](), recursiveVk.anchors[name])
  const pkCall = one('publishCommittee').call.args
  const pkArgs = [e3Id, await committee.rootAt(e3Id), nodes, e3.committeePublicKey, committeeHash, pkCall.proof]
  assert.equal(await pk.verify(...pkArgs, gas), true)
  const attestation = new Contract(roles.DkgFoldAttestationVerifier, pinned.abis.attestation, provider)
  assert.deepEqual((await attestation.verify(roles.CiphernodeRegistryOwnable, 31337, e3Id, pkCall.proof, pkCall.dkgAttestationBundle, gas)).toArray(true),
    (await committee.getDkgAnchors(e3Id)).toArray(true))
  checks.push('real-committee-proof-recursive-anchors-and-signed-DKG-attestations-verified')
  await rejects('committee-changed-key-rejected', () => pk.verify(...pkArgs.with(3, ZeroHash), gas))
  const envelope = readFileSync(join(bundle, 'recovery-native.compute-envelope.bin')), [seal, paramsHash, rootHash] = abi.decode(['bytes', 'bytes32', 'bytes32'], envelope)
  assert.equal(sha256(seal).slice(2), pinned.sealSha256); assert.equal(BigInt(rootHash), round.inputRoot); assert.equal(paramsHash, round.paramsHash)
  const manifestContext = { chainId: '31337', interfoldAddress: roles.Interfold, programAddress: roles.CRISPProgram, e3Id: String(e3Id),
    committeeKeyCommitment: e3.committeePublicKey, paramsHash }
  const journal = computeJournal(manifestContext, e3.ciphertextOutput, e3.ciphertextCommitment, inputRoot)
  assert.equal(journal, hexlify(readFileSync(join(bundle, 'recovery-native.journal.bin')))); assert.equal(sha256(journal).slice(2), pinned.journalSha256)
  assert.equal(keccak256(readFileSync(join(bundle, 'recovery-native.ciphertext.bin'))), e3.ciphertextOutput)
  const receipt = new Contract(roles.OpenVmReceiptVerifier, ['function verify(bytes,bytes32,bytes32) view', 'function verifier() view returns(address)',
    'function imageId() view returns(bytes32)', 'function appExeCommit() view returns(bytes32)', 'function appVmCommit() view returns(bytes32)'], provider)
  assert.equal((await receipt.verifier()).toLowerCase(), roles.OpenVmHalo2Verifier)
  assert.equal(await receipt.appExeCommit(), pinned.guest.app_exe_commit); assert.equal(await receipt.appVmCommit(), pinned.guest.app_vm_commit)
  const imageId = await receipt.imageId()
  await receipt.verify(seal, imageId, sha256(journal), gas)
  assert.equal(await program.verify(e3Id, e3.ciphertextOutput, e3.ciphertextCommitment, hexlify(envelope), gas), true)
  checks.push('original-computation-seal-journal-guest-and-complete-transcript-verified')
  await rejects('computation-wrong-journal-rejected', () => receipt.verify(seal, imageId, ZeroHash, gas))
  const decrypted = one('publishPlaintextOutput').call.args
  assert.equal(decrypted.plaintextOutput, e3.plaintextOutput)
  const dec = new Contract(roles.BfvDecryptionVerifier, [...wrapperGetters, 'function threshold() view returns(uint256)',
    'function verify(uint256,bytes32,bytes32,bytes32,bytes32,bytes) view returns(bool)'], provider)
  assert.equal(await dec.threshold(), 1n); assert.equal((await dec.circuitVerifier()).toLowerCase(), roles.DecryptionAggregatorVerifier)
  for (const name of ['expectedC6FoldKeyHash', 'expectedC7KeyHash']) assert.equal(await dec[name](), recursiveVk.anchors[name])
  assert.equal(await dec.verify(e3Id, decryptionDomain(manifestContext, committeeHash, e3.ciphertextOutput), keccak256(e3.plaintextOutput),
    committeeHash, e3.ciphertextCommitment, decrypted.proof, gas), true)
  const totals = decodeAggregate(e3.plaintextOutput, 3, 5).map(String); assert.deepEqual(totals, ['1', '2', '2'])
  checks.push('real-threshold-decryption-and-three-totals-with-47-zero-coefficients-verified')
  writeFileSync(join(output, 'verification.json'), JSON.stringify({ result: 'passed', scope: pinned.scope, checks, totals,
    trustedRuntimeCount: Object.keys(pinned.runtimes).length, completeT08: false,
    limits: ['Local synthetic evidence, not an authenticated public-network state', 'One operator controls the committee',
      'Eligibility, randomness and availability are fixtures', 'No browser/coordinator or production-service qualification is claimed by this verifier'] }, null, 2) + '\n')
  console.log(JSON.stringify({ result: 'passed', totals, checks: checks.length, output }))
} finally {
  provider?.destroy()
  if (child?.exitCode === null) { child.kill('SIGTERM'); await Promise.race([new Promise(r => child.once('exit', r)), delay(5000, undefined, { ref: false })]); if (child.exitCode === null) child.kill('SIGKILL') }
  if (fd !== undefined) closeSync(fd)
}
