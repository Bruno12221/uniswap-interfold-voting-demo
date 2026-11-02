// SPDX-License-Identifier: LGPL-3.0-only
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { getBytes, hexlify, keccak256, sha256, Wallet, recoverAddress } from 'ethers'
import { buildCensus } from '../src/census.mjs'
import { canonical, digest } from '../src/format.mjs'
import { profile, makeRoundManifest, assertRoundManifest, ballotDigest, expectedPublicInputs } from '../src/round.mjs'
import { finishBoundBallot, validateUnitVote } from '../src/ballot.mjs'
import { checkTranscript, decodeAggregate, transcriptRoot } from '../src/transcript.mjs'

const fixture = JSON.parse(readFileSync(new URL('../fixtures/t04-synthetic.json', import.meta.url)))
const census = buildCensus(fixture.context, fixture.records)
const artifacts = JSON.parse(readFileSync(new URL('../config/t05-artifacts.json', import.meta.url)))
const info = { chainId: '31337', interfoldAddress: '0x' + '01'.repeat(20), programAddress: '0x' + '02'.repeat(20),
  registryAddress: '0x' + '03'.repeat(20), e3Id: '17', preset: 'insecure-512',
  paramsHash: profile.presets['insecure-512'].paramsHash, committeeKeyCommitment: '0x' + '00'.repeat(31) + '01',
  inputStart: '0', inputEnd: '9999999999', artifactsHash: digest(artifacts) }
const manifest = makeRoundManifest(census, census.manifestHash, info)
const clone = x => structuredClone(x)
const output = values => {
  const bytes = new Uint8Array(400), view = new DataView(bytes.buffer)
  values.forEach((v, i) => view.setBigUint64(i * 8, BigInt(v), true))
  return hexlify(bytes)
}

test('unit encoding permits one full unit or zero and rejects splits, excess and extra choices', () => {
  for (const n of [2, 3]) {
    validateUnitVote(Array(n).fill(0), n, false)
    validateUnitVote(Array(n).fill(0), n, true)
    for (let i = 0; i < n; i++) validateUnitVote(Array.from({ length: n }, (_, k) => +(k === i)), n, false)
    for (const invalid of [Array(n).fill(1), [2, ...Array(n - 1).fill(0)], [-1, ...Array(n - 1).fill(0)],
      [0.5, ...Array(n - 1).fill(0)], Array(n + 1).fill(0)]) assert.throws(() => validateUnitVote(invalid, n, false))
  }
  assert.throws(() => validateUnitVote([1, 0], 2, true))
  assert.throws(() => validateUnitVote([1, 0], 2, 'false'))
})

test('frozen manifest catches altered proposal, census, chain, program, key, parameters and artifacts', () => {
  assert.deepEqual(assertRoundManifest(manifest, manifest.manifestHash, census, census.manifestHash), manifest)
  for (const mutate of [x => x.proposalTextHash = '0x' + '44'.repeat(32), x => x.choices.reverse(),
    x => x.censusRoot = '1', x => x.censusManifestHash = '0x' + '55'.repeat(32), x => x.chainId = '1',
    x => x.e3Id = '18', x => x.programAddress = '0x' + '04'.repeat(20), x => x.registryAddress = '0x' + '05'.repeat(20),
    x => x.committeeKeyCommitment = '0x' + '00'.repeat(31) + '02', x => x.paramsHash = '0x' + '66'.repeat(32),
    x => x.artifactsHash = '0x' + '77'.repeat(32)]) {
    const altered = clone(manifest); mutate(altered)
    assert.throws(() => assertRoundManifest(altered, manifest.manifestHash, census, census.manifestHash))
  }
  assert.throws(() => makeRoundManifest(census, '0x' + '00'.repeat(32), info))
})

test('signature and nine-field statement bind the actual round domain', () => {
  const wallet = Wallet.createRandom(), commitment = '0x' + '00'.repeat(31) + '09'
  const hash = ballotDigest(manifest, wallet.address, commitment)
  const signature = wallet.signingKey.sign(hash).serialized
  for (const changed of [{ ...manifest, chainId: '1' }, { ...manifest, e3Id: '18' },
    { ...manifest, programAddress: '0x' + '06'.repeat(20) }])
    assert.notEqual(recoverAddress(ballotDigest(changed, wallet.address, commitment), signature), wallet.address)
  const inputs = expectedPublicInputs(manifest, wallet.address, commitment, 0n, true)
  assert.equal(inputs.length, 9)
  assert.equal(BigInt(inputs[4]).toString(), census.root)
  assert.equal(BigInt(inputs[6]), 2n)
  assert.equal(inputs[8], manifest.committeeKeyCommitment)
})

test('a changed public manifest cannot reuse an existing private preparation session', async () => {
  const changed = clone(manifest); changed.choices.reverse()
  await assert.rejects(finishBoundBallot({}, changed, { contextHash: manifest.manifestHash, contextJson: canonical(manifest) }), /another round context/)
})

// Structural unit fixture only. The integration script uses the real SAFE implementation.
const mockRuntime = { generator: { computeCtCommitment: bytes => getBytes(sha256(bytes)) } }
function entry(index, slot, parent, byte) {
  const ciphertext = '0x' + byte.toString(16).padStart(2, '0')
  return { index: String(index), slot, commitment: sha256(ciphertext), ciphertextHash: keccak256(ciphertext),
    parentIndexPlusOne: String(parent), ciphertext }
}

test('complete transcript includes stale and superseded records without adding a second slot', () => {
  const a = census.eligible[0].address, b = census.eligible[1].address
  const entries = [entry(0, a, 0, 1), entry(1, a, 1, 2), entry(2, a, 0, 3), entry(3, b, 0, 4), entry(4, a, 2, 5)]
  const checked = checkTranscript(entries, census, manifest, transcriptRoot(entries), '5', mockRuntime)
  assert.deepEqual(checked.dispositions, ['superseded', 'superseded', 'stale-parent', 'selected', 'selected'])
  assert.deepEqual(checked.selectedIndices, [3, 4])
  assert.equal(checked.selectedSlots, 2)
  assert.deepEqual(decodeAggregate(output([1, 1]), 2, checked.selectedSlots), [1n, 1n])
  assert.throws(() => decodeAggregate(output([2, 1]), 2, checked.selectedSlots))
})

test('missing, reordered, duplicated, unavailable or changed ciphertext data fail', () => {
  const entries = [entry(0, census.eligible[0].address, 0, 1), entry(1, census.eligible[1].address, 0, 2)]
  const root = transcriptRoot(entries)
  for (const mutate of [x => x.pop(), x => x.reverse(), x => x[0].ciphertext = '0x',
    x => x[0].ciphertext = '0xff', x => x[0].commitment = '0x' + '11'.repeat(32),
    x => x[1] = { ...x[0], index: '1' }, x => x[1].parentIndexPlusOne = '1']) {
    const altered = clone(entries); mutate(altered)
    assert.throws(() => checkTranscript(altered, census, manifest, root, '2', mockRuntime))
  }
  assert.throws(() => checkTranscript(entries, census, manifest, '1', '2', mockRuntime))
})

test('aggregate decoder enforces exact width, zero padding, zero totals and maximum supported totals', () => {
  assert.deepEqual(decodeAggregate(output([0, 0]), 2, 0), [0n, 0n])
  assert.deepEqual(decodeAggregate(output([20, 0, 0]), 3, 20), [20n, 0n, 0n])
  assert.throws(() => decodeAggregate('0x', 2, 20))
  assert.throws(() => decodeAggregate(output([1, 0, 1]), 2, 20))
  assert.throws(() => decodeAggregate(output([21, 0, 0]), 3, 20))
  assert.throws(() => decodeAggregate(output([10, 11]), 2, 20))
  assert.throws(() => decodeAggregate(output([1, 0]) + '00', 2, 20))
  assert.throws(() => decodeAggregate(output([1, 0]), 2, 21))
  for (const p of Object.values(profile.presets)) assert(BigInt(profile.maxEligibleSlots) < BigInt(p.plaintextModulus))
})
