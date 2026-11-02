// SPDX-License-Identifier: LGPL-3.0-only
import test from 'node:test'
import assert from 'node:assert/strict'
import { AbiCoder, keccak256, toBeHex } from 'ethers'
import { digest } from '../src/format.mjs'
import { decodeSubmission, developmentTotals, envelopeTypes, submissionPhase } from '../src/interface.mjs'

test('T07 public envelope rejects extra fields, changed bytes and noncanonical tails', () => {
  const bytes = '0x1234', proof = '0x123456', slot = '0x0000000000000000000000000000000000000011'
  const encoded = AbiCoder.defaultAbiCoder().encode(envelopeTypes, [proof, slot, toBeHex(1, 32), keccak256(bytes), 0, bytes])
  const decoded = decodeSubmission(encoded, { manifestHash: digest({ round: 'synthetic' }) })
  assert.equal(decoded.identity.slot, slot)
  assert.throws(() => decodeSubmission(encoded + '00'.repeat(32), {}))
  assert.throws(() => decodeSubmission(encoded.replace(/1234000/, '1334000'), {}))
})
test('T07 inclusion follows confirmed ledger rather than transport acceptance', () => {
  const identity = { slot: 's', commitment: 'c', ciphertextHash: 'h', parentIndexPlusOne: '0' }
  const snapshot = { cached: false, state: { status: 'voting-open', reason: null }, ledger: [], dispositions: [] }
  assert.equal(submissionPhase(identity, snapshot), 'Submission pending')
  snapshot.ledger.push({ ...identity, index: '0', availability: null }); snapshot.dispositions.push('selected')
  assert.equal(submissionPhase(identity, snapshot), 'Commitment confirmed')
  snapshot.ledger[0].availability = { block: '1' }
  assert.equal(submissionPhase(identity, snapshot), 'Availability confirmed')
  snapshot.dispositions[0] = 'superseded'
  assert.equal(submissionPhase(identity, snapshot), 'Replaced or excluded')
  snapshot.state.reason = 'RPC_UNAVAILABLE'
  assert.equal(submissionPhase(identity, snapshot), 'Checking chain evidence')
})
test('T07 totals disappear on stale, failed, partial or mismatched evidence', () => {
  const config = { round: { approvedManifestHash: 'mh', approvedPolicyHash: 'ph', policy: { assurance: 'development' },
    manifest: { choices: ['a', 'b', 'c'], maxEffectiveTotal: '20' } } }
  const good = { cached: false, state: { status: 'development-complete', reason: null, manifestHash: 'mh', policyHash: 'ph',
    result: { policyHash: 'ph', totals: ['1', '1', '0'], assurance: 'development proof checks; mock cryptography permitted; no secure attestation' } } }
  assert.deepEqual(developmentTotals(config, good), ['1', '1', '0'])
  for (const mutate of [x => x.cached = true, x => x.state.status = 'verified', x => x.state.status = 'failed-computation',
    x => x.state.reason = 'CHECK_FAILED', x => x.state.policyHash = 'other', x => x.state.manifestHash = 'other',
    x => x.state.result.assurance = 'secure', x => x.state.result.totals = ['21', '0', '0'], x => x.state.result.totals = ['1', '1']]) {
    const changed = structuredClone(good); mutate(changed); assert.equal(developmentTotals(config, changed), null)
  }
})

test('T07 wallet commitment binds the service attestation to the exact proven input', async () => {
  const { validateCommitmentPayload, normalizeDelivery } = await import('../src/interface.mjs')
  const abi = AbiCoder.defaultAbiCoder(), ct = '0x1234', slot = '0x0000000000000000000000000000000000000011'
  const fields = ['0x123456', slot, toBeHex(1, 32), keccak256(ct), 0]
  const full = abi.encode(envelopeTypes, [...fields, ct])
  const types = ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'uint64', 'bytes']
  const compact = abi.encode(types, [...fields, 200, '0x' + '11'.repeat(65)])
  assert.equal(validateCommitmentPayload(full, compact, {}, 100), compact)
  assert.throws(() => validateCommitmentPayload(full, compact, {}, 200))
  for (const index of [0, 1, 2, 3, 4]) {
    const changed = [...fields]
    changed[index] = index === 0 ? '0x00' : index === 1 ? '0x0000000000000000000000000000000000000012' : index === 4 ? 1 : toBeHex(2, 32)
    assert.throws(() => validateCommitmentPayload(full, abi.encode(types, [...changed, 200, '0x' + '11'.repeat(65)]), {}, 100))
  }
  assert.throws(() => normalizeDelivery({ status: 'counted' }))
  assert.deepEqual(normalizeDelivery({ status: 'pending_commitment', message: 'untrusted service detail' }),
    { status: 'pending_commitment', encoded_proof: null, job_id: null })
})

test('T07 reload restores only the public envelope bound to its account and manifest', async () => {
  const { publicReceipt, restorePublicReceipt } = await import('../src/interface.mjs')
  const slot = '0x0000000000000000000000000000000000000011', bytes = '0x1234'
  const encoded = AbiCoder.defaultAbiCoder().encode(envelopeTypes, ['0x123456', slot, toBeHex(1, 32), keccak256(bytes), 0, bytes])
  const manifest = { manifestHash: digest({ synthetic: 'round' }) }
  const receipt = publicReceipt(encoded, manifest, slot)
  assert.deepEqual(restorePublicReceipt(JSON.parse(JSON.stringify(receipt)), manifest, slot), receipt)
  assert.throws(() => restorePublicReceipt(receipt, { manifestHash: digest({ other: 'round' }) }, slot))
  assert.throws(() => restorePublicReceipt(receipt, manifest, '0x0000000000000000000000000000000000000012'))
  assert.throws(() => restorePublicReceipt({ ...receipt, vote: [1, 0, 0] }, manifest, slot))
})
