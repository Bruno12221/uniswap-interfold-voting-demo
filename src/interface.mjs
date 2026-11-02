// SPDX-License-Identifier: LGPL-3.0-only
import { AbiCoder, getBytes, hexlify, keccak256, sha256, toUtf8Bytes } from 'ethers'
import { address, canonical, digest, hash32, keys } from './format.mjs'
import { assertRoundManifest, profile } from './round.mjs'
import { assertCoordinatorPolicy } from './coordinator-policy.mjs'

export const envelopeTypes = ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'bytes']
const abi = AbiCoder.defaultAbiCoder()
export function assertInterfaceConfig(config, approvedHash) {
  keys(config, ['schemaVersion', 'round', 'proposal', 'publicKey', 'configHash'])
  const { configHash, ...contents } = config
  if (config.schemaVersion !== 1 || configHash !== hash32(approvedHash) || digest(contents) !== configHash)
    throw new Error('Interface configuration is not approved')
  const r = config.round
  keys(r, ['schemaVersion', 'manifest', 'approvedManifestHash', 'census', 'approvedCensusHash', 'policy', 'approvedPolicyHash'])
  if (r.schemaVersion !== 1) throw new Error('Unsupported round')
  assertRoundManifest(r.manifest, r.approvedManifestHash, r.census, r.approvedCensusHash)
  assertCoordinatorPolicy(r.policy, r.approvedPolicyHash, r.manifest)
  const supported = (r.policy.assurance === 'development' && r.manifest.preset === 'insecure-512') ||
    (r.policy.assurance === 'secure-candidate' && r.manifest.preset === 'secure-8192')
  if (!supported || r.manifest.chainId !== '31337')
    throw new Error('This interface supports local synthetic development only')
  keys(config.proposal, ['title', 'text', 'url'])
  if (!config.proposal.title || config.proposal.title.length > 160 || !config.proposal.text || config.proposal.text.length > 16000 ||
      sha256(toUtf8Bytes(config.proposal.text)) !== r.census.context.proposalTextHash ||
      new URL(config.proposal.url).protocol !== 'https:') throw new Error('Proposal text or link is invalid')
  if (typeof config.publicKey !== 'string' || !/^0x(?:[0-9a-f]{2})+$/.test(config.publicKey) || config.publicKey.length > 2 ** 22)
    throw new Error('Invalid public key bytes')
  return config
}
export function decodeSubmission(encoded, manifest) {
  if (typeof encoded !== 'string' || !/^0x(?:[0-9a-f]{2})+$/.test(encoded) || encoded.length > 2 ** 22)
    throw new Error('Invalid public submission')
  const values = abi.decode(envelopeTypes, encoded)
  if (abi.encode(envelopeTypes, values) !== encoded) throw new Error('Noncanonical submission')
  const [proof, slot, commitment, ciphertextHash, parentIndexPlusOne, ciphertext] = values
  if (!getBytes(proof).length || !getBytes(ciphertext).length || keccak256(ciphertext) !== ciphertextHash ||
      BigInt(commitment) >= BigInt(profile.fieldModulus)) throw new Error('Invalid public submission')
  const identity = { slot: address(slot), commitment, ciphertextHash, parentIndexPlusOne: String(parentIndexPlusOne) }
  return { proof, ciphertext, identity, manifestHash: manifest.manifestHash }
}
export function sameInput(a, b) {
  return ['slot', 'commitment', 'ciphertextHash', 'parentIndexPlusOne'].every(key => a[key] === b[key])
}
export function submissionPhase(identity, snapshot) {
  if (!snapshot || snapshot.cached || !snapshot.state || snapshot.state.status === 'pending-rpc' || snapshot.state.reason)
    return 'Checking chain evidence'
  const entry = snapshot.ledger.find(x => sameInput(x, identity))
  if (!entry) return 'Submission pending'
  const disposition = snapshot.dispositions?.[Number(entry.index)]
  if (['superseded', 'stale-parent', 'unusable'].includes(disposition)) return 'Replaced or excluded'
  return entry.availability ? 'Availability confirmed' : 'Commitment confirmed'
}
export function developmentTotals(config, snapshot) {
  const state = snapshot?.state
  // A stale, partial, failed or incompatible response must never retain old totals.
  if (snapshot?.cached !== false || state?.status !== 'development-complete' || state.reason ||
      state.manifestHash !== config.round.approvedManifestHash || state.policyHash !== config.round.approvedPolicyHash ||
      state.result?.policyHash !== state.policyHash || config.round.policy.assurance !== 'development' ||
      !state.result.assurance?.startsWith('development proof checks;')) return null
  const totals = state.result.totals
  if (!Array.isArray(totals) || totals.length !== config.round.manifest.choices.length ||
      totals.some(x => typeof x !== 'string' || !/^(0|[1-9][0-9]*)$/.test(x)) ||
      totals.reduce((sum, x) => sum + BigInt(x), 0n) > BigInt(config.round.manifest.maxEffectiveTotal)) return null
  return totals
}
export function secureTotals(config, snapshot) {
  const state = snapshot?.state, r = config.round
  if (snapshot?.cached !== false || state?.status !== 'verified' || state.reason ||
      r.policy.assurance !== 'secure-candidate' || r.manifest.preset !== 'secure-8192' ||
      state.manifestHash !== r.approvedManifestHash || state.policyHash !== r.approvedPolicyHash ||
      state.result?.policyHash !== state.policyHash || state.result.imageId !== r.policy.guest.imageId ||
      state.result.assurance !== 'proof checked under reviewed deployment policy') return null
  // A configuration fingerprint alone is not approval for secure verification.
  try { assertCoordinatorPolicy(r.policy, r.approvedPolicyHash, r.manifest) } catch { return null }
  const totals = state.result.totals
  if (!Array.isArray(totals) || totals.length !== r.manifest.choices.length ||
      totals.some(x => typeof x !== 'string' || !/^(0|[1-9][0-9]*)$/.test(x)) ||
      totals.reduce((sum, x) => sum + BigInt(x), 0n) > BigInt(r.manifest.maxEffectiveTotal)) return null
  return totals
}
export const interfaceHash = config => digest(Object.fromEntries(Object.entries(config).filter(([key]) => key !== 'configHash')))

// The availability service returns a seven-field signed commitment, not the six-field staging envelope.
export function validateCommitmentPayload(fullEnvelope, compact, manifest, now) {
  const original = decodeSubmission(fullEnvelope, manifest)
  const types = ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'uint64', 'bytes']
  if (typeof compact !== 'string' || compact.length > fullEnvelope.length + 512) throw new Error('Invalid commitment payload')
  const values = abi.decode(types, compact)
  if (abi.encode(types, values) !== compact || values[0] !== original.proof || address(values[1]) !== original.identity.slot ||
      values[2] !== original.identity.commitment || values[3] !== original.identity.ciphertextHash ||
      String(values[4]) !== original.identity.parentIndexPlusOne || values[5] <= BigInt(now) || getBytes(values[6]).length !== 65)
    throw new Error('Availability service changed the ballot or returned an expired attestation')
  return compact
}
export function normalizeDelivery(value) {
  if (!value || !['success', 'pending_commitment', 'ready_for_commitment', 'pending_availability', 'failed_broadcast'].includes(value.status))
    throw new Error('Unrecognized submission route response')
  return { status: value.status, job_id: typeof value.job_id === 'string' ? value.job_id : null,
    encoded_proof: typeof value.encoded_proof === 'string' ? value.encoded_proof : null }
}

export function publicReceipt(encodedProof, manifest, slot) {
  const { identity } = decodeSubmission(encodedProof, manifest)
  if (identity.slot !== address(slot)) throw new Error('Receipt belongs to another account')
  return { schemaVersion: 1, manifestHash: manifest.manifestHash, identity, encodedProof }
}
export function restorePublicReceipt(value, manifest, slot) {
  keys(value, ['schemaVersion', 'manifestHash', 'identity', 'encodedProof'])
  const expected = publicReceipt(value.encodedProof, manifest, slot)
  if (canonical(value) !== canonical(expected)) throw new Error('Stored receipt belongs to another context')
  return expected
}
