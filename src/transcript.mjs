// SPDX-License-Identifier: LGPL-3.0-only
import { getBytes, hexlify, keccak256, sha256, solidityPacked } from 'ethers'
import { poseidon2 } from 'poseidon-lite'
import { address, hash32, keys, uint } from './format.mjs'
import { assertRoundManifest, profile, readBoundRound } from './round.mjs'
import { checkLockedArtifacts, loadProofRuntime } from './upstream.mjs'

export function inputLeaf(entry) {
  return BigInt(sha256(solidityPacked(['bytes32', 'bytes32', 'address', 'uint40'],
    [hash32(entry.ciphertextHash), hash32(entry.commitment), address(entry.slot),
      uint(entry.parentIndexPlusOne, (1n << 40n) - 1n)]))) % BigInt(profile.fieldModulus)
}

// CRISP input roots use zero-padded LazyIMT semantics, not the census's LeanIMT.
export function transcriptRoot(entries) {
  let width = 2
  while (width < entries.length) width *= 2
  let level = entries.map(inputLeaf)
  level.push(...Array(width - level.length).fill(0n))
  while (level.length > 1) {
    const next = []
    for (let i = 0; i < level.length; i += 2) next.push(poseidon2([level[i], level[i + 1]]))
    level = next
  }
  return level[0].toString()
}

export function checkTranscript(entries, census, manifest, expectedRoot, expectedCount, runtime) {
  if (!Array.isArray(entries) || BigInt(entries.length) !== uint(expectedCount, BigInt(manifest.hardAdmissionLimit)))
    throw new Error('Complete admitted input count is required')
  const seen = new Set(), heads = new Map(), dispositions = []
  for (let index = 0; index < entries.length; index++) {
    const e = entries[index]
    keys(e, ['index', 'slot', 'commitment', 'ciphertextHash', 'parentIndexPlusOne', 'ciphertext'])
    if (e.index !== String(index) || address(e.slot) !== e.slot || !census.eligible.some(x => x.address === e.slot))
      throw new Error('Transcript order or slot is invalid')
    if (uint(e.parentIndexPlusOne, (1n << 40n) - 1n) > BigInt(index)) throw new Error('Parent must precede its input')
    const identity = JSON.stringify([e.slot, e.commitment, e.ciphertextHash, e.parentIndexPlusOne])
    if (seen.has(identity)) throw new Error('Duplicate admitted input identity')
    seen.add(identity)
    const bytes = getBytes(e.ciphertext)
    if (!bytes.length || keccak256(bytes) !== hash32(e.ciphertextHash) ||
        hexlify(runtime.generator.computeCtCommitment(bytes)) !== hash32(e.commitment))
      throw new Error('Required ciphertext bytes do not match their admitted identity')
    const parent = e.parentIndexPlusOne === '0' ? undefined : Number(BigInt(e.parentIndexPlusOne) - 1n)
    if (parent !== undefined && entries[parent].slot !== e.slot) throw new Error('Parent belongs to another slot')
    if (parent !== heads.get(e.slot)) { dispositions.push('stale-parent'); continue }
    if (parent !== undefined) dispositions[parent] = 'superseded'
    heads.set(e.slot, index)
    dispositions.push('selected')
  }
  const root = transcriptRoot(entries)
  if (root !== expectedRoot) throw new Error('Complete input root differs from the chain')
  return { root, admittedInputs: entries.length, selectedSlots: heads.size, dispositions,
    selectedIndices: [...heads.values()].sort((a, b) => a - b) }
}

export function decodeAggregate(output, numOptions, maxUnits) {
  if (![2, 3].includes(numOptions) || !Number.isSafeInteger(maxUnits) || maxUnits < 0 || maxUnits > profile.maxEligibleSlots)
    throw new Error('Unsupported aggregate bounds')
  const bytes = getBytes(output)
  if (bytes.length !== profile.outputCoefficients * 8) throw new Error('Expected exactly 400 output bytes')
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const words = Array.from({ length: profile.outputCoefficients }, (_, i) => view.getBigUint64(i * 8, true))
  const totals = words.slice(0, numOptions)
  if (words.slice(numOptions).some(x => x !== 0n) || totals.some(x => x > BigInt(maxUnits)) ||
      totals.reduce((a, b) => a + b, 0n) > BigInt(maxUnits)) throw new Error('Output violates unit totals or zero padding')
  return totals
}

// Checks public mechanics only. Real protocol-verifier identities/proofs remain a separate gate.
export async function checkPublicResult({ provider, manifest, approvedHash, census, approvedCensusHash, entries }) {
  assertRoundManifest(manifest, approvedHash, census, approvedCensusHash)
  if (manifest.artifactsHash !== await checkLockedArtifacts()) throw new Error('Wrong proof artifacts')
  const runtime = await loadProofRuntime(manifest.preset)
  const { program, e3, round } = await readBoundRound(provider, manifest, 5)
  if (await program.pendingInputCount(manifest.e3Id) !== 0n) throw new Error('Availability is incomplete')
  const transcript = checkTranscript(entries, census, manifest, round.inputRoot.toString(), round.numberOfVotes.toString(), runtime)
  const totals = decodeAggregate(e3.plaintextOutput, manifest.choices.length, transcript.selectedSlots)
  return { totals: totals.map(String), transcript, assurance: 'public mechanics only; not a secure proof-path attestation' }
}
