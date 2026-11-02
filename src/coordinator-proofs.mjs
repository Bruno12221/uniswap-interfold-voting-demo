// SPDX-License-Identifier: LGPL-3.0-only
import { Contract, concat, getBytes, hexlify, keccak256, sha256 } from 'ethers'
import { address, keys } from './format.mjs'
import { authenticatePublicKey } from './ballot.mjs'
import { checkTranscript, decodeAggregate } from './transcript.mjs'
import { loadProofRuntime, checkLockedArtifacts } from './upstream.mjs'
import { COMMITTEE_ABI, PK_ABI, DECRYPT_ABI, RECEIPT_ABI, DA_ABI, PROGRAM_ABI,
  abi, SCHEME, computeJournal, decryptionDomain, requireThat, CoordinationError, isRpcError } from './coordinator-protocol.mjs'

export function assertProofBundle(bundle, manifest, policy) {
  keys(bundle, ['schemaVersion', 'manifestHash', 'policyHash', 'publicKey', 'pkProof', 'computeProof',
    'outputCiphertext', 'outputAvailabilityProof', 'inputAvailabilityProofs', 'decryptionProof'])
  requireThat(bundle.schemaVersion === 1 && bundle.manifestHash === manifest.manifestHash && bundle.policyHash === policy.policyHash,
    'PROOF_BUNDLE_CONTEXT_MISMATCH')
  for (const name of ['publicKey', 'pkProof', 'computeProof', 'outputCiphertext', 'outputAvailabilityProof', 'decryptionProof'])
    requireThat(typeof bundle[name] === 'string' && /^0x(?:[0-9a-f]{2})+$/.test(bundle[name]) && bundle[name].length <= 16 * 1024 * 1024 + 2, 'INVALID_PUBLIC_PROOF_BYTES')
  requireThat(Array.isArray(bundle.inputAvailabilityProofs) && bundle.inputAvailabilityProofs.length <= Number(manifest.hardAdmissionLimit), 'INVALID_INPUT_RECEIPTS')
  const indices = new Set()
  for (const item of bundle.inputAvailabilityProofs) {
    keys(item, ['index', 'proof'])
    requireThat(/^(0|[1-9][0-9]*)$/.test(item.index) && !indices.has(item.index) &&
      typeof item.proof === 'string' && /^0x(?:[0-9a-f]{2})+$/.test(item.proof), 'INVALID_INPUT_RECEIPT')
    indices.add(item.index)
  }
  return bundle
}

async function validProof(operation, code, expectsBoolean = true) {
  try {
    const result = await operation()
    requireThat(!expectsBoolean || result === true, code)
    return result
  } catch (error) {
    if (isRpcError(error)) throw error
    throw new CoordinationError(code)
  }
}

export async function verifyRoundProofs({ provider, manifest, policy, bundle, ledger, output, plaintext, snapshot, getCiphertext, blockTag }) {
  assertProofBundle(bundle, manifest, policy)
  requireThat(await checkLockedArtifacts() === manifest.artifactsHash, 'ARTIFACT_LOCK_CHANGED')
  const runtime = await loadProofRuntime(manifest.preset)
  const at = { blockTag }, { e3, round } = snapshot
  requireThat(e3.encryptionSchemeId === SCHEME && address(e3.pkVerifier) === policy.contracts.pkVerifier.address &&
    address(e3.decryptionVerifier) === policy.contracts.decryptionVerifier.address, 'VERIFIER_CONTEXT_CHANGED')
  authenticatePublicKey(runtime, getBytes(bundle.publicKey), manifest.committeeKeyCommitment)
  const registry = new Contract(policy.contracts.committeeRegistry.address, COMMITTEE_ABI, provider)
  const nodes = Array.from(await registry.getCommitteeNodes(manifest.e3Id, at), address)
  const committeeHash = await registry.getCommitteeHash(manifest.e3Id, at)
  requireThat(nodes.length > 0 && new Set(nodes.map(address)).size === nodes.length &&
    nodes.every(x => BigInt(x) !== 0n) && keccak256(concat(nodes.map(address))) === committeeHash, 'COMMITTEE_HASH_MISMATCH')
  const pk = new Contract(policy.contracts.pkVerifier.address, PK_ABI, provider)
  const committeeRoot = await registry.rootAt(manifest.e3Id, at)
  await validProof(() => pk.verify(manifest.e3Id, committeeRoot, nodes,
    manifest.committeeKeyCommitment, committeeHash, bundle.pkProof, at), 'INVALID_COMMITTEE_PROOF')

  requireThat(bundle.inputAvailabilityProofs.length === ledger.length, 'INCOMPLETE_INPUT_RECEIPTS')
  const da = new Contract(policy.contracts.dataAvailabilityVerifier.address, DA_ABI, provider)
  const entries = []
  for (const entry of ledger) {
    const bytes = getCiphertext(entry.ciphertextHash)
    requireThat(bytes !== undefined, 'MISSING_CIPHERTEXT')
    const proof = bundle.inputAvailabilityProofs.find(x => x.index === entry.index)
    requireThat(proof && entry.availability, 'MISSING_AVAILABILITY_RECEIPT')
    const receipt = await validProof(() => da.verifyDataAvailability(entry.ciphertextHash, proof.proof, at), 'INVALID_INPUT_AVAILABILITY', false)
    requireThat(receipt.contentHash === entry.ciphertextHash && receipt.blockNumber.toString() === entry.availability.block &&
      receipt.leafIndex.toString() === entry.availability.leafIndex, 'INPUT_AVAILABILITY_MISMATCH')
    entries.push({ index: entry.index, slot: entry.slot, commitment: entry.commitment, ciphertextHash: entry.ciphertextHash,
      parentIndexPlusOne: entry.parentIndexPlusOne, ciphertext: hexlify(bytes) })
  }
  const transcript = checkTranscript(entries, snapshot.census, manifest, round.inputRoot.toString(), round.numberOfVotes.toString(), runtime)
  requireThat(output && plaintext && output.contentHash === e3.ciphertextOutput && output.commitment === e3.ciphertextCommitment &&
    plaintext.plaintext === e3.plaintextOutput && plaintext.proof === bundle.decryptionProof, 'OUTPUT_EVENT_MISMATCH')
  requireThat(keccak256(bundle.outputCiphertext) === e3.ciphertextOutput &&
    hexlify(runtime.generator.computeCtCommitment(getBytes(bundle.outputCiphertext))) === e3.ciphertextCommitment, 'OUTPUT_CIPHERTEXT_MISMATCH')
  const outputReceipt = await validProof(() => da.verifyDataAvailability(e3.ciphertextOutput, bundle.outputAvailabilityProof, at), 'INVALID_OUTPUT_AVAILABILITY', false)
  requireThat(outputReceipt.contentHash === e3.ciphertextOutput && outputReceipt.blockNumber.toString() === output.availabilityBlock &&
    outputReceipt.leafIndex.toString() === output.availabilityLeafIndex, 'OUTPUT_AVAILABILITY_MISMATCH')
  const [seal, paramsHash, inputRoot] = abi.decode(['bytes', 'bytes32', 'bytes32'], bundle.computeProof)
  requireThat(seal !== '0x' && paramsHash === manifest.paramsHash && BigInt(inputRoot) === BigInt(transcript.root) &&
    abi.encode(['bytes', 'bytes32', 'bytes32'], [seal, paramsHash, inputRoot]) === bundle.computeProof, 'COMPUTE_ENVELOPE_MISMATCH')
  const journal = computeJournal(manifest, e3.ciphertextOutput, e3.ciphertextCommitment, transcript.root)
  const journalDigest = sha256(journal)
  const receiptVerifier = new Contract(policy.contracts.receiptVerifier.address, RECEIPT_ABI, provider)
  await validProof(() => receiptVerifier.verify(seal, policy.guest.imageId, journalDigest, at), 'INVALID_COMPUTATION_PROOF', false)
  const program = new Contract(manifest.programAddress, PROGRAM_ABI, provider)
  await validProof(() => program.verify(manifest.e3Id, e3.ciphertextOutput, e3.ciphertextCommitment, bundle.computeProof, at), 'INVALID_PROGRAM_PROOF')
  const decryption = new Contract(policy.contracts.decryptionVerifier.address, DECRYPT_ABI, provider)
  await validProof(() => decryption.verify(manifest.e3Id, decryptionDomain(manifest, committeeHash, e3.ciphertextOutput),
    keccak256(e3.plaintextOutput), committeeHash, e3.ciphertextCommitment, bundle.decryptionProof, at), 'INVALID_DECRYPTION_PROOF')
  const totals = decodeAggregate(e3.plaintextOutput, manifest.choices.length, transcript.selectedSlots).map(String)
  return { totals, transcript, journalDigest, imageId: policy.guest.imageId, policyHash: policy.policyHash,
    assurance: policy.assurance === 'development' ? 'development proof checks; mock cryptography permitted; no secure attestation' : 'proof checked under reviewed deployment policy' }
}
