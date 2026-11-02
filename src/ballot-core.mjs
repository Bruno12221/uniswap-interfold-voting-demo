// SPDX-License-Identifier: LGPL-3.0-only
import { getBytes, hexlify, recoverAddress } from 'ethers'
import { address, canonical } from './format.mjs'
import { assertRoundManifest, assertInputCommitmentWindow, ballotDigest, ballotTypedData, expectedPublicInputs, readBoundRound } from './round.mjs'
import { isDelegatedEoaCode } from './wallet.mjs'

export function validateUnitVote(vote, numOptions, isMask) {
  if (typeof isMask !== 'boolean' || ![2, 3].includes(numOptions) || !Array.isArray(vote) || vote.length !== numOptions ||
      vote.some(x => !Number.isSafeInteger(x) || (x !== 0 && x !== 1)) ||
      vote.reduce((a, b) => a + b, 0) > 1 || (isMask && vote.some(x => x !== 0)))
    throw new Error('Ballot must contain one authorized unit or a documented zero contribution')
}

export function authenticatePublicKey(runtime, keyBytes, expectedCommitment) {
  const { core, params } = runtime
  const actual = hexlify(core.compute_pk_commitment(keyBytes, params.degree, params.plaintextModulus, BigUint64Array.from(params.moduli)))
  if (actual !== expectedCommitment) throw new Error('Public key does not match the authenticated committee commitment')
}

// The returned session contains a private witness. Keep it in the local proving boundary.
export async function prepareBoundBallot({ provider, manifest, approvedHash, census, approvedCensusHash,
  publicKey, slot, vote, isMask = false, previousCiphertext, previousIndex }, runtime, checkedArtifactsHash) {
  assertRoundManifest(manifest, approvedHash, census, approvedCensusHash)
  if (manifest.artifactsHash !== checkedArtifactsHash) throw new Error('Wrong proof artifact version')
  const state = await readBoundRound(provider, manifest, 3)
  await assertInputCommitmentWindow(provider, manifest, state.program)
  slot = address(slot)
  if (!census.eligible.some(x => x.address === slot && x.weight === '1')) throw new Error('Slot is not in the approved unit census')
  const code = await provider.getCode(slot)
  if (code !== '0x' && !isDelegatedEoaCode(code)) throw new Error('Contract-wallet ballots need a different circuit')
  validateUnitVote(vote, manifest.choices.length, isMask)
  authenticatePublicKey(runtime, publicKey, manifest.committeeKeyCommitment)
  let parentCommitment = '0x' + '00'.repeat(32)
  if (previousCiphertext !== undefined) {
    if (!Number.isSafeInteger(previousIndex) || previousIndex < 0 || previousIndex >= 2 ** 40 - 1)
      throw new Error('A previous ciphertext needs its exact parent index')
    parentCommitment = await state.program.inputCommitmentOf(manifest.e3Id, slot, previousIndex)
    if (parentCommitment === '0x' + '00'.repeat(32) || hexlify(runtime.generator.computeCtCommitment(previousCiphertext)) !== parentCommitment)
      throw new Error('Parent bytes do not match the onchain commitment')
  } else if (previousIndex !== undefined) throw new Error('A parent index needs its ciphertext')
  const prepared = await runtime.sdk.prepareBallot({ e3Id: BigInt(manifest.e3Id), publicKey,
    slotAddress: slot, isMaskVote: isMask, numOptions: manifest.choices.length, vote,
    censusMode: 'merkle', balance: 1n, merkleLeaves: census.eligible.map(x => BigInt(x.leaf)),
    ...(previousCiphertext === undefined ? {} : { previousCiphertext, previousIndex }) })
  if (prepared.parentIndexPlusOne !== (previousCiphertext === undefined ? 0 : previousIndex + 1))
    throw new Error('SDK prepared a different parent than the authenticated slot head')
  return { runtime, prepared, slot, isMask, parentCommitment, contextHash: manifest.manifestHash, contextJson: canonical(manifest) }
}

export async function finishBoundBallot(provider, manifest, session, signer) {
  if (session.contextHash !== manifest.manifestHash || session.contextJson !== canonical(manifest))
    throw new Error('Private session belongs to another round context')
  const { program } = await readBoundRound(provider, manifest, 3)
  await assertInputCommitmentWindow(provider, manifest, program)
  const { runtime, prepared, slot, isMask, parentCommitment } = session
  if (runtime.sdk.registeredPreset() !== manifest.preset) throw new Error('Concurrent preset switch refused')
  const digest = ballotDigest(manifest, slot, prepared.ctCommitment)
  if (await program.ballotDigest(manifest.e3Id, slot, prepared.ctCommitment) !== digest) throw new Error('Onchain signing domain differs')
  let proof
  if (isMask) proof = await runtime.sdk.finishMaskProof(prepared, digest)
  else {
    const { domain, types, value } = ballotTypedData(manifest, slot, prepared.ctCommitment)
    const signature = await signer.signTypedData(domain, types, value)
    if (address(recoverAddress(digest, signature)) !== slot) throw new Error('Wrong slot signer')
    proof = await runtime.sdk.finishBallotProof(prepared, digest, signature)
  }
  const expected = expectedPublicInputs(manifest, slot, prepared.ctCommitment, parentCommitment, prepared.parentIndexPlusOne === 0)
  if (proof.publicInputs.length !== expected.length || proof.publicInputs.some((x, i) => BigInt(x) !== BigInt(expected[i])))
    throw new Error('Proof statement differs from the frozen context')
  if (!await runtime.sdk.verifyProof(proof)) throw new Error('Ballot proof failed local verification')
  await assertInputCommitmentWindow(provider, manifest, program)
  // Only public ciphertext/proof material leaves this function, never the private session.
  return { ...proof, encryptedVote: getBytes(proof.encryptedVote) }
}
