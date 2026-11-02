// SPDX-License-Identifier: LGPL-3.0-only
import config from '../config/t05-profile.json' with { type: 'json' }
import { AbiCoder, Contract, TypedDataEncoder, toBeHex } from 'ethers'
import { verifyCensus } from './census.mjs'
import { address, canonical, digest, hash32, keys, uint } from './format.mjs'

export const profile = config
const INFO_KEYS = ['chainId', 'interfoldAddress', 'programAddress', 'registryAddress', 'e3Id', 'preset',
  'paramsHash', 'committeeKeyCommitment', 'inputStart', 'inputEnd', 'artifactsHash']
const ZERO = '0x' + '0'.repeat(40)
export const fieldHex = value => toBeHex(uint(BigInt(value).toString(), BigInt(profile.fieldModulus) - 1n), 32)
export const PROGRAM_READ_ABI = [
  'function getRoundData(uint256) view returns (uint256 merkleRoot,bytes32 paramsHash,uint256 numOptions,uint8 creditMode,uint256 inputRoot,uint40 numberOfVotes)',
  'function pendingInputCount(uint256) view returns (uint40)',
  'function inputCommitmentOf(uint256,address,uint40) view returns (bytes32)',
  'function ballotDigest(uint256,address,bytes32) view returns (bytes32)',
  'function inputCommitmentDeadline(uint256) view returns (uint256)',
]
export const INTERFOLD_READ_ABI = [
  'function getE3(uint256) view returns ((uint256 seed,uint8 committeeSize,uint256 requestBlock,uint256[2] inputWindow,bytes32 encryptionSchemeId,address e3Program,uint8 paramSet,bytes customParams,address decryptionVerifier,address pkVerifier,bytes32 committeePublicKey,bytes32 ciphertextOutput,bytes plaintextOutput,address requester,bytes32 ciphertextCommitment))',
  'function getE3Stage(uint256) view returns (uint8)',
]

export function makeRoundManifest(census, approvedCensusHash, info) {
  verifyCensus(census, census.context, census.records)
  if (census.manifestHash !== hash32(approvedCensusHash) || census.context.purpose !== 'synthetic-unit')
    throw new Error('Only an independently approved synthetic census may vote')
  keys(info, INFO_KEYS)
  const preset = profile.presets[info.preset]
  if (!preset || info.chainId !== '31337' || info.paramsHash !== preset.paramsHash) throw new Error('Unsupported round parameters')
  uint(info.e3Id); uint(info.inputStart); uint(info.inputEnd)
  if (BigInt(info.inputEnd) <= BigInt(info.inputStart)) throw new Error('Invalid input window')
  for (const name of ['interfoldAddress', 'programAddress', 'registryAddress'])
    if (address(info[name]) !== info[name] || info[name] === ZERO) throw new Error('Expected a canonical contract address')
  hash32(info.artifactsHash); hash32(info.committeeKeyCommitment)
  if (BigInt(info.committeeKeyCommitment) === 0n) throw new Error('Missing committee key')
  fieldHex(info.committeeKeyCommitment)
  const contents = { schemaVersion: 1, profile: profile.profile, ...info,
    censusManifestHash: census.manifestHash, censusRoot: census.root,
    proposalId: census.context.proposalId, proposalTextHash: census.context.proposalTextHash,
    choices: census.context.choices, maxEffectiveTotal: String(census.eligible.length), hardAdmissionLimit: preset.hardAdmissionLimit }
  return { ...contents, manifestHash: digest(contents) }
}

export function assertRoundManifest(manifest, approvedHash, census, approvedCensusHash) {
  const info = Object.fromEntries(INFO_KEYS.map(key => [key, manifest[key]]))
  const expected = makeRoundManifest(census, approvedCensusHash, info)
  if (hash32(approvedHash) !== expected.manifestHash || canonical(manifest) !== canonical(expected))
    throw new Error('Round does not match its approved manifest')
  return expected
}

export function ballotTypedData(manifest, slot, commitment) {
  return { domain: { name: 'CRISP', version: '1', chainId: manifest.chainId, verifyingContract: manifest.programAddress },
    types: { Ballot: [{ name: 'e3Id', type: 'uint256' }, { name: 'slot', type: 'address' },
      { name: 'ciphertextCommitment', type: 'bytes32' }] },
    value: { e3Id: manifest.e3Id, slot: address(slot), ciphertextCommitment: hash32(commitment) } }
}

export function ballotDigest(manifest, slot, commitment) {
  const { domain, types, value } = ballotTypedData(manifest, slot, commitment)
  return TypedDataEncoder.hash(domain, types, value)
}

export function expectedPublicInputs(manifest, slot, commitment, parentCommitment, first) {
  const hash = ballotDigest(manifest, slot, commitment)
  return [parentCommitment, BigInt('0x' + hash.slice(2, 34)), BigInt('0x' + hash.slice(34)),
    BigInt(address(slot)), BigInt(manifest.censusRoot), first ? 1n : 0n,
    BigInt(manifest.choices.length), commitment, manifest.committeeKeyCommitment].map(fieldHex)
}

export async function assertInputCommitmentWindow(provider, manifest, program) {
  const block = await provider.getBlock('latest')
  const deadline = await program.inputCommitmentDeadline(manifest.e3Id, { blockTag: block.number })
  if (deadline <= BigInt(manifest.inputStart) || deadline > BigInt(manifest.inputEnd) ||
      BigInt(block.timestamp) < BigInt(manifest.inputStart) || BigInt(block.timestamp) >= deadline)
    throw new Error('Input commitment window is not open')
}

export async function readBoundRound(provider, manifest, expectedStage, { blockTag } = {}) {
  const at = blockTag === undefined ? {} : { blockTag }
  if (BigInt(await provider.send('eth_chainId', [])) !== BigInt(manifest.chainId)) throw new Error('Wrong application chain')
  const protocol = new Contract(manifest.interfoldAddress, INTERFOLD_READ_ABI, provider)
  const program = new Contract(manifest.programAddress, PROGRAM_READ_ABI, provider)
  const registry = new Contract(manifest.registryAddress,
    ['function getManifestHash(address,address,uint256) view returns (bytes32)'], provider)
  if (await registry.getManifestHash(manifest.interfoldAddress, manifest.programAddress, manifest.e3Id, at) !== manifest.manifestHash)
    throw new Error('Round manifest is not frozen in the approved registry')
  const e3 = await protocol.getE3(manifest.e3Id, at)
  const round = await program.getRoundData(manifest.e3Id, at)
  const preset = profile.presets[manifest.preset]
  const custom = AbiCoder.defaultAbiCoder().decode(['address', 'uint256', 'uint256', 'uint8', 'uint256', 'uint256', 'uint256'], e3.customParams)
  if ((expectedStage !== undefined && Number(await protocol.getE3Stage(manifest.e3Id, at)) !== expectedStage) ||
      address(e3.e3Program) !== manifest.programAddress || Number(e3.paramSet) !== preset.paramSet ||
      e3.committeePublicKey !== manifest.committeeKeyCommitment || round.paramsHash !== manifest.paramsHash ||
      round.merkleRoot.toString() !== manifest.censusRoot || Number(round.numOptions) !== manifest.choices.length ||
      round.creditMode !== 0n || custom[2] !== round.numOptions || custom[3] !== 0n || custom[4] !== 1n || custom[5] > 1n ||
      e3.inputWindow[0].toString() !== manifest.inputStart || e3.inputWindow[1].toString() !== manifest.inputEnd)
    throw new Error('Actual round differs from the approved unit-credit context')
  return { protocol, program, e3, round }
}
