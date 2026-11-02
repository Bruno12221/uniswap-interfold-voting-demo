// SPDX-License-Identifier: LGPL-3.0-only
import { AbiCoder, Interface, keccak256, toUtf8Bytes } from 'ethers'
import { PROGRAM_READ_ABI, INTERFOLD_READ_ABI } from './round.mjs'
import { address, hash32, uint } from './format.mjs'

export const abi = AbiCoder.defaultAbiCoder()
export const SCHEME = keccak256(toUtf8Bytes('fhe.rs:BFV'))
export const PROGRAM_ABI = [...PROGRAM_READ_ABI,
  'function interfold() view returns (address)', 'function openVmVerifier() view returns (address)',
  'function imageId() view returns (bytes32)', 'function dataAvailabilityVerifier() view returns (address)',
  'function verify(uint256,bytes32,bytes32,bytes) view returns (bool)',
  'function finalizeInput(uint256,address,bytes32,bytes32,uint40,bytes)',
  'event InputCommitted(uint256 indexed e3Id,bytes32 indexed inputId,address indexed slotAddress,bytes32 encryptedVoteCommitment,bytes32 encryptedVoteHash,uint40 parentIndexPlusOne,uint40 index)',
  'event InputPublished(uint256 indexed e3Id,address indexed slotAddress,bytes32 encryptedVoteCommitment,bytes32 encryptedVoteHash,uint32 availabilityBlock,uint128 availabilityLeafIndex,uint256 index,uint40 parentIndexPlusOne)',
]
export const PROTOCOL_ABI = [...INTERFOLD_READ_ABI,
  'function getDeadlines(uint256) view returns ((uint256 dkgDeadline,uint256 computeDeadline,uint256 decryptionDeadline))',
  'function publishCiphertextOutput(uint256,bytes)', 'function publishPlaintextOutput(uint256,bytes,bytes) returns (bool)',
  'event CiphertextOutputReferencePublished(uint256 indexed e3Id,bytes32 contentHash,bytes32 ciphertextCommitment,uint32 availabilityBlock,uint128 availabilityLeafIndex)',
  'event PlaintextOutputPublished(uint256 indexed e3Id,bytes plaintextOutput,bytes proof)',
]
export const COMMITTEE_ABI = [
  'function getCommitteeNodes(uint256) view returns (address[])',
  'function getCommitteeHash(uint256) view returns (bytes32)', 'function rootAt(uint256) view returns (uint256)',
]
export const PK_ABI = ['function verify(uint256,uint256,address[],bytes32,bytes32,bytes) view returns (bool)']
export const DECRYPT_ABI = ['function verify(uint256,bytes32,bytes32,bytes32,bytes32,bytes) view returns (bool)']
export const RECEIPT_ABI = ['function appExeCommit() view returns (bytes32)', 'function appVmCommit() view returns (bytes32)',
  'function imageId() view returns (bytes32)', 'function verifier() view returns (address)',
  'function verify(bytes,bytes32,bytes32) view']
export const DA_ABI = ['function verifyDataAvailability(bytes32,bytes) view returns ((bytes32 contentHash,uint32 blockNumber,uint128 leafIndex))']
export const programInterface = new Interface(PROGRAM_ABI)
export const protocolInterface = new Interface(PROTOCOL_ABI)
const events = [[programInterface, ['InputCommitted', 'InputPublished']],
  [protocolInterface, ['CiphertextOutputReferencePublished', 'PlaintextOutputPublished']]]
export const EVENT_TOPICS = events.flatMap(([iface, names]) => names.map(name => iface.getEvent(name).topicHash))

export class CoordinationError extends Error { constructor(code) { super(code); this.code = code } }
export const requireThat = (condition, code) => { if (!condition) throw new CoordinationError(code) }
export const isRpcError = e => ['NETWORK_ERROR', 'SERVER_ERROR', 'TIMEOUT', 'UNKNOWN_ERROR', 'ECONNRESET', 'ECONNREFUSED'].includes(e?.code)

export function inputId(manifest, entry) {
  return keccak256(abi.encode(['string', 'address', 'uint256', 'bytes32', 'bytes32', 'address', 'uint40'],
    ['CRISP_INPUT_V1', manifest.programAddress, manifest.e3Id, entry.ciphertextHash, entry.commitment, entry.slot, entry.parentIndexPlusOne]))
}

export function normalizeLog(log, manifest) {
  requireThat(!log.removed && Number.isSafeInteger(log.index) && log.index >= 0, 'INVALID_LOG')
  const match = events.find(([iface, names]) => names.some(name => iface.getEvent(name).topicHash === log.topics[0]))
  requireThat(match, 'UNEXPECTED_LOG')
  const [iface] = match, decoded = iface.parseLog(log), a = decoded.args
  const emitter = iface === programInterface ? manifest.programAddress : manifest.interfoldAddress
  requireThat(address(log.address) === emitter && a.e3Id.toString() === manifest.e3Id, 'WRONG_EVENT_CONTEXT')
  const base = { event: decoded.name, blockNumber: String(log.blockNumber), blockHash: hash32(log.blockHash),
    transactionHash: hash32(log.transactionHash), logIndex: log.index, emitter }
  if (decoded.name === 'PlaintextOutputPublished') return { ...base, plaintext: a.plaintextOutput, proof: a.proof }
  if (decoded.name === 'CiphertextOutputReferencePublished') return { ...base, contentHash: a.contentHash,
    commitment: a.ciphertextCommitment, availabilityBlock: a.availabilityBlock.toString(), availabilityLeafIndex: a.availabilityLeafIndex.toString() }
  return { ...base, index: a.index.toString(), slot: address(a.slotAddress), commitment: a.encryptedVoteCommitment,
    ciphertextHash: a.encryptedVoteHash, parentIndexPlusOne: a.parentIndexPlusOne.toString(),
    ...(decoded.name === 'InputCommitted' ? { inputId: a.inputId } :
      { availabilityBlock: a.availabilityBlock.toString(), availabilityLeafIndex: a.availabilityLeafIndex.toString() }) }
}

export function computeJournal(manifest, ciphertextHash, ciphertextCommitment, inputRoot) {
  return abi.encode(Array(9).fill('bytes32'), [BigInt(manifest.chainId), BigInt(manifest.interfoldAddress), BigInt(manifest.e3Id),
    SCHEME, manifest.committeeKeyCommitment, ciphertextHash, ciphertextCommitment, manifest.paramsHash, BigInt(inputRoot)]
    .map(x => typeof x === 'bigint' ? '0x' + x.toString(16).padStart(64, '0') : hash32(x)))
}

export function decryptionDomain(manifest, committeeHash, ciphertextHash) {
  return keccak256(abi.encode(['uint256', 'address', 'uint256', 'bytes32', 'bytes32', 'bytes32'],
    [manifest.chainId, manifest.interfoldAddress, manifest.e3Id, committeeHash, ciphertextHash, manifest.committeeKeyCommitment]))
}

export function phaseAt(stage, timestamp, inputStart, commitmentDeadline, inputEnd, computeDeadline, decryptionDeadline, pending) {
  const now = uint(String(timestamp))
  if (stage === 6) return 'failed-protocol'
  if (stage === 5) return 'checking-result'
  if (stage === 4) return now > BigInt(decryptionDeadline) ? 'failed-decryption-deadline' : 'decrypting'
  requireThat(stage === 3, 'UNEXPECTED_STAGE')
  if (now > BigInt(computeDeadline)) return pending ? 'failed-availability-deadline' : 'failed-compute-deadline'
  if (now < BigInt(inputStart)) return 'awaiting-input-window'
  if (now < BigInt(commitmentDeadline)) return 'voting-open'
  if (pending) return 'awaiting-availability'
  return now < BigInt(inputEnd) ? 'commitments-closed' : 'computing'
}
