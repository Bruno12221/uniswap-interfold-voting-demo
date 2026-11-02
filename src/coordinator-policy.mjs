// SPDX-License-Identifier: LGPL-3.0-only
import reviewed from '../config/t06-approved-secure-policies.json' with { type: 'json' }
import { Contract, keccak256, toUtf8Bytes } from 'ethers'
import { address, canonical, digest, hash32, keys, uint } from './format.mjs'
import { RECEIPT_ABI, abi, requireThat } from './coordinator-protocol.mjs'

const ROLE_NAMES = ['protocol', 'program', 'contextRegistry', 'committeeRegistry', 'pkVerifier', 'decryptionVerifier',
  'receiptVerifier', 'halo2Verifier', 'dataAvailabilityVerifier']
const GETTERS = ['interfold', 'openVmVerifier', 'dataAvailabilityVerifier', 'verifier', 'ciphernodeRegistry', 'circuitVerifier', 'bridge', 'vectorx']
const IMPLEMENTATION = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
const BEACON = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'

export function makeCoordinatorPolicy(input, manifest) {
  keys(input, ['schemaVersion', 'manifestHash', 'assurance', 'anchor', 'confirmations', 'scanBatchSize', 'contracts', 'edges', 'guest'])
  requireThat(input.schemaVersion === 1 && input.manifestHash === manifest.manifestHash &&
    ['development', 'secure-candidate'].includes(input.assurance), 'INVALID_POLICY')
  keys(input.anchor, ['number', 'hash']); uint(input.anchor.number, BigInt(Number.MAX_SAFE_INTEGER)); hash32(input.anchor.hash)
  requireThat(Number.isSafeInteger(input.confirmations) && input.confirmations >= 1 && input.confirmations <= 64 &&
    Number.isSafeInteger(input.scanBatchSize) && input.scanBatchSize >= 1 && input.scanBatchSize <= 1000, 'INVALID_SCAN_POLICY')
  requireThat(input.contracts && Object.getPrototypeOf(input.contracts) === Object.prototype &&
    ROLE_NAMES.every(role => Object.hasOwn(input.contracts, role)), 'MISSING_DEPLOYMENT_ROLE')
  for (const [role, c] of Object.entries(input.contracts)) {
    requireThat(/^[A-Za-z][A-Za-z0-9]{0,40}$/.test(role), 'INVALID_DEPLOYMENT_ROLE')
    keys(c, ['address', 'runtimeHash', 'implementation'])
    requireThat(address(c.address) === c.address && BigInt(c.address) !== 0n, 'INVALID_CONTRACT_ADDRESS')
    hash32(c.runtimeHash)
    if (c.implementation !== null) {
      keys(c.implementation, ['address', 'runtimeHash']); hash32(c.implementation.runtimeHash)
      requireThat(address(c.implementation.address) === c.implementation.address && BigInt(c.implementation.address) !== 0n, 'INVALID_IMPLEMENTATION')
    }
  }
  for (const [role, expected] of [['protocol', manifest.interfoldAddress], ['program', manifest.programAddress], ['contextRegistry', manifest.registryAddress]])
    requireThat(input.contracts[role].address === expected, 'POLICY_ROUND_MISMATCH')
  requireThat(Array.isArray(input.edges), 'INVALID_DEPLOYMENT_EDGES')
  for (const edge of input.edges) {
    keys(edge, ['from', 'getter', 'to'])
    requireThat(input.contracts[edge.from] && input.contracts[edge.to] && GETTERS.includes(edge.getter), 'INVALID_DEPLOYMENT_EDGE')
  }
  for (const [from, getter, to] of [['program', 'interfold', 'protocol'], ['program', 'openVmVerifier', 'receiptVerifier'],
    ['program', 'dataAvailabilityVerifier', 'dataAvailabilityVerifier'], ['receiptVerifier', 'verifier', 'halo2Verifier'],
    ['decryptionVerifier', 'ciphernodeRegistry', 'committeeRegistry']])
    requireThat(input.edges.some(x => x.from === from && x.getter === getter && x.to === to), 'MISSING_DEPLOYMENT_EDGE')
  keys(input.guest, ['imageId', 'appExeCommit', 'appVmCommit'])
  Object.values(input.guest).forEach(hash32)
  const image = keccak256(abi.encode(['bytes32', 'address', 'bytes32', 'bytes32'],
    [keccak256(toUtf8Bytes('INTERFOLD_OPENVM_RECEIPT_V1')), input.contracts.halo2Verifier.address, input.guest.appExeCommit, input.guest.appVmCommit]))
  requireThat(image === input.guest.imageId, 'WRONG_GUEST_IMAGE')
  return { ...structuredClone(input), policyHash: digest(input) }
}

export function assertCoordinatorPolicy(policy, approvedHash, manifest) {
  const { policyHash, ...input } = policy
  const rebuilt = makeCoordinatorPolicy(input, manifest)
  requireThat(hash32(approvedHash) === rebuilt.policyHash && canonical(policy) === canonical(rebuilt), 'UNAPPROVED_POLICY')
  if (policy.assurance === 'secure-candidate')
    requireThat(manifest.preset === 'secure-8192' && reviewed.schemaVersion === 1 && reviewed.policyHashes.includes(policyHash), 'SECURE_POLICY_NOT_REVIEWED')
  return policy
}

export async function verifyDeployment(provider, policy, blockTag) {
  const at = { blockTag }
  for (const c of Object.values(policy.contracts)) {
    const code = await provider.getCode(c.address, blockTag)
    requireThat(code !== '0x' && keccak256(code) === c.runtimeHash, 'DEPLOYMENT_CODE_CHANGED')
    const impl = await provider.getStorage(c.address, IMPLEMENTATION, blockTag)
    const beacon = await provider.getStorage(c.address, BEACON, blockTag)
    requireThat(BigInt(beacon) === 0n, 'UNSUPPORTED_BEACON_PROXY')
    if (c.implementation === null) requireThat(BigInt(impl) === 0n, 'UNEXPECTED_PROXY')
    else {
      requireThat(BigInt(impl) === BigInt(c.implementation.address), 'PROXY_IMPLEMENTATION_CHANGED')
      const implementationCode = await provider.getCode(c.implementation.address, blockTag)
      requireThat(implementationCode !== '0x' && keccak256(implementationCode) === c.implementation.runtimeHash, 'IMPLEMENTATION_CODE_CHANGED')
    }
  }
  for (const edge of policy.edges) {
    const contract = new Contract(policy.contracts[edge.from].address, [`function ${edge.getter}() view returns (address)`], provider)
    requireThat(address(await contract[edge.getter](at)) === policy.contracts[edge.to].address, 'DEPLOYMENT_WIRING_CHANGED')
  }
  const receipt = new Contract(policy.contracts.receiptVerifier.address, RECEIPT_ABI, provider)
  for (const field of ['imageId', 'appExeCommit', 'appVmCommit'])
    requireThat(await receipt[field](at) === policy.guest[field], 'GUEST_IDENTITY_CHANGED')
}
