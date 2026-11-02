// SPDX-License-Identifier: LGPL-3.0-only
import { LeanIMT } from '@zk-kit/lean-imt'
import { poseidon2 } from 'poseidon-lite'
import { address, canonical, digest, hash32, keys, uint } from './format.mjs'
import { reference } from './reference.mjs'

export const MAX_RAW_WEIGHT = (1n << 96n) - 1n
const CONTEXT_KEYS = ['schemaVersion', 'purpose', 'space', 'proposalId', 'proposalTextHash', 'choices',
  'sourceChainId', 'snapshotBlock', 'snapshotBlockHash', 'strategy', 'units', 'authority', 'electorateScope', 'candidateAddresses']

export function normalizeContext(input) {
  keys(input, CONTEXT_KEYS)
  if (input.schemaVersion !== 1 || !['synthetic-unit', 'historical-read-only'].includes(input.purpose))
    throw new Error('Unsupported census purpose or version')
  hash32(input.proposalId); hash32(input.proposalTextHash); hash32(input.snapshotBlockHash)
  uint(input.sourceChainId); uint(input.snapshotBlock, (1n << 32n) - 1n)
  if (!Array.isArray(input.choices) || input.choices.length < 2 || input.choices.length > 3 ||
      input.choices.some(x => typeof x !== 'string' || !x.trim()) || new Set(input.choices).size !== input.choices.length)
    throw new Error('Expected two or three distinct ordered choices')
  if (typeof input.authority !== 'string' || !input.authority.trim()) throw new Error('Name the census authority')
  if (typeof input.space !== 'string' || !input.space.trim()) throw new Error('Name the source space')
  if (input.electorateScope !== 'explicit-address-list') throw new Error('Expected an explicit electorate scope')
  if (!Array.isArray(input.candidateAddresses) || !input.candidateAddresses.length || input.candidateAddresses.length > 2 ** 20)
    throw new Error('Invalid candidate count')
  const candidateAddresses = input.candidateAddresses.map(address).sort()
  if (new Set(candidateAddresses).size !== candidateAddresses.length || candidateAddresses.includes('0x' + '0'.repeat(40)))
    throw new Error('Duplicate or zero candidate address')
  if (input.purpose === 'synthetic-unit') {
    keys(input.strategy, ['name', 'version', 'credits'])
    if (canonical(input.strategy) !== canonical({ name: 'synthetic-unit', version: '1', credits: '1' }) ||
        input.sourceChainId !== '31337' || input.units !== 'synthetic-vote' || candidateAddresses.length > 20)
      throw new Error('Unsupported synthetic profile')
  } else {
    keys(input.strategy, ['name', 'version', 'revision', 'token', 'decimals'])
    if (input.units !== 'UNI-wei' || input.strategy.name !== 'uni' || input.strategy.version !== '0.1.1' ||
        input.strategy.decimals !== 18 || !/^[0-9a-f]{40}$/.test(input.strategy.revision))
      throw new Error('Unsupported historical strategy')
    address(input.strategy.token)
    for (const [key, value] of Object.entries(reference))
      if (canonical(input[key]) !== canonical(value)) throw new Error('Historical reference changed')
  }
  return structuredClone({ ...input, candidateAddresses })
}

export const leafOf = (slot, weight) => poseidon2([BigInt(address(slot)), uint(weight, MAX_RAW_WEIGHT)])

export function buildCensus(inputContext, inputRecords) {
  const context = normalizeContext(inputContext)
  if (!Array.isArray(inputRecords)) throw new Error('Expected scoring records')
  const records = inputRecords.map(record => {
    keys(record, ['address', 'weight'])
    const normalized = { address: address(record.address), weight: record.weight }
    const weight = uint(record.weight, MAX_RAW_WEIGHT)
    if (context.purpose === 'synthetic-unit' && weight > 1n) throw new Error('Synthetic credits must be zero or one')
    return normalized
  }).sort((a, b) => a.address < b.address ? -1 : a.address > b.address ? 1 : 0)
  if (canonical(records.map(x => x.address)) !== canonical(context.candidateAddresses))
    throw new Error('Scoring records must cover every authorized candidate exactly once')
  const eligible = records.filter(x => x.weight !== '0').map(x => ({ ...x, leaf: leafOf(x.address, x.weight).toString() }))
  if (!eligible.length) throw new Error('Empty eligible census')
  const tree = new LeanIMT((a, b) => poseidon2([a, b]), eligible.map(x => BigInt(x.leaf)))
  const contents = { schemaVersion: 1, context, contextHash: digest(context), records, eligible, root: tree.root.toString() }
  return { ...contents, manifestHash: digest(contents) }
}

// The independently approved context and independently obtained scores are required inputs.
// Rehashing an untrusted manifest alone cannot detect a false source list or false chain data.
export function verifyCensus(manifest, expectedContext, expectedRecords) {
  const rebuilt = buildCensus(expectedContext, expectedRecords)
  if (canonical(manifest) !== canonical(rebuilt)) throw new Error('Census does not match the independently rebuilt manifest')
  return rebuilt
}
