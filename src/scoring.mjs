// SPDX-License-Identifier: LGPL-3.0-only
import { Contract, formatUnits } from 'ethers'
import { address, canonical, uint } from './format.mjs'
import { MAX_RAW_WEIGHT } from './census.mjs'
import { reference } from './reference.mjs'
import { isDelegatedEoaCode } from './wallet.mjs'

export { reference }
export const UNI_ABI = [
  'function getCurrentVotes(address) view returns (uint96)',
  'function getPriorVotes(address,uint256) view returns (uint96)',
  'function numCheckpoints(address) view returns (uint32)',
  'function checkpoints(address,uint32) view returns (uint32 fromBlock,uint96 votes)',
  'function balanceOf(address) view returns (uint256)',
  'function delegates(address) view returns (address)',
  'function decimals() view returns (uint8)',
]

export const snapshotDisplayScore = raw => Number(formatUnits(uint(raw, MAX_RAW_WEIGHT), 18))

// Read the retained checkpoint table independently of UNI's getPriorVotes implementation.
export async function checkpointPower(contract, slot, snapshotBlock, atBlock) {
  const overrides = { blockTag: atBlock }
  let low = 0n
  let high = BigInt(await contract.numCheckpoints(slot, overrides))
  while (low < high) {
    const mid = (low + high) / 2n
    const cp = await contract.checkpoints(slot, mid, overrides)
    if (BigInt(cp.fromBlock) <= snapshotBlock) low = mid + 1n
    else high = mid
  }
  if (low === 0n) return 0n
  const cp = await contract.checkpoints(slot, low - 1n, overrides)
  return uint(BigInt(cp.votes).toString(), MAX_RAW_WEIGHT)
}

export async function readHistoricalScores(provider, candidates, expected = reference) {
  // No arbitrary strategy, current block, token substitution or floating-point weights.
  if (canonical(expected) !== canonical(reference)) throw new Error('Historical reference changed')
  const slots = candidates.map(address).sort()
  if (!slots.length || slots.length > 2 ** 20 || new Set(slots).size !== slots.length) throw new Error('Invalid candidate list')
  if (BigInt(await provider.send('eth_chainId', [])) !== 1n) throw new Error('Wrong source chain')
  const block = Number(uint(reference.snapshotBlock, (1n << 32n) - 1n))
  const checkHeader = async () => {
    const header = await provider.getBlock(block)
    if (header?.hash?.toLowerCase() !== reference.snapshotBlockHash) throw new Error('Wrong historical block hash')
  }
  await checkHeader()
  const finalized = await provider.getBlock('finalized')
  if (!finalized || finalized.number <= block) throw new Error('Historical checkpoint is not finalized')
  const token = new Contract(reference.strategy.token, UNI_ABI, provider)
  if (await token.decimals({ blockTag: block }) !== 18n) throw new Error('Wrong token decimals')
  const records = []
  for (const slot of slots) {
    const raw = await token.getCurrentVotes(slot, { blockTag: block })
    const retained = await token.getPriorVotes(slot, block, { blockTag: finalized.number })
    const independent = await checkpointPower(token, slot, BigInt(block), finalized.number)
    if (raw !== retained || raw !== independent) throw new Error('Historical and retained checkpoint weights differ')
    const balance = await token.balanceOf(slot, { blockTag: block })
    const delegate = address(await token.delegates(slot, { blockTag: block }))
    const code = await provider.getCode(slot, block)
    records.push({ address: slot, weight: uint(raw.toString(), MAX_RAW_WEIGHT).toString(),
      balance: balance.toString(), delegate, accountType: code === '0x' ? 'eoa' : isDelegatedEoaCode(code) ? 'delegated-eoa' : 'contract',
      snapshotDisplayScore: String(snapshotDisplayScore(raw.toString())) })
  }
  await checkHeader()
  return { source: structuredClone(reference), checkpointReadBlock: String(finalized.number),
    checkpointReadBlockHash: finalized.hash, records }
}

export async function checkSnapshotReference(report) {
  if (canonical(report.source) !== canonical(reference)) throw new Error('Historical reference changed')
  const snapshotReference = []
  for (const row of report.records) {
    const params = { address: row.address, network: '1', snapshot: Number(reference.snapshotBlock),
      space: reference.space, delegation: false, strategies: [{ name: 'uni', network: '1',
        params: { address: reference.strategy.token, symbol: 'UNI', decimals: 18 } }] }
    const response = await fetch('https://score.snapshot.org', { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(30000),
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'get_vp', params }) })
    if (!response.ok) throw new Error('Snapshot scoring reference unavailable')
    const { result } = await response.json()
    const expected = snapshotDisplayScore(row.weight)
    if (!result || result.vp_state !== 'final' || !Number.isFinite(result.vp) || result.vp !== expected ||
        canonical(result.vp_by_strategy.map(String)) !== canonical([String(expected)]))
      throw new Error('Snapshot scoring reference differs')
    snapshotReference.push({ address: row.address, displayScore: String(result.vp) })
  }
  return { ...report, snapshotReference }
}
