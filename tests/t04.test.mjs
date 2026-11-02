// SPDX-License-Identifier: LGPL-3.0-only
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { Wallet, Interface, formatUnits } from 'ethers'
import { poseidon2 } from 'poseidon-lite'
import { buildCensus, verifyCensus, MAX_RAW_WEIGHT } from '../src/census.mjs'
import { digest, canonical } from '../src/format.mjs'
import { checkpointPower, readHistoricalScores, reference, snapshotDisplayScore } from '../src/scoring.mjs'
import { verifyWalletSignature } from '../src/wallet.mjs'

const fixture = JSON.parse(readFileSync(new URL('../fixtures/t04-synthetic.json', import.meta.url), 'utf8'))
const clone = x => structuredClone(x)

test('deterministic census agrees with an independent pairwise tree and input permutation', () => {
  const manifest = buildCensus(fixture.context, fixture.records)
  let level = manifest.eligible.map(x => poseidon2([BigInt(x.address), BigInt(x.weight)]))
  while (level.length > 1) {
    const next = []
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 === level.length ? level[i] : poseidon2([level[i], level[i + 1]]))
    level = next
  }
  assert.equal(manifest.root, level[0].toString())
  assert.equal(manifest.eligible.length, 5)
  const reversed = clone(fixture.context); reversed.candidateAddresses.reverse()
  assert.deepEqual(buildCensus(reversed, [...fixture.records].reverse()), manifest)
  assert.deepEqual(verifyCensus(manifest, fixture.context, fixture.records), manifest)
})

test('omissions, duplicates, changed weights and changed roots fail independent rebuild', () => {
  assert.throws(() => buildCensus(fixture.context, fixture.records.slice(1)))
  assert.throws(() => buildCensus(fixture.context, [...fixture.records, fixture.records[0]]))
  const duplicate = clone(fixture.context); duplicate.candidateAddresses.push(duplicate.candidateAddresses[0])
  assert.throws(() => buildCensus(duplicate, fixture.records))
  for (const mutate of [x => x.root = '1', x => x.records[0].weight = '0',
    x => x.eligible.pop(), x => x.context.snapshotBlock = '1', x => x.context.strategy.credits = '2']) {
    const altered = clone(buildCensus(fixture.context, fixture.records)); mutate(altered)
    assert.throws(() => verifyCensus(altered, fixture.context, fixture.records))
  }
})

test('context changes are bound even when the membership root is unchanged', () => {
  const original = buildCensus(fixture.context, fixture.records)
  for (const mutate of [x => x.snapshotBlock = '1', x => x.snapshotBlockHash = '0x' + '44'.repeat(32),
    x => x.proposalTextHash = '0x' + '55'.repeat(32), x => x.choices.reverse(), x => x.authority = 'another authority']) {
    const changed = clone(fixture.context); mutate(changed)
    const rebuilt = buildCensus(changed, fixture.records)
    assert.equal(rebuilt.root, original.root)
    assert.notEqual(rebuilt.manifestHash, original.manifestHash)
  }
})

test('historical units stay exact at uint96; no scaling to synthetic credits', () => {
  const context = { ...clone(fixture.context), ...clone(reference), purpose: 'historical-read-only', units: 'UNI-wei' }
  const records = fixture.records.map((x, i) => ({ ...x, weight: i === 0 ? MAX_RAW_WEIGHT.toString() : '0' }))
  assert.equal(buildCensus(context, records).eligible[0].weight, MAX_RAW_WEIGHT.toString())
  records[0].weight = (MAX_RAW_WEIGHT + 1n).toString()
  assert.throws(() => buildCensus(context, records))
  for (const weight of [1, '01', '-1', '1.0', '1e18'])
    assert.throws(() => buildCensus(fixture.context, [{ ...fixture.records[0], weight }, ...fixture.records.slice(1)]))
  assert.equal(snapshotDisplayScore('50844361091245691549815'), Number(formatUnits(50844361091245691549815n, 18)))
})

test('checkpoint boundary cases agree with a linear reference', async () => {
  for (const points of [[], [[10n, 5n]], [[3n, 9n], [10n, 0n], [11n, 30n], [25n, MAX_RAW_WEIGHT]]]) {
    const contract = { numCheckpoints: async () => BigInt(points.length), checkpoints: async (_, index) => {
      const [fromBlock, votes] = points[Number(index)]; return { fromBlock, votes }
    } }
    for (const block of [0n, 3n, 9n, 10n, 11n, 24n, 25n, 100n]) {
      const expected = points.filter(x => x[0] <= block).at(-1)?.[1] || 0n
      assert.equal(await checkpointPower(contract, fixture.records[0].address, block, 200), expected)
    }
  }
})

test('wrong source chain, block hash and strategy fail before scores are accepted', async () => {
  const slots = [fixture.records[0].address]
  await assert.rejects(readHistoricalScores({ send: async () => '0x7a69' }, slots), /Wrong source chain/)
  await assert.rejects(readHistoricalScores({ send: async () => '0x1', getBlock: async () => ({ hash: '0x' + '00'.repeat(32) }) }, slots), /Wrong historical block/)
  await assert.rejects(readHistoricalScores({}, slots, { ...reference, snapshotBlock: '1' }), /reference changed/)
  const context = { ...clone(fixture.context), ...clone(reference), purpose: 'historical-read-only', units: 'UNI-wei' }
  context.strategy.decimals = 17
  assert.throws(() => buildCensus(context, fixture.records))
})

test('EOA authorization rejects another signer or replayed digest', async () => {
  const wallet = Wallet.createRandom(); const other = Wallet.createRandom()
  const hash = digest({ round: '1', census: 'synthetic', chain: '31337' })
  const signature = wallet.signingKey.sign(hash).serialized
  const provider = { getCode: async () => '0x' }
  assert.equal(await verifyWalletSignature(provider, wallet.address, hash, signature, 'latest'), true)
  assert.equal(await verifyWalletSignature(provider, other.address, hash, signature, 'latest'), false)
  assert.equal(await verifyWalletSignature(provider, wallet.address, digest({ round: '2' }), signature, 'latest'), false)
  provider.getCode = async () => '0xef0100' + '11'.repeat(20)
  assert.equal(await verifyWalletSignature(provider, wallet.address, hash, signature, 'latest'), true)
})

test('contract authorization accepts only ERC-1271 magic; transport errors stay errors', async () => {
  // Unit transport fixture, not evidence of CRISP contract-wallet ballot support.
  const abi = new Interface(['function isValidSignature(bytes32,bytes) view returns (bytes4)'])
  const hash = digest({ round: '1' }); let answer = '0x1626ba7e'
  const provider = { getCode: async () => '0x6000', call: async () => abi.encodeFunctionResult('isValidSignature', [answer]) }
  assert.equal(await verifyWalletSignature(provider, fixture.records[0].address, hash, '0x', 'latest'), true)
  answer = '0xffffffff'
  assert.equal(await verifyWalletSignature(provider, fixture.records[0].address, hash, '0x', 'latest'), false)
  provider.call = async () => { throw Object.assign(new Error('unavailable'), { code: 'NETWORK_ERROR' }) }
  await assert.rejects(verifyWalletSignature(provider, fixture.records[0].address, hash, '0x', 'latest'), /unavailable/)
  assert.equal(canonical({ b: '2', a: '1' }), '{"a":"1","b":"2"}')
})

test('two fresh CLI rebuilds agree; an existing census cannot be overwritten', async () => {
  await mkdir('.local', { recursive: true })
  const dir = await mkdtemp(resolve('.local/t04-test-'))
  try {
    const input = resolve(dir, 'input.json'), first = resolve(dir, 'a.json'), second = resolve(dir, 'b.json')
    const reversed = clone(fixture); reversed.context.candidateAddresses.reverse(); reversed.records.reverse()
    await writeFile(input, JSON.stringify(reversed))
    const run = args => spawnSync(process.execPath, ['scripts/t04/census.mjs', ...args], { encoding: 'utf8' })
    assert.equal(run(['build', 'fixtures/t04-synthetic.json', first]).status, 0)
    assert.equal(run(['build', input, second]).status, 0)
    assert.equal(await readFile(first, 'utf8'), await readFile(second, 'utf8'))
    assert.equal(run(['build', input, first]).status, 1)
    assert.equal(run(['verify', input, first]).status, 0)
  } finally { await rm(dir, { recursive: true, force: true }) }
})
