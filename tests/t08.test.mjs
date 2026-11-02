// SPDX-License-Identifier: LGPL-3.0-only
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { toBeHex } from 'ethers'
import { assertInterfaceConfig, interfaceHash, developmentTotals, secureTotals } from '../src/interface.mjs'
import { CoordinatorStore } from '../src/coordinator-store.mjs'
import { reserveAdmission } from '../src/admission-budget.mjs'

const round = JSON.parse(readFileSync(new URL('../fixtures/t08-application-config.json', import.meta.url)))
const config = { schemaVersion: 1, round, proposal: { title: 'Synthetic private preliminary poll',
  text: 'Local synthetic demonstration. Choose one of three synthetic options. This poll has no effect on Uniswap governance.',
  url: 'https://github.com/theinterfold/interfold' }, publicKey: '0x1234' }
config.configHash = interfaceHash(config)

test('secure interface requires the exact reviewed synthetic deployment policy', () => {
  assertInterfaceConfig(config, config.configHash)
  const changed = structuredClone(config)
  changed.round.policy.contracts.ballotVerifier.runtimeHash = '0x' + '01'.repeat(32)
  changed.configHash = interfaceHash(changed)
  assert.throws(() => assertInterfaceConfig(changed, changed.configHash))
  assert.throws(() => assertInterfaceConfig(config, '0x' + '00'.repeat(32)))
})

test('attestation quota survives restart and concurrent requests cannot reserve a sixty-first input', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'voting-budget-')), path = join(directory, 'budget.db')
  let store = new CoordinatorStore(path)
  const identity = i => ({ slot: round.census.eligible[i % 10].address, commitment: toBeHex(i + 1, 32),
    ciphertextHash: toBeHex(i + 100, 32), parentIndexPlusOne: '0' })
  try {
    const first = await reserveAdmission(store, round.manifest, identity(0))
    assert.equal((await reserveAdmission(store, round.manifest, identity(0))).ordinal, first.ordinal)
    for (let i = 1; i < 59; i++) await reserveAdmission(store, round.manifest, identity(i))
    store.close(); store = new CoordinatorStore(path)
    const other = new CoordinatorStore(path)
    try {
      const attempts = await Promise.allSettled([reserveAdmission(store, round.manifest, identity(59)), reserveAdmission(other, round.manifest, identity(60))])
      assert.equal(attempts.filter(x => x.status === 'fulfilled').length, 1)
      assert.equal(attempts.find(x => x.status === 'fulfilled').value.ordinal, 60)
      await assert.rejects(reserveAdmission(other, round.manifest, identity(61)), /ADMISSION_BUDGET_EXHAUSTED/)
    } finally { other.close() }
    assert.equal((await reserveAdmission(store, round.manifest, identity(0))).ordinal, 1)
  } finally { store.close(); rmSync(directory, { recursive: true, force: true }) }
})

test('secure totals disappear on stale, failed, unapproved or mismatched proof evidence', () => {
  const good = { cached: false, state: { status: 'verified', reason: null,
    manifestHash: round.approvedManifestHash, policyHash: round.approvedPolicyHash,
    result: { totals: ['1', '2', '2'], policyHash: round.approvedPolicyHash,
      imageId: round.policy.guest.imageId, assurance: 'proof checked under reviewed deployment policy' } } }
  assert.deepEqual(secureTotals(config, good), ['1', '2', '2'])
  assert.equal(developmentTotals(config, good), null)
  for (const mutate of [x => x.cached = true, x => x.state.status = 'development-complete',
    x => x.state.status = 'failed-protocol', x => x.state.reason = 'RPC_UNAVAILABLE',
    x => x.state.manifestHash = 'other', x => x.state.policyHash = 'other',
    x => x.state.result.imageId = 'other', x => x.state.result.assurance = 'unreviewed',
    x => x.state.result.totals = ['11', '0', '0'], x => x.state.result.totals = ['1', '2'],
    x => x.state.result.totals = ['-1', '2', '2']]) {
    const changed = structuredClone(good); mutate(changed)
    assert.equal(secureTotals(config, changed), null)
  }
  const unapproved = structuredClone(config)
  unapproved.round.policy.anchor.hash = '0x' + '00'.repeat(32)
  assert.equal(secureTotals(unapproved, good), null)
})
