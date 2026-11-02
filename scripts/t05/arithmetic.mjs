// SPDX-License-Identifier: LGPL-3.0-only
// Native BFV arithmetic checks with disposable keys. No admission or threshold proof is claimed.
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { ROOT, checkLockedArtifacts, loadProofRuntime } from '../../src/upstream.mjs'
import { profile } from '../../src/round.mjs'

const report = { schemaVersion: 1, scope: 'Native BFV arithmetic with disposable single-party keys; no admission, computation or threshold-decryption proof.',
  sourceRevision: profile.sourceRevision, artifactsHash: await checkLockedArtifacts(), cases: [] }
for (const preset of Object.keys(profile.presets)) {
  const runtime = await loadProofRuntime(preset)
  try {
    const { publicKey, secretKey } = runtime.sdk.generateBFVKeys()
    const decrypt = ciphertext => Array.from(runtime.generator.decryptVote(secretKey, ciphertext), BigInt)
    const check = (label, ciphertext, expected) => {
      const words = decrypt(ciphertext)
      assert(words.length >= 50)
      assert.deepEqual(words.slice(0, 3), expected)
      assert(words.slice(3).every(x => x === 0n), 'Nonzero unused coefficient')
      report.cases.push({ preset, label, totals: expected.map(String), checkedCoefficients: words.length })
    }
    for (const [label, votes] of [
      ['20 units in one choice', Array.from({ length: 20 }, () => [1n, 0n, 0n])],
      ['20 units across three choices', Array.from({ length: 20 }, (_, i) => [0, 1, 2].map(j => BigInt(i % 3 === j)))],
      ['20 zero contributions', Array.from({ length: 20 }, () => [0n, 0n, 0n])],
    ]) {
      let ciphertext
      const expected = [0n, 0n, 0n]
      for (const vote of votes) {
        // Exercise the native addition primitive, not the zero-only mask proof branch.
        ciphertext = runtime.generator.generateInputs(ciphertext, publicKey, BigInt64Array.from(vote), true).encryptedVote
        vote.forEach((x, i) => expected[i] += x)
      }
      check(label, ciphertext, expected)
    }
    const first = runtime.generator.generateInputs(undefined, publicKey, BigInt64Array.from([0n, 1n, 0n]), false).encryptedVote
    const mask = runtime.generator.generateInputs(first, publicKey, BigInt64Array.from([0n, 0n, 0n]), true).encryptedVote
    check('zero mask preserves contribution', mask, [0n, 1n, 0n])
    const replacement = runtime.generator.generateInputs(mask, publicKey, BigInt64Array.from([1n, 0n, 0n]), false).encryptedVote
    check('replacement does not add weight', replacement, [1n, 0n, 0n])
  } finally { runtime.sdk.destroyBBApi() }
}
const run = resolve(ROOT, '.local/runs/t05-arithmetic-' + new Date().toISOString().replace(/[-:.]/g, ''))
mkdirSync(run, { recursive: true })
writeFileSync(resolve(run, 'arithmetic.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' })
writeFileSync(resolve(ROOT, '.local/latest-t05-arithmetic'), run + '\n')
console.log('T05 native arithmetic checks passed: ' + report.cases.length + ' cases. Public metadata: ' + run)
