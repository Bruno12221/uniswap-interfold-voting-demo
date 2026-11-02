// SPDX-License-Identifier: LGPL-3.0-only
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { resolve, dirname } from 'node:path'
import { JsonRpcProvider } from 'ethers'
import { buildCensus, verifyCensus } from '../../src/census.mjs'
import { readHistoricalScores, checkSnapshotReference } from '../../src/scoring.mjs'

const [mode, input, output] = process.argv.slice(2)
let provider
try {
  const data = JSON.parse(await readFile(input, 'utf8'))
  let result
  if (mode === 'build') result = buildCensus(data.context, data.records)
  else if (mode === 'verify') {
    const manifest = JSON.parse(await readFile(output, 'utf8'))
    result = verifyCensus(manifest, data.context, data.records)
    console.log(JSON.stringify({ root: result.root, manifestHash: result.manifestHash, eligible: result.eligible.length }))
    process.exit(0)
  } else if (mode === 'score' || mode === 'reference') {
    provider = new JsonRpcProvider(process.env.HISTORICAL_RPC_URL || 'https://rpc.snapshot.org/1', 1,
      { staticNetwork: true, batchMaxCount: 1 })
    result = await readHistoricalScores(provider, data)
    if (mode === 'reference') result = await checkSnapshotReference(result)
  } else throw new Error('Choose build, verify, score or reference')
  const local = resolve('.local') + '/'
  if (!output || !resolve(output).startsWith(local)) throw new Error('Write unreviewed output below .local')
  await mkdir(dirname(resolve(output)), { recursive: true })
  await writeFile(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' })
  console.log(['score', 'reference'].includes(mode) ? 'Historical scoring report written.' : 'Census written: ' + result.manifestHash)
} catch {
  // Provider exceptions can contain authenticated URLs. Do not print them.
  console.error('Census command failed. Check the input, mode and private endpoint configuration. No result is approved.')
  process.exitCode = 1
} finally { provider?.destroy() }
