// SPDX-License-Identifier: LGPL-3.0-only
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { JsonRpcProvider } from 'ethers'
import { ROOT, CRISP } from '../../src/upstream.mjs'
import { pathToFileURL } from 'node:url'
import { CoordinatorStore } from '../../src/coordinator-store.mjs'
import { startInterface } from '../../src/interface-server.mjs'
const [file, approvedHash] = process.argv.slice(2)
let app, provider, store
try {
  const config = JSON.parse(readFileSync(file, 'utf8'))
  // Service URLs are operator configuration; no URL or credential is returned to the browser.
  const rpc = new URL(process.env.COORDINATOR_RPC_URL ?? 'http://127.0.0.1:18546')
  const crisp = process.env.T07_CRISP_URL ? new URL(process.env.T07_CRISP_URL) : null
  for (const url of [rpc, crisp].filter(Boolean))
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') throw new Error('Only loopback development services are supported')
  provider = new JsonRpcProvider(rpc.href, 31337, { staticNetwork: true, batchMaxCount: 1, cacheTimeout: -1 })
  store = new CoordinatorStore(resolve(ROOT, '.local/coordinator', config.round.approvedManifestHash.slice(2), 'state.db'))
  const sdk = await import(pathToFileURL(resolve(CRISP, 'packages/crisp-sdk/dist/index.js')).href)
  app = await startInterface({ config, approvedHash, store, provider,
    broadcast: crisp ? encodedProof => sdk.broadcastVote(crisp.href.replace(/\/$/, ''), { e3Id: BigInt(config.round.manifest.e3Id), encodedProof }) : undefined })
  console.log('Local synthetic interface: ' + app.url)
  const close = async () => { await app.close(); provider.destroy(); store.close() }
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void close().then(() => process.exit(0)) })
} catch {
  await app?.close(); provider?.destroy(); store?.close()
  console.error('Local interface could not start. Check the approved config, coordinator database and locked assets.')
  process.exitCode = 1
}
