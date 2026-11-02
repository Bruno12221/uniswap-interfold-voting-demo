// SPDX-License-Identifier: LGPL-3.0-only
import http from 'node:http'
import { readFileSync, realpathSync } from 'node:fs'
import { resolve, extname } from 'node:path'
import { getBytes, hexlify } from 'ethers'
import { address, canonical, keys } from './format.mjs'
import { assertInterfaceConfig, decodeSubmission, normalizeDelivery } from './interface.mjs'
import { assertInputCommitmentWindow, readBoundRound } from './round.mjs'
import { syncCoordinator, rebuildLedger, validateCoordinatorConfig } from './coordinator.mjs'
import { checkTranscript, transcriptRoot } from './transcript.mjs'
import { authenticatePublicKey } from './ballot-core.mjs'
import { loadProofRuntime, checkLockedArtifacts, ROOT } from './upstream.mjs'

const readMethods = new Set(['eth_chainId', 'eth_blockNumber', 'eth_call', 'eth_getCode', 'eth_getBlockByNumber',
  'eth_getBlockByHash', 'eth_getLogs', 'eth_getTransactionReceipt', 'eth_getTransactionByHash', 'eth_getStorageAt'])
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.wasm': 'application/wasm' }
async function body(req) {
  if (!String(req.headers['content-type']).startsWith('application/json')) throw new Error('JSON required')
  let size = 0; const chunks = []
  for await (const chunk of req) { size += chunk.length; if (size > 2 ** 22) throw new Error('Request too large'); chunks.push(chunk) }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}
// The public service never accepts a choice, a witness, randomness or a wallet secret.
export async function startInterface({ config, approvedHash, store, provider, broadcast, port = 18707, assets = resolve(ROOT, 'dist/t07') }) {
  assertInterfaceConfig(config, approvedHash)
  const round = validateCoordinatorConfig(store.get('config'))
  if (canonical(round) !== canonical(config.round) || round.manifest.artifactsHash !== await checkLockedArtifacts())
    throw new Error('Interface and coordinator contexts differ')
  const runtime = await loadProofRuntime(round.manifest.preset)
  authenticatePublicKey(runtime, getBytes(config.publicKey), round.manifest.committeeKeyCommitment)
  const root = realpathSync(assets)
  let queue = Promise.resolve()
  async function snapshot() {
    const state = await syncCoordinator(store, provider)
    const ledger = rebuildLedger(state.events, round.manifest, round.census).ledger
    let dispositions = null, entries = null
    try {
      entries = ledger.map(entry => {
        const bytes = store.getCiphertext(entry.ciphertextHash)
        if (!bytes) throw new Error('Missing ciphertext')
        return { index: entry.index, slot: entry.slot, commitment: entry.commitment, ciphertextHash: entry.ciphertextHash,
          parentIndexPlusOne: entry.parentIndexPlusOne, ciphertext: hexlify(bytes) }
      })
      dispositions = checkTranscript(entries, round.census, round.manifest, transcriptRoot(ledger), String(ledger.length), runtime).dispositions
    } catch { entries = null }
    return { schemaVersion: 1, cached: false, state, ledger, dispositions, entries }
  }
  const server = http.createServer((req, res) => {
    // Serialize transactions on this SQLite connection; a failed request releases the queue.
    const task = async () => {
      const origin = 'http://127.0.0.1:' + server.address().port
      if (req.headers.host !== new URL(origin).host || (req.headers.origin && req.headers.origin !== origin)) {
        res.writeHead(403); res.end(); return
      }
      res.setHeader('Cache-Control', 'no-store')
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
      res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp')
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('Referrer-Policy', 'no-referrer')
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self' data: https://crs.aztec-cdn.foundation https://crs.aztec-labs.com; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
      const send = (value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)) }
      try {
        const url = new URL(req.url, origin)
        if (req.method === 'GET' && url.pathname === '/api/config') { send(config); return }
        if (req.method === 'POST' && url.pathname === '/api/rpc') {
          const message = await body(req)
          keys(message, ['id', 'jsonrpc', 'method', 'params'])
          if (message.jsonrpc !== '2.0' || !Number.isSafeInteger(message.id) || !readMethods.has(message.method) || !Array.isArray(message.params))
            throw new Error('Read-only RPC required')
          try { send({ id: message.id, jsonrpc: '2.0', result: await provider.send(message.method, message.params) }) }
          catch { send({ id: message.id, jsonrpc: '2.0', error: { code: -32000, message: 'Public chain read failed' } }) }
          return
        }
        if (req.method === 'GET' && ['/api/status', '/api/parent', '/api/evidence'].includes(url.pathname)) {
          const current = await snapshot()
          if (url.pathname === '/api/status') { const { entries, ...publicState } = current; send(publicState); return }
          if (url.pathname === '/api/evidence') {
            send({ config, ...current, proofBundle: store.get('proof-bundle') ?? null,
              warning: round.policy.assurance === 'development' ? 'Development evidence; fixture verification is permitted. No secure attestation.' :
                'Local synthetic application replay with real secure proofs. One operator controls the committee; eligibility, randomness and availability remain local fixtures.' }); return
          }
          const slot = address(url.searchParams.get('slot'))
          if (current.state.status !== 'voting-open' || current.state.reason || !current.entries || !current.dispositions)
            throw new Error('Confirmed transcript unavailable')
          const index = current.entries.findIndex((entry, i) => entry.slot === slot && current.dispositions[i] === 'selected')
          send({ entry: index < 0 ? null : current.entries[index] }); return
        }
        if (req.method === 'POST' && url.pathname === '/api/submit') {
          const request = await body(req); keys(request, ['encodedProof'])
          const decoded = decodeSubmission(request.encodedProof, round.manifest)
          if (hexlify(runtime.generator.computeCtCommitment(getBytes(decoded.ciphertext))) !== decoded.identity.commitment)
            throw new Error('Ciphertext does not match its proven commitment')
          if (!round.census.eligible.some(x => x.address === decoded.identity.slot && x.weight === '1')) throw new Error('Not eligible')
          const { program } = await readBoundRound(provider, round.manifest, 3)
          await assertInputCommitmentWindow(provider, round.manifest, program)
          if (typeof broadcast !== 'function') throw new Error('Submission route unavailable')
          // This callback must use the reviewed CRISP public-envelope route, never server-side proving.
          store.putCiphertext(getBytes(decoded.ciphertext))
          const result = normalizeDelivery(await broadcast(request.encodedProof))
          send({ acceptedForDelivery: result.status !== 'failed_broadcast', confirmed: false, identity: decoded.identity, response: result ?? null }); return
        }
        if (req.method !== 'GET' || url.pathname.startsWith('/api/')) { send({ message: 'Route unavailable' }, 404); return }
        const file = realpathSync(resolve(root, '.' + (url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname))))
        if (!file.startsWith(root + '/')) throw new Error('Asset unavailable')
        const type = mime[extname(file)]; if (!type) throw new Error('Asset unavailable')
        res.writeHead(200, { 'Content-Type': type }); res.end(readFileSync(file))
      } catch {
        // No native exception, RPC URL, request body or witness goes into a response or reporter.
        if (!res.headersSent) send({ message: 'Local operation unavailable. Check the round and retry.' }, 503)
        else res.end()
      }
    }
    queue = queue.then(task, task)
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve) })
  return { server, url: 'http://127.0.0.1:' + server.address().port + '/#' + approvedHash,
    close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await queue } }
}
