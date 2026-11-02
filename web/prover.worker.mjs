// SPDX-License-Identifier: LGPL-3.0-only
import { JsonRpcProvider, getBytes } from 'ethers'
import { assertInterfaceConfig } from '../src/interface.mjs'
import { prepareBoundBallot, finishBoundBallot } from '../src/ballot-core.mjs'
import { runtime } from './runtime.mjs'
let session, config, provider, signatureResolve
// The witness stays in this worker. Only signing requests and the public envelope leave it.
self.onmessage = async ({ data }) => {
  if (data.type === 'signature') { signatureResolve?.(data.signature); signatureResolve = undefined; return }
  if (data.type !== 'prove' || session) return
  let phase = 'context'
  try {
    config = assertInterfaceConfig(data.config, data.approvedHash)
    provider = new JsonRpcProvider(new URL('/api/rpc', self.location.origin).href, 31337,
      { staticNetwork: true, cacheTimeout: -1, batchMaxCount: 1 })
    phase = 'public parameters'
    const r = config.round, rt = await runtime(r.manifest.preset)
    phase = 'encryption and witness'
    session = await prepareBoundBallot({ provider, manifest: r.manifest, approvedHash: r.approvedManifestHash,
      census: r.census, approvedCensusHash: r.approvedCensusHash, publicKey: getBytes(config.publicKey), slot: data.slot, vote: data.vote,
      ...(data.parent ? { previousCiphertext: getBytes(data.parent.ciphertext), previousIndex: Number(data.parent.index) } : {}) }, rt, rt.artifactsHash)
    self.postMessage({ type: 'prepared' })
    phase = 'proof generation and verification'
    const proof = await finishBoundBallot(provider, r.manifest, session, { signTypedData: (domain, types, value) => {
      self.postMessage({ type: 'sign', domain, types, value })
      return new Promise(resolve => { signatureResolve = resolve })
    } })
    self.postMessage({ type: 'proof', encodedProof: rt.sdk.encodeSolidityProof(proof) })
  } catch (error) {
    const message = typeof error === 'string' ? error : String(error?.message ?? '')
    const kind = Object.prototype.toString.call(error) + ':' + (['Error', 'TypeError', 'ReferenceError', 'DataCloneError', 'SecurityError', 'InvalidStateError', 'NotSupportedError', 'QuotaExceededError', 'RuntimeError', 'CompileError', 'LinkError'].includes(error?.name) ? error.name : typeof error)
    const category = /Buffer/.test(message) ? 'buffer-unavailable' : /fetch|network|crs/i.test(message) ? 'public-parameter-download' :
      /memory|alloc/i.test(message) ? 'browser-memory' : /signature|signer/i.test(message) ? 'signature-check' :
      /witness|constraint|circuit/i.test(message) ? 'circuit-execution' : /WebAssembly|wasm/i.test(message) ? 'wasm-runtime' :
      error instanceof ReferenceError ? 'browser-reference' : error instanceof TypeError ? 'browser-type' : 'unclassified'
    const sites = [...String(error?.stack ?? '').matchAll(/\/assets\/[a-zA-Z0-9._-]+\.js:[0-9]+:[0-9]+/g)].slice(0, 3).map(x => x[0])
    // Native exceptions can contain witnesses. Never forward them to the page or network.
    self.postMessage({ type: 'failed', phase, category, sites, kind })
  } finally { provider?.destroy() }
}
