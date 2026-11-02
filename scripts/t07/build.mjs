// SPDX-License-Identifier: LGPL-3.0-only
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import { resolve, dirname } from 'node:path'
import { ROOT, UPSTREAM, CRISP, checkLockedArtifacts } from '../../src/upstream.mjs'
await checkLockedArtifacts()
const require = createRequire(resolve(CRISP, 'client/package.json'))
if (require('vite/package.json').version !== '5.4.21') throw new Error('Wrong upstream Vite version')
const { build } = await import(pathToFileURL(resolve(dirname(require.resolve('vite/package.json')), 'dist/node/index.js')).href)
export const options = {
  configFile: false, root: resolve(ROOT, 'web'), base: '/', define: { global: 'globalThis' },
  resolve: { alias: {
    '@crisp-e3/sdk/insecure-512': resolve(CRISP, 'packages/crisp-sdk/dist/presets/insecure-512.js'),
    '@crisp-e3/sdk/secure-8192': resolve(CRISP, 'packages/crisp-sdk/dist/presets/secure-8192.js'),
    '@crisp-e3/sdk': resolve(CRISP, 'packages/crisp-sdk/dist/index.js'),
    '@crisp-e3/zk-inputs': resolve(CRISP, 'packages/crisp-zk-inputs/main.js'),
    '@pilot/bb-crs': resolve(CRISP, 'packages/crisp-sdk/node_modules/@aztec/bb.js/dest/browser/crs/index.js'),
    '@pilot/buffer': resolve(UPSTREAM, 'node_modules/.pnpm/buffer@6.0.3/node_modules/buffer/index.js'),
    '@pilot/core-base64': resolve(UPSTREAM, 'crates/wasm/dist/web/e3_wasm_base64.js'),
    '@pilot/core': resolve(UPSTREAM, 'crates/wasm/dist/web/e3_wasm.js'),
  } },
  worker: { format: 'es' }, build: { target: 'esnext', minify: false, outDir: resolve(ROOT, 'dist/t07'), emptyOutDir: true, sourcemap: false, chunkSizeWarningLimit: 100000 },
}
await build(options)
console.log('Local browser assets built from the locked source. No deployment performed.')
