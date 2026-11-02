// SPDX-License-Identifier: LGPL-3.0-only
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { JsonRpcProvider } from 'ethers'
import { ROOT } from '../../src/upstream.mjs'
import { hash32 } from '../../src/format.mjs'
import { CoordinatorStore } from '../../src/coordinator-store.mjs'
import { initializeCoordinator, importProofBundle, replayCoordinator, syncCoordinator, validateCoordinatorConfig, readCoordinatorState } from '../../src/coordinator.mjs'
import { queueOperatorTransaction, pumpOperatorTransactions } from '../../src/coordinator-outbox.mjs'
import { CoordinationError } from '../../src/coordinator-protocol.mjs'

const [command, roundOrFile, file] = process.argv.slice(2)
let store, provider
const json = path => JSON.parse(readFileSync(path, 'utf8'))
const summary = state => ({ schemaVersion: state.schemaVersion, manifestHash: state.manifestHash, cursor: state.cursor,
  status: state.status, reason: state.reason, counts: state.counts, lastCheckedAt: state.lastCheckedAt ?? null, result: state.result })
try {
  const config = command === 'init' ? json(roundOrFile) : null
  const manifestHash = hash32(config ? config.approvedManifestHash : roundOrFile)
  const path = resolve(ROOT, '.local/coordinator', manifestHash.slice(2), 'state.db')
  store = new CoordinatorStore(path)
  if (command === 'init') { await initializeCoordinator(store, config); console.log('Initialized local round: ' + manifestHash) }
  else if (command === 'ciphertext') {
    readCoordinatorState(store, validateCoordinatorConfig(store.get('config')))
    console.log('Stored public ciphertext: ' + store.putCiphertext(readFileSync(file)))
  }
  else if (command === 'proofs') { await importProofBundle(store, json(file)); console.log('Imported public proof bundle.') }
  else if (command === 'queue') {
    const job = await queueOperatorTransaction(store, readFileSync(file, 'utf8').trim())
    console.log(JSON.stringify({ hash: job.hash, status: job.status }))
  } else if (command === 'replay') { await replayCoordinator(store); console.log('Cursor reset to approved anchor; signed transactions retained.') }
  else if (command === 'status') console.log(JSON.stringify({ cached: true,
    ...summary(readCoordinatorState(store, validateCoordinatorConfig(store.get('config')))) }, null, 2))
  else if (command === 'sync' || command === 'pump') {
    provider = new JsonRpcProvider(process.env.COORDINATOR_RPC_URL ?? 'http://127.0.0.1:18546', 31337,
      { staticNetwork: true, cacheTimeout: -1, batchMaxCount: 1 })
    if (command === 'pump') console.log(JSON.stringify(await pumpOperatorTransactions(store, provider), null, 2))
    else {
      const state = await syncCoordinator(store, provider)
      console.log(JSON.stringify({ cached: false, ...summary(state) }, null, 2))
      if (['blocked-check', 'replay-required'].includes(state.status) || state.status.startsWith('failed-')) process.exitCode = 2
    }
  } else throw new Error('Unknown coordinator command')
} catch (error) {
  // Do not print RPC URLs, signed payloads, provider exceptions or local file contents.
  console.error(error instanceof CoordinationError ? error.code : 'Coordinator operation failed. Saved state was retained.')
  process.exitCode = 1
} finally { provider?.destroy(); store?.close() }
