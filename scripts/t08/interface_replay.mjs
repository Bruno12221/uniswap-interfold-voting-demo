// SPDX-License-Identifier: LGPL-3.0-only
// Browser qualification against a disposable secure replay. Never start aggregate proving.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { createRequire } from 'node:module'
import { spawn } from 'node:child_process'
import { setTimeout as delay } from 'node:timers/promises'
import net from 'node:net'
import { Contract, JsonRpcProvider, TypedDataEncoder, getBytes, toBeHex, keccak256 } from 'ethers'
import { ROOT, CRISP } from '../../src/upstream.mjs'
import { canonical } from '../../src/format.mjs'
import { CoordinatorStore } from '../../src/coordinator-store.mjs'
import { initializeCoordinator, importProofBundle } from '../../src/coordinator.mjs'
import { startInterface } from '../../src/interface-server.mjs'
import { assertInterfaceConfig, interfaceHash, decodeSubmission, envelopeTypes, publicReceipt, restorePublicReceipt } from '../../src/interface.mjs'
import { reserveAdmission } from '../../src/admission-budget.mjs'
import { abi, inputId } from '../../src/coordinator-protocol.mjs'

const [directory, mode = '--verify', receiptFile] = process.argv.slice(2)
assert(directory && ['--verify', '--prove', '--retry', '--round-replay', '--serve', '--vote'].includes(mode), 'Supply APPLICATION_RUN [--verify|--prove|--retry PUBLIC_RECEIPT_FILE|--round-replay|--serve|--vote]')
assert(mode !== '--retry' || receiptFile, 'A public receipt file is required for a delivery-only retry')
const source = resolve(directory), run = join(ROOT, '.local/runs/t08-browser-' + Date.now())
mkdirSync(run, { recursive: false, mode: 0o700 })
const json = file => JSON.parse(readFileSync(file, 'utf8'))
const round = json(join(source, 'application-config.json'))
assert.equal(canonical(round), canonical(json(join(ROOT, 'fixtures/t08-application-config.json'))), 'Unreviewed replay configuration')
const { proposal, publicKey } = json(join(source, 'application-interface.json'))
const config = { schemaVersion: 1, round, proposal, publicKey }
config.configHash = interfaceHash(config); assertInterfaceConfig(config, config.configHash)
const open = ['--prove', '--vote', '--retry', '--round-replay'].includes(mode)
const report = { scope: 'Secure local replay browser qualification; transport/eligibility/randomness remain fixtures; automatic wallet is an EIP-1193 test adapter',
  mode, checks: [], configHash: config.configHash, completeT08: false }
let child, provider, store, app, browser, fd, progress, finalizer, closing = false
let walletAccount
let retryReceiptPath
const port = Number(process.env.T08_RPC_PORT ?? 18591), httpPort = Number(process.env.T08_HTTP_PORT ?? 18709)
assert([port, httpPort].every(value => Number.isInteger(value) && value >= 1024 && value <= 65535))
async function until(check, timeout = 30000) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) { if (await check()) return; await delay(250) }
  throw new Error('Browser condition timed out')
}
async function closeChain(destroyProvider = true) {
  if (destroyProvider) provider?.destroy()
  if (child?.exitCode === null) {
    child.kill('SIGTERM'); await Promise.race([new Promise(r => child.once('exit', r)), delay(5000, undefined, { ref: false })])
    if (child.exitCode === null) child.kill('SIGKILL')
  }
}
async function cleanup() {
  closing = true
  clearInterval(progress)
  if (browser) await Promise.race([browser.close().catch(() => {}), delay(5000, undefined, { ref: false })])
  if (app) await Promise.race([app.close().catch(() => {}), delay(5000, undefined, { ref: false })])
  await closeChain()
  if (finalizer) await Promise.race([finalizer.catch(() => {}), delay(1000, undefined, { ref: false })])
  store?.close(); if (fd !== undefined) closeSync(fd)
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void cleanup().then(() => process.exit(130)) })
async function startChain() {
  const snapshotFile = join(source, open ? 'application-open-chain.json' : 'application-chain.json')
  const genesis = json(snapshotFile).blocks.find(block => BigInt(block.header.number) === 0n)
  assert(genesis, 'Missing replay genesis header')
  child = spawn('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', '31337', '--silent',
    '--timestamp', String(Number(genesis.header.timestamp)), '--load-state', snapshotFile], { stdio: ['ignore', fd, fd] })
  provider = new JsonRpcProvider('http://127.0.0.1:' + port, 31337, { staticNetwork: true, cacheTimeout: -1, batchMaxCount: 1, pollingInterval: 100 })
  for (let i = 0; i < 100; i++) {
    try {
      if (await provider.send('eth_chainId', []) === '0x7a69') {
        const latest = await provider.getBlock('latest')
        // Restoring state does not restore Anvil's wall-clock offset. Estimates
        // use the pending block, so align it before signing expiring receipts.
        await provider.send('evm_setNextBlockTimestamp', [latest.timestamp + 1])
        return
      }
    } catch {}
    assert.equal(child.exitCode, null, 'Owned Anvil exited'); await delay(100)
  }
  throw new Error('Owned Anvil did not start')
}
async function main() {
  await new Promise((r, reject) => { const socket = net.createServer(); socket.once('error', reject); socket.listen(port, '127.0.0.1', () => socket.close(r)) })
  fd = openSync(join(run, 'anvil.log'), 'w'); await startChain()
  const program = new Contract(round.manifest.programAddress,
    json(join(CRISP, 'packages/crisp-contracts/artifacts/contracts/CRISPProgram.sol/CRISPProgram.json')).abi, provider)
  const savedProofs = json(join(source, 'application-proofs.json'))
  store = new CoordinatorStore(join(run, 'interface.db')); await initializeCoordinator(store, round)
  if (!open) {
    const original = new CoordinatorStore(join(source, 'application.db'))
    try { for (const row of original.db.prepare('SELECT bytes FROM ciphertexts').all()) store.putCiphertext(row.bytes) } finally { original.close() }
    await importProofBundle(store, savedProofs)
  }
  const broadcast = async encoded => {
    const { identity } = decodeSubmission(encoded, round.manifest), fields = abi.decode(envelopeTypes, encoded)
    assert.equal(await program.validateInputProof(round.manifest.e3Id, ...Array.from(fields).slice(0, 5), { gasLimit: 50000000 }), true)
    await reserveAdmission(store, round.manifest, identity)
    const block = await provider.getBlock('latest'), expiresAt = BigInt(block.timestamp) + 600n, id = inputId(round.manifest, identity)
    const domain = { name: 'CRISP', version: '1', chainId: 31337, verifyingContract: round.manifest.programAddress }
    const types = { InputAvailability: [{ name: 'e3Id', type: 'uint256' }, { name: 'inputId', type: 'bytes32' }, { name: 'expiresAt', type: 'uint64' }] }
    const value = { e3Id: round.manifest.e3Id, inputId: id, expiresAt }
    assert.equal(TypedDataEncoder.hash(domain, types, value), await program.inputAvailabilityDigest(round.manifest.e3Id, id, expiresAt))
    const signer = await provider.getSigner(0), signature = await signer.signTypedData(domain, types, value)
    const compact = abi.encode(['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'uint64', 'bytes'], [...Array.from(fields).slice(0, 5), expiresAt, signature])
    writeFileSync(join(run, 'public-commitment.json'), JSON.stringify({ encodedProof: compact, identity }) + '\n')
    finalizer = (async () => {
      for (let i = 0; i < 600; i++) {
        if (closing) return
        if (await program.isInputCommitted(round.manifest.e3Id, identity.ciphertextHash, identity.commitment, identity.slot, identity.parentIndexPlusOne)) {
          await (await program.connect(signer).finalizeInput(round.manifest.e3Id, identity.slot, identity.commitment,
            identity.ciphertextHash, identity.parentIndexPlusOne, fields[5], { gasLimit: 25000000 })).wait(1, 30000); return
        }
        await delay(500)
      }
      throw new Error('Wallet commitment was not observed')
    })()
    void finalizer.catch(() => {})
    return { status: 'ready_for_commitment', encoded_proof: compact }
  }
  app = await startInterface({ config, approvedHash: config.configHash, store, provider, broadcast: open ? broadcast : undefined, port: httpPort })
  console.log('Local secure replay: ' + app.url)
  console.log('Disposable local RPC: http://127.0.0.1:' + port + '; mode ' + mode + '; output ' + run)
  writeFileSync(join(run, 'session.json'), JSON.stringify({ url: app.url, anvilPid: child.pid, supervisorPid: process.pid, source, mode }) + '\n')
  if (['--serve', '--vote'].includes(mode)) { await new Promise(() => {}); return }
  const require = createRequire(join(CRISP, 'package.json')), { chromium } = require('playwright')
  browser = await chromium.launch({ executablePath: process.env.T07_BROWSER_EXECUTABLE ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true })
  const context = await browser.newContext({ viewport: { width: 1100, height: 1000 } }), page = await context.newPage(), requests = []
  let leak = false, walletNetwork = '0x7a69', signatures = 0
  context.on('request', request => {
    const u = new URL(request.url()), body = request.postData() ?? ''
    if (u.pathname.startsWith('/api/') && /"(?:vote|choice|witness|randomness|secretKey|privateKey)"\s*:/.test(body)) leak = true
    requests.push({ host: u.host, path: u.protocol === 'data:' ? '[public embedded asset]' : u.pathname, method: request.method(), bodyBytes: Buffer.byteLength(body) })
    if (u.pathname === '/api/submit' && request.method() === 'POST') {
      const { encodedProof } = JSON.parse(body), decoded = decodeSubmission(encodedProof, round.manifest)
      writeFileSync(join(run, 'public-receipts.json'), JSON.stringify([publicReceipt(encodedProof, round.manifest, decoded.identity.slot)]) + '\n')
    }
  })
  if (open) {
    const signer = await provider.getSigner(0), account = await signer.getAddress()
    walletAccount = account
    await page.exposeBinding('testWalletRequest', async (_, { method, params }) => {
      (report.walletMethods ??= []).push(method)
      if (method === 'eth_chainId') return walletNetwork
      if (['eth_requestAccounts', 'eth_accounts'].includes(method)) return [walletAccount]
      if (method === 'eth_signTypedData_v4') {
        const typed = JSON.parse(params[1]), { EIP712Domain, ...types } = typed.types
        assert.equal(typed.primaryType, 'Ballot'); assert.equal(typed.domain.verifyingContract.toLowerCase(), round.manifest.programAddress)
        signatures++; return signer.signTypedData(typed.domain, types, typed.message)
      }
      if (method === 'eth_sendTransaction') {
        const t = params[0]; assert.equal(t.from.toLowerCase(), walletAccount.toLowerCase()); assert.equal(t.to.toLowerCase(), round.manifest.programAddress)
        assert.equal(BigInt(t.value ?? 0), 0n); assert.equal(program.interface.parseTransaction(t).name, 'publishInput')
        const active = await provider.getSigner(walletAccount)
        const sent = await active.sendTransaction({ to: t.to, data: t.data, value: 0, gasLimit: 25000000 }); await sent.wait(); return sent.hash
      }
      if (['eth_blockNumber', 'eth_estimateGas', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getBlockByNumber',
        'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_getTransactionCount'].includes(method)) {
        try { return await provider.send(method, params) }
        catch (error) {
          let contractError
          try { contractError = program.interface.parseError(error.error?.data ?? error.data)?.name } catch {}
          (report.walletFailures ??= []).push({ method, code: error.code, contractError })
          writeFileSync(join(run, 'wallet-public-request.json'), JSON.stringify({ method, params }) + '\n')
          throw new Error('Local test wallet request failed')
        }
      }
      throw new Error('Unsupported synthetic wallet method')
    })
    await page.addInitScript(() => { window.ethereum = { request: args => window.testWalletRequest(args), on: () => {} } })
    if (mode === '--retry') {
      const receipts = json(resolve(receiptFile)); assert.equal(receipts.length, 1)
      const receipt = restorePublicReceipt(receipts[0], round.manifest, account)
      retryReceiptPath = join(run, 'retry-public-receipt.json')
      writeFileSync(retryReceiptPath, JSON.stringify(receipt) + '\n')
      report.reusedClientProof = true
    }
  }
  await page.goto(app.url)
  if (!open) {
    await until(async () => (await page.locator('#results').textContent()).includes('Synthetic option C: 2'), 120000)
    assert.match(await page.locator('#phase').textContent(), /Secure proof checks passed/)
    assert.match(await page.locator('#results').textContent(), /Synthetic option A: 1/)
    assert.equal(await page.locator('#submit').isDisabled(), true)
    report.checks.push('browser-renders-real-secure-coordinator-result-1-2-2', 'completed-round-keeps-ballot-controls-disabled')
    await page.screenshot({ path: join(run, 'verified-result.png'), fullPage: true })
    await closeChain(false)
    await until(async () => await page.locator('#results').textContent() === '' && /unavailable/i.test(await page.locator('#phase').textContent()))
    report.checks.push('actual-RPC-process-outage-clears-browser-totals')
  } else if (mode === '--round-replay') {
    const snapshot = json(join(source, 'application-chain.json'))
    const orderedBlocks = [...snapshot.blocks].sort((a, b) => Number(BigInt(a.header.number) - BigInt(b.header.number)))
    const admissions = orderedBlocks.flatMap(block => block.transactions).map(entry => entry.transaction.EIP1559)
      .filter(tx => tx.to?.toLowerCase() === round.manifest.programAddress)
      .map(tx => { try { return program.interface.parseTransaction({ data: tx.input }) } catch { return null } })
      .filter(call => call?.name === 'publishInput')
    assert.equal(admissions.length, 6)
    const receipts = admissions.map((call, i) => {
      const fields = abi.decode(['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'uint64', 'bytes'], call.args.data)
      const encoded = abi.encode(envelopeTypes, [...Array.from(fields).slice(0, 5), savedProofs.inputAvailabilityProofs[i].proof])
      return publicReceipt(encoded, round.manifest, fields[1])
    })
    const first = abi.decode(envelopeTypes, receipts[0].encodedProof), wrongCiphertext = savedProofs.inputAvailabilityProofs[1].proof
    const substituted = abi.encode(envelopeTypes, [first[0], first[1], first[2], keccak256(wrongCiphertext), first[4], wrongCiphertext])
    const rejected = await fetch(new URL('/api/submit', app.url), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ encodedProof: substituted }) })
    assert.equal(rejected.status, 503)
    assert.equal(store.list('admission-budget:').length, 0)
    report.checks.push('wrong-ciphertext-SAFE-commitment-rejected-before-attestation-or-quota-reservation')
    for (let i = 0; i < receipts.length; i++) {
      walletAccount = receipts[i].identity.slot
      await page.reload(); await until(async () => await page.locator('#phase').textContent() === 'Voting open')
      await page.locator('#connect').click()
      const receiptPath = join(run, 'saved-receipt-' + i + '.json')
      writeFileSync(receiptPath, JSON.stringify(receipts[i]) + '\n')
      await page.locator('#import-receipt').setInputFiles(receiptPath)
      await until(async () => await page.locator('#continue').isVisible() && !(await page.locator('#continue').isDisabled()))
      await page.locator('#continue').click()
      await until(async () => await page.locator('#feedback').textContent() === 'Availability confirmed', 60000)
      await finalizer
      assert((await page.locator('#import-receipt').inputValue()).endsWith('saved-receipt-' + i + '.json'))
      assert.match(await page.locator('#receipt-file-status').textContent(), /Receipt loaded:/)
      assert.equal((await program.getRoundData(round.manifest.e3Id)).numberOfVotes, BigInt(i + 1))
      console.log('Browser replay admitted and finalized saved ballot ' + (i + 1))
    }
    assert.equal(signatures, 0, 'Saved proofs must not request new ballot signatures')
    const [,, expectedRoot] = abi.decode(['bytes', 'bytes32', 'bytes32'], savedProofs.computeProof)
    assert.equal((await program.getRoundData(round.manifest.e3Id)).inputRoot, BigInt(expectedRoot))
    report.checks.push('browser-delivers-all-six-original-secure-ballots-in-order-without-regenerating-proofs')
    report.checks.push('imported-receipt-filename-and-loaded-confirmation-remain-visible-after-polling')
    const protocol = new Contract(round.manifest.interfoldAddress, [
      'function publishCiphertextOutput(uint256,bytes)', 'function publishPlaintextOutput(uint256,bytes,bytes) returns(bool)',
      'function getE3Stage(uint256) view returns(uint8)'], await provider.getSigner(0))
    await provider.send('evm_setNextBlockTimestamp', [Number(round.manifest.inputEnd) + 1]); await provider.send('evm_mine', [])
    const publications = orderedBlocks.flatMap(block => block.transactions).map(entry => entry.transaction.EIP1559)
      .filter(tx => tx.to?.toLowerCase() === round.manifest.interfoldAddress)
      .map(tx => { try { return protocol.interface.parseTransaction({ data: tx.input }) } catch { return null } })
    const computes = publications.filter(call => call?.name === 'publishCiphertextOutput')
    const decryptions = publications.filter(call => call?.name === 'publishPlaintextOutput')
    assert.equal(computes.length, 1); assert.equal(decryptions.length, 1)
    const reference = computes[0].args[1], plaintext = decryptions[0].args[1]
    assert.equal(decryptions[0].args[2], savedProofs.decryptionProof)
    await (await protocol.publishCiphertextOutput(round.manifest.e3Id, reference, { gasLimit: 25000000 })).wait(1, 30000)
    await (await protocol.publishPlaintextOutput(round.manifest.e3Id, plaintext, savedProofs.decryptionProof, { gasLimit: 10000000 })).wait(1, 30000)
    assert.equal(await protocol.getE3Stage(round.manifest.e3Id), 5n)
    await importProofBundle(store, savedProofs)
    await until(async () => (await page.locator('#results').textContent()).includes('Synthetic option C: 2'), 120000)
    const state = store.get('state')
    assert.equal(state.status, 'verified'); assert.deepEqual(state.result.totals, ['1', '2', '2'])
    assert.equal(state.counts.committed, 6); assert.equal(state.counts.available, 6)
    assert.match(await page.locator('#replay-note').textContent(), /Saved-ballot replay/)
    report.aggregate = state.result.totals; report.admittedInputs = 6; report.originalProofsReused = true
    report.checks.push('actual-protocol-accepts-original-computation-and-threshold-decryption-for-the-browser-delivered-transcript',
      'coordinator-and-browser-show-exact-verified-replay-tally-1-2-2-with-explicit-replay-label')
    writeFileSync(join(run, 'saved-ballot-receipts.json'), JSON.stringify(receipts) + '\n')
    writeFileSync(join(run, 'replay-state.json'), JSON.stringify(state, null, 2) + '\n')
    await page.screenshot({ path: join(run, 'complete-replay.png'), fullPage: true })
  } else {
    await until(async () => await page.locator('#phase').textContent() === 'Voting open')
    walletNetwork = '0x1'; await page.locator('#connect').click()
    await until(async () => (await page.locator('#feedback').textContent()).includes('Wrong network'))
    assert.equal(await page.locator('#submit').isDisabled(), true)
    walletNetwork = '0x7a69'; await page.locator('#connect').click()
    await until(async () => !(await page.locator('#choices').isDisabled()))
    const started = Date.now()
    if (mode === '--retry') {
      await page.locator('#import-receipt').setInputFiles(retryReceiptPath)
      await page.locator('#continue').click()
      report.checks.push('public-receipt-import-stays-local-and-restores-the-exact-account-and-round')
    }
    else { await page.getByLabel('Synthetic option A', { exact: true }).check(); await page.locator('#submit').click() }
    let previous
    progress = setInterval(async () => { try { const text = await page.locator('#feedback').textContent(); if (text !== previous) { previous = text; console.log('Browser: ' + text) } } catch {} }, 2000)
    await until(async () => /Availability confirmed|failed|No new submission|Unable to prepare|signature rejected/i.test(await page.locator('#feedback').textContent()), mode === '--retry' ? 60000 : 20 * 60000)
    const feedback = await page.locator('#feedback').textContent()
    assert.equal(feedback, 'Availability confirmed', 'Secure browser flow: ' + feedback + '; category ' + await page.locator('html').getAttribute('data-failure'))
    await finalizer; assert.equal((await program.getRoundData(round.manifest.e3Id)).numberOfVotes, 1n)
    assert.equal(await program.pendingInputCount(round.manifest.e3Id), 0n); assert.equal(signatures, mode === '--retry' ? 0 : 1)
    assert.equal(await page.locator('#results').textContent(), '', 'New ciphertext has no aggregate proof')
    report.clientFlowMs = Date.now() - started
    report.checks.push('wrong-network-disables-browser-ballot', mode === '--retry' ? 'browser-public-receipt-retry-admits-existing-secure-client-proof' : 'secure-browser-encryption-signature-proof-and-actual-admission-pass',
      'wallet-commitment-finalizes-with-local-availability-receipt', 'new-browser-ballot-is-not-presented-as-the-old-proven-tally')
    await page.screenshot({ path: join(run, 'secure-ballot.png'), fullPage: true })
  }
  assert.equal(leak, false); assert(requests.every(x => [new URL(app.url).host, 'crs.aztec-cdn.foundation', 'crs.aztec-labs.com', ''].includes(x.host)))
  report.checks.push('network-inspection-found-no-plaintext-choice-or-private-witness-fields')
  report.requests = requests; report.browser = await browser.version(); report.result = 'passed'
}
try { await main() }
catch (error) { report.result = 'failed'; report.failure = { code: error.code ?? error.name, message: String(error.shortMessage ?? error.message).slice(0, 400) }; console.error(report.failure) ; process.exitCode = 1 }
finally {
  writeFileSync(join(run, 'browser-verification.json'), JSON.stringify(report, null, 2) + '\n')
  await cleanup()
  await new Promise(resolve => process.stdout.write(JSON.stringify({ output: run, result: report.result, checks: report.checks, clientFlowMs: report.clientFlowMs }) + '\n', resolve))
  // An interrupted Chromium shutdown can retain IPC handles after the browser
  // process exited. All owned chain/service cleanup above is bounded.
  if (!['--serve', '--vote'].includes(mode)) process.exit(process.exitCode ?? 0)
}
