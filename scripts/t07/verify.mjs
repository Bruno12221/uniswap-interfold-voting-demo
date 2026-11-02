// SPDX-License-Identifier: LGPL-3.0-only
// Local orchestration exercise. Cryptographic committee/DA/threshold proofs are explicit fixtures.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { startInterface } from '../../src/interface-server.mjs'
import { decodeSubmission, interfaceHash, restorePublicReceipt } from '../../src/interface.mjs'
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import net from 'node:net'
import { ContractFactory, JsonRpcProvider, Wallet, getBytes, hexlify, keccak256, sha256, toUtf8Bytes, toBeHex, parseEther } from 'ethers'
import { ROOT, CRISP, loadProofRuntime, checkLockedArtifacts } from '../../src/upstream.mjs'
import { buildCensus } from '../../src/census.mjs'
import { address, digest } from '../../src/format.mjs'
import { makeRoundManifest, profile } from '../../src/round.mjs'
import { makeCoordinatorPolicy } from '../../src/coordinator-policy.mjs'
import { CoordinatorStore } from '../../src/coordinator-store.mjs'
import { initializeCoordinator, syncCoordinator, importProofBundle } from '../../src/coordinator.mjs'
import { abi, computeJournal, decryptionDomain } from '../../src/coordinator-protocol.mjs'
import { prepareBoundBallot } from '../../src/ballot.mjs'
import { compileComponents, linkedBytecode, ensurePoseidon } from '../t05/compile.mjs'

const run = resolve(ROOT, '.local/runs/t07-' + new Date().toISOString().replace(/[-:.]/g, ''))
mkdirSync(run, { recursive: true })
const report = { schemaVersion: 1, task: 'T07', sourceRevision: profile.sourceRevision,
  scope: 'Local coordinator on a real EVM with native ciphertexts and original OpenVM receipt adapter. Browser ballot proof uses the original EVM Honk verifier; native extra input, protocol state, availability attestation, Halo2, committee, DA and decryption proofs remain fixtures.', checks: [] }
let child, provider, runtime, store, fd, app, browser, mineTimer, progressTimer
async function cleanup() {
  clearInterval(mineTimer); clearInterval(progressTimer)
  await browser?.close(); browser = undefined; await app?.close(); app = undefined;
  store?.close(); store = undefined; runtime?.sdk.destroyBBApi(); provider?.destroy()
  if (child && child.exitCode === null) {
    child.kill('SIGTERM'); await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(5000)])
    if (child.exitCode === null) child.kill('SIGKILL')
  }
  if (fd !== undefined) { closeSync(fd); fd = undefined }
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void cleanup().finally(() => process.exit(130)) })

async function main() {
  const demo = process.argv[2] === '--demo'
  const demoAddress = demo ? address(process.argv[3]) : null
  console.log('T07 ignored run directory: ' + run)
  await new Promise((resolve, reject) => { const s = net.createServer(); s.once('error', reject); s.listen(18547, '127.0.0.1', () => s.close(resolve)) })
  const compiled = compileComponents(['contracts/FrozenRoundRegistry.sol', 'tests/contracts/T07Fixture.sol'])
  fd = openSync(resolve(run, 'anvil.log'), 'w')
  child = spawn('anvil', ['--host', '127.0.0.1', '--port', '18547', '--chain-id', '31337', '--silent'], { stdio: ['ignore', fd, fd] })
  writeFileSync(resolve(run, 'process.json'), JSON.stringify({ ownedAnvilPid: child.pid }) + '\n')
  provider = new JsonRpcProvider('http://127.0.0.1:18547', 31337, { staticNetwork: true, cacheTimeout: -1, batchMaxCount: 1 })
  let ready = false
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error('Owned Anvil exited')
    try { ready = await provider.send('eth_chainId', []) === '0x7a69' } catch {}
    if (ready) break; await delay(100)
  }
  assert(ready)
  const publisher = await provider.getSigner(0), other = await provider.getSigner(1)
  async function deploy(artifact, args = [], libraries = {}) {
    const c = await new ContractFactory(artifact.abi, linkedBytecode(artifact, libraries), publisher).deploy(...args)
    await c.waitForDeployment(); return c
  }
  const poseidon = await ensurePoseidon(provider, publisher)
  const fixtures = compiled['tests/contracts/T06Fixture.sol']
  const verifierLibraries = {}
  for (const name of ['RelationsLib', 'ZKTranscriptLib']) {
    const artifact = JSON.parse(readFileSync(resolve(CRISP, `packages/crisp-contracts/artifacts/contracts/verifiers/CRISPVerifier.sol/${name}.json`)))
    const library = await deploy(artifact); verifierLibraries[`project/contracts/verifiers/CRISPVerifier.sol:${name}`] = await library.getAddress()
  }
  const honk = await deploy(JSON.parse(readFileSync(resolve(CRISP, 'packages/crisp-contracts/artifacts/contracts/verifiers/CRISPVerifier.sol/HonkVerifier.json'))), [], verifierLibraries)
  const fixture = await deploy(compiled['tests/contracts/T07Fixture.sol'].T07Fixture, [await honk.getAddress()], { 'poseidon-solidity/PoseidonT3.sol:PoseidonT3': poseidon })
  const frozen = await deploy(compiled['contracts/FrozenRoundRegistry.sol'].FrozenRoundRegistry, [await publisher.getAddress()])
  const halo = await deploy(fixtures.T06Halo2Fixture)
  const receipt = await deploy(compiled['.local/upstream/interfold/packages/interfold-contracts/contracts/verifiers/OpenVmReceiptVerifier.sol'].OpenVmReceiptVerifier,
    [await halo.getAddress(), toBeHex(1n, 32), toBeHex(2n, 32)])
  const nodes = [await publisher.getAddress(), await other.getAddress()]
  const committee = await deploy(fixtures.T06CommitteeFixture, [nodes])
  const pk = await deploy(fixtures.T06ProofFixture, [await committee.getAddress()])
  const decrypt = await deploy(fixtures.T06ProofFixture, [await committee.getAddress()])
  const da = await deploy(fixtures.T06AvailabilityFixture)
  runtime = await loadProofRuntime('insecure-512')
  const { publicKey, secretKey } = runtime.sdk.generateBFVKeys()
  const key = hexlify(runtime.core.compute_pk_commitment(publicKey, runtime.params.degree, runtime.params.plaintextModulus, BigUint64Array.from(runtime.params.moduli)))
  const wallet = Wallet.createRandom().connect(provider)
  if (!demo) await (await publisher.sendTransaction({ to: wallet.address, value: parseEther('1') })).wait()
  const proposal = { title: 'Choose a synthetic option', text: 'Local interface exercise. Choose one of three synthetic options. This is not an official Uniswap vote.', url: 'https://gov.uniswap.org/' }
  const template = JSON.parse(readFileSync(resolve(ROOT, 'fixtures/t04-synthetic.json')))
  template.context.choices.push('Synthetic option C')
  const old = template.records[0].address
  template.records[0].address = demoAddress ?? address(wallet.address)
  template.context.candidateAddresses = template.context.candidateAddresses.map(x => x === old ? (demoAddress ?? address(wallet.address)) : x)
  template.context.proposalTextHash = sha256(toUtf8Bytes(proposal.text))
  const census = buildCensus(template.context, template.records), now = await provider.getBlock('latest')
  const manifest = makeRoundManifest(census, census.manifestHash, { chainId: '31337', interfoldAddress: address(await fixture.getAddress()),
    programAddress: address(await fixture.getAddress()), registryAddress: address(await frozen.getAddress()), e3Id: '17', preset: 'insecure-512',
    paramsHash: profile.presets['insecure-512'].paramsHash, committeeKeyCommitment: key, inputStart: String(now.timestamp),
    inputEnd: String(now.timestamp + 14400), artifactsHash: await checkLockedArtifacts() })
  runtime = await loadProofRuntime('insecure-512')
  await (await fixture.configure(census.root, manifest.paramsHash, 3, key, 0, manifest.inputStart, manifest.inputEnd)).wait()
  const setup = await (await fixture.configureCoordinator(await receipt.getAddress(), await da.getAddress(), await committee.getAddress(),
    await pk.getAddress(), await decrypt.getAddress(), BigInt(manifest.inputEnd) - 60n, BigInt(manifest.inputEnd) + 600n)).wait()
  await (await frozen.freeze({ interfold: manifest.interfoldAddress, program: manifest.programAddress, e3Id: 17,
    manifestHash: manifest.manifestHash, censusRoot: census.root, paramsHash: manifest.paramsHash, committeeKey: key, numOptions: 3 })).wait()
  const contracts = {}
  for (const [role, contract] of Object.entries({ protocol: fixture, program: fixture, contextRegistry: frozen, committeeRegistry: committee,
    pkVerifier: pk, decryptionVerifier: decrypt, receiptVerifier: receipt, halo2Verifier: halo, dataAvailabilityVerifier: da })) {
    const a = address(await contract.getAddress()); contracts[role] = { address: a, runtimeHash: keccak256(await provider.getCode(a)), implementation: null }
  }
  contracts.ballotVerifier = { address: address(await honk.getAddress()), runtimeHash: keccak256(await provider.getCode(await honk.getAddress())), implementation: null }
  for (const [index, a] of Object.values(verifierLibraries).entries()) contracts['ballotLibrary' + index] = { address: address(a), runtimeHash: keccak256(await provider.getCode(a)), implementation: null }
  contracts.poseidon = { address: address(poseidon), runtimeHash: keccak256(await provider.getCode(poseidon)), implementation: null }
  const anchor = await provider.getBlock(setup.blockNumber)
  const policy = makeCoordinatorPolicy({ schemaVersion: 1, manifestHash: manifest.manifestHash, assurance: 'development',
    anchor: { number: String(anchor.number), hash: anchor.hash }, confirmations: 2, scanBatchSize: 100, contracts,
    guest: { imageId: await receipt.imageId(), appExeCommit: await receipt.appExeCommit(), appVmCommit: await receipt.appVmCommit() },
    edges: [['program', 'interfold', 'protocol'], ['program', 'openVmVerifier', 'receiptVerifier'],
      ['program', 'dataAvailabilityVerifier', 'dataAvailabilityVerifier'], ['receiptVerifier', 'verifier', 'halo2Verifier'],
      ['decryptionVerifier', 'ciphernodeRegistry', 'committeeRegistry']].map(([from, getter, to]) => ({ from, getter, to })) }, manifest)
  const config = { schemaVersion: 1, manifest, approvedManifestHash: manifest.manifestHash, census, approvedCensusHash: census.manifestHash,
    policy, approvedPolicyHash: policy.policyHash }
  writeFileSync(resolve(run, 'config.json'), JSON.stringify(config, null, 2) + '\n')
  const path = resolve(run, 'state.db'); store = new CoordinatorStore(path)
  await initializeCoordinator(store, config)
  const mine = () => provider.send('evm_mine', [])
  await mine()
  let state = await syncCoordinator(store, provider)
  assert.equal(state.status, 'voting-open', JSON.stringify(state))
  const publicConfig = { schemaVersion: 1, round: config, proposal, publicKey: hexlify(publicKey) }
  publicConfig.configHash = interfaceHash(publicConfig)
  writeFileSync(resolve(run, 'interface.json'), JSON.stringify(publicConfig, null, 2) + '\n')
  const entries = []
  let lastEnvelope, loseResponse = false
  app = await startInterface({ config: publicConfig, approvedHash: publicConfig.configHash, store, provider, port: 18708,
    broadcast: async encoded => {
      const decoded = decodeSubmission(encoded, manifest)
      lastEnvelope = encoded
      if (!demo) {
        if (loseResponse) { loseResponse = false; throw new Error('Simulated lost HTTP response before delivery') }
        const compact = abi.encode(['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'uint64', 'bytes'],
          [decoded.proof, decoded.identity.slot, decoded.identity.commitment, decoded.identity.ciphertextHash,
            decoded.identity.parentIndexPlusOne, (await provider.getBlock('latest')).timestamp + 600, '0x' + '11'.repeat(65)])
        return { status: 'ready_for_commitment', encoded_proof: compact }
      }
      await (await fixture.publishBallot(17, encoded, { gasLimit: 12000000 })).wait()
      lastEnvelope = encoded
      entries.push({ index: String(entries.length), ...decoded.identity, bytes: getBytes(decoded.ciphertext) })
      const daProof = abi.encode(['tuple(bytes32 contentHash,uint32 blockNumber,uint128 leafIndex)'], [[decoded.identity.ciphertextHash, 100, 2]])
      await (await fixture.finalizeInput(17, decoded.identity.slot, decoded.identity.commitment, decoded.identity.ciphertextHash, decoded.identity.parentIndexPlusOne, daProof)).wait()
      return { status: 'pending_availability' }
    } })
  if (demo) {
    mineTimer = setInterval(() => { void mine().catch(() => {}) }, 2000)
    console.log('Local synthetic interface: ' + app.url)
    console.log('Use your disposable wallet on chain 31337. RPC: http://127.0.0.1:18547. Stop with Ctrl-C. No secure result is produced in this preview.')
    await new Promise(() => {})
  }
  report.interfaceConfigHash = publicConfig.configHash
  const require = createRequire(resolve(CRISP, 'package.json'))
  const { chromium } = require('playwright')
  browser = await chromium.launch({ executablePath: process.env.T07_BROWSER_EXECUTABLE ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true })
  const context = await browser.newContext({ viewport: { width: 1100, height: 1000 } })
  const page = await context.newPage()
  const browserDiagnostics = []
  context.on('requestfailed', request => browserDiagnostics.push({ path: new URL(request.url()).pathname, reason: request.failure()?.errorText }))
  page.on('console', message => { if (message.type() === 'error') {
    const value = message.text(); if (/Public prover initialization|Content Security Policy|Failed to fetch|Buffer is not defined|require is not defined/.test(value)) browserDiagnostics.push({ kind: 'browser error', note: value.slice(0, 220) })
  } })
  let network = '0x7a69', account = wallet.address, rejectSignature = false, signatures = 0
  let lostWalletResponse = true, previousFeedback
  progressTimer = setInterval(async () => {
    try { const current = await page.locator('#feedback').textContent(); if (current !== previousFeedback) { previousFeedback = current; console.log('T07 browser: ' + current) } } catch {}
  }, 2000)
  const walletMethods = [], requests = [], pageErrors = []
  page.on('pageerror', error => pageErrors.push(error.name))
  context.on('request', request => {
    const u = new URL(request.url())
    requests.push({ path: u.pathname, host: u.host, method: request.method(), body: request.postData() })
  })
  await page.exposeBinding('testWalletRequest', async (_, { method, params }) => {
    walletMethods.push(method)
    if (method === 'eth_chainId') return network
    if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [account]
    if (method === 'eth_signTypedData_v4') {
      signatures++
      if (rejectSignature) throw new Error('User rejected test signature')
      const typed = JSON.parse(params[1]), { EIP712Domain, ...types } = typed.types
      assert.equal(typed.primaryType, 'Ballot'); assert.equal(typed.domain.name, 'CRISP')
      assert.equal(typed.domain.verifyingContract.toLowerCase(), manifest.programAddress)
      return wallet.signTypedData(typed.domain, types, typed.message)
    }
    if (method === 'eth_sendTransaction') {
      const transaction = params[0]
      assert.equal(address(transaction.from), address(wallet.address)); assert.equal(address(transaction.to), manifest.programAddress)
      assert.equal(BigInt(transaction.value ?? 0), 0n)
      const call = fixture.interface.parseTransaction({ data: transaction.data })
      assert.equal(call.name, 'publishInput'); assert.equal(call.args[0], 17n)
      const decoded = decodeSubmission(lastEnvelope, manifest)
      const sent = await wallet.sendTransaction({ to: transaction.to, data: transaction.data, value: 0n, gasLimit: 12000000 })
      await sent.wait()
      entries.push({ index: String(entries.length), ...decoded.identity, bytes: getBytes(decoded.ciphertext) })
      if (lostWalletResponse) { lostWalletResponse = false; throw new Error('Simulated lost wallet RPC response after admission') }
      return sent.hash
    }
    if (['eth_blockNumber', 'eth_estimateGas', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getBlockByNumber', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_getTransactionCount'].includes(method)) return provider.send(method, params)
    throw new Error('Unsupported synthetic wallet method')
  })
  await page.addInitScript(() => {
    const listeners = new Map()
    window.ethereum = { request: args => window.testWalletRequest(args), on: (event, fn) => {
      if (!listeners.has(event)) listeners.set(event, []); listeners.get(event).push(fn)
    } }
    window.testWalletEvent = event => { for (const fn of listeners.get(event) ?? []) fn([]) }
  })
  async function text(selector, expected, timeout = 30000) {
    console.log('T07 checking: ' + selector + ' → ' + expected)
    const until = Date.now() + timeout
    while (Date.now() < until) {
      if (expected === 'Submission uncertain') {
        const state = await page.locator('#feedback').textContent()
        if (state.includes(' failed.') || state.includes('No new submission')) { console.log('T07 safe failure: ' + state + ' / ' + await page.locator('html').getAttribute('data-failure')); console.log(JSON.stringify(browserDiagnostics)); throw new Error('Browser proving stopped') }
      }
      if ((await page.locator(selector).textContent())?.includes(expected)) return
      await delay(200)
    }
    console.log(JSON.stringify(browserDiagnostics))
    console.log('T07 page status: ' + await page.locator('#feedback').textContent() + ' / ' + await page.locator('#phase').textContent())
    throw new Error('Browser state timeout: ' + selector + ' → ' + expected)
  }
  await page.goto(app.url)
  await text('#phase', 'Voting open')
  assert.equal(await page.locator('h1').textContent(), 'Synthetic voting experiment')
  assert.equal(await page.locator('#proposal').textContent(), proposal.text)
  assert.equal(await page.locator('input[name=choice]').count(), 4)
  assert(await page.locator('#submit').isDisabled())
  report.checks.push('approved proposal, snapshot, credit, limits, choices and commitment cutoff render before signing')
  await page.goto(app.url.split('#')[0] + '#' + toBeHex(1, 32))
  await text('#title', 'Approved configuration unavailable')
  assert(await page.locator('#connect').isDisabled())
  await page.goto(app.url); await text('#phase', 'Voting open')
  network = '0x1'; await page.locator('#connect').click(); await text('#feedback', 'Wrong network')
  assert(await page.locator('#submit').isDisabled())
  network = '0x7a69'; account = Wallet.createRandom().address
  await page.locator('#connect').click(); await text('#eligibility', 'not eligible')
  assert(await page.locator('#submit').isDisabled())
  account = wallet.address; await page.locator('#connect').click(); await text('#eligibility', '1 synthetic vote')
  report.checks.push('wrong fingerprint, wrong wallet chain and ineligible wallet disable signing')
  // Keyboard-only selection/submission through the actual EIP-1193 signature path.
  rejectSignature = true
  await page.locator('input[name=choice]').first().focus(); await page.keyboard.press('Space')
  await page.locator('#submit').focus(); await page.keyboard.press('Enter')
  await text('#feedback', 'Voting signature rejected', 120000)
  assert.equal(signatures, 1); assert.equal(entries.length, 0)
  report.checks.push('keyboard flow and rejected voting signature leave no admitted input')
  rejectSignature = false
  await page.locator('input[name=choice]').first().focus(); await page.keyboard.press('Space')
  // Loss is after real EVM admission; the UI must recover from events, never HTTP success.
  loseResponse = true
  const started = performance.now()
  await page.locator('#submit').focus(); await page.keyboard.press('Enter')
  await text('#feedback', 'Submission uncertain', 900000)
  assert.equal(entries.length, 0); assert(lastEnvelope)
  report.browserProofMs = Math.round(performance.now() - started)
  await page.locator('#continue').focus(); await page.keyboard.press('Enter')
  await text('#feedback', 'Delivery remains uncertain', 120000)
  assert.equal(entries.length, 1)
  report.checks.push('browser encryption and proof pass original EVM Honk verifier through seven-field wallet commitment', 'lost HTTP response before admission and lost wallet response after admission recover without a false inclusion claim')
  await mine()
  await text('#feedback', 'Commitment confirmed')
  const availability = (hash, block, leaf) => abi.encode(['tuple(bytes32 contentHash,uint32 blockNumber,uint128 leafIndex)'], [[hash, block, leaf]])
  entries[0].availabilityProof = availability(entries[0].ciphertextHash, 100, 2)
  await (await fixture.finalizeInput(17, entries[0].slot, entries[0].commitment, entries[0].ciphertextHash, 0, entries[0].availabilityProof)).wait()
  await mine(); await text('#feedback', 'Availability confirmed')
  assert.equal(await page.locator('#results li').count(), 0)
  // Replacement must fetch and authenticate the confirmed parent, with the same wallet flow.
  const parent = await fetch(app.url.split('/#')[0] + '/api/parent?slot=' + address(wallet.address)).then(x => x.json())
  assert.equal(parent.entry.index, '0'); assert.equal(parent.entry.ciphertext, hexlify(entries[0].bytes))
  rejectSignature = true
  await page.locator('input[name=choice]').nth(2).check(); await page.locator('#submit').click()
  await text('#feedback', 'Voting signature rejected', 120000)
  assert.equal(signatures, 3); assert.equal(entries.length, 1)
  await page.evaluate(() => window.testWalletEvent('accountsChanged'))
  await text('#account', 'Wallet not connected'); assert(await page.locator('#submit').isDisabled())
  await page.locator('#connect').click(); await text('#feedback', 'Availability confirmed')
  await page.reload(); await text('#phase', 'Voting open'); await page.locator('#connect').click(); await text('#feedback', 'Availability confirmed')
  report.checks.push('confirmed commitment and DA shown separately; replacement authenticates parent; account change cancels; reload recovers public receipt')
  rejectSignature = false
  const replacementStarted = performance.now()
  await page.locator('input[name=choice]').nth(2).check(); await page.locator('#submit').click()
  const replacementUntil = Date.now() + 900000
  while (entries.length < 2 && Date.now() < replacementUntil) {
    const state = await page.locator('#feedback').textContent()
    if (state.includes(' failed.')) throw new Error('Replacement proving failed')
    await delay(200)
  }
  assert.equal(entries.length, 2, 'Replacement did not reach the EVM')
  report.replacementProofMs = Math.round(performance.now() - replacementStarted)
  assert.equal(entries[1].parentIndexPlusOne, '1')
  await mine(); await text('#feedback', 'Commitment confirmed')
  entries[1].availabilityProof = availability(entries[1].ciphertextHash, 101, 3)
  await (await fixture.finalizeInput(17, entries[1].slot, entries[1].commitment, entries[1].ciphertextHash, 1, entries[1].availabilityProof)).wait()
  await mine(); await text('#feedback', 'Availability confirmed')
  const replaced = await fetch(app.url.split('/#')[0] + '/api/status').then(x => x.json())
  assert.deepEqual(replaced.dispositions, ['superseded', 'selected'])
  report.checks.push('successful browser replacement names exact parent and passes original EVM proof verifier; old head becomes superseded')
  // A second, explicit native fixture input makes the displayed aggregate distinct from the browser ballot.
  const secondSlot = census.eligible.find(x => x.address !== address(wallet.address)).address
  const bytes = runtime.sdk.encryptVote([0, 1, 0], publicKey)
  const second = { index: '2', slot: secondSlot, bytes, commitment: hexlify(runtime.generator.computeCtCommitment(bytes)),
    ciphertextHash: keccak256(bytes), parentIndexPlusOne: '0' }
  second.availabilityProof = availability(second.ciphertextHash, 102, 2)
  await (await fixture.commitInput(17, second.slot, second.commitment, second.ciphertextHash, 0)).wait()
  store.putCiphertext(bytes); entries.push(second)
  await (await fixture.finalizeInput(17, second.slot, second.commitment, second.ciphertextHash, 0, second.availabilityProof)).wait()
  await provider.send('evm_setNextBlockTimestamp', [Number(manifest.inputEnd) + 10]); await mine(); await mine()
  await text('#phase', 'Computing')
  assert(await page.locator('#submit').isDisabled())
  const output = runtime.generator.generateInputs(entries[1].bytes, publicKey, BigInt64Array.from([0n, 1n, 0n]), true).encryptedVote
  const decrypted = Array.from(runtime.generator.decryptVote(secretKey, output), BigInt)
  assert.deepEqual(decrypted.slice(0, 3), [0n, 1n, 1n]); assert(decrypted.slice(3).every(x => x === 0n))
  const outputHash = keccak256(output), outputCommitment = hexlify(runtime.generator.computeCtCommitment(output))
  const roundData = await fixture.getRoundData(17)
  const proofData = new Uint8Array(55 * 32).fill(0x42), seal = abi.encode(['uint8', 'bytes'], [1, proofData])
  const computeProof = abi.encode(['bytes', 'bytes32', 'bytes32'], [seal, manifest.paramsHash, toBeHex(roundData[4], 32)])
  const journalDigest = sha256(computeJournal(manifest, outputHash, outputCommitment, roundData[4].toString()))
  await (await halo.expect(journalDigest, keccak256(proofData))).wait()
  const committeeHash = await committee.getCommitteeHash(17), pkProof = '0x1111', decryptionProof = '0x2222'
  await (await pk.expect(keccak256(abi.encode(['uint256', 'uint256', 'address[]', 'bytes32', 'bytes32', 'bytes'], [17, 777, nodes, key, committeeHash, pkProof])))).wait()
  const plaintext = new Uint8Array(400), view = new DataView(plaintext.buffer)
  view.setBigUint64(8, 1n, true); view.setBigUint64(16, 1n, true)
  await (await decrypt.expect(keccak256(abi.encode(['uint256', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes'],
    [17, decryptionDomain(manifest, committeeHash, outputHash), keccak256(plaintext), committeeHash, outputCommitment, decryptionProof])))).wait()
  const outputAvailabilityProof = availability(outputHash, 500, 3)
  const reference = abi.encode(['tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes computeProof,bytes availabilityProof)'],
    [[outputHash, outputCommitment, computeProof, outputAvailabilityProof]])
  await (await fixture.publishCiphertextOutput(17, reference)).wait()
  await (await fixture.publishPlaintextOutput(17, plaintext, decryptionProof)).wait(); await mine()
  await text('#phase', 'Waiting for public proof evidence')
  assert.equal(await page.locator('#results li').count(), 0)
  const bundle = { schemaVersion: 1, manifestHash: manifest.manifestHash, policyHash: policy.policyHash, publicKey: hexlify(publicKey), pkProof,
    computeProof, outputCiphertext: hexlify(output), outputAvailabilityProof,
    inputAvailabilityProofs: entries.map(x => ({ index: x.index, proof: x.availabilityProof })), decryptionProof }
  await importProofBundle(store, bundle)
  await text('#phase', 'Development checks complete')
  await text('#results', 'Synthetic option C: 1')
  assert.equal(await page.locator('#results li').count(), 3)
  await text('#results', 'No secure attestation')
  await page.screenshot({ path: resolve(run, 'development-result.png'), fullPage: true })
  report.checks.push('closed commitment window disables ballot; computing and evidence-wait states hide totals; complete T06 development checks render aggregate 0,1,1 with mock warning')
  const evidence = await fetch(app.url.split('/#')[0] + '/api/evidence').then(x => x.json())
  assert.equal(evidence.entries.length, 3); assert.equal(evidence.proofBundle.computeProof, computeProof)
  await (await decrypt.expect(toBeHex(1, 32))).wait(); await mine()
  await text('#phase', 'Evidence check failed'); assert.equal(await page.locator('#results li').count(), 0)
  await (await fixture.setStage(6)).wait(); await mine()
  await text('#phase', 'Round failed'); assert.equal(await page.locator('#results li').count(), 0)
  report.checks.push('public evidence contains full input set; invalid decryption and failed round remove prior totals')
  // Only public envelope and read-only RPC payloads may leave the browser.
  for (const request of requests.filter(x => x.method === 'POST')) {
    assert(request.host === '127.0.0.1:18708')
    const body = JSON.parse(request.body)
    assert.deepEqual(Object.keys(body).sort(), request.path === '/api/submit' ? ['encodedProof'] : ['id', 'jsonrpc', 'method', 'params'])
  }
  const writes = walletMethods.filter(x => x !== 'eth_requestAccounts' && x !== 'eth_accounts' && x !== 'eth_chainId')
  assert(writes.includes('eth_sendTransaction')); assert(writes.filter(x => x === 'eth_sendTransaction').length === 2)
  assert.equal(pageErrors.length, 0)
  assert.equal(await page.evaluate(() => localStorage.length), 0)
  const stored = await page.evaluate(() => Object.values(sessionStorage).map(JSON.parse))
  assert(stored.every(x => restorePublicReceipt(x, manifest, wallet.address).encodedProof === lastEnvelope))
  const url = app.url.split('/#')[0]
  const rpcWrite = await fetch(url + '/api/rpc', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: 1, jsonrpc: '2.0', method: 'eth_sendTransaction', params: [] }) })
  assert.equal(rpcWrite.status, 503)
  const crossOrigin = await fetch(url + '/api/submit', { method: 'POST', headers: { Origin: 'https://example.com', 'Content-Type': 'application/json' }, body: '{}' })
  assert.equal(crossOrigin.status, 403)
  report.checks.push('network audit finds only public envelopes and chain reads; no token approval or value transfer; two exact zero-value commitment transactions; only public envelope and identity persisted; RPC writes and cross-origin requests rejected')
  await page.setViewportSize({ width: 390, height: 844 })
  await page.screenshot({ path: resolve(run, 'mobile.png'), fullPage: true })
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await page.setViewportSize({ width: 1100, height: 1000 })
  await page.screenshot({ path: resolve(run, 'desktop.png'), fullPage: true })
  report.checks.push('desktop and narrow-screen rendering checked; keyboard selection and submission exercised')
  report.result = 'passed'; report.aggregate = ['0', '1', '1']; report.browser = await browser.version()
  report.limitations = ['Synthetic EIP-1193 wallet adapter; no real extension UI tested.', 'Only insecure-512 browser proving measured.', 'Protocol, native extra input, committee, DA, computation and decryption remain fixtures; T08 secure complete round not executed.', 'No live deployment or external CRISP availability service tested.']
  writeFileSync(resolve(run, 'interface-evidence.json'), JSON.stringify(report, null, 2) + '\n')
  writeFileSync(resolve(ROOT, '.local/t07-latest.json'), JSON.stringify({ run }) + '\n')
  console.log('T07 passed: ' + report.checks.length + ' browser/EVM checks; aggregate 0,1,1; browser proof ' + report.browserProofMs + ' ms.')
}
try { await main() }
catch (error) { report.result = 'failed'; report.failureCode = error.code ?? error.name; writeFileSync(resolve(run, 'interface-evidence.json'), JSON.stringify(report, null, 2) + '\n'); console.error(error); process.exitCode = 1 }
finally { await cleanup() }
