// SPDX-License-Identifier: LGPL-3.0-only
// Add a context freeze to a disposable signed-transaction replay. Never regenerate a proof.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'
import { Contract, ContractFactory, JsonRpcSigner, getBytes, hexlify, keccak256, sha256, toBeHex, toUtf8Bytes } from 'ethers'
import { ROOT, CRISP, UPSTREAM, checkLockedArtifacts, loadProofRuntime } from '../../src/upstream.mjs'
import { buildCensus } from '../../src/census.mjs'
import { address } from '../../src/format.mjs'
import { makeRoundManifest, profile, readBoundRound } from '../../src/round.mjs'
import { makeCoordinatorPolicy, assertCoordinatorPolicy, verifyDeployment } from '../../src/coordinator-policy.mjs'
import { CoordinatorStore } from '../../src/coordinator-store.mjs'
import { initializeCoordinator, syncCoordinator, importProofBundle, replayCoordinator } from '../../src/coordinator.mjs'
import { rebuildLedger } from '../../src/coordinator.mjs'
import { verifyRoundProofs } from '../../src/coordinator-proofs.mjs'
import { abi, EVENT_TOPICS, normalizeLog } from '../../src/coordinator-protocol.mjs'
import { authenticatePublicKey } from '../../src/ballot-core.mjs'
import { compileComponents, linkedBytecode } from '../t05/compile.mjs'
import { checkProgramBindings } from './deployment_bindings.mjs'

const json = file => JSON.parse(readFileSync(file, 'utf8'))
const publisher = '0x0000000000000000000000000000000000000808'
const implementationSlot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
const proposal = { title: 'Synthetic private preliminary poll',
  text: 'Local synthetic demonstration. Choose one of three synthetic options. This poll has no effect on Uniswap governance.',
  url: 'https://github.com/theinterfold/interfold' }

function inputItems(file) {
  const bytes = readFileSync(file), count = bytes.readUInt32LE(0), items = []
  assert.equal(count, 12, 'Expected header, six public ciphertexts and five selected copies')
  let offset = 4
  for (let i = 0; i < count; i++) {
    assert(offset + 8 <= bytes.length)
    const length = Number(bytes.readBigUInt64LE(offset)); offset += 8
    assert(Number.isSafeInteger(length) && length > 0 && offset + length <= bytes.length)
    items.push(bytes.subarray(offset, offset + length)); offset += length
  }
  assert.equal(offset, bytes.length)
  for (let i = 0; i < 5; i++) assert.deepEqual(items[7 + i], items[2 + i], 'Selected ciphertext copy differs')
  return items.slice(1, 7)
}

export class ApplicationReplay {
  constructor({ provider, records, output, all, recovery, inputFile }) {
    Object.assign(this, { provider, records, output, all, recovery })
    this.inputBytes = inputItems(inputFile)
    this.chain = json(join(recovery, 'public-chain.json'))
    this.checks = []
  }
  async saveChain(name) {
    const bytes = Buffer.from(getBytes(await this.provider.send('anvil_dumpState', [])))
    writeFileSync(join(this.output, name), bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes) : bytes)
  }
  async freeze(e3Id) {
    const { provider, records } = this
    assert.equal(await provider.getCode(publisher), '0x')
    assert.equal(await provider.getTransactionCount(publisher), 0)
    await provider.send('anvil_impersonateAccount', [publisher])
    await provider.send('anvil_setBalance', [publisher, toBeHex(10n ** 22n)])
    const compiled = compileComponents(['contracts/FrozenRoundRegistry.sol'])
    const artifact = compiled['contracts/FrozenRoundRegistry.sol'].FrozenRoundRegistry
    await provider.send('evm_setAutomine', [true])
    try {
      const registry = await new ContractFactory(artifact.abi, linkedBytecode(artifact), new JsonRpcSigner(provider, publisher)).deploy(publisher)
      await registry.waitForDeployment()
      const programArtifact = json(join(CRISP, 'packages/crisp-contracts/artifacts/contracts/CRISPProgram.sol/CRISPProgram.json'))
      const program = new Contract(records.CRISPProgram.address, programArtifact.abi, provider)
      const protocolArtifact = json(join(UPSTREAM, 'packages/interfold-contracts/artifacts/contracts/Interfold.sol/Interfold.json'))
      const protocol = new Contract(records.Interfold.address, protocolArtifact.abi, provider)
      const e3 = await protocol.getE3(e3Id), round = await program.getRoundData(e3Id)
      assert.equal(await protocol.getE3Stage(e3Id), 3n)
      assert.equal(round.numberOfVotes, 0n)
      const mockSource = readFileSync(join(CRISP, 'server/src/server/token_holders/etherscan.rs'), 'utf8')
      const holderFunction = mockSource.slice(mockSource.indexOf('pub fn get_mock_token_holders'))
      const addresses = [...holderFunction.slice(0, holderFunction.indexOf(']')).matchAll(/"(0x[0-9a-fA-F]{40})"/g)].map(x => address(x[1]))
      assert.equal(addresses.length, 10)
      const template = json(join(ROOT, 'fixtures/t04-synthetic.json'))
      const anchor = await provider.getBlock(0)
      const context = { ...template.context, candidateAddresses: addresses,
        proposalTextHash: sha256(toUtf8Bytes(proposal.text)), choices: ['Synthetic option A', 'Synthetic option B', 'Synthetic option C'],
        snapshotBlockHash: anchor.hash, authority: 'Pinned local mock census, independently reconstructed before replay admissions' }
      const census = buildCensus(context, addresses.map(address => ({ address, weight: '1' })))
      assert.equal(census.root, round.merkleRoot.toString(), 'Original census was not reproduced exactly')
      const manifest = makeRoundManifest(census, census.manifestHash, { chainId: '31337', interfoldAddress: address(protocol.target),
        programAddress: address(program.target), registryAddress: address(registry.target), e3Id: String(e3Id), preset: 'secure-8192',
        paramsHash: profile.presets['secure-8192'].paramsHash, committeeKeyCommitment: e3.committeePublicKey,
        inputStart: String(e3.inputWindow[0]), inputEnd: String(e3.inputWindow[1]), artifactsHash: await checkLockedArtifacts() })
      const freezeRequest = { interfold: manifest.interfoldAddress, program: manifest.programAddress, e3Id,
        manifestHash: manifest.manifestHash, censusRoot: census.root, paramsHash: manifest.paramsHash,
        committeeKey: manifest.committeeKeyCommitment, numOptions: 3 }
      await assert.rejects(registry.freeze.staticCall({ ...freezeRequest, censusRoot: 1n }), error => error.revert?.name === 'RoundMismatch')
      await assert.rejects(registry.connect(await provider.getSigner(0)).freeze.staticCall(freezeRequest), error => error.revert?.name === 'OnlyPublisher')
      await (await registry.freeze(freezeRequest)).wait()
      await assert.rejects(registry.freeze.staticCall({ ...freezeRequest, manifestHash: toBeHex(1, 32) }), error => error.revert?.name === 'AlreadyFrozen')
      await readBoundRound(provider, manifest, 3)
      const contracts = {}
      const roleRecords = { protocol: 'Interfold', program: 'CRISPProgram', committeeRegistry: 'CiphernodeRegistryOwnable',
        pkVerifier: 'BfvPkVerifier', decryptionVerifier: 'BfvDecryptionVerifier', receiptVerifier: 'OpenVmReceiptVerifier',
        halo2Verifier: 'OpenVmHalo2Verifier', dataAvailabilityVerifier: 'MockCrispDataAvailabilityVerifier',
        ballotVerifier: 'HonkVerifier', onchainBallotVerifier: 'OnchainHonkVerifier', ciphertextVerifier: 'OpenVmBfvCiphertextVerifier',
        committeeCircuitVerifier: 'DkgAggregatorVerifier', decryptionCircuitVerifier: 'DecryptionAggregatorVerifier',
        foldAttestationVerifier: 'DkgFoldAttestationVerifier' }
      for (const [role, name] of [...Object.entries(roleRecords), ['contextRegistry', null]]) {
        const a = address(name ? records[name].address : registry.target), code = await provider.getCode(a)
        const impl = await provider.getStorage(a, implementationSlot)
        contracts[role] = { address: a, runtimeHash: keccak256(code), implementation: BigInt(impl) === 0n ? null :
          { address: address('0x' + impl.slice(-40)), runtimeHash: keccak256(await provider.getCode('0x' + impl.slice(-40))) } }
      }
      const receipt = new Contract(records.OpenVmReceiptVerifier.address,
        ['function imageId() view returns(bytes32)', 'function appExeCommit() view returns(bytes32)', 'function appVmCommit() view returns(bytes32)'], provider)
      const policy = makeCoordinatorPolicy({ schemaVersion: 1, manifestHash: manifest.manifestHash, assurance: 'secure-candidate',
        anchor: { number: '0', hash: anchor.hash }, confirmations: 1, scanBatchSize: 1000, contracts,
        guest: { imageId: await receipt.imageId(), appExeCommit: await receipt.appExeCommit(), appVmCommit: await receipt.appVmCommit() },
        edges: [['program', 'interfold', 'protocol'], ['program', 'openVmVerifier', 'receiptVerifier'],
          ['program', 'dataAvailabilityVerifier', 'dataAvailabilityVerifier'], ['receiptVerifier', 'verifier', 'halo2Verifier'],
          ['decryptionVerifier', 'ciphernodeRegistry', 'committeeRegistry'], ['pkVerifier', 'circuitVerifier', 'committeeCircuitVerifier'],
          ['decryptionVerifier', 'circuitVerifier', 'decryptionCircuitVerifier'], ['ciphertextVerifier', 'openVmVerifier', 'receiptVerifier']]
          .map(([from, getter, to]) => ({ from, getter, to })) }, manifest)
      const compilerOutput = json(join(CRISP, 'packages/crisp-contracts/artifacts/build-info', programArtifact.buildInfoId + '.output.json'))
      this.bindings = checkProgramBindings({ chain: this.chain, records, artifact: programArtifact, compilerOutput, code: await provider.getCode(program.target) })
      this.config = { schemaVersion: 1, manifest, approvedManifestHash: manifest.manifestHash, census, approvedCensusHash: census.manifestHash,
        policy, approvedPolicyHash: policy.policyHash }
      this.checks.push('original-ten-address-unit-census-rebuilt-exactly', 'proposal-context-frozen-on-chain-before-first-secure-admission',
        'wrong-census-freeze-rejected', 'unauthorized-context-publisher-rejected', 'frozen-proposal-context-cannot-be-replaced',
        'private-ballot-verifier-constructor-bindings-and-all-signing-domain-immutables-checked')
      writeFileSync(join(this.output, 'application-config.json'), JSON.stringify(this.config, null, 2) + '\n')
      await this.saveChain('application-open-chain.json')
      console.log('Application context frozen before admissions; candidate policy ' + policy.policyHash)
    } finally {
      await provider.send('evm_setAutomine', [false])
      await provider.send('anvil_stopImpersonatingAccount', [publisher])
    }
  }
  async finish() {
    const { provider, config, all } = this, { manifest, census, policy } = config
    const find = name => { const values = all.filter(x => x.parsed?.name === name); assert.equal(values.length, 1); return values[0].parsed }
    const keyChunks = all.filter(x => x.parsed?.name === 'publishCommitteePublicKey').map(x => x.parsed.args).sort((a, b) => Number(a.chunkIndex - b.chunkIndex))
    assert.equal(keyChunks.length, 5)
    keyChunks.forEach((x, i) => { assert.equal(x.e3Id, BigInt(manifest.e3Id)); assert.equal(x.chunkIndex, BigInt(i));
      assert.equal(x.chunkCount, 5n); assert.equal(x.candidateHash, keyChunks[0].candidateHash); assert.equal(x.totalLength, keyChunks[0].totalLength) })
    const publicKey = '0x' + keyChunks.map(x => x.chunk.slice(2)).join('')
    assert.equal(getBytes(publicKey).length, Number(keyChunks[0].totalLength)); assert.equal(keccak256(publicKey), keyChunks[0].candidateHash)
    const runtime = await loadProofRuntime(manifest.preset)
    try {
      authenticatePublicKey(runtime, getBytes(publicKey), manifest.committeeKeyCommitment)
      const logs = await provider.getLogs({ address: [manifest.programAddress, manifest.interfoldAddress],
        topics: [EVENT_TOPICS, toBeHex(BigInt(manifest.e3Id), 32)], fromBlock: 0, toBlock: 'latest' })
      const events = logs.map(log => normalizeLog(log, manifest)), { ledger, output, plaintext } = rebuildLedger(events, manifest, census)
      assert.equal(ledger.length, 6)
      this.inputBytes.forEach((bytes, i) => { assert.equal(keccak256(bytes), ledger[i].ciphertextHash);
        assert.equal(hexlify(runtime.generator.computeCtCommitment(bytes)), ledger[i].commitment) })
      const reference = abi.decode(['tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes proof,bytes availabilityProof)'], find('publishCiphertextOutput').args.encodedOutputReference)[0]
      const finalizations = all.filter(x => x.parsed?.name === 'finalizeInput').map(x => x.parsed.args)
      const bundle = { schemaVersion: 1, manifestHash: manifest.manifestHash, policyHash: policy.policyHash, publicKey,
        pkProof: find('publishCommittee').args.proof, computeProof: reference.proof,
        outputCiphertext: hexlify(readFileSync(join(this.recovery, 'recovery-native.ciphertext.bin'))), outputAvailabilityProof: reference.availabilityProof,
        inputAvailabilityProofs: ledger.map(entry => {
          const matching = finalizations.filter(x => address(x[1]) === entry.slot && x[2] === entry.commitment && x[3] === entry.ciphertextHash && String(x[4]) === entry.parentIndexPlusOne)
          assert.equal(matching.length, 1); return { index: entry.index, proof: matching[0][5] }
        }), decryptionProof: find('publishPlaintextOutput').args.proof }
      const blockTag = await provider.getBlockNumber(), snapshot = await readBoundRound(provider, manifest, 5, { blockTag })
      snapshot.census = census
      await verifyDeployment(provider, policy, blockTag)
      const getCiphertext = hash => this.inputBytes.find(bytes => keccak256(bytes) === hash)
      const result = await verifyRoundProofs({ provider, manifest, policy, bundle, ledger, output, plaintext, snapshot, getCiphertext, blockTag })
      assert.deepEqual(result.totals, ['1', '2', '2'])
      this.checks.push('public-key-reassembled-from-five-original-on-chain-chunks-and-commitment-authenticated',
        'all-six-public-ciphertexts-match-admitted-hashes-and-commitments', 'application-proof-bundle-passes-real-key-computation-decryption-and-full-transcript-checks')
      writeFileSync(join(this.output, 'application-proofs.json'), JSON.stringify(bundle) + '\n')
      writeFileSync(join(this.output, 'application-interface.json'), JSON.stringify({ proposal, publicKey }, null, 2) + '\n')
      let approved = false
      try { assertCoordinatorPolicy(policy, policy.policyHash, manifest); approved = true }
      catch (error) { assert.equal(error.code, 'SECURE_POLICY_NOT_REVIEWED') }
      if (approved) await this.checkCoordinator(bundle)
      await this.saveChain('application-chain.json')
      const report = { scope: 'Disposable application integration replay; context added before the original admissions. Original VM execution is separate.',
        policyHash: policy.policyHash, manifestHash: manifest.manifestHash, checks: this.checks, programBindings: this.bindings,
        tally: result.totals, policyApproved: approved, completeT08: false,
        limits: ['One operator controls all committee nodes', 'Eligibility, randomness and availability are local fixtures',
          'No new proof generation; all original proof-bound inputs and contract addresses retained',
          'Two extra context transactions; original chain roots are not reproduced',
          'Six controlled admissions; 60-admission attestation budget is not yet enforced',
          'Browser, ordinary wallet and fresh-operator checks remain separate'] }
      writeFileSync(join(this.output, 'application-verification.json'), JSON.stringify(report, null, 2) + '\n')
      console.log('Application replay checks passed: ' + this.checks.length + '; secure policy approved: ' + approved)
    } finally { runtime.sdk.destroyBBApi() }
  }
  async checkCoordinator(bundle) {
    const { config, provider, output } = this, path = join(output, 'application.db')
    let store = new CoordinatorStore(path)
    const recover = async (rpc = provider) => {
      let state
      for (let i = 0; i < 100; i++) { state = await syncCoordinator(store, rpc); if (state.status !== 'catching-up') return state }
      throw new Error('Coordinator did not finish its bounded scan')
    }
    const wrap = overrides => new Proxy(provider, { get(target, name) { if (name in overrides) return overrides[name];
      const value = Reflect.get(target, name, target); return typeof value === 'function' ? value.bind(target) : value } })
    const valid = state => { assert.equal(state.status, 'verified', JSON.stringify(state)); assert.deepEqual(state.result.totals, ['1', '2', '2']) }
    try {
      await initializeCoordinator(store, config)
      this.inputBytes.forEach(bytes => store.putCiphertext(bytes))
      const waiting = await recover()
      assert.equal(waiting.status, 'awaiting-proof-bundle'); assert.equal(waiting.result, null)
      this.checks.push('missing-computation-evidence-remains-pending-without-a-result')
      await importProofBundle(store, bundle); valid(await recover())
      this.checks.push('actual-coordinator-verifies-the-frozen-secure-round-to-exact-tally')
      store.close(); store = new CoordinatorStore(path); valid(await recover())
      this.checks.push('coordinator-restart-preserves-six-inputs-and-reverifies-existing-proofs')
      const before = store.get('state')
      const unavailable = wrap({ getBlock: async () => { throw Object.assign(new Error('transport outage'), { code: 'SERVER_ERROR' }) } })
      const outage = await recover(unavailable)
      assert.equal(outage.status, 'pending-rpc'); assert.equal(outage.result, null); assert.deepEqual(outage.cursor, before.cursor)
      valid(await recover()); this.checks.push('RPC-outage-clears-result-and-recovers-with-same-secure-proofs')
      await replayCoordinator(store)
      const repeated = wrap({ getLogs: async filter => { const logs = await provider.getLogs(filter); return [...logs].reverse().concat(logs) } })
      valid(await recover(repeated)); this.checks.push('duplicate-and-reordered-RPC-events-preserve-verified-secure-result')
      await replayCoordinator(store)
      const omitted = wrap({ getLogs: async filter => { const logs = await provider.getLogs(filter);
        const index = logs.findIndex(x => x.topics[0] === EVENT_TOPICS[0]); return index < 0 ? logs : logs.filter((_, i) => i !== index) } })
      const missing = await recover(omitted); assert.equal(missing.result, null); assert(['INCOMPLETE_CHAIN_LEDGER', 'INVALID_COMMITMENT_LEDGER', 'UNMATCHED_AVAILABILITY'].includes(missing.reason))
      await replayCoordinator(store); valid(await recover()); this.checks.push('omitted-admission-event-blocks-result-until-full-replay')
      const hash = keccak256(this.inputBytes[0]); store.db.prepare('DELETE FROM ciphertexts WHERE hash=?').run(hash)
      assert.equal((await recover()).status, 'awaiting-ciphertexts'); assert.equal(store.get('state').result, null)
      store.putCiphertext(this.inputBytes[0]); valid(await recover()); this.checks.push('missing-ciphertext-hides-result-and-never-drops-an-accepted-input')
      const changed = structuredClone(bundle), bytes = getBytes(changed.pkProof); bytes[bytes.length - 1] ^= 1; changed.pkProof = hexlify(bytes)
      await importProofBundle(store, changed); const invalid = await recover()
      assert.equal(invalid.reason, 'INVALID_COMMITTEE_PROOF'); assert.equal(invalid.result, null)
      await importProofBundle(store, bundle); valid(await recover()); this.checks.push('changed-real-committee-proof-suppresses-coordinator-result')
      writeFileSync(join(output, 'application-state.json'), JSON.stringify(store.get('state'), null, 2) + '\n')
    } finally { store.close() }
  }
}
