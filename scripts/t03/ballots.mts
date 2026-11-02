// SPDX-License-Identifier: LGPL-3.0-only
// Synthetic T03 harness. No secret, witness or individual plaintext is serialized.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { performance } from 'node:perf_hooks'

const root = process.env.T03_ROOT
assert(root, 'Source scripts/t03/env.sh from bash first')
const upstream = resolve(root, '.local/upstream/interfold')
const crisp = resolve(upstream, 'examples/CRISP')
const require = createRequire(resolve(crisp, 'package.json'))
const { Contract, JsonRpcProvider, TypedDataEncoder, AbiCoder, getBytes, hexlify } = require('ethers')
const sdkModule = await import(pathToFileURL(resolve(crisp, 'packages/crisp-sdk/dist/index.js')).href)
const { ballotTypedData } = await import(pathToFileURL(resolve(crisp, 'client/src/utils/ballotDigest.ts')).href)
// Local proving can block Node long enough to outlive the server's idle connection.
// Use a fresh connection for each local API call while retaining the SDK request path.
const runtimeFetch = globalThis.fetch
globalThis.fetch = (input, init) => {
  const request = new Request(input, init)
  if (new URL(request.url).origin === 'http://127.0.0.1:4000') request.headers.set('Connection', 'close')
  return runtimeFetch(request)
}
const mode = process.argv[2]
const e3Id = BigInt(process.argv[3])
const output = process.argv[4]
assert(['round', 'secure-client'].includes(mode), 'Choose round or secure-client')
assert(output && resolve(output).startsWith(resolve(root, '.local') + '/'), 'Save raw run output in .local only')
const provider = new JsonRpcProvider('http://127.0.0.1:8545', 31337, { staticNetwork: true })
assert.equal(await provider.send('eth_chainId', []), '0x7a69', 'Refuse a nonlocal chain')
const deployment = JSON.parse(readFileSync(resolve(crisp, 'packages/crisp-contracts/deployed_contracts.json'), 'utf8')).localhost
const programAddress = deployment.CRISPProgram.address
const interfoldAddress = deployment.Interfold.address
const artifact = JSON.parse(readFileSync(resolve(crisp, 'packages/crisp-contracts/artifacts/contracts/CRISPProgram.sol/CRISPProgram.json'), 'utf8'))
const program = new Contract(programAddress, artifact.abi, provider)
const interfoldArtifact = JSON.parse(readFileSync(resolve(upstream, 'packages/interfold-contracts/artifacts/contracts/Interfold.sol/Interfold.json'), 'utf8'))
const interfold = new Contract(interfoldAddress, interfoldArtifact.abi, provider)
const sdk = new sdkModule.CrispSDK('http://127.0.0.1:4000', 'http://127.0.0.1:8545')
const signers = await Promise.all([0, 1, 2, 3, 4].map(i => provider.getSigner(i)))
const addresses = await Promise.all(signers.map(s => s.getAddress()))
const leaves = await sdk.getTokenHolderHashes(e3Id)
assert(leaves.length >= 5, 'Need the upstream synthetic census')
const report: any = {
  schemaVersion: 1, task: 'T03', mode, fixtureType: 'disposable synthetic local wallets only',
  sourceRevision: '4ace535c1ff4d7897ec958a943cb45c55dc298a7',
  chainId: 31337, e3Id: e3Id.toString(), measurements: [],
}

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
async function waitFor(label: string, check: () => Promise<any>, seconds = 180) {
  const deadline = performance.now() + seconds * 1000
  while (performance.now() < deadline) {
    const result = await check()
    if (result) return result
    await delay(1000)
  }
  throw new Error('Timed out waiting for ' + label)
}

async function prove(voter: number, vote: number[], isMask: boolean, publicKey: Uint8Array, standalone = false) {
  const start = performance.now()
  const request = {
    e3Id, publicKey, slotAddress: addresses[voter], isMaskVote: isMask,
    numOptions: 2, vote, censusMode: 'merkle', balance: 1n, merkleLeaves: leaves,
  }
  const prepared = standalone ? await sdkModule.prepareBallot(request) : await sdk.prepareBallot(request)
  const preparedAt = performance.now()
  const digest = await program.ballotDigest(e3Id, addresses[voter], prepared.ctCommitment)
  let signature
  if (!isMask) {
    const { domain, types } = ballotTypedData(31337, programAddress)
    const message = { e3Id, slot: addresses[voter], ciphertextCommitment: prepared.ctCommitment }
    assert.equal(TypedDataEncoder.hash(domain, types, message).toLowerCase(), digest.toLowerCase())
    signature = await signers[voter].signTypedData(domain, types, message)
  }
  const proofStart = performance.now()
  const proof = await sdk.finishBallot(prepared, digest, signature)
  const proofEnd = performance.now()
  const verified = await sdkModule.verifyProof(proof)
  assert.equal(verified, true, 'SDK proof verification failed')
  const measured = {
    ordinal: report.measurements.length + 1,
    preparationMs: Math.round(preparedAt - start), proofMs: Math.round(proofEnd - proofStart),
    localVerificationMs: Math.round(performance.now() - proofEnd), proofBytes: proof.proof.length,
  }
  report.measurements.push(measured)
  console.log('Verified synthetic input ' + measured.ordinal)
  return proof
}

try {
  const preset = mode === 'secure-client' ? 'secure-8192' : 'insecure-512'
  const presetModule = await import(pathToFileURL(resolve(crisp, `packages/crisp-sdk/dist/presets/${preset}.js`)).href)
  sdkModule.setCircuits(await presetModule.loadCircuits())
  report.preset = preset

  if (mode === 'secure-client') {
    const started = performance.now()
    const { publicKey } = sdkModule.generateBFVKeys()
    report.singlePartyKeyGenerationMs = Math.round(performance.now() - started)
    // A fresh local key exercises the client component only. It is not the round committee key.
    const proof = await prove(0, [1, 0], false, publicKey, true)
    const changed = { ...proof, proof: Uint8Array.from(proof.proof) }
    changed.proof[changed.proof.length - 1] ^= 1
    let rejected = false
    try { rejected = !(await sdkModule.verifyProof(changed)) } catch { rejected = true }
    assert(rejected, 'Changed proof unexpectedly verified')
    report.changedProofRejected = true
    report.scope = 'offchain secure-parameter client proof with a fresh single-party key; no secure round or compute/decryption proof'
  } else {
    const publicKey = await sdk.getRoundPublicKey(e3Id)
    const round = await interfold.getE3(e3Id)
    assert.equal(Number(round.paramSet), 0)
    const before = await program.getRoundData(e3Id)
    assert.equal(before.numberOfVotes, 0n)
    assert.equal(before.numOptions, 2n)
    // Five contributors, then one replacement and one zero mask: expected final aggregate 2/3.
    const actions = [
      { voter: 0, vote: [1, 0], mask: false }, { voter: 1, vote: [0, 1], mask: false },
      { voter: 2, vote: [1, 0], mask: false }, { voter: 3, vote: [0, 1], mask: false },
      { voter: 4, vote: [1, 0], mask: false }, { voter: 0, vote: [0, 1], mask: false },
      { voter: 1, vote: [0, 0], mask: true },
    ]
    let admitted = 0n
    for (const action of actions) {
      const proof = await prove(action.voter, action.vote, action.mask, publicKey)
      const start = performance.now()
      let job = await sdk.broadcastVote({ e3Id, encodedProof: sdkModule.encodeSolidityProof(proof) })
      job = await waitFor('commitment payload', async () => {
        if (job.status === 'failed_broadcast') throw new Error('Availability staging failed')
        if (job.status === 'ready_for_commitment') return job
        assert(job.job_id, 'Wallet-submission run needs an availability job')
        job = await sdk.getVoteAvailability(job.job_id)
        return false
      })
      assert(job.encoded_proof, 'Missing compact commitment payload')
      const connected = program.connect(signers[action.voter])
      if (admitted === 0n) {
        // Valid control and corrupted proof use the same valid availability attestation/context.
        await connected.publishInput.staticCall(e3Id, job.encoded_proof)
        const types = ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'uint64', 'bytes']
        const fields = Array.from(AbiCoder.defaultAbiCoder().decode(types, job.encoded_proof))
        const changed = getBytes(fields[0]); changed[changed.length - 1] ^= 1
        fields[0] = hexlify(changed)
        const malformed = AbiCoder.defaultAbiCoder().encode(types, fields)
        let rejected = false
        try { await connected.publishInput.staticCall(e3Id, malformed) }
        catch (error: any) { rejected = error.code === 'CALL_EXCEPTION' && typeof error.data === 'string' && error.data !== '0x' }
        assert(rejected, 'Changed proof was not rejected by an onchain revert')
        assert.equal((await program.getRoundData(e3Id)).numberOfVotes, admitted)
        report.changedProofRejectedOnchain = true
      }
      await (await connected.publishInput(e3Id, job.encoded_proof)).wait()
      const jobId = job.job_id
      await waitFor('finalized input availability', async () => {
        const state = await sdk.getVoteAvailability(jobId)
        if (state.status === 'failed_broadcast') throw new Error('Input finalization failed')
        return state.status === 'success'
      })
      admitted++
      await waitFor('input counter', async () => (await program.getRoundData(e3Id)).numberOfVotes === admitted)
      report.measurements.at(-1).admissionAndAvailabilityMs = Math.round(performance.now() - start)
      assert(admitted <= 20n)
    }
    const frozen = await program.getRoundData(e3Id)
    assert.equal(frozen.numberOfVotes, 7n)
    assert.notEqual(frozen.inputRoot, 0n)
    report.admittedInputs = 7
    report.syntheticContributors = 5
    report.censusSlots = leaves.length
    report.inputRoot = frozen.inputRoot.toString()
    const closeStart = performance.now()
    await provider.send('evm_setNextBlockTimestamp', [Number(round.inputWindow[1]) + 1])
    await provider.send('evm_mine', [])
    await waitFor('complete round', async () => {
      const stage = Number(await interfold.getE3Stage(e3Id))
      if (stage === 6) throw new Error('The E3 entered Failed')
      return stage === 5
    }, 600)
    report.closeToCompleteMs = Math.round(performance.now() - closeStart)
    const tally = Array.from(await program.decodeTally(e3Id), (n: any) => n.toString())
    assert.deepEqual(tally, ['2', '3'])
    assert.equal((await program.getRoundData(e3Id)).numberOfVotes, 7n)
    report.tally = tally
    report.stage = 'Complete'
    report.plaintextOutputBytes = getBytes((await interfold.getE3(e3Id)).plaintextOutput).length
    assert.equal(report.plaintextOutputBytes, 400)
    report.scope = 'insecure local mechanics; real client/ballot verification, mock aggregate DKG/decryption verifiers, dev compute receipt, mock availability, one local operator'
  }
  writeFileSync(output, JSON.stringify(report, null, 2) + '\n')
  console.log('T03 ' + mode + ' checks passed')
} finally {
  sdkModule.destroyBBApi()
  provider.destroy()
}
