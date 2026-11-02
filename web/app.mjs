// SPDX-License-Identifier: LGPL-3.0-only
import { BrowserProvider, JsonRpcProvider, Contract, Interface } from 'ethers'
import { address } from '../src/format.mjs'
import { assertInterfaceConfig, decodeSubmission, developmentTotals, secureTotals, submissionPhase, validateCommitmentPayload, publicReceipt, restorePublicReceipt, sameInput } from '../src/interface.mjs'
import { readBoundRound } from '../src/round.mjs'
const $ = id => document.getElementById(id)
let receiptPhase
let config, snapshot, slot, wallet, worker, busy = false, generation = 0, encoded, identity, poll, deadline
const rpc = new JsonRpcProvider(new URL('/api/rpc', location.origin).href, 31337, { staticNetwork: true, batchMaxCount: 1, cacheTimeout: -1 })
const approvedHash = location.hash.slice(1)
const feedback = text => { $('feedback').textContent = text }
async function api(path, body) {
  const response = await fetch('/api/' + path, { method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }), cache: 'no-store', signal: AbortSignal.timeout(20000) })
  if (!response.ok) throw new Error('Service unavailable')
  return response.json()
}
const names = {
  initialized: 'Preparing key', 'awaiting-input-window': 'Waiting for voting to open', 'commitments-closed': 'Commitment closed · Waiting for computation', 'awaiting-confirmations': 'Waiting for chain confirmations', 'awaiting-key': 'Preparing key',
  'voting-open': 'Voting open', 'availability-tail': 'Commitment closed · Waiting for availability',
  'awaiting-availability': 'Waiting for availability', computing: 'Computing', decrypting: 'Decrypting',
  'development-complete': 'Development checks complete · Mock verification', 'awaiting-proof-bundle': 'Waiting for public proof evidence',
  verified: 'Secure proof checks passed · Local synthetic result',
  'awaiting-ciphertexts': 'Waiting for public ciphertexts', 'catching-up': 'Replaying chain evidence',
  'pending-rpc': 'Chain unavailable · Results hidden', 'blocked-check': 'Evidence check failed · Results hidden',
  'replay-required': 'Chain changed · Operator replay required', 'checking-result': 'Checking result evidence'
}
function controls() {
  const open = snapshot?.state.status === 'voting-open' && !snapshot?.state.reason && snapshot?.cached === false
  const pending = identity && !snapshot?.ledger.some(x => sameInput(x, identity))
  const eligible = config && slot && config.round.census.eligible.some(x => x.address === slot && x.weight === '1')
  $('choices').disabled = busy || !open || !eligible || pending
  $('submit').disabled = busy || !open || !eligible || pending
  $('cancel').disabled = !busy || Boolean(encoded)
  $('connect').disabled = busy || !config
  $('import-receipt').disabled = busy || !open || !eligible
  $('continue').hidden = !encoded || !identity || !open || snapshot?.ledger.some(x => sameInput(x, identity))
  $('continue').disabled = busy || !eligible
}
function reset(message) {
  generation++; worker?.terminate(); worker = undefined; busy = false; encoded = undefined
  $('ballot').reset(); feedback(message); controls()
}
async function checkWallet() {
  if (!window.ethereum) throw new Error('Wallet missing')
  if (BigInt(await window.ethereum.request({ method: 'eth_chainId' })) !== 31337n) throw new Error('Wrong network')
  const accounts = await window.ethereum.request({ method: 'eth_accounts' })
  if (!accounts[0] || address(accounts[0]) !== slot) throw new Error('Account changed')
}
async function connect() {
  if (!window.ethereum) { feedback('Open this page in a wallet browser or install an EIP-1193 wallet. Use local chain 31337.'); return }
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' })
    if (BigInt(await window.ethereum.request({ method: 'eth_chainId' })) !== 31337n) {
      slot = undefined; feedback('Wrong network. Select local chain 31337 in your wallet, then reconnect.'); return
    }
    slot = address(accounts[0]); wallet = new BrowserProvider(window.ethereum, 'any')
    $('account').textContent = slot
    const eligible = config.round.census.eligible.some(x => x.address === slot && x.weight === '1')
    $('eligibility').textContent = eligible ? 'Eligible · 1 synthetic vote' : 'This address is not eligible in the approved census.'
    feedback(eligible ? 'Ready. Your choice stays in this browser.' : 'Choose a disposable wallet from the approved synthetic census.')
    const receipt = sessionStorage.getItem('receipt:' + approvedHash + ':' + slot)
    identity = undefined; encoded = undefined; receiptPhase = undefined
    if (receipt) {
      try {
        const restored = restorePublicReceipt(JSON.parse(receipt), config.round.manifest, slot)
        identity = restored.identity; encoded = restored.encodedProof
      } catch { sessionStorage.removeItem('receipt:' + approvedHash + ':' + slot) }
    }
  } catch { feedback('Wallet connection was rejected or unavailable. Reconnect when ready.') }
  finally { controls() }
}
async function refresh() {
  $('results').replaceChildren()
  try {
    snapshot = await api('status')
    if (snapshot.state.manifestHash !== config.round.approvedManifestHash || snapshot.state.policyHash !== config.round.approvedPolicyHash)
      throw new Error('Context changed')
    const status = snapshot.state.status
    $('phase').textContent = names[status] ?? (status.startsWith('failed-') ? 'Round failed · No verified result' : 'Waiting for verified chain state')
    $('counts').textContent = snapshot.state.counts ? `${snapshot.state.counts.committed} commitments · ${snapshot.state.counts.available} availability confirmations` : ''
    $('results').replaceChildren()
    const secure = secureTotals(config, snapshot)
    const totals = secure ?? developmentTotals(config, snapshot)
    if (totals) {
      const warning = document.createElement('p'); warning.className = 'warning'
      warning.textContent = secure ? 'Local synthetic result checked with real secure proofs. One operator controls the committee; eligibility, randomness and availability use local fixtures.' :
        'Development totals only. Mock committee, DA, compute and decryption verification. No secure attestation.'
      const list = document.createElement('ul')
      totals.forEach((value, i) => { const item = document.createElement('li'); item.textContent = `${config.round.manifest.choices[i]}: ${value}`; list.append(item) })
      $('results').append(warning, list)
    }
    if (identity && !busy) { const phase = submissionPhase(identity, snapshot); if (phase !== receiptPhase) feedback(phase === 'Submission pending' && encoded ? 'Submission pending. Use Finish pending submission before the cutoff if delivery or a wallet commitment is still needed.' : phase); receiptPhase = phase; $('receipt').textContent = 'Public ciphertext hash: ' + identity.ciphertextHash }
    if (busy && status !== 'voting-open') reset('Commitment window closed or chain evidence changed. Preparation cancelled; check your public receipt.')
  } catch {
    snapshot = undefined; $('results').replaceChildren(); $('counts').textContent = ''
    $('phase').textContent = 'Status unavailable · Results hidden'
    if (busy) reset('Chain status unavailable. Preparation cancelled. Recheck before retrying.')
  } finally { controls() }
}
async function broadcast(token) {
  await checkWallet()
  // Re-check the actual exclusive commitment deadline after the long proof operation.
  const { program } = await readBoundRound(rpc, config.round.manifest, 3)
  const block = await rpc.getBlock('latest')
  deadline = await program.inputCommitmentDeadline(config.round.manifest.e3Id)
  if (BigInt(block.timestamp) >= deadline || generation !== token) throw new Error('Closed')
  feedback('Submission pending · Waiting for chain confirmation')
  identity = decodeSubmission(encoded, config.round.manifest).identity; receiptPhase = undefined
  sessionStorage.setItem('receipt:' + approvedHash + ':' + slot, JSON.stringify(publicReceipt(encoded, config.round.manifest, slot)))
  const delivered = await api('submit', { encodedProof: encoded })
  if (generation !== token) return
  if (delivered.response.status === 'failed_broadcast') throw new Error('Delivery failed')
  if (delivered.response.status === 'ready_for_commitment') {
    const compact = validateCommitmentPayload(encoded, delivered.response.encoded_proof, config.round.manifest, block.timestamp)
    const inputState = new Contract(config.round.manifest.programAddress,
      ['function isInputCommitted(uint256,bytes32,bytes32,address,uint40) view returns (bool)'], rpc)
    if (await inputState.isInputCommitted(config.round.manifest.e3Id, identity.ciphertextHash, identity.commitment, identity.slot, identity.parentIndexPlusOne)) return
    const iface = new Interface(['function publishInput(uint256,bytes)'])
    const transaction = { to: config.round.manifest.programAddress, value: 0n,
      data: iface.encodeFunctionData('publishInput', [config.round.manifest.e3Id, compact]), from: slot }
    // The actual pinned program checks the availability signature, expiry and ballot proof.
    await rpc.call(transaction)
    await checkWallet()
    if (generation !== token) return
    feedback('Confirm the zero-value ballot commitment transaction. Only local test gas is required.')
    const sent = await (await wallet.getSigner(slot)).sendTransaction(transaction)
    if (generation !== token) return
    feedback('Submission pending · Transaction sent; waiting for confirmed commitment and availability')
  } else if (delivered.response.status === 'pending_commitment') {
    feedback('Proof queued. Before the cutoff, choose Finish pending submission to check whether your wallet must send the commitment.')
  }
  // A transport response cannot change inclusion state. Only confirmed events do that.
}
$('connect').addEventListener('click', connect)
$('import-receipt').addEventListener('change', async event => {
  if (busy || !config || !slot) return
  try {
    const file = event.target.files?.[0]
    if (!file || file.size > 2 ** 22) throw new Error('Invalid public receipt')
    const restored = restorePublicReceipt(JSON.parse(await file.text()), config.round.manifest, slot)
    identity = restored.identity; encoded = restored.encodedProof; receiptPhase = undefined
    sessionStorage.setItem('receipt:' + approvedHash + ':' + slot, JSON.stringify(restored))
    $('receipt-file-status').textContent = 'Receipt loaded: ' + file.name + '. Choose Finish pending submission.'
    feedback('Saved encrypted ballot loaded. Choose Finish pending submission to deliver its existing proof.')
  } catch {
    event.target.value = ''; $('receipt-file-status').textContent = 'Receipt could not be loaded for this account and round.'
    feedback('Receipt does not match this account and round. No submission was sent.')
  } finally { controls() }
})
$('cancel').addEventListener('click', () => reset('Preparation cancelled. No new submission was sent.'))
$('continue').addEventListener('click', async () => {
  if (busy || !encoded) return
  const token = ++generation; busy = true; controls()
  try { await broadcast(token) }
  catch { feedback('Delivery remains uncertain or the wallet declined. Check the confirmed receipt before replacing.') }
  finally { busy = false; controls() }
})
$('ballot').addEventListener('submit', async event => {
  event.preventDefault()
  if (busy || $('submit').disabled) return
  const choice = new FormData($('ballot')).get('choice')
  if (choice === null) { feedback('Choose one option or withdraw your unit.'); return }
  const token = ++generation; encoded = undefined; busy = true; controls(); feedback('Checking wallet and confirmed parent…')
  try {
    await checkWallet()
    const parent = await api('parent?slot=' + encodeURIComponent(slot))
    if (generation !== token) return
    feedback('Preparing key and encrypting in your browser…')
    const vote = config.round.manifest.choices.map((_, i) => Number(choice) === i ? 1 : 0)
    worker = new Worker(new URL('./prover.worker.mjs', import.meta.url), { type: 'module' })
    worker.onerror = () => { if (generation === token) reset('Browser proving failed. No secret diagnostic data was sent. Try again on a supported desktop browser.') }
    worker.onmessage = async ({ data }) => {
      if (generation !== token) return
      try {
        if (data.type === 'prepared') feedback('Ballot encrypted · Preparing voting authorization')
        else if (data.type === 'sign') {
          await checkWallet()
          feedback('Approve the CRISP Ballot voting signature in your wallet. No token approval is needed.')
          const signer = await wallet.getSigner(slot)
          const signature = await signer.signTypedData(data.domain, data.types, data.value)
          await checkWallet()
          if (generation !== token) return
          worker.postMessage({ type: 'signature', signature })
          feedback('Proving in your browser… This may take several minutes. Keep this tab open.')
        } else if (data.type === 'proof') {
          encoded = data.encodedProof; controls(); worker.terminate(); worker = undefined
          await broadcast(token)
          busy = false; $('ballot').reset(); controls(); await refresh()
        } else if (data.type === 'failed') { document.documentElement.dataset.failure = data.category + ' ' + data.kind + ' ' + JSON.stringify(data.sites); reset('Browser ' + (['context', 'public parameters', 'encryption and witness', 'proof generation and verification'].includes(data.phase) ? data.phase : 'preparation') + ' failed. No ballot was submitted. Recheck the round and try again.') }
      } catch {
        worker?.terminate(); worker = undefined; busy = false; controls()
        feedback(identity && encoded ? 'Submission uncertain. Check commitment and availability confirmation before replacing. An HTTP response is not inclusion.' :
          'Voting signature rejected, account changed, or cutoff reached. No new submission was sent. Reconnect and try again.')
        $('ballot').reset()
      }
    }
    worker.postMessage({ type: 'prove', config, approvedHash, slot, vote, parent: parent.entry })
    // Do not leave the selected plaintext in the page while proving.
    $('ballot').reset()
  } catch { reset('Unable to prepare. Check your wallet network, the current parent and the commitment cutoff, then try again.') }
})
if (window.ethereum?.on) {
  for (const event of ['accountsChanged', 'chainChanged', 'disconnect']) window.ethereum.on(event, () => {
    reset('Wallet account or network changed. Reconnect to continue.'); slot = undefined; identity = undefined
    $('account').textContent = 'Wallet not connected'; $('eligibility').textContent = ''; controls()
  })
}
try {
  config = assertInterfaceConfig(await api('config'), approvedHash)
  const secureMode = config.round.manifest.preset === 'secure-8192'
  $('replay-note').hidden = !secureMode
  $('replay-note').textContent = 'Saved-ballot replay · Existing encrypted ballots and proofs. This is not a new live poll.'
  $('privacy-limit').textContent = secureMode ? 'This local round uses secure encryption and real client, computation and decryption proofs. One operator controls all committee nodes. Eligibility, randomness and availability remain local fixtures. Public totals can still reveal choices in small groups. It does not establish private UNI voting.' :
    'This local demonstration uses weak test parameters and mock committee, availability, computation and decryption verification. It does not establish private UNI voting.'
  $('evidence-limit').textContent = secureMode ? 'The local coordinator checks the public proofs and full admitted input set. Open the evidence to verify it independently. This saved-input replay is separate from the original VM execution.' :
    'Results are refreshed from the local coordinator. No secure result label is enabled for development rounds.'
  $('title').textContent = config.proposal.title; $('proposal').textContent = config.proposal.text
  $('source').href = config.proposal.url; $('config-hash').textContent = approvedHash
  const r = config.round, manifest = r.manifest
  for (const [name, value] of [['Network', 'Local synthetic · 31337'], ['Snapshot', r.census.context.snapshotBlock + ' · ' + r.census.context.snapshotBlockHash],
    ['Eligibility', r.census.eligible.length + ' approved synthetic addresses · 1 credit each'], ['Input end', new Date(Number(manifest.inputEnd) * 1000).toISOString()],
    ['Census hash', r.approvedCensusHash], ['Round hash', r.approvedManifestHash]]) {
    const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = name; dd.textContent = value; $('context').append(dt, dd)
  }
  const { program } = await readBoundRound(rpc, manifest)
  deadline = await program.inputCommitmentDeadline(manifest.e3Id)
  const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = 'Commitment cutoff'; dd.textContent = new Date(Number(deadline) * 1000).toISOString() + ' (exclusive)'; $('context').append(dt, dd)
  for (const [index, text] of [...manifest.choices, 'Withdraw my synthetic unit (zero contribution)'].entries()) {
    const label = document.createElement('label'), input = document.createElement('input')
    input.type = 'radio'; input.name = 'choice'; input.value = String(index); label.append(input, document.createTextNode(text)); $('choices').append(label)
  }
  $('evidence').href = '/api/evidence#' + approvedHash
  await refresh(); poll = setInterval(refresh, 5000); controls()
} catch {
  config = undefined; $('title').textContent = 'Approved configuration unavailable'
  feedback('Use the operator’s complete local link, including its configuration fingerprint. No signing is enabled.')
  $('evidence').hidden = true
}
window.addEventListener('pagehide', () => { generation++; worker?.terminate(); clearInterval(poll); rpc.destroy(); wallet?.destroy() })

window.addEventListener('hashchange', () => { reset('Round context changed. Reloading approved configuration.'); location.reload() })
