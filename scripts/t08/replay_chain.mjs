// SPDX-License-Identifier: LGPL-3.0-only
// Replay public signed local transactions, reusing completed proofs. Never run a prover.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { resolve, join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import net from 'node:net'
import { AbiCoder, Contract, Interface, JsonRpcProvider, Transaction, getBytes, hexlify, toBeHex, keccak256, sha256, ZeroHash } from 'ethers'
import { ROOT, UPSTREAM, CRISP } from '../../src/upstream.mjs'
import { ApplicationReplay } from './application_replay.mjs'

assert(process.argv[2],'Supply the checked public-chain export folder')
const saved=resolve(process.argv[2]), output=resolve(process.argv[3] ?? join(ROOT,'.local/runs/t08-replay-'+Date.now()))
mkdirSync(output,{recursive:false,mode:0o700})
const json=path=>JSON.parse(readFileSync(path,'utf8')), snapshot=json(join(saved,'chain.json'))
const exported=json(join(saved,'export-manifest.json'))
assert.deepEqual(Object.keys(exported.files).sort(),['admissions.json','chain.json','deployed_contracts.json','deployment-check.json','package-manifest.json','public-source.json','result.json'].sort())
for(const [name,item] of Object.entries(exported.files)){
  const bytes=readFileSync(join(saved,name));assert.equal(bytes.length,item.bytes);assert.equal(sha256(bytes).slice(2),item.sha256,'Export checksum differs: '+name)
}
const records=json(join(saved,'deployed_contracts.json')).localhost,result=json(join(saved,'result.json'))
const artifact=path=>json(join(UPSTREAM,'packages/interfold-contracts/artifacts',path))
const programArtifact=json(join(CRISP,'packages/crisp-contracts/artifacts/contracts/CRISPProgram.sol/CRISPProgram.json'))
const protocolInterface=new Interface(artifact('contracts/Interfold.sol/Interfold.json').abi),programInterface=new Interface(programArtifact.abi)
const registryInterface=new Interface(artifact('contracts/registry/CiphernodeRegistryOwnable.sol/CiphernodeRegistryOwnable.json').abi)
const abi=AbiCoder.defaultAbiCoder(),e3Id=BigInt(result.e3Id),checks=[],replayed=[]
const blocks=snapshot.blocks.filter(b=>b.transactions.length).sort((a,b)=>Number(BigInt(a.header.number)-BigInt(b.header.number)))
function signed(entry){
  assert.equal(entry.impersonated_sender,null,'Impersonated transaction in original chain')
  assert.deepEqual(Object.keys(entry.transaction),['EIP1559'])
  const t=entry.transaction.EIP1559
  const tx=Transaction.from({type:2,chainId:BigInt(t.chainId),nonce:Number(t.nonce),gasLimit:BigInt(t.gas),
    maxFeePerGas:BigInt(t.maxFeePerGas),maxPriorityFeePerGas:BigInt(t.maxPriorityFeePerGas),to:t.to,
    value:BigInt(t.value),accessList:t.accessList,data:t.input,signature:{r:t.r,s:t.s,yParity:Number(t.yParity)}})
  assert.equal(tx.hash,t.hash);return tx
}
const signedBlocks=blocks.map(block=>({...block,parsed:block.transactions.map(signed)}))
const receiptByHash=new Map(snapshot.transactions.map(t=>[t.info.transaction_hash,t]))
function parse(tx){for(const iface of [protocolInterface,programInterface,registryInterface])try{const p=iface.parseTransaction(tx);if(p)return p}catch{};return null}
const all=signedBlocks.flatMap(b=>b.parsed.map(tx=>({tx,parsed:parse(tx)})))
const find=name=>{const found=all.filter(t=>t.parsed?.name===name);assert.equal(found.length,1,name);return found[0]}
const compute=find('publishCiphertextOutput'),plaintext=find('publishPlaintextOutput')
const seedDifferences=[],compressedGaps=[]
const applicationArgs=process.argv.slice(4)
assert(applicationArgs.length===0 || (applicationArgs.length===3 && applicationArgs[0]==='--application'),
  'Optional arguments: --application RECOVERY_FOLDER CHECKED_PUBLIC_INPUT_BIN')
function comparableLogs(logs){
  return logs.map(({address,topics,data})=>{
    // Anvil 1.3.1 cannot set PREVRANDAO. CRISP's validate ignores this E3
    // computation seed, and committee selection uses its separate fixture VRF.
    // Normalize only that field, preserving every other byte of every event.
    const event=(()=>{try{return protocolInterface.parseLog({topics,data})}catch{return null}})()
    if(address===records.Interfold.address.toLowerCase() && event?.name==='E3Requested'){
      const args=Array.from(event.args);args[1]=Array.from(args[1]).with(0,0n)
      return {address,...protocolInterface.encodeEventLog(event.fragment,args)}
    }
    return {address,topics,data}
  })
}
let child,provider,fd,program,protocol,committee,application,firstBallot=false,pending=false,computeTest=false,decryptionTest=false,finalizationTest=false
const gas={gasLimit:50000000}
async function rejects(label,operation,expectedError){
  let ok=false
  try{ok=(await operation())===false && !expectedError}catch(e){
    assert.equal(e.code,'CALL_EXCEPTION',label);assert(!/out of gas/i.test(e.message))
    if(expectedError){
      if(e.revert?.name)assert.equal(e.revert.name,expectedError,label+': wrong rejection reason')
      else assert.equal(e.data?.slice(0,10),(protocolInterface.getError(expectedError) ?? programInterface.getError(expectedError)).selector,label+': wrong rejection selector')
    }
    ok=true
  }
  assert(ok,label+' unexpectedly accepted');checks.push(label)
}
async function branch(operation){const id=await provider.send('evm_snapshot',[]);try{await operation()}finally{assert.equal(await provider.send('evm_revert',[id]),true)}}
async function at(timestamp){await provider.send('evm_setNextBlockTimestamp',[Number(timestamp)]);await provider.send('evm_mine',[])}
const inputTypes=['bytes','address','bytes32','bytes32','uint40','uint64','bytes']
async function before(tx,p){
  if(p?.name==='publishCommittee'){
    const deadline=(await protocol.getDeadlines(e3Id)).dkgDeadline
    await branch(async()=>{
      for(const timestamp of [deadline-1n,deadline]){
        await at(timestamp);await committee.publishCommittee.staticCall(...Array.from(p.args),{...gas,from:tx.from})
        checks.push('actual-DKG-publication-valid-'+(timestamp===deadline?'at-inclusive-deadline':'one-second-before-deadline'))
      }
      await at(deadline+1n)
      await rejects('actual-DKG-publication-after-deadline-rejected',()=>committee.publishCommittee.staticCall(...Array.from(p.args),{...gas,from:tx.from}),'DKGDeadlinePassed')
    })
  }
  if(p?.name==='finalizeInput' && !finalizationTest){
    finalizationTest=true
    const deadline=(await protocol.getDeadlines(e3Id)).computeDeadline
    await branch(async()=>{
      for(const timestamp of [deadline-1n,deadline]){
        await at(timestamp);await program.finalizeInput.staticCall(...Array.from(p.args),{...gas,from:tx.from})
        checks.push('actual-availability-finalization-valid-'+(timestamp===deadline?'at-inclusive-deadline':'one-second-before-deadline'))
      }
      await at(deadline+1n)
      await rejects('actual-availability-finalization-after-deadline-rejected',()=>program.finalizeInput.staticCall(...Array.from(p.args),{...gas,from:tx.from}),'InputDeadlinePassed')
    })
  }
  if(p?.name==='publishInput' && !firstBallot){
    firstBallot=true
    if(application)await application.freeze(e3Id)
    const fields=Array.from(abi.decode(inputTypes,p.args.data)), proofArgs=[e3Id,...fields.slice(0,5)]
    assert.equal(await program.validateInputProof(...proofArgs,gas),true)
    checks.push('actual-program-valid-secure-client-proof-before-admission')
    const start=(await protocol.getE3(e3Id)).inputWindow[0]
    const startCall={to:program.target,data:programInterface.encodeFunctionData('validateInputProof',proofArgs),gas:'0x2faf080'}
    let startRejected=false
    try{await provider.send('eth_call',[startCall,'latest',{}, {time:toBeHex(start-1n)}])}
    catch(error){assert.equal((error.error?.data ?? error.data)?.slice(0,10),programInterface.getError('E3NotAcceptingInputs').selector);startRejected=true}
    assert(startRejected);checks.push('actual-program-voting-start-one-second-before-rejected-with-block-time-override')
    for(const timestamp of [start,start+1n]){
      assert.equal(abi.decode(['bool'],await provider.send('eth_call',[startCall,'latest',{}, {time:toBeHex(timestamp)}]))[0],true)
      checks.push('actual-program-voting-start-'+(timestamp===start?'at-inclusive-boundary':'one-second-after')+'-valid-with-block-time-override')
    }
    const changed=getBytes(fields[0]);changed[changed.length-1]^=1
    for(const [label,index,value] of [['proof',0,hexlify(changed)],['slot',1,records.Interfold.address],['commitment',2,ZeroHash],['hash',3,ZeroHash]]){
      const data=abi.encode(inputTypes,fields.with(index,value))
      await rejects('actual-admission-changed-'+label+'-rejected',()=>program.publishInput.staticCall(e3Id,data,{...gas,from:tx.from}))
    }
    await rejects('actual-admission-wrong-round-rejected',()=>program.publishInput.staticCall(e3Id+1n,p.args.data,{...gas,from:tx.from}))
    const deadline=await program.inputCommitmentDeadline(e3Id)
    await branch(async()=>{
      await at(deadline-1n);assert.equal(await program.validateInputProof(...proofArgs,gas),true)
      checks.push('actual-admission-one-second-before-cutoff-valid')
      await at(deadline);await rejects('actual-admission-at-exclusive-cutoff-rejected',()=>program.validateInputProof(...proofArgs,gas))
      await at(deadline+1n);await rejects('actual-admission-after-cutoff-rejected',()=>program.validateInputProof(...proofArgs,gas))
    })
  }
  if(p?.name==='publishCiphertextOutput' && !computeTest){
    computeTest=true
    assert.equal(await protocol.getE3Stage(e3Id),3n)
    await protocol.publishCiphertextOutput.staticCall(...Array.from(p.args),{...gas,from:tx.from})
    checks.push('actual-lifecycle-valid-computation-publication-preflight')
    const types=['tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes proof,bytes availabilityProof)']
    const reference=Array.from(abi.decode(types,p.args.encodedOutputReference)[0])
    const broken=Array.from(reference);broken[0]=ZeroHash
    await rejects('actual-lifecycle-changed-output-reference-rejected',()=>protocol.publishCiphertextOutput.staticCall(e3Id,abi.encode(types,[broken]),{...gas,from:tx.from}))
    await branch(async()=>{
      const deadlines=await protocol.getDeadlines(e3Id)
      for(const timestamp of [deadlines.computeDeadline-1n,deadlines.computeDeadline]){
        await at(timestamp);await protocol.publishCiphertextOutput.staticCall(...Array.from(p.args),{...gas,from:tx.from})
        checks.push('actual-compute-publication-valid-'+(timestamp===deadlines.computeDeadline?'at-inclusive-deadline':'one-second-before-deadline'))
      }
      await at(deadlines.computeDeadline+1n)
      await rejects('actual-compute-publication-after-deadline-rejected',()=>protocol.publishCiphertextOutput.staticCall(...Array.from(p.args),{...gas,from:tx.from}),'CommitteeDutiesCompleted')
      const signer=await provider.getSigner(0)
      const hash=await provider.send('eth_sendTransaction',[{from:await signer.getAddress(),to:protocol.target,
        data:protocolInterface.encodeFunctionData('markE3Failed',[e3Id]),gas:'0x989680'}])
      await provider.send('evm_mine',[])
      assert.equal((await provider.send('eth_getTransactionReceipt',[hash])).status,'0x1')
      assert.equal(await protocol.getE3Stage(e3Id),6n)
      await rejects('actual-failed-round-rejects-original-valid-computation',()=>protocol.publishCiphertextOutput.staticCall(...Array.from(p.args),{...gas,from:tx.from}))
      await rejects('actual-failed-round-rejects-original-valid-decryption',()=>protocol.publishPlaintextOutput.staticCall(...Array.from(plaintext.parsed.args),{...gas,from:plaintext.tx.from}))
      checks.push('actual-compute-timeout-marks-failed-and-cannot-complete')
    })
  }
  if(p?.name==='publishPlaintextOutput' && !decryptionTest){
    decryptionTest=true
    assert.equal(await protocol.getE3Stage(e3Id),4n)
    assert.equal(await protocol.publishPlaintextOutput.staticCall(...Array.from(p.args),{...gas,from:tx.from}),true)
    await branch(async()=>{
      const deadline=(await protocol.getDeadlines(e3Id)).decryptionDeadline
      for(const timestamp of [deadline-1n,deadline]){
        await at(timestamp);assert.equal(await protocol.publishPlaintextOutput.staticCall(...Array.from(p.args),{...gas,from:tx.from}),true)
        checks.push('actual-decryption-publication-valid-'+(timestamp===deadline?'at-inclusive-deadline':'one-second-before-deadline'))
      }
      await at(deadline+1n)
      await rejects('actual-decryption-publication-after-deadline-rejected',()=>protocol.publishPlaintextOutput.staticCall(...Array.from(p.args),{...gas,from:tx.from}),'CommitteeDutiesCompleted')
    })
    const changed=getBytes(p.args.proof);changed[changed.length-1]^=1
    await rejects('actual-lifecycle-changed-decryption-proof-rejected',()=>protocol.publishPlaintextOutput.staticCall(e3Id,p.args.plaintextOutput,hexlify(changed),{...gas,from:tx.from}))
    assert.equal(await protocol.getE3Stage(e3Id),4n)
    checks.push('invalid-decryption-does-not-transition-to-complete')
  }
}
async function after(tx,p){
  if(p?.name==='publishInput'){
    const round=await program.getRoundData(e3Id)
    if(round.numberOfVotes===1n)
      await rejects('actual-admission-duplicate-input-rejected',()=>program.publishInput.staticCall(...Array.from(p.args),{...gas,from:tx.from}))
    // Use the final proof only once all six leaves match its root. Otherwise
    // a wrong transcript could hide a missing availability guard.
    if(round.numberOfVotes===6n && !pending){
      pending=true
      assert.equal(await program.pendingInputCount(e3Id),1n)
      const reference=abi.decode(['tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes proof,bytes availabilityProof)'],compute.parsed.args.encodedOutputReference)[0]
      const [, ,inputRoot]=abi.decode(['bytes','bytes32','bytes32'],reference.proof)
      assert.equal(round.inputRoot,BigInt(inputRoot),'Availability control must use the exact proven transcript')
      await rejects('actual-program-pending-availability-blocks-computation',()=>program.verify(e3Id,reference.contentHash,reference.ciphertextCommitment,reference.proof,gas),'InputAvailabilityPending')
    }
  }
  if(p?.name==='finalizeInput'){
    await rejects('actual-finalization-duplicate-receipt-'+checks.filter(x=>x.startsWith('actual-finalization-duplicate')).length+'-rejected',
      ()=>program.finalizeInput.staticCall(...Array.from(p.args),{...gas,from:tx.from}))
    if(pending && await program.pendingInputCount(e3Id)===0n){
      const reference=abi.decode(['tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes proof,bytes availabilityProof)'],compute.parsed.args.encodedOutputReference)[0]
      assert.equal(await program.verify(e3Id,reference.contentHash,reference.ciphertextCommitment,reference.proof,gas),true,'The same proof must pass after final availability')
    }
  }
}
try{
  await new Promise((resolve,reject)=>{const socket=net.createServer();socket.once('error',reject);socket.listen(18590,'127.0.0.1',()=>socket.close(resolve))})
  const genesis=snapshot.blocks.find(b=>BigInt(b.header.number)===0n)
  fd=openSync(join(output,'anvil.log'),'w')
  child=spawn('anvil',['--host','127.0.0.1','--port','18590','--chain-id','31337','--silent',
    '--timestamp',String(Number(genesis.header.timestamp))],{stdio:['ignore',fd,fd]})
  provider=new JsonRpcProvider('http://127.0.0.1:18590',31337,{staticNetwork:true,cacheTimeout:-1,batchMaxCount:1,pollingInterval:50})
  if(applicationArgs.length)application=new ApplicationReplay({provider,records,output,all,recovery:resolve(applicationArgs[1]),inputFile:resolve(applicationArgs[2])})
  let ready=false
  for(let i=0;i<100;i++){try{ready=(await provider.send('eth_chainId',[]))==='0x7a69'}catch{};if(ready)break;assert(child.exitCode===null);await delay(100)}
  assert(ready)
  await provider.send('evm_setAutomine',[false])
  // Fund only public transaction senders on the disposable replay chain. No app storage/code overrides.
  for(const sender of new Set(all.map(x=>x.tx.from)))await provider.send('anvil_setBalance',[sender,toBeHex(10n**24n)])
  program=new Contract(records.CRISPProgram.address,programInterface,provider)
  protocol=new Contract(records.Interfold.address,protocolInterface,provider)
  committee=new Contract(records.CiphernodeRegistryOwnable.address,registryInterface,provider)
  let height=0
  for(const block of signedBlocks){
    const target=Number(block.header.number),gap=target-height-1
    if(gap>10000)compressedGaps.push({beforeOriginalBlock:target,emptyBlocksOmitted:gap})
    else if(gap)await provider.send('anvil_mine',[toBeHex(gap),'0x0'])
    for(const tx of block.parsed){
      const parsed=parse(tx)
      if(parsed?.name==='publishCiphertextOutput'){
        await branch(async()=>{
          const end=(await protocol.getE3(e3Id)).inputWindow[1]
          await at(end-1n)
          await rejects('actual-computation-before-input-end-rejected',()=>protocol.publishCiphertextOutput.staticCall(...Array.from(parsed.args),{...gas,from:tx.from}),'InputDeadlineNotReached')
          for(const timestamp of [end,end+1n]){
            await at(timestamp);await protocol.publishCiphertextOutput.staticCall(...Array.from(parsed.args),{...gas,from:tx.from})
            checks.push('actual-computation-'+(timestamp===end?'at-input-end':'one-second-after-input-end')+'-valid')
          }
        })
        await branch(async()=>{await at(Number(block.header.timestamp));await before(tx,parsed)})
      }
      else await before(tx,parsed)
    }
    await provider.send('anvil_setNextBlockBaseFeePerGas',[block.header.baseFeePerGas])
    await provider.send('evm_setNextBlockTimestamp',[Number(block.header.timestamp)])
    for(const tx of block.parsed)assert.equal(await provider.send('eth_sendRawTransaction',[tx.serialized]),tx.hash)
    await provider.send('evm_mine',[]);height=target
    for(const tx of block.parsed){
      const receipt=await provider.send('eth_getTransactionReceipt',[tx.hash]),original=receiptByHash.get(tx.hash)
      assert(receipt,'Transaction was not mined: '+tx.hash);assert(original,'Missing original receipt')
      assert.equal(receipt.status,original.receipt.status,'Replay status differs: '+parse(tx)?.name)
      assert.deepEqual(comparableLogs(receipt.logs),comparableLogs(original.receipt.logs),'Replay emitted different public logs: '+parse(tx)?.name)
      if(parse(tx)?.name==='request'){
        const current=await protocol.getE3(e3Id),header=await provider.getBlock('latest')
        assert.equal(toBeHex(current.seed,32),keccak256(abi.encode(['bytes32','uint256'],[header.prevRandao,e3Id])))
        seedDifferences.push({scope:'E3 computation seed only; ignored by CRISP validation and not the registry committee seed',replay:current.seed.toString()})
      }
      replayed.push({hash:tx.hash,block:target,method:parse(tx)?.name ?? (tx.to?'other':'deployment'),gasUsed:BigInt(receipt.gasUsed).toString(),status:receipt.status})
      if(receipt.status==='0x1')await after(tx,parse(tx))
    }
    if(replayed.length%20===0)console.log('Replayed '+replayed.length+' public transactions')
  }
  assert(firstBallot && pending && computeTest && decryptionTest)
  assert.equal(await protocol.getE3Stage(e3Id),5n)
  assert.deepEqual(Array.from(await program.decodeTally(e3Id),String),['1','2','2'])
  assert.equal(await program.pendingInputCount(e3Id),0n)
  checks.push('original-signed-transactions-replay-through-real-secure-verifiers-to-exact-tally')
  if(application)await application.finish()
  writeFileSync(join(output,'verification.json'),JSON.stringify({scope:'signed local transaction replay and disposable lifecycle failure branches; no new proving',
    e3Id:result.e3Id,chainId:31337,checks,replayed,seedDifferences,compressedGaps,
    replayLimits:'Original signed transaction bytes, deployment addresses, admission proofs and result are retained. Native balances are prefunded. Empty-block timestamps, block hashes, PREVRANDAO and the unused E3 computation seed differ; this is not chain-root reproduction.',completeT08:false},null,2)+'\n')
  console.log(JSON.stringify({output,checks,replayedTransactions:replayed.length},null,2))
}catch(error){
  const failure={code:error.code ?? error.name,message:String(error.shortMessage ?? error.message).slice(0,500),checksCompleted:checks.length,replayedTransactions:replayed.length}
  writeFileSync(join(output,'failure.json'),JSON.stringify(failure,null,2)+'\n')
  console.error(JSON.stringify({output,failure},null,2));process.exitCode=1
}finally{
  provider?.destroy()
  if(child?.exitCode===null){child.kill('SIGTERM');await Promise.race([new Promise(r=>child.once('exit',r)),delay(5000,undefined,{ref:false})]);if(child.exitCode===null)child.kill('SIGKILL')}
  if(fd!==undefined)closeSync(fd)
}
