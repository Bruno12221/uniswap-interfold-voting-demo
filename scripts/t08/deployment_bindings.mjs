// SPDX-License-Identifier: LGPL-3.0-only
// Check constructor arguments and every CRISP immutable, including private verifier pointers.
import assert from 'node:assert/strict'
import { AbiCoder, Interface, TypedDataEncoder, keccak256, toBeHex, toUtf8Bytes } from 'ethers'

const abi = AbiCoder.defaultAbiCoder()
const word = value => toBeHex(BigInt(value), 32)
const shortString = value => '0x' + Buffer.from(value).toString('hex').padEnd(62, '0') + Buffer.byteLength(value).toString(16).padStart(2, '0')

export function namedImmutables(code, artifact, compilerOutput) {
  const output = compilerOutput.output ?? compilerOutput
  const compiled = output.contracts['project/contracts/CRISPProgram.sol']?.CRISPProgram ??
    output.contracts['contracts/CRISPProgram.sol']?.CRISPProgram
  assert(compiled, 'Missing CRISP compiler output')
  assert.deepEqual(compiled.evm.deployedBytecode.immutableReferences, artifact.immutableReferences)
  const names = new Map()
  function visit(node) {
    if (!node || typeof node !== 'object') return
    if (node.nodeType === 'VariableDeclaration' && node.mutability === 'immutable') names.set(String(node.id), node.name)
    for (const value of Object.values(node)) if (typeof value === 'object') visit(value)
  }
  for (const source of Object.values(output.sources)) visit(source.ast)
  const values = {}
  assert.equal(code.length, artifact.deployedBytecode.length, 'Unexpected CRISP runtime length')
  for (const [id, locations] of Object.entries(artifact.immutableReferences)) {
    const name = names.get(id)
    assert(name && !Object.hasOwn(values, name), 'Unknown or duplicate immutable')
    for (const { start, length } of locations) {
      assert.equal(length, 32)
      const value = '0x' + code.slice(2 + start * 2, 2 + (start + length) * 2)
      if (values[name]) assert.equal(value, values[name], 'Inconsistent immutable: ' + name)
      values[name] = value
    }
  }
  return values
}

export function checkProgramBindings({ chain, records, artifact, compilerOutput, code }) {
  const program = records.CRISPProgram.address.toLowerCase()
  const deployments = chain.transactions.filter(x => x.receipt.contractAddress?.toLowerCase() === program)
  assert.equal(deployments.length, 1, 'Expected the original program creation transaction')
  const creation = deployments[0]
  assert.equal(creation.receipt.status, '0x1')
  const constructor = new Interface(artifact.abi).deploy
  const encoded = '0x' + creation.transaction.input.slice(artifact.bytecode.length)
  const args = abi.decode(constructor.inputs, encoded)
  assert.equal(abi.encode(constructor.inputs, args), encoded, 'Noncanonical constructor arguments')
  const expectedArgs = [creation.transaction.from, records.OpenVmReceiptVerifier.address, records.HonkVerifier.address,
    records.OnchainHonkVerifier.address, records.MockCrispDataAvailabilityVerifier.address]
  expectedArgs.forEach((value, i) => assert.equal(args[i].toLowerCase(), value.toLowerCase(), 'Wrong constructor dependency ' + i))
  // The recovered local deployment reserves zero seconds. Check the actual
  // value rather than retroactively claiming that it provided a DA tail.
  assert.equal(args[6].toLowerCase(), creation.transaction.from.toLowerCase(), 'Unexpected local availability signer')
  const values = namedImmutables(code, artifact, compilerOutput)
  const expected = {
    _cachedDomainSeparator: TypedDataEncoder.hashDomain({ name: 'CRISP', version: '1', chainId: 31337, verifyingContract: program }),
    _cachedChainId: word(31337), _cachedThis: word(program),
    _hashedName: keccak256(toUtf8Bytes('CRISP')), _hashedVersion: keccak256(toUtf8Bytes('1')),
    _name: shortString('CRISP'), _version: shortString('1'),
    honkVerifier: word(expectedArgs[2]), onchainHonkVerifier: word(expectedArgs[3]),
    dataAvailabilityVerifier: word(expectedArgs[4]), availabilityFinalizationWindow: word(args[5]),
    inputAvailabilitySigner: word(args[6]),
  }
  assert.deepEqual(values, expected, 'CRISP constructor/immutable binding differs')
  return { constructorTransaction: creation.transaction.hash, immutables: values,
    receiptVerifier: args[1].toLowerCase(), imageId: args[7], checks: Object.keys(values).length }
}
