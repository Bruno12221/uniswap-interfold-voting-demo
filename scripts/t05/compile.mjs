// SPDX-License-Identifier: LGPL-3.0-only
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { CRISP, ROOT } from '../../src/upstream.mjs'

export function compileComponents(paths = ['contracts/FrozenRoundRegistry.sol', 'tests/contracts/T05Fixture.sol']) {
  if (!execFileSync('solc', ['--version'], { encoding: 'utf8' }).includes('0.8.28+commit.7893614a'))
    throw new Error('Source the pinned T03 tool environment')
  const sources = Object.fromEntries(paths
    .map(path => [path, { content: readFileSync(resolve(ROOT, path), 'utf8') }]))
  const input = { language: 'Solidity', sources, settings: {
    optimizer: { enabled: true, runs: 200 }, viaIR: true,
    remappings: ['@interfold/contracts/=.local/upstream/interfold/packages/interfold-contracts/'],
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.bytecode.linkReferences'] } } } }
  const output = JSON.parse(execFileSync('solc', ['--base-path', ROOT, '--include-path',
    resolve(CRISP, 'packages/crisp-contracts/node_modules'), '--standard-json'],
  { input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }))
  const errors = (output.errors || []).filter(x => x.severity === 'error')
  if (errors.length) throw new Error(errors.map(x => x.formattedMessage).join('\n'))
  return output.contracts
}

export async function ensurePoseidon(provider, signer) {
  const requireContracts = createRequire(resolve(CRISP, 'packages/crisp-contracts/package.json'))
  const poseidon = requireContracts('poseidon-solidity')
  if (await provider.getCode(poseidon.proxy.address) === '0x') {
    await (await signer.sendTransaction({ to: poseidon.proxy.from, value: poseidon.proxy.gas })).wait()
    await (await provider.broadcastTransaction(poseidon.proxy.tx)).wait()
  }
  if (await provider.getCode(poseidon.PoseidonT3.address) === '0x')
    await (await signer.sendTransaction({ to: poseidon.proxy.address, data: poseidon.PoseidonT3.data })).wait()
  if (await provider.send('eth_getCode', [poseidon.PoseidonT3.address, 'latest']) === '0x') throw new Error('Poseidon deployment failed')
  return poseidon.PoseidonT3.address
}

export function linkedBytecode(artifact, libraries = {}) {
  let code = artifact.evm ? artifact.evm.bytecode.object : artifact.bytecode.slice(2)
  const links = artifact.evm ? artifact.evm.bytecode.linkReferences : artifact.linkReferences
  for (const [file, names] of Object.entries(links))
    for (const [name, references] of Object.entries(names)) {
      const value = libraries[`${file}:${name}`]
      if (!/^0x[0-9a-fA-F]{40}$/.test(value)) throw new Error('Missing test library')
      for (const { start, length } of references) {
        if (length !== 20) throw new Error('Unexpected link width')
        code = code.slice(0, start * 2) + value.slice(2) + code.slice((start + length) * 2)
      }
    }
  if (!/^[0-9a-fA-F]+$/.test(code)) throw new Error('Unresolved bytecode link')
  return '0x' + code
}
