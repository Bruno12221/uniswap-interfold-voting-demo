// SPDX-License-Identifier: LGPL-3.0-only
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { canonical, digest } from './format.mjs'
import { profile } from './round.mjs'

export const ROOT = fileURLToPath(new URL('../', import.meta.url))
export const UPSTREAM = resolve(ROOT, '.local/upstream/interfold')
export const CRISP = resolve(UPSTREAM, 'examples/CRISP')
const require = createRequire(import.meta.url)
const sha = bytes => '0x' + createHash('sha256').update(bytes).digest('hex')
const json = path => JSON.parse(readFileSync(path, 'utf8'))
const acirHash = circuit => sha(Buffer.from(circuit.bytecode, 'base64'))

export async function loadProofRuntime(preset) {
  if (!profile.presets[preset]) throw new Error('Unsupported proof preset')
  if (execFileSync('git', ['rev-parse', 'HEAD'], { cwd: UPSTREAM, encoding: 'utf8' }).trim() !== profile.sourceRevision)
    throw new Error('Wrong upstream revision')
  const sdk = await import(pathToFileURL(resolve(CRISP, 'packages/crisp-sdk/dist/index.js')).href)
  const bundle = await import(pathToFileURL(resolve(CRISP, `packages/crisp-sdk/dist/presets/${preset}.js`)).href)
  const circuits = await bundle.loadCircuits()
  sdk.setCircuits(circuits)
  const { ZKInputsGenerator } = await import(pathToFileURL(resolve(CRISP, 'packages/crisp-zk-inputs/main.js')).href)
  const generator = ZKInputsGenerator.fromPreset(preset)
  const params = generator.getBFVParams()
  if (params.degree !== profile.presets[preset].degree || params.plaintextModulus.toString() !== profile.presets[preset].plaintextModulus)
    throw new Error('Generator parameters differ from the profile')
  const core = require(resolve(UPSTREAM, 'crates/wasm/dist/node/e3_wasm.js'))
  return { sdk, circuits, generator, params, core }
}

export async function inspectArtifacts() {
  const presets = {}
  const constants = readFileSync(resolve(UPSTREAM, 'packages/interfold-contracts/scripts/utils.ts'), 'utf8')
  for (const preset of Object.keys(profile.presets)) {
    const { circuits } = await loadProofRuntime(preset)
    const symbol = preset === 'insecure-512' ? 'INSECURE_PARAM_SET_HASH' : 'SECURE_PARAM_SET_HASH'
    const found = constants.match(new RegExp('const ' + symbol + '\\s*=\\s*"(0x[0-9a-f]{64})"'))
    if (found?.[1] !== profile.presets[preset].paramsHash) throw new Error('Protocol parameter hash differs from the profile')
    presets[preset] = { crispAcirSha256: acirHash(circuits.crisp),
      encryptionCt0AcirSha256: acirHash(circuits.userDataEncryptionCt0), encryptionCt1AcirSha256: acirHash(circuits.userDataEncryptionCt1) }
  }
  const verifierArtifacts = {}
  for (const name of ['HonkVerifier', 'RelationsLib', 'ZKTranscriptLib']) {
    const artifact = json(resolve(CRISP, `packages/crisp-contracts/artifacts/contracts/verifiers/CRISPVerifier.sol/${name}.json`))
    // The unlinked verifier contains non-hex library placeholders. Hash the complete
    // template and link table, rather than silently truncating it with hex decoding.
    verifierArtifacts[name] = { creationTemplateSha256: sha(Buffer.from(artifact.bytecode, 'utf8')),
      linkReferences: artifact.linkReferences }
  }
  return { schemaVersion: 1, sourceRevision: profile.sourceRevision, profileHash: digest(profile), censusMode: 'merkle', presets,
    foldAcirSha256: acirHash(json(resolve(CRISP, 'circuits/bin/fold/target/crisp_fold.json'))),
    encryptionFoldAcirSha256: acirHash(json(resolve(UPSTREAM, 'circuits/bin/threshold/target/user_data_encryption.json'))),
    verifierSourceSha256: sha(readFileSync(resolve(CRISP, 'packages/crisp-contracts/contracts/verifiers/CRISPVerifier.sol'))),
    verifierArtifacts }
}

export async function checkLockedArtifacts() {
  const expected = json(resolve(ROOT, 'config/t05-artifacts.json'))
  if (canonical(await inspectArtifacts()) !== canonical(expected)) throw new Error('Proof artifacts differ from their reviewed lock')
  return digest(expected)
}
