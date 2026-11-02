// SPDX-License-Identifier: LGPL-3.0-only
import { Crs } from '@pilot/bb-crs'
import { Buffer } from '@pilot/buffer'
import * as sdk from '@crisp-e3/sdk'
import { ZKInputsGenerator } from '@crisp-e3/zk-inputs'
import * as core from '@pilot/core'
import coreBase64 from '@pilot/core-base64'
import lock from '../config/t05-artifacts.json' with { type: 'json' }
import { digest } from '../src/format.mjs'
import { profile } from '../src/round.mjs'
import { sha256 } from 'ethers'
globalThis.Buffer = Buffer
// Chromium rejects individual IndexedDB values around 128 MiB. Keep the full SRS
// in proving memory; skip only the optional oversized public cache write.
const cacheUncompressed = Crs.prototype.cacheUncompressed
Crs.prototype.cacheUncompressed = async function (data) {
  if (data.byteLength > 120 * 1024 * 1024) return
  return cacheUncompressed.call(this, data)
}
const decode = value => Uint8Array.from(atob(value), x => x.charCodeAt(0))
let promise, selectedPreset
export function runtime(preset) {
  if (!['insecure-512', 'secure-8192'].includes(preset) || (selectedPreset && selectedPreset !== preset))
    throw new Error('Unsupported or concurrent browser preset switch')
  selectedPreset = preset
  return promise ??= (async () => {
    const { loadCircuits } = preset === 'secure-8192' ? await import('@crisp-e3/sdk/secure-8192') : await import('@crisp-e3/sdk/insecure-512')
    const circuits = await loadCircuits()
    for (const [name, expected] of [['crisp', 'crispAcirSha256'], ['userDataEncryptionCt0', 'encryptionCt0AcirSha256'],
      ['userDataEncryptionCt1', 'encryptionCt1AcirSha256']])
      if (sha256(decode(circuits[name].bytecode)) !== lock.presets[preset][expected]) throw new Error('Circuit hash mismatch')
    if (digest(profile) !== lock.profileHash) throw new Error('Profile hash mismatch')
    core.initSync({ module: decode(coreBase64) })
    sdk.setCircuits(circuits)
    const generator = ZKInputsGenerator.fromPreset(preset), params = generator.getBFVParams()
    if (params.degree !== profile.presets[preset].degree ||
      params.plaintextModulus.toString() !== profile.presets[preset].plaintextModulus) throw new Error('Wrong FHE parameters')
    return { sdk, circuits, generator, params, core, artifactsHash: digest(lock) }
  })()
}
