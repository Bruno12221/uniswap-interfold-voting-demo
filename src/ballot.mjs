// SPDX-License-Identifier: LGPL-3.0-only
import { prepareBoundBallot as prepare } from './ballot-core.mjs'
import { checkLockedArtifacts, loadProofRuntime } from './upstream.mjs'
export { validateUnitVote, authenticatePublicKey, finishBoundBallot } from './ballot-core.mjs'
export async function prepareBoundBallot(options) {
  const hash = await checkLockedArtifacts()
  return prepare(options, await loadProofRuntime(options.manifest.preset), hash)
}
