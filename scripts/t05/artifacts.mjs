// SPDX-License-Identifier: LGPL-3.0-only
import { writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { checkLockedArtifacts, inspectArtifacts, ROOT } from '../../src/upstream.mjs'
if (process.argv[2] === '--write') {
  await writeFile(resolve(ROOT, 'config/t05-artifacts.json'), JSON.stringify(await inspectArtifacts(), null, 2) + '\n', { flag: 'wx' })
  console.log('Artifact lock created. Review it before committing.')
} else if (process.argv[2] === '--check') {
  console.log('Artifact lock matches: ' + await checkLockedArtifacts())
} else { throw new Error('Choose --write for an initial reviewed lock or --check to verify it') }
