// SPDX-License-Identifier: LGPL-3.0-only
import { digest } from './format.mjs'
import { inputId, requireThat } from './coordinator-protocol.mjs'

export const SYNTHETIC_ADMISSION_BUDGET = 60

// The availability signer must reserve here BEFORE issuing any attestation,
// including wallet-submitted commitments. Relay-only limits are insufficient.
// Reservations are never recycled: a previously issued signature may still be
// submitted directly. Keep the durable database across service restarts.
export async function reserveAdmission(store, manifest, identity) {
  const namespace = digest({ chainId: manifest.chainId, protocol: manifest.interfoldAddress,
    program: manifest.programAddress, e3Id: manifest.e3Id })
  const id = inputId(manifest, identity), prefix = 'admission-budget:' + namespace
  return store.transaction(() => {
    const key = prefix + ':' + id, existing = store.get(key)
    if (existing) return existing
    const budget = store.get(prefix) ?? { limit: SYNTHETIC_ADMISSION_BUDGET, reserved: 0 }
    requireThat(budget.limit === SYNTHETIC_ADMISSION_BUDGET && Number.isSafeInteger(budget.reserved) && budget.reserved >= 0,
      'INVALID_ADMISSION_BUDGET')
    requireThat(budget.reserved < budget.limit, 'ADMISSION_BUDGET_EXHAUSTED')
    const reservation = { inputId: id, ordinal: budget.reserved + 1 }
    store.put(prefix, { ...budget, reserved: reservation.ordinal }); store.put(key, reservation)
    return reservation
  })
}
