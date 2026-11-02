// SPDX-License-Identifier: LGPL-3.0-only
import { getAddress, sha256, toUtf8Bytes } from 'ethers'

export function address(value) {
  if (typeof value !== 'string') throw new Error('Address must be a string')
  return getAddress(value).toLowerCase()
}

export function uint(value, max = (1n << 256n) - 1n) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > max)
    throw new Error('Expected a canonical unsigned decimal string')
  return BigInt(value)
}

export function hash32(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/.test(value)) throw new Error('Expected a lowercase 32-byte hash')
  return value
}

export function keys(value, expected) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort()))
    throw new Error('Unexpected object fields')
}

// Version 1 accepts JSON strings, booleans, null and safe integers. Weights use strings.
export function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('Malformed Unicode')
    return JSON.stringify(value)
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value && Object.getPrototypeOf(value) === Object.prototype)
    return '{' + Object.keys(value).sort().map(key => canonical(key) + ':' + canonical(value[key])).join(',') + '}'
  throw new Error('Unsupported canonical value')
}

export const digest = value => sha256(toUtf8Bytes(canonical(value)))
