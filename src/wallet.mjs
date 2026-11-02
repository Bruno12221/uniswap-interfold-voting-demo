// SPDX-License-Identifier: LGPL-3.0-only
import { Contract, recoverAddress } from 'ethers'
import { address, hash32 } from './format.mjs'

export const isDelegatedEoaCode = code => /^0xef0100[0-9a-fA-F]{40}$/.test(code)

// Checks authorization only. CRISP's ballot circuit still requires an EOA signature.
export async function verifyWalletSignature(provider, slot, digest, signature, blockTag) {
  slot = address(slot); hash32(digest)
  if (blockTag === undefined) throw new Error('Choose an authorization block')
  const code = await provider.getCode(slot, blockTag)
  if (code === '0x' || isDelegatedEoaCode(code)) {
    try { if (address(recoverAddress(digest, signature)) === slot) return true }
    catch { /* A delegated account may instead use its contract validation path. */ }
    if (code === '0x') return false
  }
  const wallet = new Contract(slot, ['function isValidSignature(bytes32,bytes) view returns (bytes4)'], provider)
  try {
    return await wallet.isValidSignature(digest, signature, { blockTag }) === '0x1626ba7e'
  } catch (error) {
    if (error.code === 'CALL_EXCEPTION' || error.code === 'BAD_DATA') return false
    throw error
  }
}
