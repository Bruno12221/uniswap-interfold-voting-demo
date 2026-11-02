// SPDX-License-Identifier: LGPL-3.0-only
import { DatabaseSync } from 'node:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { getBytes, keccak256 } from 'ethers'
import { canonical, digest, hash32 } from './format.mjs'

// Only public configuration, chain data, proofs and signed public transactions belong here.
export class CoordinatorStore {
  constructor(path) {
    mkdirSync(dirname(path), { recursive: true })
    this.db = new DatabaseSync(path)
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=0;
      CREATE TABLE IF NOT EXISTS records (name TEXT PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS ciphertexts (hash TEXT PRIMARY KEY, bytes BLOB NOT NULL);`)
  }
  get(name) {
    const row = this.db.prepare('SELECT body,hash FROM records WHERE name=?').get(name)
    if (!row) return undefined
    const value = JSON.parse(row.body)
    if (digest(value) !== row.hash) throw new Error('Stored public record checksum mismatch')
    return value
  }
  put(name, value) {
    this.db.prepare('INSERT INTO records VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET body=excluded.body,hash=excluded.hash')
      .run(name, canonical(value), digest(value))
  }
  list(prefix) {
    return this.db.prepare('SELECT name FROM records WHERE substr(name,1,?)=? ORDER BY name').all(prefix.length, prefix)
      .map(row => [row.name, this.get(row.name)])
  }
  putCiphertext(bytes) {
    bytes = getBytes(bytes)
    if (!bytes.length || bytes.length > 8 * 1024 * 1024) throw new Error('Invalid ciphertext size')
    const hash = keccak256(bytes)
    this.db.prepare('INSERT OR IGNORE INTO ciphertexts VALUES (?,?)').run(hash, bytes)
    return hash
  }
  getCiphertext(hash) {
    const row = this.db.prepare('SELECT bytes FROM ciphertexts WHERE hash=?').get(hash32(hash))
    if (!row) return undefined
    const bytes = Uint8Array.from(row.bytes)
    if (keccak256(bytes) !== hash) throw new Error('Stored ciphertext checksum mismatch')
    return bytes
  }
  async transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE')
    try { const value = await fn(); this.db.exec('COMMIT'); return value }
    catch (error) { this.db.exec('ROLLBACK'); throw error }
  }
  close() { this.db.close() }
}
