// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired (partial) — genesisHashFor consumed by routes/aimos.js for T2/T3 chain saves. Full live-path chain verification (verifyChain, advanceChain) not yet wired — deferred to Aimos-2 / Paper 2 mutation ledger (§11).
// Purpose: Per-agent append-only hash chain primitives — content hashing,
//          deterministic genesis, link advancement, chain verification, and
//          fork detection. Tamper-evident audit trail for save events.
// Wire into: auth middleware (Phase 4) and SAVE pipeline (Phase 5+).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * identity-chain.js — Per-Agent Hash Chain Primitives
 * Source: FIPS 180-4 (SHA-256), RFC 6962 Certificate Transparency,
 * Schneier & Kelsey 1999 (Secure Audit Logs), Crosby & Wallach 2009
 * (Efficient Data Structures for Tamper-Evident Logging), Accountability
 * of Things, and Aladdin Law (append-only, no overwrite).
 * Per-agent append-only chain follows Certificate Transparency log
 * semantics (RFC 6962) — Merkle-style consistency without the tree
 * (linear chain is sufficient for per-agent traffic at this scale).
 * Audit-log requirements per Schneier & Kelsey 1999: append-only,
 * tamper-evident, forward-secure under compromise.
 *
 * Pure functions. No DB. No I/O. Stateless.
 *
 * Formula contract:
 *   content_hash = SHA-256(JCS(save_body))
 *   genesis      = SHA-256("aimos-chain-genesis|" || agent_id || "|" || valid_from)
 *   chain_hash_n = SHA-256(
 *                    base64url(prev_hash) || "|" ||
 *                    base64url(content_hash) || "|" ||
 *                    ts || "|" || agent_id || "|" || memory_id
 *                  )
 *
 * This is a per-agent linear Certificate-Transparency-style log. RFC 6962
 * provides the append-only audit semantics; tamper-evident logging papers
 * justify the verification sweep and future O(log n) history-tree upgrade.
 *
 * Each (agent_id, valid_from) tuple has its own chain with deterministic
 * genesis. Rotation produces a fresh chain; old chains stay frozen at
 * their last head as historical artifacts. Chain advancement is
 * client-supplied (cryptographic ordering) — server-supplied is supported
 * by the same primitive but is a Phase 4 deployment choice, not encoded
 * here.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalJson } from './agent-identity.js';

const HASH_BYTES = 32;
const GENESIS_PREFIX = 'aimos-chain-genesis|';
const LINK_SEP = '|';

// ─── Encoding helpers ────────────────────────────────────────────────────────
// Self-contained to keep this module decoupled from agent-identity.js's
// internal encoding helpers (which are not exported).

export function bufToB64u(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  return buf.toString('base64url');
}

export function b64uToBuf(str) {
  if (typeof str !== 'string' || str.length === 0) return null;
  // Validate base64url alphabet: A-Z a-z 0-9 - _ (no padding expected,
  // but tolerate stray '=' for robustness).
  if (!/^[A-Za-z0-9_\-=]+$/.test(str)) return null;
  try {
    const buf = Buffer.from(str, 'base64url');
    return buf;
  } catch {
    return null;
  }
}

// ─── Content hash ────────────────────────────────────────────────────────────

export function contentHash(value) {
  const cj = canonicalJson(value);
  return createHash('sha256').update(cj, 'utf8').digest();
}

// ─── Genesis ─────────────────────────────────────────────────────────────────
// Deterministic, non-secret. Each (agent_id, valid_from) gets a unique
// starting point. Both client and server can derive without coordination.

export function genesisHashFor(agentId, validFromIso) {
  if (typeof agentId !== 'string' || agentId.length === 0) {
    throw new Error('genesisHashFor: agentId must be non-empty string');
  }
  if (typeof validFromIso !== 'string' || validFromIso.length === 0) {
    throw new Error('genesisHashFor: validFromIso must be non-empty string');
  }
  const seed = GENESIS_PREFIX + agentId + LINK_SEP + validFromIso;
  return createHash('sha256').update(seed, 'utf8').digest();
}

// ─── Link advancement ────────────────────────────────────────────────────────
// chain_hash_n = SHA-256( base64url(prev) || "|" || base64url(content)
//                         || "|" || ts || "|" || agentId || "|" || memoryId )

export function chainHashOf(prevHashBuf, contentHashBuf, ts, agentId, memoryId) {
  if (!Buffer.isBuffer(prevHashBuf) || prevHashBuf.length !== HASH_BYTES) {
    throw new Error('chainHashOf: prevHashBuf must be 32-byte Buffer');
  }
  if (!Buffer.isBuffer(contentHashBuf) || contentHashBuf.length !== HASH_BYTES) {
    throw new Error('chainHashOf: contentHashBuf must be 32-byte Buffer');
  }
  if (!Number.isInteger(ts)) {
    throw new Error('chainHashOf: ts must be integer unix seconds');
  }
  if (typeof agentId !== 'string' || agentId.length === 0) {
    throw new Error('chainHashOf: agentId must be non-empty string');
  }
  if (typeof memoryId !== 'string' || memoryId.length === 0) {
    throw new Error('chainHashOf: memoryId must be non-empty string');
  }

  const message =
    prevHashBuf.toString('base64url') + LINK_SEP +
    contentHashBuf.toString('base64url') + LINK_SEP +
    String(ts) + LINK_SEP +
    agentId + LINK_SEP +
    memoryId;
  return createHash('sha256').update(message, 'utf8').digest();
}

// ─── Single-link verification ────────────────────────────────────────────────

export function verifyChainLink(prev, claimedNext, contentHashBuf, ts, agentId, memoryId) {
  if (!Buffer.isBuffer(prev) || prev.length !== HASH_BYTES) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (!Buffer.isBuffer(claimedNext) || claimedNext.length !== HASH_BYTES) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (!Buffer.isBuffer(contentHashBuf) || contentHashBuf.length !== HASH_BYTES) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (!Number.isInteger(ts)) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof agentId !== 'string' || agentId.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof memoryId !== 'string' || memoryId.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }

  let expected;
  try {
    expected = chainHashOf(prev, contentHashBuf, ts, agentId, memoryId);
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }

  if (expected.length !== claimedNext.length) {
    return { valid: false, reason: 'malformed_input' };
  }
  return timingSafeEqual(expected, claimedNext)
    ? { valid: true, reason: null }
    : { valid: false, reason: 'link_mismatch' };
}

// ─── Full-chain verification ─────────────────────────────────────────────────
// Walks from genesis, recomputes each link, returns the first failure.
// rows: [{ contentHash: Buffer, chainHash: Buffer, ts: number, memoryId: string }, ...]

export function verifyChain(rows, agentId, validFromIso) {
  if (!Array.isArray(rows)) {
    return { valid: false, brokenAtIndex: null, reason: 'malformed_input' };
  }
  if (rows.length === 0) {
    return { valid: true, brokenAtIndex: null, reason: null };
  }

  let prev;
  try {
    prev = genesisHashFor(agentId, validFromIso);
  } catch {
    return { valid: false, brokenAtIndex: null, reason: 'malformed_input' };
  }

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const link = verifyChainLink(prev, r.chainHash, r.contentHash, r.ts, agentId, r.memoryId);
    if (!link.valid) {
      return { valid: false, brokenAtIndex: i, reason: link.reason };
    }
    prev = r.chainHash;
  }
  return { valid: true, brokenAtIndex: null, reason: null };
}

// ─── Fork detection ──────────────────────────────────────────────────────────

export function detectForkAdvanced(claimedPrev, storedHead) {
  if (!Buffer.isBuffer(claimedPrev) || claimedPrev.length !== HASH_BYTES) {
    return { ok: false, reason: 'malformed_input' };
  }
  if (!Buffer.isBuffer(storedHead) || storedHead.length !== HASH_BYTES) {
    return { ok: false, reason: 'malformed_input' };
  }
  return timingSafeEqual(claimedPrev, storedHead)
    ? { ok: true, reason: null }
    : { ok: false, reason: 'fork_detected' };
}

export function detectForkInitial(claimedPrev, agentId, validFromIso) {
  if (!Buffer.isBuffer(claimedPrev) || claimedPrev.length !== HASH_BYTES) {
    return { ok: false, reason: 'malformed_input' };
  }
  let genesis;
  try {
    genesis = genesisHashFor(agentId, validFromIso);
  } catch {
    return { ok: false, reason: 'malformed_input' };
  }
  return timingSafeEqual(claimedPrev, genesis)
    ? { ok: true, reason: null }
    : { ok: false, reason: 'first_save_must_use_genesis' };
}
