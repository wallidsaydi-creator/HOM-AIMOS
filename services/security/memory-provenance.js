// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired — POST /save handler calls commitProvenance UNCONDITIONALLY
// (T1/T2/T3) after persistMemory returns a memory_id, additive alongside the
// existing T2/T3 commitEnvelope gate. The provenance ledger is the
// memory-centric mutation ledger — sibling to the agent-chain envelope ledger.
// Cross-identity: a memory mutated by agent A and then agent B has two linked
// rows; the chain survives the identity transition.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * memory-provenance.js — memory-centric mutation ledger (Phase 4)
 *
 * Every save — T1, T2, or T3 — writes one provenance row here. The 018 schema
 * traces a memory's mutations via prev_mutation_hash. The 021 schema locks
 * in the linked-list shape (one genesis per memory_id; no fork-race on prev).
 *
 * Cross-ledger reference:
 *   . content_hash  = sha256(canonicalJson(body))    — SAME form as the
 *                                                      envelope ledger's
 *                                                      content_hash (identity-
 *                                                      chain.js#contentHash)
 *   . sig           = Ed25519 over canonicalJson(body) + '\n' + nonce +
 *                      '\n' + String(ts_signed)         — SAME signed-message
 *                                                      form as the envelope
 *                                                      ledger (agent-identity.
 *                                                      js#buildSignedMessage)
 *
 * For T2/T3 saves: the SAME sig bytes are stored in BOTH aimos_save_envelope
 * AND aimos_memory_provenance. One sig, two ledger rows. The shared
 * canonical form is the cross-ledger reference key — a row in one ledger can
 * be cross-referenced to a row in the other by matching content_hash.
 *
 * For T1 saves (no envelope row by design — routes/aimos.js:2426 gates the
 * INSERT at :2663 on isChainSave): this is the ONLY cryptographic attestation
 * of the save. The architectural finding driving Phase 4: T1 saves were
 * agent-authenticated but not memory-attested; commitProvenance closes that
 * gap. |provenance|19,041 - |envelope|43 = 18,998 T1-class memories gained
 * cryptographic mutation coverage at the backfill, and every T1 save going
 * forward writes a P-live row.
 *
 * mutation_hash form (from migration 018 comment):
 *   genesis  : sha256(content_hash || nonce || String(ts_signed))
 *   mutation : sha256(content_hash || prev_mutation_hash || nonce || String(ts_signed))
 *
 * Chain integrity (migration 021):
 *   UNIQUE(memory_id)              WHERE prev_mutation_hash IS NULL    — one genesis
 *   UNIQUE(memory_id, prev_mutation_hash) WHERE prev IS NOT NULL      — no fork-race
 *   CHECK (is_genesis ⟺ prev_mutation_hash IS NULL)                  — invariant
 *
 * . `ok` on race-victory: caller-visible retry; the harness surfaces it.
 * . `ok:false, reason:'fork_race'` : another writer claimed the same prev
 *   between our SELECT and INSERT — partial unique constraint rejected us.
 * . `ok:false, reason:'duplicate_genesis'` : non-recoverable without an
 *   in-call retry (handled transparently here, surfaced only if the retry
 *   itself fails).
 *
 * Dependency-injected like save-envelope.js so tests use a mock pool.
 */

import { createHash } from 'node:crypto';
import { contentHash } from './identity-chain.js';
import {
  canonicalJson,
  verifyStoredPayloadSig,
  verifyStoredPayloadSigV2,
  verifyStoredPayloadSigWithContext,
  verifyStoredPayloadSigWithEnvelopeClaims,
  verifyCertChain,
  verifyAgentRevocationProof,
  resolveCertificateAuthorityPubkey,
} from './agent-identity.js';
import { verifyHousekeeperSupersessionLineage } from './memory-lineage.js';
import {
  retainedProvenanceLeafHash,
  retainedProvenanceMerkleRoot,
} from './protocol/mutmem-protocol.js';
import { signedMemoryValueMatchesRetained } from './protocol/memory-value.js';
import {
  CONTENT_STATE_OCCURRENCE_V3,
  computeLegacyOccurrenceReference,
  computeOccurrenceCommitmentV3,
  verifyOccurrenceSignatureV3,
} from './protocol/content-state-occurrence-v3.js';
import { readVerifiedRequestReceiptByMutationHash } from './request-receipt-ledger.js';
import { readVerifiedEventById } from '../observe/event-ledger.js';
export {
  retainedProvenanceLeafHash,
  retainedProvenanceMerkleRoot,
} from './protocol/mutmem-protocol.js';
import { pool as defaultPool } from '../../db/connection.js';

const HASH_BYTES = 32;

function tsBuf(ts) {
  return Buffer.from(String(ts), 'utf8');
}

function nonceBuf(nonce) {
  return Buffer.from(nonce, 'utf8');
}

function computeMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts) {
  const parts = prevMutationHashBuf
    ? [contentHashBuf, prevMutationHashBuf, nonceBuf(nonce), tsBuf(ts)]
    : [contentHashBuf, nonceBuf(nonce), tsBuf(ts)];
  return createHash('sha256').update(Buffer.concat(parts)).digest();
}

// ─── v2 mutation_hash (backfill ceremony rows) ─────────────────────────────
// v2 folds memory_originated_at_unix into the mutation_hash preimage so the
// time axis is cryptographically bound into the chain, not just into the sig.
// Used by scripts/backfill-ledger-reviewer.mjs for the 18,998 P-anchor
// re-attestation rows (sig_form_version=2). commitProvenance stays v1 — the
// live /save path is unchanged. Verification selects the canonical form from
// the signed row's sig_form_version.
export function computeMutationHashV2(contentHashBuf, prevMutationHashBuf, nonce, ts, memoryOriginatedAtUnix) {
  if (!Number.isInteger(memoryOriginatedAtUnix)) {
    throw new Error('computeMutationHashV2: memoryOriginatedAtUnix must be integer unix seconds');
  }
  const moaBuf = Buffer.from(String(memoryOriginatedAtUnix), 'utf8');
  const parts = prevMutationHashBuf
    ? [contentHashBuf, prevMutationHashBuf, nonceBuf(nonce), tsBuf(ts), moaBuf]
    : [contentHashBuf, nonceBuf(nonce), tsBuf(ts), moaBuf];
  return createHash('sha256').update(Buffer.concat(parts)).digest();
}

// ─── Phase 8: verify-side mirrors ──────────────────────────────────────────
// Used by the /recall choke-point (handleAimosRecall) to verify each recalled
// memory's mutation_hash recomputes against its provenance row. If a row's
// value is tampered in aimos_memories, the content_hash won't match the
// stored content_hash in the provenance row, so the recomputed mutation_hash
// won't match the stored mutation_hash — the row is rejected under enforce
// or logged under shadow. See docs/security/backfill-ceremony-design.md §5.
// The verifier mirrors the signed provenance form used by the write path.
export function verifyMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts, expectedHashBuf) {
  if (!Buffer.isBuffer(expectedHashBuf) || expectedHashBuf.length !== HASH_BYTES) return false;
  try {
    const computed = computeMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts);
    return computed.equals(expectedHashBuf);
  } catch {
    return false;
  }
}

export function verifyMutationHashV2(contentHashBuf, prevMutationHashBuf, nonce, ts, memoryOriginatedAtUnix, expectedHashBuf) {
  if (!Buffer.isBuffer(expectedHashBuf) || expectedHashBuf.length !== HASH_BYTES) return false;
  try {
    const computed = computeMutationHashV2(contentHashBuf, prevMutationHashBuf, nonce, ts, memoryOriginatedAtUnix);
    return computed.equals(expectedHashBuf);
  } catch {
    return false;
  }
}

// ─── Phase 9a: live-row content hash ────────────────────────────────────────
// Distinct from the provenance row's content_hash (which is sha256 of the full
// freeform req.body). The live-row content_hash is sha256 of a CANONICAL SUBSET
// of fields stored on aimos_memories: {key, value, scope, memory_type,
// clearance_level, data_class, source}. These are the fields that define the
// memory's CONTENT + CLASSIFICATION — not its lifecycle state (access_count,
// decay_weight, etc. legitimately change over time).
//
// Computed at save time in persist-memory.js + stored on aimos_memories.
// At recall time, verifyRecallMemories recomputes from the live row's fields
// and compares to the stored content_hash. Mismatch → the live row was tampered
// (someone UPDATEd value/key/scope/etc. without recomputing the hash). This is
// check 2a — catches the lazy attacker. Phase 9b will add the append-only
// snapshot on aimos_memory_provenance to catch the sophisticated attacker who
// recomputes the stored hash after tampering.
//
// Field order is fixed by canonicalJson (sorted keys), so the hash is stable
// regardless of object property insertion order. All field values are coerced
// to strings for hashing — numbers, booleans, null all become their JSON
// representation via canonicalJson. NULL fields in the DB are normalized to
// empty string before canonicalization so the hash is stable across PG null
// vs. empty-string representations.
export function computeLiveRowContentHash(fields) {
  if (!fields || typeof fields !== 'object') {
    throw new Error('computeLiveRowContentHash: fields must be an object');
  }
  const normalized = {
    key: fields.key == null ? '' : String(fields.key),
    value: fields.value == null ? '' : String(fields.value),
    scope: fields.scope == null ? '' : String(fields.scope),
    memory_type: fields.memory_type == null ? '' : String(fields.memory_type),
    clearance_level: fields.clearance_level == null ? '' : String(fields.clearance_level),
    data_class: fields.data_class == null ? '' : String(fields.data_class),
    source: fields.source == null ? '' : String(fields.source),
  };
  const canonical = canonicalJson(normalized);
  return createHash('sha256').update(canonical, 'utf8').digest();
}

export function verifyLiveRowContentHash(fields, expectedHashBuf) {
  if (!Buffer.isBuffer(expectedHashBuf) || expectedHashBuf.length !== HASH_BYTES) return false;
  try {
    const computed = computeLiveRowContentHash(fields);
    return computed.equals(expectedHashBuf);
  } catch {
    return false;
  }
}

function parseJsonObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function occurrenceReferenceForProvenanceRow(row, companyId) {
  if (Number(row.sig_form_version || 1) === 3) {
    const commitment = Buffer.from(row.mutation_hash || []);
    if (commitment.length !== HASH_BYTES) throw new Error('occurrence_v3_commitment_shape_invalid');
    return commitment.toString('hex');
  }
  const validFromMs = new Date(row.agent_valid_from).getTime();
  if (!Number.isSafeInteger(validFromMs)) throw new Error('legacy_occurrence_signer_epoch_invalid');
  return computeLegacyOccurrenceReference({
    company_id: companyId,
    memory_id: row.memory_id,
    provenance_id: row.provenance_id,
    mutation_hash_hex: Buffer.from(row.mutation_hash || []).toString('hex'),
    agent_id: row.provenance_agent_id || row.agent_id,
    signer_valid_from_unix_ms: validFromMs,
    cert_fingerprint_hex: row.cert_fingerprint,
    event_type: String(row.event_type || 'SAVE').toUpperCase(),
    sig_form_version: Number(row.sig_form_version || 1),
  });
}

/**
 * Order a mixed legacy/v3 provenance stream by occurrence references.
 * Legacy predecessor columns still contain legacy mutation hashes, whereas v3
 * predecessor columns contain occurrence references. This bridge preserves all
 * retained bytes and makes the transition verifiable without rewriting them.
 */
export function orderProvenanceRowsByOccurrenceTopology(rows = [], companyId) {
  if (!Array.isArray(rows) || rows.length === 0) return [];
  const references = new Map();
  const legacyByMutation = new Map();
  for (const row of rows) {
    const reference = occurrenceReferenceForProvenanceRow(row, companyId);
    if (references.has(reference)) throw new Error('provenance_occurrence_reference_duplicate');
    references.set(reference, row);
    if (Number(row.sig_form_version || 1) !== 3) {
      const mutation = Buffer.from(row.mutation_hash || []).toString('hex');
      if (legacyByMutation.has(mutation)) throw new Error('provenance_legacy_mutation_duplicate');
      legacyByMutation.set(mutation, reference);
    }
  }

  const children = new Map();
  const roots = [];
  for (const [reference, row] of references) {
    let predecessor = null;
    if (row.prev_mutation_hash != null) {
      const stored = Buffer.from(row.prev_mutation_hash).toString('hex');
      predecessor = Number(row.sig_form_version || 1) === 3
        ? stored
        : legacyByMutation.get(stored) || (references.has(stored) ? stored : null);
      if (!predecessor || !references.has(predecessor)) {
        throw new Error('provenance_occurrence_predecessor_missing');
      }
      if (children.has(predecessor)) throw new Error('provenance_occurrence_fork');
      children.set(predecessor, reference);
    } else {
      roots.push(reference);
    }
  }
  if (roots.length !== 1) throw new Error('provenance_occurrence_genesis_invalid');
  const ordered = [];
  const visited = new Set();
  let cursor = roots[0];
  while (cursor) {
    if (visited.has(cursor) || !references.has(cursor)) throw new Error('provenance_occurrence_cycle');
    visited.add(cursor);
    ordered.push(references.get(cursor));
    cursor = children.get(cursor) || null;
  }
  if (ordered.length !== rows.length) throw new Error('provenance_occurrence_disconnected');
  return ordered;
}

export function verifyOccurrenceEvidenceRowV3(row = {}) {
  const body = parseJsonObject(row.body_json);
  if (!body || body.schema !== CONTENT_STATE_OCCURRENCE_V3.schema) {
    return { valid: false, reason: 'occurrence_v3_body_missing' };
  }
  if (!row.signer_pubkey || !row.signer_cert || !row.agent_valid_from
      || !Buffer.isBuffer(row.sig) || row.sig.length !== 64) {
    return { valid: false, reason: 'occurrence_v3_signer_material_missing' };
  }
  const certBody = parseCertificateBody(row.signer_cert);
  const certificateFingerprint = createHash('sha256')
    .update(String(row.signer_cert), 'utf8')
    .digest('hex');
  const signedTs = Number(row.ts_signed);
  const certAuthorityPubkey = resolveCertificateAuthorityPubkey({
    certificateBody: certBody,
    subjectPubkey: row.signer_pubkey,
    masterPubkey: row.master_pubkey,
    masterFingerprint: row.master_fingerprint,
  });
  if (!certBody || !certAuthorityPubkey || certificateFingerprint !== row.cert_fingerprint) {
    return { valid: false, reason: 'occurrence_v3_signer_identity_mismatch' };
  }
  const certificate = verifyCertChain(row.signer_cert, certAuthorityPubkey, {
    nowFn: () => signedTs,
  });
  if (!certificate.valid
      || certBody.agent_id !== row.provenance_agent_id
      || certBody.pubkey !== row.signer_pubkey
      || Number(certBody.valid_from) !== Math.floor(new Date(row.agent_valid_from).getTime() / 1000)) {
    return { valid: false, reason: certificate.reason || 'occurrence_v3_certificate_mismatch' };
  }
  if (row.revocation_sig && Number(row.revocation_ts_signed) <= signedTs) {
    return { valid: false, reason: 'occurrence_v3_signer_revoked_before_event' };
  }
  const expectedRecord = {
    company_id: String(row.live_company_id),
    occurrence_event_id: String(row.provenance_id).toLowerCase(),
    memory_id: String(row.memory_id).toLowerCase(),
    event_type: String(row.event_type || '').toUpperCase(),
    live_content_hash_hex: Buffer.from(row.live_content_hash || []).toString('hex'),
    predecessor_present: row.prev_mutation_hash == null ? 0 : 1,
    predecessor_commitment_hex: row.prev_mutation_hash
      ? Buffer.from(row.prev_mutation_hash).toString('hex')
      : '',
    agent_id: String(row.provenance_agent_id),
    signer_valid_from_unix_ms: new Date(row.agent_valid_from).getTime(),
    cert_fingerprint_hex: String(row.cert_fingerprint),
    identity_tier: String(row.identity_tier || '').toUpperCase(),
    sig_form_version: 3,
    nonce_hex: String(row.nonce || '').toLowerCase(),
    ts_signed_unix_seconds: signedTs,
    signed_method: String(body.signed_method || ''),
    signed_path: String(body.signed_path || ''),
    request_body_hash_hex: Buffer.from(row.prov_content_hash || []).toString('hex'),
    request_receipt_present: Number(body.request_receipt_present),
    request_receipt_mutation_hash_hex: String(body.request_receipt_mutation_hash_hex || ''),
    authorization_event_present: Number(body.authorization_event_present),
    authorization_event_id: String(body.authorization_event_id || ''),
  };
  let commitment;
  try { commitment = computeOccurrenceCommitmentV3(expectedRecord); }
  catch { return { valid: false, reason: 'occurrence_v3_encoding_invalid' }; }
  const exactBody = body.occurrence_commitment === commitment
    && Object.entries(expectedRecord).every(([key, value]) => body[key] === value);
  if (!exactBody || commitment !== Buffer.from(row.mutation_hash || []).toString('hex')) {
    return { valid: false, reason: 'occurrence_v3_commitment_mismatch' };
  }
  if (!verifyOccurrenceSignatureV3(expectedRecord, row.sig, row.signer_pubkey)) {
    return { valid: false, reason: 'occurrence_v3_signature_invalid' };
  }
  const liveFields = {
    key: row.live_key,
    value: row.live_value,
    scope: row.live_scope,
    memory_type: row.live_memory_type,
    clearance_level: row.live_clearance_level,
    data_class: row.live_data_class,
    source: row.live_source,
  };
  if (!verifyLiveRowContentHash(liveFields, Buffer.from(row.live_content_hash || []))
      || !buffersEqual(row.live_content_hash, row.snapshot_live_content_hash)) {
    return { valid: false, reason: 'occurrence_v3_live_content_mismatch' };
  }
  return { valid: true, reason: null, record: expectedRecord, commitment };
}

/**
 * Verify the three-way origin-time binding introduced by provenance schema v4.
 * The signed body, provenance projection, and canonical memory row must carry
 * the same database-issued Unix millisecond. Older binding versions have no
 * v4 time claim and therefore remain valid historical evidence.
 */
export function verifyMemoryOriginBindingV4({
  bindingSchemaVersion,
  eventType,
  body,
  memoryOriginatedAt,
  liveCreatedAt,
} = {}) {
  if (Number(bindingSchemaVersion) !== 4) return { valid: true, reason: null };
  if (eventType !== 'BIND' || !body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, reason: 'memory_origin_time_binding_invalid' };
  }
  const bodyUnixMs = body.memory_originated_at_unix_ms;
  const provenanceUnixMs = new Date(memoryOriginatedAt).getTime();
  const liveUnixMs = new Date(liveCreatedAt).getTime();
  const valid = Number.isSafeInteger(bodyUnixMs)
    && bodyUnixMs > 0
    && Number.isSafeInteger(provenanceUnixMs)
    && provenanceUnixMs > 0
    && Number.isSafeInteger(liveUnixMs)
    && liveUnixMs > 0
    && bodyUnixMs === provenanceUnixMs
    && provenanceUnixMs === liveUnixMs;
  return valid
    ? { valid: true, reason: null, unixMs: liveUnixMs }
    : { valid: false, reason: 'memory_origin_time_binding_invalid' };
}

function parseJsonValue(value) {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string') return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function buffersEqual(a, b, bytes = HASH_BYTES) {
  try {
    const left = Buffer.from(a);
    const right = Buffer.from(b);
    return left.length === bytes && right.length === bytes && left.equals(right);
  } catch {
    return false;
  }
}

/**
 * Reconstruct one retained provenance stream from its signed hash links.
 * Timestamps are evidence fields, never chain-order authority: PostgreSQL
 * transaction timestamps can run opposite to lock/commit order.
 */
export function orderProvenanceRowsByTopology(rows = []) {
  if (!Array.isArray(rows) || rows.length === 0) return [];
  const byMutation = new Map();
  const successorByPrev = new Map();
  const genesis = [];
  for (const row of rows) {
    const mutation = Buffer.from(row.mutation_hash || []);
    const previous = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
    if (mutation.length !== HASH_BYTES || (previous && previous.length !== HASH_BYTES)) {
      throw new Error('provenance_topology_hash_invalid');
    }
    const mutationHex = mutation.toString('hex');
    const previousHex = previous?.toString('hex') || null;
    if (byMutation.has(mutationHex)) throw new Error('provenance_topology_duplicate_mutation');
    if (previousHex && successorByPrev.has(previousHex)) throw new Error('provenance_topology_fork');
    byMutation.set(mutationHex, row);
    if (previousHex) successorByPrev.set(previousHex, mutationHex);
    else genesis.push(mutationHex);
  }
  if (genesis.length !== 1) throw new Error('provenance_topology_genesis_invalid');
  const ordered = [];
  const visited = new Set();
  let cursor = genesis[0];
  while (cursor) {
    if (visited.has(cursor) || !byMutation.has(cursor)) {
      throw new Error('provenance_topology_cycle_or_missing_link');
    }
    visited.add(cursor);
    ordered.push(byMutation.get(cursor));
    cursor = successorByPrev.get(cursor) || null;
  }
  if (visited.size !== rows.length) throw new Error('provenance_topology_disconnected');
  return ordered;
}

function parseCertificateBody(certString) {
  try {
    const envelope = JSON.parse(Buffer.from(String(certString), 'base64url').toString('utf8'));
    return envelope?.body || null;
  } catch {
    return null;
  }
}

function normalizeSignedSessionOptionalText(value) {
  if (value == null) return null;
  const text = String(value).trim();
  return text || null;
}

function normalizeSignedSessionImageContext(value) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > 16) return null;
  const normalized = [];
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
      || Object.keys(entry).some((key) => !['url', 'caption', 'query'].includes(key))) {
      return null;
    }
    const url = normalizeSignedSessionOptionalText(entry.url);
    const caption = normalizeSignedSessionOptionalText(entry.caption);
    const query = normalizeSignedSessionOptionalText(entry.query);
    if (!url && !caption && !query) return null;
    normalized.push({
      ...(url ? { url } : {}),
      ...(caption ? { caption } : {}),
      ...(query ? { query } : {}),
    });
  }
  return normalized;
}

function signedSessionTurnIntent(body, row) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const sessionId = String(body.session_id ?? '').trim();
  const turnId = String(body.turn_id ?? '');
  const role = String(body.role ?? '').trim().toLowerCase();
  const content = String(body.content ?? '');
  const observed = new Date(body.observed_at);
  const imageContext = normalizeSignedSessionImageContext(body.image_context);
  if (!sessionId || !turnId.trim() || !content.trim()
    || !['user', 'assistant', 'system', 'tool'].includes(role)
    || Number.isNaN(observed.getTime())
    || imageContext == null) {
    return null;
  }

  const prefix = `sess:${sessionId}:`;
  const liveKey = String(row.live_key || '');
  if (!liveKey.startsWith(prefix)) return null;
  const keyMatch = liveKey.slice(prefix.length).match(/^turn:(\d{12}):([0-9a-f]{64})$/);
  if (!keyMatch) return null;
  const sequence = Number(keyMatch[1]);
  const turnIdHash = createHash('sha256').update(Buffer.from(turnId, 'utf8')).digest('hex');
  if (!Number.isSafeInteger(sequence) || sequence < 1 || keyMatch[2] !== turnIdHash) return null;

  const sourceRef = normalizeSignedSessionOptionalText(body.source_ref);
  const speaker = normalizeSignedSessionOptionalText(body.speaker);
  const record = {
    schema: 'aimos.session-turn/v1',
    session_id: sessionId,
    sequence,
    turn_id_sha256: turnIdHash,
    role,
    observed_at: observed.toISOString(),
    source_ref: sourceRef,
    content,
    ...(speaker ? { speaker } : {}),
    ...(imageContext.length ? { image_context: imageContext } : {}),
  };
  const value = canonicalJson(record);
  const clearanceLevel = Number(body.clearance_level ?? 1);
  const companyId = String(body.company_id ?? 'hom');
  const claimedAgentId = body.agent_id == null || body.agent_id === ''
    ? String(row.provenance_agent_id || '')
    : String(body.agent_id);
  const exactDerivedWrite = value === String(row.live_value ?? '')
    && Number(row.live_clearance_level) === clearanceLevel
    && String(row.live_company_id ?? '') === companyId
    && String(row.live_agent_id ?? '') === claimedAgentId
    && String(row.provenance_agent_id ?? '') === claimedAgentId;
  if (!exactDerivedWrite) return null;

  return {
    company_id: companyId,
    agent_id: claimedAgentId,
    key: liveKey,
    value,
  };
}

function signedSaveIntent(body, row) {
  const signedPath = String(row.signed_path || '');
  if (signedPath === '/aimos/save' || !signedPath) return body;
  if (signedPath === '/aimos/session/turn') return signedSessionTurnIntent(body, row);
  if (signedPath === '/aimos/mcp/tools/call') {
    return body?.name === 'aimos_save' ? parseJsonObject(body.arguments) : null;
  }
  if (signedPath !== '/mcp') return null;
  const requests = Array.isArray(body) ? body : [body];
  const matching = requests
    .filter((rpc) => rpc?.method === 'tools/call' && rpc?.params?.name === 'aimos_save')
    .map((rpc) => parseJsonObject(rpc.params?.arguments))
    .filter(Boolean)
    .filter((intent) => String(intent.key ?? '') === String(row.live_key ?? '')
      && signedMemoryValueMatchesRetained(intent.value, row.live_value));
  return matching.length === 1 ? matching[0] : null;
}

/**
 * Verify one retained SAVE provenance row as portable recall evidence.
 * Request freshness is intentionally not re-applied: this verifies the exact
 * historical bytes stored at save time. Revocation also does not invalidate a
 * signature that was valid before the terminal revocation event.
 */
export function verifyRecallEvidenceRow(row = {}) {
  const body = parseJsonValue(row.body_json);
  if (!body) return { valid: false, reason: 'signed_body_missing' };
  if (!row.signer_pubkey || !row.signer_cert || !row.agent_valid_from) {
    return { valid: false, reason: 'signer_epoch_missing' };
  }
  if (!Buffer.isBuffer(row.sig) || row.sig.length !== 64) {
    return { valid: false, reason: 'signature_missing' };
  }

  const canonicalContentHash = contentHash(body);
  if (!buffersEqual(canonicalContentHash, row.prov_content_hash)) {
    return { valid: false, reason: 'signed_body_content_hash_mismatch' };
  }
  const certificateFingerprint = createHash('sha256')
    .update(String(row.signer_cert), 'utf8')
    .digest('hex');
  if (certificateFingerprint !== row.cert_fingerprint) {
    return { valid: false, reason: 'signer_certificate_fingerprint_mismatch' };
  }

  const signedTs = Number(row.ts_signed);
  const nonce = String(row.nonce || '');
  const sigB64u = Buffer.from(row.sig).toString('base64url');
  const certBody = parseCertificateBody(row.signer_cert);
  if (!certBody) return { valid: false, reason: 'signer_certificate_malformed' };
  const certAuthorityPubkey = resolveCertificateAuthorityPubkey({
    certificateBody: certBody,
    subjectPubkey: row.signer_pubkey,
    masterPubkey: row.master_pubkey,
    masterFingerprint: row.master_fingerprint,
  });
  if (!certAuthorityPubkey) return { valid: false, reason: 'certificate_authority_missing' };
  const certVerification = verifyCertChain(row.signer_cert, certAuthorityPubkey, {
    nowFn: () => signedTs,
  });
  const validFromUnix = Math.floor(new Date(row.agent_valid_from).getTime() / 1000);
  const validUntilUnix = Math.floor(new Date(row.signer_valid_until).getTime() / 1000);
  if (!certVerification.valid
    || certBody.agent_id !== row.provenance_agent_id
    || certBody.pubkey !== row.signer_pubkey
    || certBody.device_fp !== row.signer_device_fp
    || Number(certBody.valid_from) !== validFromUnix
    || Number(certBody.valid_until) !== validUntilUnix) {
    return { valid: false, reason: certVerification.reason || 'signer_certificate_row_mismatch' };
  }
  if (row.revocation_sig) {
    const revocation = verifyAgentRevocationProof({
      agent_id: row.provenance_agent_id,
      agent_valid_from: row.agent_valid_from,
      master_fingerprint: row.revocation_master_fingerprint,
      target_cert_hash: row.revocation_target_cert_hash,
      prior_identity_hash: row.revocation_prior_identity_hash,
      signed_body: row.revocation_signed_body,
      content_hash: row.revocation_content_hash,
      mutation_hash: row.revocation_mutation_hash,
      ts_signed: row.revocation_ts_signed,
      nonce: row.revocation_nonce,
      sig: row.revocation_sig,
    }, row.master_pubkey, row.signer_cert);
    if (!revocation.valid) return { valid: false, reason: `revocation_${revocation.reason}` };
    if (Number(row.revocation_ts_signed) <= signedTs) {
      return { valid: false, reason: 'signer_revoked_before_evidence' };
    }
  }
  const provenanceSigForm = Number(row.sig_form_version || 1);
  const requestSigForm = Number(row.request_sig_form || 1);
  const signedClaims = parseJsonObject(row.signed_claims);
  if (Boolean(row.is_genesis) !== (row.prev_mutation_hash == null)) {
    return { valid: false, reason: 'provenance_genesis_shape_invalid' };
  }
  if (['T2', 'T3'].includes(String(row.identity_tier)) && requestSigForm !== 4) {
    return { valid: false, reason: 'elevated_provenance_requires_form4' };
  }
  if (requestSigForm === 4) {
    const prevClaim = signedClaims?.prev_chain_hash;
    let prevBytes = null;
    try { prevBytes = Buffer.from(String(prevClaim || ''), 'base64url'); } catch { /* malformed below */ }
    if (!prevBytes || prevBytes.length !== 32) return { valid: false, reason: 'signed_chain_claim_invalid' };
    if (String(row.identity_tier) === 'T3' && signedClaims?.device_fp !== row.signer_device_fp) {
      return { valid: false, reason: 'signed_device_claim_mismatch' };
    }
  }
  let signature;
  if (provenanceSigForm === 2) {
    const originatedAt = row.memory_originated_at
      ? Math.floor(new Date(row.memory_originated_at).getTime() / 1000)
      : NaN;
    signature = verifyStoredPayloadSigV2(
      row.signer_pubkey, body, nonce, signedTs, originatedAt, sigB64u,
    );
  } else if (requestSigForm === 4) {
    signature = verifyStoredPayloadSigWithEnvelopeClaims(
      row.signer_pubkey,
      body,
      row.signed_method,
      row.signed_path,
      signedClaims,
      nonce,
      signedTs,
      sigB64u,
    );
  } else if (requestSigForm === 3) {
    signature = verifyStoredPayloadSigWithContext(
      row.signer_pubkey,
      body,
      row.signed_method,
      row.signed_path,
      nonce,
      signedTs,
      sigB64u,
    );
  } else if (requestSigForm === 1) {
    signature = verifyStoredPayloadSig(row.signer_pubkey, body, nonce, signedTs, sigB64u);
  } else {
    return { valid: false, reason: 'request_signature_form_invalid' };
  }
  if (!signature?.valid) return { valid: false, reason: signature?.reason || 'signature_invalid' };

  const prev = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
  const mutationOk = provenanceSigForm === 2
    ? verifyMutationHashV2(
        canonicalContentHash,
        prev,
        nonce,
        signedTs,
        Math.floor(new Date(row.memory_originated_at).getTime() / 1000),
        Buffer.from(row.mutation_hash),
      )
    : verifyMutationHash(
        canonicalContentHash,
        prev,
        nonce,
        signedTs,
        Buffer.from(row.mutation_hash),
      );
  if (!mutationOk) return { valid: false, reason: 'mutation_hash_mismatch' };

  const eventType = String(row.event_type || 'SAVE');
  const contentBindingEvent = ['SAVE', 'BIND', 'RETAINED_ATTEST'].includes(eventType);
  if (contentBindingEvent && (row.live_content_hash == null || row.snapshot_live_content_hash == null)) {
    return { valid: false, reason: 'live_content_hash_unattested' };
  }
  const liveFields = {
    key: row.live_key,
    value: row.live_value,
    scope: row.live_scope,
    memory_type: row.live_memory_type,
    clearance_level: row.live_clearance_level,
    data_class: row.live_data_class,
    source: row.live_source,
  };
  if (contentBindingEvent && !verifyLiveRowContentHash(liveFields, Buffer.from(row.live_content_hash))) {
    return { valid: false, reason: 'live_row_content_hash_mismatch' };
  }
  if (contentBindingEvent && !buffersEqual(row.live_content_hash, row.snapshot_live_content_hash)) {
    return { valid: false, reason: 'live_row_snapshot_mismatch' };
  }

  // SAVE and BIND prove different facts and must not be conflated:
  //
  // - SAVE is the caller's signed intent. The native write path may
  //   deterministically reclassify scope/type/source after that signature
  //   (quarantine classification and degraded-embedding provenance are two
  //   examples), so those normalized fields cannot be required to equal the
  //   pre-normalization request bytes.
  // - BIND is the atomic housekeeper receipt over the database-generated UUID
  //   and canonical live-content hash. The full-chain verifier below also
  //   binds it to the exact SAVE hashes and signer epoch.
  //
  // The live hash still covers key, value, normalized scope, type, clearance,
  // data class, and source. Relaxing SAVE classification equality therefore
  // does not relax exact-row integrity; it restores the correct two-proof
  // model for a server-normalized write.
  const intentBody = eventType === 'SAVE' ? signedSaveIntent(body, row) : body;
  if (eventType === 'SAVE' && !intentBody) {
    return { valid: false, reason: 'signed_save_intent_missing_or_ambiguous' };
  }
  const requiredBindings = eventType === 'SAVE'
    ? [
        ['key', row.live_key],
        ['value', row.live_value],
      ]
    : eventType === 'BIND' || eventType === 'RETAINED_ATTEST'
      ? [
          ['memory_id', row.memory_id],
          ['company_id', row.live_company_id],
          ['subject_agent_id', row.live_agent_id],
          ['key', row.live_key],
          ['live_content_hash', Buffer.from(row.live_content_hash).toString('hex')],
        ]
      : [];
  for (const [field, expected] of requiredBindings) {
    const bindingBody = intentBody;
    const bindingFailure = !Object.hasOwn(bindingBody, field)
      ? `signed_body_${field}_missing`
      : field === 'value'
        ? signedMemoryValueMatchesRetained(bindingBody[field], expected)
          ? null
          : `signed_body_${field}_mismatch`
        : String(bindingBody[field] ?? '') === String(expected ?? '')
        ? null
        : `signed_body_${field}_mismatch`;
    if (bindingFailure) return { valid: false, reason: bindingFailure };
  }
  if (eventType === 'SAVE') {
    if (Object.hasOwn(intentBody, 'company_id')
      && String(intentBody.company_id) !== String(row.live_company_id)) {
      return { valid: false, reason: 'signed_body_company_id_mismatch' };
    }
    const subjectField = Object.hasOwn(intentBody, 'subject_agent_id')
      ? 'subject_agent_id'
      : Object.hasOwn(intentBody, 'agent_id')
        ? 'agent_id'
        : null;
    if (subjectField && String(intentBody[subjectField]) !== String(row.live_agent_id)) {
      return { valid: false, reason: `signed_body_${subjectField}_mismatch` };
    }
  }
  if (Object.hasOwn(body, 'event_type') && body.event_type !== eventType) {
    return { valid: false, reason: 'signed_body_event_type_mismatch' };
  }

  return {
    valid: true,
    reason: null,
    proof: {
      memory_id: row.memory_id,
      provenance_id: row.provenance_id,
      content_hash: canonicalContentHash.toString('hex'),
      mutation_hash: Buffer.from(row.mutation_hash).toString('hex'),
      live_content_hash: row.live_content_hash ? Buffer.from(row.live_content_hash).toString('hex') : null,
      signer_agent_id: row.provenance_agent_id,
      signer_valid_from: new Date(row.agent_valid_from).toISOString(),
      cert_fingerprint: row.cert_fingerprint,
      request_sig_form: requestSigForm,
      version_status: row.has_successor ? 'historical' : 'current',
      supersedes_id: row.supersedes_id || null,
    },
  };
}

// A retained pre-portable node may lack the signed body required to re-verify
// its original signature. A later v3 housekeeper BIND may attest the exact
// retained bytes only when this historical mutation link still recomputes.
// This proves retained existence/continuity, not authenticity at origin.
export function verifyRetainedMutationNode(row = {}) {
  const content = Buffer.from(row.prov_content_hash || []);
  const mutation = Buffer.from(row.mutation_hash || []);
  const previous = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
  const nonce = String(row.nonce || '');
  const signedTs = Number(row.ts_signed);
  if (content.length !== 32 || mutation.length !== 32 || (previous && previous.length !== 32)) {
    return { valid: false, reason: 'retained_mutation_hash_shape_invalid' };
  }
  if (!nonce || !Number.isInteger(signedTs) || signedTs <= 0) {
    return { valid: false, reason: 'retained_mutation_link_input_missing' };
  }
  if (Boolean(row.is_genesis) !== (previous == null)) {
    return { valid: false, reason: 'retained_mutation_genesis_shape_invalid' };
  }
  const sigForm = Number(row.sig_form_version || 1);
  const valid = sigForm === 2
    ? row.memory_originated_at != null && verifyMutationHashV2(
        content,
        previous,
        nonce,
        signedTs,
        Math.floor(new Date(row.memory_originated_at).getTime() / 1000),
        mutation,
      )
    : sigForm === 1 && verifyMutationHash(content, previous, nonce, signedTs, mutation);
  return valid
    ? { valid: true, reason: null }
    : { valid: false, reason: 'retained_mutation_hash_mismatch' };
}

export function createMemoryProvenanceLedger(deps = {}) {
  const pool = deps.pool || defaultPool;
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));

  // R3 Step 4: when an injected transaction client is present, read/write on it
  // so the provenance chain-tip lookup sees rows written earlier in the same
  // transaction and the INSERT rolls back with the memory row on failure.
  function runner(client) {
    return client ? ((sql, params = []) => client.query(sql, params)) : queryFn;
  }

  // R3 Step 5: aimos_memory_provenance.agent_valid_from is added by migration 040
  // (composite FK to agent_identity(agent_id, valid_from)). This process may boot
  // against a DB that has not applied 040 yet, so probe once and only reference
  // the column when it exists. Cached for the lifetime of the process.
  let _agentValidFromColumn; // undefined = unprobed, true/false = known
  async function hasAgentValidFromColumn(run) {
    if (_agentValidFromColumn !== undefined) return _agentValidFromColumn;
    try {
      const r = await run(
        `SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'aimos_memory_provenance'
            AND column_name = 'agent_valid_from'
          LIMIT 1`
      );
      _agentValidFromColumn = !!(r && Array.isArray(r.rows) && r.rows.length > 0);
    } catch {
      _agentValidFromColumn = false;
    }
    return _agentValidFromColumn;
  }

  async function getLatestOccurrenceReference(memoryId, companyId, client) {
    const run = runner(client);
    const result = await run(
      `SELECT provenance_id, memory_id, agent_id, agent_id AS provenance_agent_id,
              agent_valid_from, cert_fingerprint, mutation_hash,
              prev_mutation_hash, event_type, sig_form_version
         FROM aimos_memory_provenance
        WHERE memory_id = $1`,
      [memoryId],
    );
    const ordered = orderProvenanceRowsByOccurrenceTopology(result.rows || [], companyId);
    if (!ordered.length) return null;
    return occurrenceReferenceForProvenanceRow(ordered[ordered.length - 1], companyId);
  }

  async function getLatestMutationHash(memoryId, client) {
    const run = runner(client);
    const legacyTopology = await run(
      `SELECT mutation_hash
         FROM (
           SELECT candidate.mutation_hash
             FROM aimos_memory_provenance candidate
            WHERE candidate.memory_id = $1
              AND NOT EXISTS (
                SELECT 1
                  FROM aimos_memory_provenance successor
                 WHERE successor.memory_id = candidate.memory_id
                   AND successor.prev_mutation_hash = candidate.mutation_hash
              )
            ORDER BY encode(candidate.mutation_hash, 'hex')
            LIMIT 2
         ) topology_heads`,
      [memoryId],
    );
    if (!legacyTopology || !Array.isArray(legacyTopology.rows)) {
      throw new Error('provenance_topology_read_invalid');
    }
    if (legacyTopology.rows.length === 0) return { prevMutationHash: null, isGenesis: true };
    if (legacyTopology.rows.length === 1) {
      return { prevMutationHash: legacyTopology.rows[0].mutation_hash, isGenesis: false };
    }
    // A mixed v1/v2/v3 stream has two apparent heads under the legacy hash
    // namespace because the first v3 predecessor is a derived occurrence
    // reference. Resolve it only then; the unchanged legacy hot path remains
    // one indexed query.
    const memory = await run('SELECT company_id FROM aimos_memories WHERE id = $1', [memoryId]);
    if (!memory?.rows?.[0]) throw new Error('provenance_memory_missing');
    const latest = await getLatestOccurrenceReference(
      memoryId,
      memory.rows[0].company_id,
      client,
    );
    if (!latest) throw new Error('provenance_occurrence_topology_no_head');
    return { prevMutationHash: Buffer.from(latest, 'hex'), isGenesis: false };
  }

  function _validate(args) {
    const {
      memoryId, body, signedTs, nonce, sigBytes, identityTier, eventType,
      requestSigForm = 1, signedMethod = null, signedPath = null, signedClaims = null,
    } = args;
    if (typeof memoryId !== 'string' || memoryId.length === 0) return 'malformed_input';
    if (body === null || body === undefined || typeof body !== 'object') return 'malformed_input';
    if (!Number.isInteger(signedTs) || signedTs <= 0) return 'malformed_input';
    if (typeof nonce !== 'string' || nonce.length === 0) return 'malformed_input';
    if (!Buffer.isBuffer(sigBytes) || sigBytes.length !== 64) return 'malformed_input';
    if (identityTier !== 'T1' && identityTier !== 'T2' && identityTier !== 'T3') return 'malformed_input';
    if (![1, 3, 4].includes(requestSigForm)) return 'malformed_input';
    if (requestSigForm === 1 && (signedMethod !== null || signedPath !== null || signedClaims !== null)) return 'malformed_input';
    if (requestSigForm === 3 && (!signedMethod || !signedPath || signedClaims !== null)) return 'malformed_input';
    if (requestSigForm === 4 && (!signedMethod || !signedPath || !signedClaims?.prev_chain_hash)) return 'malformed_input';
    // BIND is the housekeeper commit receipt that cryptographically attaches a
    // request signature to the database-generated memory id and live snapshot.
    // Default 'SAVE' (backward compat with /save path which passes no eventType).
    if (eventType !== undefined && eventType !== null) {
      if (typeof eventType !== 'string' || !['SAVE', 'BIND', 'RETAINED_ATTEST', 'CONSOLIDATE', 'REWEIGHT'].includes(eventType)) {
        return 'malformed_input';
      }
    }
    return null;
  }

  async function _insert(client, fields) {
    const {
      provenanceId = null,
      memoryId, agentId, agentValidFrom, certFingerprint, cHash,
      mutationHash, prevMutationHash, signedTs, nonce, sigBytes,
      identityTier, isGenesis, eventType, bodyJson, liveContentHash,
      bindingSchemaVersion, memoryOriginatedAt,
      requestSigForm, signedMethod, signedPath, signedClaims,
      sigFormVersion = 1,
    } = fields;
    // R3 Step 5: bind to the identity EPOCH (agent_id, agent_valid_from) when the
    // column exists. A NULL agent_valid_from leaves the composite FK unchecked
    // (MATCH SIMPLE) — correct for P-anchor/system rows that have no epoch — while
    // a non-NULL value is enforced against agent_identity(agent_id, valid_from).
    const includeEpoch = await hasAgentValidFromColumn((sql, params = []) => client.query(sql, params));
    const validFromValue = agentValidFrom || null;
    if (includeEpoch) {
      await client.query(
        `INSERT INTO aimos_memory_provenance
            (provenance_id, memory_id, agent_id, agent_valid_from, cert_fingerprint, content_hash,
             mutation_hash, prev_mutation_hash, ts_signed, nonce, sig,
             identity_tier, is_genesis, backfilled,
             event_type, body_json, live_content_hash, binding_schema_version,
             memory_originated_at, request_sig_form, signed_method, signed_path, signed_claims,
             sig_form_version)
         VALUES (COALESCE($18::uuid, gen_random_uuid()), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, false, $13, $14, $15, $16, $17, $20, $21, $22, $23, $19)`,
        [
          memoryId, agentId, validFromValue, certFingerprint, cHash,
          mutationHash, prevMutationHash, signedTs, nonce, sigBytes,
          identityTier, isGenesis,
          eventType || 'SAVE',
          bodyJson != null ? JSON.stringify(bodyJson) : null,
          liveContentHash || null,
          bindingSchemaVersion, memoryOriginatedAt || null,
          provenanceId,
          Number(sigFormVersion),
          requestSigForm, signedMethod, signedPath,
          signedClaims ? JSON.stringify(signedClaims) : null,
        ]
      );
    } else {
      await client.query(
        `INSERT INTO aimos_memory_provenance
            (provenance_id, memory_id, agent_id, cert_fingerprint, content_hash,
             mutation_hash, prev_mutation_hash, ts_signed, nonce, sig,
             identity_tier, is_genesis, backfilled,
             event_type, body_json, live_content_hash, binding_schema_version,
             memory_originated_at, request_sig_form, signed_method, signed_path, signed_claims,
             sig_form_version)
         VALUES (COALESCE($17::uuid, gen_random_uuid()), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, $12, $13, $14, $15, $16, $19, $20, $21, $22, $18)`,
        [
          memoryId, agentId, certFingerprint, cHash,
          mutationHash, prevMutationHash, signedTs, nonce, sigBytes,
          identityTier, isGenesis,
          eventType || 'SAVE',                           // default SAVE (backward compat)
          bodyJson != null ? JSON.stringify(bodyJson) : null,
          liveContentHash || null,                      // Phase 9b snapshot (NULL for REWEIGHT/backfill)
          bindingSchemaVersion, memoryOriginatedAt || null,
          provenanceId,
          Number(sigFormVersion),
          requestSigForm, signedMethod, signedPath,
          signedClaims ? JSON.stringify(signedClaims) : null,
        ]
      );
    }
  }

  // ─── commitProvenance ──────────────────────────────────────────────────────
  // Called AFTER persistMemory returned a memory_id. Writes one P-live row.
  // One in-call retry for the duplicate-genesis race (the other writer beat us
  // to genesis; we re-fetch as non-genesis and write the linker). Fork-race
  // (another writer beat us to the prev link) is unrecoverable in-call.
  async function commitProvenance({
    memoryId,
    body,
    agentId,
    validFromIso,
    certString,
    signedTs,
    nonce,
    sigBytes,
    identityTier,
    requestSigForm = 1,
    signedMethod = null,
    signedPath = null,
    signedClaims = null,
    eventType,        // Aimos-2 extension (§11.1): 'SAVE' (default) | 'CONSOLIDATE' | 'REWEIGHT'
    bodyJson,         // Optional: persist the full body for auditability (REWEIGHT bodies
                      // not reconstructable from aimos_memories). NULL for backfilled rows.
    liveContentHash,  // Phase 9b: append-only snapshot of aimos_memories.content_hash at
                      // save time. Buffer (32 bytes) or NULL. NULL for REWEIGHT/governor
                      // mutations (canonical subset unchanged) + backfilled rows.
    memoryOriginatedAt = null,
    bindingSchemaVersion = 2,
    client            // R3 Step 4: injected pg client already inside an open txn.
                      // When present, the provenance row is written on THAT txn so
                      // it commits/rolls back atomically with the memory row. No
                      // self-managed BEGIN/COMMIT and no genesis-race retry (a
                      // brand-new memory_id has no concurrent writer); a unique
                      // violation surfaces as ok:false and the caller rolls back.
  }) {
    // Authentication distinguishes the bootstrap housekeeper as
    // T1_SYSTEM_SELF. The persisted provenance ontology intentionally records
    // signer classes T1/T2/T3, so the native ledger owns the one semantic
    // conversion. Callers must pass the verified authentication tier unchanged.
    const storedIdentityTier = identityTier === 'T1_SYSTEM_SELF' ? 'T1' : identityTier;
    const bad = _validate({
      memoryId,
      body,
      signedTs,
      nonce,
      sigBytes,
      identityTier: storedIdentityTier,
      eventType,
      requestSigForm,
      signedMethod,
      signedPath,
      signedClaims,
    });
    if (bad) return { ok: false, reason: bad };
    if (![1, 2, 3, 4].includes(Number(bindingSchemaVersion))) return { ok: false, reason: 'malformed_input' };
    if (Number(bindingSchemaVersion) === 4) {
      const originatedAtUnixMs = new Date(memoryOriginatedAt).getTime();
      if (eventType !== 'BIND'
        || !Number.isSafeInteger(originatedAtUnixMs)
        || originatedAtUnixMs <= 0
        || !Number.isSafeInteger(body?.memory_originated_at_unix_ms)
        || body.memory_originated_at_unix_ms !== originatedAtUnixMs) {
        return { ok: false, reason: 'memory_origin_time_binding_invalid' };
      }
    }

    const cHash = contentHash(body);
    const certFingerprint = createHash('sha256')
      .update(String(certString || ''), 'utf8')
      .digest('hex');
    // R3 Step 5: bind the provenance row to the signing identity's epoch. This is
    // the exact value the envelope ledger stores in oracle_save_envelope
    // .agent_valid_from and validates against agent_identity(agent_id, valid_from).
    const agentValidFrom = (typeof validFromIso === 'string' && validFromIso.length > 0)
      ? validFromIso
      : null;

    // ─── R3 Step 4: injected-transaction path (atomic with the memory row) ─────
    if (client) {
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`memory-provenance:${memoryId}`]
      );
      const { prevMutationHash, isGenesis } = await getLatestMutationHash(memoryId, client);
      const mutationHash = computeMutationHash(cHash, prevMutationHash, nonce, signedTs);
      try {
        await _insert(client, {
          memoryId, agentId, agentValidFrom, certFingerprint, cHash,
          mutationHash, prevMutationHash, signedTs, nonce, sigBytes,
          identityTier: storedIdentityTier, isGenesis, eventType, bodyJson, liveContentHash,
          bindingSchemaVersion: Number(bindingSchemaVersion), memoryOriginatedAt,
          requestSigForm, signedMethod, signedPath, signedClaims,
        });
        // No COMMIT here — the caller's withTransaction owns the boundary.
        return { ok: true, contentHash: cHash, mutationHash, prevMutationHash, isGenesis };
      } catch (err) {
        // Do NOT swallow: the injected transaction is now aborted and the caller
        // must roll it back. Map the known unique-violations to reasons; rethrow
        // anything else so the atomic save fails loudly.
        if (err.code === '23505' && err.constraint === 'aimos_memory_provenance_one_genesis') {
          return { ok: false, reason: 'duplicate_genesis' };
        }
        if (err.code === '23505' && err.constraint === 'aimos_memory_provenance_next_unique') {
          return { ok: false, reason: 'fork_race', currentPrev: prevMutationHash };
        }
        throw err;
      }
    }

    // ─── self-managed path (no injected client) ──────────────────────────────
    // The provenance owner acquires its stream lock before resolving the head;
    // a caller cannot race between predecessor selection and append.
    const conn = await pool.connect();
    try {
      await conn.query('BEGIN');
      await conn.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`memory-provenance:${memoryId}`]
      );
      const { prevMutationHash, isGenesis } = await getLatestMutationHash(memoryId, conn);
      const mutationHash = computeMutationHash(cHash, prevMutationHash, nonce, signedTs);
      await _insert(conn, {
        memoryId, agentId, agentValidFrom, certFingerprint, cHash,
        mutationHash, prevMutationHash, signedTs, nonce, sigBytes,
        identityTier: storedIdentityTier, isGenesis, eventType, bodyJson, liveContentHash,
        bindingSchemaVersion: Number(bindingSchemaVersion), memoryOriginatedAt,
        requestSigForm, signedMethod, signedPath, signedClaims,
      });
      await conn.query('COMMIT');
      return { ok: true, contentHash: cHash, mutationHash, prevMutationHash, isGenesis };
    } catch (err) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
      if (err.code === '23505' && err.constraint === 'aimos_memory_provenance_one_genesis') {
        return { ok: false, reason: 'duplicate_genesis' };
      }
      if (err.code === '23505' && err.constraint === 'aimos_memory_provenance_next_unique') {
        return { ok: false, reason: 'fork_race' };
      }
      throw err;
    } finally {
      conn.release();
    }
  }

  /**
   * Append one successor-form occurrence to an existing content state.
   * The caller pre-generates and signs the complete event, while this owner
   * serializes the stream and rechecks its predecessor inside the transaction.
   */
  async function commitOccurrenceV3({
    companyId,
    memoryId,
    record,
    signature,
    certString,
    liveContentHash,
    client = null,
  }) {
    const storedTier = record?.identity_tier === 'T1_SYSTEM_SELF' ? 'T1' : record?.identity_tier;
    const commitmentHex = computeOccurrenceCommitmentV3(record);
    const certificateBody = parseCertificateBody(certString);
    const certFingerprint = createHash('sha256').update(String(certString || ''), 'utf8').digest('hex');
    if (!certificateBody
        || String(record?.company_id) !== String(companyId)
        || String(record?.memory_id).toLowerCase() !== String(memoryId).toLowerCase()
        || String(record?.occurrence_event_id || '').length === 0
        || !['SAVE_REASSERT', 'INTERNAL_SAVE_REASSERT'].includes(String(record?.event_type))
        || Number(record?.sig_form_version) !== 3
        || record?.agent_id !== certificateBody.agent_id
        || Number(record?.signer_valid_from_unix_ms) !== new Date(
          Number(certificateBody.valid_from) < 10_000_000_000
            ? Number(certificateBody.valid_from) * 1000
            : Number(certificateBody.valid_from),
        ).getTime()
        || record?.cert_fingerprint_hex !== certFingerprint
        || !Buffer.isBuffer(signature)
        || signature.length !== 64
        || !verifyOccurrenceSignatureV3(record, signature, certificateBody.pubkey)
        || Buffer.from(String(record.live_content_hash_hex), 'hex').length !== HASH_BYTES
        || !Buffer.from(String(record.live_content_hash_hex), 'hex').equals(Buffer.from(liveContentHash || []))) {
      return { ok: false, reason: 'occurrence_v3_input_invalid' };
    }
    const ownsTransaction = !client;
    const conn = client || await pool.connect();
    try {
      if (ownsTransaction) await conn.query('BEGIN');
      await conn.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`memory-occurrence:${String(companyId).length}:${companyId}:${memoryId}`],
      );
      const signer = await conn.query(
        `SELECT identity.pubkey, identity.cert, identity.device_fp,
                master.master_pubkey, master.fingerprint AS master_fingerprint,
                revocation.ts_signed AS revocation_ts_signed
           FROM agent_identity identity
           LEFT JOIN aimos_master_identity master ON master.id = 1
           LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
          WHERE identity.agent_id = $1
            AND identity.valid_from = $2
            AND identity.cert = $3
          FOR SHARE OF identity`,
        [record.agent_id, new Date(Number(record.signer_valid_from_unix_ms)).toISOString(), certString],
      );
      const signerRow = signer.rows[0];
      const certAuthority = resolveCertificateAuthorityPubkey({
        certificateBody,
        subjectPubkey: signerRow?.pubkey,
        masterPubkey: signerRow?.master_pubkey,
        masterFingerprint: signerRow?.master_fingerprint,
      });
      const certificate = certAuthority
        ? verifyCertChain(certString, certAuthority, {
            nowFn: () => Number(record.ts_signed_unix_seconds),
          })
        : { valid: false };
      if (!signerRow
          || signerRow.revocation_ts_signed != null
          || signerRow.pubkey !== certificateBody.pubkey
          || !certificate.valid) {
        if (ownsTransaction) await conn.query('ROLLBACK');
        return { ok: false, reason: 'occurrence_v3_signer_epoch_invalid' };
      }
      const predecessor = await getLatestOccurrenceReference(memoryId, companyId, conn);
      const expectedPredecessor = record.predecessor_present === 1
        ? String(record.predecessor_commitment_hex || '').toLowerCase()
        : null;
      if (!predecessor || expectedPredecessor !== predecessor) {
        if (ownsTransaction) await conn.query('ROLLBACK');
        return { ok: false, reason: 'occurrence_v3_predecessor_mismatch', currentHead: predecessor };
      }
      await _insert(conn, {
        provenanceId: record.occurrence_event_id,
        memoryId,
        agentId: record.agent_id,
        agentValidFrom: new Date(Number(record.signer_valid_from_unix_ms)).toISOString(),
        certFingerprint,
        cHash: Buffer.from(record.request_body_hash_hex, 'hex'),
        mutationHash: Buffer.from(commitmentHex, 'hex'),
        prevMutationHash: Buffer.from(predecessor, 'hex'),
        signedTs: Number(record.ts_signed_unix_seconds),
        nonce: String(record.nonce_hex),
        sigBytes: signature,
        identityTier: storedTier,
        isGenesis: false,
        eventType: record.event_type,
        bodyJson: { ...record, schema: CONTENT_STATE_OCCURRENCE_V3.schema, occurrence_commitment: commitmentHex },
        liveContentHash: Buffer.from(liveContentHash),
        bindingSchemaVersion: 1,
        memoryOriginatedAt: null,
        requestSigForm: 1,
        signedMethod: null,
        signedPath: null,
        signedClaims: null,
        sigFormVersion: 3,
      });
      if (ownsTransaction) await conn.query('COMMIT');
      return {
        ok: true,
        provenanceId: record.occurrence_event_id,
        contentHash: Buffer.from(record.request_body_hash_hex, 'hex'),
        mutationHash: Buffer.from(commitmentHex, 'hex'),
        prevMutationHash: Buffer.from(predecessor, 'hex'),
        isGenesis: false,
        sigFormVersion: 3,
      };
    } catch (error) {
      if (ownsTransaction) {
        try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
      }
      if (error.code === '23505') {
        return { ok: false, reason: 'occurrence_v3_replay_or_fork' };
      }
      throw error;
    } finally {
      if (ownsTransaction) conn.release();
    }
  }

  async function getProvenanceRow(memoryId, mutationHash, { retry = 5, sleepMs = 50 } = {}) {
    if (!Buffer.isBuffer(mutationHash)) {
      throw new Error('getProvenanceRow: mutationHash must be Buffer');
    }
    for (let i = 0; i < retry; i++) {
      const r = await queryFn(
        `SELECT provenance_id, memory_id, agent_id, cert_fingerprint,
                content_hash, mutation_hash, prev_mutation_hash,
                ts_signed, nonce, sig, identity_tier, is_genesis,
                backfilled, memory_originated_at, legacy_envelope_sig,
                created_at
           FROM aimos_memory_provenance
          WHERE memory_id = $1 AND mutation_hash = $2`,
        [memoryId, mutationHash]
      );
      if (r && Array.isArray(r.rows) && r.rows.length > 0) {
        return r.rows[0];
      }
      await new Promise(res => setTimeout(res, sleepMs));
    }
    return null;
  }

  async function getProvenanceChain(memoryId) {
    const r = await queryFn(
      `SELECT p.provenance_id, p.memory_id, p.agent_id,
              p.agent_id AS provenance_agent_id, p.agent_valid_from,
              p.cert_fingerprint, p.content_hash, p.mutation_hash,
              p.prev_mutation_hash, p.ts_signed, p.nonce, p.sig,
              p.identity_tier, p.is_genesis, p.backfilled,
              p.memory_originated_at, p.legacy_envelope_sig,
              p.sig_form_version, p.event_type, p.created_at,
              m.company_id
         FROM aimos_memory_provenance p
         JOIN aimos_memories m ON m.id = p.memory_id
        WHERE p.memory_id = $1`,
      [memoryId]
    );
    return orderProvenanceRowsByOccurrenceTopology(
      r?.rows || [],
      r?.rows?.[0]?.company_id,
    );
  }

  // ─── Phase 8 + Phase 9a: /recall choke-point verify ───────────────────────
  // For each memory_id in the recall result set, fetch the latest provenance
  // row + run TWO integrity checks:
  //
  //   check 1 (Phase 8, provenance self-consistency): recompute mutation_hash
  //   from the stored content_hash in the provenance row (v1 or v2 based on
  //   sig_form_version) + compare to the stored mutation_hash. Mismatch → the
  //   provenance row itself was tampered.
  //
  //   check 2a (Phase 9a, live-row integrity): JOIN aimos_memories on
  //   memory_id, fetch the live row's {key, value, scope, memory_type,
  //   clearance_level, data_class, source} + its stored content_hash column.
  //   Recompute the live-row content_hash from those fields + compare to the
  //   stored content_hash on aimos_memories. Mismatch → the live row was
  //   tampered (someone UPDATEd value/key/scope/etc. without recomputing the
  //   hash). NULL stored content_hash → row predates migration 030; treat as
  //   `unhashed` (caller decides; default keep + log, NOT rejected).
  //
  //   Phase 9b (follow-up) will add check 2b: compare the stored live
  //   content_hash on aimos_memories to the live_content_hash snapshot on
  //   aimos_memory_provenance (append-only). That catches the sophisticated
  //   attacker who recomputes the stored hash after tampering. Phase 9a alone
  //   catches the primary attack (direct DB UPDATE of value without hash
  //   recompute).
  //
  // A row is `verified` only if BOTH checks pass (check 1 + check 2a, or
  // check 2a is N/A because the row is unhashed). Otherwise it goes to
  // `rejected` (enforce=true, caller drops) or `shadow` (enforce=false, caller
  // keeps + logs). `missing` = no provenance row. `unhashed` = live row has
  //   no content_hash column value (predates migration 030 — backfill pending).
  //
  // enforce=true: rejected rows go to `rejected` (caller drops them from the
  //   response + logs recall_sig_verify_rejected).
  // enforce=false (shadow): rejected rows go to `shadow` (caller keeps them
  //   in the response + logs recall_sig_verify_shadow).
  async function verifyRecallMemories({ memoryIds, enforce = false }) {
    if (!Array.isArray(memoryIds) || memoryIds.length === 0) {
      return { verified: new Set(), rejected: [], shadow: [], missing: [], unhashed: [] };
    }
    const r = await queryFn(
      `SELECT p.provenance_id,
              p.memory_id AS memory_id,
              p.agent_id,
              p.agent_id AS provenance_agent_id,
              p.agent_valid_from,
              p.cert_fingerprint,
              p.content_hash AS prov_content_hash,
              p.mutation_hash,
              p.prev_mutation_hash,
              p.ts_signed,
              p.nonce,
              p.event_type,
              p.identity_tier,
              p.body_json,
              p.sig_form_version,
              p.memory_originated_at,
              p.live_content_hash AS snapshot_live_content_hash,
              m.content_hash AS live_content_hash,
              m.company_id AS live_company_id,
              m.key AS live_key,
              m.value AS live_value,
              m.scope AS live_scope,
              m.memory_type AS live_memory_type,
              m.clearance_level AS live_clearance_level,
              m.data_class AS live_data_class,
              m.source AS live_source
         FROM aimos_memory_provenance p
         JOIN aimos_memories m ON m.id = p.memory_id
        WHERE p.memory_id = ANY($1::uuid[])`,
      [memoryIds]
    );
    const rows = (r && r.rows) || [];
    const verified = new Set();
    const rejected = [];
    const shadow = [];
    const missing = [];
    const unhashed = [];
    const rowsByMemory = new Map();
    for (const row of rows) {
      if (!rowsByMemory.has(row.memory_id)) rowsByMemory.set(row.memory_id, []);
      rowsByMemory.get(row.memory_id).push(row);
    }
    for (const memoryId of [...new Set(memoryIds)]) {
      const provenanceRows = rowsByMemory.get(memoryId) || [];
      if (!provenanceRows.length) {
        missing.push(memoryId);
        continue;
      }
      let row;
      try {
        row = orderProvenanceRowsByOccurrenceTopology(
          provenanceRows,
          provenanceRows[0].live_company_id,
        ).at(-1);
      } catch (error) {
        const entry = {
          memory_id: memoryId,
          reason: 'provenance_topology_invalid',
          detail: error.message,
        };
        if (enforce) rejected.push(entry);
        else shadow.push(entry);
        continue;
      }
      // ─── check 1: provenance self-consistency (Phase 8) ───
      const contentHashBuf = Buffer.from(row.prov_content_hash);
      const prevBuf = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
      const expectedBuf = Buffer.from(row.mutation_hash);
      const ts = Number(row.ts_signed);
      const nonce = String(row.nonce);
      let check1Ok = false;
      try {
        if (Number(row.sig_form_version) === 3) {
          const body = parseJsonObject(row.body_json);
          check1Ok = body?.occurrence_commitment === expectedBuf.toString('hex')
            && computeOccurrenceCommitmentV3(body) === expectedBuf.toString('hex');
        } else if (Number(row.sig_form_version) === 2) {
          const moaUnix = row.memory_originated_at
            ? Math.floor(new Date(row.memory_originated_at).getTime() / 1000)
            : 0;
          check1Ok = verifyMutationHashV2(contentHashBuf, prevBuf, nonce, ts, moaUnix, expectedBuf);
        } else {
          check1Ok = verifyMutationHash(contentHashBuf, prevBuf, nonce, ts, expectedBuf);
        }
      } catch {
        check1Ok = false;
      }
      // ─── check 2a: live-row content_hash (Phase 9a) ───
      // NULL live_content_hash = row predates migration 030; treat as
      // unhashed (not rejected). check 2a is N/A for these rows.
      let check2aOk = true; // default pass when N/A
      let isUnhashed = row.live_content_hash == null;
      if (!isUnhashed) {
        try {
          const liveFields = {
            key: row.live_key,
            value: row.live_value,
            scope: row.live_scope,
            memory_type: row.live_memory_type,
            clearance_level: row.live_clearance_level,
            data_class: row.live_data_class,
            source: row.live_source,
          };
          const expectedLiveBuf = Buffer.from(row.live_content_hash);
          check2aOk = verifyLiveRowContentHash(liveFields, expectedLiveBuf);
        } catch {
          check2aOk = false;
        }
      }
      // ─── check 2b: live_content_hash snapshot (Phase 9b) ───
      // Compares the stored live content_hash on aimos_memories (mutable —
      // recomputed on UPDATE) to the append-only snapshot on the latest
      // provenance row (immutable — Aladdin Law). Mismatch → the live row
      // was tampered AND the attacker recomputed the live hash (sophisticated
      // attack that bypasses check 2a). NULL snapshot = N/A (REWEIGHT,
      // governor mutation, or backfilled row) — not rejected.
      let check2bOk = true; // default pass when N/A
      let isSnapshotted = row.snapshot_live_content_hash != null;
      if (!isUnhashed && isSnapshotted) {
        try {
          const liveBuf = Buffer.from(row.live_content_hash);
          const snapshotBuf = Buffer.from(row.snapshot_live_content_hash);
          check2bOk = liveBuf.equals(snapshotBuf);
        } catch {
          check2bOk = false;
        }
      }
      const ok = check1Ok && check2aOk && check2bOk;
      if (ok) {
        verified.add(row.memory_id);
        if (isUnhashed) unhashed.push(row.memory_id);
      } else {
        const reason = !check1Ok
          ? 'mutation_hash_mismatch'
          : !check2aOk
            ? 'live_row_tampered'
            : 'live_row_tampered_sophisticated';
        const entry = {
          memory_id: row.memory_id,
          reason,
          sig_form_version: Number(row.sig_form_version) || 1,
        };
        if (enforce) rejected.push(entry);
        else shadow.push(entry);
      }
    }
    return { verified, rejected, shadow, missing, unhashed };
  }

  /**
   * Fail-closed evidence admission for the native recall authority. Unlike the
   * retained shadow verifier above, missing bodies, missing snapshots, unknown
   * signer epochs, and invalid Ed25519 signatures are all rejected.
   */
  async function verifyRecallEvidence({ memoryIds, client = null } = {}) {
    if (!Array.isArray(memoryIds) || memoryIds.length === 0) {
      return { verified: new Set(), proofs: new Map(), rejected: [] };
    }
    const uniqueIds = [...new Set(memoryIds.map((id) => String(id || '')).filter(Boolean))];
    const run = runner(client);
    const recallEvidenceSql = `SELECT
          m.id::text AS memory_id,
          m.company_id AS live_company_id,
          m.agent_id AS live_agent_id,
          m.key AS live_key,
          m.value AS live_value,
          m.scope AS live_scope,
          m.cube_scope AS live_cube_scope,
          m.memory_type AS live_memory_type,
          m.clearance_level AS live_clearance_level,
          m.data_class AS live_data_class,
          m.source AS live_source,
          m.content_hash AS live_content_hash,
          m.created_at AS live_created_at,
          m.supersedes_id,
          (SELECT count(*)::int FROM aimos_memories successor
            WHERE successor.company_id = m.company_id
              AND successor.key = m.key
              AND successor.supersedes_id = m.id) AS successor_count,
          (m.supersedes_id IS NULL OR EXISTS (
            SELECT 1 FROM aimos_memories predecessor
             WHERE predecessor.id = m.supersedes_id
               AND predecessor.company_id = m.company_id
               AND predecessor.key = m.key
          )) AS predecessor_valid,
          (SELECT count(*)::int FROM supersession_events se
            WHERE se.company_id = m.company_id
              AND se.post_memory_id = m.id
              AND se.prior_memory_id = m.supersedes_id) AS incoming_edge_count,
          (SELECT se.id FROM supersession_events se
            WHERE se.company_id = m.company_id
              AND se.post_memory_id = m.id
              AND se.prior_memory_id = m.supersedes_id
            LIMIT 1) AS supersession_event_id,
          (SELECT predecessor.content_hash FROM aimos_memories predecessor
            WHERE predecessor.company_id = m.company_id
              AND predecessor.id = m.supersedes_id
              AND predecessor.key = m.key
            LIMIT 1) AS predecessor_live_content_hash,
          edge.trigger_type AS supersession_trigger_type,
          edge.metadata AS supersession_metadata,
          lineage.lineage_id,
          lineage.child_id AS lineage_child_id,
          lineage.parent_id AS lineage_parent_id,
          lineage.derivation_type AS lineage_derivation_type,
          lineage.attestation_tier AS lineage_attestation_tier,
          lineage.attesting_agent_id AS lineage_attesting_agent_id,
          lineage.attesting_agent_valid_from AS lineage_attesting_agent_valid_from,
          lineage.attesting_cert_fingerprint AS lineage_attesting_cert_fingerprint,
          lineage.sig AS lineage_sig,
          lineage.nonce AS lineage_nonce,
          lineage.ts_signed AS lineage_ts_signed,
          lineage.body_json AS lineage_body_json,
          lineage.content_hash AS lineage_content_hash,
          lineage.mutation_hash AS lineage_mutation_hash,
          lineage.prev_mutation_hash AS lineage_prev_mutation_hash,
          lineage.is_genesis AS lineage_is_genesis,
          lineage.request_sig_form AS lineage_request_sig_form,
          lineage.binding_schema_version AS lineage_binding_schema_version,
          lineage_signer.pubkey AS lineage_signer_pubkey,
          lineage_signer.cert AS lineage_signer_cert,
          lineage_signer.valid_until AS lineage_signer_valid_until,
          p.provenance_id,
          p.agent_id AS provenance_agent_id,
          p.agent_valid_from,
          p.cert_fingerprint,
          p.content_hash AS prov_content_hash,
          p.mutation_hash,
          p.prev_mutation_hash,
          p.ts_signed,
          p.nonce,
          p.sig,
          p.event_type,
          p.binding_schema_version,
          p.identity_tier,
          p.is_genesis,
          p.backfilled,
          p.legacy_envelope_sig,
          p.sig_form_version,
          p.request_sig_form,
          p.signed_method,
          p.signed_path,
          p.signed_claims,
          p.body_json,
          p.memory_originated_at,
          p.created_at AS provenance_created_at,
          p.live_content_hash AS snapshot_live_content_hash,
          ai.pubkey AS signer_pubkey,
          ai.cert AS signer_cert,
          ai.device_fp AS signer_device_fp,
          ai.valid_until AS signer_valid_until,
          master.master_pubkey,
          master.fingerprint AS master_fingerprint,
          rev.master_fingerprint AS revocation_master_fingerprint,
          rev.target_cert_hash AS revocation_target_cert_hash,
          rev.prior_identity_hash AS revocation_prior_identity_hash,
          rev.signed_body AS revocation_signed_body,
          rev.content_hash AS revocation_content_hash,
          rev.mutation_hash AS revocation_mutation_hash,
          rev.ts_signed AS revocation_ts_signed,
          rev.nonce AS revocation_nonce,
          rev.sig AS revocation_sig
        FROM aimos_memories m
        LEFT JOIN LATERAL (
          SELECT se.* FROM supersession_events se
           WHERE se.company_id = m.company_id
             AND se.post_memory_id = m.id
             AND se.prior_memory_id = m.supersedes_id
           LIMIT 1
        ) edge ON true
        LEFT JOIN LATERAL (
          SELECT ml.* FROM aimos_memory_lineage ml
           WHERE ml.child_id = m.id
             AND ml.parent_id = m.supersedes_id
             AND ml.attestation_tier = 'D2'
           LIMIT 1
        ) lineage ON true
        LEFT JOIN agent_identity lineage_signer
          ON lineage_signer.agent_id = lineage.attesting_agent_id
         AND lineage_signer.valid_from = lineage.attesting_agent_valid_from
        LEFT JOIN aimos_memory_provenance p ON p.memory_id = m.id
        LEFT JOIN agent_identity ai
          ON ai.agent_id = p.agent_id
         AND ai.valid_from = p.agent_valid_from
        LEFT JOIN aimos_master_identity master ON master.id = 1
        LEFT JOIN aimos_agent_revocation_events rev
          ON rev.agent_id = ai.agent_id
         AND rev.agent_valid_from = ai.valid_from
       WHERE m.id = ANY($1::uuid[])`;
    const result = client
      ? await client.query({
          name: 'aimos_recall_evidence_v1',
          text: recallEvidenceSql,
          values: [uniqueIds],
        })
      : await run(recallEvidenceSql, [uniqueIds]);

    const rowsById = new Map();
    for (const row of result.rows || []) {
      if (!rowsById.has(row.memory_id)) rowsById.set(row.memory_id, []);
      rowsById.get(row.memory_id).push(row);
    }
    const verified = new Set();
    const proofs = new Map();
    const rejected = [];
    for (const memoryId of uniqueIds) {
      const rows = rowsById.get(memoryId) || [];
      const base = rows[0];
      if (!base) {
        rejected.push({ memory_id: memoryId, reason: 'memory_missing' });
        continue;
      }
      if (!base.predecessor_valid
        || Number(base.successor_count) > 1
        || (base.supersedes_id && Number(base.incoming_edge_count) !== 1)
        || (!base.supersedes_id && Number(base.incoming_edge_count) !== 0)) {
        rejected.push({ memory_id: memoryId, reason: 'supersession_topology_invalid' });
        continue;
      }
      let signedLineageMutationHash = null;
      if (base.supersedes_id) {
        const lineageVerification = verifyHousekeeperSupersessionLineage({
          body_json: base.lineage_body_json,
          attestation_tier: base.lineage_attestation_tier,
          binding_schema_version: base.lineage_binding_schema_version,
          content_hash: base.lineage_content_hash,
          mutation_hash: base.lineage_mutation_hash,
          prev_mutation_hash: base.lineage_prev_mutation_hash,
          is_genesis: base.lineage_is_genesis,
          nonce: base.lineage_nonce,
          ts_signed: base.lineage_ts_signed,
          sig: base.lineage_sig,
          attesting_agent_id: base.lineage_attesting_agent_id,
          attesting_agent_valid_from: base.lineage_attesting_agent_valid_from,
          attesting_cert_fingerprint: base.lineage_attesting_cert_fingerprint,
          signer_pubkey: base.lineage_signer_pubkey,
          signer_cert: base.lineage_signer_cert,
          signer_valid_until: base.lineage_signer_valid_until,
          master_pubkey: base.master_pubkey,
          master_fingerprint: base.master_fingerprint,
          company_id: base.live_company_id,
          key: base.live_key,
          child_id: base.lineage_child_id,
          parent_id: base.lineage_parent_id,
          derivation_type: base.lineage_derivation_type,
          supersession_event_id: base.supersession_event_id,
          trigger_type: base.supersession_trigger_type,
          supersession_metadata: base.supersession_metadata,
          child_live_content_hash: base.live_content_hash,
          parent_live_content_hash: base.predecessor_live_content_hash,
        });
        if (!lineageVerification.valid) {
          rejected.push({ memory_id: memoryId, reason: lineageVerification.reason });
          continue;
        }
        signedLineageMutationHash = lineageVerification.mutationHash;
      } else if (base.lineage_id) {
        rejected.push({ memory_id: memoryId, reason: 'unexpected_signed_lineage' });
        continue;
      }
      const provenanceRows = rows.filter((row) => row.provenance_id);
      if (!provenanceRows.length) {
        rejected.push({ memory_id: memoryId, reason: 'save_provenance_missing' });
        continue;
      }

      let nodeFailure = null;
      let orderedRows = [];
      try {
        orderedRows = orderProvenanceRowsByOccurrenceTopology(provenanceRows, base.live_company_id);
      } catch (error) {
        nodeFailure = error?.message || 'provenance_occurrence_topology_invalid';
      }
      const portableBindings = orderedRows.filter(
        (row) => row.event_type === 'BIND' && [3, 4].includes(Number(row.binding_schema_version)),
      );
      if (!nodeFailure && portableBindings.length > 1) nodeFailure = 'portable_binding_multiple_current';
      const v3Binding = portableBindings.find(
        (row) => Number(row.binding_schema_version) === 3,
      ) || null;
      const v3Body = v3Binding ? parseJsonObject(v3Binding.body_json) : null;
      const permitsLegacyPrefix = v3Body?.attestation_reason === 'retained_memory_portable_upgrade';
      const retainedAttestRows = orderedRows.filter((row) => row.event_type === 'RETAINED_ATTEST');
      if (!nodeFailure && retainedAttestRows.length > 1) nodeFailure = 'retained_attestation_multiple';
      const retainedAttestRow = retainedAttestRows[0] || null;
      const retainedAttestIndex = retainedAttestRow ? orderedRows.indexOf(retainedAttestRow) : -1;
      let legacyUnverifiedNodes = 0;
      const v3AuthorityByProvenance = new Map();
      if (!nodeFailure) {
        for (let index = 0; index < orderedRows.length; index += 1) {
          const row = orderedRows[index];
          if (Number(row.sig_form_version || 1) === 3) {
            const occurrence = verifyOccurrenceEvidenceRowV3(row);
            if (!occurrence.valid) {
              nodeFailure = occurrence.reason;
              break;
            }
            const record = occurrence.record;
            if (record.request_receipt_present === 0) {
              if (!record.event_type.startsWith('INTERNAL_') || record.authorization_event_present !== 0) {
                nodeFailure = 'occurrence_v3_internal_authority_invalid';
                break;
              }
              v3AuthorityByProvenance.set(String(row.provenance_id), {
                actorAgentId: row.provenance_agent_id,
                actorValidFromIso: new Date(row.agent_valid_from).toISOString(),
                actorCertFingerprint: row.cert_fingerprint,
              });
              continue;
            }
            let requestAuthority;
            try {
              requestAuthority = await readVerifiedRequestReceiptByMutationHash({
                companyId: base.live_company_id,
                requestReceiptMutationHash: record.request_receipt_mutation_hash_hex,
                client,
              });
            } catch {
              nodeFailure = 'occurrence_v3_request_receipt_invalid';
              break;
            }
            if (requestAuthority.requestHash !== record.request_body_hash_hex
                || requestAuthority.signedMethod !== record.signed_method
                || requestAuthority.signedPath !== record.signed_path
                || record.authorization_event_present !== 1) {
              nodeFailure = 'occurrence_v3_request_binding_invalid';
              break;
            }
            let admission;
            try {
              admission = await readVerifiedEventById(
                record.authorization_event_id,
                base.live_company_id,
                { client },
              );
            } catch {
              nodeFailure = 'occurrence_v3_authorization_event_invalid';
              break;
            }
            const metadata = parseJsonObject(admission.metadata);
            if (admission.operation !== 'request_admission_verified'
                || admission.agent_id !== requestAuthority.actorAgentId
                || metadata?.request_receipt_mutation_hash !== record.request_receipt_mutation_hash_hex
                || metadata?.request_hash !== record.request_body_hash_hex) {
              nodeFailure = 'occurrence_v3_authorization_binding_invalid';
              break;
            }
            v3AuthorityByProvenance.set(String(row.provenance_id), requestAuthority);
            continue;
          }
          const structural = verifyRetainedMutationNode(row);
          if (!structural.valid) {
            nodeFailure = structural.reason;
            break;
          }
          const verification = verifyRecallEvidenceRow(row);
          if (!verification.valid) {
            if (permitsLegacyPrefix && retainedAttestIndex >= 0 && index < retainedAttestIndex) {
              legacyUnverifiedNodes += 1;
              continue;
            }
            nodeFailure = verification.reason;
            break;
          }
        }
      }
      if (nodeFailure) {
        rejected.push({ memory_id: memoryId, reason: nodeFailure });
        continue;
      }

      if (retainedAttestRow) {
        const attestationBody = parseJsonObject(retainedAttestRow.body_json);
        const retainedPrefix = orderedRows.slice(0, retainedAttestIndex);
        const retainedRoot = retainedProvenanceMerkleRoot(retainedPrefix).toString('hex');
        const retainedHead = retainedAttestRow.prev_mutation_hash
          ? Buffer.from(retainedAttestRow.prev_mutation_hash).toString('hex')
          : null;
        const exactRetainedAttestation = attestationBody?.event_type === 'RETAINED_ATTEST'
          && attestationBody.attestation_reason === 'retained_memory_portable_upgrade'
          && attestationBody.historical_origin_signature_claimed === false
          && attestationBody.retained_provenance_merkle_root === retainedRoot
          && Number(attestationBody.retained_provenance_node_count) === retainedPrefix.length
          && attestationBody.attested_predecessor_mutation_hash === retainedHead
          && attestationBody.supersedes_id === (base.supersedes_id ? String(base.supersedes_id) : null)
          && attestationBody.supersession_event_id === (base.supersession_event_id == null ? null : Number(base.supersession_event_id))
          && attestationBody.predecessor_live_content_hash === (base.predecessor_live_content_hash
            ? Buffer.from(base.predecessor_live_content_hash).toString('hex')
            : null)
          && attestationBody.lineage_mutation_hash === signedLineageMutationHash;
        if (!exactRetainedAttestation) {
          rejected.push({ memory_id: memoryId, reason: 'retained_attestation_binding_invalid' });
          continue;
        }
      }

      const saveRows = provenanceRows.filter((row) => row.event_type === 'SAVE');
      const bindingRows = provenanceRows.filter((row) => row.event_type === 'BIND');
      const saveCardinalityValid = permitsLegacyPrefix
        ? saveRows.length <= 1 && (saveRows.length === 1 || retainedAttestRow != null)
        : saveRows.length === 1;
      if (!saveCardinalityValid || bindingRows.length < 1) {
        rejected.push({ memory_id: memoryId, reason: 'portable_binding_missing' });
        continue;
      }
      const saveRow = saveRows[0] || null;
      const bindingRow = bindingRows.find((row) => {
        const body = parseJsonObject(row.body_json);
        if (!body) return false;
        const liveHashHex = Buffer.from(row.live_content_hash || []).toString('hex');
        const baseBindingsValid = body.memory_id === memoryId
          && body.company_id === row.live_company_id
          && body.subject_agent_id === row.live_agent_id
          && body.key === row.live_key
          && body.live_content_hash === liveHashHex;
        if (!baseBindingsValid) return false;
        if ([3, 4].includes(Number(row.binding_schema_version))) {
          const bindingVersion = Number(row.binding_schema_version);
          const exactSupersedes = body.supersedes_id == null
            ? row.supersedes_id == null
            : String(body.supersedes_id) === String(row.supersedes_id || '');
          const exactEvent = body.supersession_event_id == null
            ? row.supersession_event_id == null
            : Number(body.supersession_event_id) === Number(row.supersession_event_id);
          const predecessorHash = row.predecessor_live_content_hash
            ? Buffer.from(row.predecessor_live_content_hash).toString('hex')
            : null;
          const exactPredecessorHash = body.predecessor_live_content_hash == null
            ? predecessorHash == null
            : body.predecessor_live_content_hash === predecessorHash;
          const exactLineage = body.lineage_mutation_hash == null
            ? signedLineageMutationHash == null
            : body.lineage_mutation_hash === signedLineageMutationHash;
          const predecessorMutationHash = row.prev_mutation_hash
            ? Buffer.from(row.prev_mutation_hash).toString('hex')
            : null;
          const exactHead = body.attested_predecessor_mutation_hash === predecessorMutationHash;
          const exactNodeCount = Number(body.attested_predecessor_node_count)
            === orderedRows.indexOf(row);
          const reason = String(body.attestation_reason || '');
          const nativeRequestBinding = reason !== 'native_save_commit' || (saveRow != null &&
            body.request_content_hash === Buffer.from(saveRow.prov_content_hash).toString('hex')
            && body.request_mutation_hash === Buffer.from(saveRow.mutation_hash).toString('hex')
            && body.request_signature_hash === createHash('sha256').update(Buffer.from(saveRow.sig)).digest('hex')
            && body.request_signer_agent_id === saveRow.provenance_agent_id
            && new Date(body.request_signer_valid_from).toISOString() === new Date(saveRow.agent_valid_from).toISOString()
          );
          const retainedAuthority = retainedAttestRow || saveRow;
          const retainedAuthorityBinding = reason !== 'retained_memory_portable_upgrade' || (
            retainedAuthority != null
            && body.authority_event_type === retainedAuthority.event_type
            && body.authority_content_hash === Buffer.from(retainedAuthority.prov_content_hash).toString('hex')
            && body.authority_mutation_hash === Buffer.from(retainedAuthority.mutation_hash).toString('hex')
            && body.authority_signature_hash === createHash('sha256').update(Buffer.from(retainedAuthority.sig)).digest('hex')
            && body.authority_signer_agent_id === retainedAuthority.provenance_agent_id
            && new Date(body.authority_signer_valid_from).toISOString()
              === new Date(retainedAuthority.agent_valid_from).toISOString()
          );
          const exactOrigin = verifyMemoryOriginBindingV4({
            bindingSchemaVersion: bindingVersion,
            eventType: row.event_type,
            body,
            memoryOriginatedAt: row.memory_originated_at,
            liveCreatedAt: row.live_created_at,
          }).valid;
          const schemaReasonValid = bindingVersion === 3
            ? ['native_save_commit', 'retained_memory_portable_upgrade'].includes(reason)
            : reason === 'native_save_commit';
          return body.binding_schema_version === bindingVersion
            && schemaReasonValid
            && exactSupersedes
            && exactEvent
            && exactPredecessorHash
            && exactLineage
            && exactHead
            && exactNodeCount
            && exactOrigin
            && nativeRequestBinding
            && retainedAuthorityBinding;
        }
        return saveRow != null
          && body.request_content_hash === Buffer.from(saveRow.prov_content_hash).toString('hex')
          && body.request_mutation_hash === Buffer.from(saveRow.mutation_hash).toString('hex')
          && body.request_signature_hash === createHash('sha256').update(Buffer.from(saveRow.sig)).digest('hex')
          && body.request_signer_agent_id === saveRow.provenance_agent_id
          && new Date(body.request_signer_valid_from).toISOString() === new Date(saveRow.agent_valid_from).toISOString();
      });
      if (!bindingRow) {
        rejected.push({ memory_id: memoryId, reason: 'portable_binding_invalid' });
        continue;
      }

      const bindingVerification = verifyRecallEvidenceRow(bindingRow);
      const signedSaveIntent = saveRow ? parseJsonObject(saveRow.body_json) : null;
      // R7 exposes the latest independently verified reassertion as the
      // temporal/authority witness while the content state still contributes
      // only once to ordinary retrieval. If no successor event exists, retain
      // the R4 legacy witness selection unchanged.
      const successorOccurrences = orderedRows.filter(
        (row) => Number(row.sig_form_version || 1) === 3,
      );
      const occurrenceRow = successorOccurrences.at(-1) || saveRow || retainedAttestRow || bindingRow;
      const occurrenceAuthority = v3AuthorityByProvenance.get(String(occurrenceRow.provenance_id)) || null;
      const proof = {
        ...bindingVerification.proof,
        company_id: base.live_company_id,
        subject_agent_id: base.live_agent_id,
        key: base.live_key,
        session_id: signedSaveIntent?.session_id == null
          ? null
          : String(signedSaveIntent.session_id),
        scope: base.live_scope,
        cube_scope: base.live_cube_scope,
        memory_type: base.live_memory_type,
        clearance_level: Number(base.live_clearance_level),
        data_class: base.live_data_class || 'public',
        source: base.live_source,
        save_content_hash: saveRow ? Buffer.from(saveRow.prov_content_hash).toString('hex') : null,
        save_mutation_hash: saveRow ? Buffer.from(saveRow.mutation_hash).toString('hex') : null,
        binding_mutation_hash: Buffer.from(bindingRow.mutation_hash).toString('hex'),
        occurrence_provenance_id: String(occurrenceRow.provenance_id),
        occurrence_mutation_hash: Buffer.from(occurrenceRow.mutation_hash).toString('hex'),
        occurrence_signer_agent_id: occurrenceRow.provenance_agent_id,
        occurrence_signer_valid_from: new Date(occurrenceRow.agent_valid_from).toISOString(),
        occurrence_cert_fingerprint: occurrenceRow.cert_fingerprint,
        occurrence_event_type: String(occurrenceRow.event_type || 'SAVE'),
        occurrence_sig_form_version: Number(occurrenceRow.sig_form_version || 1),
        occurrence_ts_signed: Number(occurrenceRow.ts_signed),
        occurrence_actor_agent_id: occurrenceAuthority?.actorAgentId || occurrenceRow.provenance_agent_id,
        occurrence_actor_valid_from: occurrenceAuthority?.actorValidFromIso
          || new Date(occurrenceRow.agent_valid_from).toISOString(),
        occurrence_actor_cert_fingerprint: occurrenceAuthority?.actorCertFingerprint
          || occurrenceRow.cert_fingerprint,
        occurrence_count: successorOccurrences.length + 1,
        lineage_mutation_hash: signedLineageMutationHash,
        provenance_nodes: provenanceRows.length,
        binding_schema_version: Number(bindingRow.binding_schema_version),
        memory_originated_at: bindingRow.memory_originated_at
          ? new Date(bindingRow.memory_originated_at).toISOString()
          : null,
        historical_signature_status: retainedAttestRow
          ? 'retrospectively_attested'
          : 'original_save_verified',
        legacy_unverified_nodes: legacyUnverifiedNodes,
        version_status: Number(base.successor_count) > 0 ? 'historical' : 'current',
      };
      verified.add(memoryId);
      proofs.set(memoryId, proof);
    }
    return { verified, proofs, rejected };
  }

  return {
    commitProvenance,
    commitOccurrenceV3,
    getProvenanceRow,
    getProvenanceChain,
    getLatestMutationHash,
    getLatestOccurrenceReference,
    verifyRecallMemories,
    verifyRecallEvidence,
  };
}

export const memoryProvenanceLedger = createMemoryProvenanceLedger();
