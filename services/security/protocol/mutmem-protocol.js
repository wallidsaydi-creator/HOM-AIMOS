// MutMem authority-free deterministic protocol primitives.
//
// This module owns only canonical byte construction and structural hashes. It
// has no database, Keychain, filesystem, network, route, signer, model, policy,
// or mutable runtime dependency. Producing authority remains in the native
// housekeeper and restricted database writer; verification authority remains
// in evidence consumers.

import { createHash } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';

export const MUTMEM_PROTOCOL_CONSTANTS = Object.freeze({
  COGNITIVE_TRANSITION_DOMAIN: Buffer.from('aimos.cognitive-transition/v2\0', 'utf8'),
  COGNITIVE_BASELINE_DOMAIN: Buffer.from('aimos.cognitive-baseline/v1\0', 'utf8'),
  COGNITIVE_PROJECTION_DOMAIN: Buffer.from('aimos.cwc/v1\0', 'utf8'),
  COGNITIVE_CORPUS_DOMAIN: Buffer.from('aimos.cognitive-corpus-proof/v1\0', 'utf8'),
  EVENT_LINK_DOMAIN: Buffer.from('AIMOS-EVENT-LINK-v1\0', 'utf8'),
  EVENT_GENESIS_DOMAIN: Buffer.from('aimos-event-genesis/v1\0', 'utf8'),
  RETAINED_PROVENANCE_LEAF_DOMAIN: Buffer.from('aimos.retained-provenance-leaf/v1\0', 'utf8'),
  RETAINED_PROVENANCE_NODE_DOMAIN: Buffer.from('aimos.retained-provenance-node/v1\0', 'utf8'),
  RETAINED_PROVENANCE_EMPTY_DOMAIN: Buffer.from('aimos.retained-provenance-empty/v1\0', 'utf8'),
  EPISTEMIC_CLASSIFICATION_DOMAIN: Buffer.from('aimos.memory-epistemic/v1\0', 'utf8'),
  RECALL_LEAF_PREFIX: Buffer.from([0x00]),
  RECALL_NODE_PREFIX: Buffer.from([0x01]),
  RECALL_CORPUS_ROOT_DOMAIN: Buffer.from('aimos.mutmem-recall-corpus/v1\0', 'utf8'),
});

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function uuidBytes(value, errorCode) {
  const bytes = Buffer.from(String(value || '').replaceAll('-', ''), 'hex');
  if (bytes.length !== 16) throw new Error(errorCode);
  return bytes;
}

function int32Bytes(value, errorCode) {
  if (!Number.isSafeInteger(value)) throw new Error(errorCode);
  const bytes = Buffer.alloc(4);
  bytes.writeInt32BE(value);
  return bytes;
}

function int64Bytes(value, errorCode) {
  if (!Number.isSafeInteger(value)) throw new Error(errorCode);
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64BE(BigInt(value));
  return bytes;
}

function projectionInt64Bytes(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64BE(BigInt(value));
  return bytes;
}

function lengthPrefixedUtf8(value, errorCode) {
  const bytes = Buffer.from(String(value || ''), 'utf8');
  if (!bytes.length || bytes.length > 0x7fffffff) throw new Error(errorCode);
  return Buffer.concat([int32Bytes(bytes.length, errorCode), bytes]);
}

function exactHashBytes(value, errorCode) {
  const bytes = Buffer.from(value || []);
  if (bytes.length !== 32) throw new Error(errorCode);
  return bytes;
}

export function cognitiveTransitionHash({
  companyId,
  memoryId,
  oldWeight,
  newWeight,
  provenanceMutationHash,
} = {}) {
  const company = Buffer.from(String(companyId || ''), 'utf8');
  const memory = Buffer.from(String(memoryId || '').replaceAll('-', ''), 'hex');
  const provenance = Buffer.from(provenanceMutationHash || []);
  const oldMilli = Math.round(Number(oldWeight) * 1000);
  const newMilli = Math.round(Number(newWeight) * 1000);
  if (!company.length || company.length > 0x7fffffff || memory.length !== 16 || provenance.length !== 32) {
    throw new Error('cognitive_transition_identity_malformed');
  }
  if (oldMilli < 100 || oldMilli > 3000 || newMilli < 100 || newMilli > 3000 || oldMilli === newMilli) {
    throw new Error('cognitive_transition_weight_malformed');
  }
  const companyLength = Buffer.alloc(4);
  companyLength.writeInt32BE(company.length);
  const oldBytes = Buffer.alloc(8);
  const newBytes = Buffer.alloc(8);
  oldBytes.writeBigInt64BE(BigInt(oldMilli));
  newBytes.writeBigInt64BE(BigInt(newMilli));
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.COGNITIVE_TRANSITION_DOMAIN,
    companyLength,
    company,
    memory,
    oldBytes,
    newBytes,
    provenance,
  ]));
}

export function cognitiveBaselineHash({
  companyId,
  memoryId,
  eventId,
  eventMutationHash,
  liveContentHash,
  observedWeight,
  weightMilli,
  observedTs,
  signerValidFromIso,
  certFingerprint,
} = {}) {
  const company = Buffer.from(String(companyId || ''), 'utf8');
  const contentHash = Buffer.from(liveContentHash || []);
  const eventHash = Buffer.from(eventMutationHash || []);
  const certHash = Buffer.from(String(certFingerprint || ''), 'hex');
  const observedWeightBytes = Buffer.alloc(4);
  observedWeightBytes.writeFloatBE(Number(observedWeight));
  const validFromSeconds = Math.round(new Date(signerValidFromIso).getTime() / 1000);
  if (!company.length || company.length > 0x7fffffff || contentHash.length !== 32
      || eventHash.length !== 32 || certHash.length !== 32
      || !Number.isFinite(Number(observedWeight))
      || Math.round(Number(observedWeight) * 1000) !== weightMilli
      || !Number.isInteger(weightMilli) || weightMilli < 100 || weightMilli > 3000
      || !Number.isSafeInteger(observedTs) || observedTs <= 0
      || !Number.isSafeInteger(validFromSeconds) || validFromSeconds <= 0) {
    throw new Error('cognitive_baseline_input_malformed');
  }
  const companyLength = Buffer.alloc(4);
  companyLength.writeInt32BE(company.length);
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.COGNITIVE_BASELINE_DOMAIN,
    companyLength,
    company,
    uuidBytes(memoryId, 'cognitive_baseline_memory_malformed'),
    uuidBytes(eventId, 'cognitive_baseline_event_malformed'),
    eventHash,
    contentHash,
    observedWeightBytes,
    int64Bytes(weightMilli, 'cognitive_baseline_weight_malformed'),
    int64Bytes(observedTs, 'cognitive_baseline_observation_malformed'),
    int64Bytes(validFromSeconds, 'cognitive_baseline_epoch_malformed'),
    certHash,
  ]));
}

export function cognitiveProjectionHash({
  memoryId,
  oldWeightMilli,
  newWeightMilli,
  provenanceMutationHash,
  previousHash = null,
} = {}) {
  const previous = previousHash ? Buffer.from(previousHash) : Buffer.alloc(32);
  const provenance = Buffer.from(provenanceMutationHash || []);
  if (previous.length !== 32 || provenance.length !== 32) {
    throw new Error('cognitive_projection_hash_input_invalid');
  }
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.COGNITIVE_PROJECTION_DOMAIN,
    uuidBytes(memoryId, 'cognitive_uuid_malformed'),
    projectionInt64Bytes(oldWeightMilli),
    projectionInt64Bytes(newWeightMilli),
    provenance,
    previous,
  ]));
}

export function cognitiveCorpusRoot(proofRecords = []) {
  if (!Array.isArray(proofRecords)) throw new Error('cognitive_corpus_records_invalid');
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.COGNITIVE_CORPUS_DOMAIN,
    Buffer.from(canonicalJson(proofRecords), 'utf8'),
  ]));
}

export function eventGenesisHash(companyId, signerAgentId, signerValidFrom) {
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.EVENT_GENESIS_DOMAIN,
    Buffer.from(String(companyId), 'utf8'),
    Buffer.from('\0', 'utf8'),
    Buffer.from(String(signerAgentId), 'utf8'),
    Buffer.from('\0', 'utf8'),
    Buffer.from(new Date(signerValidFrom).toISOString(), 'utf8'),
  ]));
}

export function eventMutationHash(prevHash, contentHash, nonce, signedTs) {
  if (!Buffer.isBuffer(prevHash) || prevHash.length !== 32) throw new Error('event_prev_hash_invalid');
  if (!Buffer.isBuffer(contentHash) || contentHash.length !== 32) throw new Error('event_content_hash_invalid');
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.EVENT_LINK_DOMAIN,
    prevHash,
    contentHash,
    Buffer.from(String(nonce), 'utf8'),
    Buffer.from(String(signedTs), 'utf8'),
  ]));
}

function hexOrNull(value) {
  return value == null ? null : Buffer.from(value).toString('hex');
}

function isoOrNull(value) {
  if (value == null) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function retainedProvenanceLeafHash(row = {}) {
  const retained = {
    provenance_id: String(row.provenance_id || ''),
    memory_id: String(row.memory_id || ''),
    agent_id: row.provenance_agent_id ?? row.agent_id ?? null,
    agent_valid_from: isoOrNull(row.agent_valid_from),
    cert_fingerprint: row.cert_fingerprint ?? null,
    content_hash: hexOrNull(row.prov_content_hash ?? row.content_hash),
    mutation_hash: hexOrNull(row.mutation_hash),
    prev_mutation_hash: hexOrNull(row.prev_mutation_hash),
    ts_signed: row.ts_signed == null ? null : Number(row.ts_signed),
    nonce: row.nonce ?? null,
    sig: hexOrNull(row.sig),
    identity_tier: row.identity_tier ?? null,
    is_genesis: Boolean(row.is_genesis),
    backfilled: Boolean(row.backfilled),
    memory_originated_at: isoOrNull(row.memory_originated_at),
    legacy_envelope_sig: hexOrNull(row.legacy_envelope_sig),
    created_at: isoOrNull(row.provenance_created_at ?? row.created_at),
    event_type: row.event_type ?? null,
    body_json: row.body_json ?? null,
    sig_form_version: Number(row.sig_form_version || 1),
    live_content_hash: hexOrNull(row.snapshot_live_content_hash ?? row.live_content_hash),
    request_sig_form: Number(row.request_sig_form || 1),
    signed_method: row.signed_method ?? null,
    signed_path: row.signed_path ?? null,
    signed_claims: row.signed_claims ?? null,
    binding_schema_version: Number(row.binding_schema_version || 1),
  };
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.RETAINED_PROVENANCE_LEAF_DOMAIN,
    Buffer.from(canonicalJson(retained), 'utf8'),
  ]));
}

export function retainedProvenanceMerkleRoot(rows = []) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return sha256(MUTMEM_PROTOCOL_CONSTANTS.RETAINED_PROVENANCE_EMPTY_DOMAIN);
  }
  let level = rows.map(retainedProvenanceLeafHash);
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] || left;
      next.push(sha256(Buffer.concat([
        MUTMEM_PROTOCOL_CONSTANTS.RETAINED_PROVENANCE_NODE_DOMAIN,
        left,
        right,
      ])));
    }
    level = next;
  }
  return level[0];
}

export function recallMerkleRoot(entries = []) {
  const leaves = entries.map((entry) => sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.RECALL_LEAF_PREFIX,
    Buffer.from(canonicalJson(entry), 'utf8'),
  ])));
  if (!leaves.length) return sha256(Buffer.alloc(0));
  function tree(nodes) {
    if (nodes.length === 1) return nodes[0];
    let split = 1;
    while ((split << 1) < nodes.length) split <<= 1;
    return sha256(Buffer.concat([
      MUTMEM_PROTOCOL_CONSTANTS.RECALL_NODE_PREFIX,
      tree(nodes.slice(0, split)),
      tree(nodes.slice(split)),
    ]));
  }
  return tree(leaves);
}

export function recallCorpusRoot({ intendedN, members = [] } = {}) {
  if (!Number.isSafeInteger(intendedN) || intendedN < 1
      || !Array.isArray(members) || members.length !== intendedN) {
    throw new Error('recall_corpus_intended_n_invalid');
  }
  const seenIds = new Set();
  const normalized = members.map((member, ordinal) => {
    if (!member || typeof member !== 'object' || Array.isArray(member)
        || Number(member.ordinal) !== ordinal
        || typeof member.bundle_id !== 'string' || !member.bundle_id
        || !/^[0-9a-f]{64}$/.test(String(member.bundle_sha256 || ''))
        || seenIds.has(member.bundle_id)) {
      throw new Error('recall_corpus_member_invalid');
    }
    seenIds.add(member.bundle_id);
    return Object.freeze({
      ordinal,
      bundle_id: member.bundle_id,
      bundle_sha256: member.bundle_sha256,
    });
  });
  const intendedBytes = Buffer.alloc(8);
  intendedBytes.writeBigInt64BE(BigInt(intendedN));
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.RECALL_CORPUS_ROOT_DOMAIN,
    intendedBytes,
    recallMerkleRoot(normalized),
  ]));
}

export function memoryEpistemicClassificationHash({
  memoryId,
  label,
  confidenceMilli,
  liveContentHash,
  eventMutationHash,
  previousHash = null,
} = {}) {
  const allowed = new Set([
    'unverified', 'supported', 'disputed', 'poison_suspect',
    'poison_likely', 'poison_confirmed', 'poison_refuted',
  ]);
  if (!allowed.has(label)) throw new Error('epistemic_classification_label_invalid');
  if (!Number.isInteger(confidenceMilli) || confidenceMilli < 0 || confidenceMilli > 1000) {
    throw new Error('epistemic_classification_confidence_invalid');
  }
  const live = exactHashBytes(liveContentHash, 'epistemic_classification_live_hash_invalid');
  const event = exactHashBytes(eventMutationHash, 'epistemic_classification_event_hash_invalid');
  const previous = previousHash == null
    ? Buffer.alloc(32)
    : exactHashBytes(previousHash, 'epistemic_classification_previous_hash_invalid');
  return sha256(Buffer.concat([
    MUTMEM_PROTOCOL_CONSTANTS.EPISTEMIC_CLASSIFICATION_DOMAIN,
    uuidBytes(memoryId, 'epistemic_classification_memory_id_invalid'),
    lengthPrefixedUtf8(label, 'epistemic_classification_label_invalid'),
    int64Bytes(confidenceMilli, 'epistemic_classification_confidence_invalid'),
    live,
    event,
    previous,
  ]));
}
