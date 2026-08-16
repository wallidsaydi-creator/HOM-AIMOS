// MutMem V2 cognitive evidence bundle and pure verifier.
//
// This module owns a descriptive, JSON-safe evidence interchange for the
// current cognitive-weight corpus and verifies that evidence without database,
// Keychain, filesystem, network, route, signer, policy, model, or private-key
// authority. The database-facing reader lives in cognitive-weight-verifier.js.
//
// Sources: docs/security/cognitive-weight-chain-SPEC.md; RFC 8032; RFC 6962.

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';
import {
  cognitiveBaselineHash,
  cognitiveCorpusRoot,
  cognitiveProjectionHash,
  cognitiveTransitionHash,
  eventGenesisHash,
  eventMutationHash,
} from './mutmem-protocol.js';

export const COGNITIVE_EVIDENCE_SCHEMA = 'hom.aimos.mutmem-cognitive-evidence/v1';

const REVOCATION_SCHEMA = 'hom.aimos.agent-revocation/v1';
const REVOCATION_DOMAIN = Buffer.from('aimos-agent-revocation-v1\0', 'utf8');
const MASTER_CERTIFICATE_ISSUER = 'aimos-master';
const REQUIRED_CERT_FIELDS = Object.freeze([
  'v', 'agent_id', 'pubkey', 'device_fp',
  'valid_from', 'valid_until', 'issuer', 'issued_at',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function masterFingerprint(publicKeyB64u) {
  return sha256(Buffer.from(String(publicKeyB64u || ''), 'base64url')).toString('hex');
}

function certificateAuthorityPubkey(identity, certBody) {
  if (!certBody || typeof certBody !== 'object') return null;
  if (certBody.issuer === certBody.agent_id) return identity?.pubkey || null;
  const masterIssuer = certBody.issuer === MASTER_CERTIFICATE_ISSUER
    || certBody.issuer === identity?.master_fingerprint;
  if (!masterIssuer || !identity?.master_pubkey || !identity?.master_fingerprint) return null;
  try {
    return masterFingerprint(identity.master_pubkey) === identity.master_fingerprint
      ? identity.master_pubkey
      : null;
  } catch {
    return null;
  }
}

function parseObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value)) {
    return value;
  }
  if (typeof value !== 'string') return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function epochSeconds(value, reason) {
  const milliseconds = new Date(value).getTime();
  if (!Number.isFinite(milliseconds)) throw new Error(reason);
  const seconds = Math.floor(milliseconds / 1000);
  if (!Number.isSafeInteger(seconds) || seconds <= 0) throw new Error(reason);
  return seconds;
}

function isoFromEpoch(value, reason = 'cognitive_evidence_epoch_invalid') {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(reason);
  return new Date(value * 1000).toISOString();
}

function exactInteger(value, reason, { minimum = null, maximum = null } = {}) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)
      || (minimum !== null && number < minimum)
      || (maximum !== null && number > maximum)) {
    throw new Error(reason);
  }
  return number;
}

function exactHex(value, bytes, reason) {
  const hex = Buffer.isBuffer(value) ? value.toString('hex') : String(value || '');
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(hex)) throw new Error(reason);
  return hex;
}

function optionalHex(value, bytes, reason) {
  return value == null ? null : exactHex(value, bytes, reason);
}

function hexBuffer(value, bytes, reason) {
  return Buffer.from(exactHex(value, bytes, reason), 'hex');
}

function float4Hex(value, reason = 'cognitive_evidence_float4_invalid') {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(reason);
  const bytes = Buffer.alloc(4);
  bytes.writeFloatBE(number);
  return bytes.toString('hex');
}

function float4FromHex(value, reason = 'cognitive_evidence_float4_invalid') {
  return hexBuffer(value, 4, reason).readFloatBE(0);
}

function normalizeRevocation(row = {}) {
  if (row.revocation_signed_body == null && row.revocation_sig == null) return null;
  return {
    agent_id: String(row.provenance_agent_id ?? row.signer_agent_id ?? row.agent_id ?? ''),
    agent_valid_from: epochSeconds(
      row.agent_valid_from ?? row.signer_valid_from,
      'cognitive_evidence_revocation_epoch_invalid',
    ),
    master_fingerprint: String(row.revocation_master_fingerprint || ''),
    target_cert_hash: exactHex(row.revocation_target_cert_hash, 32, 'cognitive_evidence_revocation_target_invalid'),
    prior_identity_hash: exactHex(row.revocation_prior_identity_hash, 32, 'cognitive_evidence_revocation_prior_invalid'),
    signed_body: parseObject(row.revocation_signed_body),
    content_hash: exactHex(row.revocation_content_hash, 32, 'cognitive_evidence_revocation_content_invalid'),
    mutation_hash: exactHex(row.revocation_mutation_hash, 32, 'cognitive_evidence_revocation_mutation_invalid'),
    ts_signed: exactInteger(row.revocation_ts_signed, 'cognitive_evidence_revocation_time_invalid', { minimum: 1 }),
    nonce: String(row.revocation_nonce || ''),
    signature: exactHex(row.revocation_sig, 64, 'cognitive_evidence_revocation_signature_invalid'),
  };
}

function normalizeIdentity(row, masterIdentity, fields = {}) {
  const identity = {
    agent_id: String(row[fields.agentId || 'agent_id'] || ''),
    pubkey_b64u: String(row[fields.pubkey || 'pubkey'] || ''),
    certificate_b64u: String(row[fields.cert || 'cert'] || ''),
    device_fingerprint: String(row[fields.deviceFp || 'device_fp'] || ''),
    valid_from: epochSeconds(row[fields.validFrom || 'valid_from'], 'cognitive_evidence_identity_epoch_invalid'),
    valid_until: epochSeconds(row[fields.validUntil || 'valid_until'], 'cognitive_evidence_identity_epoch_invalid'),
    revocation: normalizeRevocation(row),
  };
  if (!identity.agent_id || !identity.pubkey_b64u || !identity.certificate_b64u
      || !identity.device_fingerprint || identity.valid_until <= identity.valid_from) {
    throw new Error('cognitive_evidence_identity_invalid');
  }
  if (!masterIdentity?.master_pubkey || !masterIdentity?.master_fingerprint) {
    throw new Error('cognitive_evidence_master_identity_missing');
  }
  return identity;
}

function normalizeEvent(row) {
  return {
    event_id: String(row.id || ''),
    company_id: String(row.company_id || ''),
    subject_agent_id: String(row.agent_id || ''),
    signer_agent_id: String(row.signer_agent_id || ''),
    signer_valid_from: epochSeconds(row.signer_valid_from, 'cognitive_evidence_event_epoch_invalid'),
    certificate_fingerprint: String(row.cert_fingerprint || ''),
    identity_tier: String(row.identity_tier || ''),
    authority_kind: String(row.authority_kind || ''),
    operation: String(row.operation || ''),
    key: row.key == null ? null : String(row.key),
    metadata: parseObject(row.metadata) ?? {},
    parent_event_id: row.parent_event_id == null ? null : String(row.parent_event_id),
    ledger_sequence: exactInteger(row.ledger_seq, 'cognitive_evidence_event_sequence_invalid', { minimum: 1 }),
    previous_mutation_hash: exactHex(row.prev_mutation_hash, 32, 'cognitive_evidence_event_previous_invalid'),
    content_hash: exactHex(row.content_hash, 32, 'cognitive_evidence_event_content_invalid'),
    mutation_hash: exactHex(row.mutation_hash, 32, 'cognitive_evidence_event_mutation_invalid'),
    signed_at: exactInteger(row.ts_signed, 'cognitive_evidence_event_time_invalid', { minimum: 1 }),
    nonce: String(row.nonce || ''),
    signature: exactHex(row.sig, 64, 'cognitive_evidence_event_signature_invalid'),
    proof_required: row.proof_required === true,
    ledger_version: exactInteger(row.ledger_version, 'cognitive_evidence_event_version_invalid', { minimum: 1 }),
    signed_body: parseObject(row.signed_body),
  };
}

function normalizeBaseline(row, masterIdentity) {
  return {
    baseline_id: String(row.baseline_id || ''),
    company_id: String(row.company_id || ''),
    memory_id: String(row.memory_id || ''),
    event_id: String(row.event_id || ''),
    event_mutation_hash: exactHex(row.event_mutation_hash, 32, 'cognitive_evidence_baseline_event_invalid'),
    live_content_hash: exactHex(row.live_content_hash, 32, 'cognitive_evidence_baseline_content_invalid'),
    observed_weight_milli: exactInteger(
      row.retrieval_weight_milli,
      'cognitive_evidence_baseline_weight_invalid',
      { minimum: 100, maximum: 3000 },
    ),
    observed_weight_float4: exactHex(
      row.observed_weight_float4 ?? Buffer.from(float4Hex(row.observed_weight), 'hex'),
      4,
      'cognitive_evidence_baseline_float4_invalid',
    ),
    observed_at: exactInteger(row.observed_ts, 'cognitive_evidence_baseline_time_invalid', { minimum: 1 }),
    attestation_reason: String(row.attestation_reason || ''),
    historical_origin_claimed: row.historical_origin_claimed === true,
    signer_agent_id: String(row.signer_agent_id || ''),
    signer_valid_from: epochSeconds(row.signer_valid_from, 'cognitive_evidence_baseline_epoch_invalid'),
    certificate_fingerprint: String(row.cert_fingerprint || ''),
    baseline_hash: exactHex(row.baseline_hash, 32, 'cognitive_evidence_baseline_hash_invalid'),
    signature: exactHex(row.baseline_sig, 64, 'cognitive_evidence_baseline_signature_invalid'),
    identity: normalizeIdentity(row, masterIdentity),
  };
}

function normalizeProjection(row, masterIdentity) {
  const signedClaims = parseObject(row.signed_claims);
  return {
    projection_id: String(row.projection_id || ''),
    company_id: String(row.company_id || ''),
    memory_id: String(row.memory_id || ''),
    old_weight_milli: exactInteger(row.old_weight_milli, 'cognitive_evidence_projection_weight_invalid'),
    new_weight_milli: exactInteger(row.new_weight_milli, 'cognitive_evidence_projection_weight_invalid'),
    old_weight_float4: float4Hex(row.old_weight, 'cognitive_evidence_projection_float4_invalid'),
    new_weight_float4: float4Hex(row.new_weight, 'cognitive_evidence_projection_float4_invalid'),
    provenance_mutation_hash: exactHex(row.provenance_mutation_hash, 32, 'cognitive_evidence_projection_provenance_invalid'),
    previous_projection_hash: optionalHex(row.prev_projection_hash, 32, 'cognitive_evidence_projection_previous_invalid'),
    projection_hash: exactHex(row.projection_hash, 32, 'cognitive_evidence_projection_hash_invalid'),
    transition_hash: exactHex(row.transition_hash, 32, 'cognitive_evidence_transition_hash_invalid'),
    transition_signature: exactHex(row.transition_sig, 64, 'cognitive_evidence_transition_signature_invalid'),
    provenance: {
      provenance_id: String(row.provenance_id || ''),
      body: parseObject(row.body_json),
      content_hash: exactHex(row.prov_content_hash, 32, 'cognitive_evidence_provenance_content_invalid'),
      mutation_hash: exactHex(row.mutation_hash, 32, 'cognitive_evidence_provenance_mutation_invalid'),
      previous_mutation_hash: optionalHex(row.prev_mutation_hash, 32, 'cognitive_evidence_provenance_previous_invalid'),
      signed_at: exactInteger(row.ts_signed, 'cognitive_evidence_provenance_time_invalid', { minimum: 1 }),
      nonce: String(row.nonce || ''),
      signature: exactHex(row.sig, 64, 'cognitive_evidence_provenance_signature_invalid'),
      event_type: String(row.event_type || ''),
      binding_schema_version: exactInteger(row.binding_schema_version, 'cognitive_evidence_provenance_binding_invalid', { minimum: 1 }),
      signer_agent_id: String(row.provenance_agent_id || ''),
      signer_valid_from: epochSeconds(row.agent_valid_from, 'cognitive_evidence_provenance_epoch_invalid'),
      certificate_fingerprint: String(row.cert_fingerprint || ''),
      identity_tier: String(row.identity_tier || ''),
      signature_form: exactInteger(row.sig_form_version || 1, 'cognitive_evidence_provenance_signature_form_invalid', { minimum: 1 }),
      request_signature_form: exactInteger(row.request_sig_form || 1, 'cognitive_evidence_request_signature_form_invalid', { minimum: 1 }),
      signed_method: row.signed_method == null ? null : String(row.signed_method),
      signed_path: row.signed_path == null ? null : String(row.signed_path),
      signed_claims: signedClaims,
      is_genesis: row.is_genesis === true,
      backfilled: row.backfilled === true,
      memory_originated_at: row.memory_originated_at == null
        ? null
        : epochSeconds(row.memory_originated_at, 'cognitive_evidence_provenance_origin_invalid'),
      identity: normalizeIdentity(row, masterIdentity, {
        agentId: 'provenance_agent_id',
        pubkey: 'signer_pubkey',
        cert: 'signer_cert',
        deviceFp: 'signer_device_fp',
        validFrom: 'agent_valid_from',
        validUntil: 'signer_valid_until',
      }),
    },
  };
}

function normalizeSqlRecord(row) {
  return {
    memory_id: String(row.memory_id || ''),
    certification_status: String(row.certification_status || ''),
    ok: row.ok === true,
    chain_length: exactInteger(row.chain_length, 'cognitive_evidence_sql_count_invalid', { minimum: 0 }),
    signatures_verified: exactInteger(row.sigs_verified, 'cognitive_evidence_sql_count_invalid', { minimum: 0 }),
    reason: row.reason == null ? null : String(row.reason),
  };
}

export function createCognitiveWeightEvidenceBundle({
  companyId,
  masterIdentity,
  memories = [],
  baselines = [],
  events = [],
  projections = [],
  sqlRows = [],
} = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('cognitive_evidence_company_required');
  const master = {
    public_key_b64u: String(masterIdentity?.master_pubkey || ''),
    fingerprint: String(masterIdentity?.master_fingerprint || ''),
  };
  if (!master.public_key_b64u || !/^[0-9a-f]{64}$/.test(master.fingerprint)) {
    throw new Error('cognitive_evidence_master_identity_invalid');
  }
  if (masterFingerprint(master.public_key_b64u) !== master.fingerprint) {
    throw new Error('cognitive_evidence_master_fingerprint_mismatch');
  }

  const baselineByMemory = new Map();
  for (const row of baselines) {
    const normalized = normalizeBaseline(row, masterIdentity);
    if (baselineByMemory.has(normalized.memory_id)) throw new Error('cognitive_evidence_duplicate_baseline');
    baselineByMemory.set(normalized.memory_id, normalized);
  }
  const projectionsByMemory = new Map();
  for (const row of projections) {
    const normalized = normalizeProjection(row, masterIdentity);
    if (!projectionsByMemory.has(normalized.memory_id)) projectionsByMemory.set(normalized.memory_id, []);
    projectionsByMemory.get(normalized.memory_id).push(normalized);
  }
  for (const rows of projectionsByMemory.values()) {
    rows.sort((a, b) => a.projection_id.localeCompare(b.projection_id));
  }

  const streamRows = new Map();
  for (const row of events) {
    const signerValidFrom = epochSeconds(row.signer_valid_from, 'cognitive_evidence_event_epoch_invalid');
    const key = `${String(row.signer_agent_id)}\0${signerValidFrom}`;
    if (!streamRows.has(key)) streamRows.set(key, []);
    streamRows.get(key).push(row);
  }
  const eventStreams = [...streamRows.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, rows]) => {
      rows.sort((a, b) => Number(a.ledger_seq) - Number(b.ledger_seq));
      const identity = normalizeIdentity(rows[0], masterIdentity, {
        agentId: 'signer_agent_id',
        validFrom: 'signer_valid_from',
      });
      return {
        signer_agent_id: identity.agent_id,
        signer_valid_from: identity.valid_from,
        identity,
        events: rows.map(normalizeEvent),
      };
    });

  const memoryRows = memories.map((row) => {
    const id = String(row.id || '');
    const retrievalWeight = Number(row.retrieval_weight);
    const milli = Math.round(retrievalWeight * 1000);
    if (!id || String(row.company_id) !== company || !Number.isFinite(retrievalWeight)) {
      throw new Error('cognitive_evidence_memory_invalid');
    }
    return {
      memory_id: id,
      company_id: company,
      content_hash: exactHex(row.content_hash, 32, 'cognitive_evidence_memory_content_invalid'),
      retrieval_weight_milli: exactInteger(milli, 'cognitive_evidence_memory_weight_invalid'),
      retrieval_weight_float4: float4Hex(retrievalWeight),
      baseline: baselineByMemory.get(id) || null,
      projections: projectionsByMemory.get(id) || [],
    };
  }).sort((a, b) => a.memory_id.localeCompare(b.memory_id));

  const bundle = {
    format: {
      schema: COGNITIVE_EVIDENCE_SCHEMA,
      version: 1,
      authority: 'descriptive_only',
      binary_encoding: 'lowercase_hex',
      time_encoding: 'unix_seconds',
    },
    company_id: company,
    master_identity: master,
    event_streams: eventStreams,
    memories: memoryRows,
    sql_records: sqlRows.map(normalizeSqlRecord)
      .sort((a, b) => a.memory_id.localeCompare(b.memory_id)),
  };
  canonicalJson(bundle);
  return bundle;
}

function loadPublicKey(pubkeyB64u) {
  return createPublicKey({
    key: Buffer.from(String(pubkeyB64u || ''), 'base64url'),
    format: 'der',
    type: 'spki',
  });
}

function rawVerify(pubkeyB64u, message, signature) {
  try {
    return verifySignature(
      null,
      Buffer.from(message),
      loadPublicKey(pubkeyB64u),
      Buffer.from(signature),
    );
  } catch {
    return false;
  }
}

function certificateBody(certB64u) {
  try {
    return JSON.parse(Buffer.from(String(certB64u || ''), 'base64url').toString('utf8'))?.body || null;
  } catch {
    return null;
  }
}

function verifyCertificate(certB64u, authorityPubkeyB64u, signedTs) {
  let envelope;
  try {
    envelope = JSON.parse(Buffer.from(String(certB64u || ''), 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'cert_malformed', body: null };
  }
  if (!envelope || typeof envelope !== 'object' || !envelope.body || typeof envelope.sig !== 'string') {
    return { valid: false, reason: 'cert_malformed', body: null };
  }
  const body = envelope.body;
  if (REQUIRED_CERT_FIELDS.some((field) => !Object.hasOwn(body, field))) {
    return { valid: false, reason: 'cert_schema', body: null };
  }
  if (!rawVerify(
    authorityPubkeyB64u,
    Buffer.from(canonicalJson(body), 'utf8'),
    Buffer.from(envelope.sig, 'base64url'),
  )) return { valid: false, reason: 'cert_sig_invalid', body: null };
  if (signedTs < Number(body.valid_from)) return { valid: false, reason: 'cert_not_yet_valid', body };
  if (signedTs > Number(body.valid_until)) return { valid: false, reason: 'cert_expired', body };
  return { valid: true, reason: null, body };
}

function verifyStoredSignature(pubkeyB64u, body, nonce, signedTs, signature, context = {}) {
  if (!Number.isSafeInteger(signedTs) || typeof nonce !== 'string' || !nonce) {
    return { valid: false, reason: 'malformed_input' };
  }
  try {
    let message = canonicalJson(body);
    if (context.signatureForm === 2) {
      if (!Number.isSafeInteger(context.memoryOriginatedAt)) return { valid: false, reason: 'malformed_input' };
      message += `\n${nonce}\n${signedTs}\n${context.memoryOriginatedAt}`;
    } else if (context.requestSignatureForm === 3) {
      const method = String(context.method || '').toUpperCase();
      const path = String(context.path || '').split('?')[0];
      if (!method || !path) return { valid: false, reason: 'malformed_input' };
      message += `\n${method}\n${path}\n${nonce}\n${signedTs}`;
    } else if (context.requestSignatureForm === 4) {
      const method = String(context.method || '').toUpperCase();
      const path = String(context.path || '').split('?')[0];
      const previous = context.claims?.prevChainHash ?? context.claims?.prev_chain_hash ?? null;
      const device = context.claims?.deviceFp ?? context.claims?.device_fp ?? null;
      if (!method || !path || typeof previous !== 'string' || !previous
          || (device !== null && (typeof device !== 'string' || !device))) {
        return { valid: false, reason: 'malformed_input' };
      }
      message += `\n${method}\n${path}\n${canonicalJson({ prev_chain_hash: previous, device_fp: device })}\n${nonce}\n${signedTs}`;
    } else {
      message += `\n${nonce}\n${signedTs}`;
    }
    return rawVerify(pubkeyB64u, Buffer.from(message, 'utf8'), signature)
      ? { valid: true, reason: null }
      : { valid: false, reason: 'sig_invalid' };
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }
}

function decodeRevocation(revocation) {
  if (!revocation) return null;
  return {
    agent_id: revocation.agent_id,
    agent_valid_from: isoFromEpoch(revocation.agent_valid_from),
    master_fingerprint: revocation.master_fingerprint,
    target_cert_hash: hexBuffer(revocation.target_cert_hash, 32, 'cognitive_evidence_revocation_target_invalid'),
    prior_identity_hash: hexBuffer(revocation.prior_identity_hash, 32, 'cognitive_evidence_revocation_prior_invalid'),
    signed_body: revocation.signed_body,
    content_hash: hexBuffer(revocation.content_hash, 32, 'cognitive_evidence_revocation_content_invalid'),
    mutation_hash: hexBuffer(revocation.mutation_hash, 32, 'cognitive_evidence_revocation_mutation_invalid'),
    ts_signed: revocation.ts_signed,
    nonce: revocation.nonce,
    sig: hexBuffer(revocation.signature, 64, 'cognitive_evidence_revocation_signature_invalid'),
  };
}

function verifyRevocation(row, masterPubkeyB64u, targetCert) {
  try {
    const body = parseObject(row?.signed_body);
    if (!body || body.schema !== REVOCATION_SCHEMA || body.event_type !== 'REVOKE_AGENT_IDENTITY') {
      return { valid: false, reason: 'revocation_body_invalid' };
    }
    const targetCertHash = sha256(Buffer.from(String(targetCert || ''), 'utf8'));
    const priorIdentityHash = sha256(Buffer.from(canonicalJson({
      agent_id: String(body.agent_id),
      agent_valid_from: new Date(body.agent_valid_from).toISOString(),
      target_cert_hash: targetCertHash.toString('hex'),
    }), 'utf8'));
    const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
    const mutationHash = sha256(Buffer.concat([
      REVOCATION_DOMAIN,
      priorIdentityHash,
      contentHash,
      Buffer.from(row.sig),
    ]));
    const exact = body.agent_id === row.agent_id
      && new Date(body.agent_valid_from).toISOString() === new Date(row.agent_valid_from).toISOString()
      && body.target_cert_hash === targetCertHash.toString('hex')
      && body.prior_identity_hash === priorIdentityHash.toString('hex')
      && body.master_fingerprint === row.master_fingerprint
      && Buffer.from(row.target_cert_hash).equals(targetCertHash)
      && Buffer.from(row.prior_identity_hash).equals(priorIdentityHash)
      && Buffer.from(row.content_hash).equals(contentHash)
      && Buffer.from(row.mutation_hash).equals(mutationHash)
      && Number(row.ts_signed) === Math.floor(new Date(body.revoked_at).getTime() / 1000);
    if (!exact) return { valid: false, reason: 'revocation_hash_mismatch' };
    return verifyStoredSignature(masterPubkeyB64u, body, String(row.nonce), Number(row.ts_signed), row.sig);
  } catch {
    return { valid: false, reason: 'revocation_proof_malformed' };
  }
}

function decodeIdentity(identity, master) {
  return {
    agent_id: identity.agent_id,
    pubkey: identity.pubkey_b64u,
    cert: identity.certificate_b64u,
    device_fp: identity.device_fingerprint,
    valid_from: isoFromEpoch(identity.valid_from),
    valid_until: isoFromEpoch(identity.valid_until),
    master_pubkey: master.public_key_b64u,
    master_fingerprint: master.fingerprint,
    revocation: decodeRevocation(identity.revocation),
  };
}

function verifyIdentityEpoch(identity, signedTs) {
  const certBody = certificateBody(identity?.cert);
  const authorityPubkey = certificateAuthorityPubkey(identity, certBody);
  const certificate = authorityPubkey
    ? verifyCertificate(identity.cert, authorityPubkey, signedTs)
    : { valid: false, reason: 'certificate_authority_missing' };
  const from = Math.floor(new Date(identity?.valid_from).getTime() / 1000);
  const until = Math.floor(new Date(identity?.valid_until).getTime() / 1000);
  const exact = certificate.valid
    && certBody?.agent_id === identity?.agent_id
    && certBody?.pubkey === identity?.pubkey
    && certBody?.device_fp === identity?.device_fp
    && Number(certBody?.valid_from) === from
    && Number(certBody?.valid_until) === until
    && Number.isSafeInteger(signedTs)
    && signedTs >= from
    && signedTs < until;
  if (!exact) return { valid: false, reason: certificate.reason || 'identity_epoch_mismatch' };
  if (!identity.revocation) return { valid: true, reason: null };
  if (identity.revocation.master_fingerprint !== identity.master_fingerprint) {
    return { valid: false, reason: 'revocation_master_mismatch' };
  }
  const revocation = verifyRevocation(identity.revocation, identity.master_pubkey, identity.cert);
  if (!revocation.valid) return { valid: false, reason: `revocation_${revocation.reason}` };
  return Number(identity.revocation.ts_signed) > signedTs
    ? { valid: true, reason: null }
    : { valid: false, reason: 'identity_revoked_before_signature' };
}

function decodeEvent(event, identity) {
  return {
    id: event.event_id,
    company_id: event.company_id,
    agent_id: event.subject_agent_id,
    signer_agent_id: event.signer_agent_id,
    signer_valid_from: isoFromEpoch(event.signer_valid_from),
    cert_fingerprint: event.certificate_fingerprint,
    identity_tier: event.identity_tier,
    authority_kind: event.authority_kind,
    operation: event.operation,
    key: event.key,
    metadata: event.metadata,
    parent_event_id: event.parent_event_id,
    ledger_seq: event.ledger_sequence,
    prev_mutation_hash: hexBuffer(event.previous_mutation_hash, 32, 'cognitive_evidence_event_previous_invalid'),
    content_hash: hexBuffer(event.content_hash, 32, 'cognitive_evidence_event_content_invalid'),
    mutation_hash: hexBuffer(event.mutation_hash, 32, 'cognitive_evidence_event_mutation_invalid'),
    ts_signed: event.signed_at,
    ts: new Date(event.signed_at * 1000),
    nonce: event.nonce,
    sig: hexBuffer(event.signature, 64, 'cognitive_evidence_event_signature_invalid'),
    proof_required: event.proof_required,
    ledger_version: event.ledger_version,
    signed_body: event.signed_body,
    pubkey: identity.pubkey,
    cert: identity.cert,
    device_fp: identity.device_fp,
    valid_until: identity.valid_until,
    revocation_master_fingerprint: identity.revocation?.master_fingerprint ?? null,
    revocation_target_cert_hash: identity.revocation?.target_cert_hash ?? null,
    revocation_prior_identity_hash: identity.revocation?.prior_identity_hash ?? null,
    revocation_signed_body: identity.revocation?.signed_body ?? null,
    revocation_content_hash: identity.revocation?.content_hash ?? null,
    revocation_mutation_hash: identity.revocation?.mutation_hash ?? null,
    revocation_ts_signed: identity.revocation?.ts_signed ?? null,
    revocation_nonce: identity.revocation?.nonce ?? null,
    revocation_sig: identity.revocation?.sig ?? null,
  };
}

function verifyEventProof(row, signerPubkey) {
  try {
    const body = parseObject(row.signed_body);
    if (!body || row.proof_required !== true || Number(row.ledger_version) !== 1) {
      return { valid: false, reason: 'event_proof_version' };
    }
    const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
    const mutationHash = eventMutationHash(
      Buffer.from(row.prev_mutation_hash),
      contentHash,
      String(row.nonce),
      Number(row.ts_signed),
    );
    const exact = body.event_id === row.id
      && body.company_id === row.company_id
      && body.subject_agent_id === row.agent_id
      && body.signer_agent_id === row.signer_agent_id
      && new Date(body.signer_valid_from).toISOString() === new Date(row.signer_valid_from).toISOString()
      && body.cert_fingerprint === row.cert_fingerprint
      && body.identity_tier === row.identity_tier
      && body.authority_kind === row.authority_kind
      && body.operation === row.operation
      && body.key === row.key
      && canonicalJson(body.metadata) === canonicalJson(row.metadata)
      && body.parent_event_id === (row.parent_event_id || null)
      && Number(body.ledger_seq) === Number(row.ledger_seq)
      && body.prev_mutation_hash === Buffer.from(row.prev_mutation_hash).toString('hex')
      && Number(body.ts_signed) === Number(row.ts_signed)
      && new Date(row.ts).getTime() === Number(row.ts_signed) * 1000
      && Buffer.from(row.content_hash).equals(contentHash)
      && Buffer.from(row.mutation_hash).equals(mutationHash);
    if (!exact) return { valid: false, reason: 'event_proof_hash_mismatch' };
    return verifyStoredSignature(signerPubkey, body, String(row.nonce), Number(row.ts_signed), row.sig);
  } catch {
    return { valid: false, reason: 'event_proof_malformed' };
  }
}

function verifyEventStream(rows, masterPubkey, masterFingerprintValue) {
  let previous = null;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (index === 0) {
      previous = eventGenesisHash(row.company_id, row.signer_agent_id, row.signer_valid_from);
    }
    if (Number(row.ledger_seq) !== index + 1 || !Buffer.from(row.prev_mutation_hash).equals(previous)) {
      throw new Error('event_ledger_chain_link_invalid');
    }
    const certBody = certificateBody(row.cert);
    const certFingerprint = sha256(Buffer.from(String(row.cert), 'utf8')).toString('hex');
    if (!certBody || certBody.agent_id !== row.signer_agent_id
        || certBody.pubkey !== row.pubkey || certFingerprint !== row.cert_fingerprint) {
      throw new Error('event_ledger_identity_mismatch');
    }
    const authority = certificateAuthorityPubkey({
      pubkey: row.pubkey,
      master_pubkey: masterPubkey,
      master_fingerprint: masterFingerprintValue,
    }, certBody);
    if (!authority) throw new Error('event_ledger_certificate_issuer_invalid');
    const certificate = authority
      ? verifyCertificate(row.cert, authority, Number(row.ts_signed))
      : { valid: false, reason: 'event_ledger_master_identity_missing' };
    if (!certificate.valid) throw new Error(`event_ledger_certificate_invalid:${certificate.reason}`);
    if (row.revocation_ts_signed != null && Number(row.revocation_ts_signed) <= Number(row.ts_signed)) {
      throw new Error('event_ledger_signer_revoked_at_signature_time');
    }
    const proof = verifyEventProof(row, row.pubkey);
    if (!proof.valid) throw new Error(`event_ledger_proof_invalid:${proof.reason}`);
    previous = Buffer.from(row.mutation_hash);
  }
  return true;
}

function provenanceMutationHash(contentHash, previousHash, nonce, signedTs, originatedAt = null) {
  const parts = previousHash
    ? [contentHash, previousHash, Buffer.from(nonce, 'utf8'), Buffer.from(String(signedTs), 'utf8')]
    : [contentHash, Buffer.from(nonce, 'utf8'), Buffer.from(String(signedTs), 'utf8')];
  if (originatedAt !== null) parts.push(Buffer.from(String(originatedAt), 'utf8'));
  return sha256(Buffer.concat(parts));
}

function verifyReweightProvenance(row) {
  const body = parseObject(row.body_json);
  if (!body) return { valid: false, reason: 'signed_body_missing' };
  if (!row.signer_pubkey || !row.signer_cert || !row.agent_valid_from) {
    return { valid: false, reason: 'signer_epoch_missing' };
  }
  if (!Buffer.isBuffer(row.sig) || row.sig.length !== 64) {
    return { valid: false, reason: 'signature_missing' };
  }
  const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  if (!contentHash.equals(Buffer.from(row.prov_content_hash))) {
    return { valid: false, reason: 'signed_body_content_hash_mismatch' };
  }
  const fingerprint = sha256(Buffer.from(String(row.signer_cert), 'utf8')).toString('hex');
  if (fingerprint !== row.cert_fingerprint) {
    return { valid: false, reason: 'signer_certificate_fingerprint_mismatch' };
  }
  const signedTs = Number(row.ts_signed);
  const certBody = certificateBody(row.signer_cert);
  if (!certBody) return { valid: false, reason: 'signer_certificate_malformed' };
  const authority = certificateAuthorityPubkey({
    pubkey: row.signer_pubkey,
    master_pubkey: row.master_pubkey,
    master_fingerprint: row.master_fingerprint,
  }, certBody);
  if (!authority) return { valid: false, reason: 'certificate_authority_missing' };
  const certificate = verifyCertificate(row.signer_cert, authority, signedTs);
  const validFrom = Math.floor(new Date(row.agent_valid_from).getTime() / 1000);
  const validUntil = Math.floor(new Date(row.signer_valid_until).getTime() / 1000);
  if (!certificate.valid || certBody.agent_id !== row.provenance_agent_id
      || certBody.pubkey !== row.signer_pubkey || certBody.device_fp !== row.signer_device_fp
      || Number(certBody.valid_from) !== validFrom || Number(certBody.valid_until) !== validUntil) {
    return { valid: false, reason: certificate.reason || 'signer_certificate_row_mismatch' };
  }
  if (row.revocation_sig) {
    const revocation = verifyRevocation({
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
  const signatureForm = Number(row.sig_form_version || 1);
  const requestForm = Number(row.request_sig_form || 1);
  const claims = parseObject(row.signed_claims);
  if (Boolean(row.is_genesis) !== (row.prev_mutation_hash == null)) {
    return { valid: false, reason: 'provenance_genesis_shape_invalid' };
  }
  if (['T2', 'T3'].includes(String(row.identity_tier)) && requestForm !== 4) {
    return { valid: false, reason: 'elevated_provenance_requires_form4' };
  }
  if (requestForm === 4) {
    let previousClaim = null;
    try { previousClaim = Buffer.from(String(claims?.prev_chain_hash || ''), 'base64url'); } catch { /* invalid below */ }
    if (!previousClaim || previousClaim.length !== 32) return { valid: false, reason: 'signed_chain_claim_invalid' };
    if (String(row.identity_tier) === 'T3' && claims?.device_fp !== row.signer_device_fp) {
      return { valid: false, reason: 'signed_device_claim_mismatch' };
    }
  }
  const originatedAt = row.memory_originated_at
    ? Math.floor(new Date(row.memory_originated_at).getTime() / 1000)
    : null;
  const signature = verifyStoredSignature(
    row.signer_pubkey,
    body,
    String(row.nonce || ''),
    signedTs,
    row.sig,
    {
      signatureForm,
      requestSignatureForm: requestForm,
      memoryOriginatedAt: originatedAt,
      method: row.signed_method,
      path: row.signed_path,
      claims,
    },
  );
  if (!signature.valid) return { valid: false, reason: signature.reason || 'signature_invalid' };
  const expectedMutation = provenanceMutationHash(
    contentHash,
    row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null,
    String(row.nonce || ''),
    signedTs,
    signatureForm === 2 ? originatedAt : null,
  );
  if (!expectedMutation.equals(Buffer.from(row.mutation_hash))) {
    return { valid: false, reason: 'mutation_hash_mismatch' };
  }
  if (String(row.event_type || '') !== 'REWEIGHT' || body.event_type !== 'REWEIGHT') {
    return { valid: false, reason: 'signed_body_event_type_mismatch' };
  }
  return { valid: true, reason: null };
}

function float4(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeFloatBE(Number(value));
  return bytes;
}

function isoOrNull(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function verifyPortableCognitiveBaseline({ baseline, memory, identity, revocation, event }) {
  if (!baseline) return { valid: false, reason: 'baseline_missing' };
  const observedFloat = float4(baseline.observed_weight);
  const certFingerprint = sha256(Buffer.from(String(identity?.cert || ''), 'utf8')).toString('hex');
  const identityProof = verifyIdentityEpoch({ ...identity, revocation }, Number(baseline.observed_ts));
  const exact = baseline.company_id === memory.company_id
    && String(baseline.memory_id) === String(memory.id)
    && Buffer.from(baseline.live_content_hash).equals(Buffer.from(memory.content_hash))
    && observedFloat.equals(Buffer.from(baseline.observed_weight_float4))
    && !observedFloat.equals(float4(1))
    && Math.round(Number(baseline.observed_weight) * 1000) === Number(baseline.retrieval_weight_milli)
    && baseline.attestation_reason === 'retained_nondefault_weight_baseline'
    && baseline.historical_origin_claimed === false
    && baseline.signer_agent_id === 'housekeeper'
    && isoOrNull(identity?.valid_from) !== null
    && isoOrNull(identity?.valid_from) === isoOrNull(baseline.signer_valid_from)
    && certFingerprint === baseline.cert_fingerprint
    && identityProof.valid;
  if (!exact) return { valid: false, reason: identityProof.reason || 'baseline_binding_invalid' };
  if (!event || String(event.id) !== String(baseline.event_id)
      || Buffer.from(event.mutation_hash).toString('hex') !== Buffer.from(baseline.event_mutation_hash).toString('hex')) {
    return { valid: false, reason: 'baseline_event_missing' };
  }
  if (event.company_id !== baseline.company_id
      || event.signer_agent_id !== baseline.signer_agent_id
      || isoOrNull(event.signer_valid_from) === null
      || isoOrNull(event.signer_valid_from) !== isoOrNull(baseline.signer_valid_from)
      || event.cert_fingerprint !== baseline.cert_fingerprint
      || event.event_stream_verified !== true
      || Math.abs(Number(event.ts_signed) - Number(baseline.observed_ts)) > 5
      || !verifyIdentityEpoch({ ...identity, revocation }, Number(event.ts_signed)).valid) {
    return { valid: false, reason: 'baseline_event_epoch_invalid' };
  }
  const eventProof = verifyEventProof(event, identity.pubkey);
  if (!eventProof.valid) return { valid: false, reason: `baseline_event_${eventProof.reason}` };
  const metadata = parseObject(event.metadata);
  if (event.operation !== 'cognitive_initial_weight_attested'
      || event.key !== String(memory.id)
      || metadata?.schema !== 'hom.aimos.cognitive-initial-weight/v1'
      || metadata?.observed_weight_float4 !== observedFloat.toString('hex')
      || Number(metadata?.weight_milli) !== Number(baseline.retrieval_weight_milli)
      || Number(metadata?.observed_ts) !== Number(baseline.observed_ts)
      || metadata?.memory_content_hash !== Buffer.from(memory.content_hash).toString('hex')
      || metadata?.historical_origin_claimed !== false
      || metadata?.canonical_memory_mutation !== false) {
    return { valid: false, reason: 'baseline_event_binding_invalid' };
  }
  const expectedHash = cognitiveBaselineHash({
    companyId: baseline.company_id,
    memoryId: baseline.memory_id,
    eventId: baseline.event_id,
    eventMutationHash: Buffer.from(baseline.event_mutation_hash),
    liveContentHash: Buffer.from(baseline.live_content_hash),
    observedWeight: Number(baseline.observed_weight),
    weightMilli: Number(baseline.retrieval_weight_milli),
    observedTs: Number(baseline.observed_ts),
    signerValidFromIso: baseline.signer_valid_from,
    certFingerprint: baseline.cert_fingerprint,
  });
  if (!expectedHash.equals(Buffer.from(baseline.baseline_hash))) {
    return { valid: false, reason: 'baseline_hash_invalid' };
  }
  if (!rawVerify(identity.pubkey, expectedHash, baseline.baseline_sig)) {
    return { valid: false, reason: 'baseline_signature_invalid' };
  }
  return { valid: true, reason: null, baselineHash: expectedHash };
}

function orderProjectionRows(rows) {
  if (!rows.length) return [];
  const byHash = new Map();
  const childByPrevious = new Map();
  const genesis = [];
  for (const row of rows) {
    const hash = Buffer.from(row.projection_hash).toString('hex');
    const previous = row.prev_projection_hash ? Buffer.from(row.prev_projection_hash).toString('hex') : null;
    if (byHash.has(hash) || (previous && childByPrevious.has(previous))) throw new Error('cognitive_projection_fork');
    byHash.set(hash, row);
    if (previous) childByPrevious.set(previous, row);
    else genesis.push(row);
  }
  if (genesis.length !== 1) throw new Error('cognitive_projection_genesis_invalid');
  const ordered = [];
  const visited = new Set();
  let current = genesis[0];
  while (current) {
    const hash = Buffer.from(current.projection_hash).toString('hex');
    if (visited.has(hash)) throw new Error('cognitive_projection_cycle');
    visited.add(hash);
    ordered.push(current);
    current = childByPrevious.get(hash) || null;
  }
  if (ordered.length !== rows.length) throw new Error('cognitive_projection_disconnected');
  return ordered;
}

export function verifyPortableCognitiveState({ memory, baseline = null, baselineEvent = null, projections = [] }) {
  const baselineProof = baseline
    ? verifyPortableCognitiveBaseline({
        baseline,
        memory,
        identity: baseline.identity,
        revocation: baseline.revocation,
        event: baselineEvent,
      })
    : null;
  if (!projections.length) {
    if (baseline) {
      const valid = baselineProof.valid
        && float4(memory.retrieval_weight).equals(float4(baseline.observed_weight));
      return {
        memory_id: String(memory.id),
        certification_status: 'signed_initial_weight',
        ok: valid,
        chain_length: 0,
        sigs_verified: 0,
        reason: valid ? null : baselineProof.reason || 'baseline_terminal_weight_mismatch',
      };
    }
    const isDefault = float4(memory.retrieval_weight).equals(float4(1));
    return {
      memory_id: String(memory.id),
      certification_status: isDefault ? 'default_empty_chain' : 'unattested_initial_weight',
      ok: isDefault,
      chain_length: 0,
      sigs_verified: 0,
      reason: isDefault ? null : 'unattested_initial_weight',
    };
  }

  let ordered;
  try { ordered = orderProjectionRows(projections); } catch (error) {
    return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: 0, sigs_verified: 0, reason: error.message };
  }
  let previousHash = null;
  let previousMilli = null;
  let signatures = 0;
  for (const [index, row] of ordered.entries()) {
    const oldMilli = Number(row.old_weight_milli);
    const newMilli = Number(row.new_weight_milli);
    if (!Number.isInteger(oldMilli) || !Number.isInteger(newMilli)
        || oldMilli < 100 || oldMilli > 3000 || newMilli < 100 || newMilli > 3000
        || oldMilli === newMilli
        || !float4(row.old_weight).equals(float4(oldMilli / 1000))
        || !float4(row.new_weight).equals(float4(newMilli / 1000))) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'projection_display_invalid' };
    }
    if (previousMilli !== null && oldMilli !== previousMilli) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'continuity_break' };
    }
    const provenance = row.provenance;
    const provenanceProof = verifyReweightProvenance(provenance);
    const provenanceBody = parseObject(provenance.body_json);
    const provenanceBound = provenance.event_type === 'REWEIGHT'
      && Number(provenance.binding_schema_version) === 2
      && provenance.provenance_agent_id === 'housekeeper'
      && provenance.backfilled === false
      && provenanceBody?.event_type === 'REWEIGHT'
      && provenanceBody?.company_id === memory.company_id
      && String(provenanceBody?.memory_id) === String(memory.id)
      && Math.round(Number(provenanceBody?.old_weight) * 1000) === oldMilli
      && Math.round(Number(provenanceBody?.new_weight) * 1000) === newMilli
      && String(row.company_id) === String(memory.company_id)
      && String(row.memory_id) === String(memory.id)
      && Buffer.from(row.provenance_mutation_hash).equals(Buffer.from(provenance.mutation_hash));
    if (!provenanceProof.valid || !provenanceBound) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: `provenance_${provenanceProof.reason || 'event_type_invalid'}` };
    }
    const expectedProjection = cognitiveProjectionHash({
      memoryId: memory.id,
      oldWeightMilli: oldMilli,
      newWeightMilli: newMilli,
      provenanceMutationHash: Buffer.from(row.provenance_mutation_hash),
      previousHash,
    });
    if (!expectedProjection.equals(Buffer.from(row.projection_hash))) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'projection_hash_invalid' };
    }
    const expectedTransition = cognitiveTransitionHash({
      companyId: memory.company_id,
      memoryId: memory.id,
      oldWeight: oldMilli / 1000,
      newWeight: newMilli / 1000,
      provenanceMutationHash: Buffer.from(row.provenance_mutation_hash),
    });
    if (!expectedTransition.equals(Buffer.from(row.transition_hash))
        || !rawVerify(provenance.signer_pubkey, expectedTransition, row.transition_sig)) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'transition_signature_invalid' };
    }
    previousHash = expectedProjection;
    previousMilli = newMilli;
    signatures += 1;
  }
  if (baseline && (!baselineProof.valid || Number(baseline.retrieval_weight_milli) !== Number(ordered[0].old_weight_milli))) {
    return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: ordered.length, sigs_verified: signatures, reason: 'baseline_chain_anchor_invalid' };
  }
  if (!baseline && Number(ordered[0].old_weight_milli) !== 1000) {
    return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: ordered.length, sigs_verified: signatures, reason: 'default_chain_anchor_invalid' };
  }
  const terminalValid = float4(memory.retrieval_weight).equals(float4(previousMilli / 1000));
  return {
    memory_id: String(memory.id),
    certification_status: 'certified_chain',
    ok: terminalValid,
    chain_length: ordered.length,
    sigs_verified: signatures,
    reason: terminalValid ? null : 'terminal_weight_mismatch',
  };
}

function decodeBaseline(baseline, master) {
  if (!baseline) return null;
  const identity = decodeIdentity(baseline.identity, master);
  return {
    baseline_id: baseline.baseline_id,
    company_id: baseline.company_id,
    memory_id: baseline.memory_id,
    event_id: baseline.event_id,
    event_mutation_hash: hexBuffer(baseline.event_mutation_hash, 32, 'cognitive_evidence_baseline_event_invalid'),
    live_content_hash: hexBuffer(baseline.live_content_hash, 32, 'cognitive_evidence_baseline_content_invalid'),
    observed_weight: float4FromHex(baseline.observed_weight_float4),
    observed_weight_float4: hexBuffer(baseline.observed_weight_float4, 4, 'cognitive_evidence_baseline_float4_invalid'),
    retrieval_weight_milli: baseline.observed_weight_milli,
    observed_ts: baseline.observed_at,
    attestation_reason: baseline.attestation_reason,
    historical_origin_claimed: baseline.historical_origin_claimed,
    signer_agent_id: baseline.signer_agent_id,
    signer_valid_from: isoFromEpoch(baseline.signer_valid_from),
    cert_fingerprint: baseline.certificate_fingerprint,
    baseline_hash: hexBuffer(baseline.baseline_hash, 32, 'cognitive_evidence_baseline_hash_invalid'),
    baseline_sig: hexBuffer(baseline.signature, 64, 'cognitive_evidence_baseline_signature_invalid'),
    identity,
    revocation: identity.revocation,
  };
}

function decodeProjection(projection, master) {
  const identity = decodeIdentity(projection.provenance.identity, master);
  const provenance = projection.provenance;
  return {
    projection_id: projection.projection_id,
    company_id: projection.company_id,
    memory_id: projection.memory_id,
    old_weight: float4FromHex(projection.old_weight_float4),
    new_weight: float4FromHex(projection.new_weight_float4),
    old_weight_milli: projection.old_weight_milli,
    new_weight_milli: projection.new_weight_milli,
    provenance_mutation_hash: hexBuffer(projection.provenance_mutation_hash, 32, 'cognitive_evidence_projection_provenance_invalid'),
    prev_projection_hash: projection.previous_projection_hash == null
      ? null
      : hexBuffer(projection.previous_projection_hash, 32, 'cognitive_evidence_projection_previous_invalid'),
    projection_hash: hexBuffer(projection.projection_hash, 32, 'cognitive_evidence_projection_hash_invalid'),
    transition_hash: hexBuffer(projection.transition_hash, 32, 'cognitive_evidence_transition_hash_invalid'),
    transition_sig: hexBuffer(projection.transition_signature, 64, 'cognitive_evidence_transition_signature_invalid'),
    provenance: {
      provenance_id: provenance.provenance_id,
      memory_id: projection.memory_id,
      body_json: provenance.body,
      prov_content_hash: hexBuffer(provenance.content_hash, 32, 'cognitive_evidence_provenance_content_invalid'),
      mutation_hash: hexBuffer(provenance.mutation_hash, 32, 'cognitive_evidence_provenance_mutation_invalid'),
      prev_mutation_hash: provenance.previous_mutation_hash == null
        ? null
        : hexBuffer(provenance.previous_mutation_hash, 32, 'cognitive_evidence_provenance_previous_invalid'),
      ts_signed: provenance.signed_at,
      nonce: provenance.nonce,
      sig: hexBuffer(provenance.signature, 64, 'cognitive_evidence_provenance_signature_invalid'),
      event_type: provenance.event_type,
      binding_schema_version: provenance.binding_schema_version,
      provenance_agent_id: provenance.signer_agent_id,
      agent_valid_from: isoFromEpoch(provenance.signer_valid_from),
      cert_fingerprint: provenance.certificate_fingerprint,
      identity_tier: provenance.identity_tier,
      sig_form_version: provenance.signature_form,
      request_sig_form: provenance.request_signature_form,
      signed_method: provenance.signed_method,
      signed_path: provenance.signed_path,
      signed_claims: provenance.signed_claims,
      is_genesis: provenance.is_genesis,
      backfilled: provenance.backfilled,
      memory_originated_at: provenance.memory_originated_at == null
        ? null
        : isoFromEpoch(provenance.memory_originated_at),
      signer_pubkey: identity.pubkey,
      signer_cert: identity.cert,
      signer_valid_until: identity.valid_until,
      signer_device_fp: identity.device_fp,
      master_pubkey: identity.master_pubkey,
      master_fingerprint: identity.master_fingerprint,
      revocation_master_fingerprint: identity.revocation?.master_fingerprint ?? null,
      revocation_target_cert_hash: identity.revocation?.target_cert_hash ?? null,
      revocation_prior_identity_hash: identity.revocation?.prior_identity_hash ?? null,
      revocation_signed_body: identity.revocation?.signed_body ?? null,
      revocation_content_hash: identity.revocation?.content_hash ?? null,
      revocation_mutation_hash: identity.revocation?.mutation_hash ?? null,
      revocation_ts_signed: identity.revocation?.ts_signed ?? null,
      revocation_nonce: identity.revocation?.nonce ?? null,
      revocation_sig: identity.revocation?.sig ?? null,
    },
  };
}

export function verifyCognitiveWeightEvidenceBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    throw new Error('cognitive_evidence_bundle_invalid');
  }
  const expectedKeys = ['company_id', 'event_streams', 'format', 'master_identity', 'memories', 'sql_records'];
  if (Object.keys(bundle).sort().join('\0') !== expectedKeys.join('\0')
      || bundle.format?.schema !== COGNITIVE_EVIDENCE_SCHEMA
      || bundle.format?.version !== 1
      || bundle.format?.authority !== 'descriptive_only'
      || bundle.format?.binary_encoding !== 'lowercase_hex'
      || bundle.format?.time_encoding !== 'unix_seconds'
      || !Array.isArray(bundle.event_streams)
      || !Array.isArray(bundle.memories)
      || !Array.isArray(bundle.sql_records)) {
    throw new Error('cognitive_evidence_bundle_schema_invalid');
  }
  const company = String(bundle.company_id || '').trim();
  const master = bundle.master_identity;
  if (!company || !master?.public_key_b64u || !/^[0-9a-f]{64}$/.test(String(master.fingerprint || ''))) {
    throw new Error('cognitive_evidence_bundle_identity_invalid');
  }
  if (masterFingerprint(master.public_key_b64u) !== master.fingerprint) {
    throw new Error('cognitive_evidence_master_fingerprint_mismatch');
  }
  canonicalJson(bundle);

  const verifiedEventIds = new Set();
  const eventStreamResults = [];
  for (const stream of bundle.event_streams) {
    let valid = true;
    let reason = null;
    try {
      const identity = decodeIdentity(stream.identity, master);
      if (identity.agent_id !== stream.signer_agent_id
          || epochSeconds(identity.valid_from, 'cognitive_evidence_event_epoch_invalid') !== stream.signer_valid_from) {
        throw new Error('cognitive_evidence_event_identity_mismatch');
      }
      const rows = stream.events.map((event) => decodeEvent(event, identity));
      for (const row of rows) {
        if (row.company_id !== company || row.signer_agent_id !== identity.agent_id
            || !verifyIdentityEpoch(identity, Number(row.ts_signed)).valid) {
          valid = false;
          reason = 'cognitive_evidence_event_identity_epoch_invalid';
        }
      }
      if (valid) verifyEventStream(rows, master.public_key_b64u, master.fingerprint);
      if (valid) for (const row of rows) verifiedEventIds.add(String(row.id));
    } catch (error) {
      valid = false;
      reason = error instanceof Error ? error.message : 'cognitive_evidence_event_stream_invalid';
    }
    eventStreamResults.push({
      signer_agent_id: String(stream.signer_agent_id || ''),
      signer_valid_from: stream.signer_valid_from,
      event_count: Array.isArray(stream.events) ? stream.events.length : 0,
      valid,
      reason: valid ? null : reason || 'cognitive_evidence_event_stream_invalid',
    });
  }

  const eventById = new Map();
  for (const stream of bundle.event_streams) {
    const identity = decodeIdentity(stream.identity, master);
    for (const event of stream.events) {
      const row = decodeEvent(event, identity);
      if (eventById.has(String(row.id))) throw new Error('cognitive_evidence_event_duplicate');
      eventById.set(String(row.id), {
        ...row,
        event_stream_verified: verifiedEventIds.has(String(row.id)),
      });
    }
  }

  const records = [];
  let previousMemoryId = null;
  for (const item of bundle.memories) {
    const memoryId = String(item.memory_id || '');
    if (!memoryId || (previousMemoryId !== null && memoryId <= previousMemoryId)
        || item.company_id !== company) {
      throw new Error('cognitive_evidence_memory_order_invalid');
    }
    previousMemoryId = memoryId;
    const memory = {
      id: memoryId,
      company_id: company,
      content_hash: hexBuffer(item.content_hash, 32, 'cognitive_evidence_memory_content_invalid'),
      retrieval_weight: float4FromHex(item.retrieval_weight_float4),
    };
    if (Math.round(memory.retrieval_weight * 1000) !== Number(item.retrieval_weight_milli)) {
      throw new Error('cognitive_evidence_memory_weight_invalid');
    }
    const baseline = decodeBaseline(item.baseline, master);
    const projections = item.projections.map((projection) => decodeProjection(projection, master));
    try {
      records.push(verifyPortableCognitiveState({
        memory,
        baseline,
        baselineEvent: baseline ? eventById.get(String(baseline.event_id)) || null : null,
        projections,
      }));
    } catch {
      records.push({
        memory_id: memoryId,
        certification_status: projections.length
          ? 'certified_chain'
          : baseline
            ? 'signed_initial_weight'
            : 'unattested_initial_weight',
        ok: false,
        chain_length: 0,
        sigs_verified: 0,
        reason: 'portable_evidence_malformed',
      });
    }
  }

  const sqlRows = bundle.sql_records.map((row) => ({
    memory_id: row.memory_id,
    certification_status: row.certification_status,
    ok: row.ok,
    chain_length: row.chain_length,
    sigs_verified: row.signatures_verified,
    reason: row.reason,
  }));
  const sqlById = new Map(sqlRows.map((row) => [String(row.memory_id), row]));
  const parity = records.every((record) => {
    const sql = sqlById.get(record.memory_id);
    return sql && Boolean(sql.ok) === record.ok
      && sql.certification_status === record.certification_status
      && Number(sql.chain_length) === record.chain_length
      && Number(sql.sigs_verified) === record.sigs_verified
      && (sql.reason ?? null) === (record.reason ?? null);
  }) && sqlRows.length === records.length;
  const proofRecords = records.map((record) => ({
    memory_id: record.memory_id,
    certification_status: record.certification_status,
    ok: record.ok,
    chain_length: record.chain_length,
    sigs_verified: record.sigs_verified,
    reason: record.reason,
  }));
  return {
    records,
    sqlRows,
    parity,
    proofRoot: cognitiveCorpusRoot(proofRecords),
    bundleSha256: sha256(Buffer.from(canonicalJson(bundle), 'utf8')),
    eventStreamResults,
  };
}
