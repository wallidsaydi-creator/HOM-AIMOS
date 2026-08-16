// ─── PIPELINE CONNECTIONS ───────────────────────────────────────────────────────────────────────────────
// ← Called by: N1-D ceremony and the native evidence-assertion commit owner
// → Calls: Ed25519 identity primitives + exact evidence-assertion verifier
// Pipeline: SECURITY | Master authorization for one exact evidence assertion
// Authority: no label, save, recall, ranking, deletion, or antigen authority
// ───────────────────────────────────────────────────────────────────────────────

import { createHash, randomBytes } from 'node:crypto';

import {
  canonicalJson,
  pubkeyFingerprint,
  signPayload,
  verifyStoredPayloadSig,
} from './agent-identity.js';
import { verifyMemoryEpistemicEvidenceAssertion } from './memory-epistemic-evidence-assertion.js';

export const MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_BODY_SCHEMA =
  'hom.aimos.memory-epistemic-evidence-authorization/v1';
export const MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_ENVELOPE_SCHEMA =
  'hom.aimos.memory-epistemic-evidence-authorization-envelope/v1';
export const MEMORY_EPISTEMIC_ASSERTION_AUTHORITY_SCOPE =
  'append_one_exact_memory_epistemic_evidence_assertion_only';

const APPROVAL_HASH_DOMAIN = Buffer.from(
  'hom-aimos/memory-epistemic-evidence/master-approval/v1\0',
  'utf8',
);
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(code, detail = '') {
  throw new Error(`epistemic_evidence_authorization_${code}${detail ? `:${detail}` : ''}`);
}

function assert(condition, code, detail = '') {
  if (!condition) fail(code, detail);
}

function exactHash(value, code) {
  const normalized = String(value || '').toLowerCase();
  assert(HEX64.test(normalized), code);
  return normalized;
}

function exactUuid(value, code) {
  const normalized = String(value || '').toLowerCase();
  assert(UUID.test(normalized), code);
  return normalized;
}

function exactIso(value, code) {
  const parsed = new Date(value);
  assert(!Number.isNaN(parsed.getTime()), code);
  return parsed.toISOString();
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

export function sha256AuthorizationCanonical(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8')).toString('hex');
}

function domainHash(domain, parts) {
  const hash = createHash('sha256');
  hash.update(domain);
  for (const part of parts) {
    const bytes = Buffer.isBuffer(part) ? part : Buffer.from(String(part), 'utf8');
    const length = Buffer.alloc(4);
    assert(bytes.length <= 0xffffffff, 'hash_part_too_large');
    length.writeUInt32BE(bytes.length);
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest('hex');
}

function approvalHash({ body, master_pubkey: masterPubkey, nonce, ts_signed: tsSigned, sig }) {
  return domainHash(APPROVAL_HASH_DOMAIN, [
    canonicalJson(body),
    masterPubkey,
    nonce,
    String(tsSigned),
    Buffer.from(String(sig), 'base64url'),
  ]);
}

function normalizeHousekeeperSigner(value = {}) {
  const signer = Object.freeze({
    agent_id: String(value.agent_id || ''),
    valid_from: exactIso(value.valid_from, 'housekeeper_valid_from_invalid'),
    cert_fingerprint: exactHash(
      value.cert_fingerprint,
      'housekeeper_cert_fingerprint_invalid',
    ),
    identity_tier: String(value.identity_tier || ''),
  });
  assert(signer.agent_id === 'housekeeper', 'housekeeper_agent_invalid');
  assert(signer.identity_tier === 'T1', 'housekeeper_identity_tier_invalid');
  return signer;
}

function normalizeClassificationSource(value = {}) {
  const source = Object.freeze({
    event_id: exactUuid(value.event_id, 'classification_event_id_invalid'),
    event_content_sha256: exactHash(
      value.event_content_sha256,
      'classification_event_content_hash_invalid',
    ),
    event_mutation_sha256: exactHash(
      value.event_mutation_sha256,
      'classification_event_mutation_hash_invalid',
    ),
    signer_agent_id: String(value.signer_agent_id || ''),
    signer_valid_from: exactIso(value.signer_valid_from, 'classification_signer_epoch_invalid'),
    signer_cert_fingerprint: exactHash(
      value.signer_cert_fingerprint,
      'classification_signer_cert_fingerprint_invalid',
    ),
    classifier_version: String(value.classifier_version || ''),
    label: String(value.label || ''),
    confidence_milli: Number(value.confidence_milli),
    save_mutation_sha256: exactHash(
      value.save_mutation_sha256,
      'classification_save_mutation_hash_invalid',
    ),
    binding_mutation_sha256: exactHash(
      value.binding_mutation_sha256,
      'classification_binding_mutation_hash_invalid',
    ),
  });
  assert(source.signer_agent_id === 'housekeeper', 'classification_signer_invalid');
  assert(source.classifier_version && source.classifier_version.length <= 128,
    'classification_version_invalid');
  assert(['poison_suspect', 'poison_likely', 'poison_confirmed'].includes(source.label),
    'classification_label_not_poison_evidence');
  assert(Number.isSafeInteger(source.confidence_milli)
    && source.confidence_milli >= 0
    && source.confidence_milli <= 1000,
  'classification_confidence_invalid');
  return source;
}

export function deterministicEvidenceAssertionId(value) {
  const hex = sha256AuthorizationCanonical(value).slice(0, 32).split('');
  hex[12] = '5';
  hex[16] = ['8', '9', 'a', 'b'][Number.parseInt(hex[16], 16) % 4];
  const joined = hex.join('');
  return `${joined.slice(0, 8)}-${joined.slice(8, 12)}-${joined.slice(12, 16)}-${joined.slice(16, 20)}-${joined.slice(20)}`;
}

export function buildMemoryEpistemicEvidenceAuthorizationBody({
  companyId,
  assertion,
  classificationSource,
  masterFingerprint,
  masterEpoch,
  housekeeperSigner,
  reason,
  signedTs = Math.floor(Date.now() / 1000),
} = {}) {
  const verifiedAssertion = verifyMemoryEpistemicEvidenceAssertion(assertion);
  const source = normalizeClassificationSource(classificationSource);
  const signer = normalizeHousekeeperSigner(housekeeperSigner);
  const company = String(companyId || '').trim();
  const normalizedReason = String(reason || '').trim();
  assert(company && company.length <= 128, 'company_invalid');
  assert(normalizedReason.length >= 32 && normalizedReason.length <= 1000, 'reason_invalid');
  assert(Number.isSafeInteger(signedTs) && signedTs > 0, 'signed_ts_invalid');
  assert(verifiedAssertion.evidence_record.evidence_type === 'classification_history',
    'assertion_evidence_type_invalid');
  assert(verifiedAssertion.evidence_record.artifact_sha256 === source.event_content_sha256
    && verifiedAssertion.evidence_record.provenance_sha256 === source.event_mutation_sha256,
  'assertion_classification_source_mismatch');
  assert(verifiedAssertion.claim_record.relation === 'supports',
    'assertion_relation_not_supporting');
  assert(verifiedAssertion.evidence_record.source_independence.status === 'dependent',
    'assertion_source_independence_overclaimed');
  return Object.freeze({
    schema: MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_BODY_SCHEMA,
    event_type: 'AUTHORIZE_MEMORY_EPISTEMIC_EVIDENCE_ASSERTION',
    company_id: company,
    authority_scope: MEMORY_EPISTEMIC_ASSERTION_AUTHORITY_SCOPE,
    subject_agent_id: signer.agent_id,
    subject_memory_id: verifiedAssertion.hypothesis.subject_memory_id,
    subject_live_content_hash: verifiedAssertion.hypothesis.subject_live_content_hash,
    hypothesis_sha256: verifiedAssertion.hypothesis.hypothesis_sha256,
    assertion_sha256: verifiedAssertion.assertion_sha256,
    claim_sha256: verifiedAssertion.claim_record.claim_sha256,
    evidence_artifact_sha256: verifiedAssertion.evidence_record.artifact_sha256,
    evidence_provenance_sha256: verifiedAssertion.evidence_record.provenance_sha256,
    source_identity_sha256:
      verifiedAssertion.evidence_record.source_independence.source_identity_sha256,
    independence_group_sha256:
      verifiedAssertion.evidence_record.source_independence.independence_group_sha256,
    independence_status: verifiedAssertion.evidence_record.source_independence.status,
    classification_source: source,
    housekeeper_valid_from: signer.valid_from,
    housekeeper_cert_fingerprint: signer.cert_fingerprint,
    housekeeper_identity_tier: signer.identity_tier,
    master_fingerprint: exactHash(masterFingerprint, 'master_fingerprint_invalid'),
    master_epoch: exactIso(masterEpoch, 'master_epoch_invalid'),
    retained_content_unchanged: true,
    retained_classification_unchanged: true,
    classification_transition_authority: false,
    save_authority: false,
    recall_authority: false,
    ranking_authority: false,
    deletion_authority: false,
    antigen_authority: false,
    automatic_policy_activation: false,
    housekeeper_discretion: false,
    reason: normalizedReason,
    ts_signed: signedTs,
  });
}

export function createMemoryEpistemicEvidenceAuthorization({
  body,
  masterPrivkeyB64u,
  masterPubkeyB64u,
  nonce = randomBytes(16).toString('base64url'),
} = {}) {
  assert(body?.schema === MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_BODY_SCHEMA,
    'approval_body_invalid');
  assert(pubkeyFingerprint(masterPubkeyB64u) === body.master_fingerprint,
    'master_public_key_fingerprint_mismatch');
  assert(typeof nonce === 'string' && nonce.length >= 16 && nonce.length <= 128,
    'approval_nonce_invalid');
  const sig = signPayload(masterPrivkeyB64u, body, nonce, body.ts_signed);
  const envelope = {
    schema: MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_ENVELOPE_SCHEMA,
    body,
    master_pubkey: masterPubkeyB64u,
    nonce,
    ts_signed: body.ts_signed,
    sig,
  };
  return Object.freeze({ ...envelope, approval_sha256: approvalHash(envelope) });
}

export function memoryEpistemicEvidenceMasterAuthorityContext(approval) {
  assert(approval?.schema === MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_ENVELOPE_SCHEMA,
    'approval_schema_invalid');
  return Object.freeze({
    actorAgentId: 'aimos-master',
    actorValidFromIso: approval.body.master_epoch,
    requestSigForm: 1,
    signedMethod: 'CEREMONY',
    signedPath: '/security/memory-epistemic-evidence/assertion',
    signedTs: approval.ts_signed,
    nonce: approval.nonce,
    sigBytes: Buffer.from(approval.sig, 'base64url'),
  });
}

export function verifyMemoryEpistemicEvidenceAuthorization(approval, {
  assertion,
  classificationSource,
  expectedMasterPubkeyB64u,
  expectedMasterFingerprint,
  expectedHousekeeperSigner,
} = {}) {
  try {
    assert(approval?.schema === MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_ENVELOPE_SCHEMA,
      'approval_schema_invalid');
    assert(approval.body?.schema === MEMORY_EPISTEMIC_ASSERTION_AUTHORIZATION_BODY_SCHEMA,
      'approval_body_invalid');
    assert(Number(approval.body.ts_signed) === Number(approval.ts_signed),
      'approval_timestamp_mismatch');
    assert(approvalHash(approval) === approval.approval_sha256, 'approval_hash_invalid');
    const masterPubkey = String(expectedMasterPubkeyB64u || '');
    assert(masterPubkey && masterPubkey === approval.master_pubkey,
      'approval_master_public_key_mismatch');
    assert(pubkeyFingerprint(masterPubkey) === expectedMasterFingerprint
      && approval.body.master_fingerprint === expectedMasterFingerprint,
    'approval_master_fingerprint_mismatch');
    const signature = verifyStoredPayloadSig(
      masterPubkey,
      approval.body,
      String(approval.nonce),
      Number(approval.ts_signed),
      String(approval.sig),
    );
    assert(signature.valid === true, 'approval_signature_invalid', signature.reason || 'unknown');
    const expected = buildMemoryEpistemicEvidenceAuthorizationBody({
      companyId: approval.body.company_id,
      assertion,
      classificationSource,
      masterFingerprint: expectedMasterFingerprint,
      masterEpoch: approval.body.master_epoch,
      housekeeperSigner: expectedHousekeeperSigner,
      reason: approval.body.reason,
      signedTs: approval.body.ts_signed,
    });
    assert(canonicalJson(expected) === canonicalJson(approval.body),
      'approval_bound_inputs_mismatch');
    return Object.freeze({
      valid: true,
      approval_sha256: approval.approval_sha256,
      assertion_sha256: approval.body.assertion_sha256,
      hypothesis_sha256: approval.body.hypothesis_sha256,
      master_fingerprint: approval.body.master_fingerprint,
      housekeeper_valid_from: approval.body.housekeeper_valid_from,
    });
  } catch (error) {
    return Object.freeze({ valid: false, reason: String(error?.message || error) });
  }
}
