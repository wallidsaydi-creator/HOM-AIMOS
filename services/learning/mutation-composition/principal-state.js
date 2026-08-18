/**
 * principal-state.js — authority-free R7-M mutation target projection
 *
 * Groups already verified, security-eligible occurrences into principal states
 * and selects one deterministic representative without consulting weights or
 * outcomes. It owns no database, signing, mutation, classification, or policy.
 */

export const PRINCIPAL_STATE_MUTATION_CONTRACT = Object.freeze({
  schema: 'hom.aimos.principal-state-mutation-target/v1',
  target_scopes: Object.freeze([
    'occurrence_observation',
    'principal_state',
    'content_state',
  ]),
  content_state_mutation_authorized: false,
  representative_order: 'signed_time_desc_occurrence_ref_asc_memory_id_asc',
  time_complexity: 'O(n)',
  space_complexity: 'O(u)',
});

const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fail(code) {
  throw new Error(`principal_state_mutation:${code}`);
}

function normalize(record = {}) {
  const companyId = String(record.company_id || '').trim();
  const memoryId = String(record.memory_id || '').trim().toLowerCase();
  const contentHash = String(record.live_content_hash || '').trim().toLowerCase();
  const principalId = String(record.principal_agent_id || '').trim();
  const occurrenceRef = String(record.occurrence_ref || '').trim().toLowerCase();
  const signedTimeMs = Number(record.signed_time_ms);
  if (!companyId || !UUID.test(memoryId) || !HEX32.test(contentHash)
      || !principalId || !HEX32.test(occurrenceRef)
      || !Number.isSafeInteger(signedTimeMs) || signedTimeMs <= 0
      || record.security_eligible !== true) {
    fail('verified_eligible_occurrence_required');
  }
  return Object.freeze({
    company_id: companyId,
    memory_id: memoryId,
    live_content_hash: contentHash,
    principal_agent_id: principalId,
    occurrence_ref: occurrenceRef,
    signed_time_ms: signedTimeMs,
    security_eligible: true,
  });
}

function key(record) {
  return `${record.company_id}\0${record.live_content_hash}\0${record.principal_agent_id}`;
}

function better(candidate, current) {
  return candidate.signed_time_ms > current.signed_time_ms
    || (candidate.signed_time_ms === current.signed_time_ms
      && (candidate.occurrence_ref < current.occurrence_ref
        || (candidate.occurrence_ref === current.occurrence_ref
          && candidate.memory_id < current.memory_id)));
}

export function projectPrincipalStateMutationTargets(records = []) {
  if (!Array.isArray(records)) fail('records_required');
  const representatives = new Map();
  const counts = new Map();
  const refs = new Set();
  for (const raw of records) {
    const record = normalize(raw);
    if (refs.has(record.occurrence_ref)) fail('duplicate_occurrence_reference');
    refs.add(record.occurrence_ref);
    const stateKey = key(record);
    counts.set(stateKey, (counts.get(stateKey) || 0) + 1);
    const current = representatives.get(stateKey);
    if (!current || better(record, current)) representatives.set(stateKey, record);
  }
  return Object.freeze([...representatives.entries()]
    .map(([stateKey, representative]) => Object.freeze({
      schema: PRINCIPAL_STATE_MUTATION_CONTRACT.schema,
      principal_state_key: stateKey,
      company_id: representative.company_id,
      live_content_hash: representative.live_content_hash,
      principal_agent_id: representative.principal_agent_id,
      representative_memory_id: representative.memory_id,
      representative_occurrence_ref: representative.occurrence_ref,
      representative_signed_time_ms: representative.signed_time_ms,
      retained_occurrence_count: counts.get(stateKey),
    }))
    .sort((left, right) => left.principal_state_key.localeCompare(right.principal_state_key)));
}

export function validateOutcomeMutationEvidence(evidence = {}) {
  const targetScope = String(evidence.target_scope || '');
  if (!PRINCIPAL_STATE_MUTATION_CONTRACT.target_scopes.includes(targetScope)) {
    fail('target_scope_invalid');
  }
  if (targetScope === 'content_state') fail('content_state_mutation_not_authorized');
  const normalized = {
    schema: String(evidence.schema || ''),
    company_id: String(evidence.company_id || ''),
    memory_id: String(evidence.memory_id || '').toLowerCase(),
    live_content_hash: String(evidence.live_content_hash || '').toLowerCase(),
    occurrence_ref: String(evidence.occurrence_ref || '').toLowerCase(),
    target_scope: targetScope,
    recall_event_id: String(evidence.recall_event_id || '').toLowerCase(),
    recall_event_mutation_hash: String(evidence.recall_event_mutation_hash || '').toLowerCase(),
    recall_merkle_root: String(evidence.recall_merkle_root || '').toLowerCase(),
    security_closure_sha256: String(evidence.security_closure_sha256 || '').toLowerCase(),
    outcome_id: String(evidence.outcome_id || '').toLowerCase(),
  };
  if (normalized.schema !== 'hom.aimos.mutation-outcome-evidence/v2'
      || !normalized.company_id
      || !UUID.test(normalized.memory_id)
      || !HEX32.test(normalized.live_content_hash)
      || !HEX32.test(normalized.occurrence_ref)
      || !UUID.test(normalized.recall_event_id)
      || !HEX32.test(normalized.recall_event_mutation_hash)
      || !HEX32.test(normalized.recall_merkle_root)
      || !HEX32.test(normalized.security_closure_sha256)
      || !UUID.test(normalized.outcome_id)) {
    fail('outcome_evidence_invalid');
  }
  return Object.freeze(normalized);
}
