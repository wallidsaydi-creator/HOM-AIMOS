/**
 * kernel.js — pure content-state/signed-occurrence two-view projection
 *
 * Paper/design authority:
 * - RFC 6962 and Crosby/Wallach: ordered events remain independently provable.
 * - Louck 2606.24322 and Miller 2006: equal content does not merge origin or
 *   authority; repeated content is not independent corroboration.
 * - Carbonell/Goldstein MMR: redundancy control is a ranking concern, not a
 *   provenance or truth claim.
 *
 * This module accepts only already principal- and provenance-admitted
 * occurrences. It has no database, server, environment, save, mutation,
 * classification, deletion, policy, or disclosure authority.
 */

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../security/protocol/canonical-json.js';

export const CONTENT_STATE_OCCURRENCE_KERNEL_CONTRACT = Object.freeze({
  schema: 'hom.aimos.content-state-occurrence-kernel/v1',
  content_schema: 'hom.aimos.live-content/v1-existing',
  state_view_schema: 'hom.aimos.content-state-view/v1',
  occurrence_view_schema: 'hom.aimos.signed-occurrence-view/v1',
  evidence_scope_default: 'occurrence_scoped',
  occurrence_reducer: 'eligible_max_then_occurrence_ref',
  input_authority: 'already_principal_and_provenance_admitted_only',
  database_authority: false,
  server_authority: false,
  environment_authority: false,
  disclosure_authority: false,
  mutation_authority: false,
  deletion_authority: false,
});

const HEX_32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CONTENT_FIELDS = Object.freeze([
  'key',
  'value',
  'scope',
  'memory_type',
  'clearance_level',
  'data_class',
  'source',
]);
const STATE_VIEW_ROOT_DOMAIN = Buffer.from('hom.aimos.content-state-view-root/v1\0', 'utf8');
const OCCURRENCE_VIEW_ROOT_DOMAIN = Buffer.from('hom.aimos.occurrence-view-root/v1\0', 'utf8');
const DECISION_ROOT_DOMAIN = Buffer.from('hom.aimos.content-state-occurrence-decision/v1\0', 'utf8');

function fail(code) {
  throw new Error(`content_state_occurrence_kernel:${code}`);
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function domainHash(domain, value) {
  return sha256Hex(Buffer.concat([
    domain,
    Buffer.from(canonicalJson(value), 'utf8'),
  ]));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function normalizedString(value) {
  return value == null ? '' : String(value);
}

export function canonicalizeLiveContentState(fields = {}) {
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    fail('content_fields_invalid');
  }
  const normalized = {};
  for (const field of CONTENT_FIELDS) normalized[field] = normalizedString(fields[field]);
  const canonicalBytes = canonicalJson(normalized);
  return deepFreeze({
    normalized_fields: normalized,
    canonical_json: canonicalBytes,
    live_content_hash: sha256Hex(Buffer.from(canonicalBytes, 'utf8')),
  });
}

export function assertNoContentDigestCollision(left = {}, right = {}) {
  const leftHash = String(left.live_content_hash || '').toLowerCase();
  const rightHash = String(right.live_content_hash || '').toLowerCase();
  if (!HEX_32.test(leftHash) || !HEX_32.test(rightHash)) fail('live_content_hash_invalid');
  if (leftHash === rightHash && String(left.canonical_json) !== String(right.canonical_json)) {
    fail('content_state_digest_collision');
  }
  return true;
}

function normalizeAdmission(admission) {
  if (!admission || typeof admission !== 'object') fail('admission_proof_required');
  if (admission.principal_scope_admitted !== true) fail('principal_scope_rejected');
  if (admission.provenance_verified !== true) fail('provenance_admission_rejected');
  if (admission.topology_verified !== true) fail('topology_lineage_invalid');
  return Object.freeze({
    principal_scope_admitted: true,
    provenance_verified: true,
    topology_verified: true,
  });
}

function normalizeEvidence(evidence = {}) {
  if (!evidence || typeof evidence !== 'object') fail('evidence_scope_invalid');
  if (typeof evidence.occurrence_eligible !== 'boolean'
      || typeof evidence.content_eligible !== 'boolean') {
    fail('evidence_scope_invalid');
  }
  const occurrenceEligible = evidence.occurrence_eligible;
  const contentEligible = evidence.content_eligible;
  const occurrenceDecisionRef = evidence.occurrence_decision_ref == null
    ? null : String(evidence.occurrence_decision_ref).toLowerCase();
  const contentDecisionRef = evidence.content_decision_ref == null
    ? null : String(evidence.content_decision_ref).toLowerCase();
  if (!occurrenceEligible && !HEX_32.test(occurrenceDecisionRef || '')) {
    fail('evidence_scope_invalid');
  }
  if (!contentEligible && !HEX_32.test(contentDecisionRef || '')) {
    fail('evidence_scope_invalid');
  }
  return Object.freeze({
    occurrence_eligible: occurrenceEligible,
    content_eligible: contentEligible,
    occurrence_decision_ref: occurrenceDecisionRef,
    content_decision_ref: contentDecisionRef,
  });
}

function normalizePrincipal(principal) {
  if (!principal || typeof principal !== 'object') fail('occurrence_identity_epoch_invalid');
  const agentId = String(principal.agent_id || '').trim();
  const validFrom = new Date(principal.valid_from || '');
  const certFingerprint = String(principal.cert_fingerprint || '').toLowerCase();
  if (!agentId || Number.isNaN(validFrom.getTime()) || !HEX_32.test(certFingerprint)) {
    fail('occurrence_identity_epoch_invalid');
  }
  return Object.freeze({
    agent_id: agentId,
    valid_from: validFrom.toISOString(),
    cert_fingerprint: certFingerprint,
  });
}

function normalizeLineage(lineage) {
  if (!lineage || typeof lineage !== 'object') fail('topology_lineage_invalid');
  const lineageId = String(lineage.lineage_id || '').trim();
  const signedTimeMs = Number(lineage.signed_time_ms);
  if (!lineageId || !Number.isSafeInteger(signedTimeMs)) fail('topology_lineage_invalid');
  return Object.freeze({
    lineage_id: lineageId,
    is_current_head: lineage.is_current_head === true,
    signed_time_ms: signedTimeMs,
  });
}

function normalizeGearScores(gearScores = {}) {
  if (!gearScores || typeof gearScores !== 'object' || Array.isArray(gearScores)) {
    fail('gear_scores_invalid');
  }
  const normalized = {};
  for (const [gear, raw] of Object.entries(gearScores)) {
    const name = String(gear || '').trim();
    const score = Number(raw);
    if (!name || !Number.isFinite(score)) fail('gear_scores_invalid');
    normalized[name] = score;
  }
  return Object.freeze(Object.fromEntries(
    Object.entries(normalized).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function normalizeOccurrence(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('occurrence_invalid');
  const companyId = String(raw.company_id || '').trim();
  const memoryId = String(raw.memory_id || '').toLowerCase();
  const occurrenceRef = String(raw.occurrence_ref || '').toLowerCase();
  const storedHash = String(raw.live_content_hash || '').toLowerCase();
  if (!companyId || !UUID.test(memoryId) || !HEX_32.test(occurrenceRef) || !HEX_32.test(storedHash)) {
    fail('occurrence_invalid');
  }
  const content = canonicalizeLiveContentState(raw.content || {});
  if (content.live_content_hash !== storedHash) fail('live_content_hash_mismatch');
  return {
    company_id: companyId,
    memory_id: memoryId,
    occurrence_ref: occurrenceRef,
    live_content_hash: storedHash,
    canonical_json: content.canonical_json,
    content: content.normalized_fields,
    principal: normalizePrincipal(raw.principal),
    lineage: normalizeLineage(raw.lineage),
    admission: normalizeAdmission(raw.admission),
    evidence: normalizeEvidence(raw.evidence || {}),
    gear_scores: normalizeGearScores(raw.gear_scores || {}),
  };
}

function classInternalKey(occurrence) {
  return `${occurrence.company_id}\0${occurrence.live_content_hash}`;
}

function chooseWitness(eligibleMembers, preferredOccurrenceRef = null) {
  if (!eligibleMembers.length) return null;
  if (preferredOccurrenceRef != null) {
    const preferred = String(preferredOccurrenceRef).toLowerCase();
    if (!eligibleMembers.some((member) => member.occurrence_ref === preferred)) {
      fail('preferred_occurrence_ineligible');
    }
    return preferred;
  }
  const currentHeads = eligibleMembers.filter((member) => member.lineage.is_current_head);
  const pool = currentHeads.length ? currentHeads : eligibleMembers;
  return [...pool].sort((left, right) => (
    right.lineage.signed_time_ms - left.lineage.signed_time_ms
    || left.occurrence_ref.localeCompare(right.occurrence_ref)
  ))[0].occurrence_ref;
}

function assertLineageTopology(members) {
  const headsByLineage = new Map();
  for (const member of members) {
    if (!member.lineage.is_current_head) continue;
    const count = (headsByLineage.get(member.lineage.lineage_id) || 0) + 1;
    headsByLineage.set(member.lineage.lineage_id, count);
    if (count > 1) fail('topology_lineage_invalid');
  }
}

/**
 * Build immutable state and occurrence views from already admitted occurrences.
 * `preferred_occurrence_by_content_hash` is optional, deterministic evidence
 * from an occurrence-sensitive gear; it cannot make an ineligible occurrence
 * eligible.
 */
export function projectContentStateOccurrenceViews({
  occurrences,
  preferred_occurrence_by_content_hash = {},
} = {}) {
  if (!Array.isArray(occurrences)) fail('occurrences_required');
  if (!preferred_occurrence_by_content_hash
      || typeof preferred_occurrence_by_content_hash !== 'object'
      || Array.isArray(preferred_occurrence_by_content_hash)) {
    fail('preferred_occurrence_map_invalid');
  }

  const normalized = occurrences.map(normalizeOccurrence)
    .sort((left, right) => left.occurrence_ref.localeCompare(right.occurrence_ref));
  if (new Set(normalized.map((occurrence) => occurrence.company_id)).size > 1) {
    fail('principal_scope_rejected');
  }
  assertLineageTopology(normalized);
  const refs = new Set();
  const memoryRefs = new Set();
  for (const occurrence of normalized) {
    if (refs.has(occurrence.occurrence_ref)) fail('duplicate_occurrence_reference');
    refs.add(occurrence.occurrence_ref);
    const memoryKey = `${occurrence.company_id}\0${occurrence.memory_id}\0${occurrence.occurrence_ref}`;
    if (memoryRefs.has(memoryKey)) fail('duplicate_occurrence_reference');
    memoryRefs.add(memoryKey);
  }

  const groups = new Map();
  for (const occurrence of normalized) {
    const key = classInternalKey(occurrence);
    const existing = groups.get(key);
    if (existing) {
      assertNoContentDigestCollision(existing[0], occurrence);
      existing.push(occurrence);
    } else {
      groups.set(key, [occurrence]);
    }
  }

  const stateView = [];
  const occurrenceEligibility = new Map();
  let contentBlockedStates = 0;
  let occurrenceBlockedCount = 0;
  let independentMultiheadStates = 0;

  for (const members of [...groups.values()].sort((left, right) => (
    classInternalKey(left[0]).localeCompare(classInternalKey(right[0]))
  ))) {
    const contentBlocked = members.some((member) => !member.evidence.content_eligible);
    if (contentBlocked) contentBlockedStates += 1;
    const lineages = new Set(members.map((member) => member.lineage.lineage_id));
    const currentHeadCount = members.filter((member) => member.lineage.is_current_head).length;
    if (currentHeadCount > 1 && lineages.size > 1) independentMultiheadStates += 1;

    const eligibleMembers = [];
    const blockedRefs = [];
    for (const member of members) {
      const occurrenceBlocked = !member.evidence.occurrence_eligible;
      const rankEligible = !contentBlocked && !occurrenceBlocked;
      if (occurrenceBlocked) occurrenceBlockedCount += 1;
      occurrenceEligibility.set(member.occurrence_ref, {
        rank_eligible: rankEligible,
        ineligibility_reason: contentBlocked
          ? 'content_scope_blocked'
          : occurrenceBlocked ? 'occurrence_scope_blocked' : null,
      });
      if (rankEligible) eligibleMembers.push(member);
      else blockedRefs.push(member.occurrence_ref);
    }

    const representative = members[0];
    const preferred = preferred_occurrence_by_content_hash[representative.live_content_hash] ?? null;
    const witness = chooseWitness(eligibleMembers, preferred);
    stateView.push({
      schema: CONTENT_STATE_OCCURRENCE_KERNEL_CONTRACT.state_view_schema,
      company_id: representative.company_id,
      live_content_hash: representative.live_content_hash,
      canonical_json: representative.canonical_json,
      content: representative.content,
      occurrence_count: members.length,
      occurrence_refs: members.map((member) => member.occurrence_ref),
      eligible_occurrence_refs: eligibleMembers.map((member) => member.occurrence_ref).sort(),
      blocked_occurrence_refs: blockedRefs.sort(),
      lineage_count: lineages.size,
      current_head_count: currentHeadCount,
      content_scope_blocked: contentBlocked,
      rank_eligible: eligibleMembers.length > 0,
      disclosure_witness_occurrence_ref: witness,
    });
  }

  const occurrenceView = normalized.map((occurrence) => ({
    schema: CONTENT_STATE_OCCURRENCE_KERNEL_CONTRACT.occurrence_view_schema,
    ...occurrence,
    ...occurrenceEligibility.get(occurrence.occurrence_ref),
  }));
  const stateViewRoot = domainHash(STATE_VIEW_ROOT_DOMAIN, stateView);
  const occurrenceViewRoot = domainHash(OCCURRENCE_VIEW_ROOT_DOMAIN, occurrenceView);
  const decisionBody = {
    schema: CONTENT_STATE_OCCURRENCE_KERNEL_CONTRACT.schema,
    input_occurrence_count: occurrenceView.length,
    unique_state_count: stateView.length,
    collapsed_occurrence_count: occurrenceView.length - stateView.length,
    rank_eligible_state_count: stateView.filter((state) => state.rank_eligible).length,
    content_blocked_state_count: contentBlockedStates,
    occurrence_blocked_count: occurrenceBlockedCount,
    independent_multihead_state_count: independentMultiheadStates,
    membership_operations: occurrenceView.length,
    state_view_root_sha256: stateViewRoot,
    occurrence_view_root_sha256: occurrenceViewRoot,
    canonical_memory_mutated: false,
    retention_changed: false,
    authority_changed: false,
  };
  const decision = {
    ...decisionBody,
    decision_sha256: domainHash(DECISION_ROOT_DOMAIN, decisionBody),
  };
  return deepFreeze({
    state_view: stateView,
    occurrence_view: occurrenceView,
    decision,
  });
}

/**
 * Reduce one occurrence-sensitive gear to at most one contribution per
 * rank-eligible content state. Scores are read only from the immutable
 * occurrence view produced above.
 */
export function reduceOccurrenceSensitiveGear(projection, gear) {
  const name = String(gear || '').trim();
  if (!projection || !Array.isArray(projection.occurrence_view) || !name) {
    fail('occurrence_reducer_input_invalid');
  }
  const bestByState = new Map();
  for (const occurrence of projection.occurrence_view) {
    if (occurrence.rank_eligible !== true) continue;
    const score = Number(occurrence.gear_scores?.[name]);
    if (!Number.isFinite(score)) continue;
    const key = `${occurrence.company_id}\0${occurrence.live_content_hash}`;
    const current = bestByState.get(key);
    if (!current || score > current.score
        || (score === current.score
          && occurrence.occurrence_ref.localeCompare(current.occurrence_ref) < 0)) {
      bestByState.set(key, {
        company_id: occurrence.company_id,
        live_content_hash: occurrence.live_content_hash,
        score,
        occurrence_ref: occurrence.occurrence_ref,
      });
    }
  }
  return deepFreeze([...bestByState.values()].sort((left, right) => (
    right.score - left.score
    || left.live_content_hash.localeCompare(right.live_content_hash)
    || left.occurrence_ref.localeCompare(right.occurrence_ref)
  )));
}
