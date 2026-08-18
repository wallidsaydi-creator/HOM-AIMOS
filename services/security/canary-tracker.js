/**
 * canary-tracker.js — Kill-Chain Canary Stage Tracking (P0-B3-6)
 * Source: Kill-Chain Canaries (MIT, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: quality-gate.js (Wall 2) or tool-registry.js
 * 2. → Pulls from: Inbound prompt strings (Injection payloads)
 * 3. → Pushes to: services/observe/event-ledger.js (Provenance logs)
 * 4. ↔ Interacts with: aimos_memories (Tracks persistence stage)
 *
 * LOGIC GUIDE: Uses cryptographic tokens (SECRET-[A-F0-9]{8}) to trace 
 * prompt injections through the source stages EXPOSED → PERSISTED → RELAYED
 * → EXECUTED. HOM-AIMOS splits the pre-model relay gate into
 * OBSERVED_AT_RELAY_GATE and RELAY_BLOCKED so a contained marker is never
 * mislabeled as RELAYED. RELAYED is reserved for content actually delivered
 * to, and processed by, the downstream model.
 * Additive Batch9 Wave2 authority: The Midas Touch and Governing What You
 * Cannot Observe. Canary scans now return native kill-chain diagnostics without
 * changing token semantics or canonical memory behavior.
 *
 * HOM-AIMOS production adaptation: a request-bound Canary–MAGMA composition
 * decision preserves marked/quarantined memories in the central candidate set
 * while making them ineligible as graph anchors or endpoints. Kill-Chain
 * Canaries does not specify this graph composition; MAGMA does not specify
 * marker evidence. The scale-bounded signed composition is an AIMOS
 * engineering contribution, not a claim about either source paper.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

import { createHash, randomBytes } from 'node:crypto';

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { logEvent } from '../observe/event-ledger.js';
import { canonicalJson } from './protocol/canonical-json.js';

const COMPANY = AIMOS_COMPANY_ID;
const CANARY_REGEX = /\bSECRET-[A-F0-9]{8}(?![A-Za-z0-9_])/g;
const PROPAGATION_STAGES = ['EXPOSED', 'PERSISTED', 'RELAYED', 'EXECUTED'];
const STAGES = [
  'EXPOSED',
  'PERSISTED',
  'OBSERVED_AT_RELAY_GATE',
  'RELAY_BLOCKED',
  'RELAYED',
  'EXECUTED',
];

export const CANARY_RELAY_STAGE_CONTRACT = Object.freeze({
  schema: 'hom-aimos/canary-relay-stage/v1',
  observed_definition: 'marker_present_in_recalled_memory_at_pre_model_relay_gate',
  blocked_definition: 'observed_marker_withheld_before_model_prompt_delivery',
  relayed_definition: 'marker_bearing_recalled_memory_delivered_to_and_processed_by_downstream_model',
  transition_equation:
    'OBSERVED_AT_RELAY_GATE -> exactly_one_of(RELAY_BLOCKED,RELAYED)',
  blocked_and_relayed_mutually_exclusive: true,
  relayed_requires_completed_model_invocation: true,
  source_stage_definition: 'RELAYED=canary_read_by_Agent_B',
  canonical_memory_mutated: false,
  retention_changed: false,
  environment_authority: false,
});

export const CANARY_RELAY_DECONTAMINATION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/canary-relay-decontamination/v1',
  source_metric: 'fraction_of_injections_stripped_at_the_relay_stage',
  aimos_adaptation: 'exact_cohort_unique_token_set_accounting_with_explicit_non_result_states',
  exposed_set: 'E_C=unique_valid_canary_tokens_at_EXPOSED_in_exact_cohort_C',
  blocked_set: 'B_C=unique_valid_canary_tokens_at_RELAY_BLOCKED_in_exact_cohort_C',
  relayed_set: 'R_C=unique_valid_canary_tokens_at_RELAYED_in_exact_cohort_C',
  equation: 'D_C=1-|E_C_intersection_R_C|/|E_C|=|E_C_intersection_B_C|/|E_C|',
  zero_exposure_result: 'undefined',
  incomplete_or_inconsistent_result: 'indeterminate',
  duplicate_invariant: 'one_issued_token_contributes_at_most_once_per_stage_per_cohort',
  issuance_invariant: 'only_tokens_bound_to_the_exact_issued_cohort_manifest_contribute_to_efficacy',
  forged_marker_invariant: 'valid_grammar_but_unissued_markers_are_contained_but_never_counted_as_favorable_efficacy_evidence',
  cohort_invariant: 'events_outside_exact_cohort_C_have_zero_influence',
  terminal_invariant: 'each_exposed_token_has_exactly_one_of_RELAY_BLOCKED_or_RELAYED',
  token_disclosure: false,
  canonical_memory_mutated: false,
  retention_changed: false,
  environment_authority: false,
});

export const CANARY_MAGMA_COMPOSITION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/canary-magma-composition/v1',
  marker_source: 'kill_chain_canary_exact_grammar',
  quarantine_source: 'native_retained_security_disposition',
  graph_admission_equation: 'a_i=(1-c_i)(1-q_i)',
  guarded_transition_equation:
    'T_C(i,j|q)=a_i*a_j*exp(lambda_structure*phi(r_ij,T_q)+lambda_semantic*cos(e_j,e_q))',
  candidate_invariant: 'retained_baseline_subseteq_central_candidates',
  graph_invariant: 'marked_or_quarantined_evidence_has_zero_magma_graph_vote',
  time_complexity: 'O(candidate_count+serialized_candidate_bytes)',
  space_complexity: 'O(candidate_count)',
  deletes_memory: false,
  mutates_memory: false,
  suppresses_canonical_retention: false,
  disclosure_authority: false,
  environment_authority: false,
});

export const CANARY_CLEAN_SELECTION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/canary-clean-selection/v2-epistemic-withholding',
  eligibility_equation: 'e_i=(1-c_i)(1-q_i)(1-u_i)',
  selected_count_equation: 's=min(k,sum_i(e_i))',
  backfill_equation: 'b=max(0,s-clean_eligible_in_raw_top_k)',
  selection_invariant: 'selected_top_k_subseteq_clean_eligible_evidence',
  retention_invariant: 'ineligible_evidence_retained_in_signed_decision_set',
  clean_label_establishes_content_truth: false,
  canonical_memory_mutated: false,
  retention_changed: false,
  deletion_performed: false,
  persistent_suppression_performed: false,
  environment_authority: false,
});

export const CANARY_CLEAN_SELECTION_RETURN_PATHS = Object.freeze([
  'identifier_exact',
  'post_compaction_handoff',
  'semantic_cache',
  'adaptive_early_exit',
  'normal_recall',
]);

export const CANARY_CONTENT_CLASSIFICATION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/canary-content-classification-map/v1',
  key: 'sha256(canonical_json({key,value}))',
  scan_invariant: 'each_unique_content_hash_scanned_at_most_once_per_request',
  disposition_invariant: 'content_marker_classification_is_separate_from_memory_quarantine_disposition',
  canonical_memory_mutated: false,
  retention_changed: false,
  environment_authority: false,
});

export const CANARY_FINAL_CLOSURE_CONTRACT = Object.freeze({
  schema: 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope',
  selected_invariant: 'selected_top_k_subseteq_clean_eligible_evidence',
  consumer_invariant: 'all_consumers_commit_to_one_request_local_classification_map',
  receipt_count_per_return: 1,
  canonical_memory_mutated: false,
  retention_changed: false,
  deletion_performed: false,
  persistent_suppression_performed: false,
  environment_authority: false,
});

/**
 * @typedef {Object} CanaryEvent
 * @property {string} canaryToken
 * @property {'EXPOSED'|'PERSISTED'|'OBSERVED_AT_RELAY_GATE'|'RELAY_BLOCKED'|'RELAYED'|'EXECUTED'} stage
 * @property {string} location - where detected (tool name, memory key, etc.)
 * @property {string} runId
 * @property {number} timestamp
 */

// In-memory event log (flushed to Aimos periodically)
const _eventLog = [];
const _relayTerminalStates = new WeakMap();

export function buildCanaryKillChainDiagnostics(events = _eventLog, { cohortId = null } = {}) {
  const eventList = Array.isArray(events) ? events : [];
  const stageCounts = {
    EXPOSED: 0,
    PERSISTED: 0,
    OBSERVED_AT_RELAY_GATE: 0,
    RELAY_BLOCKED: 0,
    RELAYED: 0,
    EXECUTED: 0,
  };
  for (const event of eventList) {
    if (stageCounts[event.stage] !== undefined) stageCounts[event.stage] += 1;
  }
  const deepestStage = [...PROPAGATION_STAGES]
    .reverse()
    .find((stage) => stageCounts[stage] > 0) || 'NONE';
  const relayState = stageCounts.RELAYED > 0
    ? 'RELAYED'
    : stageCounts.RELAY_BLOCKED > 0
      ? 'RELAY_BLOCKED'
      : stageCounts.OBSERVED_AT_RELAY_GATE > 0
        ? 'OBSERVED_AT_RELAY_GATE'
        : 'NOT_OBSERVED';
  const relayDecontamination = buildCanaryRelayDecontaminationEvidence(eventList, { cohortId });
  return {
    source_papers: [
      'Kill-Chain Canaries: Stage-Level Tracking of Prompt Injection Across Attack Surfaces and Model Safety Tiers',
      'The Midas Touch: Triggering LLMs with Hidden Intentions',
      'Governing What You Cannot Observe: Adaptive Runtime Governance for Autonomous AI',
    ],
    diagnostic_only: true,
    stage_counts: stageCounts,
    deepest_stage: deepestStage,
    relay_state: relayState,
    relay_stage_contract: CANARY_RELAY_STAGE_CONTRACT.schema,
    executed_stage_seen: stageCounts.EXECUTED > 0,
    executed_tool_invocations: eventList.filter((event) => event.stage === 'EXECUTED' && event.toolInvoked === true).length,
    blocked_tool_dispatches: eventList.filter((event) => event.stage === 'EXECUTED' && event.dispatchBlocked === true).length,
    relay_decontamination_rate: relayDecontamination.value,
    relay_decontamination: relayDecontamination,
    canonical_memory_changed: false,
    canary_semantics_changed: false,
  };
}

/**
 * Generate a canary token for injection tracking.
 * @returns {string} SECRET-XXXXXXXX format token
 */
export function generateCanary() {
  return `SECRET-${randomBytes(4).toString('hex').toUpperCase()}`;
}

/**
 * Scan text for canary tokens.
 * @param {string} text
 * @returns {string[]} found canary tokens
 */
export function detectCanaries(text) {
  const matches = renderCanaryText(text).match(CANARY_REGEX);
  return matches ? [...new Set(matches)] : [];
}

function renderCanaryText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function canaryMemoryId(memory) {
  return String(memory?.id || memory?.memory_id || '').trim().toLowerCase();
}

function retainedQuarantineEvidence(memory) {
  return memory?.scope === 'quarantine'
    || memory?.memory_type === 'quarantine'
    || Number(memory?.retrieval_weight) === 0.1;
}

function canaryContentCommitment(memory, rendered) {
  const liveContentHash = String(memory?.provenance_proof?.live_content_hash || '').trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(liveContentHash)) return liveContentHash;
  return createHash('sha256').update(rendered, 'utf8').digest('hex');
}

/**
 * Create one request-local content classifier shared by every recall consumer.
 *
 * Exact marker detection is cached by the SHA-256 of the canonical scanned
 * bytes. Quarantine remains a per-memory retained disposition and therefore is
 * evaluated on every memory binding without rescanning its content. New graph
 * discoveries extend this same map; no graph owns a private classifier.
 */
export function createCanaryContentClassificationMap() {
  const contentByScanHash = new Map();
  let classificationRequests = 0;
  let classificationCacheHits = 0;

  function classifyMemories(memories = []) {
    const candidates = Array.isArray(memories) ? memories : [];
    const records = [];
    const seenIds = new Set();
    const uniqueMarkerTokens = new Set();

    for (const memory of candidates) {
      const memoryId = canaryMemoryId(memory);
      if (!memoryId || seenIds.has(memoryId)) {
        throw new Error(memoryId
          ? 'canary_content_classification_duplicate_memory_id'
          : 'canary_content_classification_memory_id_invalid');
      }
      seenIds.add(memoryId);
      classificationRequests += 1;
      const rendered = canonicalJson({
        key: memory?.key ?? null,
        value: memory?.value ?? null,
      });
      const scanInputSha256 = createHash('sha256').update(rendered, 'utf8').digest('hex');
      let classified = contentByScanHash.get(scanInputSha256);
      if (!classified) {
        const tokens = Object.freeze(detectCanaries(rendered).sort());
        const publicClassification = Object.freeze({
          content_scan_sha256: scanInputSha256,
          serialized_content_bytes: Buffer.byteLength(rendered, 'utf8'),
          canary_marker_present: tokens.length > 0,
          canary_marker_count: tokens.length,
        });
        classified = Object.freeze({ publicClassification, tokens });
        contentByScanHash.set(scanInputSha256, classified);
      } else {
        classificationCacheHits += 1;
      }
      for (const token of classified.tokens) uniqueMarkerTokens.add(token);
      const quarantineEvidence = retainedQuarantineEvidence(memory);
      records.push(Object.freeze({
        memory_id: memoryId,
        content_commitment_sha256: canaryContentCommitment(memory, rendered),
        ...classified.publicClassification,
        retained_quarantine_evidence: quarantineEvidence,
        selection_eligible:
          !classified.publicClassification.canary_marker_present && !quarantineEvidence,
      }));
    }

    return Object.freeze({
      records: Object.freeze(records),
      canary_tokens: Object.freeze([...uniqueMarkerTokens].sort()),
      unique_canary_marker_count: uniqueMarkerTokens.size,
    });
  }

  function snapshot() {
    const classifications = Object.freeze([...contentByScanHash.values()]
      .map((entry) => entry.publicClassification)
      .sort((left, right) => left.content_scan_sha256.localeCompare(right.content_scan_sha256)));
    const body = Object.freeze({
      schema: CANARY_CONTENT_CLASSIFICATION_CONTRACT.schema,
      key: CANARY_CONTENT_CLASSIFICATION_CONTRACT.key,
      scan_invariant: CANARY_CONTENT_CLASSIFICATION_CONTRACT.scan_invariant,
      unique_content_count: classifications.length,
      unique_content_bytes: classifications.reduce(
        (sum, record) => sum + record.serialized_content_bytes,
        0,
      ),
      canary_marked_content_count: classifications.filter(
        (record) => record.canary_marker_present,
      ).length,
      classifications,
      canonical_memory_mutated: false,
      retention_changed: false,
    });
    return Object.freeze({
      ...body,
      classification_map_root_sha256: createHash('sha256')
        .update(canonicalJson(body), 'utf8')
        .digest('hex'),
      classification_requests: classificationRequests,
      classification_cache_hits: classificationCacheHits,
      content_scans_executed: classifications.length,
      content_rescans_executed: 0,
    });
  }

  return Object.freeze({ classifyMemories, snapshot });
}

/**
 * Compose retained Canary/quarantine evidence with a graph-retrieval boundary.
 *
 * Let c_i indicate an exact Canary marker and q_i indicate a native retained
 * quarantine disposition.  A memory may seed or traverse MAGMA only when
 * a_i=(1-c_i)(1-q_i)=1.  The memory itself remains in the centrally owned
 * candidate population; this function changes neither retention nor final
 * disclosure authority.
 */
export function buildCanaryMagmaGraphAdmission(
  memories = [],
  { classificationMap = createCanaryContentClassificationMap() } = {},
) {
  const candidates = Array.isArray(memories) ? memories : [];
  const graphAdmittedMemories = [];
  const retainedEvidenceMemories = [];
  const records = [];
  let quarantineEvidenceCount = 0;
  const classified = classificationMap.classifyMemories(candidates);

  for (let index = 0; index < candidates.length; index += 1) {
    const memory = candidates[index];
    const classification = classified.records[index];
    const markerPresent = classification.canary_marker_present;
    const quarantineEvidence = classification.retained_quarantine_evidence;
    if (quarantineEvidence) quarantineEvidenceCount += 1;
    const graphAdmitted = !markerPresent && !quarantineEvidence;
    const record = Object.freeze({
      memory_id: classification.memory_id,
      content_commitment_sha256: classification.content_commitment_sha256,
      content_scan_sha256: classification.content_scan_sha256,
      canary_marker_present: markerPresent,
      canary_marker_count: classification.canary_marker_count,
      retained_quarantine_evidence: quarantineEvidence,
      graph_admitted: graphAdmitted,
    });
    records.push(record);
    if (graphAdmitted) graphAdmittedMemories.push(memory);
    else retainedEvidenceMemories.push(memory);
  }

  const decisionBody = {
    schema: CANARY_MAGMA_COMPOSITION_CONTRACT.schema,
    graph_admission_equation: CANARY_MAGMA_COMPOSITION_CONTRACT.graph_admission_equation,
    guarded_transition_equation: CANARY_MAGMA_COMPOSITION_CONTRACT.guarded_transition_equation,
    input_count: records.length,
    graph_admitted_count: graphAdmittedMemories.length,
    retained_evidence_count: retainedEvidenceMemories.length,
    canary_marked_memory_count: records.filter((record) => record.canary_marker_present).length,
    canary_marker_count: classified.unique_canary_marker_count,
    quarantine_evidence_count: quarantineEvidenceCount,
    serialized_candidate_bytes: classified.records.reduce(
      (sum, record) => sum + record.serialized_content_bytes,
      0,
    ),
    classification_map_root_sha256:
      classificationMap.snapshot().classification_map_root_sha256,
    records: Object.freeze(records),
    retained_baseline_preserved: true,
    canonical_memory_mutated: false,
    retention_changed: false,
    deletion_performed: false,
    disclosure_authority: false,
  };
  const decisionSha256 = createHash('sha256')
    .update(JSON.stringify(decisionBody), 'utf8')
    .digest('hex');

  return Object.freeze({
    graph_admitted_memories: Object.freeze(graphAdmittedMemories),
    retained_evidence_memories: Object.freeze(retainedEvidenceMemories),
    decision: Object.freeze({ ...decisionBody, decision_sha256: decisionSha256 }),
  });
}

/**
 * Build the response-local clean-selection boundary over the complete ordered
 * post-fusion population. Ineligible evidence remains retained canonically and
 * is committed to a separate decision set; only the current response's
 * selection pool changes. "Clean eligible" means no exact Canary marker, no
 * native retained-quarantine disposition, and no response-local untrusted
 * epistemic handling. It does not establish truth.
 */
export function buildCanaryCleanSelectionBoundary(
  memories = [],
  topK = 10,
  { classificationMap = createCanaryContentClassificationMap() } = {},
) {
  const candidates = Array.isArray(memories) ? memories : [];
  const boundedTopK = Math.max(1, Math.min(200, Math.trunc(Number(topK) || 10)));
  const cleanEligibleMemories = [];
  const retainedEvidenceMemories = [];
  const records = [];
  const classified = classificationMap.classifyMemories(candidates);

  for (let index = 0; index < candidates.length; index += 1) {
    const memory = candidates[index];
    const classification = classified.records[index];
    const memoryId = classification.memory_id;
    const markerPresent = classification.canary_marker_present;
    const quarantineEvidence = classification.retained_quarantine_evidence;
    const epistemicUntrusted = memory?.evidence_handling === 'untrusted_reference_only';
    const selectionEligible = !markerPresent && !quarantineEvidence && !epistemicUntrusted;
    const record = Object.freeze({
      memory_id: memoryId,
      original_rank: index + 1,
      content_commitment_sha256: classification.content_commitment_sha256,
      content_scan_sha256: classification.content_scan_sha256,
      canary_marker_present: markerPresent,
      retained_quarantine_evidence: quarantineEvidence,
      retained_epistemic_evidence: epistemicUntrusted,
      selection_eligible: selectionEligible,
      retained_reason: [
        markerPresent ? 'canary_marker' : null,
        quarantineEvidence ? 'retained_quarantine' : null,
        epistemicUntrusted ? 'untrusted_epistemic_evidence' : null,
      ].filter(Boolean).join('+') || null,
    });
    records.push(record);
    if (selectionEligible) cleanEligibleMemories.push(memory);
    else retainedEvidenceMemories.push(memory);
  }

  const retainedEvidenceRecords = Object.freeze(
    records.filter((record) => !record.selection_eligible),
  );
  const rawTopK = records.slice(0, boundedTopK);
  const expectedSelectedCount = Math.min(boundedTopK, cleanEligibleMemories.length);
  const rawTopKCleanEligibleCount = rawTopK
    .filter((record) => record.selection_eligible).length;
  const cleanBackfillCount = Math.max(
    0,
    expectedSelectedCount - rawTopKCleanEligibleCount,
  );
  const boundaryBody = Object.freeze({
    schema: CANARY_CLEAN_SELECTION_CONTRACT.schema,
    eligibility_equation: CANARY_CLEAN_SELECTION_CONTRACT.eligibility_equation,
    selected_count_equation: CANARY_CLEAN_SELECTION_CONTRACT.selected_count_equation,
    backfill_equation: CANARY_CLEAN_SELECTION_CONTRACT.backfill_equation,
    requested_top_k: boundedTopK,
    candidate_count: records.length,
    clean_eligible_count: cleanEligibleMemories.length,
    retained_evidence_count: retainedEvidenceRecords.length,
    retained_epistemic_evidence_count: records.filter(
      (record) => record.retained_epistemic_evidence,
    ).length,
    expected_selected_count: expectedSelectedCount,
    raw_top_k_clean_eligible_count: rawTopKCleanEligibleCount,
    clean_backfill_count: cleanBackfillCount,
    unfilled_clean_slot_count: Math.max(0, boundedTopK - expectedSelectedCount),
    serialized_candidate_bytes: classified.records.reduce(
      (sum, record) => sum + record.serialized_content_bytes,
      0,
    ),
    classification_map_root_sha256:
      classificationMap.snapshot().classification_map_root_sha256,
    records: Object.freeze(records),
    retained_evidence_records: retainedEvidenceRecords,
    retained_decision_set_sha256: createHash('sha256')
      .update(canonicalJson(retainedEvidenceRecords), 'utf8')
      .digest('hex'),
    clean_label_establishes_content_truth: false,
    canonical_memory_mutated: false,
    retention_changed: false,
    deletion_performed: false,
    persistent_suppression_performed: false,
  });
  const boundarySha256 = createHash('sha256')
    .update(canonicalJson(boundaryBody), 'utf8')
    .digest('hex');

  return Object.freeze({
    clean_eligible_memories: Object.freeze(cleanEligibleMemories),
    retained_evidence_memories: Object.freeze(retainedEvidenceMemories),
    boundary: Object.freeze({ ...boundaryBody, boundary_sha256: boundarySha256 }),
  });
}

/** Finalize the signed decision with the exact clean-only top-k actually used. */
export function finalizeCanaryCleanSelectionDecision(
  boundaryResult,
  selectedMemories = [],
  { returnPath = 'conformance_fixture' } = {},
) {
  const boundary = boundaryResult?.boundary;
  if (!boundary || !/^[0-9a-f]{64}$/.test(String(boundary.boundary_sha256 || ''))) {
    throw new Error('canary_clean_selection_boundary_invalid');
  }
  const normalizedReturnPath = String(returnPath || '').trim();
  if (normalizedReturnPath !== 'conformance_fixture'
    && !CANARY_CLEAN_SELECTION_RETURN_PATHS.includes(normalizedReturnPath)) {
    throw new Error('canary_clean_selection_return_path_invalid');
  }
  const eligibleIds = new Set(
    boundary.records
      .filter((record) => record.selection_eligible)
      .map((record) => record.memory_id),
  );
  const selectedIds = [];
  const seenIds = new Set();
  for (const memory of Array.isArray(selectedMemories) ? selectedMemories : []) {
    const memoryId = canaryMemoryId(memory);
    if (!memoryId || seenIds.has(memoryId)) {
      throw new Error(memoryId
        ? 'canary_clean_selection_selected_duplicate_memory_id'
        : 'canary_clean_selection_selected_memory_id_invalid');
    }
    if (!eligibleIds.has(memoryId)) {
      throw new Error('canary_clean_selection_ineligible_memory_selected');
    }
    seenIds.add(memoryId);
    selectedIds.push(memoryId);
  }
  if (selectedIds.length !== boundary.expected_selected_count) {
    throw new Error('canary_clean_selection_selected_count_invalid');
  }
  const selectedSetSha256 = createHash('sha256')
    .update(canonicalJson(selectedIds), 'utf8')
    .digest('hex');
  const decisionBody = Object.freeze({
    schema: CANARY_CLEAN_SELECTION_CONTRACT.schema,
    return_path: normalizedReturnPath,
    boundary_sha256: boundary.boundary_sha256,
    classification_map_root_sha256: boundary.classification_map_root_sha256,
    eligibility_equation: boundary.eligibility_equation,
    selected_count_equation: boundary.selected_count_equation,
    backfill_equation: boundary.backfill_equation,
    requested_top_k: boundary.requested_top_k,
    candidate_count: boundary.candidate_count,
    clean_eligible_count: boundary.clean_eligible_count,
    retained_evidence_count: boundary.retained_evidence_count,
    retained_epistemic_evidence_count: boundary.retained_epistemic_evidence_count,
    selected_clean_count: selectedIds.length,
    clean_backfill_count: boundary.clean_backfill_count,
    unfilled_clean_slot_count: boundary.unfilled_clean_slot_count,
    selected_clean_memory_ids: Object.freeze(selectedIds),
    selected_clean_set_sha256: selectedSetSha256,
    retained_evidence_records: boundary.retained_evidence_records,
    retained_decision_set_sha256: boundary.retained_decision_set_sha256,
    selected_top_k_subseteq_clean_eligible_evidence: true,
    retained_evidence_canonical_state_unchanged: true,
    clean_label_establishes_content_truth: false,
    canonical_memory_mutated: false,
    retention_changed: false,
    deletion_performed: false,
    persistent_suppression_performed: false,
  });
  const decisionSha256 = createHash('sha256')
    .update(canonicalJson(decisionBody), 'utf8')
    .digest('hex');
  return Object.freeze({ ...decisionBody, decision_sha256: decisionSha256 });
}

/** Append and await the exact clean-only top-k and retained-decision receipt. */
export async function governCanaryCleanTopKSelection({
  boundaryResult,
  selectedMemories,
  returnPath,
  companyId,
  subjectAgentId,
  recallAuthority,
  parentEventId = null,
} = {}) {
  if (!recallAuthority?.requestAuthority) {
    throw new Error('canary_clean_selection_recall_authority_required');
  }
  if (!CANARY_CLEAN_SELECTION_RETURN_PATHS.includes(String(returnPath || '').trim())) {
    throw new Error('canary_clean_selection_runtime_return_path_invalid');
  }
  const decision = finalizeCanaryCleanSelectionDecision(
    boundaryResult,
    selectedMemories,
    { returnPath },
  );
  const receipt = await logEvent(
    companyId || COMPANY,
    subjectAgentId || recallAuthority.actorAgentId,
    'canary_clean_selection_decision',
    decision.decision_sha256,
    {
      reasoning: 'The response top-k is selected only from clean-eligible evidence. Marked or retained-quarantine evidence remains canonical and is committed to a separate signed decision set; clean candidates below the raw cutoff backfill excluded slots.',
      source_knowledge: 'Kill-Chain Canaries stage evidence + MAGMA RRF/top-k retrieval + HOM-AIMOS signed clean-selection composition',
      ...decision,
    },
    parentEventId || recallAuthority.requestAuthority.requestAdmissionEventId || null,
    { authority: recallAuthority.requestAuthority, returnReceipt: true },
  );
  return Object.freeze({
    decision,
    receipt: Object.freeze({
      event_id: receipt.event_id,
      ledger_seq: receipt.ledger_seq,
      content_hash: receipt.content_hash,
      mutation_hash: receipt.mutation_hash,
    }),
  });
}

function normalizeCanaryFinalClosureConsumers(consumers = {}) {
  const normalized = [];
  for (const [consumer, decision] of Object.entries(consumers || {})) {
    if (!decision) continue;
    const decisionSha256 = String(decision?.decision_sha256 || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(decisionSha256)) {
      throw new Error(`canary_final_closure_consumer_decision_invalid:${consumer}`);
    }
    normalized.push(Object.freeze({
      consumer: String(consumer),
      decision_sha256: decisionSha256,
      classification_map_root_sha256:
        /^[0-9a-f]{64}$/.test(String(decision?.classification_map_root_sha256 || '').trim().toLowerCase())
          ? String(decision.classification_map_root_sha256).trim().toLowerCase()
          : null,
    }));
  }
  return Object.freeze(normalized.sort((left, right) => left.consumer.localeCompare(right.consumer)));
}

/**
 * Append the one terminal Canary/Aladdin closure for a native recall return.
 * No graph may append a private disclosure closure. The receipt commits the
 * final request-local classification map, clean selection, epistemic decision,
 * selected identities, retained decision set, and every graph/fusion consumer.
 */
export async function governCanaryRecallFinalClosure({
  classificationMap,
  returnPath,
  selectedMemories,
  cleanSelection,
  epistemicDecision,
  epistemicReceipt,
  contentStateEvidenceScope,
  consumers = {},
  companyId,
  subjectAgentId,
  recallAuthority,
} = {}) {
  if (!classificationMap?.classifyMemories || !classificationMap?.snapshot) {
    throw new Error('canary_final_closure_classification_map_required');
  }
  if (!recallAuthority?.requestAuthority) {
    throw new Error('canary_final_closure_recall_authority_required');
  }
  const normalizedReturnPath = String(returnPath || '').trim();
  if (!CANARY_CLEAN_SELECTION_RETURN_PATHS.includes(normalizedReturnPath)) {
    throw new Error('canary_final_closure_return_path_invalid');
  }
  const cleanDecision = cleanSelection?.decision;
  if (!cleanDecision || cleanDecision.return_path !== normalizedReturnPath) {
    throw new Error('canary_final_closure_clean_selection_invalid');
  }
  const epistemicDecisionSha256 = String(
    epistemicDecision?.decision_sha256 || '',
  ).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(epistemicDecisionSha256)) {
    throw new Error('canary_final_closure_epistemic_decision_invalid');
  }
  const evidenceScopeDecision = contentStateEvidenceScope?.decision;
  const evidenceScopeDecisionSha256 = String(
    evidenceScopeDecision?.decision_sha256 || '',
  ).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(evidenceScopeDecisionSha256)
      || !/^[0-9a-f]{64}$/.test(String(
        evidenceScopeDecision?.authorized_class_commitment_sha256 || '',
      ).toLowerCase())
      || !/^[0-9a-f]{64}$/.test(String(
        evidenceScopeDecision?.retained_blocked_decision_set_sha256 || '',
      ).toLowerCase())) {
    throw new Error('canary_final_closure_content_state_evidence_scope_invalid');
  }
  const selected = Array.isArray(selectedMemories) ? selectedMemories : [];
  const classified = classificationMap.classifyMemories(selected);
  if (classified.records.some((record) => !record.selection_eligible)) {
    throw new Error('canary_final_closure_ineligible_selected_memory');
  }
  const selectedIds = Object.freeze(classified.records.map((record) => record.memory_id));
  if (selectedIds.length !== cleanDecision.selected_clean_count
    || selectedIds.some((memoryId, index) => memoryId !== cleanDecision.selected_clean_memory_ids[index])) {
    throw new Error('canary_final_closure_selected_set_mismatch');
  }
  const classificationSnapshot = classificationMap.snapshot();
  if (classificationSnapshot.classification_map_root_sha256
    !== cleanDecision.classification_map_root_sha256) {
    throw new Error('canary_final_closure_classification_map_drift');
  }
  const consumerRecords = normalizeCanaryFinalClosureConsumers(consumers);
  const consumerCommitmentRootSha256 = createHash('sha256')
    .update(canonicalJson(consumerRecords), 'utf8')
    .digest('hex');
  const body = Object.freeze({
    schema: CANARY_FINAL_CLOSURE_CONTRACT.schema,
    return_path: normalizedReturnPath,
    classification_map: classificationSnapshot,
    classification_map_root_sha256:
      classificationSnapshot.classification_map_root_sha256,
    unique_content_count: classificationSnapshot.unique_content_count,
    content_scans_executed: classificationSnapshot.content_scans_executed,
    classification_requests: classificationSnapshot.classification_requests,
    classification_cache_hits: classificationSnapshot.classification_cache_hits,
    content_rescans_executed: 0,
    clean_selection_decision_sha256: cleanDecision.decision_sha256,
    retained_decision_set_sha256: cleanDecision.retained_decision_set_sha256,
    epistemic_decision_sha256: epistemicDecisionSha256,
    content_state_evidence_scope_decision_sha256: evidenceScopeDecisionSha256,
    content_state_evidence_scope_event_id:
      contentStateEvidenceScope?.receipt?.event_id || null,
    authorized_class_commitment_sha256:
      evidenceScopeDecision.authorized_class_commitment_sha256,
    state_view_root_sha256: evidenceScopeDecision.state_view_root_sha256,
    occurrence_view_root_sha256: evidenceScopeDecision.occurrence_view_root_sha256,
    retained_blocked_decision_set_sha256:
      evidenceScopeDecision.retained_blocked_decision_set_sha256,
    evidence_root_sha256s: evidenceScopeDecision.evidence_root_sha256s,
    eligibility_exhaustion_reason:
      evidenceScopeDecision.eligibility_exhaustion_reason,
    no_epistemic_exoneration: evidenceScopeDecision.no_exoneration === true,
    selected_clean_memory_ids: selectedIds,
    selected_clean_set_sha256: cleanDecision.selected_clean_set_sha256,
    selected_clean_count: selectedIds.length,
    consumer_records: consumerRecords,
    consumer_commitment_root_sha256: consumerCommitmentRootSha256,
    selected_top_k_subseteq_clean_eligible_evidence: true,
    one_request_local_classification_map: true,
    classification_map_independently_recomputable: true,
    final_closure_receipt_count: 1,
    canonical_memory_mutated: false,
    retention_changed: false,
    deletion_performed: false,
    persistent_suppression_performed: false,
    saber_runtime_authority: false,
  });
  const decision = Object.freeze({
    ...body,
    decision_sha256: createHash('sha256').update(canonicalJson(body), 'utf8').digest('hex'),
  });
  const receipt = await logEvent(
    companyId || COMPANY,
    subjectAgentId || recallAuthority.actorAgentId,
    'canary_recall_final_closure',
    decision.decision_sha256,
    {
      reasoning: 'One request-local content-hash classification map governs graph admission, clean selection, and final disclosure. This terminal receipt replaces per-graph rescans and per-graph disclosure closures while retaining all canonical evidence.',
      source_knowledge: 'Kill-Chain Canaries + MAGMA + HOM-AIMOS Aladdin retention composition',
      ...decision,
    },
    epistemicReceipt?.event_id || null,
    { authority: recallAuthority.requestAuthority, returnReceipt: true },
  );
  return Object.freeze({
    memories: Object.freeze([...selected]),
    decision,
    receipt: Object.freeze({
      event_id: receipt.event_id,
      ledger_seq: receipt.ledger_seq,
      content_hash: receipt.content_hash,
      mutation_hash: receipt.mutation_hash,
    }),
  });
}

/**
 * Append and await the request-bound production admission receipt before
 * MAGMA may observe the graph-admitted subset.
 */
export async function governCanaryMagmaGraphAdmission({
  memories,
  classificationMap,
  companyId,
  subjectAgentId,
  recallAuthority,
} = {}) {
  if (!recallAuthority?.requestAuthority) {
    throw new Error('canary_magma_composition_recall_authority_required');
  }
  if (!classificationMap?.classifyMemories || !classificationMap?.snapshot) {
    throw new Error('canary_magma_composition_classification_map_required');
  }
  const composition = buildCanaryMagmaGraphAdmission(memories, { classificationMap });
  const decision = composition.decision;
  const receipt = await logEvent(
    companyId || COMPANY,
    subjectAgentId || recallAuthority.actorAgentId,
    'canary_magma_graph_admission',
    decision.decision_sha256,
    {
      reasoning: 'Retained Canary/quarantine evidence remains in the native candidate population but cannot seed, traverse, or gain a graph-family vote. The retained canary_magma operation name is a verifier-compatibility identifier; MAGMA itself is dormant.',
      source_knowledge: 'Kill-Chain Canaries stage evidence + HOM-AIMOS signed scale-bounded graph-family composition',
      ...decision,
    },
    recallAuthority.requestAuthority.requestAdmissionEventId || null,
    { authority: recallAuthority.requestAuthority, returnReceipt: true },
  );

  return Object.freeze({
    ...composition,
    receipt: Object.freeze({
      event_id: receipt.event_id,
      ledger_seq: receipt.ledger_seq,
      content_hash: receipt.content_hash,
      mutation_hash: receipt.mutation_hash,
    }),
  });
}

/**
 * Log a canary detection event at a specific pipeline stage.
 *
 * @param {string} canaryToken
 * @param {'EXPOSED'|'PERSISTED'|'OBSERVED_AT_RELAY_GATE'|'RELAY_BLOCKED'|'RELAYED'|'EXECUTED'} stage
 * @param {string} location - where detected
 * @param {string} runId
 * @param {object} context
 * @param {string|null} [context.parentEventId]
 * @param {object|null} [context.authority]
 * @param {boolean} [context.toolInvoked]
 * @param {boolean} [context.dispatchBlocked]
 */
export async function logCanaryEvent(canaryToken, stage, location, runId = '', context = {}) {
  if (!STAGES.includes(stage)) throw new Error(`invalid_canary_stage:${stage}`);
  if (['OBSERVED_AT_RELAY_GATE', 'RELAY_BLOCKED', 'RELAYED'].includes(stage)
      && !/^[0-9a-f]{64}$/.test(String(context.relayAttemptSha256 || ''))) {
    throw new Error(`canary_relay_attempt_sha256_required:${stage}`);
  }
  if (['RELAY_BLOCKED', 'RELAYED'].includes(stage)) {
    const observationEventId = String(context.relayObservationEventId || '').trim();
    if (!observationEventId || String(context.parentEventId || '').trim() !== observationEventId) {
      throw new Error(`canary_relay_observation_parent_required:${stage}`);
    }
  }
  if (stage === 'RELAYED' && context.modelInvocationCompleted !== true) {
    throw new Error('canary_relayed_requires_completed_model_invocation');
  }
  if (stage === 'RELAY_BLOCKED' && context.modelInvocationCompleted === true) {
    throw new Error('canary_relay_blocked_model_invocation_conflict');
  }
  const event = {
    canaryToken,
    stage,
    location,
    runId,
    timestamp: Date.now(),
    toolInvoked: context.toolInvoked === true,
    dispatchBlocked: context.dispatchBlocked === true,
  };
  const dispatchState = event.dispatchBlocked
    ? 'The outbound dispatch was blocked before the tool function was invoked.'
    : event.toolInvoked
      ? 'The tool function was invoked.'
      : 'No tool invocation is attributed to this stage.';
  const operation = stage === 'EXECUTED'
    ? 'canary_executed'
    : stage === 'OBSERVED_AT_RELAY_GATE'
      ? 'canary_relay_gate_observed'
      : stage === 'RELAY_BLOCKED'
        ? 'canary_relay_blocked'
        : stage === 'RELAYED'
          ? 'canary_relayed'
          : 'security_detection';
  const receipt = await logEvent(
    COMPANY,
    'canary-tracker',
    operation,
    stage === 'EXECUTED' ? `canary:${canaryToken}` : `canary:${stage.toLowerCase()}:${canaryToken}`,
    {
      reasoning: `Security event: Canary token ${canaryToken} reached the ${stage} boundary at ${location}. ${dispatchState}`,
      severity: stage === 'EXECUTED' ? 'critical' : stage === 'RELAYED' ? 'high' : 'medium',
      details: {
        canaryToken,
        stage,
        location,
        runId,
        tool_invoked: event.toolInvoked,
        dispatch_blocked: event.dispatchBlocked,
        relay_attempt_sha256: context.relayAttemptSha256 || null,
        relay_observation_event_id: context.relayObservationEventId || null,
        model_invocation_completed: context.modelInvocationCompleted === true,
      },
      source_knowledge: 'Kill-Chain Canaries — stage-level propagation tracking',
    },
    context.parentEventId || null,
    { authority: context.authority || null, returnReceipt: true },
  );
  const provenEvent = Object.freeze({ ...event, receipt });
  _eventLog.push(provenEvent);
  if (stage === 'EXECUTED') {
    console.error(`[CANARY-ALERT] Injection reached the EXECUTED boundary: ${canaryToken} at ${location}`);
  }
  return provenEvent;
}

/**
 * Middleware: scan tool results for canary tokens.
 * Call after each tool execution to detect EXPOSED stage.
 *
 * @param {string} toolName
 * @param {string} toolResult
 * @param {string} runId
 * @returns {{ canariesFound: string[], stage: string }}
 */
export async function scanToolResult(toolName, toolResult, runId = '', context = {}) {
  const canaries = detectCanaries(toolResult);
  const events = [];
  for (const token of canaries) {
    events.push(await logCanaryEvent(token, 'EXPOSED', `tool_result:${toolName}`, runId, context));
  }
  return {
    canariesFound: canaries,
    stage: 'EXPOSED',
    events,
    kill_chain_diagnostics: buildCanaryKillChainDiagnostics(events, { cohortId: runId }),
  };
}

/**
 * Middleware: scan memory write for canary tokens.
 * Call before persisting to Aimos to detect PERSISTED stage.
 *
 * @param {string} key
 * @param {string} value
 * @param {string} runId
 * @returns {{ canariesFound: string[], blocked: boolean }}
 */
export async function scanMemoryWrite(key, value, runId = '', context = {}) {
  const canaries = detectCanaries([key, value]);
  const events = [];
  for (const token of canaries) {
    events.push(await logCanaryEvent(token, 'PERSISTED', `memory_write:${key}`, runId, context));
  }
  return {
    canariesFound: canaries,
    blocked: canaries.length > 0,
    events,
    kill_chain_diagnostics: buildCanaryKillChainDiagnostics(events, { cohortId: runId }),
  };
}

/**
 * Observe only recalled memory at the pre-model relay gate. Observation is not
 * delivery and must never be labeled RELAYED. User input, system instructions,
 * and model output are not relay evidence.
 *
 * @param {string|object} recalledMemory
 * @param {string} runId
 * @returns {{ canariesFound: string[] }}
 */
export async function observeCanariesAtRelayGate(recalledMemory, runId = '', context = {}) {
  const canaries = detectCanaries(recalledMemory);
  const events = [];
  const sourceAgentId = String(context.sourceAgentId || 'memory');
  const targetAgentId = String(context.targetAgentId || 'model');
  const relayAttemptSha256 = createHash('sha256').update(canonicalJson({
    schema: CANARY_RELAY_STAGE_CONTRACT.schema,
    run_id: String(runId || ''),
    source_agent_id: sourceAgentId,
    target_agent_id: targetAgentId,
    recalled_memory_sha256: createHash('sha256')
      .update(renderCanaryText(recalledMemory), 'utf8')
      .digest('hex'),
    marker_commitments_sha256: canaries
      .map((token) => createHash('sha256').update(token, 'utf8').digest('hex'))
      .sort(),
  })).digest('hex');
  for (const token of canaries) {
    events.push(await logCanaryEvent(
      token,
      'OBSERVED_AT_RELAY_GATE',
      `relay_gate:${sourceAgentId}->${targetAgentId}`,
      runId,
      { ...context, relayAttemptSha256 },
    ));
  }
  return Object.freeze({
    schema: 'hom-aimos/canary-relay-observation/v1',
    canariesFound: Object.freeze([...canaries]),
    events: Object.freeze([...events]),
    sourceAgentId,
    targetAgentId,
    runId: String(runId || ''),
    relayAttemptSha256,
    kill_chain_diagnostics: buildCanaryKillChainDiagnostics(events, { cohortId: runId }),
  });
}

function assertRelayObservation(observation) {
  if (observation?.schema !== 'hom-aimos/canary-relay-observation/v1') {
    throw new Error('canary_relay_observation_required');
  }
  if (!Array.isArray(observation.canariesFound) || !Array.isArray(observation.events)) {
    throw new Error('canary_relay_observation_invalid');
  }
  if (observation.canariesFound.length !== observation.events.length) {
    throw new Error('canary_relay_observation_event_count_invalid');
  }
  if (!/^[0-9a-f]{64}$/.test(String(observation.relayAttemptSha256 || ''))) {
    throw new Error('canary_relay_attempt_sha256_invalid');
  }
}

async function closeCanaryRelayTransition(observation, stage, context = {}) {
  assertRelayObservation(observation);
  if (stage === 'RELAYED' && context.modelInvocationCompleted !== true) {
    throw new Error('canary_relayed_requires_completed_model_invocation');
  }
  if (observation.canariesFound.length > 0) {
    const existingState = _relayTerminalStates.get(observation);
    if (existingState) {
      throw new Error(`canary_relay_terminal_already_recorded:${existingState}`);
    }
    _relayTerminalStates.set(observation, 'IN_PROGRESS');
  }
  const events = [];
  try {
    for (let index = 0; index < observation.canariesFound.length; index += 1) {
      const token = observation.canariesFound[index];
      const observed = observation.events[index];
      const observedEventId = observed?.receipt?.event_id || null;
      if (!observedEventId) throw new Error('canary_relay_observation_receipt_required');
      events.push(await logCanaryEvent(
        token,
        stage,
        `${stage === 'RELAY_BLOCKED' ? 'relay_blocked' : 'relay_delivered'}:${observation.sourceAgentId}->${observation.targetAgentId}`,
        observation.runId,
        {
          ...context,
          parentEventId: observedEventId,
          relayAttemptSha256: observation.relayAttemptSha256,
          relayObservationEventId: observedEventId,
        },
      ));
    }
    if (observation.canariesFound.length > 0) _relayTerminalStates.set(observation, stage);
  } catch (error) {
    if (observation.canariesFound.length > 0) {
      _relayTerminalStates.set(observation, `INDETERMINATE_${stage}`);
    }
    throw error;
  }
  return Object.freeze({
    stage,
    canariesFound: observation.canariesFound,
    events: Object.freeze(events),
    relayAttemptSha256: observation.relayAttemptSha256,
    kill_chain_diagnostics: buildCanaryKillChainDiagnostics(
      [...observation.events, ...events],
      { cohortId: observation.runId },
    ),
  });
}

export async function recordCanaryRelayBlocked(observation, context = {}) {
  return closeCanaryRelayTransition(observation, 'RELAY_BLOCKED', {
    ...context,
    modelInvocationCompleted: false,
  });
}

export async function recordCanariesRelayed(observation, context = {}) {
  return closeCanaryRelayTransition(observation, 'RELAYED', context);
}

/**
 * Middleware: scan outbound tool call arguments for canary tokens.
 * Call before executing any tool to detect EXECUTED stage.
 *
 * @param {string} toolName
 * @param {string} toolArgs - JSON-stringified arguments
 * @param {string} runId
 * @returns {{ canariesFound: string[], blocked: boolean }}
 */
export async function scanToolExecution(toolName, toolArgs, runId = '', context = {}) {
  const canaries = detectCanaries(toolArgs);
  const events = [];
  for (const token of canaries) {
    events.push(await logCanaryEvent(token, 'EXECUTED', `tool_exec:${toolName}`, runId, {
      ...context,
      toolInvoked: false,
      dispatchBlocked: true,
    }));
  }
  return {
    canariesFound: canaries,
    blocked: canaries.length > 0,
    events,
    kill_chain_diagnostics: buildCanaryKillChainDiagnostics(events, { cohortId: runId }),
  };
}

/**
 * Compute objective drift: TF-IDF cosine distance between current tool args
 * and original task description.
 *
 * @param {string} originalTask
 * @param {string} currentToolArgs
 * @returns {number} drift score (0 = aligned, 1 = completely diverged)
 */
export function computeObjectiveDrift(originalTask, currentToolArgs) {
  const taskTerms = extractTerms(originalTask);
  const argsTerms = extractTerms(currentToolArgs);

  if (taskTerms.size === 0 || argsTerms.size === 0) return 1.0;

  // Jaccard-based drift (simplified TF-IDF proxy)
  const intersection = new Set([...taskTerms].filter(t => argsTerms.has(t)));
  const union = new Set([...taskTerms, ...argsTerms]);

  return 1 - (intersection.size / union.size);
}

/**
 * Token-overlap provenance heuristic.
 * Match alphanumeric tokens (>=4 chars) between tool args and prior tool results.
 *
 * @param {string} toolArgs
 * @param {string[]} priorToolResults
 * @returns {{ matched: boolean, overlapCount: number, coverageRatio: number }}
 */
export function checkTokenProvenance(toolArgs, priorToolResults) {
  const argTokens = extractTerms(toolArgs);
  if (argTokens.size === 0) return { matched: false, overlapCount: 0, coverageRatio: 0 };

  const allPriorTokens = new Set();
  for (const result of priorToolResults) {
    for (const t of extractTerms(result)) allPriorTokens.add(t);
  }

  const overlap = [...argTokens].filter(t => allPriorTokens.has(t));
  const coverageRatio = overlap.length / argTokens.size;

  return {
    matched: overlap.length >= 3 || coverageRatio >= 0.2,
    overlapCount: overlap.length,
    coverageRatio
  };
}

/**
 * Extract alphanumeric tokens >= 4 chars.
 */
function extractTerms(text) {
  const tokens = String(text || '').toLowerCase().match(/[a-z0-9]{4,}/g) || [];
  return new Set(tokens);
}

/**
 * Get the full canary event log for a run.
 * @param {string} runId
 * @returns {CanaryEvent[]}
 */
export function getRunEvents(runId) {
  return _eventLog.filter(e => e.runId === runId);
}

/**
 * Get stage-level propagation summary.
 * Shows how far injections penetrated the pipeline.
 */
export function getPropagationSummary() {
  const summary = {
    EXPOSED: 0,
    PERSISTED: 0,
    OBSERVED_AT_RELAY_GATE: 0,
    RELAY_BLOCKED: 0,
    RELAYED: 0,
    EXECUTED: 0,
  };
  for (const event of _eventLog) {
    summary[event.stage] = (summary[event.stage] || 0) + 1;
  }
  return summary;
}

/**
 * Compute signed-runtime relay decontamination evidence for one exact cohort.
 *
 * The paper supplies the prose metric. AIMOS adds unique-token set accounting,
 * exact cohort binding, and explicit undefined/indeterminate states so repeated
 * observations, cross-run events, and unfinished relay transitions cannot
 * manufacture a favorable number.
 */
export function getDecontaminationRate(runId, issuedTokens = null) {
  const cohortId = String(runId || '').trim();
  if (!cohortId) throw new Error('canary_decontamination_cohort_required');
  return buildCanaryRelayDecontaminationEvidence(
    getRunEvents(cohortId),
    { cohortId, issuedTokens },
  );
}

function canaryMetricResult({
  cohortId,
  status,
  reason,
  exposed,
  blocked,
  relayed,
  duplicateExposed,
  duplicateBlocked,
  duplicateRelayed,
  invalidEventCount,
  issuedTokens,
  issuedManifestPresent,
  invalidIssuedTokenCount,
  duplicateIssuedTokenCount,
  unissuedEventTokens,
}) {
  const relayedFromExposed = new Set([...relayed].filter((token) => exposed.has(token)));
  const blockedFromExposed = new Set([...blocked].filter((token) => exposed.has(token)));
  const relayedWithoutExposure = [...relayed].filter((token) => !exposed.has(token)).length;
  const blockedWithoutExposure = [...blocked].filter((token) => !exposed.has(token)).length;
  const conflictingTerminal = [...relayed].filter((token) => blocked.has(token)).length;
  const unresolvedExposed = [...exposed]
    .filter((token) => !blocked.has(token) && !relayed.has(token)).length;
  const value = status === 'defined'
    ? 1 - (relayedFromExposed.size / exposed.size)
    : null;
  const issuedTokenCommitment = createHash('sha256')
    .update(canonicalJson([...issuedTokens].sort()), 'utf8')
    .digest('hex');
  return Object.freeze({
    schema: CANARY_RELAY_DECONTAMINATION_CONTRACT.schema,
    cohort_id: cohortId || null,
    status,
    reason,
    value,
    issued_token_manifest_present: issuedManifestPresent,
    issued_token_count: issuedTokens.size,
    issued_token_set_commitment_sha256: issuedTokenCommitment,
    invalid_issued_token_count: invalidIssuedTokenCount,
    duplicate_issued_token_count: duplicateIssuedTokenCount,
    unissued_relevant_token_count: unissuedEventTokens.size,
    unique_exposed_token_count: exposed.size,
    unique_relay_blocked_token_count: blocked.size,
    unique_relayed_token_count: relayed.size,
    relayed_from_exposed_unique_token_count: relayedFromExposed.size,
    decontaminated_unique_token_count: blockedFromExposed.size,
    unresolved_exposed_unique_token_count: unresolvedExposed,
    relayed_without_exposure_unique_token_count: relayedWithoutExposure,
    blocked_without_exposure_unique_token_count: blockedWithoutExposure,
    conflicting_terminal_unique_token_count: conflictingTerminal,
    duplicate_exposed_event_count: duplicateExposed,
    duplicate_relay_blocked_event_count: duplicateBlocked,
    duplicate_relayed_event_count: duplicateRelayed,
    invalid_relevant_event_count: invalidEventCount,
    formula: CANARY_RELAY_DECONTAMINATION_CONTRACT.equation,
    token_values_disclosed: false,
  });
}

export function buildCanaryRelayDecontaminationEvidence(
  events,
  { cohortId = null, issuedTokens = null } = {},
) {
  const eventList = Array.isArray(events) ? events : [];
  const requestedCohort = String(cohortId || '').trim();
  const relevantStages = new Set(['EXPOSED', 'RELAY_BLOCKED', 'RELAYED']);
  const relevantEvents = eventList.filter((event) => relevantStages.has(event?.stage));
  const observedCohorts = [...new Set(relevantEvents
    .map((event) => String(event?.runId || '').trim())
    .filter(Boolean))];
  const exactCohort = requestedCohort || (observedCohorts.length === 1 ? observedCohorts[0] : '');
  const exposed = new Set();
  const blocked = new Set();
  const relayed = new Set();
  const issued = new Set();
  const unissuedEventTokens = new Set();
  let duplicateExposed = 0;
  let duplicateBlocked = 0;
  let duplicateRelayed = 0;
  let invalidEventCount = 0;
  let invalidIssuedTokenCount = 0;
  let duplicateIssuedTokenCount = 0;
  const issuedManifestPresent = Array.isArray(issuedTokens);

  for (const rawToken of issuedManifestPresent ? issuedTokens : []) {
    const token = String(rawToken || '').trim();
    if (!/^SECRET-[A-F0-9]{8}$/.test(token)) {
      invalidIssuedTokenCount += 1;
      continue;
    }
    if (issued.has(token)) duplicateIssuedTokenCount += 1;
    issued.add(token);
  }

  if (!exactCohort && relevantEvents.length > 0) {
    return canaryMetricResult({
      cohortId: null,
      status: 'indeterminate',
      reason: observedCohorts.length > 1 ? 'cohort_ambiguous' : 'cohort_missing',
      exposed,
      blocked,
      relayed,
      duplicateExposed,
      duplicateBlocked,
      duplicateRelayed,
      invalidEventCount,
      issuedTokens: issued,
      issuedManifestPresent,
      invalidIssuedTokenCount,
      duplicateIssuedTokenCount,
      unissuedEventTokens,
    });
  }

  for (const event of relevantEvents) {
    if (String(event?.runId || '').trim() !== exactCohort) continue;
    const token = String(event?.canaryToken || '').trim();
    if (!/^SECRET-[A-F0-9]{8}$/.test(token)) {
      invalidEventCount += 1;
      continue;
    }
    if (!issuedManifestPresent || !issued.has(token)) {
      unissuedEventTokens.add(token);
      continue;
    }
    const target = event.stage === 'EXPOSED'
      ? exposed
      : event.stage === 'RELAY_BLOCKED'
        ? blocked
        : relayed;
    if (target.has(token)) {
      if (event.stage === 'EXPOSED') duplicateExposed += 1;
      else if (event.stage === 'RELAY_BLOCKED') duplicateBlocked += 1;
      else duplicateRelayed += 1;
    }
    target.add(token);
  }

  const common = {
    cohortId: exactCohort,
    exposed,
    blocked,
    relayed,
    duplicateExposed,
    duplicateBlocked,
    duplicateRelayed,
    invalidEventCount,
    issuedTokens: issued,
    issuedManifestPresent,
    invalidIssuedTokenCount,
    duplicateIssuedTokenCount,
    unissuedEventTokens,
  };
  if (invalidIssuedTokenCount > 0) {
    return canaryMetricResult({ ...common, status: 'indeterminate', reason: 'issued_token_manifest_invalid' });
  }
  if (!issuedManifestPresent && relevantEvents.some(
    (event) => String(event?.runId || '').trim() === exactCohort,
  )) {
    return canaryMetricResult({ ...common, status: 'indeterminate', reason: 'issued_token_manifest_required' });
  }
  if (unissuedEventTokens.size > 0) {
    return canaryMetricResult({ ...common, status: 'indeterminate', reason: 'unissued_marker_event' });
  }
  if (invalidEventCount > 0) {
    return canaryMetricResult({ ...common, status: 'indeterminate', reason: 'invalid_relevant_event' });
  }
  if (exposed.size === 0) {
    const terminalWithoutExposure = blocked.size > 0 || relayed.size > 0;
    return canaryMetricResult({
      ...common,
      status: terminalWithoutExposure ? 'indeterminate' : 'undefined',
      reason: terminalWithoutExposure ? 'terminal_event_without_exposure' : 'no_exposed_tokens',
    });
  }
  if ([...blocked].some((token) => relayed.has(token))) {
    return canaryMetricResult({ ...common, status: 'indeterminate', reason: 'conflicting_terminal_outcomes' });
  }
  if ([...blocked, ...relayed].some((token) => !exposed.has(token))) {
    return canaryMetricResult({ ...common, status: 'indeterminate', reason: 'terminal_event_without_exposure' });
  }
  if ([...exposed].some((token) => !blocked.has(token) && !relayed.has(token))) {
    return canaryMetricResult({ ...common, status: 'indeterminate', reason: 'relay_outcomes_incomplete' });
  }
  return canaryMetricResult({ ...common, status: 'defined', reason: null });
}
