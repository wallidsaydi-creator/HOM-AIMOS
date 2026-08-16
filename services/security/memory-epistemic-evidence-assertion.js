// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: memory-epistemic-classifier.js and ECR-4D-N1 verification
// → Calls: node:crypto only
// Pipeline: SECURITY | Pure poison-hypothesis evidence assertion contract
// Basis: AIMOS retained evidence, signed event custody, and Aladdin retention
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

export const MEMORY_POISON_HYPOTHESIS_SCHEMA = 'aimos.memory-poison-hypothesis/v1';
export const MEMORY_EPISTEMIC_EVIDENCE_ASSERTION_SCHEMA = 'aimos.memory-epistemic-evidence-assertion/v1';
export const MEMORY_EPISTEMIC_EVIDENCE_CHAIN_SCHEMA = 'aimos.memory-epistemic-evidence-chain/v1';
export const MEMORY_EPISTEMIC_EVIDENCE_LEDGER_SCHEMA = 'aimos.memory-epistemic-evidence-ledger/v1';
export const MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION = 'aimos.epistemic-seven-state/v2';
export const MEMORY_EPISTEMIC_STATE_CONTINUITY_VERSION = 'aimos.epistemic-state-continuity/v1';

export const MEMORY_EPISTEMIC_LABELS_V2 = Object.freeze([
  'unverified',
  'supported',
  'disputed',
  'poison_suspect',
  'poison_likely',
  'poison_confirmed',
  'poison_refuted',
]);

export const EPISTEMIC_EVIDENCE_RELATIONS = Object.freeze([
  'supports',
  'refutes',
  'inconclusive',
  'contextualizes',
]);

export const EPISTEMIC_EVIDENCE_LINK_RELATIONS = Object.freeze([
  'corroborates',
  'contradicts',
  'duplicates',
  'derives_from',
  'supersedes',
  'retracts',
  'contextualizes',
]);

export const EPISTEMIC_EVIDENCE_TYPES = Object.freeze([
  'origin_provenance',
  'content_signal',
  'cross_source_corroboration',
  'cross_source_contradiction',
  'canary_observation',
  'poisontrace_observation',
  'saber_certificate',
  'attack_replay',
  'runtime_behavior',
  'classification_history',
  'cryptographic_integrity',
  'human_review',
  'model_judgment',
  'external_reference',
  'counterevidence',
  'other_declared',
]);

export const EPISTEMIC_SOURCE_INDEPENDENCE_STATUSES = Object.freeze([
  'independent',
  'dependent',
  'unknown',
]);

export const EPISTEMIC_SOURCE_INDEPENDENCE_BASES = Object.freeze([
  'origin',
  'publisher',
  'agent_epoch',
  'benchmark_target',
  'human_reviewer',
  'runtime_run',
  'external_authority',
  'declared',
]);

const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LABEL_SET = new Set(MEMORY_EPISTEMIC_LABELS_V2);
const RELATION_SET = new Set(EPISTEMIC_EVIDENCE_RELATIONS);
const LINK_RELATION_SET = new Set(EPISTEMIC_EVIDENCE_LINK_RELATIONS);
const EVIDENCE_TYPE_SET = new Set(EPISTEMIC_EVIDENCE_TYPES);
const INDEPENDENCE_STATUS_SET = new Set(EPISTEMIC_SOURCE_INDEPENDENCE_STATUSES);
const INDEPENDENCE_BASIS_SET = new Set(EPISTEMIC_SOURCE_INDEPENDENCE_BASES);
const POISON_LABELS = new Set(['poison_suspect', 'poison_likely', 'poison_confirmed']);

const RESTRICTION_RANK = Object.freeze({
  supported: 0,
  poison_refuted: 0,
  unverified: 1,
  disputed: 2,
  poison_suspect: 3,
  poison_likely: 4,
  poison_confirmed: 5,
});

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function exactString(value, reason) {
  const normalized = String(value || '').trim();
  assert(normalized, reason);
  return normalized;
}

function exactHash(value, reason, { nullable = false } = {}) {
  if (nullable && value == null) return null;
  const normalized = String(value || '').toLowerCase();
  assert(HEX64.test(normalized), reason);
  return normalized;
}

function exactUuid(value, reason) {
  const normalized = String(value || '').toLowerCase();
  assert(UUID.test(normalized), reason);
  return normalized;
}

function exactConfidence(value) {
  const normalized = Number(value);
  assert(Number.isSafeInteger(normalized) && normalized >= 0 && normalized <= 1000,
    'epistemic_evidence_confidence_invalid');
  return normalized;
}

export function canonicalEvidenceJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    assert(Number.isFinite(value), 'epistemic_evidence_non_finite_number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalEvidenceJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalEvidenceJson(value[key])}`
    ));
    return `{${entries.join(',')}}`;
  }
  throw new Error('epistemic_evidence_non_canonical_type');
}

export function sha256EvidenceCanonical(value) {
  return createHash('sha256').update(canonicalEvidenceJson(value), 'utf8').digest('hex');
}

export function buildMemoryPoisonHypothesis({
  memoryId,
  liveContentHash,
} = {}) {
  const body = Object.freeze({
    schema: MEMORY_POISON_HYPOTHESIS_SCHEMA,
    proposition: 'memory_is_poison',
    subject_memory_id: exactUuid(memoryId, 'epistemic_evidence_memory_id_invalid'),
    subject_live_content_hash: exactHash(
      liveContentHash,
      'epistemic_evidence_live_content_hash_invalid',
    ),
  });
  return Object.freeze({ ...body, hypothesis_sha256: sha256EvidenceCanonical(body) });
}

export function verifyMemoryPoisonHypothesis(hypothesis) {
  assert(hypothesis?.schema === MEMORY_POISON_HYPOTHESIS_SCHEMA,
    'epistemic_evidence_hypothesis_schema_invalid');
  const expected = buildMemoryPoisonHypothesis({
    memoryId: hypothesis.subject_memory_id,
    liveContentHash: hypothesis.subject_live_content_hash,
  });
  assert(hypothesis.proposition === expected.proposition
    && hypothesis.hypothesis_sha256 === expected.hypothesis_sha256,
  'epistemic_evidence_hypothesis_hash_invalid');
  return expected;
}

function normalizeSourceIndependence(value = {}) {
  const status = exactString(value.status, 'epistemic_evidence_independence_status_missing');
  const basis = exactString(value.basis, 'epistemic_evidence_independence_basis_missing');
  assert(INDEPENDENCE_STATUS_SET.has(status), 'epistemic_evidence_independence_status_invalid');
  assert(INDEPENDENCE_BASIS_SET.has(basis), 'epistemic_evidence_independence_basis_invalid');
  return Object.freeze({
    status,
    basis,
    source_identity_sha256: exactHash(
      value.source_identity_sha256,
      'epistemic_evidence_source_identity_invalid',
    ),
    independence_group_sha256: exactHash(
      value.independence_group_sha256,
      'epistemic_evidence_independence_group_invalid',
    ),
    basis_evidence_sha256: exactHash(
      value.basis_evidence_sha256,
      'epistemic_evidence_independence_basis_evidence_invalid',
    ),
  });
}

function normalizeEvidenceLinks(links = []) {
  assert(Array.isArray(links), 'epistemic_evidence_links_invalid');
  const normalized = links.map((link) => {
    const relation = exactString(link?.relation, 'epistemic_evidence_link_relation_missing');
    assert(LINK_RELATION_SET.has(relation), 'epistemic_evidence_link_relation_invalid');
    return Object.freeze({
      relation,
      target_assertion_sha256: exactHash(
        link?.target_assertion_sha256,
        'epistemic_evidence_link_target_invalid',
      ),
    });
  }).sort((left, right) => (
    left.target_assertion_sha256.localeCompare(right.target_assertion_sha256)
      || left.relation.localeCompare(right.relation)
  ));
  const identities = normalized.map((link) => `${link.relation}:${link.target_assertion_sha256}`);
  assert(new Set(identities).size === identities.length, 'epistemic_evidence_link_duplicate');
  return Object.freeze(normalized);
}

export function buildMemoryEpistemicEvidenceAssertion({
  assertionId,
  hypothesis,
  relation,
  confidenceMilli,
  rationaleSha256,
  assessorIdentitySha256,
  evidenceType,
  evidenceArtifactSha256,
  evidenceProvenanceSha256,
  sourceIndependence,
  evidenceLinks = [],
  prevAssertionSha256 = null,
} = {}) {
  const verifiedHypothesis = verifyMemoryPoisonHypothesis(hypothesis);
  const normalizedRelation = exactString(relation, 'epistemic_evidence_relation_missing');
  const normalizedEvidenceType = exactString(evidenceType, 'epistemic_evidence_type_missing');
  assert(RELATION_SET.has(normalizedRelation), 'epistemic_evidence_relation_invalid');
  assert(EVIDENCE_TYPE_SET.has(normalizedEvidenceType), 'epistemic_evidence_type_invalid');

  const claimBody = Object.freeze({
    schema: 'aimos.memory-epistemic-evidence-claim/v1',
    hypothesis_sha256: verifiedHypothesis.hypothesis_sha256,
    relation: normalizedRelation,
    confidence_milli: exactConfidence(confidenceMilli),
    rationale_sha256: exactHash(rationaleSha256, 'epistemic_evidence_rationale_hash_invalid'),
    assessor_identity_sha256: exactHash(
      assessorIdentitySha256,
      'epistemic_evidence_assessor_identity_invalid',
    ),
  });
  const claimRecord = Object.freeze({
    ...claimBody,
    claim_sha256: sha256EvidenceCanonical(claimBody),
  });
  const evidenceRecord = Object.freeze({
    schema: 'aimos.memory-epistemic-evidence-record/v1',
    evidence_type: normalizedEvidenceType,
    artifact_sha256: exactHash(
      evidenceArtifactSha256,
      'epistemic_evidence_artifact_hash_invalid',
    ),
    provenance_sha256: exactHash(
      evidenceProvenanceSha256,
      'epistemic_evidence_provenance_hash_invalid',
    ),
    source_independence: normalizeSourceIndependence(sourceIndependence),
  });
  const body = Object.freeze({
    schema: MEMORY_EPISTEMIC_EVIDENCE_ASSERTION_SCHEMA,
    assertion_id: exactUuid(assertionId, 'epistemic_evidence_assertion_id_invalid'),
    hypothesis: verifiedHypothesis,
    claim_record: claimRecord,
    evidence_record: evidenceRecord,
    evidence_links: normalizeEvidenceLinks(evidenceLinks),
    prev_assertion_sha256: exactHash(
      prevAssertionSha256,
      'epistemic_evidence_predecessor_invalid',
      { nullable: true },
    ),
  });
  return Object.freeze({ ...body, assertion_sha256: sha256EvidenceCanonical(body) });
}

export function verifyMemoryEpistemicEvidenceAssertion(assertion) {
  assert(assertion?.schema === MEMORY_EPISTEMIC_EVIDENCE_ASSERTION_SCHEMA,
    'epistemic_evidence_assertion_schema_invalid');
  const expected = buildMemoryEpistemicEvidenceAssertion({
    assertionId: assertion.assertion_id,
    hypothesis: assertion.hypothesis,
    relation: assertion.claim_record?.relation,
    confidenceMilli: assertion.claim_record?.confidence_milli,
    rationaleSha256: assertion.claim_record?.rationale_sha256,
    assessorIdentitySha256: assertion.claim_record?.assessor_identity_sha256,
    evidenceType: assertion.evidence_record?.evidence_type,
    evidenceArtifactSha256: assertion.evidence_record?.artifact_sha256,
    evidenceProvenanceSha256: assertion.evidence_record?.provenance_sha256,
    sourceIndependence: assertion.evidence_record?.source_independence,
    evidenceLinks: assertion.evidence_links,
    prevAssertionSha256: assertion.prev_assertion_sha256,
  });
  assert(assertion.claim_record?.claim_sha256 === expected.claim_record.claim_sha256,
    'epistemic_evidence_claim_hash_invalid');
  assert(assertion.assertion_sha256 === expected.assertion_sha256,
    'epistemic_evidence_assertion_hash_invalid');
  return expected;
}

function increment(target, key) {
  target[key] = (target[key] || 0) + 1;
}

export function verifyMemoryEpistemicEvidenceChain(assertions = [], {
  expectedHypothesisSha256 = null,
  expectedEvidenceRootSha256 = null,
} = {}) {
  assert(Array.isArray(assertions), 'epistemic_evidence_chain_invalid');
  const verified = assertions.map(verifyMemoryEpistemicEvidenceAssertion);
  const seen = new Set();
  let previous = null;
  let hypothesisSha256 = expectedHypothesisSha256 == null
    ? null
    : exactHash(expectedHypothesisSha256, 'epistemic_evidence_expected_hypothesis_invalid');

  for (const assertion of verified) {
    assert(!seen.has(assertion.assertion_sha256), 'epistemic_evidence_chain_duplicate_assertion');
    assert(assertion.prev_assertion_sha256 === previous, 'epistemic_evidence_chain_predecessor_mismatch');
    hypothesisSha256 ||= assertion.hypothesis.hypothesis_sha256;
    assert(assertion.hypothesis.hypothesis_sha256 === hypothesisSha256,
      'epistemic_evidence_chain_hypothesis_mismatch');
    for (const link of assertion.evidence_links) {
      assert(seen.has(link.target_assertion_sha256), 'epistemic_evidence_link_forward_or_unknown');
    }
    seen.add(assertion.assertion_sha256);
    previous = assertion.assertion_sha256;
  }

  const inactive = new Set();
  for (const assertion of verified) {
    for (const link of assertion.evidence_links) {
      if (link.relation === 'retracts' || link.relation === 'supersedes') {
        inactive.add(link.target_assertion_sha256);
      }
    }
  }
  const active = verified.filter((assertion) => !inactive.has(assertion.assertion_sha256));
  const relationCounts = {};
  const evidenceTypeCounts = {};
  const claimRecords = { supports: [], refutes: [], inconclusive: [], contextualizes: [] };
  const independentGroups = { supports: new Set(), refutes: new Set() };

  for (const assertion of active) {
    const relation = assertion.claim_record.relation;
    increment(relationCounts, relation);
    increment(evidenceTypeCounts, assertion.evidence_record.evidence_type);
    claimRecords[relation].push(Object.freeze({
      assertion_sha256: assertion.assertion_sha256,
      claim_sha256: assertion.claim_record.claim_sha256,
      relation,
      rationale_sha256: assertion.claim_record.rationale_sha256,
      assessor_identity_sha256: assertion.claim_record.assessor_identity_sha256,
      confidence_milli: assertion.claim_record.confidence_milli,
      evidence_type: assertion.evidence_record.evidence_type,
      evidence_artifact_sha256: assertion.evidence_record.artifact_sha256,
      evidence_provenance_sha256: assertion.evidence_record.provenance_sha256,
      source_identity_sha256: assertion.evidence_record.source_independence.source_identity_sha256,
      independence_group_sha256: assertion.evidence_record.source_independence.independence_group_sha256,
      independence_status: assertion.evidence_record.source_independence.status,
      independence_basis: assertion.evidence_record.source_independence.basis,
      independence_basis_evidence_sha256:
        assertion.evidence_record.source_independence.basis_evidence_sha256,
      evidence_links: assertion.evidence_links,
    }));
    if ((relation === 'supports' || relation === 'refutes')
        && assertion.evidence_record.source_independence.status === 'independent') {
      independentGroups[relation].add(
        assertion.evidence_record.source_independence.independence_group_sha256,
      );
    }
  }

  const rootBody = Object.freeze({
    schema: MEMORY_EPISTEMIC_EVIDENCE_CHAIN_SCHEMA,
    hypothesis_sha256: hypothesisSha256,
    assertion_sha256s: verified.map((assertion) => assertion.assertion_sha256),
  });
  const evidenceRootSha256 = sha256EvidenceCanonical(rootBody);
  if (expectedEvidenceRootSha256 != null) {
    assert(evidenceRootSha256 === exactHash(
      expectedEvidenceRootSha256,
      'epistemic_evidence_expected_root_invalid',
    ), 'epistemic_evidence_root_mismatch');
  }

  const assertionLifecycleRecords = verified.map((assertion) => Object.freeze({
    assertion_sha256: assertion.assertion_sha256,
    active: !inactive.has(assertion.assertion_sha256),
    relation: assertion.claim_record.relation,
    evidence_type: assertion.evidence_record.evidence_type,
    source_identity_sha256: assertion.evidence_record.source_independence.source_identity_sha256,
    independence_group_sha256:
      assertion.evidence_record.source_independence.independence_group_sha256,
    independence_status: assertion.evidence_record.source_independence.status,
    independence_basis: assertion.evidence_record.source_independence.basis,
    evidence_links: assertion.evidence_links,
  }));
  const allClaimRecords = EPISTEMIC_EVIDENCE_RELATIONS.flatMap(
    (relation) => claimRecords[relation],
  );

  return Object.freeze({
    valid: true,
    schema: MEMORY_EPISTEMIC_EVIDENCE_CHAIN_SCHEMA,
    hypothesis_sha256: hypothesisSha256,
    assertion_count: verified.length,
    active_assertion_count: active.length,
    head_assertion_sha256: previous,
    evidence_root_sha256: evidenceRootSha256,
    relation_counts: Object.freeze(relationCounts),
    evidence_type_counts: Object.freeze(evidenceTypeCounts),
    claim_records: Object.freeze(allClaimRecords),
    supporting_claim_records: Object.freeze(claimRecords.supports),
    refuting_claim_records: Object.freeze(claimRecords.refutes),
    inconclusive_claim_records: Object.freeze(claimRecords.inconclusive),
    contextual_claim_records: Object.freeze(claimRecords.contextualizes),
    assertion_lifecycle_records: Object.freeze(assertionLifecycleRecords),
    inactive_assertion_sha256s: Object.freeze([...inactive].sort()),
    independent_supporting_source_count: independentGroups.supports.size,
    independent_refuting_source_count: independentGroups.refutes.size,
    conflict_present: claimRecords.supports.length > 0 && claimRecords.refutes.length > 0,
  });
}

export function buildEvidenceBoundExplicitClassification({
  label,
  confidenceMilli,
  assertions,
} = {}) {
  const normalizedLabel = projectEpistemicLabelExact(label);
  const chain = verifyMemoryEpistemicEvidenceChain(assertions);
  const supports = chain.supporting_claim_records.length;
  const refutes = chain.refuting_claim_records.length;
  assert(chain.assertion_count > 0, 'epistemic_evidence_classification_chain_empty');
  if (POISON_LABELS.has(normalizedLabel)) {
    assert(supports > 0, 'epistemic_evidence_poison_label_missing_support');
  } else if (normalizedLabel === 'poison_refuted' || normalizedLabel === 'supported') {
    assert(refutes > 0, 'epistemic_evidence_refutation_label_missing_refutation');
  } else if (normalizedLabel === 'disputed') {
    assert(supports > 0 && refutes > 0, 'epistemic_evidence_disputed_label_missing_both_sides');
  }
  return Object.freeze({
    label: normalizedLabel,
    confidence_milli: exactConfidence(confidenceMilli),
    evidence_sha256: chain.evidence_root_sha256,
    evidence_assertion_binding: chain,
  });
}

export function projectEpistemicLabelExact(label) {
  const normalized = exactString(label, 'epistemic_exact_projection_label_missing');
  assert(LABEL_SET.has(normalized), 'epistemic_exact_projection_label_invalid');
  return normalized;
}

export function resolveEffectiveEpistemicState({
  signedLabel,
  detectorLabel,
} = {}) {
  const signed = projectEpistemicLabelExact(signedLabel);
  const detector = projectEpistemicLabelExact(detectorLabel);
  const effective = RESTRICTION_RANK[detector] > RESTRICTION_RANK[signed]
    ? detector
    : signed;
  return Object.freeze({
    version: MEMORY_EPISTEMIC_STATE_CONTINUITY_VERSION,
    signed_label: signed,
    detector_label: detector,
    effective_label: effective,
    signed_restriction_rank: RESTRICTION_RANK[signed],
    detector_restriction_rank: RESTRICTION_RANK[detector],
    effective_restriction_rank: RESTRICTION_RANK[effective],
    exoneration_blocked: POISON_LABELS.has(signed) && !POISON_LABELS.has(detector),
    persistent_transition_authorized: false,
  });
}
