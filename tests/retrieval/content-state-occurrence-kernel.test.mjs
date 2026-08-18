import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CONTENT_STATE_OCCURRENCE_KERNEL_CONTRACT,
  assertNoContentDigestCollision,
  canonicalizeLiveContentState,
  projectContentStateOccurrenceViews,
  reduceOccurrenceSensitiveGear,
} from '../../services/retrieval/content-state-occurrence/kernel.js';

const UUIDS = Object.freeze([
  '550e8400-e29b-41d4-a716-446655440010',
  '550e8400-e29b-41d4-a716-446655440011',
  '550e8400-e29b-41d4-a716-446655440012',
  '550e8400-e29b-41d4-a716-446655440013',
]);
const REF = (digit) => String(digit).repeat(64);
const baseContent = Object.freeze({
  key: 'guide:test',
  value: 'Authenticate recall with a signed envelope.',
  scope: 'global',
  memory_type: 'fact',
  clearance_level: 10,
  data_class: 'confidential',
  source: 'r1-vector',
});
const baseHash = '22bb73a6f078629a6aa9f36ac99f4504dbfe67f6c7e86d317f7e004b6430a0e6';
const differentSourceContent = Object.freeze({
  ...baseContent,
  source: 'different-origin-label',
});
const differentSourceHash = 'd833e3df0dc027655b990f628fb057e20ead9d0ef56bdd1df9fb5450eca3fb02';

function occurrence({
  ordinal = 0,
  ref = REF(ordinal + 1),
  content = baseContent,
  contentHash = canonicalizeLiveContentState(content).live_content_hash,
  lineageId = `lineage-${ordinal}`,
  current = true,
  time = 1_786_200_000_000 + ordinal,
  agent = `agent-${ordinal}`,
  occurrenceEligible = true,
  contentEligible = true,
  principalAdmitted = true,
  provenanceVerified = true,
  topologyVerified = true,
  gearScores = {},
} = {}) {
  return {
    company_id: 'hom',
    memory_id: UUIDS[ordinal % UUIDS.length],
    occurrence_ref: ref,
    live_content_hash: contentHash,
    content,
    principal: {
      agent_id: agent,
      valid_from: '2026-08-17T00:00:00.000Z',
      cert_fingerprint: 'a'.repeat(64),
    },
    lineage: {
      lineage_id: lineageId,
      is_current_head: current,
      signed_time_ms: time,
    },
    admission: {
      principal_scope_admitted: principalAdmitted,
      provenance_verified: provenanceVerified,
      topology_verified: topologyVerified,
    },
    evidence: {
      occurrence_eligible: occurrenceEligible,
      content_eligible: contentEligible,
      occurrence_decision_ref: occurrenceEligible ? null : 'b'.repeat(64),
      content_decision_ref: contentEligible ? null : 'c'.repeat(64),
    },
    gear_scores: gearScores,
  };
}

function permutation(values, seed) {
  const output = [...values];
  let state = seed >>> 0;
  for (let index = output.length - 1; index > 0; index -= 1) {
    state = (1664525 * state + 1013904223) >>> 0;
    const swap = state % (index + 1);
    [output[index], output[swap]] = [output[swap], output[index]];
  }
  return output;
}

test('R1 canonical content vector matches the existing live-content hash contract', () => {
  const result = canonicalizeLiveContentState(baseContent);
  assert.equal(result.live_content_hash, baseHash);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(CONTENT_STATE_OCCURRENCE_KERNEL_CONTRACT.database_authority, false);
  assert.equal(CONTENT_STATE_OCCURRENCE_KERNEL_CONTRACT.environment_authority, false);
});

test('A/A exact repeats produce one state vote and retain two occurrences', () => {
  const result = projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1) }),
    occurrence({ ordinal: 1, ref: REF(2) }),
  ] });
  assert.equal(result.state_view.length, 1);
  assert.equal(result.occurrence_view.length, 2);
  assert.equal(result.state_view[0].occurrence_count, 2);
  assert.equal(result.state_view[0].eligible_occurrence_refs.length, 2);
  assert.equal(result.decision.collapsed_occurrence_count, 1);
  assert.equal(result.decision.retention_changed, false);
});

test('A/B/A preserves three occurrences, two states, and the latest A witness', () => {
  const contentB = { ...baseContent, value: 'Different intermediate state.' };
  const result = projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1), lineageId: 'one', current: false, time: 10 }),
    occurrence({ ordinal: 1, ref: REF(2), content: contentB, lineageId: 'one', current: false, time: 20 }),
    occurrence({ ordinal: 2, ref: REF(3), lineageId: 'one', current: true, time: 30 }),
  ] });
  assert.equal(result.state_view.length, 2);
  assert.equal(result.occurrence_view.length, 3);
  const stateA = result.state_view.find((state) => state.live_content_hash === baseHash);
  assert.equal(stateA.disclosure_witness_occurrence_ref, REF(3));
  assert.equal(stateA.occurrence_count, 2);
});

test('independent principal heads remain separate authority occurrences without a topology failure', () => {
  const result = projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1), lineageId: 'principal-a', agent: 'a' }),
    occurrence({ ordinal: 1, ref: REF(2), lineageId: 'principal-b', agent: 'b' }),
  ] });
  assert.equal(result.state_view[0].current_head_count, 2);
  assert.equal(result.state_view[0].lineage_count, 2);
  assert.equal(result.decision.independent_multihead_state_count, 1);
  assert.notEqual(
    result.occurrence_view[0].principal.agent_id,
    result.occurrence_view[1].principal.agent_id,
  );
});

test('two current heads in one lineage fail closed', () => {
  assert.throws(() => projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1), lineageId: 'fork' }),
    occurrence({ ordinal: 1, ref: REF(2), lineageId: 'fork' }),
  ] }), /content_state_occurrence_kernel:topology_lineage_invalid/);
});

test('two current heads in one lineage fail even when their content states differ', () => {
  assert.throws(() => projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1), lineageId: 'cross-state-fork' }),
    occurrence({
      ordinal: 1,
      ref: REF(2),
      lineageId: 'cross-state-fork',
      content: { ...baseContent, value: 'forked state' },
    }),
  ] }), /content_state_occurrence_kernel:topology_lineage_invalid/);
});

test('occurrence-scoped poison blocks only its occurrence and cannot be exonerated', () => {
  const result = projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1), occurrenceEligible: true }),
    occurrence({ ordinal: 1, ref: REF(2), occurrenceEligible: false }),
  ] });
  const state = result.state_view[0];
  assert.equal(state.rank_eligible, true);
  assert.deepEqual(state.eligible_occurrence_refs, [REF(1)]);
  assert.deepEqual(state.blocked_occurrence_refs, [REF(2)]);
  assert.equal(result.occurrence_view.find((row) => row.occurrence_ref === REF(2)).ineligibility_reason,
    'occurrence_scope_blocked');
});

test('content-scoped poison blocks the class while retaining every occurrence', () => {
  const result = projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1), contentEligible: true }),
    occurrence({ ordinal: 1, ref: REF(2), contentEligible: false }),
  ] });
  assert.equal(result.state_view[0].rank_eligible, false);
  assert.equal(result.state_view[0].content_scope_blocked, true);
  assert.equal(result.state_view[0].disclosure_witness_occurrence_ref, null);
  assert.equal(result.occurrence_view.length, 2);
  assert.equal(result.occurrence_view.every((row) => row.ineligibility_reason === 'content_scope_blocked'), true);
});

test('principal and provenance rejection errors do not expose occurrence identity', () => {
  for (const candidate of [
    occurrence({ principalAdmitted: false, memoryId: UUIDS[0] }),
    occurrence({ provenanceVerified: false, memoryId: UUIDS[0] }),
  ]) {
    let error;
    try { projectContentStateOccurrenceViews({ occurrences: [candidate] }); } catch (caught) { error = caught; }
    assert.ok(error instanceof Error);
    assert.equal(error.message.includes(candidate.memory_id), false);
    assert.equal(error.message.includes(candidate.occurrence_ref), false);
  }
});

test('evidence eligibility must be explicit and cannot default clean', () => {
  const candidate = occurrence();
  candidate.evidence = {};
  assert.throws(
    () => projectContentStateOccurrenceViews({ occurrences: [candidate] }),
    /content_state_occurrence_kernel:evidence_scope_invalid/,
  );
});

test('one projection cannot combine companies', () => {
  const foreign = occurrence({ ordinal: 1, ref: REF(2) });
  foreign.company_id = 'foreign';
  assert.throws(
    () => projectContentStateOccurrenceViews({ occurrences: [occurrence({ ref: REF(1) }), foreign] }),
    /content_state_occurrence_kernel:principal_scope_rejected/,
  );
});

test('same text with different canonical metadata remains two states', () => {
  const result = projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1) }),
    occurrence({
      ordinal: 1,
      ref: REF(2),
      content: differentSourceContent,
      contentHash: differentSourceHash,
    }),
  ] });
  assert.equal(result.state_view.length, 2);
});

test('equal digest with unequal canonical bytes is a named collision failure', () => {
  assert.throws(() => assertNoContentDigestCollision(
    { live_content_hash: 'd'.repeat(64), canonical_json: '{"a":1}' },
    { live_content_hash: 'd'.repeat(64), canonical_json: '{"a":2}' },
  ), /content_state_occurrence_kernel:content_state_digest_collision/);
});

test('stored live hash mismatch fails before class influence', () => {
  assert.throws(() => projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ contentHash: 'e'.repeat(64) }),
  ] }), /content_state_occurrence_kernel:live_content_hash_mismatch/);
});

test('occurrence-sensitive reducer takes eligible max and deterministic reference tie-break', () => {
  const result = projectContentStateOccurrenceViews({ occurrences: [
    occurrence({ ordinal: 0, ref: REF(1), gearScores: { temporal: 0.8 } }),
    occurrence({ ordinal: 1, ref: REF(2), gearScores: { temporal: 0.9 } }),
    occurrence({ ordinal: 2, ref: REF(3), gearScores: { temporal: 0.9 } }),
    occurrence({ ordinal: 3, ref: REF(4), occurrenceEligible: false, gearScores: { temporal: 10 } }),
  ] });
  const reduced = reduceOccurrenceSensitiveGear(result, 'temporal');
  assert.equal(reduced.length, 1);
  assert.equal(reduced[0].score, 0.9);
  assert.equal(reduced[0].occurrence_ref, REF(2));
});

test('projection is deterministic under input permutation and does not mutate input', () => {
  const input = [
    occurrence({ ordinal: 0, ref: REF(1), gearScores: { temporal: 0.2 } }),
    occurrence({ ordinal: 1, ref: REF(2), gearScores: { temporal: 0.3 } }),
    occurrence({ ordinal: 2, ref: REF(3), content: { ...baseContent, value: 'B' } }),
  ];
  const before = structuredClone(input);
  const expected = projectContentStateOccurrenceViews({ occurrences: input });
  for (let seed = 1; seed <= 20; seed += 1) {
    assert.deepEqual(projectContentStateOccurrenceViews({ occurrences: permutation(input, seed) }), expected);
  }
  assert.deepEqual(input, before);
  assert.equal(Object.isFrozen(expected), true);
  assert.equal(Object.isFrozen(expected.state_view[0]), true);
});

test('preferred occurrence witness must remain an eligible class member', () => {
  assert.throws(() => projectContentStateOccurrenceViews({
    occurrences: [occurrence({ ref: REF(1) })],
    preferred_occurrence_by_content_hash: { [baseHash]: REF(9) },
  }), /content_state_occurrence_kernel:preferred_occurrence_ineligible/);
});

test('maximum duplicate class performs one membership operation per occurrence and one downstream state', () => {
  const count = 20_000;
  const input = Array.from({ length: count }, (_, index) => occurrence({
    ordinal: index % UUIDS.length,
    ref: index.toString(16).padStart(64, '0'),
    lineageId: `lineage-${index}`,
    current: index === count - 1,
    time: index,
  }));
  const result = projectContentStateOccurrenceViews({ occurrences: input });
  assert.equal(result.occurrence_view.length, count);
  assert.equal(result.state_view.length, 1);
  assert.equal(result.decision.membership_operations, count);
  assert.equal(result.decision.collapsed_occurrence_count, count - 1);
  assert.equal(result.state_view[0].occurrence_count, count);
});

test('unrecognized learned-state fields cannot change content identity or authority projection', () => {
  const low = occurrence({ ref: REF(1) });
  const high = structuredClone(low);
  low.retrieval_weight = 0.1;
  high.retrieval_weight = 3.0;
  assert.deepEqual(
    projectContentStateOccurrenceViews({ occurrences: [low] }),
    projectContentStateOccurrenceViews({ occurrences: [high] }),
  );
});
