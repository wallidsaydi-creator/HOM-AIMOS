import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  EPISTEMIC_ABLATION_POLICY_IDS,
  EPISTEMIC_ABLATION_VERSION,
  EPISTEMIC_DECISION_VERSION,
  calibrateEpistemicRecall,
  evaluateEpistemicRecallAblation,
} from '../../services/retrieval/epistemic-trust-retrieval.js';
import { epistemicReceiptDecisionHash } from '../../services/retrieval/native-recall-pipeline.js';
import { calibrateNativeRecallResponse } from '../../services/retrieval/recall-output-calibrator.js';

const HASH = 'a'.repeat(64);
const POLICY_HASH = 'd'.repeat(64);

test('native final receipts bind every epistemic decision and fail closed on an invalid hash', () => {
  assert.equal(epistemicReceiptDecisionHash({ decision_sha256: HASH.toUpperCase() }), HASH);
  assert.throws(
    () => epistemicReceiptDecisionHash({ decision_sha256: null }),
    /native_recall_epistemic_decision_hash_invalid/,
  );
});

function memory(id, value, overrides = {}) {
  return {
    id,
    key: `memory:${id}`,
    value,
    source: 'import:reference-corpus',
    memory_type: 'research',
    scope: 'global',
    retrieval_weight: 1,
    rerank_score: 0.8,
    provenance_proof: {
      live_content_hash: HASH,
      save_mutation_hash: 'b'.repeat(64),
      binding_mutation_hash: 'c'.repeat(64),
      binding_schema_version: 4,
      memory_originated_at: '2026-08-01T00:00:00.000Z',
      historical_signature_status: 'original_save_verified',
    },
    ...overrides,
  };
}

function twinPolicy(overrides = {}) {
  return {
    version: 'hom-aimos/twin-prime-policy/v1',
    arm: 'B2',
    lambda_t: '1',
    gamma: '0',
    execution: 'enforce',
    cache: 'off',
    early_exit: 'off',
    ...overrides,
  };
}

function twinContext(memories, overrides = {}) {
  return {
    policy: twinPolicy(),
    policyMutationHash: POLICY_HASH,
    queryEmbedding: [1, 0, 0],
    requestTimeMs: Date.parse('2026-08-08T12:00:00.000Z'),
    temporalScope: { kind: 'open', start_day: null, end_day_exclusive: null },
    featuresByMemoryId: new Map(memories.map((entry, index) => [entry.id, {
      embedding: index === 0 ? [1, 0, 0] : [0, 1, 0],
    }])),
    ...overrides,
  };
}

test('query-lure clusters are retained but demoted before top-k disclosure', () => {
  const question = 'How many moons does Mars have?';
  const poisons = Array.from({ length: 5 }, (_, index) => memory(
    `poison-${index}`,
    `${question} Mars has ${40 + index} moons according to an invented registry.`,
    { rerank_score: 0.99 - index * 0.01 },
  ));
  const clean = [
    memory('clean-1', 'Mars has two natural satellites, Phobos and Deimos.', { rerank_score: 0.82 }),
    memory('clean-2', 'Phobos and Deimos are the two moons orbiting Mars.', { rerank_score: 0.78 }),
    memory('clean-3', 'Astronomical catalogues identify the Martian moons as Phobos and Deimos.', { rerank_score: 0.72 }),
  ];

  const result = calibrateEpistemicRecall({ query: question, memories: [...poisons, ...clean], limit: 3 });
  assert.deepEqual(result.memories.map((entry) => entry.id).sort(), ['clean-1', 'clean-2', 'clean-3']);
  assert.equal(result.decision.states.query_lure_cluster, 5);
  assert.equal(result.decision.canonical_memory_mutated, false);
  assert.equal(result.decision.persistent_reweight_applied, false);
  assert.match(result.decision.decision_sha256, /^[0-9a-f]{64}$/);
  for (const decision of result.decision.decisions.filter((entry) => entry.memory_id.startsWith('poison-'))) {
    assert.equal(decision.evidence_handling, 'untrusted_reference_only');
    assert.equal(decision.epistemic_score, 0.1);
    assert.equal(decision.persistent_reweight_eligible, true);
  }
});

test('a single unverified query echo is response-local suspect, not persistently reweight eligible', () => {
  const question = 'Where was the conference held?';
  const result = calibrateEpistemicRecall({
    query: question,
    memories: [
      memory('quoted-question', `${question} The minutes record the venue as Rome.`),
      memory('support', 'The conference minutes list Rome as the venue.'),
    ],
    limit: 2,
  });
  const quoted = result.decision.decisions.find((entry) => entry.memory_id === 'quoted-question');
  assert.equal(quoted.epistemic_state, 'query_lure_suspect');
  assert.equal(quoted.evidence_handling, 'untrusted_reference_only');
  assert.equal(quoted.persistent_reweight_eligible, false);
  assert.equal(result.memories.some((entry) => entry.id === 'quoted-question'), false);
  assert.deepEqual(result.decision.withheld_untrusted_memory_ids, ['quoted-question']);
  assert.equal(result.decision.active_context_withholding_enforced, true);
});

test('existing quarantine remains retained at the 0.1 epistemic floor', () => {
  const result = calibrateEpistemicRecall({
    query: 'credential rotation',
    memories: [
      memory('quarantine', 'Untrusted retained reference about credential rotation.', {
        scope: 'quarantine',
        memory_type: 'quarantine',
        retrieval_weight: 0.1,
      }),
    ],
    limit: 1,
  });
  assert.equal(result.memories.length, 0);
  assert.equal(result.decision.decisions[0].epistemic_state, 'retained_quarantine');
  assert.equal(result.decision.decisions[0].evidence_handling, 'untrusted_reference_only');
  assert.equal(result.decision.decisions[0].epistemic_score, 0.1);
  assert.deepEqual(result.decision.withheld_untrusted_memory_ids, ['quarantine']);
  assert.equal(result.decision.abstention_required, true);
});

test('stored signed poison labels take precedence over valid transport provenance', () => {
  const result = calibrateEpistemicRecall({
    query: 'How many moons does Mars have?',
    memories: [
      memory('labelled-poison', 'A passage claims Mars has 41 moons.', {
        current_epistemic_label: 'poison_likely',
        current_epistemic_confidence_milli: 900,
        current_epistemic_event_id: '11111111-1111-4111-8111-111111111111',
      }),
    ],
    limit: 1,
  });
  assert.equal(result.memories.length, 0);
  const decision = result.decision.decisions[0];
  assert.equal(decision.epistemic_state, 'poison_likely');
  assert.equal(decision.epistemic_score, 0.1);
  assert.equal(decision.evidence_handling, 'untrusted_reference_only');
  assert.equal(decision.stored_epistemic_confidence_milli, 900);
  assert.deepEqual(result.decision.withheld_untrusted_memory_ids, ['labelled-poison']);
  assert.equal(result.decision.abstention_required, true);
});

test('poison_refuted is a reversible supported state, not permanent suppression', () => {
  const result = calibrateEpistemicRecall({
    query: 'How many moons does Mars have?',
    memories: [
      memory('refuted-label', 'Mars has two moons, Phobos and Deimos.', {
        current_epistemic_label: 'poison_refuted',
        current_epistemic_confidence_milli: 980,
      }),
    ],
    limit: 1,
  });
  assert.equal(result.memories[0].epistemic_state, 'poison_refuted');
  assert.equal(result.memories[0].epistemic_score, 1);
  assert.equal(result.memories[0].evidence_handling, 'supported_reference');
  assert.equal(result.decision.abstention_required, false);
});

test('explicit independent verification is distinct from provenance validity', () => {
  const result = calibrateEpistemicRecall({
    query: 'signed release date',
    memories: [
      memory('verified', 'The independently verified release date is 10 July.', {
        verified_by: 'release-auditor',
        verification_basis: 'independent_evidence',
      }),
      memory('merely-saved', 'The release date is 11 July.', {
        verified_by: 'housekeeper',
        verification_basis: 'save',
      }),
    ],
    limit: 2,
  });
  const verified = result.memories.find((entry) => entry.id === 'verified');
  const saved = result.memories.find((entry) => entry.id === 'merely-saved');
  assert.equal(verified.epistemic_state, 'supported');
  assert.equal(verified.evidence_handling, 'supported_reference');
  assert.equal(saved.epistemic_state, 'unverified');
  assert.equal(saved.evidence_handling, 'unverified_reference');
  assert.equal(verified.epistemic_decision_version, EPISTEMIC_DECISION_VERSION);
});

test('selection is deterministic and preserves all candidates in the decision record', () => {
  const memories = [
    memory('a', 'Alpha retained evidence.', { rerank_score: 0.7 }),
    memory('b', 'Beta retained evidence.', { rerank_score: 0.7 }),
    memory('c', 'Gamma retained evidence.', { rerank_score: 0.7 }),
  ];
  const first = calibrateEpistemicRecall({ query: 'retained evidence', memories, limit: 2 });
  const second = calibrateEpistemicRecall({ query: 'retained evidence', memories, limit: 2 });
  assert.deepEqual(first, second);
  assert.equal(first.decision.decisions.length, 3);
  assert.equal(first.memories.length, 2);
});

test('absence of twin-prime policy preserves the canonical B0 result exactly', () => {
  const memories = [
    memory('a', 'Alpha retained evidence.', { rerank_score: 0.9 }),
    memory('b', 'Beta retained evidence.', { rerank_score: 0.8 }),
  ];
  const first = calibrateEpistemicRecall({ query: 'retained evidence', memories, limit: 2 });
  const second = calibrateEpistemicRecall({ query: 'retained evidence', memories, limit: 2 });
  assert.deepEqual(first, second);
  assert.equal(Object.hasOwn(first.decision, 'twin_prime'), false);
  assert.equal(first.decision.decisions.some((row) => Object.hasOwn(row, 'twin_prime_features')), false);
});

test('signed B2 policy uses verified time and embeddings without exposing vectors in returned memories', () => {
  const memories = [
    memory('near', 'Near semantic evidence.', { rerank_score: 0.4 }),
    memory('far', 'Far semantic evidence.', { rerank_score: 0.99 }),
  ];
  const result = calibrateEpistemicRecall({
    query: 'semantic evidence',
    memories,
    limit: 1,
    twinPrimeContext: twinContext(memories),
  });
  assert.equal(result.memories[0].id, 'near');
  assert.equal(result.decision.twin_prime.policy.arm, 'B2');
  assert.equal(result.decision.twin_prime.policy_mutation_hash, POLICY_HASH);
  assert.equal(result.decision.twin_prime.pre_arm_candidate_count, 2);
  assert.deepEqual(result.decision.twin_prime.pre_arm_candidate_ids, ['near', 'far']);
  assert.match(result.decision.decisions[0].twin_prime_features.embedding_sha256, /^[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(result.memories[0], 'embedding'), false);
  assert.equal(JSON.stringify(result.memories).includes('embedding_sha256'), false);
});

test('twin-prime arms classify active-context eligibility before scoring', () => {
  const poison = memory('poison', 'High-ranked retained poison.', {
    rerank_score: 1,
    current_epistemic_label: 'poison_confirmed',
  });
  const clean = memory('clean', 'Lower-ranked supported evidence.', { rerank_score: 0.2 });
  const memories = [poison, clean];
  const result = calibrateEpistemicRecall({
    query: 'supported evidence',
    memories,
    limit: 1,
    twinPrimeContext: twinContext(memories, {
      policy: twinPolicy({ arm: 'T', gamma: '1/2' }),
    }),
  });
  assert.equal(result.memories[0].id, 'clean');
  const poisonDecision = result.decision.decisions.find((row) => row.memory_id === 'poison');
  assert.equal(poisonDecision.twin_prime_features.active_context_eligible, false);
  assert.equal(poisonDecision.twin_prime_features.ineligible_reason, 'untrusted_active_context');
  assert.equal(poisonDecision.twin_prime_features.tau, 0);
});

test('shadow execution computes the signed arm but returns canonical B0 selection', () => {
  const memories = [
    memory('native-first', 'Native first.', { rerank_score: 0.99 }),
    memory('semantic-first', 'Semantic first.', { rerank_score: 0.2 }),
  ];
  const result = calibrateEpistemicRecall({
    query: 'semantic evidence',
    memories,
    limit: 1,
    twinPrimeContext: twinContext(memories, {
      policy: twinPolicy({ execution: 'shadow' }),
      featuresByMemoryId: new Map([
        ['native-first', { embedding: [0, 1, 0] }],
        ['semantic-first', { embedding: [1, 0, 0] }],
      ]),
    }),
  });
  assert.equal(result.memories[0].id, 'native-first');
  assert.equal(result.decision.twin_prime.shadow_returned_baseline, true);
  assert.deepEqual(result.decision.twin_prime.returned_selected_memory_ids, ['native-first']);
  assert.deepEqual(result.decision.twin_prime.computed_selected_memory_ids, ['semantic-first']);
});

test('TP-G3 four-arm fixture preserves candidate identity and exact half-open B1 bounds', () => {
  const memories = [
    memory('day-1', 'Retained evidence from the first day.', {
      rerank_score: 0.96,
      provenance_proof: {
        ...memory('fixture', 'fixture').provenance_proof,
        memory_originated_at: '2026-08-01T00:00:00.000Z',
      },
    }),
    memory('day-2-a', 'Retained evidence from the second day.', {
      rerank_score: 0.93,
      provenance_proof: {
        ...memory('fixture', 'fixture').provenance_proof,
        memory_originated_at: '2026-08-02T00:00:00.000Z',
      },
    }),
    memory('day-2-b', 'Equal-time retained evidence from the second day.', {
      rerank_score: 0.93,
      provenance_proof: {
        ...memory('fixture', 'fixture').provenance_proof,
        memory_originated_at: '2026-08-02T00:00:00.000Z',
      },
    }),
    memory('day-3', 'Retained evidence from the third day.', {
      rerank_score: 0.90,
      provenance_proof: {
        ...memory('fixture', 'fixture').provenance_proof,
        memory_originated_at: '2026-08-03T23:59:59.999Z',
      },
    }),
    memory('day-4', 'Retained evidence at the exclusive upper bound.', {
      rerank_score: 0.88,
      provenance_proof: {
        ...memory('fixture', 'fixture').provenance_proof,
        memory_originated_at: '2026-08-04T00:00:00.000Z',
      },
    }),
    memory('poison', 'High-ranked retained poison.', {
      rerank_score: 1,
      current_epistemic_label: 'poison_confirmed',
      provenance_proof: {
        ...memory('fixture', 'fixture').provenance_proof,
        memory_originated_at: '2026-08-02T12:00:00.000Z',
      },
    }),
  ];
  const featuresByMemoryId = new Map(memories.map((entry, index) => [entry.id, {
    embedding: index % 2 === 0 ? [1, 0, 0] : [0, 1, 0],
  }]));
  const context = {
    policyMutationHash: POLICY_HASH,
    queryEmbedding: [1, 0, 0],
    requestTimeMs: Date.parse('2026-08-08T12:00:00.000Z'),
    featuresByMemoryId,
  };
  const results = {
    B0: calibrateEpistemicRecall({
      query: 'retained evidence',
      memories,
      limit: 6,
      twinPrimeContext: {
        ...context,
        temporalScope: { kind: 'open', start_day: null, end_day_exclusive: null },
        policy: twinPolicy({ arm: 'B0', lambda_t: '0', gamma: '0' }),
      },
    }),
    B1: calibrateEpistemicRecall({
      query: 'retained evidence from 2026-08-02 through 2026-08-03',
      memories,
      limit: 6,
      twinPrimeContext: {
        ...context,
        temporalScope: {
          kind: 'calendar_interval',
          start_day: '2026-08-02',
          end_day_exclusive: '2026-08-04',
        },
        policy: twinPolicy({ arm: 'B1', lambda_t: '0', gamma: '0' }),
      },
    }),
    B2: calibrateEpistemicRecall({
      query: 'retained evidence',
      memories,
      limit: 6,
      twinPrimeContext: {
        ...context,
        temporalScope: { kind: 'open', start_day: null, end_day_exclusive: null },
        policy: twinPolicy({ arm: 'B2', lambda_t: '1', gamma: '0' }),
      },
    }),
    T: calibrateEpistemicRecall({
      query: 'retained evidence',
      memories,
      limit: 6,
      twinPrimeContext: {
        ...context,
        temporalScope: { kind: 'open', start_day: null, end_day_exclusive: null },
        policy: twinPolicy({ arm: 'T', lambda_t: '1', gamma: '1/2', execution: 'shadow' }),
      },
    }),
  };

  const expectedCandidateIds = memories.map((entry) => entry.id);
  for (const result of Object.values(results)) {
    assert.deepEqual(result.decision.twin_prime.pre_arm_candidate_ids, expectedCandidateIds);
    assert.equal(result.decision.canonical_memory_mutated, false);
    assert.equal(result.decision.persistent_reweight_applied, false);
  }

  assert.deepEqual(
    [...results.B1.decision.twin_prime.computed_selected_memory_ids].sort(),
    ['day-2-a', 'day-2-b', 'day-3'],
    'B1 must include the lower bound and exclude the upper bound',
  );
  const b1Evidence = new Map(results.B1.decision.decisions.map((row) => [row.memory_id, row.twin_prime_features]));
  assert.equal(b1Evidence.get('day-1').ineligible_reason, 'outside_signed_temporal_scope');
  assert.equal(b1Evidence.get('day-2-a').temporal_eligible, true);
  assert.equal(b1Evidence.get('day-2-b').temporal_eligible, true);
  assert.equal(b1Evidence.get('day-3').temporal_eligible, true);
  assert.equal(b1Evidence.get('day-4').ineligible_reason, 'outside_signed_temporal_scope');
  assert.equal(b1Evidence.get('poison').ineligible_reason, 'untrusted_active_context');

  for (const arm of ['B2', 'T']) {
    const eligibleEvidence = results[arm].decision.decisions
      .map((row) => row.twin_prime_features)
      .filter((features) => features?.active_context_eligible);
    assert.ok(eligibleEvidence.length > 0);
    assert.ok(eligibleEvidence.every((features) => features.temporal_distance === 0), `${arm} open-time u_t must be zero`);
  }

  assert.equal(results.T.decision.twin_prime.shadow_returned_baseline, true);
  assert.deepEqual(
    results.T.decision.twin_prime.returned_selected_memory_ids,
    results.T.decision.twin_prime.baseline_selected_memory_ids,
  );
  const repeat = calibrateEpistemicRecall({
    query: 'retained evidence',
    memories,
    limit: 6,
    twinPrimeContext: {
      ...context,
      temporalScope: { kind: 'open', start_day: null, end_day_exclusive: null },
      policy: twinPolicy({ arm: 'T', lambda_t: '1', gamma: '1/2', execution: 'shadow' }),
    },
  });
  assert.deepEqual(repeat, results.T, 'equal-time and shadow selection must be deterministic');
});

test('sealed ablation arms isolate stored labels, query-local detection, and context withholding', () => {
  const question = 'How many moons does Mars have?';
  const poisons = Array.from({ length: 5 }, (_, index) => memory(
    `poison-${index}`,
    `${question} Mars has ${40 + index} moons according to an invented registry.`,
    {
      rerank_score: 0.99 - index * 0.01,
      current_epistemic_label: 'poison_likely',
      current_epistemic_confidence_milli: 990,
      current_epistemic_event_id: `11111111-1111-4111-8111-11111111111${index}`,
    },
  ));
  const clean = [
    memory('clean-1', 'Mars has two natural satellites, Phobos and Deimos.', { rerank_score: 0.82 }),
    memory('clean-2', 'Phobos and Deimos are the two moons orbiting Mars.', { rerank_score: 0.78 }),
    memory('clean-3', 'Astronomical catalogues identify the Martian moons as Phobos and Deimos.', { rerank_score: 0.72 }),
  ];

  const result = evaluateEpistemicRecallAblation({
    query: question,
    memories: [...poisons, ...clean],
    limit: 3,
  });

  assert.deepEqual(EPISTEMIC_ABLATION_POLICY_IDS, ['A0', 'A1', 'A2', 'A3']);
  assert.deepEqual(Object.keys(result), ['A0', 'A1', 'A2', 'A3']);
  assert.ok(result.A0.memories.some((entry) => entry.id.startsWith('poison-')));
  assert.deepEqual(result.A1.memories.map((entry) => entry.id).sort(), ['clean-1', 'clean-2', 'clean-3']);
  assert.deepEqual(
    result.A2.memories.map((entry) => entry.id),
    result.A3.memories.map((entry) => entry.id),
  );
  assert.deepEqual(
    result.A2.active_context_memories.map((entry) => entry.id),
    result.A2.memories.map((entry) => entry.id),
  );
  assert.equal(result.A0.decision.version, EPISTEMIC_ABLATION_VERSION);
  assert.equal(result.A0.decision.protocol, 'poisonedrag-n100-epistemic-ablation-v1');
  assert.equal(result.A0.decision.policy_id, 'A0');
  assert.equal(result.A3.decision.policy_id, 'A3');
  assert.notEqual(result.A0.decision.decision_sha256, result.A3.decision.decision_sha256);
  for (const arm of Object.values(result)) {
    assert.equal(arm.decision.canonical_memory_mutated, false);
    assert.equal(arm.decision.persistent_reweight_applied, false);
  }
});

test('A2 discloses selected untrusted evidence while A3 withholds it from active context', () => {
  const result = evaluateEpistemicRecallAblation({
    query: 'What is the release code?',
    memories: [
      memory('labelled-poison', 'The release code is an invented value.', {
        rerank_score: 0.99,
        current_epistemic_label: 'poison_confirmed',
        current_epistemic_confidence_milli: 1000,
      }),
    ],
    limit: 1,
  });

  assert.equal(result.A2.memories.length, 1);
  assert.equal(result.A2.active_context_memories.length, 1);
  assert.equal(result.A3.memories.length, 1);
  assert.equal(result.A3.active_context_memories.length, 0);
  assert.equal(result.A3.decision.abstention_required, true);
});

test('production calibration accepts no policy selector and retains its canonical decision schema', () => {
  const result = calibrateEpistemicRecall({
    query: 'release code',
    memories: [memory('one', 'The release code is retained evidence.')],
    limit: 1,
    policy: 'A0',
  });
  assert.equal(result.decision.version, EPISTEMIC_DECISION_VERSION);
  assert.equal(Object.hasOwn(result.decision, 'policy_id'), false);
  assert.equal(Object.hasOwn(result.decision, 'protocol'), false);
});

test('epistemic labels survive full-detail output calibration', () => {
  const calibrated = calibrateNativeRecallResponse({
    query: 'open full detail',
    runtimeBudget: { answer_shape: 'full_detail' },
    recallResponse: {
      success: true,
      memories: [{
        ...memory('labelled', 'Retained untrusted evidence.'),
        evidence_handling: 'untrusted_reference_only',
        epistemic_state: 'query_lure_cluster',
        epistemic_score: 0.1,
        epistemic_decision_version: EPISTEMIC_DECISION_VERSION,
        epistemic_signals: { query_prefix_echo: true },
        freshness_state: 'historical',
        verification_basis: 'reference_import',
      }],
    },
  });
  assert.equal(calibrated.memories[0].evidence_handling, 'untrusted_reference_only');
  assert.equal(calibrated.memories[0].epistemic_state, 'query_lure_cluster');
  assert.equal(calibrated.memories[0].epistemic_score, 0.1);
  assert.deepEqual(calibrated.memories[0].epistemic_signals, { query_prefix_echo: true });
  assert.equal(calibrated.memories[0].verification_basis, 'reference_import');
});

test('native recall requests the full signed epistemic decision receipt', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('async function selectAndLedgerEpistemicRecall');
  const end = source.indexOf('function projectMemoryForRecallRerank', start);
  const owner = source.slice(start, end);
  assert.match(owner, /'epistemic_recall_decision'/);
  assert.match(owner, /\{ authority: requestAuthority, returnReceipt: true \}/);
  assert.match(owner, /event_id: receipt\.event_id/);
  assert.match(owner, /mutation_hash: receipt\.mutation_hash/);
});

test('native twin-prime integration is signed-policy owned and shortcut closed', async () => {
  const pipeline = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const receipt = await readFile(
    new URL('../../services/retrieval/native-recall.js', import.meta.url),
    'utf8',
  );

  assert.match(pipeline, /systemConfigStore\.readVerifiedConfig\('TWIN_PRIME_RETRIEVAL_POLICY'\)/);
  assert.match(pipeline, /validateTwinPrimeRetrievalPolicy\(entry\.value\)/);
  assert.doesNotMatch(pipeline, /recallAuthority\.command\.(?:arm|lambda_t|gamma|twin_prime)/);
  assert.doesNotMatch(pipeline, /process\.env/);
  assert.match(pipeline, /const allowSemanticCache = !twinPrimeConfig/);
  assert.match(pipeline, /earlyExitFlag\.enabled\s*\n\s*&& memories\.length > 0\s*\n\s*&& !twinPrimeConfig/);
  assert.match(pipeline, /embedding::text AS embedding/);
  assert.doesNotMatch(pipeline, /twinPrimeReceiptDecisionHash/);
  assert.doesNotMatch(pipeline, /decision\?\.twin_prime\s*\?\s*decision\.decision_sha256\s*:\s*null/);
  assert.match(pipeline, /function epistemicReceiptDecisionHash\(decision\)/);
  assert.match(pipeline, /native_recall_epistemic_decision_hash_invalid/);
  assert.equal(
    (pipeline.match(/epistemicDecisionHash: epistemicReceiptDecisionHash/g) || []).length,
    5,
  );
  assert.equal(
    (pipeline.slice(pipeline.indexOf('export async function executeNativeRecall'))
      .match(/calibrateAndFinalizeNativeRecallReturn\(\{/g) || []).length,
    5,
  );
  assert.match(pipeline, /securityClosureDecisionHash: securityClosure\.decision\.decision_sha256/);
  assert.match(pipeline, /returnProjectionDecision: projection/);
  assert.match(receipt, /hom-aimos\/recall-merkle\/v2-epistemic-decision/);
  assert.match(receipt, /hom-aimos\/recall-merkle\/v3-epistemic-and-security-closure/);
  assert.match(receipt, /entry_type: 'epistemic_decision'/);
  assert.match(receipt, /entry_type: 'canary_final_security_closure'/);
  assert.match(receipt, /canary_final_security_closure_sha256/);
});
