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
import { calibrateNativeRecallResponse } from '../../services/retrieval/recall-output-calibrator.js';

const HASH = 'a'.repeat(64);

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
    },
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
  const quoted = result.memories.find((entry) => entry.id === 'quoted-question');
  assert.equal(quoted.epistemic_state, 'query_lure_suspect');
  assert.equal(quoted.evidence_handling, 'untrusted_reference_only');
  assert.equal(quoted.epistemic_signals.persistent_reweight_eligible, false);
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
  assert.equal(result.memories.length, 1);
  assert.equal(result.memories[0].epistemic_state, 'retained_quarantine');
  assert.equal(result.memories[0].evidence_handling, 'untrusted_reference_only');
  assert.equal(result.memories[0].epistemic_score, 0.1);
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
  assert.equal(result.memories[0].epistemic_state, 'poison_likely');
  assert.equal(result.memories[0].epistemic_score, 0.1);
  assert.equal(result.memories[0].evidence_handling, 'untrusted_reference_only');
  assert.equal(result.memories[0].epistemic_signals.provenance_valid, true);
  assert.equal(result.memories[0].epistemic_signals.stored_epistemic_confidence_milli, 900);
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
  assert.match(owner, /\{ returnReceipt: true \}/);
  assert.match(owner, /event_id: receipt\.event_id/);
  assert.match(owner, /mutation_hash: receipt\.mutation_hash/);
});
