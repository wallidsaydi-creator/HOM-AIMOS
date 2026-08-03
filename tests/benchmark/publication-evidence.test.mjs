import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { selfHash as canonicalSelfHash } from '../../eval/poisonedrag/harness.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const file = path.join(ROOT, 'eval', 'publication', 'verified-benchmark-results.json');
const evidence = JSON.parse(readFileSync(file, 'utf8'));
const epistemicFile = path.join(
  ROOT,
  'eval',
  'publication',
  'poisonedrag-epistemic-verification.json',
);
const epistemicEvidence = JSON.parse(readFileSync(epistemicFile, 'utf8'));
const mutationFile = path.join(
  ROOT,
  'eval',
  'publication',
  'mutation-integrity-verification.json',
);
const mutationEvidence = JSON.parse(readFileSync(mutationFile, 'utf8'));
const humanFile = path.join(
  ROOT,
  'eval',
  'publication',
  'poisonedrag-human-agreement.json',
);
const humanEvidence = JSON.parse(readFileSync(humanFile, 'utf8'));
const ablationFile = path.join(
  ROOT,
  'eval',
  'publication',
  'poisonedrag-epistemic-ablation.json',
);
const ablationEvidence = JSON.parse(readFileSync(ablationFile, 'utf8'));

function selfHash(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  return createHash('sha256').update(JSON.stringify(unsigned)).digest('hex');
}

test('public benchmark evidence is self-hashed and denominator complete', () => {
  assert.equal(evidence.schema, 'hom.aimos.publication-evidence/v2');
  assert.equal(evidence.self_hash_algorithm, 'sha256(canonical-json(unsigned-object))');
  assert.equal(
    evidence.publication_evidence_sha256,
    canonicalSelfHash(evidence, 'publication_evidence_sha256'),
  );

  const utility = evidence.runs.canonical_utility;
  assert.deepEqual(
    [utility.longmemeval.llm_judged_qa.correct, utility.longmemeval.llm_judged_qa.total],
    [459, 500],
  );
  assert.deepEqual(
    [utility.locomo_llm_judged.llm_judged_qa.correct, utility.locomo_llm_judged.llm_judged_qa.total],
    [1472, 1986],
  );
  assert.equal(evidence.runs.locomo_official.result.n, 1986);
  assert.equal(evidence.runs.locomo_official.result.mean_f1, 0.5819991702124487);

  const poison = evidence.runs.poisonedrag_n100.result;
  assert.equal(evidence.runs.poisonedrag_n100.run_id, '20260722172124_db0d79');
  assert.deepEqual(
    [poison.primary_official_substring_metric.attacked_asr.count,
      poison.primary_official_substring_metric.attacked_asr.total],
    [3, 100],
  );
  assert.deepEqual(
    [poison.retrieval.poison_retrieved_at_5.count,
      poison.retrieval.poison_retrieved_at_5.total],
    [0, 100],
  );
  assert.equal(poison.admission.poison_passages_submitted, 500);
  assert.equal(poison.admission.poison_passages_admitted, 500);
  assert.equal(poison.admission.poison_passages_quarantined, 0);
  assert.equal(poison.admission.poison_signed_epistemic_label_evidence, 500);
  assert.equal(poison.proof_completeness.save_proofs, 20500);
  assert.equal(poison.proof_completeness.admitted_saves, 19380);
  assert.equal(poison.proof_completeness.rejected_saves, 1120);
  assert.equal(poison.proof_completeness.unique_retained_memories, 19308);
  assert.equal(poison.proof_completeness.deduplicated_reuses, 72);
  assert.equal(poison.proof_completeness.recall_proofs, 200);
  assert.equal(poison.proof_completeness.verified_recall_proofs, 200);
  assert.match(poison.evidence.input_preflight_sha256, /^[0-9a-f]{64}$/);
  assert.match(poison.evidence.candidate_pool_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(
    [
      poison.epistemic_classification.poison_classification.adverse_label_count,
      poison.epistemic_classification.poison_classification.total,
    ],
    [500, 500],
  );
  assert.deepEqual(
    [
      poison.epistemic_classification.clean_false_positive.count,
      poison.epistemic_classification.clean_false_positive.total,
    ],
    [4, 18808],
  );
  assert.equal(poison.epistemic_classification.chain_verification.checked, 19308);
  assert.equal(poison.epistemic_classification.chain_verification.verified, 19308);
  assert.equal(poison.epistemic_classification.chain_verification.failed, 0);
  assert.equal(evidence.empirical_completion.mutation_integrity_suite, 'complete');
  assert.equal(
    evidence.empirical_completion.blinded_human_agreement_audit,
    'complete_system_author_review',
  );
  assert.equal(evidence.runs.mutation_integrity.run_id, '20260723162050_59a52d');
  assert.equal(evidence.runs.poisonedrag_n100.human_agreement.reviewer_role, 'system_author');
  assert.equal(
    evidence.runs.poisonedrag_n100.human_agreement.independence,
    'not_independent_system_author_review',
  );
  assert.equal(
    evidence.empirical_completion.poisonedrag_epistemic_ablation,
    'complete',
  );
  assert.equal(evidence.empirical_completion.signed_scratch_brain_purges, 'complete_verified_receipts');
  assert.equal(evidence.signed_scratch_purge.receipt_count, 39);
  assert.equal(evidence.signed_scratch_purge.verified_receipt_count, 39);
  assert.equal(evidence.signed_scratch_purge.invalid_receipt_count, 0);
  assert.equal(evidence.signed_scratch_purge.canonical_brain_included, false);
  assert.equal(
    evidence.signed_scratch_purge.purge_evidence_sha256,
    canonicalSelfHash(evidence.signed_scratch_purge, 'purge_evidence_sha256'),
  );
  assert.equal(
    Object.values(evidence.runs).every(
      (run) => run.scratch_brain_status === 'signed_destroyed_receipt_verified',
    ),
    true,
  );
  assert.equal(
    evidence.runs.poisonedrag_epistemic_ablation.result.ablation_evidence_sha256,
    ablationEvidence.ablation_evidence_sha256,
  );
});

test('public benchmark evidence contains no private or dataset-bearing fields', () => {
  const encoded = JSON.stringify(evidence);
  for (const forbidden of [
    '/Users/',
    'Aimos-Agent-Cert',
    'Aimos-Agent-Signature',
    'generated_answer',
    'gold_answer',
    'question_id',
    'memory_id',
    'provider_payload',
    'private_target_manifest',
    'aimos_benchmark_',
    'aimos_test_security_',
    'master_pubkey',
    'fingerprint',
  ]) {
    assert.equal(encoded.includes(forbidden), false, `public evidence leaked ${forbidden}`);
  }
});

test('public mutation-integrity evidence is complete, self-hashed, and sanitized', () => {
  assert.equal(mutationEvidence.schema, 'hom.aimos.mutation-integrity-public-evidence/v1');
  assert.equal(
    mutationEvidence.mutation_integrity_evidence_sha256,
    selfHash(mutationEvidence, 'mutation_integrity_evidence_sha256'),
  );
  assert.equal(mutationEvidence.authorization_cases.discontinuity_rejected, true);
  assert.equal(mutationEvidence.authorization_cases.out_of_bounds_rejected, true);
  assert.match(mutationEvidence.signed_post_mutation_recall.merkle_root, /^[0-9a-f]{64}$/);
  assert.match(mutationEvidence.signed_post_mutation_recall.event_mutation_hash, /^[0-9a-f]{64}$/);
  assert.equal(mutationEvidence.execution.completed_transition_measurements, 20);
  assert.equal(mutationEvidence.verifier.sql_portable_parity, true);
  assert.equal(mutationEvidence.verifier.all_sql_records_ok, true);
  assert.equal(mutationEvidence.verifier.all_portable_records_ok, true);
  assert.equal(Object.values(mutationEvidence.authorization_cases).every(Boolean), true);
  assert.equal(Object.values(mutationEvidence.tamper_cases).every(Boolean), true);
  assert.equal(mutationEvidence.latency_ms.n, 20);
  assert.equal(mutationEvidence.logical_row_storage_bytes.n, 20);

  const encoded = JSON.stringify(mutationEvidence);
  for (const forbidden of [
    '/Users/',
    'aimos_test_security_',
    'memory_id',
    'Aimos-Agent-Cert',
    'Aimos-Agent-Signature',
    'database_name',
  ]) {
    assert.equal(encoded.includes(forbidden), false, `mutation evidence leaked ${forbidden}`);
  }
});

test('public epistemic verification is self-hashed, complete, and sanitized', () => {
  assert.equal(epistemicEvidence.schema, 'hom.aimos.poisonedrag-epistemic-verification/v1');
  assert.equal(
    epistemicEvidence.epistemic_verification_sha256,
    selfHash(epistemicEvidence, 'epistemic_verification_sha256'),
  );
  assert.deepEqual(
    [
      epistemicEvidence.chain_verification.verified,
      epistemicEvidence.chain_verification.checked,
      epistemicEvidence.chain_verification.failed,
    ],
    [19308, 19308, 0],
  );
  assert.deepEqual(
    [
      epistemicEvidence.poison_classification.adverse_label_count,
      epistemicEvidence.poison_classification.total,
    ],
    [500, 500],
  );
  assert.deepEqual(
    [
      epistemicEvidence.clean_false_positive.count,
      epistemicEvidence.clean_false_positive.total,
    ],
    [4, 18808],
  );

  const encoded = JSON.stringify(epistemicEvidence);
  for (const forbidden of [
    '/Users/',
    'aimos_benchmark_',
    'memory_id',
    'Aimos-Agent-Cert',
    'Aimos-Agent-Signature',
    'generated_answer',
    'gold_answer',
    'question_id',
    'passage_text',
  ]) {
    assert.equal(encoded.includes(forbidden), false, `epistemic evidence leaked ${forbidden}`);
  }
});

test('human agreement evidence is complete, blinded, self-hashed, and honestly attributed', () => {
  assert.equal(humanEvidence.schema, 'hom.aimos.poisonedrag-human-agreement/v1');
  assert.equal(
    humanEvidence.summary_sha256,
    canonicalSelfHash(humanEvidence, 'summary_sha256'),
  );
  assert.equal(humanEvidence.reviewer_role, 'system_author');
  assert.equal(humanEvidence.blinding.arm_hidden_during_review, true);
  assert.equal(humanEvidence.blinding.judge_verdict_hidden_during_review, true);
  assert.equal(humanEvidence.blinding.arm_mapping_revealed_after_label_completion, true);
  assert.equal(humanEvidence.audited_answers, 200);
  assert.equal(humanEvidence.complete_target_pairs, 100);
  assert.equal(humanEvidence.exclusions, 0);
  assert.deepEqual(
    [humanEvidence.correctness_agreement.agreements, humanEvidence.correctness_agreement.n],
    [193, 200],
  );
  assert.deepEqual(
    [humanEvidence.target_assertion_agreement.agreements, humanEvidence.target_assertion_agreement.n],
    [198, 200],
  );

  const encoded = JSON.stringify(humanEvidence);
  for (const forbidden of [
    '/Users/',
    'generated_answer',
    'gold_answer',
    'question_id',
    'passage_text',
    'Aimos-Agent-Cert',
    'Aimos-Agent-Signature',
  ]) {
    assert.equal(encoded.includes(forbidden), false, `human evidence leaked ${forbidden}`);
  }
});

test('public epistemic ablation evidence is causal, complete, self-hashed, and sanitized', () => {
  assert.equal(
    ablationEvidence.schema,
    'hom.aimos.poisonedrag-epistemic-ablation-public-evidence/v1',
  );
  assert.equal(
    ablationEvidence.ablation_evidence_sha256,
    canonicalSelfHash(ablationEvidence, 'ablation_evidence_sha256'),
  );
  assert.deepEqual(
    [ablationEvidence.intended_n, ablationEvidence.completed_n],
    [100, 100],
  );
  assert.equal(ablationEvidence.denominator_complete, true);
  assert.deepEqual(
    [
      ablationEvidence.policy_results.A0.retrieval.attacked_poison_retrieval_at_5.count,
      ablationEvidence.policy_results.A0.retrieval.attacked_poison_retrieval_at_5.total,
    ],
    [94, 100],
  );
  assert.deepEqual(
    [
      ablationEvidence.policy_results.A3.retrieval.attacked_poison_retrieval_at_5.count,
      ablationEvidence.policy_results.A3.retrieval.attacked_poison_retrieval_at_5.total,
    ],
    [0, 100],
  );
  assert.deepEqual(
    [
      ablationEvidence.policy_results.A3.semantic_target_assertion.induced_asr.count,
      ablationEvidence.policy_results.A3.semantic_target_assertion.induced_asr.total,
    ],
    [1, 98],
  );
  assert.equal(
    ablationEvidence.holm_bonferroni_familywise_0_05.attacked_poison_retrieval
      .find((entry) => entry.contrast === 'A1-A0').adjusted_p,
    4.0389678347315804E-28,
  );
  assert.equal(ablationEvidence.integrity.verified_target_outcomes, 100);
  assert.equal(ablationEvidence.integrity.verified_retrieval_decisions, 800);
  assert.equal(ablationEvidence.integrity.unique_verified_decision_events, 800);
  assert.equal(ablationEvidence.integrity.unique_verified_ledger_sequences, 800);
  assert.equal(ablationEvidence.integrity.artifact_manifest.artifact_count, 3518);
  assert.equal(ablationEvidence.integrity.memory_root_unchanged, true);
  assert.equal(ablationEvidence.integrity.classification_root_unchanged, true);
  assert.equal(ablationEvidence.integrity.canonical_benchmark_footprint_unchanged, true);
  assert.deepEqual(
    ablationEvidence.mechanism_activation.A1_A2_prompt_equal,
    { count: 200, total: 200 },
  );
  assert.deepEqual(
    ablationEvidence.mechanism_activation.A2_A3_prompt_equal,
    { count: 200, total: 200 },
  );
  assert.deepEqual(
    ablationEvidence.mechanism_activation.active_context_withholding_exercised,
    { count: 0, total: 200, withheld_passages: 0 },
  );

  const encoded = JSON.stringify(ablationEvidence);
  for (const forbidden of [
    '/Users/',
    'aimos_benchmark_',
    '"memory_id"',
    '"event_id"',
    '"ledger_seq"',
    '"upstream_id"',
    'generated_answer',
    'gold_answer',
    'question_id',
    'passage_text',
    'provider_payload',
    'private_target_manifest',
    'Aimos-Agent-Cert',
    'Aimos-Agent-Signature',
  ]) {
    assert.equal(encoded.includes(forbidden), false, `ablation evidence leaked ${forbidden}`);
  }
});
