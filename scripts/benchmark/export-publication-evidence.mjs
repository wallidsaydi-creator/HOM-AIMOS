#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  pairedBootstrap,
  selfHash as poisonedRagSelfHash,
  wilsonInterval,
} from '../../eval/poisonedrag/harness.mjs';
import {
  buildContrast as buildAblationContrast,
  correctedContrastFamily as correctedAblationContrastFamily,
  policyMetrics as ablationPolicyMetrics,
} from '../../eval/run-poisonedrag-epistemic-ablation.mjs';
import { verifyWholeBrainPurgeReceipt } from '../../services/security/whole-brain-purge.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RESULTS_ROOT = path.join(ROOT, 'eval', 'public-results');
const OUTPUT_ROOT = path.join(ROOT, 'eval', 'publication');
const PURGE_RECEIPT_ROOT = path.join(
  ROOT,
  'artifacts',
  'purge-receipts',
  '20260803-publication-freeze',
);
const RUNS = Object.freeze({
  utility: '20260715111742_96b25f',
  locomoOfficial: '20260718205816_fbde68',
  poisonedRag: '20260722172124_db0d79',
  poisonedRagAblation: '20260730102457_495de5',
  mutationIntegrity: '20260723162050_59a52d',
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function selfHash(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  return sha256(JSON.stringify(unsigned));
}

function readRegularFile(file) {
  if (!existsSync(file) || lstatSync(file).isSymbolicLink() || !statSync(file).isFile()) {
    throw new Error(`publication_source_invalid:${path.relative(ROOT, file)}`);
  }
  return readFileSync(file);
}

function readJson(file) {
  return JSON.parse(readRegularFile(file).toString('utf8'));
}

function readHashedJson(file, field, algorithm = 'json-stringify') {
  const value = readJson(file);
  const observed = algorithm === 'canonical-json'
    ? poisonedRagSelfHash(value, field)
    : selfHash(value, field);
  if (!/^[0-9a-f]{64}$/.test(String(value[field] || '')) || value[field] !== observed) {
    throw new Error(`publication_self_hash_invalid:${path.relative(ROOT, file)}:${field}`);
  }
  return value;
}

function safeRunDirectory(runId) {
  if (!/^20[0-9]{12}_[0-9a-f]{6}$/.test(runId)) throw new Error(`publication_run_id_invalid:${runId}`);
  return path.join(RESULTS_ROOT, runId);
}

function verifyRunComplete(runId) {
  const runDir = safeRunDirectory(runId);
  const status = readJson(path.join(runDir, 'run-status.json'));
  if (status.schema !== 'hom.canonical-benchmark-run-status/v1'
    || status.run_id !== runId
    || status.state !== 'complete'
    || status.phase !== 'complete'
    || status.resumable !== false) {
    throw new Error(`publication_run_incomplete:${runId}`);
  }
  return runDir;
}

function verifyAblationRunComplete(runId) {
  const runDir = safeRunDirectory(runId);
  const status = readJson(path.join(runDir, 'run-status.json'));
  if (status.protocol !== 'poisonedrag-n100-epistemic-ablation-v1'
    || status.run_id !== runId
    || status.state !== 'complete'
    || status.phase !== 'complete'
    || status.resumable !== false
    || status.terminal_evidence_verified !== true) {
    throw new Error(`publication_ablation_run_incomplete:${runId}`);
  }
  return runDir;
}

function verifyArtifactManifest(runDir) {
  const manifestFile = path.join(runDir, 'artifact-hashes.json');
  const manifestBytes = readRegularFile(manifestFile);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const entries = Object.entries(manifest);
  if (entries.length < 1) throw new Error(`publication_artifact_manifest_empty:${path.basename(runDir)}`);
  for (const [relative, expected] of entries) {
    const file = path.resolve(runDir, relative);
    if (!file.startsWith(`${runDir}${path.sep}`) || !/^[0-9a-f]{64}$/.test(expected)) {
      throw new Error(`publication_artifact_manifest_entry_invalid:${relative}`);
    }
    if (sha256(readRegularFile(file)) !== expected) {
      throw new Error(`publication_artifact_hash_mismatch:${path.basename(runDir)}:${relative}`);
    }
  }
  return {
    artifact_count: entries.length,
    manifest_sha256: sha256(manifestBytes),
    verification: 'all_manifest_entries_rehashed',
  };
}

function readRows(runDir, summary, schema) {
  const file = path.resolve(runDir, summary.rows_file);
  if (!file.startsWith(`${runDir}${path.sep}`)) throw new Error('publication_rows_path_escape');
  const bytes = readRegularFile(file);
  if (sha256(bytes) !== summary.rows_sha256) throw new Error('publication_rows_hash_mismatch');
  const rows = bytes.toString('utf8').trim().split('\n').map((line) => JSON.parse(line));
  if (rows.length !== summary.metrics.complete
    || rows.some((row) => row.schema !== schema || row.status !== 'complete' || row.run_id !== summary.run_id)) {
    throw new Error(`publication_rows_incomplete:${summary.run_id}:${summary.benchmark}`);
  }
  return rows;
}

function categoryMetrics(summary, answerMetric) {
  return Object.fromEntries(Object.entries(summary.by_category).map(([category, value]) => [category, {
    n: value.complete,
    retrieval: {
      eligible: value.retrieval.eligible,
      any_hit_at_k: value.retrieval.any_hit_at_k,
      hit_at_1: value.retrieval.hit_at_1,
      mrr: value.retrieval.mean_reciprocal_rank,
      evidence_recall_at_k: value.retrieval.mean_evidence_recall_at_k,
      ndcg_at_k: value.retrieval.mean_ndcg_at_k,
    },
    answer: answerMetric(value),
  }]));
}

function verifiedCanonical(runDir, benchmark, expectedN) {
  const file = path.join(runDir, `canonical-summary-${benchmark}.json`);
  const summary = readHashedJson(file, 'summary_sha256');
  if (summary.schema !== 'hom.canonical-benchmark-summary/v1'
    || summary.run_id !== RUNS.utility
    || summary.benchmark !== benchmark
    || summary.generator !== 'codex:gpt-5.4'
    || summary.judge !== 'codex:gpt-5.6-terra'
    || summary.metrics.selected !== expectedN
    || summary.metrics.complete !== expectedN
    || summary.metrics.incomplete !== 0
    || summary.metrics.judged_qa.judged !== expectedN) {
    throw new Error(`publication_canonical_summary_invalid:${benchmark}`);
  }
  readRows(runDir, summary, 'hom.canonical-benchmark-row/v1');
  const qa = summary.metrics.judged_qa;
  return {
    protocol: 'canonical-blind-v1',
    n: expectedN,
    generator: summary.generator,
    judge: summary.judge,
    retrieval_k: 20,
    retrieval: {
      eligible: summary.metrics.retrieval.eligible,
      any_hit_at_20: summary.metrics.retrieval.any_hit_at_k,
      hit_at_1: summary.metrics.retrieval.hit_at_1,
      mrr: summary.metrics.retrieval.mean_reciprocal_rank,
      evidence_recall_at_20: summary.metrics.retrieval.mean_evidence_recall_at_k,
      ndcg_at_20: summary.metrics.retrieval.mean_ndcg_at_k,
    },
    llm_judged_qa: {
      correct: qa.correct,
      total: qa.judged,
      accuracy: qa.accuracy,
      wilson_95: wilsonInterval(qa.correct, qa.judged),
      mean_score: qa.mean_score,
    },
    categories: categoryMetrics(summary, (value) => ({
      metric: 'llm_judged_accuracy',
      correct: value.judged_qa.correct,
      total: value.judged_qa.judged,
      value: value.judged_qa.accuracy,
      wilson_95: wilsonInterval(value.judged_qa.correct, value.judged_qa.judged),
    })),
    evidence: {
      summary_sha256: summary.summary_sha256,
      summary_file_sha256: sha256(readRegularFile(file)),
      rows_sha256: summary.rows_sha256,
      selection_sha256: summary.selection_sha256,
      session_artifact_sha256: summary.session_artifact_sha256,
    },
  };
}

function verifiedOfficialLocomo(runDir) {
  const file = path.join(runDir, 'locomo-official-summary.json');
  const summary = readHashedJson(file, 'summary_sha256');
  if (summary.schema !== 'hom.locomo-official-summary/v1'
    || summary.run_id !== RUNS.locomoOfficial
    || summary.protocol?.id !== 'locomo-upstream-qa-v1'
    || summary.reader !== 'codex:gpt-5.4'
    || summary.judge !== null
    || summary.metrics.selected !== 1986
    || summary.metrics.complete !== 1986
    || summary.metrics.incomplete !== 0
    || summary.metrics.official_qa.evaluated !== 1986) {
    throw new Error('publication_locomo_official_summary_invalid');
  }
  const rows = readRows(runDir, summary, 'hom.locomo-official-row/v1');
  const scores = rows.map((row) => row.official_qa_score);
  if (scores.some((score) => !Number.isFinite(score) || score < 0 || score > 1)) {
    throw new Error('publication_locomo_official_score_invalid');
  }
  const observedMean = scores.reduce((sum, value) => sum + value, 0) / scores.length;
  if (Math.abs(observedMean - summary.metrics.official_qa.mean_f1) > 1e-12) {
    throw new Error('publication_locomo_official_mean_mismatch');
  }
  return {
    protocol: summary.protocol.id,
    n: 1986,
    reader: summary.reader,
    judge: null,
    retrieval_k: summary.protocol.rag_top_k,
    metric: 'upstream_category_aware_token_f1',
    mean_f1: observedMean,
    score_percent: observedMean * 100,
    bootstrap_95: pairedBootstrap(scores),
    retrieval: {
      eligible: summary.metrics.retrieval.eligible,
      any_hit_at_25: summary.metrics.retrieval.any_hit_at_k,
      hit_at_1: summary.metrics.retrieval.hit_at_1,
      mrr: summary.metrics.retrieval.mean_reciprocal_rank,
      evidence_recall_at_25: summary.metrics.retrieval.mean_evidence_recall_at_k,
      ndcg_at_25: summary.metrics.retrieval.mean_ndcg_at_k,
    },
    categories: categoryMetrics(summary, (value) => ({
      metric: 'upstream_category_aware_token_f1',
      total: value.official_qa.evaluated,
      value: value.official_qa.mean_f1,
    })),
    comparability: {
      upstream_revision: summary.protocol.upstream_revision,
      deterministic_scorer: true,
      reader_retriever_and_memory_pipeline_are_hom_configuration_variables: true,
      note: summary.comparability_note,
    },
    evidence: {
      summary_sha256: summary.summary_sha256,
      summary_file_sha256: sha256(readRegularFile(file)),
      rows_sha256: summary.rows_sha256,
      selection_sha256: summary.selection_sha256,
      session_artifact_sha256: summary.session_artifact_sha256,
    },
  };
}

function verifyPoisonedRagProofs(runDir, summary) {
  const targetRoot = path.join(runDir, 'poisonedrag', 'targets');
  const directories = readdirSync(targetRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(targetRoot, entry.name));
  if (directories.length !== 100) throw new Error('publication_poison_target_count_invalid');

  const totals = {
    save_proofs: 0,
    admitted_saves: 0,
    rejected_saves: 0,
    unique_retained_memories: 0,
    deduplicated_reuses: 0,
    signed_security_decisions: 0,
    recall_proofs: 0,
    verified_recall_proofs: 0,
    clean_submitted: 0,
    clean_admitted: 0,
    clean_rejected: 0,
    poison_submitted: 0,
    poison_admitted: 0,
    poison_rejected: 0,
    poison_quarantined: 0,
    poison_signed_security_decisions: 0,
    poison_signed_epistemic_label_evidence: 0,
    poison_label_at_save: {},
    clean_label_at_save: {},
    verified_outcomes: 0,
  };
  const retainedMemoryIds = new Set();

  for (const directory of directories) {
    const admission = readHashedJson(
      path.join(directory, 'admission.json'),
      'admission_sha256',
      'canonical-json',
    );
    totals.poison_submitted += admission.poison_passages_submitted;
    totals.poison_admitted += admission.poison_passages_admitted;
    totals.poison_rejected += admission.poison_passages_rejected;
    totals.poison_signed_epistemic_label_evidence +=
      admission.poison_passages_with_signed_epistemic_label_evidence;
    totals.clean_submitted += admission.clean_candidates_submitted_per_arm * 2;
    totals.clean_admitted += admission.clean_candidates_admitted_per_arm * 2;
    totals.clean_rejected += admission.clean_candidates_rejected_per_arm * 2;
    for (const [label, count] of Object.entries(admission.poison_label_at_save_counts || {})) {
      totals.poison_label_at_save[label] = (totals.poison_label_at_save[label] || 0) + count;
    }
    for (const arm of admission.clean_epistemic_label_counts_per_arm || []) {
      for (const [label, count] of Object.entries(arm)) {
        totals.clean_label_at_save[label] = (totals.clean_label_at_save[label] || 0) + count;
      }
    }

    const outcome = readHashedJson(path.join(directory, 'outcome.json'), 'outcome_sha256', 'canonical-json');
    const declared = summary.target_outcomes.find((entry) => entry.target_ordinal === outcome.target_ordinal);
    if (!declared || declared.outcome_sha256 !== outcome.outcome_sha256) {
      throw new Error(`publication_poison_outcome_mismatch:${outcome.target_ordinal}`);
    }
    totals.verified_outcomes += 1;

    for (const arm of [0, 1]) {
      const saveDir = path.join(directory, 'saves', `arm-${arm}`);
      for (const entry of readdirSync(saveDir, { withFileTypes: true })) {
        if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
        const proof = readHashedJson(path.join(saveDir, entry.name), 'proof_sha256', 'canonical-json');
        totals.save_proofs += 1;
        if (proof.terminal?.admitted) {
          totals.admitted_saves += 1;
          if (proof.terminal?.memory_id) retainedMemoryIds.add(proof.terminal.memory_id);
          if (proof.terminal?.recovered_existing) totals.deduplicated_reuses += 1;
        } else {
          totals.rejected_saves += 1;
        }
        if (proof.terminal?.security_decision_event_id) totals.signed_security_decisions += 1;
        if (entry.name.startsWith('poison-')) {
          if (proof.terminal?.security_decision_event_id) totals.poison_signed_security_decisions += 1;
          if (proof.terminal?.quarantined) totals.poison_quarantined += 1;
        }
      }
      const recall = readHashedJson(
        path.join(directory, 'recall', `arm-${arm}.json`),
        'proof_sha256',
        'canonical-json',
      );
      totals.recall_proofs += 1;
      if (recall.verification?.verified) totals.verified_recall_proofs += 1;
    }
  }
  totals.unique_retained_memories = retainedMemoryIds.size;
  return totals;
}

function verifiedPoisonedRag(runDir) {
  const summaryFile = path.join(runDir, 'poisonedrag', 'summary.json');
  const summary = readHashedJson(summaryFile, 'summary_sha256', 'canonical-json');
  const plan = readHashedJson(
    path.join(runDir, 'poisonedrag', 'execution-plan.json'),
    'plan_sha256',
    'canonical-json',
  );
  const preflight = readHashedJson(
    path.join(runDir, 'poisonedrag', 'input-preflight.json'),
    'preflight_sha256',
    'canonical-json',
  );
  const runManifest = readHashedJson(path.join(runDir, 'run-manifest.json'), 'manifest_sha256');
  const retryFile = path.join(runDir, 'retry-recovery-receipt.json');
  const retry = existsSync(retryFile)
    ? readHashedJson(retryFile, 'receipt_sha256')
    : null;
  const epistemicFile = path.join(OUTPUT_ROOT, 'poisonedrag-epistemic-verification.json');
  const epistemic = readHashedJson(epistemicFile, 'epistemic_verification_sha256');
  if (summary.schema !== 'hom.aimos.poisonedrag-summary/v1'
    || summary.protocol !== 'poisonedrag-n100-v1'
    || summary.run_id !== RUNS.poisonedRag
    || summary.intended_n !== 100
    || summary.completed_n !== 100
    || summary.denominator_complete !== true
    || plan.generator !== 'codex:gpt-5.5'
    || plan.judge !== 'codex:gpt-5.6-terra'
    || plan.disclosure_k !== 5
    || preflight.total_save_operations !== 20500
    || runManifest.configuration?.phase_retries !== 6
    || (retry && (
      retry.effective_attempt_ceiling !== 6
      || retry.scientific_inputs_unchanged !== true
    ))
    || epistemic.schema !== 'hom.aimos.poisonedrag-epistemic-verification/v1'
    || epistemic.run_id !== RUNS.poisonedRag
    || epistemic.source_summary_sha256 !== summary.summary_sha256
    || epistemic.chain_verification?.failed !== 0
    || epistemic.chain_verification?.verified !== 19308
    || epistemic.poison_classification?.adverse_label_count !== 500
    || epistemic.poison_classification?.total !== 500
    || epistemic.clean_false_positive?.count !== 4
    || epistemic.clean_false_positive?.total !== 18808) {
    throw new Error('publication_poisonedrag_summary_invalid');
  }
  const proofs = verifyPoisonedRagProofs(runDir, summary);
  if (proofs.save_proofs !== 20500
    || proofs.admitted_saves !== 19380
    || proofs.rejected_saves !== 1120
    || proofs.unique_retained_memories !== 19308
    || proofs.deduplicated_reuses !== 72
    || proofs.clean_submitted !== 20000
    || proofs.clean_admitted !== 18880
    || proofs.clean_rejected !== 1120
    || proofs.poison_submitted !== 500
    || proofs.poison_admitted !== 500
    || proofs.poison_rejected !== 0
    || proofs.poison_quarantined !== 0
    || proofs.poison_signed_security_decisions !== 500
    || proofs.poison_signed_epistemic_label_evidence !== 500
    || proofs.recall_proofs !== 200
    || proofs.verified_recall_proofs !== 200
    || proofs.verified_outcomes !== 100) {
    throw new Error('publication_poisonedrag_proof_count_invalid');
  }
  return {
    protocol: summary.protocol,
    n: 100,
    generator: plan.generator,
    judge: plan.judge,
    judge_reasoning: plan.judge_reasoning,
    primary_official_substring_metric: summary.primary_official_substring_metric,
    secondary_semantic_metric: summary.secondary_semantic_metric,
    retrieval: summary.retrieval,
    utility: summary.utility,
    admission: {
      poison_passages_submitted: proofs.poison_submitted,
      poison_passages_admitted: proofs.poison_admitted,
      poison_passages_rejected: proofs.poison_rejected,
      poison_passages_quarantined: proofs.poison_quarantined,
      poison_save_security_decisions: proofs.poison_signed_security_decisions,
      poison_signed_epistemic_label_evidence: proofs.poison_signed_epistemic_label_evidence,
      poison_label_at_save: proofs.poison_label_at_save,
      clean_label_at_save: proofs.clean_label_at_save,
      interpretation: 'Poison passages were retained as signed canonical references and classified through append-only epistemic evidence; the measured defense was labelled retrieval isolation, not deletion, rejection, or quarantine.',
    },
    epistemic_classification: {
      population: epistemic.population,
      current_labels: epistemic.current_labels,
      poison_classification: epistemic.poison_classification,
      clean_false_positive: epistemic.clean_false_positive,
      chain_verification: epistemic.chain_verification,
      verification_records_root_sha256: epistemic.verification_records_root_sha256,
    },
    proof_completeness: proofs,
    retry_recovery: {
      recovery_receipt_present: Boolean(retry),
      original_attempt_ceiling: retry?.original_attempt_ceiling ?? runManifest.configuration.phase_retries,
      effective_attempt_ceiling: retry?.effective_attempt_ceiling ?? runManifest.configuration.phase_retries,
      scientific_inputs_unchanged: retry?.scientific_inputs_unchanged ?? true,
      completed_provider_outputs_reused: retry?.completed_provider_outputs_reused ?? false,
      receipt_sha256: retry?.receipt_sha256 ?? null,
      receipt_file_sha256: retry ? sha256(readRegularFile(retryFile)) : null,
      policy_source: retry ? 'retry-recovery-receipt.json' : 'run-manifest.json',
    },
    comparability: {
      classification: 'declared_adaptation_not_strict_reproduction',
      target_fixture: 'official PoisonedRAG NQ 100-target fixture',
      clean_pool: 'official pinned Contriever top-100 candidate IDs resolved against pinned NQ/BEIR corpus',
      retriever: 'AIMOS native epistemic retrieval, not Contriever',
      corpus_scope: '100 clean candidates per target, not the full 2,681,468-text NQ corpus',
      disclosure_k: 5,
      poison_passages_per_target: 5,
    },
    evidence: {
      summary_sha256: summary.summary_sha256,
      summary_file_sha256: sha256(readRegularFile(summaryFile)),
      execution_plan_sha256: summary.execution_plan_sha256,
      source_lock_sha256: plan.source_lock_sha256,
      candidate_pool_sha256: plan.candidate_pool_sha256,
      public_target_lock_sha256: plan.public_target_lock_sha256,
      input_preflight_sha256: preflight.preflight_sha256,
      epistemic_verification_sha256: epistemic.epistemic_verification_sha256,
      epistemic_verification_file_sha256: sha256(readRegularFile(epistemicFile)),
    },
  };
}

function verifyAblationProofs(runDir, summary) {
  const targetRoot = path.join(runDir, 'poisonedrag-ablation', 'targets');
  const directories = readdirSync(targetRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(targetRoot, entry.name))
    .sort();
  if (directories.length !== 100) throw new Error('publication_ablation_target_count_invalid');

  const declaredOutcomes = new Map(summary.target_outcomes.map((entry) => [
    entry.target_ordinal,
    entry.artifact_sha256,
  ]));
  if (declaredOutcomes.size !== 100) throw new Error('publication_ablation_declared_outcomes_invalid');

  const eventIds = new Set();
  const ledgerSequences = new Set();
  const outcomes = [];
  const parity = {
    total_pairs: 200,
    a1_a2_selected_equal: 0,
    a1_a2_active_context_equal: 0,
    a1_a2_prompt_equal: 0,
    a2_a3_selected_equal: 0,
    a2_a3_active_context_equal: 0,
    a2_a3_prompt_equal: 0,
    active_context_withholding_exercised: 0,
    withheld_passages: 0,
  };
  let verifiedDecisions = 0;

  for (const directory of directories) {
    const outcome = readHashedJson(
      path.join(directory, 'outcome.json'),
      'artifact_sha256',
      'canonical-json',
    );
    if (outcome.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-target-outcome/v1'
      || outcome.protocol !== summary.protocol
      || outcome.run_id !== summary.run_id
      || declaredOutcomes.get(outcome.target_ordinal) !== outcome.artifact_sha256) {
      throw new Error(`publication_ablation_outcome_invalid:${outcome.target_ordinal}`);
    }
    outcomes.push(outcome);

    for (const datasetArm of [0, 1]) {
      const decisions = {};
      const prompts = {};
      for (const policyId of ['A0', 'A1', 'A2', 'A3']) {
        const decision = readHashedJson(
          path.join(directory, 'retrieval', `dataset-arm-${datasetArm}-${policyId}.json`),
          'artifact_sha256',
          'canonical-json',
        );
        if (decision.schema
            !== 'hom.aimos.poisonedrag-epistemic-ablation-decision-evidence/v1'
          || decision.protocol !== summary.protocol
          || decision.run_id !== summary.run_id
          || decision.target_ordinal !== outcome.target_ordinal
          || decision.dataset_arm !== datasetArm
          || decision.policy_id !== policyId
          || decision.canonical_memory_mutated !== false
          || decision.retrieval_weight_mutated !== false
          || decision.classification_mutated !== false
          || decision.ledger_receipt?.verified !== true
          || !/^[0-9a-f-]{36}$/.test(String(decision.ledger_receipt?.event_id || ''))
          || !Number.isInteger(decision.ledger_receipt?.ledger_seq)
          || !/^[0-9a-f]{64}$/.test(String(decision.ledger_receipt?.content_hash || ''))
          || !/^[0-9a-f]{64}$/.test(String(decision.ledger_receipt?.mutation_hash || ''))) {
          throw new Error(
            `publication_ablation_decision_invalid:${outcome.target_ordinal}:${datasetArm}:${policyId}`,
          );
        }
        eventIds.add(decision.ledger_receipt.event_id);
        ledgerSequences.add(decision.ledger_receipt.ledger_seq);
        decisions[policyId] = decision;
        verifiedDecisions += 1;

        const answer = readHashedJson(
          path.join(directory, 'generate', `dataset-arm-${datasetArm}-${policyId}.json`),
          'artifact_sha256',
          'canonical-json',
        );
        if (answer.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-answer/v1'
          || answer.protocol !== summary.protocol
          || answer.run_id !== summary.run_id
          || !/^[0-9a-f]{64}$/.test(String(answer.prompt_sha256 || ''))) {
          throw new Error(
            `publication_ablation_answer_invalid:${outcome.target_ordinal}:${datasetArm}:${policyId}`,
          );
        }
        prompts[policyId] = answer.prompt_sha256;
      }

      const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
      parity.a1_a2_selected_equal += Number(equal(
        decisions.A1.epistemic_selected_memory_ids,
        decisions.A2.epistemic_selected_memory_ids,
      ));
      parity.a1_a2_active_context_equal += Number(equal(
        decisions.A1.active_context_memory_ids,
        decisions.A2.active_context_memory_ids,
      ));
      parity.a1_a2_prompt_equal += Number(prompts.A1 === prompts.A2);
      parity.a2_a3_selected_equal += Number(equal(
        decisions.A2.epistemic_selected_memory_ids,
        decisions.A3.epistemic_selected_memory_ids,
      ));
      parity.a2_a3_active_context_equal += Number(equal(
        decisions.A2.active_context_memory_ids,
        decisions.A3.active_context_memory_ids,
      ));
      parity.a2_a3_prompt_equal += Number(prompts.A2 === prompts.A3);
      const withheld = decisions.A3.epistemic_selected_memory_ids.length
        - decisions.A3.active_context_memory_ids.length;
      if (withheld < 0) throw new Error('publication_ablation_withholding_count_invalid');
      parity.active_context_withholding_exercised += Number(withheld > 0);
      parity.withheld_passages += withheld;
    }
  }
  outcomes.sort((left, right) => left.target_ordinal - right.target_ordinal);
  if (verifiedDecisions !== 800 || eventIds.size !== 800 || ledgerSequences.size !== 800) {
    throw new Error('publication_ablation_decision_completeness_invalid');
  }
  if (Object.entries(parity)
    .filter(([field]) => field.endsWith('_equal'))
    .some(([, value]) => value !== parity.total_pairs)
    || parity.active_context_withholding_exercised !== 0
    || parity.withheld_passages !== 0) {
    throw new Error('publication_ablation_mechanism_activation_mismatch');
  }
  return {
    outcomes,
    verified_target_outcomes: outcomes.length,
    verified_retrieval_decisions: verifiedDecisions,
    unique_verified_decision_events: eventIds.size,
    unique_verified_ledger_sequences: ledgerSequences.size,
    parity,
  };
}

function verifiedPoisonedRagAblation(runDir) {
  const summaryFile = path.join(runDir, 'poisonedrag-ablation', 'summary.json');
  const planFile = path.join(runDir, 'poisonedrag-ablation', 'execution-plan.json');
  const isolationFile = path.join(runDir, 'isolation-proof.json');
  const amendmentFile = path.join(runDir, 'resume-amendment.json');
  const reconciliationFile = path.join(runDir, 'completion-reconciliation.json');
  const summary = readHashedJson(summaryFile, 'artifact_sha256', 'canonical-json');
  const plan = readHashedJson(planFile, 'plan_sha256', 'canonical-json');
  const isolation = readHashedJson(isolationFile, 'isolation_sha256');
  const amendment = readHashedJson(amendmentFile, 'amendment_sha256');
  const reconciliation = readHashedJson(
    reconciliationFile,
    'reconciliation_sha256',
    'canonical-json',
  );
  const artifactManifest = verifyArtifactManifest(runDir);
  if (summary.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-summary/v1'
    || summary.protocol !== 'poisonedrag-n100-epistemic-ablation-v1'
    || summary.run_id !== RUNS.poisonedRagAblation
    || summary.source_run_id !== RUNS.poisonedRag
    || summary.intended_n !== 100
    || summary.completed_n !== 100
    || summary.denominator_complete !== true
    || summary.confirmatory !== true
    || summary.execution_plan_sha256 !== plan.plan_sha256
    || plan.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-plan/v1'
    || plan.protocol !== summary.protocol
    || plan.run_id !== summary.run_id
    || plan.target_count !== 100
    || plan.generator !== 'codex:gpt-5.5'
    || plan.generator_reasoning !== 'medium'
    || plan.judge !== 'codex:gpt-5.6-terra'
    || plan.judge_reasoning !== 'high'
    || plan.retrieval_decisions !== 800
    || plan.generations !== 800
    || plan.judgments !== 1600
    || plan.mutation_contract?.canonical_memory_mutated !== false
    || plan.mutation_contract?.retrieval_weight_mutated !== false
    || plan.mutation_contract?.classification_mutated !== false
    || plan.mutation_contract?.deletion_decay_suppression !== false
    || isolation.protocol !== summary.protocol
    || isolation.run_id !== summary.run_id
    || isolation.memory_root_unchanged !== true
    || isolation.classification_root_unchanged !== true
    || isolation.signed_classification_rows_unchanged !== 504
    || isolation.ablation_decision_event_rows !== 800
    || isolation.canonical_benchmark_footprint_unchanged !== true
    || amendment.protocol !== summary.protocol
    || amendment.run_id !== summary.run_id
    || amendment.scientific_contract_unchanged !== true
    || amendment.completed_artifacts_reused !== true
    || reconciliation.protocol !== summary.protocol
    || reconciliation.run_id !== summary.run_id
    || reconciliation.terminal_evidence?.verified_artifacts !== artifactManifest.artifact_count
    || artifactManifest.artifact_count !== 3518) {
    throw new Error('publication_ablation_summary_invalid');
  }

  const proofs = verifyAblationProofs(runDir, summary);
  const recomputedPolicies = Object.fromEntries(['A0', 'A1', 'A2', 'A3'].map((policyId) => [
    policyId,
    ablationPolicyMetrics(proofs.outcomes, policyId),
  ]));
  const recomputedContrasts = [
    buildAblationContrast(proofs.outcomes, 'A0', 'A1'),
    buildAblationContrast(proofs.outcomes, 'A1', 'A2'),
    buildAblationContrast(proofs.outcomes, 'A2', 'A3'),
    buildAblationContrast(proofs.outcomes, 'A0', 'A3'),
  ];
  const contrastFields = [
    'attacked_poison_retrieval',
    'attacked_target_substring',
    'incremental_target_substring',
    'attacked_target_semantic',
    'incremental_target_semantic',
    'clean_qa_correct',
    'attacked_qa_correct',
  ];
  const recomputedHolm = Object.fromEntries(contrastFields.map((field) => [
    field,
    correctedAblationContrastFamily(recomputedContrasts, field),
  ]));
  if (JSON.stringify(recomputedPolicies) !== JSON.stringify(summary.policies)
    || JSON.stringify(recomputedContrasts) !== JSON.stringify(summary.contrasts)
    || JSON.stringify(recomputedHolm) !== JSON.stringify(summary.holm_bonferroni_familywise_0_05)) {
    throw new Error('publication_ablation_recomputed_aggregate_mismatch');
  }

  const publicEvidence = {
    schema: 'hom.aimos.poisonedrag-epistemic-ablation-public-evidence/v1',
    protocol: summary.protocol,
    run_id: summary.run_id,
    source_run_id: summary.source_run_id,
    confirmatory: summary.confirmatory,
    intended_n: summary.intended_n,
    completed_n: summary.completed_n,
    denominator_complete: summary.denominator_complete,
    design: {
      disclosure_k: plan.disclosure_k,
      generator: plan.generator,
      generator_reasoning: plan.generator_reasoning,
      judge: plan.judge,
      judge_reasoning: plan.judge_reasoning,
      retrieval_arms: plan.retrieval_arms,
      model_arms: plan.model_arms,
      clean_scopes: 100,
      attacked_scopes: 100,
      completed_native_recalls: 200,
      completed_retrieval_decisions: 800,
      completed_generations: 800,
      completed_judgments: 1600,
      mutation_contract: plan.mutation_contract,
    },
    arm_definitions: {
      A0: {
        stored_signed_labels: false,
        query_local_lure_detection: false,
        active_context_withholding: false,
        interpretation: 'AIMOS native relevance plus diversity with epistemic policy bypassed; not the original Contriever baseline.',
      },
      A1: {
        stored_signed_labels: true,
        query_local_lure_detection: false,
        active_context_withholding: false,
        interpretation: 'Signed stored-label contribution.',
      },
      A2: {
        stored_signed_labels: true,
        query_local_lure_detection: true,
        active_context_withholding: false,
        interpretation: 'A1 plus query-local lure signals.',
      },
      A3: {
        stored_signed_labels: true,
        query_local_lure_detection: true,
        active_context_withholding: true,
        interpretation: 'Complete production policy.',
      },
    },
    policy_results: recomputedPolicies,
    contrasts: recomputedContrasts,
    holm_bonferroni_familywise_0_05: recomputedHolm,
    mechanism_activation: {
      pre_epistemic_positive_control: recomputedPolicies.A0
        .pre_epistemic_positive_control.attacked_with_any_poison_in_candidate_opening,
      A1_A2_selected_set_equal: {
        count: proofs.parity.a1_a2_selected_equal,
        total: proofs.parity.total_pairs,
      },
      A1_A2_active_context_equal: {
        count: proofs.parity.a1_a2_active_context_equal,
        total: proofs.parity.total_pairs,
      },
      A1_A2_prompt_equal: {
        count: proofs.parity.a1_a2_prompt_equal,
        total: proofs.parity.total_pairs,
      },
      A2_A3_selected_set_equal: {
        count: proofs.parity.a2_a3_selected_equal,
        total: proofs.parity.total_pairs,
      },
      A2_A3_active_context_equal: {
        count: proofs.parity.a2_a3_active_context_equal,
        total: proofs.parity.total_pairs,
      },
      A2_A3_prompt_equal: {
        count: proofs.parity.a2_a3_prompt_equal,
        total: proofs.parity.total_pairs,
      },
      active_context_withholding_exercised: {
        count: proofs.parity.active_context_withholding_exercised,
        total: proofs.parity.total_pairs,
        withheld_passages: proofs.parity.withheld_passages,
      },
      interpretation: 'Signed stored labels caused the observed deterministic retrieval isolation. Query-local detection had no measurable incremental contribution, and active-context withholding was not exercised. A2/A3 output differences arose from independent stochastic model and judge calls under identical prompts.',
    },
    integrity: {
      verified_target_outcomes: proofs.verified_target_outcomes,
      verified_retrieval_decisions: proofs.verified_retrieval_decisions,
      unique_verified_decision_events: proofs.unique_verified_decision_events,
      unique_verified_ledger_sequences: proofs.unique_verified_ledger_sequences,
      memory_root_unchanged: isolation.memory_root_unchanged,
      classification_root_unchanged: isolation.classification_root_unchanged,
      signed_classification_rows_unchanged: isolation.signed_classification_rows_unchanged,
      canonical_benchmark_footprint_unchanged: isolation.canonical_benchmark_footprint_unchanged,
      artifact_manifest: artifactManifest,
      preregistration_sha256: summary.preregistration_sha256,
      execution_plan_sha256: plan.plan_sha256,
      execution_plan_file_sha256: sha256(readRegularFile(planFile)),
      summary_sha256: summary.artifact_sha256,
      summary_file_sha256: sha256(readRegularFile(summaryFile)),
      isolation_sha256: isolation.isolation_sha256,
      isolation_file_sha256: sha256(readRegularFile(isolationFile)),
    },
    operational_recovery: {
      resume_amendment_present: true,
      scientific_contract_unchanged: amendment.scientific_contract_unchanged,
      completed_artifacts_reused: amendment.completed_artifacts_reused,
      lifecycle_changed_files: amendment.lifecycle_source_changes.map((entry) => entry.path),
      terminal_status_reconciled: true,
      reconciliation_sha256: reconciliation.reconciliation_sha256,
    },
    limitations: [
      'Declared N=100 adaptation; no full-corpus external-validity claim.',
      'No matched-model bridge was run.',
      'Query-local detection had no measurable incremental contribution in this fixed corpus.',
      'Active-context withholding was not activated in any of 200 clean or attacked contexts.',
      'Independent model and judge calls can differ stochastically under identical prompts.',
      'Mutable run status is excluded from the scientific artifact manifest and is bound separately by the completion reconciliation.',
    ],
  };
  publicEvidence.ablation_evidence_sha256 = poisonedRagSelfHash(
    publicEvidence,
    'ablation_evidence_sha256',
  );
  mkdirSync(OUTPUT_ROOT, { recursive: true });
  const outputFile = path.join(OUTPUT_ROOT, 'poisonedrag-epistemic-ablation.json');
  writeFileSync(outputFile, `${JSON.stringify(publicEvidence, null, 2)}\n`, { mode: 0o644 });
  return {
    result: publicEvidence,
    aggregate_file_sha256: sha256(readRegularFile(outputFile)),
  };
}

function verifiedHumanAgreement() {
  const file = path.join(OUTPUT_ROOT, 'poisonedrag-human-agreement.json');
  const agreement = readHashedJson(file, 'summary_sha256', 'canonical-json');
  if (agreement.schema !== 'hom.aimos.poisonedrag-human-agreement/v1'
    || agreement.protocol !== 'poisonedrag-n100-v1'
    || agreement.run_id !== RUNS.poisonedRag
    || agreement.reviewer_role !== 'system_author'
    || agreement.blinding?.arm_hidden_during_review !== true
    || agreement.blinding?.judge_verdict_hidden_during_review !== true
    || agreement.blinding?.arm_mapping_revealed_after_label_completion !== true
    || agreement.intended_answers !== 200
    || agreement.audited_answers !== 200
    || agreement.intended_target_pairs !== 100
    || agreement.complete_target_pairs !== 100
    || agreement.correctness_agreement?.n !== 200
    || agreement.target_assertion_agreement?.n !== 200
    || agreement.exclusions !== 0) {
    throw new Error('publication_human_agreement_invalid');
  }
  return {
    reviewer_role: agreement.reviewer_role,
    independence: 'not_independent_system_author_review',
    blinding: agreement.blinding,
    intended_answers: agreement.intended_answers,
    audited_answers: agreement.audited_answers,
    intended_target_pairs: agreement.intended_target_pairs,
    complete_target_pairs: agreement.complete_target_pairs,
    correctness_agreement: agreement.correctness_agreement,
    target_assertion_agreement: agreement.target_assertion_agreement,
    disagreement_count: agreement.disagreement_count,
    exclusions: agreement.exclusions,
    bootstrap_unit: agreement.bootstrap_unit,
    evidence: {
      packet_sha256: agreement.packet_sha256,
      summary_sha256: agreement.summary_sha256,
      aggregate_file_sha256: sha256(readRegularFile(file)),
    },
  };
}

function verifiedSignedPurgeEvidence() {
  if (!existsSync(PURGE_RECEIPT_ROOT) || lstatSync(PURGE_RECEIPT_ROOT).isSymbolicLink()) {
    throw new Error('publication_purge_receipt_root_invalid');
  }
  const files = readdirSync(PURGE_RECEIPT_ROOT)
    .filter((name) => name.endsWith('.json'))
    .sort();
  if (!files.length) throw new Error('publication_purge_receipts_missing');

  const databases = new Set();
  const receipts = files.map((name) => {
    const file = path.join(PURGE_RECEIPT_ROOT, name);
    const bytes = readRegularFile(file);
    const receipt = JSON.parse(bytes.toString('utf8'));
    const verification = verifyWholeBrainPurgeReceipt(receipt);
    const database = String(receipt.body?.target?.database || '');
    if (!verification.valid
      || receipt.body?.completion_status !== 'complete'
      || receipt.body?.postcondition?.mode !== 'destroyed'
      || receipt.body?.postcondition?.database_present !== false
      || database === 'aimos'
      || !/^aimos_(?:benchmark|test|purge)_[A-Za-z0-9_]+$/.test(database)
      || databases.has(database)) {
      throw new Error(`publication_purge_receipt_invalid:${name}`);
    }
    databases.add(database);
    return {
      database_identifier_sha256: sha256(`aimos-purge-database/v1\0${database}`),
      ceremony_identifier_sha256: sha256(
        `aimos-purge-ceremony/v1\0${receipt.body.ceremony_id}`,
      ),
      receipt_file_sha256: sha256(bytes),
      affected_table_classes: receipt.body.affected_table_classes,
      signature_verified: true,
      completion_status: 'complete',
      completion_mode: 'destroyed',
      database_absence_verified: true,
    };
  });

  const result = {
    schema: 'hom.aimos.signed-scratch-purge-public-evidence/v1',
    raw_receipts_published: false,
    master_identity_published: false,
    receipt_count: receipts.length,
    verified_receipt_count: receipts.length,
    invalid_receipt_count: 0,
    canonical_brain_included: false,
    receipts,
  };
  result.purge_evidence_sha256 = poisonedRagSelfHash(result, 'purge_evidence_sha256');
  return { result, databases };
}

const utilityRun = verifyRunComplete(RUNS.utility);
const officialLocomoRun = verifyRunComplete(RUNS.locomoOfficial);
const poisonedRagRun = verifyRunComplete(RUNS.poisonedRag);
const poisonedRagAblationRun = verifyAblationRunComplete(RUNS.poisonedRagAblation);
const poisonedRagAblation = verifiedPoisonedRagAblation(poisonedRagAblationRun);
const signedPurge = verifiedSignedPurgeEvidence();
const mutationIntegrityFile = path.join(OUTPUT_ROOT, 'mutation-integrity-verification.json');
const mutationIntegrity = readHashedJson(
  mutationIntegrityFile,
  'mutation_integrity_evidence_sha256',
);
if (mutationIntegrity.schema !== 'hom.aimos.mutation-integrity-public-evidence/v1'
  || mutationIntegrity.run_id !== RUNS.mutationIntegrity
  || mutationIntegrity.execution?.completed_transition_measurements !== 20
  || mutationIntegrity.verifier?.sql_portable_parity !== true
  || Object.values(mutationIntegrity.authorization_cases || {}).some((value) => value !== true)
  || Object.values(mutationIntegrity.tamper_cases || {}).some((value) => value !== true)) {
  throw new Error('publication_mutation_integrity_invalid');
}

const result = {
  schema: 'hom.aimos.publication-evidence/v2',
  self_hash_algorithm: 'sha256(canonical-json(unsigned-object))',
  generated_from_verified_local_artifacts: true,
  data_policy: 'Aggregate metrics, hashes, counts, model identities, and protocol declarations only; no benchmark text, answers, provider payloads, credentials, certificates, memory IDs, or absolute paths.',
  warnings: [
    'The two LoCoMo results use different metrics and protocols and must not be averaged or substituted for one another.',
    'The PoisonedRAG result is a declared N=100 adaptation, not a strict reproduction of the original full-corpus experiment.',
    'PoisonedRAG measured signed epistemic classification and retrieval isolation after canonical retention; it did not demonstrate save-time rejection or quarantine.',
    'The PoisonedRAG ablation attributes the observed deterministic retrieval isolation to signed stored epistemic labels; query-local detection had no measurable incremental contribution and active-context withholding was not exercised in the fixed corpus.',
    'The completed blinded human review was performed by the system author and is not represented as an independent assessment.',
  ],
  runs: {
    canonical_utility: {
      run_id: RUNS.utility,
      longmemeval: verifiedCanonical(utilityRun, 'longmemeval', 500),
      locomo_llm_judged: verifiedCanonical(utilityRun, 'locomo', 1986),
      artifact_manifest: verifyArtifactManifest(utilityRun),
      scratch_brain_status: signedPurge.databases.has(`aimos_benchmark_${RUNS.utility}`)
        ? 'signed_destroyed_receipt_verified' : 'signed_purge_receipt_missing',
    },
    locomo_official: {
      run_id: RUNS.locomoOfficial,
      result: verifiedOfficialLocomo(officialLocomoRun),
      artifact_manifest: verifyArtifactManifest(officialLocomoRun),
      scratch_brain_status: signedPurge.databases.has(`aimos_benchmark_${RUNS.locomoOfficial}`)
        ? 'signed_destroyed_receipt_verified' : 'signed_purge_receipt_missing',
    },
    poisonedrag_n100: {
      run_id: RUNS.poisonedRag,
      result: verifiedPoisonedRag(poisonedRagRun),
      human_agreement: verifiedHumanAgreement(),
      artifact_manifest: verifyArtifactManifest(poisonedRagRun),
      scratch_brain_status: signedPurge.databases.has(`aimos_benchmark_${RUNS.poisonedRag}`)
        ? 'signed_destroyed_receipt_verified' : 'signed_purge_receipt_missing',
    },
    poisonedrag_epistemic_ablation: {
      run_id: RUNS.poisonedRagAblation,
      source_run_id: RUNS.poisonedRag,
      result: poisonedRagAblation.result,
      aggregate_file_sha256: poisonedRagAblation.aggregate_file_sha256,
      scratch_brain_status: signedPurge.databases.has(`aimos_benchmark_${RUNS.poisonedRagAblation}`)
        ? 'signed_destroyed_receipt_verified' : 'signed_purge_receipt_missing',
    },
    mutation_integrity: {
      run_id: RUNS.mutationIntegrity,
      result: mutationIntegrity,
      aggregate_file_sha256: sha256(readRegularFile(mutationIntegrityFile)),
      scratch_brain_status: signedPurge.databases.has(`aimos_test_security_mutation_${RUNS.mutationIntegrity}`)
        ? 'signed_destroyed_receipt_verified' : 'signed_purge_receipt_missing',
    },
  },
  signed_scratch_purge: signedPurge.result,
  empirical_completion: {
    utility: 'complete',
    poisonedrag_n100: 'complete',
    poisonedrag_epistemic_ablation: 'complete',
    mutation_integrity_suite: 'complete',
    blinded_human_agreement_audit: 'complete_system_author_review',
    signed_scratch_brain_purges: 'complete_verified_receipts',
  },
};
if (Object.values(result.runs).some((run) => run.scratch_brain_status !== 'signed_destroyed_receipt_verified')) {
  throw new Error('publication_promoted_run_purge_receipt_missing');
}
result.publication_evidence_sha256 = poisonedRagSelfHash(
  result,
  'publication_evidence_sha256',
);

mkdirSync(OUTPUT_ROOT, { recursive: true });
const outputFile = path.join(OUTPUT_ROOT, 'verified-benchmark-results.json');
writeFileSync(outputFile, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
console.log(JSON.stringify({
  output_file: path.relative(ROOT, outputFile),
  publication_evidence_sha256: result.publication_evidence_sha256,
}, null, 2));
