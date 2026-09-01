#!/usr/bin/env node

// Deterministic, offline publication projection from retained public evidence.
// This is not a benchmark runner and has no database, network, identity, or
// provider authority.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUTPUT_ROOT = path.join(ROOT, 'eval', 'publication', 'v2c3');
const SHA256 = /^[0-9a-f]{64}$/;
const Z_95 = 1.959963984540054;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const SOURCES = Object.freeze({
  publication: 'eval/publication/verified-benchmark-results.json',
  mutation: 'eval/publication/mutation-integrity-verification.json',
  epistemic: 'eval/publication/poisonedrag-epistemic-verification.json',
  ablation: 'eval/publication/poisonedrag-epistemic-ablation.json',
  agreement: 'eval/publication/poisonedrag-human-agreement.json',
  canary: 'eval/publication/canary-cross-transport-verification.json',
  p1: 'verifiers/mutmem-conformance/v2/protocol-manifest.json',
  p2: 'verifiers/mutmem-conformance/v2/p2-closure-audit.json',
  s5: 'verifiers/mutmem-conformance/v1/verification-report.json',
  installer: 'verifiers/mutmem-conformance/v2/p3-clean-installer-qualification.json',
  reproducibility: 'reproducibility/mutmem-v2-contract.json',
  environment: 'reproducibility/mutmem-v2-environment-contract.json',
  canonicalCorpus: 'eval/data/canonical/corpus-manifest.json',
  poisonSource: 'eval/poisonedrag/source-lock.json',
  poisonTargets: 'eval/poisonedrag/n100-public-target-lock.json',
});

function regularBytes(relative) {
  const file = path.join(ROOT, relative);
  assert(existsSync(file) && !lstatSync(file).isSymbolicLink() && statSync(file).isFile(),
    `v2c3_source_invalid:${relative}`);
  return readFileSync(file);
}

function readJson(relative) {
  return JSON.parse(regularBytes(relative).toString('utf8'));
}

function selfHash(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  return sha256(Buffer.from(canonicalJson(unsigned), 'utf8'));
}

function withSelfHash(value, field) {
  return { ...value, [field]: selfHash(value, field) };
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function approximately(left, right, tolerance = 1e-12) {
  return Number.isFinite(left) && Number.isFinite(right) && Math.abs(left - right) <= tolerance;
}

function wilson(successes, total) {
  assert(Number.isInteger(successes) && Number.isInteger(total)
    && total > 0 && successes >= 0 && successes <= total, 'v2c3_wilson_input_invalid');
  const probability = successes / total;
  const z2 = Z_95 * Z_95;
  const denominator = 1 + z2 / total;
  const center = (probability + z2 / (2 * total)) / denominator;
  const radius = (Z_95 / denominator)
    * Math.sqrt((probability * (1 - probability) / total) + (z2 / (4 * total * total)));
  return { lower: Math.max(0, center - radius), upper: Math.min(1, center + radius) };
}

function rateCell(id, family, metric, source, options = {}) {
  const count = Number(source.count ?? source.correct ?? source.agreements ?? source.detected_n
    ?? source.flagged_n ?? source.verified ?? source.valid_n ?? source.adverse_label_count);
  const total = Number(source.total ?? source.n ?? source.intended_n ?? source.checked
    ?? source.terminal_n);
  assert(Number.isInteger(count) && Number.isInteger(total) && total > 0
    && count >= 0 && count <= total, `v2c3_rate_input_invalid:${id}`);
  const value = count / total;
  const tolerance = options.source_tolerance ?? 1e-12;
  const declaredRate = source.rate ?? source.accuracy ?? source.raw_agreement
    ?? source.detection_rate ?? source.false_positive_rate;
  if (declaredRate != null) {
    assert(approximately(value, Number(declaredRate), tolerance), `v2c3_rate_mismatch:${id}`);
  }
  const interval = wilson(count, total);
  if (source.wilson_95) {
    assert(approximately(interval.lower, Number(source.wilson_95.lower), tolerance)
      && approximately(interval.upper, Number(source.wilson_95.upper), tolerance),
    `v2c3_wilson_mismatch:${id}`);
  }
  return {
    id,
    family,
    metric,
    count,
    total,
    value,
    wilson_95: interval,
    confidence_interval_authority: 'independently_recomputed_from_public_counts',
    historical_result: options.historical_result !== false,
    scope: options.scope || null,
  };
}

function kappaCell(id, source, scope) {
  const n = Number(source.n);
  const observed = Number(source.agreements) / n;
  const human = Number(source.human_positive) / n;
  const judge = Number(source.judge_positive) / n;
  const expected = (human * judge) + ((1 - human) * (1 - judge));
  const kappa = (observed - expected) / (1 - expected);
  assert(approximately(observed, source.raw_agreement)
    && approximately(expected, source.expected_agreement)
    && approximately(kappa, source.cohen_kappa), `v2c3_kappa_mismatch:${id}`);
  return {
    id,
    family: 'human_agreement',
    metric: 'cohen_kappa',
    n,
    agreements: source.agreements,
    human_positive: source.human_positive,
    judge_positive: source.judge_positive,
    observed_agreement: observed,
    expected_agreement: expected,
    value: kappa,
    bootstrap_interval_published: false,
    bootstrap_interval_omission_reason: 'private_target_pair_rows_unavailable_for_independent_regeneration',
    historical_result: true,
    scope,
  };
}

function verifyCanonicalSelfHash(value, field, code) {
  assert(SHA256.test(String(value[field] || '')) && value[field] === selfHash(value, field), code);
}

function verifyJsonSelfHash(value, field, code) {
  const unsigned = { ...value };
  delete unsigned[field];
  assert(SHA256.test(String(value[field] || ''))
    && value[field] === sha256(Buffer.from(JSON.stringify(unsigned), 'utf8')), code);
}

function sourceInventory(values) {
  return Object.entries(SOURCES).map(([id, relative]) => ({
    id,
    path: relative,
    file_sha256: sha256(regularBytes(relative)),
    semantic_root_sha256: ({
      publication: values.publication.publication_evidence_sha256,
      mutation: values.mutation.mutation_integrity_evidence_sha256,
      epistemic: values.epistemic.epistemic_verification_sha256,
      ablation: values.ablation.ablation_evidence_sha256,
      agreement: values.agreement.summary_sha256,
      canary: values.canary.public_evidence_sha256,
      p1: values.p1.protocol_root_sha256,
      p2: values.p2.closure_sha256,
      s5: values.s5.report_root_sha256,
      installer: values.installer.qualification_sha256,
      reproducibility: values.reproducibility.reproducibility_contract_sha256,
      environment: values.environment.environment_contract_sha256,
    })[id] || null,
  }));
}

function metricContract() {
  return withSelfHash({
    schema: 'hom.aimos.mutmem-v2-publication-metric-contract/v1',
    status: 'FROZEN_BEFORE_V2_PUBLICATION_OUTPUT',
    estimators: {
      binary_rate: 'x/n with integer x and n',
      wilson_95: {
        z: Z_95,
        formula: '(p+z^2/(2n) +/- z*sqrt(p(1-p)/n+z^2/(4n^2)))/(1+z^2/n)',
      },
      paired_binary: 'exact two-sided McNemar using discordant counts b and c',
      multiple_comparisons: 'Holm-Bonferroni independently within each declared four-contrast family',
      agreement: 'Cohen kappa from public n, agreements, and positive marginals',
      historical_continuous_metrics: 'copied only from the self-hashed V1 aggregate; no row-level recomputation claim',
    },
    numerical_tolerances: {
      integer_counts_and_hashes: 0,
      derived_binary_rates_wilson_mcnemar_holm_kappa: 1e-12,
      canary_rounded_wilson_bounds: 5e-9,
      provider_generated_outputs: null,
    },
    exclusions: {
      v1_bootstrap_intervals: 'omitted_from_v2_generated_tables_because_private_rows_are_unavailable',
      saber_operational_numbers: 'omitted_until_the_exact_private_artifact_is_recovered_and_independently_verified',
      september_installed_service_attempts: 'retained_in_attempt_ledger_but_forbidden_from_result_tables',
    },
    denominator_rule: 'intended_n_equals_terminal_n; failures and exclusions remain explicit and cannot count as defenses',
    rerun_authorized: false,
    database_access: false,
    network_access: false,
    provider_call: false,
  }, 'metric_contract_sha256');
}

function buildTables(values) {
  const publication = values.publication.runs;
  const poison = publication.poisonedrag_n100.result;
  const agreement = values.agreement;
  const historicalRates = [
    rateCell('v1-longmemeval-judged-accuracy', 'historical_v1_utility', 'llm_judged_accuracy',
      publication.canonical_utility.longmemeval.llm_judged_qa),
    rateCell('v1-locomo-judged-accuracy', 'historical_v1_utility', 'llm_judged_accuracy',
      publication.canonical_utility.locomo_llm_judged.llm_judged_qa),
    rateCell('v1-poisonedrag-clean-asr', 'historical_v1_poisonedrag', 'official_substring_clean_asr',
      poison.primary_official_substring_metric.clean_asr),
    rateCell('v1-poisonedrag-attacked-asr', 'historical_v1_poisonedrag', 'official_substring_attacked_asr',
      poison.primary_official_substring_metric.attacked_asr),
    rateCell('v1-poisonedrag-induced-asr', 'historical_v1_poisonedrag', 'official_substring_induced_asr',
      poison.primary_official_substring_metric.induced_asr),
    rateCell('v1-poisonedrag-poison-retrieved-at-5', 'historical_v1_poisonedrag', 'poison_retrieved_at_5',
      poison.retrieval.poison_retrieved_at_5),
    rateCell('v1-poisonedrag-clean-accuracy', 'historical_v1_poisonedrag', 'clean_accuracy',
      poison.utility.clean_accuracy),
    rateCell('v1-poisonedrag-attacked-accuracy', 'historical_v1_poisonedrag', 'attacked_accuracy',
      poison.utility.attacked_accuracy),
    rateCell('v1-poisonedrag-poison-label-recall', 'historical_v1_epistemics', 'poison_adverse_label_rate',
      poison.epistemic_classification.poison_classification),
    rateCell('v1-poisonedrag-clean-label-fpr', 'historical_v1_epistemics', 'clean_adverse_label_rate',
      poison.epistemic_classification.clean_false_positive),
  ];

  const ablationRows = [];
  for (const [arm, result] of Object.entries(values.ablation.policy_results)) {
    const metrics = [
      ['attacked-poison-retrieval-at-5', 'attacked_poison_retrieval_at_5', result.retrieval.attacked_poison_retrieval_at_5],
      ['official-clean-asr', 'official_substring_clean_asr', result.official_substring.clean_asr],
      ['official-attacked-asr', 'official_substring_attacked_asr', result.official_substring.attacked_asr],
      ['official-induced-asr', 'official_substring_induced_asr', result.official_substring.induced_asr],
      ['semantic-attacked-asr', 'semantic_attacked_asr', result.semantic_target_assertion.attacked_asr],
      ['semantic-induced-asr', 'semantic_induced_asr', result.semantic_target_assertion.induced_asr],
      ['clean-accuracy', 'clean_accuracy', result.utility.clean_accuracy],
      ['attacked-accuracy', 'attacked_accuracy', result.utility.attacked_accuracy],
    ];
    for (const [suffix, metric, source] of metrics) {
      ablationRows.push(rateCell(`v1-ablation-${arm.toLowerCase()}-${suffix}`,
        'historical_v1_ablation', metric, source, { scope: arm }));
    }
  }

  const contrasts = values.ablation.contrasts.flatMap((contrast) => Object.entries(contrast)
    .filter(([name, value]) => name !== 'contrast' && value?.exact_two_sided_p != null)
    .map(([family, value]) => {
      const holm = values.ablation.holm_bonferroni_familywise_0_05[family]
        .find((entry) => entry.contrast === contrast.contrast);
      assert(holm, `v2c3_holm_entry_missing:${family}:${contrast.contrast}`);
      return {
        id: `v1-ablation-${family}-${contrast.contrast}`,
        family,
        contrast: contrast.contrast,
        b: value.b_left_true_right_false,
        c: value.c_left_false_right_true,
        exact_two_sided_p: value.exact_two_sided_p,
        holm_rank: holm.holm_rank,
        holm_adjusted_p: holm.adjusted_p,
        reject_familywise_0_05: holm.reject_familywise_0_05,
        historical_result: true,
      };
    }));

  const mutation = values.mutation;
  const authorizationPassed = Object.values(mutation.authorization_cases).filter(Boolean).length;
  const tamperPassed = Object.values(mutation.tamper_cases).filter(Boolean).length;
  const mutationRows = [
    {
      id: 'v1-mutation-integrity',
      transitions: mutation.latency_ms.n,
      authorization_passed: authorizationPassed,
      authorization_total: Object.keys(mutation.authorization_cases).length,
      tamper_passed: tamperPassed,
      tamper_total: Object.keys(mutation.tamper_cases).length,
      historical_result: true,
    },
    {
      id: 'v1-mutation-latency-storage',
      transitions: mutation.latency_ms.n,
      latency_ms: {
        mean: mutation.latency_ms.mean,
        median: mutation.latency_ms.median,
        p95: mutation.latency_ms.p95,
        minimum: mutation.latency_ms.minimum,
        maximum: mutation.latency_ms.maximum,
      },
      logical_row_storage_bytes: {
        combined_total: mutation.logical_row_storage_bytes.combined_total,
        combined_mean_per_transition: mutation.logical_row_storage_bytes.combined_mean_per_transition,
      },
      row_level_recomputation: false,
      authority: 'historical_self_hashed_v1_aggregate',
      limitation: mutation.latency_ms.boundary,
      historical_result: true,
    },
  ];

  const historicalContinuousRows = [
    {
      id: 'v1-locomo-token-f1',
      family: 'historical_v1_locomo_official',
      metric: publication.locomo_official.result.metric,
      n: publication.locomo_official.result.n,
      mean_f1: publication.locomo_official.result.mean_f1,
      score_percent: publication.locomo_official.result.mean_f1 * 100,
      bootstrap_interval_published: false,
      bootstrap_interval_omission_reason: 'private_row_level_inputs_unavailable_for_independent_regeneration',
      historical_result: true,
    },
  ];

  const agreementRows = [
    kappaCell('v1-human-correctness-agreement', agreement.correctness_agreement,
      'blinded_system_author_diagnostic_not_independent_validation'),
    kappaCell('v1-human-target-assertion-agreement', agreement.target_assertion_agreement,
      'blinded_system_author_diagnostic_not_independent_validation'),
  ];

  const canaryRows = [
    rateCell('v2-canary-explicit-marker-detection', 'v2_canary', 'explicit_marker_detection',
      values.canary.marked, {
        historical_result: false,
        source_tolerance: 5e-9,
        scope: values.canary.marker_scope_statement,
      }),
    rateCell('v2-canary-clean-false-positive', 'v2_canary', 'clean_false_positive',
      values.canary.clean, {
        historical_result: false,
        source_tolerance: 5e-9,
        scope: values.canary.marker_scope_statement,
      }),
  ];

  const p2Count = values.p1.vectors.intended_n
    + values.p1.mutation_profile.vectors.intended_n
    + values.p2.crypto_vectors.recall_intended_n
    + values.p2.crypto_vectors.mutation_intended_n;
  const verificationRows = [
    {
      id: 'v2-portable-protocol',
      schemas: Object.keys(values.p1.schemas).length,
      structural_vectors: values.p1.vectors.intended_n,
      mutation_vectors: values.p1.mutation_profile.vectors.intended_n,
      failure_codes: values.p1.failure_codes.length,
      protocol_root_sha256: values.p1.protocol_root_sha256,
    },
    {
      id: 'v2-node-python-independent-verification',
      intended_n: p2Count,
      terminal_n: p2Count,
      exit_criteria_passed: values.p2.exit_criteria_passed,
      exit_criteria_total: values.p2.exit_criteria_total,
      exact_verdict_and_reason_parity: values.p2.p2_complete,
      closure_sha256: values.p2.closure_sha256,
    },
    {
      id: 'v2-production-conformance',
      intended_n: values.s5.intended_n,
      terminal_n: values.s5.observed_n,
      required_classes: values.s5.required_class_count,
      exact_verdict_and_reason_parity: values.s5.production_independent_terminal_parity
        && values.s5.production_independent_protocol_reason_parity,
      report_root_sha256: values.s5.report_root_sha256,
    },
    {
      id: 'v2-clean-installer',
      node_version: values.installer.node_version,
      first_ready: values.installer.first_ready,
      restart_ready: values.installer.restart_ready,
      scheduler_ready: values.installer.scheduler_ready,
      guide_memories: values.installer.counts.guide_memories,
      experimental_memories: values.installer.counts.experimental_memories,
      public_agent_clearance_maximum: values.installer.public_agent_clearance_maximum,
      canonical_unchanged: values.installer.canonical_unchanged,
      qualified: values.installer.qualified,
      qualification_sha256: values.installer.qualification_sha256,
    },
  ];

  return withSelfHash({
    schema: 'hom.aimos.mutmem-v2-publication-table-registry/v1',
    status: 'REGENERATED_FROM_RETAINED_PUBLIC_EVIDENCE',
    tables: {
      historical_v1_rates: historicalRates,
      historical_v1_ablation_rates: ablationRows,
      historical_v1_ablation_inference: contrasts,
      historical_v1_mutation: mutationRows,
      historical_v1_continuous: historicalContinuousRows,
      historical_v1_human_agreement: agreementRows,
      v2_canary_explicit_marker_scope: canaryRows,
      v2_reproducibility_and_conformance: verificationRows,
    },
    omitted_numerical_families: [
      {
        id: 'saber-operational-campaign',
        reason: 'exact_private_artifact_not_in_verified_custody',
        numerical_claims_published: false,
      },
      {
        id: 'v1-bootstrap-intervals',
        reason: 'private_row_level_inputs_unavailable_for_independent_regeneration',
        numerical_claims_published: false,
      },
    ],
  }, 'table_registry_sha256');
}

function attemptLedger(values) {
  const runs = values.publication.runs;
  const entries = [
    {
      attempt_id: runs.canonical_utility.run_id,
      family: 'historical_v1_canonical_utility',
      intended_n: runs.canonical_utility.longmemeval.n + runs.canonical_utility.locomo_llm_judged.n,
      terminal_n: runs.canonical_utility.longmemeval.n + runs.canonical_utility.locomo_llm_judged.n,
      terminal_failures: 0,
      retries: null,
      exclusions: 0,
      amendments: false,
      reused_artifacts: false,
      terminal_state: runs.canonical_utility.scratch_brain_status,
      publication_disposition: 'HISTORICAL_V1_ONLY',
    },
    {
      attempt_id: runs.locomo_official.run_id,
      family: 'historical_v1_locomo_official',
      intended_n: runs.locomo_official.result.n,
      terminal_n: runs.locomo_official.result.n,
      terminal_failures: 0,
      retries: null,
      exclusions: 0,
      amendments: false,
      reused_artifacts: false,
      terminal_state: runs.locomo_official.scratch_brain_status,
      publication_disposition: 'HISTORICAL_V1_ONLY',
    },
    {
      attempt_id: runs.poisonedrag_n100.run_id,
      family: 'historical_v1_poisonedrag_n100',
      intended_n: runs.poisonedrag_n100.result.n,
      terminal_n: runs.poisonedrag_n100.result.n,
      terminal_failures: 0,
      retries: null,
      exclusions: 0,
      amendments: false,
      reused_artifacts: false,
      terminal_state: runs.poisonedrag_n100.scratch_brain_status,
      publication_disposition: 'HISTORICAL_V1_ONLY',
    },
    {
      attempt_id: values.ablation.run_id,
      family: 'historical_v1_poisonedrag_ablation',
      intended_n: values.ablation.intended_n,
      terminal_n: values.ablation.completed_n,
      terminal_failures: values.ablation.intended_n - values.ablation.completed_n,
      retries: null,
      exclusions: 0,
      amendments: values.ablation.operational_recovery.resume_amendment_present,
      reused_artifacts: values.ablation.operational_recovery.completed_artifacts_reused,
      terminal_state: 'COMPLETE_RECONCILED',
      publication_disposition: 'HISTORICAL_V1_ONLY',
    },
    {
      attempt_id: values.mutation.run_id,
      family: 'historical_v1_mutation_integrity',
      intended_n: values.mutation.latency_ms.n,
      terminal_n: values.mutation.latency_ms.n,
      terminal_failures: 0,
      retries: null,
      exclusions: 0,
      amendments: false,
      reused_artifacts: false,
      terminal_state: 'COMPLETE',
      publication_disposition: 'HISTORICAL_V1_ONLY',
    },
    {
      attempt_id: values.canary.source_run_id,
      family: 'v2_canary_explicit_marker_cross_transport',
      intended_n: values.canary.population.intended_n,
      terminal_n: values.canary.population.terminal_n,
      terminal_failures: values.canary.population.invalid_n + values.canary.population.indeterminate_n,
      retries: null,
      exclusions: 0,
      amendments: false,
      reused_artifacts: false,
      terminal_state: values.canary.terminal_state,
      publication_disposition: 'V2_EXPLICIT_MARKER_SCOPE',
    },
    {
      attempt_id: '20260901071952_862b14',
      family: 'installed_service_diagnostic',
      intended_n: null,
      terminal_n: 0,
      terminal_failures: 1,
      retries: null,
      exclusions: null,
      amendments: false,
      reused_artifacts: false,
      terminal_state: 'FAILED_RESUMABLE',
      publication_disposition: 'RETAINED_FAILURE_ZERO_RESULT_AUTHORITY',
      artifact_tree_root_sha256: '9d74fa2b3061d91957e0215eecd3475f10493f7946ad1703a128651dbcd7d950',
    },
    {
      attempt_id: '20260901072032_ab5355',
      family: 'installed_service_diagnostic',
      intended_n: null,
      terminal_n: 0,
      terminal_failures: 1,
      retries: null,
      exclusions: null,
      amendments: false,
      reused_artifacts: false,
      terminal_state: 'FAILED_RESUMABLE',
      publication_disposition: 'RETAINED_FAILURE_ZERO_RESULT_AUTHORITY',
      artifact_tree_root_sha256: '3341a4297ccebe755b6775ded76007486d6d6e90648f3695039b192269de8679',
    },
    {
      attempt_id: '20260901072229_d070cb',
      family: 'installed_service_diagnostic',
      intended_n: 1,
      terminal_n: 1,
      terminal_failures: 0,
      retries: null,
      exclusions: 0,
      amendments: true,
      reused_artifacts: false,
      terminal_state: 'COMPLETE_SUCCESSOR_WITH_RETAINED_FAILED_PREDECESSOR',
      publication_disposition: 'DIAGNOSTIC_ONLY_ZERO_V2_RESULT_AUTHORITY',
      artifact_tree_root_sha256: '359b2b85745d541eb66efe10c56ea7a8b9f7812bddbdb1e02f4bbd36557d0657',
    },
    {
      attempt_id: 'saber-artifact-custody-gap',
      family: 'saber_inspired_operational_campaign',
      intended_n: null,
      terminal_n: null,
      terminal_failures: null,
      retries: null,
      exclusions: null,
      amendments: null,
      reused_artifacts: null,
      terminal_state: 'RAW_ARTIFACT_NOT_IN_VERIFIED_CUSTODY',
      publication_disposition: 'NUMERICAL_CLAIMS_OMITTED',
      private_artifact_sha256: 'e18251c6ae0c0e205238a4011f27e8fcf56dac97958e4bfc1186cb972f392d20',
    },
  ];
  return withSelfHash({
    schema: 'hom.aimos.mutmem-v2-scientific-attempt-ledger/v1',
    entries,
    null_semantics: 'not_recoverable_from_the_retained_public_evidence; never interpreted_as_zero',
    failure_accounting_complete_for_promoted_numerical_results: true,
    failures_counted_as_defenses: false,
    silent_exclusions: false,
  }, 'attempt_ledger_sha256');
}

function claimMap(values, tables) {
  const rows = [
    ['V1-LONGMEMEVAL-UTILITY', 'HISTORICAL_V1', ['v1-longmemeval-judged-accuracy'],
      ['publication'], 'canonical-blind-v1', '459/500',
      'Historical V1 result; model-judged and not a current-source V2 benchmark.'],
    ['V1-LOCOMO-JUDGED', 'HISTORICAL_V1', ['v1-locomo-judged-accuracy'],
      ['publication'], 'canonical-blind-v1', '1472/1986',
      'Historical V1 judged accuracy; never merged with token F1.'],
    ['V1-LOCOMO-F1', 'HISTORICAL_V1', ['v1-locomo-token-f1'], ['publication'], 'locomo-upstream-qa-v1', '1986',
      'Point estimate remains in the V1 aggregate; bootstrap interval omitted because private rows are unavailable.'],
    ['V1-POISONEDRAG', 'HISTORICAL_V1', [
      'v1-poisonedrag-attacked-asr', 'v1-poisonedrag-poison-retrieved-at-5',
      'v1-poisonedrag-clean-accuracy', 'v1-poisonedrag-attacked-accuracy',
    ], ['publication', 'epistemic'], 'poisonedrag-n100-v1', '100 targets',
    'Adapted bounded N=100 protocol; no universal or unseen-attack claim.'],
    ['V1-EPISTEMIC-ABLATION', 'HISTORICAL_V1',
      tables.tables.historical_v1_ablation_rates.map((row) => row.id),
      ['ablation'], 'poisonedrag-n100-epistemic-ablation-v1', '100 paired targets per arm',
      'Fixed-corpus causal evidence; query-local contribution was null and withholding was not exercised.'],
    ['V1-MUTATION-INTEGRITY', 'HISTORICAL_V1', ['v1-mutation-integrity'],
      ['mutation'], 'hom-cognitive-mutation-integrity-v1', '20 transitions',
      'Historical retained-memory transition evidence under the V1 threat model.'],
    ['V1-MUTATION-LATENCY-STORAGE', 'HISTORICAL_V1', ['v1-mutation-latency-storage'],
      ['mutation'], 'hom-cognitive-mutation-integrity-v1', '20 transitions',
      'Single-machine descriptive values; row-level inputs are unavailable for independent recomputation.'],
    ['V1-HUMAN-AGREEMENT', 'HISTORICAL_V1', [
      'v1-human-correctness-agreement', 'v1-human-target-assertion-agreement',
    ], ['agreement'], 'blinded-system-author-audit-v1', '200 answers',
    'System-author diagnostic, not independent human validation; bootstrap interval omitted.'],
    ['V2-PORTABLE-PROTOCOL', 'CURRENT_V2', ['v2-portable-protocol'], ['p1'],
      values.p1.schema, `${values.p1.vectors.intended_n}+${values.p1.mutation_profile.vectors.intended_n} vectors`,
      'Portable verification protocol, not another memory engine or producer.'],
    ['V2-INDEPENDENT-VERIFIER', 'CURRENT_V2', ['v2-node-python-independent-verification'],
      ['p1', 'p2'], 'independent-node-python-v2', '72 terminal verdicts',
      'Cross-language verdict/reason parity proves verifier portability, not empirical utility.'],
    ['V2-PRODUCTION-CONFORMANCE', 'CURRENT_V2', ['v2-production-conformance'], ['s5'],
      values.s5.schema, `${values.s5.observed_n}/${values.s5.intended_n}`,
      'Conformance corpus, not benchmark efficacy.'],
    ['V2-CANARY', 'CURRENT_V2', [
      'v2-canary-explicit-marker-detection', 'v2-canary-clean-false-positive',
    ], ['canary'], values.canary.protocol_id, `${values.canary.population.terminal_n}/${values.canary.population.intended_n}`,
    values.canary.marker_scope_statement],
    ['V2-CLEAN-INSTALLER', 'CURRENT_V2', ['v2-clean-installer'], ['installer'],
      values.installer.schema, 'one qualified installation and restart',
      'Reproducibility evidence only; not benchmark evidence.'],
    ['SABER-OPERATIONAL-NUMBERS', 'OMITTED', [], [], 'unverified-private-artifact', null,
      'Exact private artifact is not in verified custody; no numerical V2 claim is permitted.'],
    ['CONTENT-TRUTH', 'PROHIBITED', [], [], 'none', null,
      'Integrity, provenance, authorization, and agreement do not establish semantic truth.'],
    ['UNIVERSAL-DEFENSE', 'PROHIBITED', [], [], 'none', null,
      'Fixed marker and N=100 evidence do not establish universal robustness.'],
    ['INDEPENDENT-REPLICATION', 'PROHIBITED', [], [], 'none', null,
      'No outside team independently reproduced the system or empirical results.'],
  ].map(([claim_id, disposition, table_cell_ids, source_ids, protocol, denominator, limitation]) => ({
    claim_id,
    disposition,
    statement_authority: disposition === 'PROHIBITED' ? 'none' : 'bounded_as_written',
    table_cell_ids,
    code: disposition === 'CURRENT_V2'
      ? ['verifiers/mutmem-v2/node', 'verifiers/mutmem-v2/python']
      : ['scripts/benchmark/regenerate-mutmem-v2-publication-evidence.mjs'],
    protocol,
    artifacts: source_ids.map((id) => SOURCES[id]),
    verifier: 'scripts/verification/verify-mutmem-v2-publication-evidence.mjs',
    denominator,
    limitation,
  }));
  return withSelfHash({
    schema: 'hom.aimos.mutmem-v2-claim-to-evidence-map/v1',
    rows,
    all_nonprohibited_claims_have_limitation: rows
      .filter((row) => row.disposition !== 'PROHIBITED')
      .every((row) => typeof row.limitation === 'string' && row.limitation.length > 0),
  }, 'claim_map_sha256');
}

function disclosureBoundary(values) {
  return withSelfHash({
    schema: 'hom.aimos.mutmem-v2-public-private-boundary/v1',
    public_source_artifacts: [
      { path: SOURCES.publication, scope: 'sanitized_historical_v1_aggregate' },
      { path: SOURCES.mutation, scope: 'sanitized_historical_mutation_aggregate' },
      { path: SOURCES.epistemic, scope: 'sanitized_historical_epistemic_aggregate' },
      { path: SOURCES.ablation, scope: 'sanitized_historical_ablation_aggregate' },
      { path: SOURCES.agreement, scope: 'sanitized_historical_agreement_aggregate' },
      { path: SOURCES.canary, scope: 'non_reconstructive_explicit_marker_aggregate' },
      { path: SOURCES.p1, scope: 'portable_protocol_manifest' },
      { path: SOURCES.p2, scope: 'independent_verifier_closure' },
      { path: SOURCES.s5, scope: 'public_conformance_report' },
    ],
    verification_only_not_republished: [
      {
        path: SOURCES.installer,
        reason: 'contains_ephemeral_certificate_and_instance_identity_metadata',
        public_substitute: 'v2-clean-installer table row without identity material',
      },
    ],
    withheld_families: [
      {
        family: 'v1_private_row_directories',
        reason: 'unavailable_on_current_machine_and_historically_identity_bearing',
        public_substitute: values.publication.publication_evidence_sha256,
      },
      {
        family: 'provider_requests_and_responses',
        reason: 'provider_confidentiality_and_possible_user_content',
        public_substitute: 'model_identity_protocol_and_aggregate_outcomes_only',
      },
      {
        family: 'restricted_dataset_text',
        reason: 'dataset_rights_and_redistribution_boundary',
        public_substitute: 'downloaders_source_locks_and_content_hashes',
      },
      {
        family: 'credentials_certificates_and_secret_material',
        reason: 'credential_and_identity_safety',
        public_substitute: 'non_identity_semantic_roots_and_boolean_verdicts',
      },
      {
        family: 'live_aimos_memories',
        reason: 'user_memory_privacy_and_noninterference',
        public_substitute: 'sanitized_public_aggregate_only',
      },
      {
        family: 'saber_private_campaign_artifact',
        reason: 'exact_artifact_not_in_verified_custody',
        public_substitute: 'no_numerical_claim',
      },
    ],
    prohibited_public_payloads: [
      'absolute_machine_paths',
      'secret_or_private_key_material',
      'identity_bearing_certificates_or_receipts',
      'live_memory_content_or_identifiers',
      'unauthorized_provider_payloads',
      'restricted_dataset_text',
    ],
  }, 'boundary_sha256');
}

function figureRegistry() {
  return withSelfHash({
    schema: 'hom.aimos.mutmem-v2-publication-figure-registry/v1',
    figures: [],
    figure_count: 0,
    reason: 'V2C3_precedes_manuscript_layout_and_the_V1_manuscript_contains_no_figure_environment',
    rule: 'Any figure introduced in V2C4 must be generated from the table registry and reopens V2C3 regeneration.',
  }, 'figure_registry_sha256');
}

function loadAndValidateSources() {
  const values = Object.fromEntries(Object.entries(SOURCES).map(([id, relative]) => [id, readJson(relative)]));
  verifyCanonicalSelfHash(values.publication, 'publication_evidence_sha256', 'v2c3_publication_hash_invalid');
  verifyJsonSelfHash(values.mutation, 'mutation_integrity_evidence_sha256', 'v2c3_mutation_hash_invalid');
  verifyJsonSelfHash(values.epistemic, 'epistemic_verification_sha256', 'v2c3_epistemic_hash_invalid');
  verifyCanonicalSelfHash(values.ablation, 'ablation_evidence_sha256', 'v2c3_ablation_hash_invalid');
  verifyCanonicalSelfHash(values.agreement, 'summary_sha256', 'v2c3_agreement_hash_invalid');
  verifyCanonicalSelfHash(values.canary, 'public_evidence_sha256', 'v2c3_canary_hash_invalid');
  verifyCanonicalSelfHash(values.p1, 'protocol_root_sha256', 'v2c3_p1_hash_invalid');
  verifyCanonicalSelfHash(values.p2, 'closure_sha256', 'v2c3_p2_hash_invalid');
  verifyCanonicalSelfHash(values.reproducibility, 'reproducibility_contract_sha256',
    'v2c3_reproducibility_hash_invalid');
  verifyCanonicalSelfHash(values.environment, 'environment_contract_sha256',
    'v2c3_environment_hash_invalid');
  assert(values.ablation.intended_n === values.ablation.completed_n
    && values.ablation.denominator_complete === true, 'v2c3_ablation_denominator_invalid');
  assert(values.canary.population.intended_n === values.canary.population.terminal_n
    && values.canary.population.invalid_n === 0
    && values.canary.population.indeterminate_n === 0, 'v2c3_canary_denominator_invalid');
  assert(values.s5.intended_n === values.s5.observed_n
    && values.s5.production_independent_terminal_parity === true
    && values.s5.production_independent_protocol_reason_parity === true, 'v2c3_s5_invalid');
  assert(values.installer.qualified === true && values.installer.canonical_unchanged === true,
    'v2c3_installer_invalid');
  return values;
}

export function buildMutMemV2PublicationEvidence() {
  const values = loadAndValidateSources();
  const outputs = {
    'metric-contract.json': metricContract(),
    'publication-tables.json': buildTables(values),
    'scientific-attempt-ledger.json': attemptLedger(values),
  };
  outputs['claim-to-evidence-map.json'] = claimMap(values, outputs['publication-tables.json']);
  outputs['public-private-boundary.json'] = disclosureBoundary(values);
  outputs['figure-registry.json'] = figureRegistry();

  const outputEntries = Object.entries(outputs).map(([name, value]) => ({
    path: `eval/publication/v2c3/${name}`,
    file_sha256: sha256(jsonBytes(value)),
    semantic_root_sha256: value[Object.keys(value).find((key) => key.endsWith('_sha256'))],
  }));
  outputs['publication-evidence-manifest.json'] = withSelfHash({
    schema: 'hom.aimos.mutmem-v2-publication-evidence-manifest/v1',
    source_inputs: sourceInventory(values),
    generated_outputs: outputEntries,
    output_file_count: outputEntries.length,
    all_outputs_deterministic: true,
    benchmark_run: false,
    database_access: false,
    network_access: false,
    provider_call: false,
  }, 'publication_evidence_root_sha256');
  return outputs;
}

export function regenerateMutMemV2PublicationEvidence({ check = false } = {}) {
  const outputs = buildMutMemV2PublicationEvidence();
  if (!check) mkdirSync(OUTPUT_ROOT, { recursive: true });
  for (const [name, value] of Object.entries(outputs)) {
    const bytes = jsonBytes(value);
    const file = path.join(OUTPUT_ROOT, name);
    if (check) {
      assert(existsSync(file) && !lstatSync(file).isSymbolicLink()
        && regularBytes(path.relative(ROOT, file)).equals(bytes), `v2c3_regeneration_drift:${name}`);
    } else {
      writeFileSync(file, bytes, { mode: 0o644 });
    }
  }
  return {
    schema: 'hom.aimos.mutmem-v2-publication-regeneration-result/v1',
    success: true,
    check,
    output_file_count: Object.keys(outputs).length,
    publication_evidence_root_sha256:
      outputs['publication-evidence-manifest.json'].publication_evidence_root_sha256,
    benchmark_run: false,
    database_access: false,
    network_access: false,
    provider_call: false,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = regenerateMutMemV2PublicationEvidence({ check: process.argv.includes('--check') });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
