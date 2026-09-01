#!/usr/bin/env node

// Independent, offline V2C-3 verifier. It does not import the publication
// exporter and independently reconstructs its statistical predicates.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { auditMutMemP2CleanTree } from './audit-mutmem-p2-clean-tree.mjs';
import { verifyP3InstallerQualification } from './verify-p3-clean-installer-qualification.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const EVIDENCE_ROOT = path.join(ROOT, 'eval', 'publication', 'v2c3');
const SHA256 = /^[0-9a-f]{64}$/;
const Z = 1.959963984540054;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function regularBytes(relative) {
  const file = path.join(ROOT, relative);
  assert(existsSync(file) && !lstatSync(file).isSymbolicLink() && statSync(file).isFile(),
    `v2c3_verify_file_invalid:${relative}`);
  return readFileSync(file);
}

function readJson(relative) {
  return JSON.parse(regularBytes(relative).toString('utf8'));
}

function canonicalSelfHash(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  return sha256(Buffer.from(canonicalJson(unsigned), 'utf8'));
}

function verifySelfHash(value, field, code) {
  assert(SHA256.test(String(value[field] || ''))
    && canonicalSelfHash(value, field) === value[field], code);
}

function verifyJsonSelfHash(value, field, code) {
  const unsigned = { ...value };
  delete unsigned[field];
  assert(SHA256.test(String(value[field] || ''))
    && sha256(Buffer.from(JSON.stringify(unsigned), 'utf8')) === value[field], code);
}

function close(left, right, tolerance = 1e-12) {
  return Number.isFinite(left) && Number.isFinite(right) && Math.abs(left - right) <= tolerance;
}

// Algebraically equivalent Wilson score construction, kept separate from the
// exporter so a shared implementation cannot make both paths falsely green.
function independentWilson(x, n) {
  assert(Number.isInteger(x) && Number.isInteger(n) && n > 0 && x >= 0 && x <= n,
    'v2c3_verify_wilson_input_invalid');
  const p = x / n;
  const correction = (Z * Z) / n;
  const midpoint = (p + correction / 2) / (1 + correction);
  const halfWidth = Math.sqrt((p * (1 - p) / n) + ((Z * Z) / (4 * n * n)))
    * Z / (1 + correction);
  return [Math.max(0, midpoint - halfWidth), Math.min(1, midpoint + halfWidth)];
}

function independentMcNemar(b, c) {
  assert(Number.isInteger(b) && Number.isInteger(c) && b >= 0 && c >= 0,
    'v2c3_verify_mcnemar_input_invalid');
  const discordant = b + c;
  if (discordant === 0) return 1;
  const tail = Math.min(b, c);
  let choose = 1;
  let sum = 1;
  for (let k = 1; k <= tail; k += 1) {
    choose *= (discordant - k + 1) / k;
    sum += choose;
  }
  return Math.min(1, (2 * sum) / (2 ** discordant));
}

function independentHolm(records) {
  const ordered = records.map((record, index) => ({ ...record, index }))
    .sort((left, right) => left.p - right.p || left.index - right.index);
  let previous = 0;
  const adjusted = ordered.map((record, position) => {
    previous = Math.max(previous, Math.min(1, record.p * (ordered.length - position)));
    return {
      contrast: record.contrast,
      rank: position + 1,
      adjusted_p: previous,
      reject: previous <= 0.05,
      index: record.index,
    };
  });
  return adjusted.sort((left, right) => left.index - right.index);
}

function independentKappa(row) {
  const observed = row.agreements / row.n;
  const humanPositive = row.human_positive / row.n;
  const judgePositive = row.judge_positive / row.n;
  const expected = (humanPositive * judgePositive)
    + ((1 - humanPositive) * (1 - judgePositive));
  return { observed, expected, kappa: (observed - expected) / (1 - expected) };
}

function flattenTableRows(tables) {
  return Object.values(tables.tables).flat();
}

function sourceRateMap(publication, ablation, canary) {
  const poison = publication.runs.poisonedrag_n100.result;
  const map = new Map([
    ['v1-longmemeval-judged-accuracy', publication.runs.canonical_utility.longmemeval.llm_judged_qa],
    ['v1-locomo-judged-accuracy', publication.runs.canonical_utility.locomo_llm_judged.llm_judged_qa],
    ['v1-poisonedrag-clean-asr', poison.primary_official_substring_metric.clean_asr],
    ['v1-poisonedrag-attacked-asr', poison.primary_official_substring_metric.attacked_asr],
    ['v1-poisonedrag-induced-asr', poison.primary_official_substring_metric.induced_asr],
    ['v1-poisonedrag-poison-retrieved-at-5', poison.retrieval.poison_retrieved_at_5],
    ['v1-poisonedrag-clean-accuracy', poison.utility.clean_accuracy],
    ['v1-poisonedrag-attacked-accuracy', poison.utility.attacked_accuracy],
    ['v1-poisonedrag-poison-label-recall', poison.epistemic_classification.poison_classification],
    ['v1-poisonedrag-clean-label-fpr', poison.epistemic_classification.clean_false_positive],
    ['v2-canary-explicit-marker-detection', canary.marked],
    ['v2-canary-clean-false-positive', canary.clean],
  ]);
  for (const [arm, result] of Object.entries(ablation.policy_results)) {
    const prefix = `v1-ablation-${arm.toLowerCase()}-`;
    map.set(`${prefix}attacked-poison-retrieval-at-5`, result.retrieval.attacked_poison_retrieval_at_5);
    map.set(`${prefix}official-clean-asr`, result.official_substring.clean_asr);
    map.set(`${prefix}official-attacked-asr`, result.official_substring.attacked_asr);
    map.set(`${prefix}official-induced-asr`, result.official_substring.induced_asr);
    map.set(`${prefix}semantic-attacked-asr`, result.semantic_target_assertion.attacked_asr);
    map.set(`${prefix}semantic-induced-asr`, result.semantic_target_assertion.induced_asr);
    map.set(`${prefix}clean-accuracy`, result.utility.clean_accuracy);
    map.set(`${prefix}attacked-accuracy`, result.utility.attacked_accuracy);
  }
  return map;
}

function sourceCount(source) {
  return Number(source.count ?? source.correct ?? source.detected_n ?? source.flagged_n
    ?? source.adverse_label_count);
}

function sourceTotal(source) {
  return Number(source.total ?? source.n ?? source.intended_n);
}

function verifyRateRows(tables, publication, ablation, canary) {
  const expected = sourceRateMap(publication, ablation, canary);
  const rows = [
    ...tables.tables.historical_v1_rates,
    ...tables.tables.historical_v1_ablation_rates,
    ...tables.tables.v2_canary_explicit_marker_scope,
  ];
  assert.equal(rows.length, expected.size, 'v2c3_verify_rate_row_count_invalid');
  const seen = new Set();
  for (const row of rows) {
    assert(!seen.has(row.id) && expected.has(row.id), `v2c3_verify_rate_id_invalid:${row.id}`);
    seen.add(row.id);
    const source = expected.get(row.id);
    const count = sourceCount(source);
    const total = sourceTotal(source);
    assert.equal(row.count, count, `v2c3_verify_rate_count_mismatch:${row.id}`);
    assert.equal(row.total, total, `v2c3_verify_rate_total_mismatch:${row.id}`);
    assert(close(row.value, count / total), `v2c3_verify_rate_value_mismatch:${row.id}`);
    const [lower, upper] = independentWilson(count, total);
    assert(close(row.wilson_95.lower, lower) && close(row.wilson_95.upper, upper),
      `v2c3_verify_rate_interval_mismatch:${row.id}`);
  }
  return rows.length;
}

function verifyAblationInference(tables, ablation) {
  const rows = tables.tables.historical_v1_ablation_inference;
  const expectedRows = ablation.contrasts.flatMap((contrast) => Object.entries(contrast)
    .filter(([family, value]) => family !== 'contrast' && value?.exact_two_sided_p != null)
    .map(([family, value]) => ({ family, contrast: contrast.contrast, source: value })));
  assert.equal(rows.length, expectedRows.length, 'v2c3_verify_inference_row_count_invalid');
  for (const expected of expectedRows) {
    const row = rows.find((candidate) => candidate.family === expected.family
      && candidate.contrast === expected.contrast);
    assert(row, `v2c3_verify_inference_row_missing:${expected.family}:${expected.contrast}`);
    assert.equal(row.b, expected.source.b_left_true_right_false);
    assert.equal(row.c, expected.source.c_left_false_right_true);
    const p = independentMcNemar(row.b, row.c);
    assert(close(row.exact_two_sided_p, p),
      `v2c3_verify_mcnemar_mismatch:${expected.family}:${expected.contrast}`);
  }
  const families = [...new Set(rows.map((row) => row.family))];
  for (const family of families) {
    const familyRows = rows.filter((row) => row.family === family);
    const adjusted = independentHolm(familyRows.map((row) => ({
      contrast: row.contrast,
      p: row.exact_two_sided_p,
    })));
    for (let index = 0; index < familyRows.length; index += 1) {
      const row = familyRows[index];
      const result = adjusted[index];
      assert.equal(row.contrast, result.contrast);
      assert.equal(row.holm_rank, result.rank);
      assert(close(row.holm_adjusted_p, result.adjusted_p));
      assert.equal(row.reject_familywise_0_05, result.reject);
    }
  }
  return rows.length;
}

function verifyAgreement(tables, agreement) {
  const sources = new Map([
    ['v1-human-correctness-agreement', agreement.correctness_agreement],
    ['v1-human-target-assertion-agreement', agreement.target_assertion_agreement],
  ]);
  for (const row of tables.tables.historical_v1_human_agreement) {
    const source = sources.get(row.id);
    assert(source, `v2c3_verify_agreement_id_invalid:${row.id}`);
    for (const field of ['n', 'agreements', 'human_positive', 'judge_positive']) {
      assert.equal(row[field], source[field], `v2c3_verify_agreement_source_mismatch:${row.id}:${field}`);
    }
    const derived = independentKappa(row);
    assert(close(row.observed_agreement, derived.observed)
      && close(row.expected_agreement, derived.expected)
      && close(row.value, derived.kappa), `v2c3_verify_kappa_mismatch:${row.id}`);
    assert.equal(row.bootstrap_interval_published, false);
  }
  return sources.size;
}

function verifyMutation(tables, mutation) {
  const integrity = tables.tables.historical_v1_mutation.find((row) => row.id === 'v1-mutation-integrity');
  const measurement = tables.tables.historical_v1_mutation
    .find((row) => row.id === 'v1-mutation-latency-storage');
  assert(integrity && measurement, 'v2c3_verify_mutation_rows_missing');
  assert.equal(integrity.transitions, mutation.latency_ms.n);
  assert.equal(integrity.authorization_passed,
    Object.values(mutation.authorization_cases).filter(Boolean).length);
  assert.equal(integrity.authorization_total, Object.keys(mutation.authorization_cases).length);
  assert.equal(integrity.tamper_passed, Object.values(mutation.tamper_cases).filter(Boolean).length);
  assert.equal(integrity.tamper_total, Object.keys(mutation.tamper_cases).length);
  for (const field of ['mean', 'median', 'p95', 'minimum', 'maximum']) {
    assert.equal(measurement.latency_ms[field], mutation.latency_ms[field]);
  }
  assert.equal(measurement.logical_row_storage_bytes.combined_total,
    mutation.logical_row_storage_bytes.combined_total);
  assert.equal(measurement.logical_row_storage_bytes.combined_mean_per_transition,
    mutation.logical_row_storage_bytes.combined_total / mutation.logical_row_storage_bytes.n);
  assert.equal(measurement.row_level_recomputation, false);
  return 2;
}

function verifyHistoricalContinuous(tables, publication) {
  const rows = tables.tables.historical_v1_continuous;
  assert.equal(rows.length, 1, 'v2c3_verify_continuous_row_count_invalid');
  const row = rows[0];
  const source = publication.runs.locomo_official.result;
  assert.equal(row.id, 'v1-locomo-token-f1');
  assert.equal(row.metric, source.metric);
  assert.equal(row.n, source.n);
  assert.equal(row.mean_f1, source.mean_f1);
  assert(close(row.score_percent, source.mean_f1 * 100));
  assert.equal(row.bootstrap_interval_published, false);
  return 1;
}

function verifyConformanceRows(tables, p1, p2, s5, installer) {
  const rows = new Map(tables.tables.v2_reproducibility_and_conformance.map((row) => [row.id, row]));
  const portable = rows.get('v2-portable-protocol');
  assert(portable && portable.schemas === Object.keys(p1.schemas).length
    && portable.structural_vectors === p1.vectors.intended_n
    && portable.mutation_vectors === p1.mutation_profile.vectors.intended_n
    && portable.failure_codes === p1.failure_codes.length
    && portable.protocol_root_sha256 === p1.protocol_root_sha256, 'v2c3_verify_p1_row_invalid');
  const parity = rows.get('v2-node-python-independent-verification');
  const expectedP2 = p1.vectors.intended_n + p1.mutation_profile.vectors.intended_n
    + p2.crypto_vectors.recall_intended_n + p2.crypto_vectors.mutation_intended_n;
  assert(parity && parity.intended_n === expectedP2 && parity.terminal_n === expectedP2
    && parity.exit_criteria_passed === p2.exit_criteria_passed
    && parity.exit_criteria_total === p2.exit_criteria_total
    && parity.exact_verdict_and_reason_parity === true, 'v2c3_verify_p2_row_invalid');
  const production = rows.get('v2-production-conformance');
  assert(production && production.intended_n === s5.intended_n
    && production.terminal_n === s5.observed_n
    && production.required_classes === s5.required_class_count
    && production.exact_verdict_and_reason_parity === true, 'v2c3_verify_s5_row_invalid');
  const install = rows.get('v2-clean-installer');
  assert(install && install.node_version === installer.node_version
    && install.first_ready === true && install.restart_ready === true
    && install.scheduler_ready === true
    && install.guide_memories === installer.counts.guide_memories
    && install.experimental_memories === 0
    && install.public_agent_clearance_maximum === 10
    && install.canonical_unchanged === true && install.qualified === true
    && install.qualification_sha256 === installer.qualification_sha256,
  'v2c3_verify_installer_row_invalid');
  return rows.size;
}

function verifyManifest(manifest) {
  verifySelfHash(manifest, 'publication_evidence_root_sha256', 'v2c3_verify_manifest_hash_invalid');
  assert.equal(manifest.output_file_count, manifest.generated_outputs.length);
  for (const input of manifest.source_inputs) {
    assert(!path.isAbsolute(input.path) && SHA256.test(input.file_sha256));
    assert.equal(sha256(regularBytes(input.path)), input.file_sha256,
      `v2c3_verify_source_hash_mismatch:${input.path}`);
  }
  for (const output of manifest.generated_outputs) {
    assert(!path.isAbsolute(output.path) && SHA256.test(output.file_sha256)
      && SHA256.test(output.semantic_root_sha256));
    assert.equal(sha256(regularBytes(output.path)), output.file_sha256,
      `v2c3_verify_output_hash_mismatch:${output.path}`);
  }
  assert.equal(manifest.benchmark_run, false);
  assert.equal(manifest.database_access, false);
  assert.equal(manifest.network_access, false);
  assert.equal(manifest.provider_call, false);
}

function verifyClaims(claims, tables) {
  verifySelfHash(claims, 'claim_map_sha256', 'v2c3_verify_claim_hash_invalid');
  const cells = new Set(flattenTableRows(tables).map((row) => row.id));
  assert.equal(cells.size, flattenTableRows(tables).length, 'v2c3_verify_duplicate_table_cell');
  const claimIds = new Set();
  for (const claim of claims.rows) {
    assert(!claimIds.has(claim.claim_id));
    claimIds.add(claim.claim_id);
    assert(['HISTORICAL_V1', 'CURRENT_V2', 'OMITTED', 'PROHIBITED'].includes(claim.disposition));
    for (const id of claim.table_cell_ids) {
      assert(cells.has(id), `v2c3_verify_unresolved_claim_cell:${claim.claim_id}:${id}`);
    }
    for (const artifact of claim.artifacts) {
      assert(!path.isAbsolute(artifact) && existsSync(path.join(ROOT, artifact)),
        `v2c3_verify_unresolved_claim_artifact:${claim.claim_id}:${artifact}`);
    }
    for (const codePath of claim.code) {
      assert(!path.isAbsolute(codePath) && existsSync(path.join(ROOT, codePath)),
        `v2c3_verify_unresolved_claim_code:${claim.claim_id}:${codePath}`);
    }
    assert(existsSync(path.join(ROOT, claim.verifier)));
    if (claim.disposition === 'OMITTED' || claim.disposition === 'PROHIBITED') {
      assert.equal(claim.table_cell_ids.length, 0, `v2c3_verify_forbidden_claim_cells:${claim.claim_id}`);
    } else {
      assert(claim.table_cell_ids.length > 0, `v2c3_verify_claim_cells_missing:${claim.claim_id}`);
      assert(typeof claim.denominator === 'string' && claim.denominator.length > 0);
    }
    assert(typeof claim.limitation === 'string' && claim.limitation.length > 0);
  }
  assert(claimIds.has('SABER-OPERATIONAL-NUMBERS')
    && claimIds.has('CONTENT-TRUTH')
    && claimIds.has('UNIVERSAL-DEFENSE')
    && claimIds.has('INDEPENDENT-REPLICATION'));
  return claims.rows.length;
}

function verifyAttempts(ledger) {
  verifySelfHash(ledger, 'attempt_ledger_sha256', 'v2c3_verify_attempt_hash_invalid');
  const ids = new Set();
  for (const entry of ledger.entries) {
    assert(!ids.has(entry.attempt_id));
    ids.add(entry.attempt_id);
    if (['HISTORICAL_V1_ONLY', 'V2_EXPLICIT_MARKER_SCOPE'].includes(entry.publication_disposition)) {
      assert(Number.isInteger(entry.intended_n) && entry.intended_n > 0
        && entry.terminal_n === entry.intended_n && entry.terminal_failures === 0
        && entry.exclusions === 0, `v2c3_verify_promoted_attempt_denominator_invalid:${entry.attempt_id}`);
    }
    if (entry.publication_disposition.includes('FAILURE')) {
      assert(entry.terminal_failures > 0 && entry.terminal_n === 0,
        `v2c3_verify_failure_attempt_invalid:${entry.attempt_id}`);
    }
  }
  assert.equal(ledger.failure_accounting_complete_for_promoted_numerical_results, true);
  assert.equal(ledger.failures_counted_as_defenses, false);
  assert.equal(ledger.silent_exclusions, false);
  return ledger.entries.length;
}

function verifyDisclosure(boundary, generatedFiles) {
  verifySelfHash(boundary, 'boundary_sha256', 'v2c3_verify_boundary_hash_invalid');
  assert(boundary.withheld_families.some((entry) => entry.family === 'saber_private_campaign_artifact'));
  assert(boundary.verification_only_not_republished.some((entry) => entry.path
    === 'verifiers/mutmem-conformance/v2/p3-clean-installer-qualification.json'));
  const forbiddenPatterns = [
    /\/Users\//,
    /\/home\//,
    /file:\/\//i,
    /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/,
    /"(?:api_key|master_passphrase|private_key|keychain_account)"\s*:/i,
    /"(?:signer_certificate|selected_agent_id|terminal_event_id|memory_id)"\s*:/i,
  ];
  for (const relative of generatedFiles) {
    const source = regularBytes(relative).toString('utf8');
    for (const pattern of forbiddenPatterns) {
      assert(!pattern.test(source), `v2c3_verify_public_leak:${relative}:${pattern}`);
    }
  }
}

function verifyS5ReadOnly() {
  const child = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts/verification/verify-mutmem-v2-s5-production-corpus.mjs'),
    '--read-only',
  ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 120_000 });
  assert.equal(child.status, 0, `v2c3_verify_s5_process_failed:${child.stderr}`);
  const result = JSON.parse(child.stdout);
  assert.equal(result.success, true);
  assert.equal(result.intended_n, result.observed_n);
  return result;
}

function verifyByteRegeneration() {
  const child = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts/benchmark/regenerate-mutmem-v2-publication-evidence.mjs'),
    '--check',
  ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 30_000 });
  assert.equal(child.status, 0, `v2c3_verify_byte_regeneration_failed:${child.stderr}`);
  const result = JSON.parse(child.stdout);
  assert.equal(result.success, true);
  assert.equal(result.check, true);
  return result;
}

export function verifyMutMemV2PublicationEvidence({
  p2Audit = null,
  verifyS5 = true,
  verifyRetainedReport = true,
} = {}) {
  const prefix = 'eval/publication/v2c3/';
  const metric = readJson(`${prefix}metric-contract.json`);
  const tables = readJson(`${prefix}publication-tables.json`);
  const attempts = readJson(`${prefix}scientific-attempt-ledger.json`);
  const claims = readJson(`${prefix}claim-to-evidence-map.json`);
  const boundary = readJson(`${prefix}public-private-boundary.json`);
  const figures = readJson(`${prefix}figure-registry.json`);
  const manifest = readJson(`${prefix}publication-evidence-manifest.json`);
  for (const [value, field, code] of [
    [metric, 'metric_contract_sha256', 'v2c3_verify_metric_hash_invalid'],
    [tables, 'table_registry_sha256', 'v2c3_verify_table_hash_invalid'],
    [figures, 'figure_registry_sha256', 'v2c3_verify_figure_hash_invalid'],
  ]) verifySelfHash(value, field, code);

  const publication = readJson('eval/publication/verified-benchmark-results.json');
  const mutation = readJson('eval/publication/mutation-integrity-verification.json');
  const agreement = readJson('eval/publication/poisonedrag-human-agreement.json');
  const ablation = readJson('eval/publication/poisonedrag-epistemic-ablation.json');
  const canary = readJson('eval/publication/canary-cross-transport-verification.json');
  const p1 = readJson('verifiers/mutmem-conformance/v2/protocol-manifest.json');
  const p2 = readJson('verifiers/mutmem-conformance/v2/p2-closure-audit.json');
  const s5 = readJson('verifiers/mutmem-conformance/v1/verification-report.json');
  const installer = readJson('verifiers/mutmem-conformance/v2/p3-clean-installer-qualification.json');

  verifySelfHash(publication, 'publication_evidence_sha256', 'v2c3_verify_publication_source_invalid');
  verifyJsonSelfHash(mutation, 'mutation_integrity_evidence_sha256', 'v2c3_verify_mutation_source_invalid');
  verifyJsonSelfHash(readJson('eval/publication/poisonedrag-epistemic-verification.json'),
    'epistemic_verification_sha256', 'v2c3_verify_epistemic_source_invalid');
  verifySelfHash(ablation, 'ablation_evidence_sha256', 'v2c3_verify_ablation_source_invalid');
  verifySelfHash(agreement, 'summary_sha256', 'v2c3_verify_agreement_source_invalid');
  verifySelfHash(canary, 'public_evidence_sha256', 'v2c3_verify_canary_source_invalid');
  verifySelfHash(p1, 'protocol_root_sha256', 'v2c3_verify_p1_source_invalid');
  verifySelfHash(p2, 'closure_sha256', 'v2c3_verify_p2_source_invalid');
  verifySelfHash(s5, 'report_root_sha256', 'v2c3_verify_s5_source_invalid');
  verifyP3InstallerQualification(installer);

  verifyManifest(manifest);
  const statisticalChecks = {
    rate_and_wilson_rows: verifyRateRows(tables, publication, ablation, canary),
    mcnemar_and_holm_rows: verifyAblationInference(tables, ablation),
    kappa_rows: verifyAgreement(tables, agreement),
    mutation_rows: verifyMutation(tables, mutation),
    historical_continuous_rows: verifyHistoricalContinuous(tables, publication),
  };
  const conformanceRows = verifyConformanceRows(tables, p1, p2, s5, installer);
  const claimRows = verifyClaims(claims, tables);
  const attemptRows = verifyAttempts(attempts);
  assert.equal(figures.figure_count, 0);
  assert.deepEqual(figures.figures, []);
  assert.equal(tables.omitted_numerical_families.find((row) => row.id === 'saber-operational-campaign')
    ?.numerical_claims_published, false);
  assert.equal(tables.omitted_numerical_families.find((row) => row.id === 'v1-bootstrap-intervals')
    ?.numerical_claims_published, false);

  const effectiveP2 = p2Audit || auditMutMemP2CleanTree();
  assert.equal(effectiveP2.passed, true);
  assert.equal(effectiveP2.intended_n, 72);
  const s5ReadOnly = verifyS5 ? verifyS5ReadOnly() : {
    success: true,
    intended_n: s5.intended_n,
    observed_n: s5.observed_n,
    corpus_root: s5.corpus_root,
    report_root_sha256: s5.report_root_sha256,
  };
  const byteRegeneration = verifyByteRegeneration();
  const generatedFiles = [
    ...manifest.generated_outputs.map((entry) => entry.path),
    `${prefix}publication-evidence-manifest.json`,
  ];
  if (existsSync(path.join(ROOT, `${prefix}independent-verification.json`))) {
    generatedFiles.push(`${prefix}independent-verification.json`);
  }
  verifyDisclosure(boundary, generatedFiles);

  const unsigned = {
    schema: 'hom.aimos.mutmem-v2-publication-independent-verification/v1',
    success: true,
    publication_evidence_root_sha256: manifest.publication_evidence_root_sha256,
    table_registry_sha256: tables.table_registry_sha256,
    claim_map_sha256: claims.claim_map_sha256,
    attempt_ledger_sha256: attempts.attempt_ledger_sha256,
    boundary_sha256: boundary.boundary_sha256,
    statistical_checks: statisticalChecks,
    conformance_rows: conformanceRows,
    claim_rows: claimRows,
    attempt_rows: attemptRows,
    node_python_verdict_reason_parity_n: effectiveP2.intended_n,
    s5_verdict_reason_parity_n: s5ReadOnly.observed_n,
    all_public_numerical_rows_regenerated: true,
    all_claim_rows_resolved: true,
    secret_and_private_boundary_passed: true,
    failures_counted_as_defenses: false,
    silent_exclusions: false,
    byte_identical_regeneration_verified: byteRegeneration.check === true,
    benchmark_run: false,
    database_access: false,
    network_access: false,
    provider_call: false,
  };
  const result = { ...unsigned, independent_verification_sha256: canonicalSelfHash(unsigned,
    'independent_verification_sha256') };
  const retainedRelative = `${prefix}independent-verification.json`;
  if (verifyRetainedReport && existsSync(path.join(ROOT, retainedRelative))) {
    const retained = readJson(retainedRelative);
    verifySelfHash(retained, 'independent_verification_sha256',
      'v2c3_verify_retained_report_hash_invalid');
    assert.deepEqual(retained, result, 'v2c3_verify_retained_report_drift');
  }
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const writing = process.argv.includes('--write');
  const result = verifyMutMemV2PublicationEvidence({ verifyRetainedReport: !writing });
  if (process.argv.includes('--write')) {
    writeFileSync(path.join(EVIDENCE_ROOT, 'independent-verification.json'),
      `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
