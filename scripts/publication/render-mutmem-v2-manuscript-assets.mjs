#!/usr/bin/env node

// Deterministic V2C-4 manuscript assets derived only from the closed V2C-3
// evidence package and the explicit manuscript contract.

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
const GENERATED = path.join(ROOT, 'paper', 'generated');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const SHA256 = /^[0-9a-f]{64}$/;

function regularBytes(relative) {
  const file = path.join(ROOT, relative);
  assert(existsSync(file) && !lstatSync(file).isSymbolicLink() && statSync(file).isFile(),
    `v2c4_asset_source_invalid:${relative}`);
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

function verifySelfHash(value, field, code) {
  assert(SHA256.test(String(value[field] || '')) && selfHash(value, field) === value[field], code);
}

function texEscape(value) {
  return String(value)
    .replaceAll('\\', '\\textbackslash{}')
    .replaceAll('&', '\\&')
    .replaceAll('%', '\\%')
    .replaceAll('$', '\\$')
    .replaceAll('#', '\\#')
    .replaceAll('_', '\\_')
    .replaceAll('{', '\\{')
    .replaceAll('}', '\\}')
    .replaceAll('~', '\\textasciitilde{}')
    .replaceAll('^', '\\textasciicircum{}');
}

function pct(value, digits = 2) {
  return (Number(value) * 100).toFixed(digits);
}

function fixed(value, digits) {
  return Number(value).toFixed(digits);
}

function rowById(rows, id) {
  const row = rows.find((candidate) => candidate.id === id);
  assert(row, `v2c4_table_row_missing:${id}`);
  return row;
}

function macro(name, value) {
  return `\\newcommand{\\${name}}{${value}}`;
}

function latexBytes(value) {
  return Buffer.from(`${value.trim()}\n`, 'utf8');
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function buildValues(contract, tables, claims, evidenceManifest, independent) {
  const historical = tables.tables.historical_v1_rates;
  const continuous = tables.tables.historical_v1_continuous;
  const mutation = tables.tables.historical_v1_mutation;
  const agreement = tables.tables.historical_v1_human_agreement;
  const ablation = tables.tables.historical_v1_ablation_rates;
  const v2 = tables.tables.v2_reproducibility_and_conformance;
  const canary = tables.tables.v2_canary_explicit_marker_scope;

  const longMem = rowById(historical, 'v1-longmemeval-judged-accuracy');
  const locomo = rowById(historical, 'v1-locomo-judged-accuracy');
  const locomoF1 = rowById(continuous, 'v1-locomo-token-f1');
  const poisonAttack = rowById(historical, 'v1-poisonedrag-attacked-asr');
  const poisonRetrieval = rowById(historical, 'v1-poisonedrag-poison-retrieved-at-5');
  const poisonCleanAccuracy = rowById(historical, 'v1-poisonedrag-clean-accuracy');
  const poisonAttackedAccuracy = rowById(historical, 'v1-poisonedrag-attacked-accuracy');
  const poisonLabels = rowById(historical, 'v1-poisonedrag-poison-label-recall');
  const cleanAdverse = rowById(historical, 'v1-poisonedrag-clean-label-fpr');
  const mutationIntegrity = rowById(mutation, 'v1-mutation-integrity');
  const mutationMeasure = rowById(mutation, 'v1-mutation-latency-storage');
  const human = rowById(agreement, 'v1-human-correctness-agreement');
  const protocol = rowById(v2, 'v2-portable-protocol');
  const parity = rowById(v2, 'v2-node-python-independent-verification');
  const conformance = rowById(v2, 'v2-production-conformance');
  const installer = rowById(v2, 'v2-clean-installer');
  const marker = rowById(canary, 'v2-canary-explicit-marker-detection');
  const cleanMarker = rowById(canary, 'v2-canary-clean-false-positive');

  const lines = [
    '% Generated from the closed publication-evidence root. Do not edit manually.',
    macro('MutMemEvidenceSourceCommit', `\\nolinkurl{${contract.evidence_source_commit}}`),
    macro('MutMemPublicationEvidenceRoot', `\\nolinkurl{${contract.publication_evidence_root_sha256}}`),
    macro('MutMemClaimMapRoot', `\\nolinkurl{${claims.claim_map_sha256}}`),
    macro('MutMemIndependentVerificationRoot', `\\nolinkurl{${independent.independent_verification_sha256}}`),
    macro('MutMemManuscriptContractRoot', `\\nolinkurl{${contract.manuscript_contract_sha256}}`),
    macro('MutMemRepositoryURL', `\\url{${contract.repository_url}}`),
    macro('MutMemVOneArxiv', texEscape(contract.published_predecessor)),
    macro('MutMemProtocolSchemaCount', protocol.schemas),
    macro('MutMemRecallStructuralVectorCount', protocol.structural_vectors),
    macro('MutMemMutationStructuralVectorCount', protocol.mutation_vectors),
    macro('MutMemFailureCodeCount', protocol.failure_codes),
    macro('MutMemCrossLanguageTerminalCount', parity.terminal_n),
    macro('MutMemVerifierExitPassed', parity.exit_criteria_passed),
    macro('MutMemVerifierExitTotal', parity.exit_criteria_total),
    macro('MutMemConformanceCount', conformance.terminal_n),
    macro('MutMemConformanceClassCount', conformance.required_classes),
    macro('MutMemCanaryPopulation', marker.total + cleanMarker.total),
    macro('MutMemCanaryMarkedDetected', marker.count),
    macro('MutMemCanaryMarkedTotal', marker.total),
    macro('MutMemCanaryMarkedPercent', pct(marker.value, 1)),
    macro('MutMemCanaryMarkedWilsonLower', pct(marker.wilson_95.lower, 2)),
    macro('MutMemCanaryCleanFlagged', cleanMarker.count),
    macro('MutMemCanaryCleanTotal', cleanMarker.total),
    macro('MutMemCanaryCleanPercent', pct(cleanMarker.value, 1)),
    macro('MutMemCanaryCleanWilsonUpper', pct(cleanMarker.wilson_95.upper, 2)),
    macro('MutMemInstallerNodeVersion', texEscape(installer.node_version)),
    macro('MutMemInstallerGuideCount', installer.guide_memories),
    macro('MutMemInstallerExperimentalCount', installer.experimental_memories),
    macro('MutMemInstallerClearanceMaximum', installer.public_agent_clearance_maximum),
    macro('MutMemLongMemCorrect', longMem.count),
    macro('MutMemLongMemTotal', longMem.total),
    macro('MutMemLongMemPercent', pct(longMem.value, 2)),
    macro('MutMemLongMemWilsonLower', pct(longMem.wilson_95.lower, 2)),
    macro('MutMemLongMemWilsonUpper', pct(longMem.wilson_95.upper, 2)),
    macro('MutMemLocomoCorrect', locomo.count),
    macro('MutMemLocomoTotal', locomo.total),
    macro('MutMemLocomoPercent', pct(locomo.value, 2)),
    macro('MutMemLocomoWilsonLower', pct(locomo.wilson_95.lower, 2)),
    macro('MutMemLocomoWilsonUpper', pct(locomo.wilson_95.upper, 2)),
    macro('MutMemLocomoFOne', fixed(locomoF1.score_percent, 2)),
    macro('MutMemPoisonAttackCount', poisonAttack.count),
    macro('MutMemPoisonAttackTotal', poisonAttack.total),
    macro('MutMemPoisonAttackPercent', pct(poisonAttack.value, 2)),
    macro('MutMemPoisonRetrievalCount', poisonRetrieval.count),
    macro('MutMemPoisonRetrievalTotal', poisonRetrieval.total),
    macro('MutMemPoisonRetrievalWilsonUpper', pct(poisonRetrieval.wilson_95.upper, 2)),
    macro('MutMemPoisonCleanAccuracyPercent', pct(poisonCleanAccuracy.value, 1)),
    macro('MutMemPoisonAttackedAccuracyPercent', pct(poisonAttackedAccuracy.value, 1)),
    macro('MutMemPoisonLabelCount', poisonLabels.count),
    macro('MutMemPoisonLabelTotal', poisonLabels.total),
    macro('MutMemCleanAdverseCount', cleanAdverse.count),
    macro('MutMemCleanAdverseTotal', cleanAdverse.total),
    macro('MutMemCleanAdversePercent', pct(cleanAdverse.value, 4)),
    macro('MutMemMutationTransitionCount', mutationIntegrity.transitions),
    macro('MutMemMutationAuthorizationPassed', mutationIntegrity.authorization_passed),
    macro('MutMemMutationAuthorizationTotal', mutationIntegrity.authorization_total),
    macro('MutMemMutationTamperPassed', mutationIntegrity.tamper_passed),
    macro('MutMemMutationTamperTotal', mutationIntegrity.tamper_total),
    macro('MutMemMutationMedianMs', fixed(mutationMeasure.latency_ms.median, 3)),
    macro('MutMemMutationPNinetyFiveMs', fixed(mutationMeasure.latency_ms.p95, 3)),
    macro('MutMemMutationMeanBytes', fixed(
      mutationMeasure.logical_row_storage_bytes.combined_mean_per_transition, 2)),
    macro('MutMemHumanAgreementCount', human.agreements),
    macro('MutMemHumanAgreementTotal', human.n),
    macro('MutMemHumanAgreementPercent', pct(human.observed_agreement, 1)),
    macro('MutMemHumanKappa', fixed(human.value, 4)),
    macro('MutMemStatisticalRateRows', independent.statistical_checks.rate_and_wilson_rows),
    macro('MutMemStatisticalInferenceRows', independent.statistical_checks.mcnemar_and_holm_rows),
    macro('MutMemEvidenceManifestOutputCount', evidenceManifest.output_file_count + 1),
  ];

  const armWords = { a0: 'AZero', a1: 'AOne', a2: 'ATwo', a3: 'AThree' };
  for (const arm of ['a0', 'a1', 'a2', 'a3']) {
    const prefix = `v1-ablation-${arm}-`;
    const label = armWords[arm];
    const retrieval = rowById(ablation, `${prefix}attacked-poison-retrieval-at-5`);
    const clean = rowById(ablation, `${prefix}clean-accuracy`);
    const attacked = rowById(ablation, `${prefix}attacked-accuracy`);
    lines.push(
      macro(`MutMemAblation${label}RetrievalCount`, retrieval.count),
      macro(`MutMemAblation${label}RetrievalTotal`, retrieval.total),
      macro(`MutMemAblation${label}CleanPercent`, pct(clean.value, 1)),
      macro(`MutMemAblation${label}AttackedPercent`, pct(attacked.value, 1)),
    );
  }
  return `${lines.join('\n')}\n`;
}

function historicalTable() {
  return String.raw`
\begin{table*}[t]
\centering
\caption{Historical MutMem V1 results, reproduced from the self-hashed V1 aggregate. These are not current-source V2 reruns.}
\label{tab:v1-historical}
\small
\begin{tabular}{@{}>{\raggedright\arraybackslash}p{0.26\textwidth}>{\raggedright\arraybackslash}p{0.30\textwidth}>{\raggedright\arraybackslash}p{0.32\textwidth}@{}}
\toprule
Protocol and metric & Historical V1 result & Boundary \\
\midrule
LongMemEval, LLM-judged accuracy & \MutMemLongMemCorrect/\MutMemLongMemTotal\ (\MutMemLongMemPercent\%; Wilson 95\% CI \MutMemLongMemWilsonLower--\MutMemLongMemWilsonUpper\%) & GPT-5.4 generator; GPT-5.6 Terra judge \\
LoCoMo, LLM-judged accuracy & \MutMemLocomoCorrect/\MutMemLocomoTotal\ (\MutMemLocomoPercent\%; Wilson 95\% CI \MutMemLocomoWilsonLower--\MutMemLocomoWilsonUpper\%) & Distinct from token F1 \\
LoCoMo, category-aware token F1 & \MutMemLocomoFOne & Bootstrap interval omitted in V2: private rows unavailable \\
PoisonedRAG adaptation, attacked ASR & \MutMemPoisonAttackCount/\MutMemPoisonAttackTotal\ (\MutMemPoisonAttackPercent\%) & Fixed post-calibration N=100 adaptation \\
PoisonedRAG adaptation, poison retrieval@5 & \MutMemPoisonRetrievalCount/\MutMemPoisonRetrievalTotal\ (Wilson upper \MutMemPoisonRetrievalWilsonUpper\%) & Retention plus retrieval isolation, not deletion \\
Mutation integrity & \MutMemMutationAuthorizationPassed/\MutMemMutationAuthorizationTotal\ authorization; \MutMemMutationTamperPassed/\MutMemMutationTamperTotal\ tamper cases & \MutMemMutationTransitionCount\ measured native transitions \\
Mutation transaction cost & median \MutMemMutationMedianMs\ ms; p95 \MutMemMutationPNinetyFiveMs\ ms; \MutMemMutationMeanBytes\ logical bytes/transition & Single historical machine and full transaction \\
Blinded system-author agreement & \MutMemHumanAgreementCount/\MutMemHumanAgreementTotal\ (\MutMemHumanAgreementPercent\%; $\kappa=\MutMemHumanKappa$) & Not independent human validation \\
\bottomrule
\end{tabular}
\end{table*}
`;
}

function ablationTable() {
  return String.raw`
\begin{table}[t]
\centering
\caption{Historical V1 fixed-corpus PoisonedRAG ablation. Each arm contains 100 paired targets.}
\label{tab:v1-ablation}
\small
\begin{tabular}{@{}lrrr@{}}
\toprule
Arm & poison retrieval@5 & clean accuracy & attacked accuracy \\
\midrule
A0 & \MutMemAblationAZeroRetrievalCount/\MutMemAblationAZeroRetrievalTotal & \MutMemAblationAZeroCleanPercent\% & \MutMemAblationAZeroAttackedPercent\% \\
A1 & \MutMemAblationAOneRetrievalCount/\MutMemAblationAOneRetrievalTotal & \MutMemAblationAOneCleanPercent\% & \MutMemAblationAOneAttackedPercent\% \\
A2 & \MutMemAblationATwoRetrievalCount/\MutMemAblationATwoRetrievalTotal & \MutMemAblationATwoCleanPercent\% & \MutMemAblationATwoAttackedPercent\% \\
A3 & \MutMemAblationAThreeRetrievalCount/\MutMemAblationAThreeRetrievalTotal & \MutMemAblationAThreeCleanPercent\% & \MutMemAblationAThreeAttackedPercent\% \\
\bottomrule
\end{tabular}
\end{table}
`;
}

function v2Table() {
  return String.raw`
\begin{table*}[t]
\centering
\caption{Current MutMem V2 reproducibility and conformance evidence. Counts are verification units, not benchmark accuracy.}
\label{tab:v2-evidence}
\small
\begin{tabular}{@{}>{\raggedright\arraybackslash}p{0.25\textwidth}>{\raggedright\arraybackslash}p{0.31\textwidth}>{\raggedright\arraybackslash}p{0.32\textwidth}@{}}
\toprule
Evidence family & Verified result & Interpretation \\
\midrule
Portable protocol & \MutMemProtocolSchemaCount\ schemas; \MutMemRecallStructuralVectorCount\ recall vectors; \MutMemMutationStructuralVectorCount\ mutation vectors; \MutMemFailureCodeCount\ recall failure codes & Versioned bytes, membership, predicates, and terminal vocabulary \\
Independent Node/Python verifier & \MutMemCrossLanguageTerminalCount/\MutMemCrossLanguageTerminalCount\ exact verdict and reason terminals; \MutMemVerifierExitPassed/\MutMemVerifierExitTotal\ exit criteria & Verifier portability, not empirical utility \\
Production conformance corpus & \MutMemConformanceCount/\MutMemConformanceCount\ cases across \MutMemConformanceClassCount\ required classes & Production/independent parity \\
Canary explicit-marker lane & marked \MutMemCanaryMarkedDetected/\MutMemCanaryMarkedTotal; clean flags \MutMemCanaryCleanFlagged/\MutMemCanaryCleanTotal & Explicit marker traversal only \\
Clean installer qualification & Node \MutMemInstallerNodeVersion; first boot, restart, and scheduler ready; \MutMemInstallerExperimentalCount\ experimental memories & One same-user installed system; no benchmark result \\
\bottomrule
\end{tabular}
\end{table*}
`;
}

function claimMapTable(claims) {
  const rows = claims.rows.map((claim) => [
    texEscape(claim.claim_id).replaceAll('-', '-\\allowbreak{}'),
    texEscape(claim.disposition.replaceAll('_', ' ')),
    texEscape(claim.denominator ?? 'No numerical claim'),
    texEscape(claim.limitation),
  ].join(' & ')).join(' \\\\\n');
  return `
\\scriptsize
\\begin{longtable}{@{}>{\\raggedright\\arraybackslash}p{0.16\\linewidth}>{\\raggedright\\arraybackslash}p{0.12\\linewidth}>{\\raggedright\\arraybackslash}p{0.14\\linewidth}>{\\raggedright\\arraybackslash}p{0.42\\linewidth}@{}}
\\caption{Complete manuscript claim-to-evidence disposition.}\\label{tab:claim-map}\\\\
\\toprule
Claim identifier & Disposition & Denominator & Limitation \\\\
\\midrule
\\endfirsthead
\\toprule
Claim identifier & Disposition & Denominator & Limitation \\\\
\\midrule
\\endhead
${rows} \\\\
\\bottomrule
\\end{longtable}
`;
}

function buildAssets() {
  const contract = readJson('paper/mutmem-v2-manuscript-contract.json');
  const tables = readJson('eval/publication/v2c3/publication-tables.json');
  const claims = readJson('eval/publication/v2c3/claim-to-evidence-map.json');
  const evidenceManifest = readJson('eval/publication/v2c3/publication-evidence-manifest.json');
  const independent = readJson('eval/publication/v2c3/independent-verification.json');
  verifySelfHash(contract, 'manuscript_contract_sha256', 'v2c4_contract_hash_invalid');
  verifySelfHash(tables, 'table_registry_sha256', 'v2c4_table_hash_invalid');
  verifySelfHash(claims, 'claim_map_sha256', 'v2c4_claim_hash_invalid');
  verifySelfHash(evidenceManifest, 'publication_evidence_root_sha256', 'v2c4_evidence_hash_invalid');
  verifySelfHash(independent, 'independent_verification_sha256', 'v2c4_verification_hash_invalid');
  assert(contract.publication_evidence_root_sha256
    === evidenceManifest.publication_evidence_root_sha256, 'v2c4_contract_evidence_mismatch');
  assert(independent.publication_evidence_root_sha256
    === evidenceManifest.publication_evidence_root_sha256, 'v2c4_verification_evidence_mismatch');
  const assets = {
    'evidence-values.tex': latexBytes(buildValues(
      contract, tables, claims, evidenceManifest, independent,
    )),
    'historical-results-table.tex': latexBytes(historicalTable()),
    'historical-ablation-table.tex': latexBytes(ablationTable()),
    'v2-evidence-table.tex': latexBytes(v2Table()),
    'claim-map-table.tex': latexBytes(claimMapTable(claims)),
  };
  const manifestUnsigned = {
    schema: 'hom.aimos.mutmem-v2-manuscript-assets/v1',
    manuscript_contract_sha256: contract.manuscript_contract_sha256,
    publication_evidence_root_sha256: evidenceManifest.publication_evidence_root_sha256,
    table_registry_sha256: tables.table_registry_sha256,
    claim_map_sha256: claims.claim_map_sha256,
    independent_verification_sha256: independent.independent_verification_sha256,
    assets: Object.entries(assets).map(([name, bytes]) => ({
      path: `paper/generated/${name}`,
      file_sha256: sha256(bytes),
    })),
    asset_count: Object.keys(assets).length,
    deterministic: true,
    benchmark_run: false,
    database_access: false,
    network_access: false,
    provider_call: false,
  };
  const manifest = {
    ...manifestUnsigned,
    manuscript_assets_sha256: sha256(Buffer.from(canonicalJson(manifestUnsigned), 'utf8')),
  };
  assets['manifest.json'] = jsonBytes(manifest);
  return { assets, manifest };
}

export function renderMutMemV2ManuscriptAssets({ check = false } = {}) {
  const { assets, manifest } = buildAssets();
  if (!check) mkdirSync(GENERATED, { recursive: true });
  for (const [name, bytes] of Object.entries(assets)) {
    const relative = `paper/generated/${name}`;
    if (check) {
      assert(regularBytes(relative).equals(bytes), `v2c4_asset_regeneration_drift:${name}`);
    } else {
      writeFileSync(path.join(GENERATED, name), bytes, { mode: 0o644 });
    }
  }
  return {
    schema: 'hom.aimos.mutmem-v2-manuscript-render-result/v1',
    success: true,
    check,
    asset_count: Object.keys(assets).length,
    manuscript_assets_sha256: manifest.manuscript_assets_sha256,
    benchmark_run: false,
    database_access: false,
    network_access: false,
    provider_call: false,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(renderMutMemV2ManuscriptAssets({
    check: process.argv.includes('--check'),
  }), null, 2)}\n`);
}
