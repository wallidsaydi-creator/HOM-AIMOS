#!/usr/bin/env node

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
import {
  MUTMEM_PORTABLE_EVIDENCE_V2,
  MUTMEM_RECALL_RESULT_KINDS_V2,
  MUTMEM_RECALL_SINGLETON_KINDS_V2,
} from '../../services/security/protocol/mutmem-portable-evidence-v2.js';
import {
  MUTMEM_PORTABLE_MUTATION_V2,
} from '../../services/security/protocol/mutmem-portable-mutation-v2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SHA256 = /^[0-9a-f]{64}$/;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function regularBytes(relative) {
  const file = path.join(ROOT, relative);
  assert(existsSync(file) && !lstatSync(file).isSymbolicLink() && statSync(file).isFile(),
    `v2c4_manuscript_file_invalid:${relative}`);
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

function run(command, args, code) {
  const child = spawnSync(command, args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    timeout: 120_000,
  });
  assert.equal(child.status, 0, `${code}:${child.stderr}:${child.stdout}`);
  return child.stdout;
}

function extractAll(source, pattern) {
  return [...source.matchAll(pattern)].map((match) => match[1]);
}

function sameSet(left, right, code) {
  assert.deepEqual([...new Set(left)].sort(), [...new Set(right)].sort(), code);
}

function verifyGeneratedAssets(manifest) {
  verifySelfHash(manifest, 'manuscript_assets_sha256', 'v2c4_asset_manifest_hash_invalid');
  assert.equal(manifest.asset_count, manifest.assets.length);
  for (const asset of manifest.assets) {
    assert(!path.isAbsolute(asset.path) && SHA256.test(asset.file_sha256));
    assert.equal(sha256(regularBytes(asset.path)), asset.file_sha256,
      `v2c4_asset_hash_mismatch:${asset.path}`);
  }
  const rendered = JSON.parse(run(process.execPath, [
    path.join(ROOT, 'scripts/publication/render-mutmem-v2-manuscript-assets.mjs'),
    '--check',
  ], 'v2c4_asset_regeneration_failed'));
  assert.equal(rendered.success, true);
  assert.equal(rendered.check, true);
  assert.equal(rendered.manuscript_assets_sha256, manifest.manuscript_assets_sha256);
  return rendered;
}

function verifyClaims(tex, claimTable, claims) {
  verifySelfHash(claims, 'claim_map_sha256', 'v2c4_claim_map_hash_invalid');
  const declared = claims.rows.map((row) => row.claim_id);
  const cited = extractAll(tex, /\\evidence\{([^}]+)\}/g);
  sameSet(cited, declared, 'v2c4_body_claim_coverage_invalid');
  assert.equal(cited.length, new Set(cited).size, 'v2c4_duplicate_body_claim_reference');
  for (const row of claims.rows) {
    const renderedId = row.claim_id.replaceAll('-', '-\\allowbreak{}');
    assert(claimTable.includes(renderedId), `v2c4_claim_table_row_missing:${row.claim_id}`);
    if (row.disposition === 'OMITTED' || row.disposition === 'PROHIBITED') {
      assert.equal(row.table_cell_ids.length, 0, `v2c4_forbidden_claim_has_numeric_cell:${row.claim_id}`);
    } else {
      assert(row.table_cell_ids.length > 0, `v2c4_supported_claim_has_no_cell:${row.claim_id}`);
    }
  }
  return {
    claim_count: declared.length,
    historical_v1: claims.rows.filter((row) => row.disposition === 'HISTORICAL_V1').length,
    current_v2: claims.rows.filter((row) => row.disposition === 'CURRENT_V2').length,
    omitted: claims.rows.filter((row) => row.disposition === 'OMITTED').length,
    prohibited: claims.rows.filter((row) => row.disposition === 'PROHIBITED').length,
  };
}

function verifyCitations(tex) {
  const citationGroups = extractAll(tex, /\\cite\{([^}]+)\}/g);
  const cited = citationGroups.flatMap((group) => group.split(',').map((value) => value.trim()));
  const bibliography = extractAll(tex, /\\bibitem\{([^}]+)\}/g);
  sameSet(cited, bibliography, 'v2c4_citation_bibliography_mismatch');
  return bibliography.length;
}

function verifyEquations(tex, metric) {
  const equationLabels = extractAll(tex, /\\label\{(eq:[^}]+)\}/g);
  assert.equal(new Set(equationLabels).size, equationLabels.length, 'v2c4_equation_label_duplicate');
  const equationRefs = extractAll(tex, /(?:eqref|ref)\{(eq:[^}]+)\}/g);
  assert(equationRefs.every((label) => equationLabels.includes(label)),
    'v2c4_equation_reference_unresolved');
  assert.equal(MUTMEM_RECALL_SINGLETON_KINDS_V2.length, 13);
  assert.equal(MUTMEM_RECALL_RESULT_KINDS_V2.length, 5);
  assert.equal(MUTMEM_PORTABLE_EVIDENCE_V2.maximum_results, 200);
  assert.equal(MUTMEM_PORTABLE_MUTATION_V2.terminal_kinds.length, 3);
  assert.equal(metric.estimators.wilson_95.z, 1.959963984540054);
  assert.equal(metric.numerical_tolerances.derived_binary_rates_wilson_mcnemar_holm_kappa, 1e-12);
  assert.equal(metric.numerical_tolerances.canary_rounded_wilson_bounds, 5e-9);
  for (const required of [
    'N_{\\mathrm{objects}}(r)=13+5r',
    '0\\le r\\le 200',
    'p_{\\mathrm{McN}}',
    '\\widetilde p_{(i)}',
    'n_{\\mathrm{intended}}=n_{\\mathrm{selected}}=n_{\\mathrm{completed}}',
    'O(n\\log n)$ implementation time',
  ]) assert(tex.includes(required), `v2c4_math_contract_missing:${required}`);
  return equationLabels.length;
}

function verifyManuscriptBoundary(tex, pdfText, contract, claims) {
  const combined = `${tex}\n${pdfText}`;
  const normalizedTex = tex.replace(/\s+/g, ' ');
  const prohibited = [
    /\/Users\//,
    /\/home\//,
    /file:\/\//i,
    /\b(?:TODO|TBD|PLACEHOLDER)\b/i,
    /\bV2C-[0-9]/,
    /\bplans\//,
    /27\s*\/\s*27/,
    /0\s*\/\s*28/,
    /55\s*\/\s*55/,
  ];
  for (const pattern of prohibited) {
    assert(!pattern.test(combined), `v2c4_manuscript_boundary_violation:${pattern}`);
  }
  assert(normalizedTex.includes('MutMem denotes the portable protocol;')
    && normalizedTex.includes('HOM-AIMOS is one producer and case study.'));
  assert(normalizedTex.includes('Historical V1 empirical results remain historical'));
  assert(normalizedTex.includes('does not establish semantic truth, universal robustness, or independent replication'));
  assert(normalizedTex.includes('SABER-inspired operational figures are omitted'));
  assert(normalizedTex.includes('adaptation') && !normalizedTex.includes('strict upstream reproduction'));
  assert(normalizedTex.includes('not publication-authorized'));
  assert.equal(contract.release_binding.publication_allowed, false);
  for (const field of ['immutable_tag', 'release_commit', 'source_manifest_sha256', 'archival_doi']) {
    assert.equal(contract.release_binding[field], null, `v2c4_release_field_premature:${field}`);
  }
  assert(claims.rows.find((row) => row.claim_id === 'SABER-OPERATIONAL-NUMBERS')
    ?.disposition === 'OMITTED');
  assert(claims.rows.filter((row) => row.disposition === 'PROHIBITED').length === 3);
  return true;
}

function verifyFirstPage(tex, contract) {
  const requirements = [
    '\\MutMemRepositoryURL',
    '\\MutMemVOneArxiv',
    'MutMem: Cryptographically Authorized Mutation in',
    '\\MutMemEvidenceSourceCommit',
    '\\MutMemPublicationEvidenceRoot',
    'npm run verify',
    'npm run evidence:regenerate',
    'npm run reproduce',
    'AGPL-3.0-or-later',
    'Dataset text is not redistributed',
    'Provider access is operator-authenticated',
    'Highest support level',
    'immutable tag, release commit,',
    'source-manifest hash, and archival DOI',
  ];
  for (const value of requirements) {
    assert(tex.includes(value), `v2c4_first_page_requirement_missing:${value}`);
  }
  return requirements.length;
}

function verifyPdf(tex, contract) {
  const relative = 'paper/mutmem-v2.pdf';
  const bytes = regularBytes(relative);
  assert(bytes.subarray(0, 5).toString('ascii') === '%PDF-', 'v2c4_pdf_header_invalid');
  const info = run('/usr/local/bin/pdfinfo', [path.join(ROOT, relative)], 'v2c4_pdfinfo_failed');
  assert(/Pages:\s+\d+/.test(info) && /Encrypted:\s+no/.test(info)
    && /JavaScript:\s+no/.test(info), 'v2c4_pdf_metadata_invalid');
  const pages = Number(info.match(/Pages:\s+(\d+)/)?.[1]);
  assert(Number.isInteger(pages) && pages > 0, 'v2c4_pdf_page_count_invalid');
  const text = run('/usr/local/bin/pdftotext', [path.join(ROOT, relative), '-'],
    'v2c4_pdftotext_failed');
  const normalizedText = text.normalize('NFKC').replace(/\s+/gu, ' ').trim();
  const normalizedTitle = contract.title.normalize('NFKC').replace(/\s+/gu, ' ').trim();
  const normalizedSubtitle = contract.subtitle.normalize('NFKC').replace(/\s+/gu, ' ').trim();
  assert(normalizedText.includes(normalizedTitle), 'v2c4_pdf_title_missing');
  assert(normalizedText.includes(normalizedSubtitle), 'v2c4_pdf_subtitle_missing');
  const log = regularBytes('paper/mutmem-v2.log').toString('utf8');
  assert(!/undefined references|undefined citation|LaTeX Error|Emergency stop/i.test(log),
    'v2c4_tex_log_invalid');
  assert(!/Overfull \\hbox/.test(log), 'v2c4_pdf_overfull_box');
  return { bytes, text, pages, info };
}

export function verifyMutMemV2Manuscript({ verifyRetainedAudit = true } = {}) {
  const contract = readJson('paper/mutmem-v2-manuscript-contract.json');
  const packageJson = readJson('package.json');
  const evidenceManifest = readJson('eval/publication/v2c3/publication-evidence-manifest.json');
  const independent = readJson('eval/publication/v2c3/independent-verification.json');
  const claims = readJson('eval/publication/v2c3/claim-to-evidence-map.json');
  const metric = readJson('eval/publication/v2c3/metric-contract.json');
  const assets = readJson('paper/generated/manifest.json');
  verifySelfHash(contract, 'manuscript_contract_sha256', 'v2c4_contract_hash_invalid');
  verifySelfHash(evidenceManifest, 'publication_evidence_root_sha256', 'v2c4_evidence_hash_invalid');
  verifySelfHash(independent, 'independent_verification_sha256', 'v2c4_independent_hash_invalid');
  verifySelfHash(metric, 'metric_contract_sha256', 'v2c4_metric_hash_invalid');
  assert.equal(packageJson.scripts['paper:render'],
    'node scripts/publication/render-mutmem-v2-manuscript-assets.mjs');
  assert.equal(packageJson.scripts['paper:build'],
    'cd paper && SOURCE_DATE_EPOCH=1788258481 FORCE_SOURCE_DATE=1 tectonic --only-cached --keep-logs --keep-intermediates mutmem-v2.tex');
  assert.equal(packageJson.scripts['paper:verify'],
    'node scripts/verification/verify-mutmem-v2-manuscript.mjs');
  assert.equal(run('tectonic', ['--version'], 'v2c4_tectonic_version_failed').trim(),
    `Tectonic ${contract.deterministic_pdf_build.engine_version}`);
  assert.equal(contract.publication_evidence_root_sha256,
    evidenceManifest.publication_evidence_root_sha256);
  assert.equal(independent.publication_evidence_root_sha256,
    evidenceManifest.publication_evidence_root_sha256);
  assert.equal(assets.publication_evidence_root_sha256,
    evidenceManifest.publication_evidence_root_sha256);
  const rendered = verifyGeneratedAssets(assets);
  const texBytes = regularBytes('paper/mutmem-v2.tex');
  const tex = texBytes.toString('utf8');
  const claimTable = regularBytes('paper/generated/claim-map-table.tex').toString('utf8');
  const pdf = verifyPdf(tex, contract);
  const claimAudit = verifyClaims(tex, claimTable, claims);
  const citationCount = verifyCitations(tex);
  const equationCount = verifyEquations(tex, metric);
  const firstPageChecks = verifyFirstPage(tex, contract);
  verifyManuscriptBoundary(tex, pdf.text, contract, claims);

  const unsigned = {
    schema: 'hom.aimos.mutmem-v2-manuscript-audit/v1',
    success: true,
    manuscript_evidence_complete: true,
    publication_release_bound: false,
    publication_evidence_root_sha256: evidenceManifest.publication_evidence_root_sha256,
    manuscript_contract_sha256: contract.manuscript_contract_sha256,
    manuscript_assets_sha256: assets.manuscript_assets_sha256,
    claim_map_sha256: claims.claim_map_sha256,
    independent_verification_sha256: independent.independent_verification_sha256,
    tex_sha256: sha256(texBytes),
    pdf_sha256: sha256(pdf.bytes),
    pdf_text_sha256: sha256(Buffer.from(pdf.text, 'utf8')),
    pdf_pages: pdf.pages,
    deterministic_build: contract.deterministic_pdf_build,
    claims: claimAudit,
    citations: citationCount,
    equations: equationCount,
    first_page_checks: firstPageChecks,
    generated_assets_byte_identical: rendered.check,
    historical_v1_visibly_separated: true,
    current_v2_claims_evidence_bound: true,
    content_truth_claimed: false,
    universal_robustness_claimed: false,
    independent_replication_claimed: false,
    saber_numerical_claims_published: false,
    internal_plan_or_private_path_published: false,
    unresolved_material_findings: 0,
    benchmark_run: false,
    database_access: false,
    live_memory_access: false,
    provider_call: false,
    next_required_gate: 'FINAL_PUBLIC_RELEASE_BINDING',
  };
  const result = {
    ...unsigned,
    manuscript_audit_sha256: sha256(Buffer.from(canonicalJson(unsigned), 'utf8')),
  };
  if (verifyRetainedAudit && existsSync(path.join(ROOT, 'paper/mutmem-v2-audit.json'))) {
    const retained = readJson('paper/mutmem-v2-audit.json');
    verifySelfHash(retained, 'manuscript_audit_sha256', 'v2c4_retained_audit_hash_invalid');
    assert.deepEqual(retained, result, 'v2c4_retained_audit_drift');
  }
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const writing = process.argv.includes('--write');
  const result = verifyMutMemV2Manuscript({ verifyRetainedAudit: !writing });
  if (writing) {
    writeFileSync(path.join(ROOT, 'paper', 'mutmem-v2-audit.json'),
      `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
