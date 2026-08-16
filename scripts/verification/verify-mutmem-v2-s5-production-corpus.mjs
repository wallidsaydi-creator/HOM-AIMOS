#!/usr/bin/env node

// Verify the V2-S5 corpus with both the production protocol owners and the
// independent Python implementation. This runner has no signing, database,
// Keychain, route, server, model, policy, mutation, save, recall, or deletion
// authority.

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  productionVerdict,
  verifyS5CorpusStructure,
} from './mutmem-v2-s5-corpus-factory.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DEFAULT_CORPUS = path.join(ROOT, 'verifiers/mutmem-conformance/v1');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function argument(name, fallback = null) {
  const prefix = `--${name}=`;
  const value = process.argv.find((entry) => entry.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

function independentOperation(kind) {
  if (kind === 'recall') return 'verify-recall';
  if (kind === 'recall_corpus') return 'verify-corpus';
  return 'verify-bundle';
}

function independentVerdict(operation, file) {
  const processResult = spawnSync(
    'python3',
    [path.join(ROOT, 'verifiers/mutmem-python/verify.py'), operation, file],
    { cwd: ROOT, encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024 },
  );
  let output;
  try {
    output = JSON.parse(String(processResult.stdout || ''));
  } catch {
    throw new Error(`mutmem_v2_s5_independent_output_invalid:${path.basename(file)}`);
  }
  if (![0, 1, 2].includes(processResult.status)) {
    throw new Error(`mutmem_v2_s5_independent_process_failed:${path.basename(file)}`);
  }
  return output;
}

async function main() {
  const corpusDir = path.resolve(argument('corpus', DEFAULT_CORPUS));
  const replaceReportSha256 = argument('replace-report-sha256');
  const readOnly = process.argv.includes('--read-only');
  const manifestFile = path.join(corpusDir, 'manifest.json');
  const manifestRaw = await readFile(manifestFile, 'utf8');
  const manifest = JSON.parse(manifestRaw);
  const hydrated = {
    ...manifest,
    members: await Promise.all(manifest.members.map(async (member) => {
      const raw = await readFile(path.join(corpusDir, member.filename), 'utf8');
      return { ...member, raw, document: JSON.parse(raw) };
    })),
  };
  const structure = verifyS5CorpusStructure(hydrated);
  const results = [];
  for (const member of hydrated.members) {
    const production = productionVerdict({
      bundle_kind: member.bundle_kind,
      document: member.document,
    });
    const independent = independentVerdict(
      independentOperation(member.bundle_kind),
      path.join(corpusDir, member.filename),
    );
    const independentReason = member.independent_expected_primary_reason
      ?? member.expected_primary_reason;
    const expected = production.verdict === member.expected_verdict
      && production.primary_reason === member.expected_primary_reason
      && independent.verdict === member.expected_verdict
      && independent.primary_reason === independentReason;
    if (!expected) throw new Error(`mutmem_v2_s5_parity_mismatch:${member.vector_id}`);
    results.push({
      vector_id: member.vector_id,
      class_id: member.class_id,
      expected_verdict: member.expected_verdict,
      expected_primary_reason: member.expected_primary_reason,
      independent_expected_primary_reason: independentReason,
      production: {
        verdict: production.verdict,
        primary_reason: production.primary_reason,
        proof_root: production.proof_root,
        bundle_sha256: production.bundle_sha256,
      },
      independent: {
        verdict: independent.verdict,
        primary_reason: independent.primary_reason,
        proof_root: independent.proof_root ?? independent.merkle_root
          ?? independent.corpus_root ?? null,
        bundle_sha256: independent.bundle_sha256 ?? null,
        verifier_version: independent.verifier_version,
        source_sha256: independent.source_sha256,
      },
      exact_terminal_parity: production.verdict === independent.verdict,
      exact_protocol_reason_parity: production.primary_reason === independentReason,
    });
  }
  const report = {
    schema: 'hom.aimos.mutmem-v2-s5-parity-report/v1',
    authority: 'verification_only',
    corpus_directory: path.relative(ROOT, corpusDir),
    manifest_sha256: sha256(Buffer.from(manifestRaw, 'utf8')),
    corpus_root: manifest.corpus_root,
    intended_n: manifest.intended_n,
    observed_n: results.length,
    required_class_count: manifest.required_class_count,
    production_independent_terminal_parity: results.every((entry) => entry.exact_terminal_parity),
    production_independent_protocol_reason_parity: results.every(
      (entry) => entry.exact_protocol_reason_parity,
    ),
    structure,
    results,
  };
  report.report_root_sha256 = sha256(Buffer.from(canonicalJson(report), 'utf8'));
  const output = path.join(corpusDir, 'verification-report.json');
  const raw = `${JSON.stringify(report, null, 2)}\n`;
  if (readOnly) {
    const retainedRaw = await readFile(output, 'utf8');
    const retained = JSON.parse(retainedRaw);
    if (retained.report_root_sha256 !== report.report_root_sha256
        || retained.manifest_sha256 !== report.manifest_sha256
        || retained.corpus_root !== report.corpus_root
        || retained.intended_n !== report.intended_n
        || retained.observed_n !== report.observed_n) {
      throw new Error('mutmem_v2_s5_retained_report_parity_mismatch');
    }
    process.stdout.write(`${JSON.stringify({
      success: true,
      mode: 'READ_ONLY',
      report: output,
      intended_n: report.intended_n,
      observed_n: report.observed_n,
      required_class_count: report.required_class_count,
      corpus_root: report.corpus_root,
      report_root_sha256: report.report_root_sha256,
    }, null, 2)}\n`);
    return;
  }
  let writeFlag = 'wx';
  if (replaceReportSha256) {
    const currentReport = await readFile(output);
    if (sha256(currentReport) !== replaceReportSha256) {
      throw new Error('mutmem_v2_s5_existing_report_hash_mismatch');
    }
    writeFlag = 'w';
  }
  await writeFile(output, raw, { flag: writeFlag, mode: 0o644 });
  await writeFile(
    `${output}.sha256`,
    `${sha256(Buffer.from(raw, 'utf8'))}  verification-report.json\n`,
    { flag: writeFlag, mode: 0o644 },
  );
  process.stdout.write(`${JSON.stringify({
    success: true,
    report: output,
    intended_n: report.intended_n,
    observed_n: report.observed_n,
    required_class_count: report.required_class_count,
    corpus_root: report.corpus_root,
    report_root_sha256: report.report_root_sha256,
  }, null, 2)}\n`);
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || error}`);
  process.exitCode = 1;
});
