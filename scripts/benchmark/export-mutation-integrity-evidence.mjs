#!/usr/bin/env node

// Verify and sanitize the retained mutation-integrity live-fire pack. The
// public output contains only aggregate cases, measurements, and commitments.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/agent-identity.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_RUN_ID = '20260723162050_59a52d';

function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function selfHash(value, field, canonical = false) {
  const body = { ...value };
  delete body[field];
  return sha256(canonical ? canonicalJson(body) : JSON.stringify(body));
}

function main() {
  const runId = cliValue('--run-id') || DEFAULT_RUN_ID;
  if (!/^20[0-9]{12}_[0-9a-f]{6}$/.test(runId)) throw new Error('mutation_export_run_id_invalid');
  const runDir = path.join(ROOT, 'eval', 'public-results', runId, 'mutation-integrity');
  const status = readJson(path.join(runDir, 'run-status.json'));
  if (status.schema !== 'hom.aimos.mutation-integrity-run-status/v1'
      || status.run_id !== runId
      || status.state !== 'complete'
      || status.phase !== 'complete'
      || status.error !== null
      || status.scratch_retained_for_signed_purge !== true) {
    throw new Error('mutation_export_run_incomplete');
  }
  const evidenceFile = path.join(runDir, 'mutation-integrity-evidence.json');
  const evidence = readJson(evidenceFile);
  if (evidence.schema !== 'hom.aimos.mutation-integrity-live-suite/v1'
      || evidence.completed_transition_measurements !== 20
      || evidence.authorization_cases?.discontinuity_rejected !== true
      || evidence.authorization_cases?.out_of_bounds_rejected !== true
      || !/^[0-9a-f]{64}$/.test(evidence.signed_post_mutation_recall?.merkle_root || '')
      || !/^[0-9a-f]{64}$/.test(evidence.signed_post_mutation_recall?.event_mutation_hash || '')
      || evidence.summary_sha256 !== selfHash(evidence, 'summary_sha256', true)) {
    throw new Error('mutation_export_evidence_invalid');
  }
  const manifestFile = path.join(runDir, 'artifact-hashes.json');
  const manifestBytes = fs.readFileSync(manifestFile);
  const manifest = JSON.parse(manifestBytes);
  if (manifest.schema !== 'hom.aimos.mutation-integrity-artifact-manifest/v1'
      || !Array.isArray(manifest.files)
      || manifest.files.length === 0) {
    throw new Error('mutation_export_manifest_invalid');
  }
  for (const entry of manifest.files) {
    const file = path.resolve(runDir, entry.path);
    if (!file.startsWith(`${runDir}${path.sep}`)
        || !fs.statSync(file).isFile()
        || fs.statSync(file).size !== entry.bytes
        || sha256(fs.readFileSync(file)) !== entry.sha256) {
      throw new Error(`mutation_export_artifact_invalid:${entry.path}`);
    }
  }
  const publicBody = {
    schema: 'hom.aimos.mutation-integrity-public-evidence/v1',
    protocol: 'mutmem-native-mutation-integrity-v1',
    run_id: runId,
    data_policy: 'Aggregate case outcomes, measurements, and cryptographic commitments only; no memory identifiers, certificates, credentials, absolute paths, or retained content.',
    execution: {
      isolated_fresh_genesis_brain: true,
      canonical_brain_untouched: true,
      scratch_brain_retained_pending_signed_whole_brain_purge: true,
      intended_transition_measurements: evidence.intended_transition_measurements,
      completed_transition_measurements: evidence.completed_transition_measurements,
    },
    authorization_cases: evidence.authorization_cases,
    trajectory_cases: evidence.trajectory_cases,
    tamper_cases: evidence.tamper_cases,
    verifier: evidence.verifier,
    signed_post_mutation_recall: evidence.signed_post_mutation_recall,
    latency_ms: evidence.latency_ms,
    logical_row_storage_bytes: evidence.logical_row_storage_bytes,
    allocated_relation_delta_bytes: evidence.allocated_relation_delta_bytes,
    evidence: {
      private_summary_sha256: evidence.summary_sha256,
      private_evidence_file_sha256: sha256(fs.readFileSync(evidenceFile)),
      artifact_count: manifest.files.length,
      artifact_manifest_file_sha256: sha256(manifestBytes),
      artifact_manifest_declared_sha256: manifest.manifest_sha256,
    },
  };
  const result = {
    ...publicBody,
    mutation_integrity_evidence_sha256: selfHash(publicBody, 'mutation_integrity_evidence_sha256'),
  };
  const output = path.join(ROOT, 'eval', 'publication', 'mutation-integrity-verification.json');
  fs.writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    success: true,
    output_file: path.relative(ROOT, output),
    mutation_integrity_evidence_sha256: result.mutation_integrity_evidence_sha256,
  }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  console.error(error?.stack || error);
  process.exitCode = 1;
}
