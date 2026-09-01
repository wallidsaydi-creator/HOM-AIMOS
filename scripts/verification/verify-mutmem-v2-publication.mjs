#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { selfHash as canonicalSelfHash } from '../../eval/poisonedrag/harness.mjs';
import { verifyBenchmarkRunDirectoryTerminal } from '../benchmark/run-isolated.mjs';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { auditMutMemP2CleanTree } from './audit-mutmem-p2-clean-tree.mjs';
import { verifyP3InstallerQualification } from './verify-p3-clean-installer-qualification.mjs';
import { verifyMutMemV2PublicationEvidence } from './verify-mutmem-v2-publication-evidence.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SHA256 = /^[0-9a-f]{64}$/;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function readRegular(relative) {
  const file = path.join(ROOT, relative);
  assert(existsSync(file) && !lstatSync(file).isSymbolicLink() && statSync(file).isFile(),
    `public_verifier_file_invalid:${relative}`);
  return readFileSync(file);
}

function readJson(relative) {
  return JSON.parse(readRegular(relative).toString('utf8'));
}

function canonicalContainer(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  assert(SHA256.test(String(value[field] || '')));
  assert.equal(value[field], sha256(Buffer.from(canonicalJson(unsigned), 'utf8')),
    `public_verifier_canonical_hash_invalid:${field}`);
}

function jsonContainer(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  assert(SHA256.test(String(value[field] || '')));
  assert.equal(value[field], sha256(JSON.stringify(unsigned)),
    `public_verifier_json_hash_invalid:${field}`);
}

function verifyHashPointer(relative, expected) {
  const pointer = readRegular(`${relative}.sha256`).toString('utf8').trim().split(/\s+/)[0];
  assert.equal(pointer, expected, `public_verifier_hash_pointer_invalid:${relative}`);
  assert.equal(sha256(readRegular(relative)), expected,
    `public_verifier_file_hash_invalid:${relative}`);
}

function verifyP1Protocol() {
  const relative = 'verifiers/mutmem-conformance/v2/protocol-manifest.json';
  const manifest = readJson(relative);
  canonicalContainer(manifest, 'protocol_root_sha256');
  verifyHashPointer(relative, sha256(readRegular(relative)));
  assert.equal(manifest.schema, 'hom.aimos.mutmem-portable-protocol-manifest/v2');
  assert.equal(manifest.status, 'p1_protocol_versioned');
  assert.equal(Object.keys(manifest.schemas).length, 18);
  assert.equal(new Set(Object.values(manifest.schemas)).size, 18);
  assert.equal(manifest.failure_codes.length, 37);
  assert.equal(new Set(manifest.failure_codes).size, 37);
  assert.equal(manifest.vectors.intended_n, 39);
  assert.equal(manifest.vectors.valid_n + manifest.vectors.invalid_n, 39);
  assert.equal(manifest.mutation_profile.vectors.intended_n, 15);
  assert.equal(
    manifest.mutation_profile.vectors.valid_n + manifest.mutation_profile.vectors.invalid_n,
    15,
  );
  for (const entry of manifest.source_files) {
    assert.equal(sha256(readRegular(entry.path)), entry.sha256,
      `public_verifier_protocol_source_mismatch:${entry.path}`);
  }
  assert.equal(
    sha256(Buffer.from(canonicalJson(manifest.source_files), 'utf8')),
    manifest.source_root_sha256,
  );
  return {
    protocol_root_sha256: manifest.protocol_root_sha256,
    structural_vectors: manifest.vectors.intended_n,
    mutation_vectors: manifest.mutation_profile.vectors.intended_n,
    failure_codes: manifest.failure_codes.length,
  };
}

function verifyPublicationEvidence() {
  const publication = readJson('eval/publication/verified-benchmark-results.json');
  assert.equal(publication.schema, 'hom.aimos.publication-evidence/v2');
  assert.equal(
    publication.publication_evidence_sha256,
    canonicalSelfHash(publication, 'publication_evidence_sha256'),
  );
  const mutation = readJson('eval/publication/mutation-integrity-verification.json');
  jsonContainer(mutation, 'mutation_integrity_evidence_sha256');
  const epistemic = readJson('eval/publication/poisonedrag-epistemic-verification.json');
  jsonContainer(epistemic, 'epistemic_verification_sha256');
  const agreement = readJson('eval/publication/poisonedrag-human-agreement.json');
  assert.equal(agreement.summary_sha256, canonicalSelfHash(agreement, 'summary_sha256'));
  const ablation = readJson('eval/publication/poisonedrag-epistemic-ablation.json');
  assert.equal(ablation.ablation_evidence_sha256,
    canonicalSelfHash(ablation, 'ablation_evidence_sha256'));
  assert.equal(ablation.intended_n, ablation.completed_n);
  assert.equal(ablation.denominator_complete, true);
  assert.equal(publication.runs.canonical_utility.longmemeval.llm_judged_qa.total, 500);
  assert.equal(publication.runs.canonical_utility.locomo_llm_judged.llm_judged_qa.total, 1986);
  assert.equal(publication.runs.poisonedrag_n100.result.primary_official_substring_metric.attacked_asr.total, 100);
  return {
    publication_evidence_sha256: publication.publication_evidence_sha256,
    longmemeval_n: 500,
    locomo_n: 1986,
    poisonedrag_n: 100,
    ablation_n: ablation.completed_n,
  };
}

function verifyContracts() {
  const contract = readJson('reproducibility/mutmem-v2-contract.json');
  canonicalContainer(contract, 'reproducibility_contract_sha256');
  const environment = readJson('reproducibility/mutmem-v2-environment-contract.json');
  canonicalContainer(environment, 'environment_contract_sha256');
  const packageJson = readJson('package.json');
  assert.equal(packageJson.scripts.verify,
    'node scripts/verification/verify-mutmem-v2-publication.mjs');
  assert.equal(packageJson.scripts.reproduce,
    'node scripts/benchmark/run-isolated.mjs --public-reproduce');
  assert.equal(packageJson.scripts['reproduce:ablation'],
    'node scripts/benchmark/run-poisonedrag-epistemic-ablation.mjs');
  assert.equal(contract.entrypoints.verify.database_access, false);
  assert.equal(contract.entrypoints.verify.network_access, false);
  assert.equal(contract.entrypoints.reproduce.second_server_owner, false);
  assert.equal(contract.entrypoints.reproduce.second_database_authority, false);
  assert.equal(contract.entrypoints.reproduce.second_identity_authority, false);
  return {
    reproducibility_contract_sha256: contract.reproducibility_contract_sha256,
    environment_contract_sha256: environment.environment_contract_sha256,
  };
}

function verifyDatasetAuthority() {
  const canonical = readJson('eval/data/canonical/corpus-manifest.json');
  assert.equal(canonical.schema, 'hom.canonical-benchmark-corpus-manifest/v1');
  for (const output of canonical.outputs) {
    assert(SHA256.test(output.sha256));
    const relative = `eval/data/canonical/${output.file}`;
    if (existsSync(path.join(ROOT, relative))) {
      assert.equal(sha256(readRegular(relative)), output.sha256,
        `public_verifier_dataset_output_mismatch:${output.file}`);
    }
  }
  const poisonSource = readJson('eval/poisonedrag/source-lock.json');
  const poisonTargets = readJson('eval/poisonedrag/n100-public-target-lock.json');
  assert.equal(poisonSource.schema, 'hom.aimos.poisonedrag-source-lock/v1');
  assert.equal(poisonTargets.schema, 'hom.aimos.poisonedrag-public-target-lock/v1');
  assert.equal(poisonTargets.target_count, 100);
  assert.equal(poisonTargets.targets.length, 100);
  assert.equal(poisonTargets.redistributed_source_text, false);
  return {
    canonical_manifest_sha256: sha256(readRegular('eval/data/canonical/corpus-manifest.json')),
    poisonedrag_source_lock_sha256: sha256(readRegular('eval/poisonedrag/source-lock.json')),
    poisonedrag_target_lock_sha256: sha256(readRegular('eval/poisonedrag/n100-public-target-lock.json')),
  };
}

const p1 = verifyP1Protocol();
const p2 = auditMutMemP2CleanTree();
assert.equal(p2.passed, true);
const installerReceipt = readJson('verifiers/mutmem-conformance/v2/p3-clean-installer-qualification.json');
const installer = verifyP3InstallerQualification(installerReceipt);
const publication = verifyPublicationEvidence();
const contracts = verifyContracts();
const datasets = verifyDatasetAuthority();
const v2c3 = verifyMutMemV2PublicationEvidence({ p2Audit: p2 });
const runDirectoryArgument = process.argv.find((value) => value.startsWith('--run-dir='));
const run = runDirectoryArgument
  ? verifyBenchmarkRunDirectoryTerminal(path.resolve(runDirectoryArgument.slice(10)))
  : null;

const result = {
  schema: 'hom.aimos.mutmem-v2-public-verification/v1',
  success: true,
  p1,
  p2,
  installer,
  publication,
  contracts,
  datasets,
  v2c3,
  run,
  database_access: false,
  keychain_access: false,
  private_key_access: false,
  provider_call: false,
  network_access: false,
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
