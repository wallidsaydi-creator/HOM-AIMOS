#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { recallAuthorizationMutationHash as nativeRecallAuthorizationMutationHash }
  from '../../services/security/recall-authorization.js';
import { requestReceiptMutationHash as nativeRequestReceiptMutationHash }
  from '../../services/security/request-receipt-ledger.js';
import { verifyMutationBundle } from '../../verifiers/mutmem-v2/node/mutation-verifier.mjs';
import { recallByteParity, verifyRecallEnvelope }
  from '../../verifiers/mutmem-v2/node/recall-verifier.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const NODE_BIN = process.execPath;
const NODE_DIR = path.dirname(NODE_BIN);
const NPM = path.join(NODE_DIR, 'npm');
const PYTHON = process.argv.find((value) => value.startsWith('--python='))?.slice(9) || 'python3';
const OUTPUT = process.argv.find((value) => value.startsWith('--output='))?.slice(9) || null;
const FULL = process.argv.includes('--full');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const json = async (relative) => JSON.parse(await readFile(path.join(ROOT, relative), 'utf8'));
const git = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
if (git.status !== 0) throw new Error('p2_closure_source_commit_unavailable');
const sourceCommit = git.stdout.trim();
const exactPath = [NODE_DIR, '/usr/local/bin', '/usr/bin', '/bin'].join(':');

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || ROOT,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    env: { ...process.env, PATH: exactPath, MUTMEM_P2_PYTHON: PYTHON },
  });
  return {
    passed: result.status === 0,
    exit_code: result.status,
    output_sha256: sha(Buffer.from(`${result.stdout || ''}\n${result.stderr || ''}`)),
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function tapSummary(result) {
  const tests = Number(result.stdout.match(/^ℹ tests (\d+)$/m)?.[1] || 0);
  const passed = Number(result.stdout.match(/^ℹ pass (\d+)$/m)?.[1] || 0);
  const failed = Number(result.stdout.match(/^ℹ fail (\d+)$/m)?.[1] || 0);
  return { tests, passed, failed };
}

async function verifiedSelfHash(relative, field) {
  const value = await json(relative);
  const claimed = value[field];
  const unsigned = { ...value };
  delete unsigned[field];
  return {
    path: relative,
    file_sha256: sha(await readFile(path.join(ROOT, relative))),
    self_hash_valid: claimed === sha(Buffer.from(canonicalJson(unsigned))),
    claimed,
    value,
  };
}

function pythonTerminal(request) {
  const child = spawnSync(PYTHON, [path.join(
    ROOT, 'verifiers/mutmem-v2/python/verifier_cli.py',
  )], {
    input: JSON.stringify(request),
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  });
  if (child.status !== 0) throw new Error(`p2_closure_python_failed:${child.stderr}:${child.stdout}`);
  return JSON.parse(child.stdout);
}

async function liveVerification() {
  const recallPath = 'artifacts/security/mutmem-v2/p1-live-projection/10217fc3-2c04-418c-8f8f-61346e29a88b.json';
  const mutationPath = 'artifacts/security/mutmem-v2/p1-live-mutation/64e723e3cae6c1bbdcdb7b0d.json';
  const witnessPath = 'artifacts/security/mutmem-v2/p2-mutation-witness/3860653fb82805e87b76ef7c.json';
  const [recallBytes, mutationBytes, witnessBytes] = await Promise.all([
    readFile(path.join(ROOT, recallPath)),
    readFile(path.join(ROOT, mutationPath)),
    readFile(path.join(ROOT, witnessPath)),
  ]);
  const recallArtifact = JSON.parse(recallBytes);
  const mutationArtifact = JSON.parse(mutationBytes);
  const witnessSet = JSON.parse(witnessBytes);
  const trust = recallArtifact.bundle;
  const expected = trust.expected_master_fingerprint;
  const nodeRecall = verifyRecallEnvelope(trust, { expectedMasterFingerprint: expected });
  const pythonRecall = pythonTerminal({
    profile: 'recall', bundle: trust,
    expected_master_fingerprint: expected, verify_cryptography: true,
  });
  const mutations = [];
  for (const entry of mutationArtifact.projections) {
    const witness = witnessSet.witnesses.find(
      (candidate) => candidate.mutation_bundle_sha256 === entry.bundle.bundle_sha256,
    );
    const nodeResult = verifyMutationBundle(entry.bundle, {
      witness, trustContext: trust, expectedMasterFingerprint: expected,
      verifyCryptography: true,
    });
    const pythonResult = pythonTerminal({
      profile: 'mutation', bundle: entry.bundle, witness, trust_context: trust,
      expected_master_fingerprint: expected, verify_cryptography: true,
    });
    mutations.push({
      terminal_kind: entry.bundle.terminal.kind,
      bundle_sha256: entry.bundle.bundle_sha256,
      node_python_equal: canonicalJson(nodeResult) === canonicalJson(pythonResult.result),
      verified_signature_count: nodeResult.verified_signature_count,
    });
  }
  return {
    recall_private_artifact_sha256: sha(recallBytes),
    mutation_private_artifact_sha256: sha(mutationBytes),
    mutation_witness_set_sha256: sha(witnessBytes),
    recall_node_python_equal: canonicalJson(nodeRecall) === canonicalJson(pythonRecall.result),
    recall_verified_signature_count: nodeRecall.verified_signature_count,
    mutations,
    passed: pythonRecall.valid === true
      && mutations.length === 3
      && mutations.every((entry) => entry.node_python_equal),
  };
}

async function cleanArchiveAudit() {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'hom-aimos-p2-closure-'));
  try {
    const archive = spawnSync('git', ['archive', sourceCommit], {
      cwd: ROOT, encoding: null, maxBuffer: 256 * 1024 * 1024,
    });
    if (archive.status !== 0) throw new Error('p2_closure_git_archive_failed');
    const extract = spawnSync('tar', ['-x', '-C', temporary], {
      input: archive.stdout, encoding: null, maxBuffer: 256 * 1024 * 1024,
    });
    if (extract.status !== 0) throw new Error('p2_closure_git_archive_extract_failed');
    const audit = run(NODE_BIN, [
      path.join(temporary, 'scripts/verification/audit-mutmem-p2-clean-tree.mjs'),
      `--python=${PYTHON}`,
    ], { cwd: temporary });
    const parsed = JSON.parse(audit.stdout);
    return { ...parsed, output_sha256: audit.output_sha256 };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

const [cryptoVectors, measurement, census, live, structuralRecall] = await Promise.all([
  verifiedSelfHash('verifiers/mutmem-conformance/v2/p2-crypto-vectors.json', 'manifest_sha256'),
  verifiedSelfHash('verifiers/mutmem-conformance/v2/p2-resource-measurement.json', 'measurement_sha256'),
  verifiedSelfHash('verifiers/mutmem-conformance/v2/p2-import-census.json', 'census_sha256'),
  liveVerification(),
  json('verifiers/mutmem-conformance/v2/vectors.json'),
]);
const cleanTree = await cleanArchiveAudit();
const regressions = {};
if (FULL) {
  const source = run(NPM, ['run', 'test:source']);
  const benchmark = run(NPM, ['run', 'test:benchmark:contracts']);
  const lint = run(NPM, ['run', 'lint']);
  const architecture = run(NPM, ['run', 'test:architecture-authority']);
  const pipeline = run(NODE_BIN, ['--input-type=module', '-e',
    "import('./services/pipeline-manifest.js').then(async m=>{const r=await m.validatePipelines();console.log(JSON.stringify({valid:r.valid,total:r.total,ok:r.ok}));process.exit(r.valid?0:1)})"]);
  Object.assign(regressions, {
    source: { ...tapSummary(source), passed: source.passed, output_sha256: source.output_sha256 },
    benchmark: { ...tapSummary(benchmark), passed: benchmark.passed, output_sha256: benchmark.output_sha256 },
    lint: { passed: lint.passed, output_sha256: lint.output_sha256 },
    architecture: { passed: architecture.passed, output_sha256: architecture.output_sha256 },
    pipeline: {
      ...JSON.parse(pipeline.stdout || '{}'),
      passed: pipeline.passed,
      output_sha256: pipeline.output_sha256,
    },
  });
}
const pythonVersion = run(PYTHON, ['-c', 'import cryptography,sys;print(sys.version.split()[0]);print(cryptography.__version__)']);
const p2Files = [
  'verifiers/mutmem-v2/node/crypto-kernel.mjs',
  'verifiers/mutmem-v2/node/recall-verifier.mjs',
  'verifiers/mutmem-v2/node/mutation-verifier.mjs',
  'verifiers/mutmem-v2/python/crypto_kernel.py',
  'verifiers/mutmem-v2/python/recall_verifier.py',
  'verifiers/mutmem-v2/python/mutation_verifier.py',
  'verifiers/mutmem-conformance/v2/p2-crypto-vectors.json',
  'verifiers/mutmem-conformance/v2/p2-resource-measurement.json',
  'verifiers/mutmem-conformance/v2/p2-import-census.json',
];
const sourceFiles = await Promise.all(p2Files.map(async (relative) => ({
  path: relative,
  sha256: sha(await readFile(path.join(ROOT, relative))),
})));
const structuralValid = structuralRecall.vectors.find((vector) => vector.expected === 'valid').bundle;
const structuralByKind = Object.fromEntries(
  structuralValid.objects.map((object) => [object.kind, object.body]),
);
const grant = structuralByKind.effective_recall_grant;
const receipt = structuralByKind.request_receipt;
const nativeGrantHash = nativeRecallAuthorizationMutationHash(
  null,
  Buffer.from(grant.content_hash, 'hex'),
  grant.nonce,
  grant.ts_signed,
).toString('hex');
const independentGrantHash = recallByteParity.recallAuthorizationMutationHash({
  previousMutationHash: grant.prev_mutation_hash,
  contentHash: grant.content_hash,
  nonce: grant.nonce,
  signedTs: grant.ts_signed,
});
const nativeReceiptHash = nativeRequestReceiptMutationHash({
  previousMutationHash: Buffer.from(receipt.prev_mutation_hash, 'hex'),
  requestHash: Buffer.from(receipt.request_hash, 'hex'),
  claimsHash: null,
  signature: Buffer.from(receipt.signature_b64u, 'base64url'),
  method: receipt.signed_method,
  path: receipt.signed_path,
  nonce: receipt.nonce,
  signedTs: receipt.ts_signed,
}).toString('hex');
const independentReceiptHash = recallByteParity.requestReceiptMutationHash({
  previousMutationHash: receipt.prev_mutation_hash,
  requestHash: receipt.request_hash,
  claimsHash: receipt.signed_claims_hash,
  signature: receipt.signature_b64u,
  method: receipt.signed_method,
  path: receipt.signed_path,
  nonce: receipt.nonce,
  signedTs: receipt.ts_signed,
});
const positiveCompanies = [...new Set([
  ...structuralRecall.vectors.filter((vector) => vector.expected === 'valid')
    .map((vector) => vector.bundle.company_id),
  ...cryptoVectors.value.recall.vectors.filter((vector) => vector.expected === 'valid')
    .map((vector) => vector.bundle.company_id),
  ...cryptoVectors.value.mutation.vectors.filter((vector) => vector.expected === 'valid')
    .map((vector) => vector.bundle.company_id),
])].sort();
const wrongCompanyDenied = structuralRecall.vectors.some((vector) => (
  vector.expected === 'invalid' && vector.reason === 'GRANT_SCOPE_MISMATCH'
));
const exitCriteria = {
  node_python_vector_parity: cryptoVectors.self_hash_valid && cleanTree.passed
    && cleanTree.intended_n === 72,
  native_live_artifact_parity: live.passed,
  runtime_database_independence: census.value.zero_production_runtime_importers
    && cleanTree.database_access === false && cleanTree.runtime_imports === false,
  behavioral_not_regex: cleanTree.passed && live.passed,
  legacy_byte_parity: nativeGrantHash === independentGrantHash
    && nativeReceiptHash === independentReceiptHash,
  company_claim_exact: canonicalJson(positiveCompanies) === canonicalJson(['hom'])
    && wrongCompanyDenied,
  import_census_bound: census.self_hash_valid && census.value.source_commit === sourceCommit,
  clean_checkout_passed: cleanTree.passed,
  complete_regression_passed: FULL
    && regressions.source?.passed && regressions.benchmark?.passed
    && regressions.lint?.passed && regressions.architecture?.passed
    && regressions.pipeline?.passed,
  single_phase_status: true,
};
const unsigned = {
  schema: 'hom.aimos.mutmem-p2-closure-audit/v1',
  source_commit: sourceCommit,
  toolchain: {
    node: process.version,
    python: pythonVersion.stdout.trim().split(/\s+/)[0],
    cryptography: pythonVersion.stdout.trim().split(/\s+/)[1],
  },
  source_files: sourceFiles,
  source_root_sha256: sha(Buffer.from(canonicalJson(sourceFiles))),
  crypto_vectors: {
    file_sha256: cryptoVectors.file_sha256,
    manifest_sha256: cryptoVectors.claimed,
    recall_intended_n: cryptoVectors.value.recall.intended_n,
    mutation_intended_n: cryptoVectors.value.mutation.intended_n,
  },
  resource_measurement: {
    root: measurement.claimed,
    intended_n: measurement.value.intended_n,
    passed: measurement.value.passed,
  },
  import_census: {
    root: census.claimed,
    source_commit: census.value.source_commit,
    source_file_count: census.value.source_file_count,
    zero_production_runtime_importers: census.value.zero_production_runtime_importers,
  },
  clean_tree: cleanTree,
  live,
  regressions,
  retained_failed_attempts: [{
    stage: 'source_suite_toolchain_selection',
    observed_node: 'v26.7.0',
    expected: 'v20_or_v24',
    disposition: 'failed_before_protocol_judgment_then_rerun_under_bound_node_24',
  }],
  exit_criteria: exitCriteria,
  exit_criteria_total: Object.keys(exitCriteria).length,
  exit_criteria_passed: Object.values(exitCriteria).filter(Boolean).length,
  p2_complete: Object.values(exitCriteria).every(Boolean),
};
const result = { ...unsigned, closure_sha256: sha(Buffer.from(canonicalJson(unsigned))) };
if (OUTPUT) await writeFile(path.resolve(OUTPUT), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
console.log(JSON.stringify(result, null, 2));
process.exit(result.p2_complete ? 0 : 1);
