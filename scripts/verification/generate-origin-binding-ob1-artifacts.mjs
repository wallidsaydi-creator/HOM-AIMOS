#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  mkdir,
  readFile,
  readdir,
  rename,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  ORIGIN_ACTION_CLASS_ORDER_V1,
  ORIGIN_ACTION_DECISIONS_V1,
  ORIGIN_ACTION_FAILURE_CODES_V1,
  ORIGIN_BINDING_LIMITS_V1,
  ORIGIN_BINDING_SCHEMAS_V1,
  ORIGIN_CLASSIFICATION_AUTHORITIES_V1,
  ORIGIN_CONFIDENTIALITY_ORDER_V1,
  ORIGIN_FAMILY_ACTION_POLICIES_V1,
  ORIGIN_FAMILY_PROFILE_BODY_V1,
  ORIGIN_FAMILY_PROFILE_SHA256_V1,
  ORIGIN_INGRESS_CHANNELS_V1,
  ORIGIN_INTEGRITY_ORDER_V1,
  ORIGIN_PROTOCOL_FAILURE_CODES_V1,
  ORIGIN_RISK_CLASSES_V1,
  createActionOriginVerdictV1,
  createMemoryOriginBindingV1,
  createOriginElevationV1,
  originProtocolDomainHexV1,
  originProtocolHashV1,
  verifyOriginDerivationV1,
} from '../../services/security/protocol/origin-binding-v1.js';
import {
  actionVerdict,
  actionVerdictInput,
  clone,
  corroborators,
  derivedBinding,
  derivedBindingInput,
  elevation,
  elevationInput,
  trustedBinding,
  trustedBindingInput,
  untrustedBinding,
  untrustedBindingInput,
} from './origin-binding-ob1-fixtures.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'verifiers/origin-binding/v1');
const PRODUCTION_SCAN_ROOTS = Object.freeze(['services', 'routes', 'jobs', 'db', 'middleware']);
const SOURCE_ROOT_DIRS = Object.freeze([
  'db',
  'middleware',
  'migrations',
  'routes',
  'services',
  'jobs',
]);
const SOURCE_ROOT_EXPLICIT = Object.freeze([
  'server.js',
  'package.json',
  'package-lock.json',
  'architecture-authority.json',
  'hom-architecture-manifest.json',
  'ARCHITECTURE-MAP.md',
  'scripts/verification/origin-binding-ob1-fixtures.mjs',
  'scripts/verification/generate-origin-binding-ob1-artifacts.mjs',
  'tests/security/origin-binding-v1.test.mjs',
  'tests/security/origin-binding-ob1-artifacts.test.mjs',
  'verifiers/origin-binding/v1/verify.py',
  'verifiers/origin-binding/v1/README.md',
]);
const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.sql', '.json', '.md', '.py']);
const MEMORY_READ = /\b(?:FROM|JOIN)\s+(?:public\.)?aimos_memories\b/i;

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function exists(file) {
  try {
    await stat(file);
    return true;
  } catch {
    return false;
  }
}

async function walk(relative) {
  const absolute = path.join(ROOT, relative);
  const entries = await readdir(absolute, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const child = path.posix.join(relative.replaceAll(path.sep, '/'), entry.name);
    if (entry.isDirectory()) files.push(...await walk(child));
    else if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) files.push(child);
  }
  return files;
}

async function writeGenerated(name, value) {
  const file = path.join(OUTPUT, name);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  const digest = sha(bytes);
  const temporary = `${file}.tmp-${process.pid}`;
  const checksum = `${file}.sha256`;
  const checksumTemporary = `${checksum}.tmp-${process.pid}`;
  await writeFile(temporary, bytes, { mode: 0o644 });
  await writeFile(checksumTemporary, `${digest}  ${name}\n`, { mode: 0o644 });
  await rename(temporary, file);
  await rename(checksumTemporary, checksum);
  return Object.freeze({ file_sha256: digest, bytes: bytes.length });
}

function relativeImports(source) {
  const imports = new Set();
  const patterns = [
    /(?:import|export)\s+(?:[^'";]+?\s+from\s+)?['"]([^'"]+)['"]/g,
    /import\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1].startsWith('.')) imports.add(match[1]);
    }
  }
  return [...imports];
}

async function resolveImport(importer, specifier) {
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
  const candidates = [base, `${base}.js`, `${base}.mjs`, path.posix.join(base, 'index.js')];
  for (const candidate of candidates) {
    if (await exists(path.join(ROOT, candidate))) return candidate;
  }
  return null;
}

async function buildImportGraph(files) {
  const sourceByFile = new Map();
  const graph = new Map();
  for (const file of files) sourceByFile.set(file, await readFile(path.join(ROOT, file), 'utf8'));
  for (const file of files) {
    const targets = [];
    for (const specifier of relativeImports(sourceByFile.get(file))) {
      const resolved = await resolveImport(file, specifier);
      if (resolved) targets.push(resolved);
    }
    graph.set(file, Object.freeze([...new Set(targets)].sort()));
  }
  return Object.freeze({ sourceByFile, graph });
}

function reachableFrom(graph, root) {
  const visited = new Set();
  const queue = [root];
  while (queue.length) {
    const current = queue.pop();
    if (visited.has(current)) continue;
    visited.add(current);
    for (const target of graph.get(current) || []) queue.push(target);
  }
  return visited;
}

function nearestFunction(lines, index) {
  for (let cursor = index; cursor >= 0; cursor -= 1) {
    const match = lines[cursor].match(
      /(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)|(?:export\s+)?const\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\(/,
    );
    if (match) return match[1] || match[2];
  }
  return '<module>';
}

function classifyDirectRead(file, recallReachable) {
  if (file === 'services/orchestration/agent-prompts.js') {
    return ['MODEL_VISIBLE_DIRECT_READ', 'OB-4'];
  }
  if (file === 'services/orchestration/agent-runner.js') {
    return ['MODEL_AND_ACTION_INFLUENCING_DIRECT_READ', 'OB-4/OB-5'];
  }
  if (file === 'services/context/post-compaction-delivery.js') {
    return ['MODEL_VISIBLE_HANDOFF_DIRECT_READ', 'OB-4'];
  }
  if (file === 'services/orchestration/session-memory-owner.js') {
    return ['SESSION_DERIVATION_RELATIONAL_READ', 'OB-3'];
  }
  if (file.startsWith('services/retrieval/magma-')) {
    return ['DORMANT_RESEARCH_ZERO_RUNTIME_AUTHORITY', 'RETAIN_DORMANT'];
  }
  if (file.startsWith('services/retrieval/')) {
    return recallReachable.has(file)
      ? ['CANONICAL_RECALL_INTERNAL_READ', 'EXISTING_NATIVE']
      : ['NONCANONICAL_RETRIEVAL_DIRECT_READ', 'OB-4'];
  }
  if (file === 'services/write/canonical-save-owner.js'
      || file === 'services/write/persist-memory.js') {
    return ['CANONICAL_SAVE_RELATIONAL_READ', 'OB-2/OB-3'];
  }
  if (file === 'db/atomic-save-origin.sql') {
    return ['DATABASE_LOCAL_ORIGIN_SAVE_VERIFIER_READ', 'OB-2/OB-3/OB-5'];
  }
  if (file === 'db/cognitive-ancestry.sql') {
    return ['DATABASE_LOCAL_COGNITIVE_ANCESTRY_VERIFIER_READ', 'AUD-007/R7'];
  }
  if (file.startsWith('services/write/')) {
    return ['SAVE_POLICY_OR_DERIVATION_READ', 'OB-3'];
  }
  if (file.startsWith('services/security/')) {
    return ['SECURITY_VERIFICATION_OR_CLASSIFICATION_READ', 'OB-2/OB-4'];
  }
  if (file.startsWith('services/dream/')
      || file.startsWith('services/learning/')
      || file.startsWith('services/governance/')) {
    return ['DURABLE_DERIVATION_OR_MUTATION_INPUT', 'OB-3'];
  }
  if (file.startsWith('services/orchestration/')) {
    return ['ACTION_INFLUENCING_DIRECT_READ', 'OB-4/OB-5'];
  }
  if (file.startsWith('services/context/')) {
    return ['MODEL_OR_DERIVATION_DIRECT_READ', 'OB-3/OB-4'];
  }
  if (file.startsWith('services/temporal/') || file.startsWith('services/core/')) {
    return ['RETRIEVAL_OR_DERIVATION_INPUT', 'OB-3/OB-4'];
  }
  if (file.startsWith('services/observe/') || file.startsWith('services/shared/')) {
    return ['OPERATIONAL_OR_DIAGNOSTIC_READ', 'REVIEW_NO_AUTHORITY'];
  }
  if (file === 'jobs/nightly-dream.js' || file === 'jobs/dream-e2e.js') {
    return ['DURABLE_DERIVATION_OR_MUTATION_INPUT', 'OB-3'];
  }
  if (file.startsWith('jobs/')) {
    return ['OPERATIONAL_CONTROL_READ', 'OB-3'];
  }
  if (file === 'routes/status.js' || file === 'routes/command-center.js') {
    return ['DIAGNOSTIC_ROUTE_READ', 'REVIEW_NO_AUTHORITY'];
  }
  if (file.startsWith('routes/')) {
    return ['EXTERNAL_DISCLOSURE_OR_ROUTE_CONTROL_READ', 'OB-4'];
  }
  fail(`unclassified_direct_memory_read:${file}`);
}

function fail(reason) {
  throw new Error(reason);
}

export async function sourceCensus() {
  const productionFiles = (await Promise.all(PRODUCTION_SCAN_ROOTS.map(walk))).flat().sort();
  const { sourceByFile, graph } = await buildImportGraph(productionFiles);
  const recallReachable = reachableFrom(graph, 'services/retrieval/native-recall-pipeline.js');
  const saveReachable = reachableFrom(graph, 'services/write/canonical-save-owner.js');
  const agentReachable = reachableFrom(graph, 'services/orchestration/agent-runner.js');
  const sites = [];
  for (const file of productionFiles) {
    const source = sourceByFile.get(file);
    const lines = source.split('\n');
    for (let index = 0; index < lines.length; index += 1) {
      if (!MEMORY_READ.test(lines[index])) continue;
      const [classification, closureOwner] = classifyDirectRead(file, recallReachable);
      const context = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 4))
        .map((line) => line.trim()).join('\n');
      sites.push(Object.freeze({
        file,
        line: index + 1,
        function: nearestFunction(lines, index),
        classification,
        closure_owner: closureOwner,
        reachable_from_canonical_recall: recallReachable.has(file),
        reachable_from_canonical_save: saveReachable.has(file),
        reachable_from_agent_run: agentReachable.has(file),
        site_sha256: sha(Buffer.from(canonicalJson({ file, line: index + 1, context }), 'utf8')),
      }));
    }
  }
  const critical = new Set([
    'MODEL_VISIBLE_DIRECT_READ',
    'MODEL_AND_ACTION_INFLUENCING_DIRECT_READ',
    'MODEL_VISIBLE_HANDOFF_DIRECT_READ',
    'ACTION_INFLUENCING_DIRECT_READ',
    'MODEL_OR_DERIVATION_DIRECT_READ',
    'NONCANONICAL_RETRIEVAL_DIRECT_READ',
    'EXTERNAL_DISCLOSURE_OR_ROUTE_CONTROL_READ',
  ]);
  const byClassification = Object.fromEntries(
    [...new Set(sites.map((site) => site.classification))].sort().map((classification) => [
      classification,
      sites.filter((site) => site.classification === classification).length,
    ]),
  );
  const unsigned = {
    schema: 'hom.aimos.origin-binding-source-census/v1',
    generated_from_live_code: true,
    scan_roots: PRODUCTION_SCAN_ROOTS,
    production_file_count: productionFiles.length,
    direct_memory_read_file_count: new Set(sites.map((site) => site.file)).size,
    direct_memory_read_site_count: sites.length,
    model_or_action_influencing_site_count: sites.filter((site) => critical.has(site.classification)).length,
    classification_counts: byClassification,
    roots: {
      canonical_save: 'services/write/canonical-save-owner.js',
      canonical_recall: 'services/retrieval/native-recall-pipeline.js',
      agent_run: 'services/orchestration/agent-runner.js',
      session: 'services/orchestration/session-memory-owner.js',
      compaction_write: 'services/write/compaction-save.js',
      compaction_delivery: 'services/context/post-compaction-delivery.js',
      ingestion: 'services/ingestion/ingestion-orchestrator.js',
      tool_execution: 'services/orchestration/tool-registry.js',
      tool_action_ledger: 'services/orchestration/tool-action-ledger.js',
      agent_context: 'services/orchestration/agent-prompts.js',
      provenance: 'services/security/memory-provenance.js',
      lineage: 'services/security/memory-lineage.js',
      identity: 'services/security/agent-identity.js',
      auth_gate: 'services/security/auth-gate.js',
      database_writer: 'services/write/persist-memory.js',
    },
    canonical_recall_import_closure_count: recallReachable.size,
    canonical_save_import_closure_count: saveReachable.size,
    agent_run_import_closure_count: agentReachable.size,
    direct_memory_read_sites: sites,
  };
  return {
    ...unsigned,
    census_sha256: sha(Buffer.from(canonicalJson(unsigned), 'utf8')),
  };
}

function expectedFailure(fn) {
  try {
    fn();
    return null;
  } catch (error) {
    return String(error?.message || error).replace(/^origin_binding_v1:/, '');
  }
}

function vector(id, operation, input, expected) {
  return Object.freeze({ id, operation, input, expected });
}

function buildVectors() {
  const parent = untrustedBinding();
  const derived = derivedBinding(parent);
  const trusted = trustedBinding();
  const license = elevation(parent);
  const verdict = actionVerdict(parent);
  const vectors = [
    vector('profile-valid', 'family_profile_hash', ORIGIN_FAMILY_PROFILE_BODY_V1, {
      valid: true,
      sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
    }),
    vector('binding-untrusted-valid', 'memory_binding', untrustedBindingInput(), {
      valid: true,
      sha256: parent.binding_sha256,
    }),
    vector('binding-trusted-valid', 'memory_binding', trustedBindingInput(), {
      valid: true,
      sha256: trusted.binding_sha256,
    }),
    vector('derivation-valid', 'derivation', { child: derived, parents: [parent] }, {
      valid: true,
      parent_count: 1,
    }),
    vector('elevation-corroborated-valid', 'elevation', elevationInput(parent), {
      valid: true,
      sha256: license.elevation_sha256,
    }),
    vector('verdict-allow-valid', 'action_verdict', actionVerdictInput(parent), {
      valid: true,
      sha256: verdict.verdict_sha256,
    }),
  ];

  const invalid = [];
  const addInvalid = (id, operation, input, fn) => {
    const failureCode = expectedFailure(fn);
    if (!failureCode) fail(`negative_vector_did_not_fail:${id}`);
    invalid.push(vector(id, operation, input, { valid: false, failure_code: failureCode }));
  };

  const caller = untrustedBindingInput();
  caller.classification.authority = 'caller';
  addInvalid('binding-caller-family-authority', 'memory_binding', caller,
    () => createMemoryOriginBindingV1(caller));

  const unknown = untrustedBindingInput();
  unknown.classification.family_ids = ['unknown.future_family'];
  addInvalid('binding-unknown-family', 'memory_binding', unknown,
    () => createMemoryOriginBindingV1(unknown));

  const order = untrustedBindingInput();
  order.classification.family_ids = [...order.classification.family_ids].reverse();
  addInvalid('binding-family-order', 'memory_binding', order,
    () => createMemoryOriginBindingV1(order));

  const closure = untrustedBindingInput();
  closure.classification.family_ids = ['information.fact'];
  addInvalid('binding-family-closure', 'memory_binding', closure,
    () => createMemoryOriginBindingV1(closure));

  const staleProfile = untrustedBindingInput();
  staleProfile.classification.profile_sha256 = '91'.repeat(32);
  addInvalid('binding-stale-family-profile', 'memory_binding', staleProfile,
    () => createMemoryOriginBindingV1(staleProfile));

  const confidentiality = trustedBindingInput({ confidentiality: 'internal' });
  addInvalid('binding-family-confidentiality-floor', 'memory_binding', confidentiality,
    () => createMemoryOriginBindingV1(confidentiality));

  const channel = untrustedBindingInput({ integrity: 'agent', action_class: 'inform' });
  addInvalid('binding-channel-integrity', 'memory_binding', channel,
    () => createMemoryOriginBindingV1(channel));

  const action = untrustedBindingInput({ action_class: 'inform' });
  addInvalid('binding-integrity-action-class', 'memory_binding', action,
    () => createMemoryOriginBindingV1(action));

  const mismatchedInput = derivedBindingInput(parent);
  mismatchedInput.parents.origin_sha256s = ['92'.repeat(32)];
  const mismatched = createMemoryOriginBindingV1(mismatchedInput);
  addInvalid('derivation-parent-substitution', 'derivation', { child: mismatched, parents: [parent] },
    () => verifyOriginDerivationV1({ child: mismatched, parents: [parent] }));

  const strippedInput = derivedBindingInput(parent);
  strippedInput.classification.family_ids = ['derived', 'derived.summary'];
  const stripped = createMemoryOriginBindingV1(strippedInput);
  addInvalid('derivation-family-stripping', 'derivation', { child: stripped, parents: [parent] },
    () => verifyOriginDerivationV1({ child: stripped, parents: [parent] }));

  const confidentialParent = createMemoryOriginBindingV1(untrustedBindingInput({
    confidentiality: 'confidential',
  }));
  const downgraded = createMemoryOriginBindingV1(derivedBindingInput(confidentialParent, {
    confidentiality: 'internal',
  }));
  addInvalid('derivation-confidentiality-downgrade', 'derivation', {
    child: downgraded,
    parents: [confidentialParent],
  }, () => verifyOriginDerivationV1({ child: downgraded, parents: [confidentialParent] }));

  const raisedIntegrity = createMemoryOriginBindingV1(derivedBindingInput(parent, {
    integrity: 'agent',
    action_class: 'inform',
  }));
  addInvalid('derivation-integrity-elevation', 'derivation', {
    child: raisedIntegrity,
    parents: [parent],
  }, () => verifyOriginDerivationV1({ child: raisedIntegrity, parents: [parent] }));

  const noActionParent = createMemoryOriginBindingV1(trustedBindingInput({ action_class: 'none' }));
  const raisedAction = createMemoryOriginBindingV1(derivedBindingInput(noActionParent, {
    origin: { ingress_channel: 'system_internal', channel_identity_sha256: '93'.repeat(32) },
    confidentiality: 'confidential',
    integrity: 'trusted',
    action_class: 'inform',
  }));
  addInvalid('derivation-action-elevation', 'derivation', {
    child: raisedAction,
    parents: [noActionParent],
  }, () => verifyOriginDerivationV1({ child: raisedAction, parents: [noActionParent] }));

  const correlated = elevationInput(parent);
  correlated.corroborators = corroborators();
  correlated.corroborators[1].administrative_domain_sha256 =
    correlated.corroborators[0].administrative_domain_sha256;
  addInvalid('elevation-correlated-corroborators', 'elevation', correlated,
    () => createOriginElevationV1(correlated));

  const insufficient = elevationInput(parent, { corroborators: [corroborators()[0]] });
  addInvalid('elevation-insufficient-corroborators', 'elevation', insufficient,
    () => createOriginElevationV1(insufficient));

  const missingAuthority = actionVerdictInput(parent, {
    elevation_sha256: null,
    user_authorization_sha256: null,
  });
  addInvalid('verdict-untrusted-without-authority', 'action_verdict', missingAuthority,
    () => createActionOriginVerdictV1(missingAuthority));

  const missingFailure = actionVerdictInput(parent, {
    decision: 'DENY',
    failure_code: null,
  });
  addInvalid('verdict-deny-without-failure', 'action_verdict', missingFailure,
    () => createActionOriginVerdictV1(missingFailure));

  const substitutedFamily = actionVerdictInput(parent);
  substitutedFamily.security_values[0].family_ids = [
    'action_input',
    'action_input.financial_value',
  ];
  addInvalid('verdict-value-family-substitution', 'action_verdict', substitutedFamily,
    () => createActionOriginVerdictV1(substitutedFamily));

  const valueOrder = actionVerdictInput(parent);
  valueOrder.security_values = [...valueOrder.security_values].reverse();
  addInvalid('verdict-security-value-order', 'action_verdict', valueOrder,
    () => createActionOriginVerdictV1(valueOrder));

  const all = [...vectors, ...invalid];
  const unsigned = {
    schema: 'hom.aimos.origin-binding-vectors/v1',
    intended_n: all.length,
    valid_n: vectors.length,
    invalid_n: invalid.length,
    vectors: all,
  };
  return {
    ...unsigned,
    vectors_root_sha256: sha(Buffer.from(canonicalJson(all), 'utf8')),
    manifest_sha256: sha(Buffer.from(canonicalJson(unsigned), 'utf8')),
  };
}

export async function sourceRoot() {
  const files = new Set();
  for (const directory of SOURCE_ROOT_DIRS) {
    for (const file of await walk(directory)) files.add(file);
  }
  for (const relative of SOURCE_ROOT_EXPLICIT) {
    if (!await exists(path.join(ROOT, relative))) fail(`ob1_source_file_missing:${relative}`);
    files.add(relative);
  }
  const entries = await Promise.all([...files].sort().map(async (file) => ({
    path: file,
    sha256: sha(await readFile(path.join(ROOT, file))),
  })));
  return Object.freeze({
    files: entries,
    root_sha256: sha(Buffer.from(canonicalJson(entries), 'utf8')),
  });
}

export async function productionProtocolImporters() {
  const productionFiles = (await Promise.all(PRODUCTION_SCAN_ROOTS.map(walk))).flat().sort();
  const importers = [];
  for (const file of productionFiles) {
    if (file === 'services/security/protocol/origin-binding-v1.js') continue;
    // OB-2 authorized production consumers: the origin ledger service and the
    // canonical-SAVE origin binding owner are the sole bridges between the
    // frozen OB-1 protocol and the database-local typed writers / SAVE path.
    // Any other production importer remains a hard failure.
    if (file === 'services/security/origin-ledger.js') continue;
    if (file === 'services/security/save-origin-binding.js') continue;
    const source = await readFile(path.join(ROOT, file), 'utf8');
    if (source.includes('origin-binding-v1.js')) importers.push(file);
  }
  return Object.freeze(importers);
}

export async function main() {
  await mkdir(OUTPUT, { recursive: true });
  const census = await sourceCensus();
  const vectors = buildVectors();
  const sources = await sourceRoot();
  const runtimeImporters = await productionProtocolImporters();
  if (runtimeImporters.length !== 0) fail('ob1_protocol_has_production_runtime_importer');

  const profileArtifact = {
    body: ORIGIN_FAMILY_PROFILE_BODY_V1,
    profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
  };
  const sourceManifestUnsigned = {
    schema: 'hom.aimos.origin-binding-source-manifest/v1',
    source_file_count: sources.files.length,
    source_files: sources.files,
    source_root_sha256: sources.root_sha256,
  };
  const sourceManifest = {
    ...sourceManifestUnsigned,
    manifest_sha256: sha(Buffer.from(canonicalJson(sourceManifestUnsigned), 'utf8')),
  };
  const profileFile = await writeGenerated('family-profile.json', profileArtifact);
  const vectorFile = await writeGenerated('vectors.json', vectors);
  const censusFile = await writeGenerated('source-census.json', census);
  const sourceFile = await writeGenerated('source-manifest.json', sourceManifest);

  const unsigned = {
    schema: 'hom.aimos.origin-binding-protocol-manifest/v1',
    version: 1,
    status: 'ob1_protocol_frozen',
    canonicalization: 'hom-aimos/canonical-json/v1-safe-integers',
    hash: 'sha256',
    signature: 'ed25519',
    schemas: ORIGIN_BINDING_SCHEMAS_V1,
    domains_hex: originProtocolDomainHexV1(),
    limits: ORIGIN_BINDING_LIMITS_V1,
    integrity_order: ORIGIN_INTEGRITY_ORDER_V1,
    confidentiality_order: ORIGIN_CONFIDENTIALITY_ORDER_V1,
    action_class_order: ORIGIN_ACTION_CLASS_ORDER_V1,
    risk_classes: ORIGIN_RISK_CLASSES_V1,
    ingress_channels: ORIGIN_INGRESS_CHANNELS_V1,
    classification_authorities: ORIGIN_CLASSIFICATION_AUTHORITIES_V1,
    family_action_policies: ORIGIN_FAMILY_ACTION_POLICIES_V1,
    action_decisions: ORIGIN_ACTION_DECISIONS_V1,
    action_failure_codes: ORIGIN_ACTION_FAILURE_CODES_V1,
    protocol_failure_codes: ORIGIN_PROTOCOL_FAILURE_CODES_V1,
    family_profile: {
      profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
      family_count: ORIGIN_FAMILY_PROFILE_BODY_V1.families.length,
      file_sha256: profileFile.file_sha256,
    },
    vectors: {
      intended_n: vectors.intended_n,
      valid_n: vectors.valid_n,
      invalid_n: vectors.invalid_n,
      vectors_root_sha256: vectors.vectors_root_sha256,
      manifest_sha256: vectors.manifest_sha256,
      file_sha256: vectorFile.file_sha256,
    },
    source_census: {
      direct_memory_read_file_count: census.direct_memory_read_file_count,
      direct_memory_read_site_count: census.direct_memory_read_site_count,
      model_or_action_influencing_site_count: census.model_or_action_influencing_site_count,
      census_sha256: census.census_sha256,
      file_sha256: censusFile.file_sha256,
    },
    source_file_count: sources.files.length,
    source_root_sha256: sources.root_sha256,
    source_manifest: {
      schema: sourceManifest.schema,
      manifest_sha256: sourceManifest.manifest_sha256,
      file_sha256: sourceFile.file_sha256,
    },
    production_runtime_importers: runtimeImporters,
    database_mutation: false,
    runtime_activation: false,
    memory_write: false,
    ob1_closed: true,
    next_required_owner: 'OB-2_ATOMIC_ORIGIN_FAMILY_LEDGER',
  };
  const manifest = {
    ...unsigned,
    protocol_root_sha256: sha(Buffer.from(canonicalJson(unsigned), 'utf8')),
  };
  const manifestFile = await writeGenerated('protocol-manifest.json', manifest);
  console.log(JSON.stringify({
    success: true,
    status: manifest.status,
    protocol_root_sha256: manifest.protocol_root_sha256,
    manifest_file_sha256: manifestFile.file_sha256,
    family_profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
    vector_root_sha256: vectors.vectors_root_sha256,
    vector_count: vectors.intended_n,
    source_census_sha256: census.census_sha256,
    direct_memory_read_sites: census.direct_memory_read_site_count,
    model_or_action_influencing_sites: census.model_or_action_influencing_site_count,
    source_root_sha256: sources.root_sha256,
    source_file_count: sources.files.length,
    production_runtime_importers: runtimeImporters.length,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`[origin-binding-ob1] ${error.message}`);
    process.exitCode = 1;
  });
}
