#!/usr/bin/env node
// scripts/identity/init-architecture-authority.js
// Generate the runtime architecture-authority.json from the portable
// architecture-authority.template.json + the operator's brain root.
//
// The template uses RELATIVE paths (no operator-specific /Users/<name> strings).
// The runtime JSON has every relative path resolved to an ABSOLUTE path against
// the operator's brain root. Reviewers run this on their own machine; the
// generated JSON is git-ignored (it's machine-specific).
//
// Idempotent: re-running overwrites the runtime JSON. No env vars. No network.
//
// Usage:
//   node scripts/identity/init-architecture-authority.js
//   node scripts/identity/init-architecture-authority.js --brain-root=/path/to/brain
//   node scripts/identity/init-architecture-authority.js --dry-run
//   node scripts/identity/init-architecture-authority.js --force  (overwrite even if runtime JSON looks already generated)
//
// Exit codes:
//   0 = runtime JSON written (or dry-run printed)
//   64 = usage error
//   70 = template missing or invalid
//   75 = runtime JSON already present and not in --force mode (refuses to clobber a hand-edited file)

import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyGenesisManifest } from '../verify-genesis-manifest.mjs';
import { collectServiceCensus } from '../architecture/sync-service-inventory.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_BRAIN_ROOT = path.resolve(__dirname, '..', '..');

const args = process.argv.slice(2);
const brainRootArg = args.find(a => a.startsWith('--brain-root='));
const dryRun = args.includes('--dry-run');
const force = args.includes('--force');

function usage() {
  console.error('Usage: init-architecture-authority.js [--brain-root=<path>] [--dry-run] [--force]');
  console.error('  --brain-root   path to the brain root (default: this brain root)');
  console.error('  --dry-run      print the generated JSON to stdout; do not write');
  console.error('  --force        overwrite even if runtime JSON looks already generated');
  process.exit(64);
}

if (args.includes('--help') || args.includes('-h')) usage();

const brainRoot = brainRootArg
  ? path.resolve(brainRootArg.split('=')[1])
  : DEFAULT_BRAIN_ROOT;

if (!fs.existsSync(brainRoot) || !fs.statSync(brainRoot).isDirectory()) {
  console.error(`[FATAL] brain root not found or not a directory: ${brainRoot}`);
  process.exit(64);
}

const templatePath = path.join(brainRoot, 'architecture-authority.template.json');
const runtimePath = path.join(brainRoot, 'architecture-authority.json');

let genesisManifest;
try {
  genesisManifest = verifyGenesisManifest({ brainRoot });
} catch (error) {
  console.error(`[FATAL] Genesis corpus verification failed: ${error.message}`);
  process.exit(70);
}

if (!fs.existsSync(templatePath)) {
  console.error(`[FATAL] template missing: ${templatePath}`);
  console.error('        The template ships with the brain repo. Restore it from git.');
  process.exit(70);
}

let template;
try {
  template = JSON.parse(fs.readFileSync(templatePath, 'utf8'));
} catch (err) {
  console.error(`[FATAL] template invalid JSON: ${err.message}`);
  process.exit(70);
}

if (template.schema !== 'hom.architecture-authority/v1') {
  console.error(`[FATAL] template schema mismatch: ${template.schema}`);
  process.exit(70);
}

if (template.runtime_mode !== 'template') {
  console.error(`[FATAL] template runtime_mode is "${template.runtime_mode}" — expected "template".`);
  console.error('        The template file must have runtime_mode=template. The runtime JSON is generated FROM the template.');
  process.exit(70);
}

const census = collectServiceCensus(brainRoot);
const serviceManifestPath = path.resolve(brainRoot, template.service_inventory?.manifest || './hom-architecture-manifest.json');
let serviceManifest;
try {
  serviceManifest = JSON.parse(fs.readFileSync(serviceManifestPath, 'utf8'));
} catch (error) {
  console.error(`[FATAL] service manifest missing or invalid: ${error.message}`);
  process.exit(70);
}

const manifestFiles = Object.entries(serviceManifest.service_inventory?.groups || {})
  .flatMap(([group, entry]) => (entry.files || []).map((file) => `services/${group}/${file}`))
  .sort();
const inventoryMatches = (
  serviceManifest.total_services === census.serviceCount
  && serviceManifest.service_inventory?.counted_service_files === census.serviceCount
  && serviceManifest.service_inventory?.service_groups === census.groupCount
  && serviceManifest.service_inventory?.census_sha256 === census.digest
  && JSON.stringify(manifestFiles) === JSON.stringify(census.files)
  && template.service_inventory?.counted_service_files === census.serviceCount
  && template.service_inventory?.counted_service_groups === census.groupCount
  && template.service_inventory?.census_sha256 === census.digest
);
if (!inventoryMatches) {
  console.error('[FATAL] service inventory drift detected.');
  console.error(`        live: groups=${census.groupCount} services=${census.serviceCount} digest=${census.digest}`);
  console.error('        Run: node scripts/architecture/sync-service-inventory.mjs, review the diff, then update the authority template binding.');
  process.exit(70);
}

// Refuse to clobber an existing runtime JSON that looks hand-edited (runtime_mode != "runtime"
// OR missing runtime_mode) unless --force. This protects a hand-edited runtime JSON from being
// silently overwritten.
if (fs.existsSync(runtimePath) && !force) {
  let existing;
  try {
    existing = JSON.parse(fs.readFileSync(runtimePath, 'utf8'));
  } catch {
    existing = {};
  }
  if (existing.runtime_mode !== 'runtime') {
    console.error(`[FATAL] existing ${runtimePath} has runtime_mode="${existing.runtime_mode ?? '<missing>'}" — looks hand-edited (or stale).`);
    console.error('        Refusing to clobber without --force. Re-run with --force to overwrite.');
    process.exit(75);
  }
}

// Walk the template, resolving every path-like field against the brain root.
// Path-like fields are: any string value that starts with "./" or "../" or is exactly "." or "..".
// Other string values (e.g. "hom.architecture-authority/v1") pass through unchanged.
function resolveValue(value) {
  if (typeof value !== 'string') return value;
  if (value === '.' || value === '..') return path.resolve(brainRoot, value);
  if (value.startsWith('./') || value.startsWith('../')) return path.resolve(brainRoot, value);
  return value;
}

function resolveObject(obj) {
  if (Array.isArray(obj)) return obj.map(resolveObject);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = resolveObject(v);
    return out;
  }
  return resolveValue(obj);
}

const runtime = resolveObject(template);
runtime.runtime_mode = 'runtime';
runtime.generated_from_template = path.basename(templatePath);
runtime.generated_at_brain_root = brainRoot;
runtime.version = template.version;
runtime.updated = template.updated;

const templateGenesis = template.genesis_corpus || {};
if (
  templateGenesis.schema !== genesisManifest.schema ||
  templateGenesis.version !== genesisManifest.version ||
  templateGenesis.corpus_root !== genesisManifest.corpusRoot
) {
  console.error('[FATAL] architecture-authority template does not match the verified Genesis corpus manifest.');
  console.error(`        manifest: schema=${genesisManifest.schema} version=${genesisManifest.version} root=${genesisManifest.corpusRoot}`);
  console.error(`        template: schema=${templateGenesis.schema} version=${templateGenesis.version} root=${templateGenesis.corpus_root}`);
  process.exit(70);
}
runtime.genesis_corpus = {
  ...runtime.genesis_corpus,
  manifest: genesisManifest.manifestPath,
  schema: genesisManifest.schema,
  version: genesisManifest.version,
  corpus_root: genesisManifest.corpusRoot,
  file_count: genesisManifest.files.length,
  verified_during_generation: true,
};

// Required static authority fails closed before the runtime JSON is written.
// Runtime-created work directories are declared separately and are not
// fabricated during authority generation.
const logicalPaths = runtime.path_authority?.logical_paths || {};
const docs = runtime.documents || {};
const missing = [];
const requiredStaticKeys = runtime.path_authority?.required_static_path_keys || [];
for (const key of requiredStaticKeys) {
  const value = logicalPaths[key];
  if (typeof value !== 'string' || !value || !fs.existsSync(value)) {
    missing.push(`${key}: ${value || '<undeclared>'}`);
  }
}
for (const [k, v] of Object.entries(docs)) {
  if (typeof v === 'string' && v && !fs.existsSync(v)) missing.push(`document ${k}: ${v}`);
}

if (missing.length) {
  console.error('[FATAL] required static authority paths are missing:');
  for (const item of missing) console.error(`  ${item}`);
  process.exit(70);
}

runtime.service_inventory = {
  ...runtime.service_inventory,
  manifest: serviceManifestPath,
  counted_service_groups: census.groupCount,
  counted_service_files: census.serviceCount,
  census_sha256: census.digest,
  verified_during_generation: true,
};

const json = JSON.stringify(runtime, null, 2) + '\n';

if (dryRun) {
  process.stdout.write(json);
  process.exit(0);
}

fs.writeFileSync(runtimePath, json, { mode: 0o644 });
console.log(`[OK] wrote ${runtimePath}`);
console.log(`     template:  ${templatePath}`);
console.log(`     brain root: ${brainRoot}`);
console.log(`     runtime_mode: ${runtime.runtime_mode}`);
console.log(`     genesis corpus: ${runtime.genesis_corpus.corpus_root} (${runtime.genesis_corpus.file_count} files)`);
console.log(`[OK] service census verified: ${census.serviceCount} services across ${census.groupCount} groups (${census.digest})`);
console.log('[OK] all required static logical paths + documents resolve on disk');
