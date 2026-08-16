#!/usr/bin/env node

/**
 * SABER ECR-3 signed certificate-custody ceremony.
 *
 * Phase prepare creates a synthetic, redistribution-safe CERT-ED certificate
 * and an immutable local preparation artifact. Phase commit consumes those
 * exact bytes, appends them through the housekeeper-signed event ledger,
 * reconstructs the certificate from verified receipts, and writes a terminal
 * proof artifact. It never changes memory, classification, save, recall,
 * ranking, policy, or disclosure.
 */

import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/agent-identity.js';
import { certifyEpistemicEditRobustness } from '../../services/security/epistemic-edit-certifier.js';
import {
  buildEpistemicCertificateCustodyPlan,
  persistEpistemicCertificateEvidence,
  verifyPersistedEpistemicCertificateEvidence,
} from '../../services/security/epistemic-certificate-ledger.js';
import { verifyEpistemicEditCertificate } from '../../services/security/epistemic-edit-certificate-verifier.js';

const SCRIPT = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT), '..', '..');
const OUTPUT = path.join(ROOT, 'artifacts', 'security', 'saber', 'ecr3-custody');
const COMPANY_ID = 'hom';
const PHASE = String(process.argv.find((arg) => arg.startsWith('--phase='))?.split('=')[1] || 'prepare');
const LIVE = process.argv.includes('--live');
const ARTIFACT_ARG = process.argv.find((arg) => arg.startsWith('--artifact='))?.slice('--artifact='.length) || null;
const CLASSIFIER = path.join(ROOT, 'services', 'security', 'memory-epistemic-classifier-kernel.js');

const MEMORY = Object.freeze({
  id: '00000000-0000-4000-8000-00000000e003',
  key: 'saber:ecr3:synthetic-custody',
  source: 'synthetic:saber-ecr3',
  memory_type: 'research',
  value: 'A retained observation can remain attributable while its bounded edit stability is certified independently.',
  content_hash: 'e'.repeat(64),
});

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function writeExclusive(filename, value) {
  fs.mkdirSync(OUTPUT, { recursive: true, mode: 0o700 });
  fs.chmodSync(OUTPUT, 0o700);
  const target = path.join(OUTPUT, filename);
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
  const descriptor = fs.openSync(target, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.chmodSync(target, 0o600);
  return Object.freeze({ path: target, sha256: sha256(bytes), bytes: bytes.length });
}

function writeOrVerifyTerminal(filename, value) {
  const target = path.join(OUTPUT, filename);
  if (!fs.existsSync(target)) return Object.freeze({ ...writeExclusive(filename, value), reused: false });
  const bytes = fs.readFileSync(target);
  const existing = JSON.parse(bytes.toString('utf8'));
  const identity = (entry) => ({
    schema: entry.schema,
    ceremony_id: entry.ceremony_id,
    prepare_artifact_sha256: entry.prepare_artifact_sha256,
    certificate_sha256: entry.certificate_sha256,
    evidence_root_sha256: entry.evidence_root_sha256,
    start_event_id: entry.start_receipt?.event_id,
    chunk_event_ids: (entry.chunk_bindings || []).map((binding) => binding.event_id),
    terminal_event_id: entry.terminal_receipt?.event_id,
    terminal_mutation_hash: entry.terminal_receipt?.mutation_hash,
    memory_or_classifier_mutation_performed: entry.memory_or_classifier_mutation_performed,
  });
  assert(canonicalJson(identity(existing)) === canonicalJson(identity(value)),
    'ecr3_existing_terminal_artifact_conflict');
  return Object.freeze({ path: target, sha256: sha256(bytes), bytes: bytes.length, reused: true });
}

function readArtifact(filename) {
  const resolved = path.resolve(filename);
  assert(resolved.startsWith(`${OUTPUT}${path.sep}`), 'ecr3_prepare_artifact_outside_custody_directory');
  const bytes = fs.readFileSync(resolved);
  return Object.freeze({ path: resolved, bytes, sha256: sha256(bytes), value: JSON.parse(bytes.toString('utf8')) });
}

function sourceManifest() {
  const files = [
    CLASSIFIER,
    path.join(ROOT, 'services', 'security', 'epistemic-edit-certificate-math.js'),
    path.join(ROOT, 'services', 'security', 'epistemic-edit-certifier.js'),
    path.join(ROOT, 'services', 'security', 'epistemic-edit-certificate-verifier.js'),
    path.join(ROOT, 'services', 'security', 'epistemic-certificate-ledger.js'),
    SCRIPT,
  ];
  return Object.freeze(files.map((filename) => Object.freeze({
    path: path.relative(ROOT, filename),
    sha256: sha256(fs.readFileSync(filename)),
  })));
}

function verifyPrepare(artifact) {
  assert(artifact.schema === 'hom.aimos.saber-ecr3-prepare/v1', 'ecr3_prepare_schema_invalid');
  assert(artifact.company_id === COMPANY_ID, 'ecr3_prepare_company_invalid');
  assert(canonicalJson(artifact.source_manifest) === canonicalJson(sourceManifest()), 'ecr3_prepare_source_drift');
  const classifierSourceSha256 = sha256(fs.readFileSync(CLASSIFIER));
  assert(artifact.classifier_source_sha256 === classifierSourceSha256, 'ecr3_prepare_classifier_drift');
  const portable = verifyEpistemicEditCertificate({
    certificate: artifact.certificate,
    memory: artifact.memory,
    peers: artifact.peers,
    expectedClassifierSourceSha256: classifierSourceSha256,
  });
  assert(portable.valid === true, `ecr3_prepare_certificate_invalid:${portable.reason || 'unknown'}`);
  const plan = buildEpistemicCertificateCustodyPlan({
    ceremonyId: artifact.ceremony_id,
    certificate: artifact.certificate,
  });
  assert(plan.evidence_root_sha256 === artifact.evidence_root_sha256, 'ecr3_prepare_evidence_root_invalid');
  return Object.freeze({ portable, plan });
}

async function prepare() {
  assert(!LIVE, 'ecr3_prepare_live_flag_forbidden');
  const ceremonyId = randomUUID();
  const classifierSourceSha256 = sha256(fs.readFileSync(CLASSIFIER));
  const certificate = certifyEpistemicEditRobustness({
    memory: MEMORY,
    peers: [],
    classifierSourceSha256,
    pDel: { numerator: 9, denominator: 10 },
    nSelect: 100,
    nCertify: 400,
    alphaFamily: { numerator: 5, denominator: 100 },
    nMax: 1,
  });
  const plan = buildEpistemicCertificateCustodyPlan({ ceremonyId, certificate });
  const artifact = Object.freeze({
    schema: 'hom.aimos.saber-ecr3-prepare/v1',
    ceremony_id: ceremonyId,
    generated_at: new Date().toISOString(),
    company_id: COMPANY_ID,
    scope: 'Synthetic ECR-3 signed custody proof; no memory, classification, save, recall, ranking, policy, or disclosure change.',
    source_manifest: sourceManifest(),
    classifier_source_sha256: classifierSourceSha256,
    memory: MEMORY,
    peers: [],
    certificate,
    evidence_root_sha256: plan.evidence_root_sha256,
    transcript_chunk_count: plan.chunks.length,
  });
  const written = writeExclusive(`saber-ecr3-prepare-${ceremonyId}.json`, artifact);
  console.log(JSON.stringify({ success: true, phase: 'prepare', artifact: written, next: `node scripts/ceremony/run-saber-ecr3-custody-proof.mjs --phase=commit --artifact=${written.path} --live` }, null, 2));
}

async function commit() {
  assert(LIVE, 'ecr3_commit_live_flag_required');
  assert(ARTIFACT_ARG, 'ecr3_commit_prepare_artifact_required');
  const prepared = readArtifact(ARTIFACT_ARG);
  const checked = verifyPrepare(prepared.value);
  console.log(JSON.stringify({
    mode: 'LIVE',
    phase: 'commit',
    prepare_artifact_sha256: prepared.sha256,
    ceremony_id: prepared.value.ceremony_id,
    certificate_sha256: prepared.value.certificate.certificate_sha256,
    evidence_root_sha256: prepared.value.evidence_root_sha256,
    transcript_chunk_count: checked.plan.chunks.length,
  }, null, 2));

  const persisted = await persistEpistemicCertificateEvidence({
    companyId: COMPANY_ID,
    subjectAgentId: 'housekeeper',
    ceremonyId: prepared.value.ceremony_id,
    certificate: prepared.value.certificate,
    memory: prepared.value.memory,
    peers: prepared.value.peers,
    expectedClassifierSourceSha256: prepared.value.classifier_source_sha256,
  });
  const verified = await verifyPersistedEpistemicCertificateEvidence({
    companyId: COMPANY_ID,
    terminalEventId: persisted.terminal_receipt.event_id,
    memory: prepared.value.memory,
    peers: prepared.value.peers,
    expectedClassifierSourceSha256: prepared.value.classifier_source_sha256,
  });
  assert(verified.valid === true, 'ecr3_live_persisted_verification_failed');
  const artifact = Object.freeze({
    schema: 'hom.aimos.saber-ecr3-live-proof/v1',
    ceremony_id: prepared.value.ceremony_id,
    generated_at: new Date().toISOString(),
    prepare_artifact_sha256: prepared.sha256,
    certificate_sha256: prepared.value.certificate.certificate_sha256,
    evidence_root_sha256: verified.evidence_root_sha256,
    start_receipt: persisted.start_receipt,
    chunk_bindings: persisted.chunk_bindings,
    terminal_receipt: persisted.terminal_receipt,
    appended: persisted.appended,
    reused: persisted.reused,
    portable_verification: persisted.portable_verification,
    persisted_verification: {
      valid: verified.valid,
      start_event_id: verified.start_event_id,
      terminal_event_id: verified.terminal_event_id,
      chunk_count: verified.chunk_count,
    },
    memory_or_classifier_mutation_performed: false,
  });
  const written = writeOrVerifyTerminal(`saber-ecr3-live-${prepared.value.ceremony_id}.json`, artifact);
  console.log(JSON.stringify({ success: true, phase: 'commit', artifact: written, evidence: artifact }, null, 2));
}

if (PHASE === 'prepare') await prepare();
else if (PHASE === 'commit') await commit();
else throw new Error('ecr3_phase_invalid');
