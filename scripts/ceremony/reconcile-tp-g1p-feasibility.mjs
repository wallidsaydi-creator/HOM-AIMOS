#!/usr/bin/env node

/**
 * Append-only TP-G1P feasibility reconciliation.
 *
 * The original run artifact is immutable. This ceremony verifies every
 * selected question-evidence self-hash and selection link, recomputes the
 * preregistered feasibility result from the native profile payloads, and
 * emits a housekeeper-signed correction receipt without rewriting the run.
 */

import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { agentPool, pool } from '../../db/connection.js';
import { verifyStoredPayloadSig } from '../../services/security/agent-identity.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { aggregateActionability } from '../../eval/twin-prime-g1p-profile.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RUN_ROOT = path.join(ROOT, 'eval', 'public-results');
const REPORT = path.join(
  ROOT,
  'plans',
  'Codex',
  'active',
  'twin-prime',
  'TP-G1P-COMPLETION-AND-FEASIBILITY-RECONCILIATION-20260808.md',
);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function cliValue(argv, name) {
  const index = argv.indexOf(name);
  if (index >= 0 && argv[index + 1]) return argv[index + 1];
  const inline = argv.find((entry) => entry.startsWith(`${name}=`));
  return inline ? inline.slice(name.length + 1) : null;
}

function selfHash(value, key) {
  const unsigned = { ...value };
  delete unsigned[key];
  return sha256(JSON.stringify(unsigned));
}

function readRegularJson(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`reconciliation_artifact_invalid:${file}`);
  const bytes = fs.readFileSync(file);
  return { bytes, value: JSON.parse(bytes) };
}

function parseCertificate(certString) {
  const encoded = String(certString || '');
  let artifact;
  try {
    artifact = JSON.parse(encoded);
  } catch {
    artifact = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  }
  const claims = artifact?.body || artifact;
  if (typeof claims?.pubkey !== 'string' || !claims.pubkey) {
    throw new Error('reconciliation_housekeeper_certificate_invalid');
  }
  return claims;
}

function writeExclusive(file, text, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, text, { flag: 'wx', mode });
}

function verifiedRun(runId) {
  if (!/^202[0-9]{11}_[0-9a-f]{6}$/.test(runId)) throw new Error('reconciliation_run_id_invalid');
  const runDir = path.join(RUN_ROOT, runId);
  const status = readRegularJson(path.join(runDir, 'run-status.json')).value;
  if (status.state !== 'complete' || status.phase !== 'complete' || status.error != null) {
    throw new Error('reconciliation_run_not_complete');
  }

  const original = readRegularJson(path.join(runDir, 'tp-g1p-summary.json'));
  if (original.value.schema !== 'hom.twin-prime-g1p-summary/v1'
    || original.value.run_id !== runId
    || original.value.protocol !== 'twin-prime-g1p-v1'
    || original.value.summary_sha256 !== selfHash(original.value, 'summary_sha256')) {
    throw new Error('reconciliation_original_summary_invalid');
  }

  const rows = {};
  const selections = {};
  const evidenceManifest = [];
  for (const benchmark of ['locomo', 'longmemeval']) {
    const selectionFile = path.join(runDir, `selection-${benchmark}.json`);
    const selection = readRegularJson(selectionFile);
    if (selection.value.schema !== 'hom.twin-prime-g1p-selection/v1'
      || selection.value.run_id !== runId
      || selection.value.benchmark !== benchmark
      || selection.value.question_count !== selection.value.entries?.length
      || selection.value.selection_sha256 !== selfHash(selection.value, 'selection_sha256')) {
      throw new Error(`reconciliation_selection_invalid:${benchmark}`);
    }
    selections[benchmark] = {
      file_sha256: sha256(selection.bytes),
      selection_sha256: selection.value.selection_sha256,
      question_count: selection.value.question_count,
    };
    rows[benchmark] = [];

    for (const entry of selection.value.entries) {
      const relative = path.join('tp-g1p', 'questions', entry.unit_id, 'evidence.json');
      const evidence = readRegularJson(path.join(runDir, relative));
      const value = evidence.value;
      if (value.schema !== 'hom.twin-prime-g1p-question-evidence/v1'
        || value.run_id !== runId
        || value.benchmark !== benchmark
        || value.question_id !== entry.question_id
        || value.input_sha256 !== entry.input_sha256
        || value.evidence_sha256 !== selfHash(value, 'evidence_sha256')
        || typeof value.profile?.set_actionable !== 'boolean'
        || typeof value.profile?.rank_actionable !== 'boolean') {
        throw new Error(`reconciliation_evidence_invalid:${entry.unit_id}`);
      }
      rows[benchmark].push(value.profile);
      evidenceManifest.push({
        file: relative,
        file_sha256: sha256(evidence.bytes),
        evidence_sha256: value.evidence_sha256,
      });
    }
  }

  evidenceManifest.sort((left, right) => left.file.localeCompare(right.file, 'en'));
  const corrected = aggregateActionability(rows);
  if (corrected.decision !== 'pass'
    || corrected.datasets.locomo.set_actionable !== original.value.datasets.locomo.set_actionable_queries
    || corrected.datasets.longmemeval.set_actionable !== original.value.datasets.longmemeval.set_actionable_queries) {
    throw new Error('reconciliation_corrected_result_invalid');
  }

  return {
    runDir,
    original,
    corrected,
    selections,
    evidenceCount: evidenceManifest.length,
    evidenceManifestSha256: sha256(JSON.stringify(evidenceManifest)),
  };
}

async function main() {
  const runId = String(cliValue(process.argv, '--run-id') || '').trim();
  const live = process.argv.includes('--live');
  const verified = verifiedRun(runId);
  const body = {
    schema: 'hom.twin-prime-g1p-feasibility-reconciliation/v1',
    event_type: 'RECONCILE_TP_G1P_FEASIBILITY',
    ceremony_id: randomUUID(),
    run_id: runId,
    protocol: 'twin-prime-g1p-v1',
    cause: 'evidence_envelope_profile_shape_mismatch',
    original_summary: {
      file: 'tp-g1p-summary.json',
      file_sha256: sha256(verified.original.bytes),
      summary_sha256: verified.original.value.summary_sha256,
      recorded_decision: verified.original.value.feasibility.decision,
    },
    selections: verified.selections,
    evidence: {
      question_count: verified.evidenceCount,
      manifest_sha256: verified.evidenceManifestSha256,
      all_self_hashes_and_selection_links_verified: true,
    },
    corrected_sources: {
      aggregate_owner_sha256: sha256(fs.readFileSync(path.join(ROOT, 'eval', 'run-twin-prime-g1p.mjs'))),
      profile_math_sha256: sha256(fs.readFileSync(path.join(ROOT, 'eval', 'twin-prime-g1p-profile.mjs'))),
      regression_contract_sha256: sha256(fs.readFileSync(path.join(ROOT, 'tests', 'benchmark', 'twin-prime-g1p.test.mjs'))),
      reconciliation_report_sha256: sha256(fs.readFileSync(REPORT)),
    },
    corrected_feasibility: verified.corrected,
    authorization_boundary: {
      authorizes_tp_g2_entry: true,
      establishes_retrieval_improvement: false,
      establishes_relevance_or_direction: false,
    },
  };

  if (!live) {
    console.log(JSON.stringify({ mode: 'DRY_RUN', body }, null, 2));
    return;
  }

  const output = path.join(verified.runDir, 'tp-g1p-feasibility-reconciliation.json');
  const sidecar = `${output}.sha256`;
  if (fs.existsSync(output) || fs.existsSync(sidecar)) throw new Error('reconciliation_receipt_already_exists');

  const signed = await signAsHousekeeper(body);
  const claims = parseCertificate(signed.certString);
  const verification = verifyStoredPayloadSig(
    claims.pubkey,
    signed.body,
    signed.nonce,
    signed.signedTs,
    signed.sigB64u,
  );
  if (!verification.valid) throw new Error(`reconciliation_signature_invalid:${verification.reason}`);

  const artifact = {
    body: signed.body,
    signer: {
      agent_id: signed.agentId,
      valid_from: signed.validFromIso,
      identity_tier: signed.identityTier,
      certificate_sha256: sha256(Buffer.from(signed.certString, 'utf8')),
    },
    nonce: signed.nonce,
    ts_signed: signed.signedTs,
    sig_form: signed.sigForm,
    signature: signed.sigB64u,
  };
  const bytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
  writeExclusive(output, bytes);
  const receiptSha256 = sha256(bytes);
  writeExclusive(sidecar, `${receiptSha256}  ${path.basename(output)}\n`);
  console.log(JSON.stringify({
    success: true,
    run_id: runId,
    corrected_decision: verified.corrected.decision,
    receipt: output,
    receipt_sha256: receiptSha256,
    ceremony_id: signed.body.ceremony_id,
  }, null, 2));
}

try {
  await main();
} catch (error) {
  console.error(`[FATAL] ${error.message}`);
  process.exitCode = 1;
} finally {
  await Promise.allSettled([pool.end(), agentPool.end()]);
}
