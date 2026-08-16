#!/usr/bin/env node

/**
 * TP-G2 live proof — signed B0 policy custody and decision-bound recall.
 *
 * This ceremony performs no memory save and no cognitive or epistemic
 * mutation. It issues one native housekeeper-signed recall through the live
 * HTTP route, reconstructs the decision-bound Merkle root, proves canonical
 * B0 identity, and records before/after row counts.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool } from '../../db/connection.js';
import { AIMOS_HTTP_ORIGIN } from '../../services/core/runtime-config.js';
import {
  canonicalJson,
  verifyStoredPayloadSig,
} from '../../services/security/agent-identity.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { systemConfigStore } from '../../services/security/system-config-store.js';
import { validateTwinPrimeRetrievalPolicy } from '../../services/security/system-config-ledger.js';
import { recallMerkleRoot } from '../../services/security/protocol/mutmem-protocol.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const LIVE = process.argv.includes('--live');
const POLICY_KEY = 'TWIN_PRIME_RETRIEVAL_POLICY';
const EXPECTED_POLICY = Object.freeze({
  version: 'hom-aimos/twin-prime-policy/v1',
  arm: 'B0',
  lambda_t: '0',
  gamma: '0',
  execution: 'enforce',
  cache: 'off',
  early_exit: 'off',
});
const ARTIFACT_DIRECTORY = path.join(ROOT, 'artifacts', 'twin-prime', 'tp-g2');

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function writeExclusive(filename, artifact) {
  fs.mkdirSync(ARTIFACT_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(ARTIFACT_DIRECTORY, 0o700);
  const target = path.join(ARTIFACT_DIRECTORY, filename);
  const bytes = Buffer.from(`${canonicalJson(artifact)}\n`, 'utf8');
  const descriptor = fs.openSync(target, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.chmodSync(target, 0o600);
  return { path: target, sha256: sha256(bytes), bytes: bytes.length };
}

async function immutableCounts() {
  const result = await pool.query(
    `SELECT
       (SELECT count(*)::text FROM public.aimos_memories) AS memories,
       (SELECT count(*)::text FROM public.aimos_memory_epistemic_classifications) AS epistemic_classifications,
       (SELECT count(*)::text FROM public.aimos_cognitive_weight_projections) AS cognitive_weight_projections,
       (SELECT count(*)::text FROM public.aimos_cognitive_weight_baselines) AS cognitive_weight_baselines`,
  );
  return result.rows[0];
}

function assertNoEmbeddingKey(value, trail = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoEmbeddingKey(entry, `${trail}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    assert(key !== 'embedding', `tp_g2_raw_embedding_exposed:${trail}.${key}`);
    assertNoEmbeddingKey(entry, `${trail}.${key}`);
  }
}

async function signedRecall() {
  const route = '/aimos/recall';
  const body = {
    company_id: 'hom',
    agent_id: 'housekeeper',
    q: 'What is the HOM-AIMOS full-retention and authorized mutation policy?',
    limit: 5,
    clearance_level: 12,
    cache: false,
    semantic_cache: false,
    early_exit: false,
  };
  const signed = await signAsHousekeeper(body, { method: 'POST', path: route });
  const response = await fetch(`${AIMOS_HTTP_ORIGIN}${route}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Aimos-Agent-Cert': signed.certString,
      'Aimos-Agent-Signature': signed.sigB64u,
      'Aimos-Agent-Nonce': signed.nonce,
      'Aimos-Agent-Timestamp': String(signed.signedTs),
      'X-Aimos-Sig-Form': String(signed.sigForm),
    },
    body: JSON.stringify(signed.body),
    signal: AbortSignal.timeout(120_000),
  });
  const result = await response.json().catch(() => ({}));
  assert(response.ok && result.success === true, `tp_g2_signed_recall_failed:${response.status}:${JSON.stringify(result)}`);
  return result;
}

async function signerPubkey(signed) {
  const result = await pool.query(
    `SELECT pubkey
       FROM public.agent_identity
      WHERE agent_id = $1
        AND valid_from = $2::timestamptz`,
    [signed.agentId, signed.validFromIso],
  );
  assert(result.rows.length === 1, 'tp_g2_housekeeper_epoch_missing');
  return result.rows[0].pubkey;
}

async function main() {
  await systemConfigStore.loadAll();
  const policyEntry = systemConfigStore.readVerifiedConfig(POLICY_KEY);
  assert(policyEntry, 'tp_g2_verified_policy_missing');
  const validated = validateTwinPrimeRetrievalPolicy(policyEntry.value);
  assert(validated.ok, `tp_g2_policy_invalid:${validated.reason}`);
  assert(canonicalJson(validated.policy) === canonicalJson(EXPECTED_POLICY), 'tp_g2_policy_not_b0_baseline');
  assert(/^[0-9a-f]{64}$/.test(String(policyEntry.mutation_hash || '')), 'tp_g2_policy_mutation_hash_invalid');

  const healthResponse = await fetch(`${AIMOS_HTTP_ORIGIN}/health`, { signal: AbortSignal.timeout(15_000) });
  assert(healthResponse.ok, 'tp_g2_server_health_transport_failed');
  const health = await healthResponse.json();
  assert(health.ready === true, `tp_g2_server_not_ready:${health.bootError || 'unknown'}`);

  const prerequisites = {
    server_origin: AIMOS_HTTP_ORIGIN,
    server_ready: true,
    database: health.runtime?.database_name,
    ceremony_source_sha256: sha256(fs.readFileSync(SCRIPT_FILE)),
    policy: validated.policy,
    policy_mutation_hash: policyEntry.mutation_hash,
  };
  console.log(JSON.stringify({ mode: LIVE ? 'LIVE' : 'DRY_RUN', prerequisites }, null, 2));
  if (!LIVE) return;

  const before = await immutableCounts();
  const recalled = await signedRecall();
  const after = await immutableCounts();
  assert(canonicalJson(before) === canonicalJson(after), 'tp_g2_recall_mutated_retained_memory_state');
  assertNoEmbeddingKey(recalled);

  const epistemic = recalled.recall_meta?.epistemic_retrieval;
  const decision = epistemic?.twin_prime;
  const receipt = recalled.recall_receipt;
  assert(epistemic && decision, 'tp_g2_twin_prime_decision_missing');
  assert(decision.policy_mutation_hash === policyEntry.mutation_hash, 'tp_g2_decision_policy_hash_mismatch');
  assert(decision.policy?.arm === 'B0', 'tp_g2_decision_arm_not_b0');
  assert(decision.policy?.execution === 'enforce', 'tp_g2_decision_execution_invalid');
  assert(canonicalJson(decision.baseline_selected_memory_ids) === canonicalJson(decision.computed_selected_memory_ids), 'tp_g2_b0_computed_identity_failed');
  assert(canonicalJson(decision.baseline_selected_memory_ids) === canonicalJson(decision.returned_selected_memory_ids), 'tp_g2_b0_disclosure_identity_failed');
  assert(receipt?.merkle_schema === 'hom-aimos/recall-merkle/v2-epistemic-decision', 'tp_g2_receipt_schema_invalid');
  assert(receipt.epistemic_decision_sha256 === epistemic.decision_sha256, 'tp_g2_receipt_decision_hash_mismatch');
  assert(Array.isArray(receipt.merkle_entries) && receipt.merkle_entries.length === receipt.evidence.length + 1, 'tp_g2_merkle_entries_invalid');
  assert(canonicalJson(receipt.merkle_entries[0]) === canonicalJson({
    entry_type: 'epistemic_decision',
    decision_sha256: epistemic.decision_sha256,
  }), 'tp_g2_merkle_decision_entry_invalid');
  assert(canonicalJson(receipt.merkle_entries.slice(1)) === canonicalJson(receipt.evidence), 'tp_g2_merkle_evidence_order_invalid');
  const reconstructedRoot = recallMerkleRoot(receipt.merkle_entries).toString('hex');
  assert(reconstructedRoot === receipt.merkle_root, 'tp_g2_merkle_reconstruction_failed');
  assert(/^[0-9a-f]{64}$/.test(String(receipt.event_receipt?.mutation_hash || '')), 'tp_g2_recall_event_receipt_missing');

  const ceremonyId = randomUUID();
  const body = {
    schema: 'hom.aimos.tp-g2-signed-policy-proof/v1',
    ceremony_id: ceremonyId,
    prerequisites,
    request: {
      command_hash: receipt.command_hash,
      result_count: recalled.memories.length,
    },
    verification: {
      b0_baseline_equals_computed: true,
      b0_baseline_equals_returned: true,
      signed_policy_mutation_hash_bound: true,
      epistemic_decision_hash_bound: true,
      merkle_root_reconstructed: true,
      raw_embedding_exposed: false,
      retained_memory_state_unchanged: true,
    },
    immutable_counts: { before, after },
    decision: {
      decision_sha256: epistemic.decision_sha256,
      policy_mutation_hash: decision.policy_mutation_hash,
      baseline_selected_memory_ids: decision.baseline_selected_memory_ids,
      computed_selected_memory_ids: decision.computed_selected_memory_ids,
      returned_selected_memory_ids: decision.returned_selected_memory_ids,
      feature_counts: decision.feature_counts,
    },
    recall_receipt: {
      merkle_schema: receipt.merkle_schema,
      merkle_root: receipt.merkle_root,
      reconstructed_merkle_root: reconstructedRoot,
      evidence_count: receipt.evidence.length,
      event_id: receipt.event_receipt.event_id,
      event_mutation_hash: receipt.event_receipt.mutation_hash,
    },
  };
  const signedArtifact = await signAsHousekeeper(body);
  const pubkey = await signerPubkey(signedArtifact);
  const verified = verifyStoredPayloadSig(
    pubkey,
    signedArtifact.body,
    signedArtifact.nonce,
    signedArtifact.signedTs,
    signedArtifact.sigB64u,
  );
  assert(verified.valid, `tp_g2_artifact_signature_invalid:${verified.reason}`);

  const artifact = {
    body: signedArtifact.body,
    signer: {
      agent_id: signedArtifact.agentId,
      valid_from: signedArtifact.validFromIso,
      identity_tier: signedArtifact.identityTier,
      certificate_sha256: sha256(signedArtifact.certString),
    },
    nonce: signedArtifact.nonce,
    ts_signed: signedArtifact.signedTs,
    sig_form: signedArtifact.sigForm,
    signature: signedArtifact.sigB64u,
  };
  const written = writeExclusive(`tp-g2-signed-policy-proof-${ceremonyId}.json`, artifact);
  console.log(JSON.stringify({ success: true, artifact: written }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || String(error)}`);
  process.exitCode = 1;
}).finally(async () => {
  try { await pool.end(); } catch { /* ignore */ }
});
