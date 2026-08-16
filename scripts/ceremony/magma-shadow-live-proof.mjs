#!/usr/bin/env node

/**
 * MAGMA signed shadow proof.
 *
 * Runs twenty housekeeper-envelope recalls through the canonical live route.
 * It proves the signed MAGMA shadow policy is consumed, baseline disclosure is
 * unchanged by the graph candidate, graph decisions and security closures are
 * receipted, and native candidate p95 remains under the preregistered ceiling.
 * It reports server background readiness independently and never bypasses an
 * incomplete Genesis corpus.
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
import { validateMagmaRetrievalPolicy } from '../../services/security/system-config-ledger.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const LIVE = process.argv.includes('--live');
const POLICY_KEY = 'MAGMA_RETRIEVAL_POLICY';
const SAMPLE_COUNT = 20;
const EXPECTED_PROOF_SHA256 = '52134f1d254174113bfaa92bd34e2317f45702d058e891de51ddd203367751b7';
const EXPECTED_RUNNER_SHA256 = 'c3094713c6816685dbd332dfc89a1ae51c4d2b561265f28efb761ed532ee1877';
const ARTIFACT_DIRECTORY = path.join(ROOT, 'artifacts', 'graph-readiness', 'magma', 'shadow');
const QUERIES = Object.freeze([
  'What is the HOM-AIMOS full-retention security policy?',
  'How are recalled memories bound to signed provenance?',
  'Why are poisoned memories retained and labeled instead of deleted?',
  'How does the housekeeper govern authorized memory changes?',
  'What evidence protects a recall from unauthorized graph expansion?',
]);

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function p95(values) {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(ordered.length * 0.95) - 1)];
}

function assertNoEmbeddingKey(value, trail = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoEmbeddingKey(entry, `${trail}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    assert(key !== 'embedding', `magma_shadow_raw_embedding_exposed:${trail}.${key}`);
    assertNoEmbeddingKey(entry, `${trail}.${key}`);
  }
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

async function signerPubkey(signed) {
  const result = await pool.query(
    `SELECT pubkey
       FROM public.agent_identity
      WHERE agent_id = $1
        AND valid_from = $2::timestamptz`,
    [signed.agentId, signed.validFromIso],
  );
  assert(result.rows.length === 1, 'magma_shadow_housekeeper_epoch_missing');
  return result.rows[0].pubkey;
}

async function signedRecall(queryText) {
  const route = '/aimos/recall';
  const body = {
    company_id: 'hom',
    agent_id: 'housekeeper',
    q: queryText,
    limit: 20,
    clearance_level: 12,
    cache: false,
    semantic_cache: false,
    early_exit: false,
  };
  const signed = await signAsHousekeeper(body, { method: 'POST', path: route });
  const startedAt = performance.now();
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
    signal: AbortSignal.timeout(180_000),
  });
  const result = await response.json().catch(() => ({}));
  const roundTripMs = Number((performance.now() - startedAt).toFixed(3));
  assert(response.ok && result.success === true, `magma_shadow_recall_failed:${response.status}:${JSON.stringify(result)}`);
  return { result, roundTripMs };
}

async function main() {
  await systemConfigStore.loadAll();
  const policyEntry = systemConfigStore.readVerifiedConfig(POLICY_KEY);
  assert(policyEntry, 'magma_shadow_verified_policy_missing');
  const validated = validateMagmaRetrievalPolicy(policyEntry.value);
  assert(validated.ok, `magma_shadow_policy_invalid:${validated.reason}`);
  assert(validated.policy.execution === 'shadow', 'magma_shadow_policy_not_shadow');
  assert(validated.policy.proof_sha256 === EXPECTED_PROOF_SHA256, 'magma_shadow_proof_identity_mismatch');
  assert(validated.policy.runner_sha256 === EXPECTED_RUNNER_SHA256, 'magma_shadow_runner_identity_mismatch');
  assert(/^[0-9a-f]{64}$/.test(String(policyEntry.mutation_hash || '')), 'magma_shadow_policy_mutation_hash_invalid');

  const healthResponse = await fetch(`${AIMOS_HTTP_ORIGIN}/health`, { signal: AbortSignal.timeout(15_000) });
  assert(healthResponse.ok, 'magma_shadow_server_health_transport_failed');
  const health = await healthResponse.json();
  const prerequisites = {
    server_origin: AIMOS_HTTP_ORIGIN,
    server_transport_reachable: true,
    server_background_ready: health.ready === true,
    server_boot_error: health.bootError || null,
    database: health.runtime?.database_name || null,
    policy: validated.policy,
    policy_mutation_hash: policyEntry.mutation_hash,
    ceremony_source_sha256: sha256(fs.readFileSync(SCRIPT_FILE)),
  };
  console.log(JSON.stringify({ mode: LIVE ? 'LIVE' : 'DRY_RUN', prerequisites }, null, 2));
  if (!LIVE) return;

  const observations = [];
  const byQuery = new Map();
  for (let ordinal = 0; ordinal < SAMPLE_COUNT; ordinal += 1) {
    const queryText = QUERIES[ordinal % QUERIES.length];
    const { result, roundTripMs } = await signedRecall(queryText);
    assertNoEmbeddingKey(result);
    const magma = result.recall_meta?.magma_retrieval;
    assert(magma?.execution === 'shadow', `magma_shadow_metadata_missing:${ordinal}`);
    assert(magma.policy_mutation_hash === policyEntry.mutation_hash, `magma_shadow_policy_hash_mismatch:${ordinal}`);
    assert(magma.proof_sha256 === EXPECTED_PROOF_SHA256, `magma_shadow_proof_hash_mismatch:${ordinal}`);
    assert(magma.runner_sha256 === EXPECTED_RUNNER_SHA256, `magma_shadow_runner_hash_mismatch:${ordinal}`);
    assert(magma.shadow_disclosure_changed === false, `magma_shadow_disclosure_flag_invalid:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(magma.decision?.decision_sha256 || '')), `magma_shadow_decision_hash_missing:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(magma.decision?.edge_commitment_sha256 || '')), `magma_shadow_edge_hash_missing:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(magma.shadow_security_receipt?.mutation_hash || '')), `magma_shadow_security_receipt_missing:${ordinal}`);
    assert(result.memories.every((memory) => !Number.isFinite(Number(memory?.magma_score))), `magma_shadow_changed_returned_candidate:${ordinal}`);
    assert(result.recall_receipt?.event_receipt?.mutation_hash, `magma_shadow_recall_receipt_missing:${ordinal}`);
    assert(Number.isFinite(Number(magma.candidate_runtime_ms)), `magma_shadow_runtime_missing:${ordinal}`);

    const returnedIds = result.memories.map((memory) => String(memory.id));
    const computedIds = magma.decision.selected_memory_ids;
    const prior = byQuery.get(queryText);
    if (prior) {
      assert(canonicalJson(prior.returnedIds) === canonicalJson(returnedIds), `magma_shadow_baseline_nondeterministic:${ordinal}`);
      assert(canonicalJson(prior.computedIds) === canonicalJson(computedIds), `magma_shadow_candidate_nondeterministic:${ordinal}`);
    } else {
      byQuery.set(queryText, { returnedIds, computedIds });
    }
    observations.push({
      ordinal,
      query_sha256: sha256(queryText),
      returned_memory_ids: returnedIds,
      computed_memory_ids: computedIds,
      decision_sha256: magma.decision.decision_sha256,
      edge_commitment_sha256: magma.decision.edge_commitment_sha256,
      security_receipt_mutation_hash: magma.shadow_security_receipt.mutation_hash,
      recall_receipt_mutation_hash: result.recall_receipt.event_receipt.mutation_hash,
      candidate_runtime_ms: Number(magma.candidate_runtime_ms),
      round_trip_ms: roundTripMs,
    });
    console.log(JSON.stringify({
      event: 'magma_shadow_observation',
      completed: ordinal + 1,
      total: SAMPLE_COUNT,
      candidate_runtime_ms: Number(magma.candidate_runtime_ms),
      decision_sha256: magma.decision.decision_sha256,
    }));
  }

  const candidateRuntimes = observations.map((row) => row.candidate_runtime_ms);
  const candidateP95 = Number(p95(candidateRuntimes).toFixed(3));
  const graphPass = candidateP95 <= validated.policy.candidate_p95_ceiling_ms;
  assert(graphPass, `magma_shadow_native_p95_exceeded:${candidateP95}`);

  const ceremonyId = randomUUID();
  const body = {
    schema: 'hom.aimos.magma-shadow-live-proof/v1',
    ceremony_id: ceremonyId,
    prerequisites,
    sample_count: SAMPLE_COUNT,
    fixed_queries: QUERIES.map((queryText) => ({ query_sha256: sha256(queryText) })),
    verification: {
      signed_agent_or_role_envelope: true,
      housekeeper_governance: true,
      shadow_disclosure_changed: false,
      candidate_deterministic_per_query: true,
      baseline_disclosure_deterministic_per_query: true,
      canary_aladdin_security_receipts_present: true,
      saber_runtime_authority: false,
      raw_embedding_exposed: false,
      native_candidate_p95_ms: candidateP95,
      preregistered_ceiling_ms: validated.policy.candidate_p95_ceiling_ms,
      native_candidate_latency_pass: graphPass,
      server_background_ready: health.ready === true,
      server_background_readiness_reason: health.bootError || null,
    },
    observations,
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
  assert(verified.valid, `magma_shadow_artifact_signature_invalid:${verified.reason}`);
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
  const written = writeExclusive(`magma-shadow-live-proof-${ceremonyId}.json`, artifact);
  console.log(JSON.stringify({
    success: true,
    graph_shadow_passed: true,
    server_background_ready: health.ready === true,
    server_boot_error: health.bootError || null,
    artifact: written,
  }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || String(error)}`);
  process.exitCode = 1;
}).finally(async () => {
  try { await pool.end(); } catch { /* ignore */ }
});
