#!/usr/bin/env node

/**
 * MAGMA enforce-mode live authority proof.
 *
 * Runs twenty housekeeper-envelope recalls through the canonical live route.
 * It proves the master-signed enforce policy is consumed, MAGMA's selected set
 * becomes the input to downstream epistemic/Canary/Aladdin disclosure control,
 * every returned memory remains inside the MAGMA decision, final recall
 * receipts are present, repeated queries are deterministic, and candidate p95
 * remains below the preregistered ceiling.
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
const ARTIFACT_DIRECTORY = path.join(ROOT, 'artifacts', 'graph-readiness', 'magma', 'enforce');
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

function normalizeIds(values) {
  return (Array.isArray(values) ? values : []).map((value) =>
    String(value?.id || value?.memory_id || value || '').trim().toLowerCase()
  ).filter(Boolean);
}

function assertNoEmbeddingKey(value, trail = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoEmbeddingKey(entry, `${trail}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    assert(key !== 'embedding', `magma_enforce_raw_embedding_exposed:${trail}.${key}`);
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
  assert(result.rows.length === 1, 'magma_enforce_housekeeper_epoch_missing');
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
    answer_shape: 'full_detail',
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
  assert(response.ok && result.success === true, `magma_enforce_recall_failed:${response.status}:${JSON.stringify(result)}`);
  return { result, roundTripMs };
}

async function main() {
  await systemConfigStore.loadAll();
  const policyEntry = systemConfigStore.readVerifiedConfig(POLICY_KEY);
  assert(policyEntry, 'magma_enforce_verified_policy_missing');
  const validated = validateMagmaRetrievalPolicy(policyEntry.value);
  assert(validated.ok, `magma_enforce_policy_invalid:${validated.reason}`);
  assert(validated.policy.execution === 'enforce', 'magma_enforce_policy_not_enforce');
  assert(validated.policy.proof_sha256 === EXPECTED_PROOF_SHA256, 'magma_enforce_proof_identity_mismatch');
  assert(validated.policy.runner_sha256 === EXPECTED_RUNNER_SHA256, 'magma_enforce_runner_identity_mismatch');
  assert(/^[0-9a-f]{64}$/.test(String(policyEntry.mutation_hash || '')), 'magma_enforce_policy_mutation_hash_invalid');

  const healthResponse = await fetch(`${AIMOS_HTTP_ORIGIN}/health`, { signal: AbortSignal.timeout(15_000) });
  assert(healthResponse.ok, 'magma_enforce_server_health_transport_failed');
  const health = await healthResponse.json();
  assert(health.ready === true, `magma_enforce_server_not_ready:${health.bootError || 'unknown'}`);
  const prerequisites = {
    server_origin: AIMOS_HTTP_ORIGIN,
    server_transport_reachable: true,
    server_background_ready: true,
    server_boot_error: null,
    database: health.runtime?.database_name || null,
    policy: validated.policy,
    policy_mutation_hash: policyEntry.mutation_hash,
    ceremony_source_sha256: sha256(fs.readFileSync(SCRIPT_FILE)),
  };
  console.log(JSON.stringify({ mode: LIVE ? 'LIVE' : 'DRY_RUN', prerequisites }, null, 2));
  if (!LIVE) return;

  const observations = [];
  const byQuery = new Map();
  let authoritativeDivergenceCount = 0;
  for (let ordinal = 0; ordinal < SAMPLE_COUNT; ordinal += 1) {
    const queryText = QUERIES[ordinal % QUERIES.length];
    const { result, roundTripMs } = await signedRecall(queryText);
    assertNoEmbeddingKey(result);
    const magma = result.recall_meta?.magma_retrieval;
    const closure = result.recall_meta?.magma_security_closure;
    const epistemic = result.recall_meta?.epistemic_retrieval;
    assert(magma?.execution === 'enforce', `magma_enforce_metadata_missing:${ordinal}`);
    assert(magma.policy_mutation_hash === policyEntry.mutation_hash, `magma_enforce_policy_hash_mismatch:${ordinal}`);
    assert(magma.proof_sha256 === EXPECTED_PROOF_SHA256, `magma_enforce_proof_hash_mismatch:${ordinal}`);
    assert(magma.runner_sha256 === EXPECTED_RUNNER_SHA256, `magma_enforce_runner_hash_mismatch:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(magma.decision?.decision_sha256 || '')), `magma_enforce_decision_hash_missing:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(magma.decision?.edge_commitment_sha256 || '')), `magma_enforce_edge_hash_missing:${ordinal}`);
    assert(closure?.graph_id === 'magma', `magma_enforce_security_closure_missing:${ordinal}`);
    assert(closure.graph_decision_sha256 === magma.decision.decision_sha256, `magma_enforce_closure_decision_mismatch:${ordinal}`);
    assert(closure.graph_edge_commitment_sha256 === magma.decision.edge_commitment_sha256, `magma_enforce_closure_edge_mismatch:${ordinal}`);
    assert(closure.canonical_memory_changed === false, `magma_enforce_canonical_memory_changed:${ordinal}`);
    assert(closure.retention_changed === false, `magma_enforce_retention_changed:${ordinal}`);
    assert(closure.saber_runtime_authority === false, `magma_enforce_saber_authority_invalid:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(closure.receipt?.mutation_hash || '')), `magma_enforce_security_receipt_missing:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(epistemic?.decision_receipt?.mutation_hash || '')), `magma_enforce_epistemic_receipt_missing:${ordinal}`);
    assert(result.recall_receipt?.event_receipt?.mutation_hash, `magma_enforce_recall_receipt_missing:${ordinal}`);
    assert(Number.isFinite(Number(magma.candidate_runtime_ms)), `magma_enforce_runtime_missing:${ordinal}`);

    const returnedIds = normalizeIds(result.memories);
    const selectedIds = normalizeIds(magma.decision.selected_memory_ids);
    const baselineIds = normalizeIds(magma.baseline_candidate_memory_ids);
    assert(returnedIds.length > 0, `magma_enforce_empty_disclosure:${ordinal}`);
    const selectedSet = new Set(selectedIds);
    assert(returnedIds.every((id) => selectedSet.has(id)), `magma_enforce_returned_outside_graph_selection:${ordinal}`);
    assert(result.memories.every((memory) => !Number.isFinite(Number(memory?.magma_score))), `magma_enforce_internal_score_exposed:${ordinal}`);
    const selectionDiffers = canonicalJson(selectedIds) !== canonicalJson(baselineIds);
    if (selectionDiffers) authoritativeDivergenceCount += 1;

    const prior = byQuery.get(queryText);
    if (prior) {
      assert(canonicalJson(prior.returnedIds) === canonicalJson(returnedIds), `magma_enforce_disclosure_nondeterministic:${ordinal}`);
      assert(canonicalJson(prior.selectedIds) === canonicalJson(selectedIds), `magma_enforce_candidate_nondeterministic:${ordinal}`);
    } else {
      byQuery.set(queryText, { returnedIds, selectedIds });
    }
    observations.push({
      ordinal,
      query_sha256: sha256(queryText),
      returned_memory_ids: returnedIds,
      selected_memory_ids: selectedIds,
      baseline_candidate_memory_ids: baselineIds,
      authoritative_selection_differs_from_baseline: selectionDiffers,
      decision_sha256: magma.decision.decision_sha256,
      edge_commitment_sha256: magma.decision.edge_commitment_sha256,
      epistemic_receipt_mutation_hash: epistemic.decision_receipt.mutation_hash,
      security_receipt_mutation_hash: closure.receipt.mutation_hash,
      recall_receipt_mutation_hash: result.recall_receipt.event_receipt.mutation_hash,
      candidate_runtime_ms: Number(magma.candidate_runtime_ms),
      candidate_runtime_breakdown_ms: magma.candidate_runtime_breakdown_ms,
      round_trip_ms: roundTripMs,
    });
    console.log(JSON.stringify({
      event: 'magma_enforce_observation',
      completed: ordinal + 1,
      total: SAMPLE_COUNT,
      candidate_runtime_ms: Number(magma.candidate_runtime_ms),
      candidate_runtime_breakdown_ms: magma.candidate_runtime_breakdown_ms,
      authoritative_selection_differs_from_baseline: selectionDiffers,
      decision_sha256: magma.decision.decision_sha256,
    }));
  }

  assert(authoritativeDivergenceCount > 0, 'magma_enforce_no_authoritative_selection_divergence_observed');
  const candidateP95 = Number(p95(observations.map((row) => row.candidate_runtime_ms)).toFixed(3));
  const roundTripP95 = Number(p95(observations.map((row) => row.round_trip_ms)).toFixed(3));
  assert(candidateP95 <= validated.policy.candidate_p95_ceiling_ms, `magma_enforce_native_p95_exceeded:${candidateP95}`);

  const ceremonyId = randomUUID();
  const body = {
    schema: 'hom.aimos.magma-enforce-live-proof/v1',
    ceremony_id: ceremonyId,
    prerequisites,
    sample_count: SAMPLE_COUNT,
    fixed_queries: QUERIES.map((queryText) => ({ query_sha256: sha256(queryText) })),
    verification: {
      signed_agent_or_role_envelope: true,
      housekeeper_governance: true,
      magma_authoritative_for_candidate_selection: true,
      authoritative_divergence_count: authoritativeDivergenceCount,
      returned_memories_subset_of_magma_selection: true,
      candidate_deterministic_per_query: true,
      disclosure_deterministic_per_query: true,
      epistemic_canary_aladdin_receipts_present: true,
      saber_runtime_authority: false,
      canonical_memory_changed: false,
      retention_changed: false,
      raw_embedding_exposed: false,
      internal_magma_score_exposed: false,
      native_candidate_p95_ms: candidateP95,
      preregistered_ceiling_ms: validated.policy.candidate_p95_ceiling_ms,
      native_candidate_latency_pass: true,
      end_to_end_round_trip_p95_ms: roundTripP95,
      server_background_ready: true,
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
  assert(verified.valid, `magma_enforce_artifact_signature_invalid:${verified.reason}`);
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
  const written = writeExclusive(`magma-enforce-live-proof-${ceremonyId}.json`, artifact);
  console.log(JSON.stringify({
    success: true,
    graph_enforce_passed: true,
    artifact: written,
  }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || String(error)}`);
  process.exitCode = 1;
}).finally(async () => {
  try { await pool.end(); } catch { /* ignore */ }
});
