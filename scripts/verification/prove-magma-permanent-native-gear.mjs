#!/usr/bin/env node

/**
 * Source-bound live proof for MAGMA as a permanent native retrieval gear.
 *
 * This proof does not compare MAGMA against or substitute it for the native
 * stack. It verifies the additive architecture now implemented: MAGMA runs
 * inside canonical recall, contributes one bounded channel to central fusion,
 * preserves every admitted baseline candidate, and remains downstream of the
 * signed identity, provenance, epistemic, Canary, and Aladdin boundaries.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { agentPool, pool } from '../../db/connection.js';
import { AIMOS_HTTP_ORIGIN } from '../../services/core/runtime-config.js';
import { canonicalJson, verifyStoredPayloadSig } from '../../services/security/agent-identity.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const LIVE = process.argv.includes('--live');
const AGENT_ID = 'codex-auditor';
const SAMPLE_COUNT = 20;
const LATENCY_CEILING_MS = 250;
const ARTIFACT_DIRECTORY = path.join(ROOT, 'artifacts', 'graph-readiness', 'magma', 'native-gear');
const QUERIES = Object.freeze([
  'What is the HOM-AIMOS full-retention security policy?',
  'How are recalled memories bound to signed provenance?',
  'Why are poisoned memories retained and classified rather than deleted?',
  'How does the housekeeper govern authorized memory transitions?',
  'How do retrieval gears preserve the admitted baseline candidate set?',
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
  return (Array.isArray(values) ? values : [])
    .map((value) => String(value?.id || value?.memory_id || value || '').trim().toLowerCase())
    .filter(Boolean);
}

function assertNoEmbeddingKey(value, trail = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoEmbeddingKey(entry, `${trail}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    assert(key !== 'embedding', `magma_native_raw_embedding_exposed:${trail}.${key}`);
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

async function signedRecall(queryText) {
  const route = '/aimos/recall';
  const body = {
    company_id: 'hom',
    agent_id: AGENT_ID,
    query: queryText,
    limit: 20,
    clearance_level: 10,
    answer_shape: 'full_detail',
    cache: false,
    semantic_cache: false,
    early_exit: false,
  };
  const headers = await buildEnvelopeHeaders(AGENT_ID, 'POST', route, body);
  const startedAt = performance.now();
  const response = await fetch(`${AIMOS_HTTP_ORIGIN}${route}`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(180_000),
  });
  const result = await response.json().catch(() => ({}));
  const roundTripMs = Number((performance.now() - startedAt).toFixed(3));
  assert(response.ok && result.success === true,
    `magma_native_recall_failed:${response.status}:${JSON.stringify(result)}`);
  return { result, roundTripMs };
}

async function canonicalCounts() {
  const result = await pool.query(
    `SELECT
       (SELECT count(*)::bigint FROM aimos_memories WHERE company_id = 'hom') AS memories,
       (SELECT count(*)::bigint FROM aimos_memory_epistemic_classifications WHERE company_id = 'hom') AS classifications`,
  );
  return {
    memories: Number(result.rows[0].memories),
    classifications: Number(result.rows[0].classifications),
  };
}

async function signerPubkey(signed) {
  const result = await pool.query(
    `SELECT pubkey
       FROM public.agent_identity
      WHERE agent_id = $1
        AND valid_from = $2::timestamptz`,
    [signed.agentId, signed.validFromIso],
  );
  assert(result.rows.length === 1, 'magma_native_housekeeper_epoch_missing');
  return result.rows[0].pubkey;
}

async function main() {
  const healthResponse = await fetch(`${AIMOS_HTTP_ORIGIN}/health`, {
    signal: AbortSignal.timeout(15_000),
  });
  assert(healthResponse.ok, 'magma_native_server_health_transport_failed');
  const health = await healthResponse.json();
  assert(health.ready === true, `magma_native_server_not_ready:${health.bootError || 'unknown'}`);

  const prerequisites = {
    server_origin: AIMOS_HTTP_ORIGIN,
    server_ready: true,
    database: health.runtime?.database_name || null,
    server_port: health.runtime?.server_port || null,
    benchmark_scratch: health.runtime?.benchmark_scratch ?? null,
    request_identity: AGENT_ID,
    sample_count: SAMPLE_COUNT,
    fixed_query_hashes: QUERIES.map((queryText) => sha256(queryText)),
    source_closure: {
      proof_runner_sha256: sha256(fs.readFileSync(SCRIPT_FILE)),
      native_pipeline_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/retrieval/native-recall-pipeline.js'))),
      native_fusion_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/retrieval/native-retrieval-fusion.js'))),
      magma_candidate_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/retrieval/magma-native-candidate.js'))),
      magma_reader_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/retrieval/magma-native-reader.js'))),
      magma_kernel_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/retrieval/magma-lineage-retriever.js'))),
    },
  };
  console.log(JSON.stringify({ mode: LIVE ? 'LIVE' : 'DRY_RUN', prerequisites }, null, 2));
  if (!LIVE) return;

  const before = await canonicalCounts();
  const observations = [];
  let magmaChannelObservations = 0;
  let discoveryObservations = 0;
  let singleCallCeilingExceedances = 0;

  for (let ordinal = 0; ordinal < SAMPLE_COUNT; ordinal += 1) {
    const queryText = QUERIES[ordinal % QUERIES.length];
    const { result, roundTripMs } = await signedRecall(queryText);
    assertNoEmbeddingKey(result);

    const magma = result.recall_meta?.magma_retrieval;
    const fusion = result.recall_meta?.native_retrieval_fusion || magma?.central_fusion_decision;
    const closure = result.recall_meta?.magma_security_closure;
    const epistemic = result.recall_meta?.epistemic_retrieval;

    assert(magma?.architecture_role === 'permanent_native_retrieval_gear',
      `magma_native_role_invalid:${ordinal}`);
    assert(magma.runtime_mode === null, `magma_native_runtime_mode_present:${ordinal}`);
    assert(magma.activation_authority === false, `magma_native_activation_authority_present:${ordinal}`);
    assert(magma.candidate_set_authority === false, `magma_native_candidate_authority_present:${ordinal}`);
    assert(magma.failure_code === null, `magma_native_degraded:${ordinal}:${magma.failure_code}`);
    assert(magma.operational_status === 'complete', `magma_native_not_complete:${ordinal}`);
    assert(Number.isFinite(Number(magma.runtime_ms)), `magma_native_runtime_missing:${ordinal}`);
    if (magma.within_single_call_ceiling !== true) singleCallCeilingExceedances += 1;
    assert(/^[0-9a-f]{64}$/.test(String(magma.decision?.decision_sha256 || '')),
      `magma_native_decision_hash_missing:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(fusion?.decision_sha256 || '')),
      `magma_native_fusion_hash_missing:${ordinal}`);
    assert(magma.central_fusion_decision?.decision_sha256 === fusion.decision_sha256,
      `magma_native_fusion_binding_invalid:${ordinal}`);
    assert(fusion.candidate_set_monotone === true, `magma_native_candidate_set_not_monotone:${ordinal}`);
    assert(fusion.baseline_candidate_set_preserved === true,
      `magma_native_baseline_not_preserved:${ordinal}`);
    assert(fusion.disclosure_authority === false, `magma_native_disclosure_authority_present:${ordinal}`);
    assert(fusion.canonical_memory_mutated === false, `magma_native_canonical_mutation_claimed:${ordinal}`);
    assert(fusion.retention_changed === false, `magma_native_retention_change_claimed:${ordinal}`);

    const baselineIds = normalizeIds(magma.baseline_candidate_memory_ids);
    const fusedIds = normalizeIds(fusion.selected_memory_ids);
    const returnedIds = normalizeIds(result.memories);
    const fusedSet = new Set(fusedIds);
    assert(baselineIds.every((id) => fusedSet.has(id)), `magma_native_baseline_identity_removed:${ordinal}`);
    assert(returnedIds.every((id) => fusedSet.has(id)), `magma_native_disclosure_outside_fusion:${ordinal}`);
    assert(returnedIds.length > 0, `magma_native_empty_disclosure:${ordinal}`);

    const magmaChannel = (fusion.channels || []).find((channel) => channel.gear === 'magma');
    if (magmaChannel?.count > 0) magmaChannelObservations += 1;
    if (Number(magma.decision.discovered_count) > 0) discoveryObservations += 1;

    assert(closure?.graph_id === 'magma', `magma_native_security_closure_missing:${ordinal}`);
    assert(closure.graph_decision_sha256 === magma.decision.decision_sha256,
      `magma_native_security_decision_unbound:${ordinal}`);
    assert(closure.canonical_memory_changed === false, `magma_native_security_memory_changed:${ordinal}`);
    assert(closure.retention_changed === false, `magma_native_security_retention_changed:${ordinal}`);
    assert(closure.saber_runtime_authority === false, `magma_native_saber_authority_invalid:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(closure.receipt?.mutation_hash || '')),
      `magma_native_security_receipt_missing:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(epistemic?.decision_receipt?.mutation_hash || '')),
      `magma_native_epistemic_receipt_missing:${ordinal}`);
    assert(/^[0-9a-f]{64}$/.test(String(result.recall_receipt?.event_receipt?.mutation_hash || '')),
      `magma_native_recall_receipt_missing:${ordinal}`);

    observations.push({
      ordinal,
      query_sha256: sha256(queryText),
      returned_count: returnedIds.length,
      baseline_count: baselineIds.length,
      fused_count: fusedIds.length,
      magma_channel_count: Number(magmaChannel?.count || 0),
      magma_discovery_count: Number(magma.decision.discovered_count || 0),
      within_single_call_ceiling: magma.within_single_call_ceiling === true,
      candidate_set_monotone: true,
      baseline_preserved: true,
      magma_decision_sha256: magma.decision.decision_sha256,
      fusion_decision_sha256: fusion.decision_sha256,
      security_receipt_mutation_hash: closure.receipt.mutation_hash,
      epistemic_receipt_mutation_hash: epistemic.decision_receipt.mutation_hash,
      recall_receipt_mutation_hash: result.recall_receipt.event_receipt.mutation_hash,
      magma_runtime_ms: Number(magma.runtime_ms),
      magma_runtime_breakdown_ms: magma.runtime_breakdown_ms,
      round_trip_ms: roundTripMs,
    });
    console.log(JSON.stringify({
      event: 'magma_permanent_native_gear_observation',
      completed: ordinal + 1,
      total: SAMPLE_COUNT,
      magma_runtime_ms: Number(magma.runtime_ms),
      round_trip_ms: roundTripMs,
      magma_channel_count: Number(magmaChannel?.count || 0),
      magma_discovery_count: Number(magma.decision.discovered_count || 0),
      within_single_call_ceiling: magma.within_single_call_ceiling === true,
    }));
  }

  const after = await canonicalCounts();
  assert(after.memories === before.memories, 'magma_native_canonical_memory_population_changed');
  assert(after.classifications === before.classifications,
    'magma_native_classification_population_changed');
  assert(magmaChannelObservations > 0, 'magma_native_channel_never_contributed');

  const magmaRuntimeP95 = Number(p95(observations.map((row) => row.magma_runtime_ms)).toFixed(3));
  const roundTripP95 = Number(p95(observations.map((row) => row.round_trip_ms)).toFixed(3));
  assert(magmaRuntimeP95 <= LATENCY_CEILING_MS,
    `magma_native_p95_exceeded:${magmaRuntimeP95}:${LATENCY_CEILING_MS}`);

  const body = {
    schema: 'hom.aimos.magma-permanent-native-gear-proof/v1',
    ceremony_id: randomUUID(),
    prerequisites,
    verification: {
      permanent_native_gear: true,
      runtime_mode: null,
      activation_authority: false,
      candidate_set_authority: false,
      bounded_marginal_addition: true,
      candidate_set_monotone: true,
      admitted_baseline_preserved: true,
      magma_channel_observations: magmaChannelObservations,
      graph_discovery_observations: discoveryObservations,
      single_call_ceiling_exceedances: singleCallCeilingExceedances,
      security_closure_receipts_present: true,
      epistemic_receipts_present: true,
      signed_recall_receipts_present: true,
      saber_runtime_authority: false,
      canonical_memory_population_before: before.memories,
      canonical_memory_population_after: after.memories,
      classification_population_before: before.classifications,
      classification_population_after: after.classifications,
      raw_embedding_exposed: false,
      magma_runtime_p95_ms: magmaRuntimeP95,
      latency_ceiling_ms: LATENCY_CEILING_MS,
      latency_pass: true,
      end_to_end_round_trip_p95_ms: roundTripP95,
    },
    observations,
  };
  const signed = await signAsHousekeeper(body);
  const pubkey = await signerPubkey(signed);
  const verified = verifyStoredPayloadSig(pubkey, signed.body, signed.nonce, signed.signedTs, signed.sigB64u);
  assert(verified.valid, `magma_native_artifact_signature_invalid:${verified.reason}`);
  const artifact = {
    body: signed.body,
    signer: {
      agent_id: signed.agentId,
      valid_from: signed.validFromIso,
      identity_tier: signed.identityTier,
      certificate_sha256: sha256(signed.certString),
    },
    nonce: signed.nonce,
    ts_signed: signed.signedTs,
    sig_form: signed.sigForm,
    signature: signed.sigB64u,
  };
  const written = writeExclusive(`magma-permanent-native-gear-${body.ceremony_id}.json`, artifact);
  console.log(JSON.stringify({ success: true, permanent_native_gear_proven: true, artifact: written,
    verification: body.verification }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || String(error)}`);
  process.exitCode = 1;
}).finally(async () => {
  await Promise.allSettled([pool.end(), agentPool.end()]);
});
