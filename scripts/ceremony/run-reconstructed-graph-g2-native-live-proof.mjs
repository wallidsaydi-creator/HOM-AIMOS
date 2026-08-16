#!/usr/bin/env node

/**
 * Reconstructed Graph G2 native full-live-system proof.
 *
 * Executes a fixed, preregistered set of signed read-only recalls through the
 * canonical HOM-AIMOS HTTP route. The proof verifies that G2 is one bounded
 * subgear inside the existing single graph-family channel, that every native
 * security closure and final receipt is present, and that canonical memory,
 * provenance, and epistemic-classification state remain unchanged.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool } from '../../db/connection.js';
import { AIMOS_HTTP_ORIGIN } from '../../services/core/runtime-config.js';
import {
  canonicalJson,
  getAgentCert,
  loadAgentPrivkey,
  signPayload,
  verifyStoredPayloadSig,
} from '../../services/security/agent-identity.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { recallAuthorizationService } from '../../services/security/recall-authorization.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const LIVE = process.argv.includes('--live');
const AGENT_ID = 'codex-auditor';
const COMPANY_ID = 'hom';
const SAMPLE_COUNT = 20;
const G2_TOTAL_P95_CEILING_MS = 50;
const FIXED_PROOF_FILE_SHA256 = 'a62e0f31fdf9b565209c70d8a5d764ab78bc5bb7a684dc0595b651046899dc50';
const FIXED_PROOF_SUMMARY_SHA256 = 'b6688996d37aec1ad1c6abf45e3ef8a98674f1291439195d8d4f47e73e293bd9';
const PREREGISTRATION = path.join(
  ROOT,
  'plans',
  'Codex',
  'active',
  'graphs',
  'RECONSTRUCTED-GRAPH-G2-NATIVE-LIVE-PROOF-PREREGISTRATION-20260816-V7.json',
);
const OUTPUT_DIRECTORY = path.join(
  ROOT,
  'artifacts',
  'graph-readiness',
  'reconstructed-graph',
  'g2-native-live',
);
const SOURCE_FILES = Object.freeze([
  'scripts/ceremony/run-reconstructed-graph-g2-native-live-proof.mjs',
  'services/retrieval/native-recall-pipeline.js',
  'services/retrieval/reconstructed-graph-native-candidate.js',
  'services/retrieval/reconstructed-graph-additive/reconstructed-graph-marginal-gear.js',
  'services/retrieval/reconstructed-graph-additive/graph-family-bounded-fusion.js',
  'services/retrieval/reconstructed-graph-grounded-candidate.js',
  'services/retrieval/native-retrieval-fusion.js',
  'services/retrieval/magma-native-candidate.js',
  'services/security/canary-tracker.js',
  'services/security/recall-authorization.js',
]);
const QUERIES = Object.freeze([
  'How does HOM-AIMOS retain suspicious memory while preventing unsafe disclosure?',
  'How are recalled memories bound to signed provenance and final recall receipts?',
  'How do the native retrieval gears cooperate without one graph replacing the candidate set?',
  'What role do Canary, SABER, and Aladdin play after graph-family retrieval?',
  'How does the housekeeper authorize memory changes while preserving historical continuity?',
]);

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fileSha256(file) {
  return sha256(fs.readFileSync(file));
}

function hex64(value) {
  return /^[0-9a-f]{64}$/.test(String(value || '').trim().toLowerCase());
}

function percentile(values, probability) {
  const ordered = values.map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  assert(ordered.length > 0, 'reconstructed_g2_live_latency_population_empty');
  return ordered[Math.max(0, Math.ceil(ordered.length * probability) - 1)];
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
    assert(key !== 'embedding', `reconstructed_g2_live_raw_embedding_exposed:${trail}.${key}`);
    assertNoEmbeddingKey(entry, `${trail}.${key}`);
  }
}

function sourceManifest() {
  return SOURCE_FILES.map((relativePath) => ({
    path: relativePath,
    sha256: fileSha256(path.join(ROOT, relativePath)),
  }));
}

function queryCommitment() {
  return sha256(canonicalJson(QUERIES.map((query) => sha256(query))));
}

function loadPreregistration() {
  assert(fs.existsSync(PREREGISTRATION), 'reconstructed_g2_live_preregistration_missing');
  const preregistration = JSON.parse(fs.readFileSync(PREREGISTRATION, 'utf8'));
  assert(
    preregistration?.schema === 'hom.aimos.reconstructed-graph-g2-native-live-preregistration/v1',
    'reconstructed_g2_live_preregistration_schema_invalid',
  );
  assert(preregistration.status === 'PREREGISTERED_BEFORE_OUTCOME', 'reconstructed_g2_live_preregistration_status_invalid');
  assert(preregistration.sample_count === SAMPLE_COUNT, 'reconstructed_g2_live_preregistered_n_mismatch');
  assert(preregistration.query_commitment_sha256 === queryCommitment(), 'reconstructed_g2_live_query_commitment_mismatch');
  assert(preregistration.gates?.g2_total_p95_ceiling_ms === G2_TOTAL_P95_CEILING_MS, 'reconstructed_g2_live_latency_gate_mismatch');
  assert(canonicalJson(preregistration.source_manifest) === canonicalJson(sourceManifest()), 'reconstructed_g2_live_source_manifest_drift');
  return preregistration;
}

async function canonicalState() {
  const [memories, provenance, classifications] = await Promise.all([
    pool.query(
      `SELECT id::text, encode(content_hash, 'hex') AS content_hash
         FROM aimos_memories
        WHERE company_id = $1
        ORDER BY id`,
      [COMPANY_ID],
    ),
    pool.query(
      `SELECT p.provenance_id::text, p.memory_id::text,
              encode(p.content_hash, 'hex') AS content_hash,
              encode(p.mutation_hash, 'hex') AS mutation_hash,
              COALESCE(encode(p.prev_mutation_hash, 'hex'), '') AS prev_mutation_hash
         FROM aimos_memory_provenance p
         JOIN aimos_memories m ON m.id = p.memory_id
        WHERE m.company_id = $1
        ORDER BY p.provenance_id`,
      [COMPANY_ID],
    ),
    pool.query(
      `SELECT classification_id::text, memory_id::text, label,
              confidence_milli, encode(classification_hash, 'hex') AS classification_hash
         FROM aimos_memory_epistemic_classifications
        WHERE company_id = $1
        ORDER BY classification_id`,
      [COMPANY_ID],
    ),
  ]);
  return Object.freeze({
    memory_count: memories.rowCount,
    memory_root_sha256: sha256(canonicalJson(memories.rows)),
    provenance_count: provenance.rowCount,
    provenance_root_sha256: sha256(canonicalJson(provenance.rows)),
    classification_count: classifications.rowCount,
    classification_root_sha256: sha256(canonicalJson(classifications.rows)),
  });
}

async function readOnlyAuthority() {
  const identity = await pool.query(
    `SELECT agent_id, valid_from, valid_until, pubkey, is_system_role
       FROM agent_identity
      WHERE agent_id = $1
      ORDER BY valid_from DESC
      LIMIT 1`,
    [AGENT_ID],
  );
  assert(identity.rowCount === 1, 'reconstructed_g2_live_agent_identity_missing');
  const row = identity.rows[0];
  assert(new Date(row.valid_until).getTime() > Date.now(), 'reconstructed_g2_live_agent_identity_expired');
  const authorization = await recallAuthorizationService.getEffective({
    companyId: COMPANY_ID,
    subjectAgentId: AGENT_ID,
    subjectValidFrom: row.valid_from,
  });
  assert(authorization?.allowed === true, 'reconstructed_g2_live_recall_authorization_missing');
  assert(authorization.writeAllowed === false, 'reconstructed_g2_live_identity_not_read_only');
  assert(authorization.clearanceCeiling >= 10, 'reconstructed_g2_live_clearance_insufficient');
  return Object.freeze({
    agent_id: row.agent_id,
    valid_from: new Date(row.valid_from).toISOString(),
    valid_until: new Date(row.valid_until).toISOString(),
    is_system_role: Boolean(row.is_system_role),
    pubkey: row.pubkey,
    recall_authorization_event_id: authorization.eventId,
    recall_authorization_mutation_hash: Buffer.from(authorization.mutationHash).toString('hex'),
    write_allowed: authorization.writeAllowed,
    clearance_ceiling: authorization.clearanceCeiling,
    data_class_ceiling: authorization.dataClassCeiling,
  });
}

async function signedRecall(queryText) {
  const route = '/aimos/recall';
  const body = {
    company_id: COMPANY_ID,
    agent_id: AGENT_ID,
    q: queryText,
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
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(180_000),
  });
  const result = await response.json().catch(() => ({}));
  const roundTripMs = Number((performance.now() - startedAt).toFixed(3));
  assert(response.ok && result.success === true, `reconstructed_g2_live_recall_failed:${response.status}:${JSON.stringify(result)}`);
  return { result, roundTripMs, certificateSha256: sha256(headers['Aimos-Agent-Cert']) };
}

async function verifySecurityClosureEvent(decision, expectedGraphId) {
  const eventId = String(decision?.receipt?.event_id || '');
  assert(eventId, `reconstructed_g2_live_${expectedGraphId}_event_id_missing`);
  const result = await pool.query(
    `SELECT operation, metadata, encode(mutation_hash, 'hex') AS mutation_hash
       FROM aimos_events
      WHERE id = $1::uuid`,
    [eventId],
  );
  assert(result.rowCount === 1, `reconstructed_g2_live_${expectedGraphId}_event_missing`);
  const event = result.rows[0];
  assert(event.operation === 'graph_security_closure', `reconstructed_g2_live_${expectedGraphId}_event_operation_invalid`);
  assert(event.mutation_hash === decision.receipt.mutation_hash, `reconstructed_g2_live_${expectedGraphId}_event_receipt_mismatch`);
  assert(event.metadata?.graph_id === expectedGraphId, `reconstructed_g2_live_${expectedGraphId}_event_graph_invalid`);
  assert(event.metadata?.aladdin?.canonical_memory_changed === false, `reconstructed_g2_live_${expectedGraphId}_event_memory_change_invalid`);
  assert(event.metadata?.aladdin?.retention_changed === false, `reconstructed_g2_live_${expectedGraphId}_event_retention_invalid`);
  assert(event.metadata?.aladdin?.deletion_performed === false, `reconstructed_g2_live_${expectedGraphId}_event_deletion_invalid`);
  assert(event.metadata?.aladdin?.suppression_performed === false, `reconstructed_g2_live_${expectedGraphId}_event_suppression_invalid`);
  assert(event.metadata?.saber?.runtime_authority === false, `reconstructed_g2_live_${expectedGraphId}_event_saber_authority_invalid`);
  return Object.freeze({
    event_id: eventId,
    mutation_hash: event.mutation_hash,
    aladdin_postconditions_valid: true,
    saber_runtime_authority: false,
  });
}

function writeExclusive(filename, value) {
  fs.mkdirSync(OUTPUT_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(OUTPUT_DIRECTORY, 0o700);
  const target = path.join(OUTPUT_DIRECTORY, filename);
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
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

async function signedArtifact(body, authority) {
  const privateKey = loadAgentPrivkey(path.join(os.homedir(), '.aimos', 'agents', `${AGENT_ID}.key`));
  const certificate = await getAgentCert(AGENT_ID);
  const nonce = randomBytes(16).toString('base64url');
  const signedTs = Math.floor(Date.now() / 1000);
  const signature = signPayload(privateKey, body, nonce, signedTs);
  const verification = verifyStoredPayloadSig(authority.pubkey, body, nonce, signedTs, signature);
  assert(verification.valid, `reconstructed_g2_live_artifact_signature_invalid:${verification.reason}`);
  return Object.freeze({
    body,
    signer: Object.freeze({
      agent_id: AGENT_ID,
      valid_from: authority.valid_from,
      is_system_role: authority.is_system_role,
      certificate_sha256: sha256(certificate),
      recall_authorization_event_id: authority.recall_authorization_event_id,
      recall_authorization_mutation_hash: authority.recall_authorization_mutation_hash,
      write_allowed: false,
    }),
    nonce,
    ts_signed: signedTs,
    sig_form: 1,
    signature,
  });
}

async function main() {
  const preregistration = loadPreregistration();
  const healthResponse = await fetch(`${AIMOS_HTTP_ORIGIN}/health`, { signal: AbortSignal.timeout(15_000) });
  const health = await healthResponse.json().catch(() => ({}));
  assert(healthResponse.ok && health.ready === true, `reconstructed_g2_live_server_not_ready:${health.bootError || 'unknown'}`);
  assert(health.runtime?.database_name === 'aimos', 'reconstructed_g2_live_wrong_database');
  assert(Number(health.runtime?.server_port) === 9100, 'reconstructed_g2_live_wrong_server_port');
  const authority = await readOnlyAuthority();
  const preflight = Object.freeze({
    mode: LIVE ? 'LIVE' : 'DRY_RUN',
    origin: AIMOS_HTTP_ORIGIN,
    database: health.runtime.database_name,
    port: health.runtime.server_port,
    server_ready: true,
    agent_id: authority.agent_id,
    write_allowed: authority.write_allowed,
    preregistration_sha256: fileSha256(PREREGISTRATION),
    source_manifest: sourceManifest(),
    query_commitment_sha256: queryCommitment(),
  });
  console.log(JSON.stringify({ preflight }, null, 2));
  if (!LIVE) return;

  const before = await canonicalState();
  const observations = [];
  const deterministicByQuery = new Map();
  for (let ordinal = 0; ordinal < SAMPLE_COUNT; ordinal += 1) {
    const queryText = QUERIES[ordinal % QUERIES.length];
    const { result, roundTripMs, certificateSha256 } = await signedRecall(queryText);
    assertNoEmbeddingKey(result);
    const meta = result.recall_meta || {};
    const family = meta.graph_family_retrieval;
    const g2 = meta.reconstructed_graph_retrieval;
    const magmaClosure = meta.magma_security_closure;
    const g2Closure = meta.reconstructed_graph_security_closure;
    const epistemic = meta.epistemic_retrieval;
    const nativeFusion = meta.native_retrieval_fusion
      || meta.explain?.stages?.native_retrieval_fusion;
    assert(nativeFusion?.schema === 'hom-aimos/native-retrieval-fusion/v1', `reconstructed_g2_live_native_fusion_missing:${ordinal}`);
    assert(nativeFusion.candidate_set_monotone === true, `reconstructed_g2_live_native_fusion_monotonicity_invalid:${ordinal}`);
    assert(nativeFusion.baseline_candidate_set_preserved === true, `reconstructed_g2_live_native_fusion_baseline_invalid:${ordinal}`);
    assert(nativeFusion.canonical_memory_mutated === false && nativeFusion.retention_changed === false, `reconstructed_g2_live_native_fusion_retention_invalid:${ordinal}`);
    assert(nativeFusion.disclosure_authority === false, `reconstructed_g2_live_native_fusion_disclosure_authority_invalid:${ordinal}`);
    assert(hex64(nativeFusion.decision_sha256), `reconstructed_g2_live_native_fusion_decision_missing:${ordinal}`);

    assert(family?.architecture_role === 'single_permanent_native_graph_family_channel', `reconstructed_g2_live_family_missing:${ordinal}`);
    assert(family.runtime_mode === null && family.activation_authority === false, `reconstructed_g2_live_family_mode_authority_invalid:${ordinal}`);
    assert(family.outer_channel_count === 1, `reconstructed_g2_live_outer_channel_count_invalid:${ordinal}`);
    assert(family.subgear_count === 2, `reconstructed_g2_live_subgear_count_invalid:${ordinal}`);
    assert(family.decision?.duplicate_signal_idempotent === true, `reconstructed_g2_live_family_idempotence_invalid:${ordinal}`);
    assert(hex64(family.decision?.decision_sha256), `reconstructed_g2_live_family_decision_missing:${ordinal}`);
    assert(hex64(family.decision?.rank_commitment_sha256), `reconstructed_g2_live_family_rank_commitment_missing:${ordinal}`);

    assert(g2?.architecture_role === 'permanent_native_graph_family_subgear', `reconstructed_g2_live_metadata_missing:${ordinal}`);
    assert(g2.runtime_mode === null && g2.activation_authority === false, `reconstructed_g2_live_mode_authority_invalid:${ordinal}`);
    assert(g2.candidate_set_authority === false && g2.disclosure_authority === false, `reconstructed_g2_live_candidate_authority_invalid:${ordinal}`);
    assert(g2.fixed_corpus_proof_file_sha256 === FIXED_PROOF_FILE_SHA256, `reconstructed_g2_live_fixed_proof_mismatch:${ordinal}`);
    assert(g2.fixed_corpus_summary_sha256 === FIXED_PROOF_SUMMARY_SHA256, `reconstructed_g2_live_fixed_summary_mismatch:${ordinal}`);
    assert(g2.operational_status === 'complete' && g2.failure_code === null, `reconstructed_g2_live_gear_not_complete:${ordinal}`);
    assert(g2.eligible_candidate_count > 0, `reconstructed_g2_live_candidate_population_empty:${ordinal}`);
    assert(g2.bounds?.maximum_workspace_states === 120 && g2.bounds?.maximum_emitted_ranks === 40, `reconstructed_g2_live_bounds_invalid:${ordinal}`);
    assert(g2.bounds?.native_workspace_states === 40 && g2.bounds?.native_emitted_ranks === 40, `reconstructed_g2_live_native_bounds_invalid:${ordinal}`);
    assert(g2.bounds?.graph_family_outer_channels === 1, `reconstructed_g2_live_bound_channel_invalid:${ordinal}`);
    assert(hex64(g2.decision?.decision_sha256), `reconstructed_g2_live_decision_missing:${ordinal}`);
    assert(hex64(g2.decision?.graph_sha256), `reconstructed_g2_live_graph_commitment_missing:${ordinal}`);
    assert(g2.decision?.edge_commitment_sha256 === g2.decision?.graph_sha256, `reconstructed_g2_live_edge_commitment_invalid:${ordinal}`);
    assert(g2.runtime_breakdown_ms?.total >= 0, `reconstructed_g2_live_runtime_missing:${ordinal}`);

    assert(magmaClosure?.graph_id === 'magma', `reconstructed_g2_live_magma_closure_missing:${ordinal}`);
    assert(g2Closure?.graph_id === 'reconstructed_graph', `reconstructed_g2_live_security_closure_missing:${ordinal}`);
    assert(g2Closure.graph_decision_sha256 === g2.decision.decision_sha256, `reconstructed_g2_live_closure_decision_mismatch:${ordinal}`);
    assert(g2Closure.graph_edge_commitment_sha256 === g2.decision.edge_commitment_sha256, `reconstructed_g2_live_closure_edge_mismatch:${ordinal}`);
    assert(g2Closure.canonical_memory_changed === false && g2Closure.retention_changed === false, `reconstructed_g2_live_retention_postcondition_invalid:${ordinal}`);
    assert(g2Closure.saber_runtime_authority === false, `reconstructed_g2_live_saber_authority_invalid:${ordinal}`);
    assert(g2Closure.withheld_from_disclosure_count === 0, `reconstructed_g2_live_canary_disclosure_invalid:${ordinal}`);
    assert(hex64(g2Closure.receipt?.mutation_hash), `reconstructed_g2_live_security_receipt_missing:${ordinal}`);
    assert(hex64(epistemic?.decision_receipt?.mutation_hash), `reconstructed_g2_live_epistemic_receipt_missing:${ordinal}`);
    assert(hex64(result.recall_receipt?.event_receipt?.mutation_hash), `reconstructed_g2_live_final_receipt_missing:${ordinal}`);
    const magmaClosureEvent = await verifySecurityClosureEvent(magmaClosure, 'magma');
    const g2ClosureEvent = await verifySecurityClosureEvent(g2Closure, 'reconstructed_graph');

    const returnedIds = normalizeIds(result.memories);
    const g2Ids = normalizeIds(g2.decision.selected_memory_ids);
    const fusionIds = normalizeIds(nativeFusion?.selected_memory_ids);
    const fusionSet = new Set(fusionIds);
    assert(returnedIds.length > 0, `reconstructed_g2_live_empty_disclosure:${ordinal}`);
    assert(g2Ids.every((id) => fusionSet.has(id)), `reconstructed_g2_live_g2_outside_admitted_fusion:${ordinal}`);
    assert(returnedIds.every((id) => fusionSet.has(id)), `reconstructed_g2_live_disclosure_outside_native_fusion:${ordinal}`);

    const deterministicProjection = {
      returned_memory_ids: returnedIds,
      g2_selected_memory_ids: g2Ids,
      family_rank_commitment_sha256: family.decision.rank_commitment_sha256,
      g2_graph_sha256: g2.decision.graph_sha256,
    };
    const prior = deterministicByQuery.get(queryText);
    if (prior) {
      assert(canonicalJson(prior) === canonicalJson(deterministicProjection), `reconstructed_g2_live_nondeterministic_replay:${ordinal}`);
    } else {
      deterministicByQuery.set(queryText, deterministicProjection);
    }

    observations.push(Object.freeze({
      ordinal,
      query_sha256: sha256(queryText),
      request_certificate_sha256: certificateSha256,
      returned_memory_ids: returnedIds,
      native_fusion_decision_sha256: nativeFusion.decision_sha256,
      graph_family_decision_sha256: family.decision.decision_sha256,
      graph_family_rank_commitment_sha256: family.decision.rank_commitment_sha256,
      reconstructed_graph_decision_sha256: g2.decision.decision_sha256,
      reconstructed_graph_sha256: g2.decision.graph_sha256,
      reconstructed_graph_selected_memory_ids: g2Ids,
      reconstructed_graph_runtime_breakdown_ms: g2.runtime_breakdown_ms,
      graph_family_runtime_ms: family.runtime_ms,
      epistemic_receipt_mutation_hash: epistemic.decision_receipt.mutation_hash,
      magma_security_receipt_mutation_hash: magmaClosure.receipt.mutation_hash,
      reconstructed_graph_security_receipt_mutation_hash: g2Closure.receipt.mutation_hash,
      magma_security_event_verified: magmaClosureEvent.aladdin_postconditions_valid,
      reconstructed_graph_security_event_verified: g2ClosureEvent.aladdin_postconditions_valid,
      final_recall_receipt_mutation_hash: result.recall_receipt.event_receipt.mutation_hash,
      round_trip_ms: roundTripMs,
    }));
    console.log(JSON.stringify({
      event: 'reconstructed_g2_native_live_observation',
      completed: ordinal + 1,
      total: SAMPLE_COUNT,
      g2_total_ms: g2.runtime_breakdown_ms.total,
      graph_family_ms: family.runtime_ms,
      round_trip_ms: roundTripMs,
    }));
  }

  const after = await canonicalState();
  assert(canonicalJson(before) === canonicalJson(after), 'reconstructed_g2_live_canonical_state_changed');
  const g2TotalP95 = Number(percentile(
    observations.map((row) => row.reconstructed_graph_runtime_breakdown_ms.total),
    0.95,
  ).toFixed(3));
  const graphFamilyP95 = Number(percentile(observations.map((row) => row.graph_family_runtime_ms), 0.95).toFixed(3));
  const roundTripP95 = Number(percentile(observations.map((row) => row.round_trip_ms), 0.95).toFixed(3));
  assert(g2TotalP95 <= G2_TOTAL_P95_CEILING_MS, `reconstructed_g2_live_p95_exceeded:${g2TotalP95}`);

  const ceremonyId = randomUUID();
  const body = Object.freeze({
    schema: 'hom.aimos.reconstructed-graph-g2-native-live-proof/v1',
    ceremony_id: ceremonyId,
    completed_at: new Date().toISOString(),
    mode: 'LIVE_CANONICAL_READ_ONLY_AGENT_ENVELOPE',
    preflight,
    sample_count: SAMPLE_COUNT,
    fixed_query_commitment_sha256: queryCommitment(),
    canonical_state_before: before,
    canonical_state_after: after,
    verification: Object.freeze({
      native_full_recall_path_executed: true,
      signed_read_only_agent_envelope: true,
      one_graph_family_outer_channel: true,
      magma_and_reconstructed_graph_subgear_count: 2,
      g2_operational_status_complete: true,
      g2_candidate_and_disclosure_authority: false,
      fixed_corpus_proof_bound: true,
      deterministic_replay_equal: true,
      canary_disclosure_zero: true,
      epistemic_magma_g2_and_final_receipts_present: true,
      saber_runtime_authority: false,
      aladdin_full_retention_postconditions_valid: true,
      canonical_memory_provenance_and_classification_roots_unchanged: true,
      raw_embeddings_exposed: false,
      g2_total_p95_ms: g2TotalP95,
      g2_total_p95_ceiling_ms: G2_TOTAL_P95_CEILING_MS,
      g2_latency_gate_passed: true,
      graph_family_p95_ms: graphFamilyP95,
      end_to_end_round_trip_p95_ms: roundTripP95,
    }),
    observations,
  });
  const artifact = await signedArtifact(body, authority);
  const written = writeExclusive(`reconstructed-graph-g2-native-live-proof-${ceremonyId}.json`, artifact);
  console.log(JSON.stringify({
    success: true,
    native_live_proof_passed: true,
    g2_total_p95_ms: g2TotalP95,
    artifact: written,
  }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || String(error)}`);
  process.exitCode = 1;
}).finally(async () => {
  try { await pool.end(); } catch { /* ignore */ }
});
