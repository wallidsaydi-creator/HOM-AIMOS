#!/usr/bin/env node

/**
 * TP-G0 live proof — database-issued memory origin time.
 *
 * This ceremony composes the native housekeeper SAVE and signed native recall
 * owners. It proves that a new schema-v4 BIND commits the same millisecond in
 * its signed body, the provenance projection, and the canonical memory row.
 * Tamper checks are in-memory verifier fixtures; no retained row is modified.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool, agentPool } from '../../db/connection.js';
import {
  AIMOS_COMPANY_ID,
  AIMOS_HTTP_ORIGIN,
  resolveAimosDatabaseName,
} from '../../services/core/runtime-config.js';
import {
  canonicalJson,
  verifyStoredPayloadSig,
} from '../../services/security/agent-identity.js';
import { contentHash } from '../../services/security/identity-chain.js';
import {
  memoryProvenanceLedger,
  verifyMemoryOriginBindingV4,
  verifyMutationHash,
} from '../../services/security/memory-provenance.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { persistMemory } from '../../services/write/persist-memory.js';
import { resolveNativeRecallAuthority } from '../../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../../services/retrieval/native-recall-pipeline.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const LIVE = process.argv.includes('--live');
const DATABASE = 'aimos';
const MIGRATION = '093-signed-memory-origin-time.sql';
const ARTIFACT_DIRECTORY = path.join(ROOT, 'artifacts', 'twin-prime', 'tp-g0');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
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

async function inspectPrerequisites() {
  assert(resolveAimosDatabaseName() === DATABASE, 'tp_g0_database_mismatch');
  const migrationSource = fs.readFileSync(path.join(ROOT, 'migrations', MIGRATION));
  const migrationSha256 = sha256(migrationSource);
  const migration = await pool.query(
    `SELECT filename, checksum, applied_at
       FROM schema_migrations
      WHERE filename = $1`,
    [MIGRATION],
  );
  assert(migration.rows.length === 1, 'tp_g0_migration_not_applied');
  assert(migration.rows[0].checksum === migrationSha256, 'tp_g0_migration_checksum_mismatch');

  const healthResponse = await fetch(`${AIMOS_HTTP_ORIGIN}/health`);
  assert(healthResponse.ok, 'tp_g0_server_health_transport_failed');
  const health = await healthResponse.json();
  assert(health.ready === true, `tp_g0_server_not_ready:${health.bootError || 'unknown'}`);
  assert(health.runtime?.database_name === DATABASE, 'tp_g0_server_database_mismatch');

  return {
    migration: {
      filename: migration.rows[0].filename,
      sha256: migrationSha256,
      applied_at: new Date(migration.rows[0].applied_at).toISOString(),
    },
    server: {
      origin: AIMOS_HTTP_ORIGIN,
      ready: true,
      database: health.runtime.database_name,
      port: health.runtime.server_port,
    },
  };
}

async function readBinding(memoryId) {
  const result = await pool.query(
    `SELECT
       m.id::text AS memory_id,
       m.company_id,
       m.agent_id AS subject_agent_id,
       m.key,
       m.created_at AS live_created_at,
       p.provenance_id::text,
       p.agent_id AS signer_agent_id,
       p.agent_valid_from,
       p.body_json,
       p.content_hash,
       p.mutation_hash,
       p.prev_mutation_hash,
       p.ts_signed,
       p.nonce,
       p.sig,
       p.event_type,
       p.binding_schema_version,
       p.memory_originated_at,
       ai.pubkey AS signer_pubkey
     FROM aimos_memories m
     JOIN aimos_memory_provenance p ON p.memory_id = m.id
     JOIN agent_identity ai
       ON ai.agent_id = p.agent_id AND ai.valid_from = p.agent_valid_from
    WHERE m.id = $1::uuid
      AND p.event_type = 'BIND'
      AND p.binding_schema_version = 4`,
    [memoryId],
  );
  assert(result.rows.length === 1, 'tp_g0_v4_binding_missing_or_ambiguous');
  return result.rows[0];
}

function verifyBindingAndTamperFixtures(row) {
  const body = row.body_json;
  const exactOrigin = verifyMemoryOriginBindingV4({
    bindingSchemaVersion: row.binding_schema_version,
    eventType: row.event_type,
    body,
    memoryOriginatedAt: row.memory_originated_at,
    liveCreatedAt: row.live_created_at,
  });
  assert(exactOrigin.valid, exactOrigin.reason || 'tp_g0_origin_binding_invalid');

  const actualSignature = verifyStoredPayloadSig(
    row.signer_pubkey,
    body,
    String(row.nonce),
    Number(row.ts_signed),
    Buffer.from(row.sig).toString('base64url'),
  );
  assert(actualSignature.valid, `tp_g0_binding_signature_invalid:${actualSignature.reason}`);
  assert(verifyMutationHash(
    Buffer.from(row.content_hash),
    row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null,
    String(row.nonce),
    Number(row.ts_signed),
    Buffer.from(row.mutation_hash),
  ), 'tp_g0_binding_mutation_hash_invalid');

  const tamperedBody = {
    ...body,
    memory_originated_at_unix_ms: body.memory_originated_at_unix_ms + 1,
  };
  const bodySignatureTamper = verifyStoredPayloadSig(
    row.signer_pubkey,
    tamperedBody,
    String(row.nonce),
    Number(row.ts_signed),
    Buffer.from(row.sig).toString('base64url'),
  );
  const bodyMutationTamperRejected = !verifyMutationHash(
    contentHash(tamperedBody),
    row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null,
    String(row.nonce),
    Number(row.ts_signed),
    Buffer.from(row.mutation_hash),
  );
  const provenanceTamperRejected = !verifyMemoryOriginBindingV4({
    bindingSchemaVersion: row.binding_schema_version,
    eventType: row.event_type,
    body,
    memoryOriginatedAt: new Date(exactOrigin.unixMs + 1).toISOString(),
    liveCreatedAt: row.live_created_at,
  }).valid;
  const liveRowTamperRejected = !verifyMemoryOriginBindingV4({
    bindingSchemaVersion: row.binding_schema_version,
    eventType: row.event_type,
    body,
    memoryOriginatedAt: row.memory_originated_at,
    liveCreatedAt: new Date(exactOrigin.unixMs + 1).toISOString(),
  }).valid;

  assert(!bodySignatureTamper.valid, 'tp_g0_signed_body_tamper_not_rejected');
  assert(bodyMutationTamperRejected, 'tp_g0_body_mutation_hash_tamper_not_rejected');
  assert(provenanceTamperRejected, 'tp_g0_provenance_time_tamper_not_rejected');
  assert(liveRowTamperRejected, 'tp_g0_live_row_time_tamper_not_rejected');

  return {
    exact_origin_unix_ms: exactOrigin.unixMs,
    signed_body_tamper_rejected: true,
    body_mutation_hash_tamper_rejected: true,
    provenance_time_tamper_rejected: true,
    live_row_time_tamper_rejected: true,
  };
}

async function signedNativeRecall(memoryId) {
  const body = {
    company_id: AIMOS_COMPANY_ID,
    agent_id: 'housekeeper',
    memory_id: memoryId,
    limit: 1,
    clearance_level: 12,
    cache: false,
    semantic_cache: false,
  };
  const signed = await signAsHousekeeper(body, { method: 'POST', path: '/aimos/recall' });
  const requestAuthority = Object.freeze({
    kind: 'verified_request',
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    requestSigForm: signed.sigForm,
    signedMethod: signed.signedMethod,
    signedPath: signed.signedPath,
    signedClaims: signed.signedClaims,
  });
  const executionContext = Object.freeze({
    actorAgentId: signed.agentId,
    actorValidFromIso: signed.validFromIso,
    companyId: AIMOS_COMPANY_ID,
    identityTier: signed.identityTier,
  });
  const authority = await resolveNativeRecallAuthority({
    rawCommand: signed.body,
    executionContext,
    requestAuthority,
    transportBinding: { transport: 'rest' },
  });
  const recalled = await executeNativeRecall(
    { ip: '127.0.0.1', headers: {}, originalUrl: '/aimos/recall' },
    authority,
  );
  assert(recalled.status === 200 && recalled.body?.success === true, 'tp_g0_native_recall_failed');
  assert(recalled.body.memories?.length === 1, 'tp_g0_native_recall_cardinality_invalid');
  assert(String(recalled.body.memories[0].id) === memoryId, 'tp_g0_native_recall_identity_mismatch');
  const receipt = recalled.body.recall_receipt;
  assert(/^[0-9a-f]{64}$/.test(String(receipt?.merkle_root || '')), 'tp_g0_recall_merkle_root_missing');
  assert(receipt.evidence?.length === 1, 'tp_g0_recall_evidence_cardinality_invalid');
  assert(String(receipt.evidence[0].memory_id) === memoryId, 'tp_g0_recall_receipt_identity_mismatch');
  assert(/^[0-9a-f]{64}$/.test(String(receipt.event_receipt?.mutation_hash || '')), 'tp_g0_recall_event_hash_missing');
  return receipt;
}

async function main() {
  const prerequisites = await inspectPrerequisites();
  console.log(JSON.stringify({ mode: LIVE ? 'LIVE' : 'DRY_RUN', prerequisites }, null, 2));
  if (!LIVE) return;

  const ceremonyId = randomUUID();
  const key = `tp-g0:origin-time-binding:${ceremonyId}`;
  const saved = await persistMemory({
    company_id: AIMOS_COMPANY_ID,
    agent_id: 'housekeeper',
    key,
    value: `TP-G0 ceremony ${ceremonyId} proves that one database-issued memory creation time is retained in the live row and cryptographically bound by the housekeeper's schema-v4 BIND receipt.`,
    scope: 'system',
    clearance_level: 1,
    memory_type: 'test',
    source: 'ceremony:tp-g0-origin-time-binding',
    session_id: `ceremony:tp-g0:${ceremonyId}`,
    mutation_authority: 'housekeeper',
  });
  assert(saved && !saved.rejected && saved.id, `tp_g0_save_failed:${saved?.reason || 'unknown'}`);

  const binding = await readBinding(saved.id);
  const tamper = verifyBindingAndTamperFixtures(binding);
  const fullEvidence = await memoryProvenanceLedger.verifyRecallEvidence({ memoryIds: [saved.id] });
  assert(fullEvidence.verified.has(String(saved.id)), `tp_g0_full_evidence_rejected:${JSON.stringify(fullEvidence.rejected)}`);
  const proof = fullEvidence.proofs.get(String(saved.id));
  assert(Number(proof?.binding_schema_version) === 4, 'tp_g0_full_evidence_not_schema_v4');
  assert(new Date(proof.memory_originated_at).getTime() === tamper.exact_origin_unix_ms, 'tp_g0_full_evidence_origin_mismatch');

  const recall = await signedNativeRecall(String(saved.id));
  const receiptBody = {
    schema: 'hom.aimos.tp-g0-origin-time-proof/v1',
    ceremony_id: ceremonyId,
    database: DATABASE,
    migration: prerequisites.migration,
    server: prerequisites.server,
    save: {
      memory_id: String(saved.id),
      key,
      source: 'ceremony:tp-g0-origin-time-binding',
      binding_schema_version: Number(binding.binding_schema_version),
      memory_row_created_at: new Date(binding.live_created_at).toISOString(),
      provenance_memory_originated_at: new Date(binding.memory_originated_at).toISOString(),
      signed_body_origin_unix_ms: Number(binding.body_json.memory_originated_at_unix_ms),
      binding_content_hash: Buffer.from(binding.content_hash).toString('hex'),
      binding_mutation_hash: Buffer.from(binding.mutation_hash).toString('hex'),
      binding_signer_agent_id: binding.signer_agent_id,
      binding_signer_valid_from: new Date(binding.agent_valid_from).toISOString(),
    },
    verification: {
      full_provenance_admission: true,
      exact_three_way_origin_binding: true,
      ...tamper,
    },
    recall: {
      returned_memory_count: 1,
      command_hash: recall.command_hash,
      merkle_root: recall.merkle_root,
      evidence_memory_id: String(recall.evidence[0].memory_id),
      event_id: recall.event_receipt.event_id,
      event_mutation_hash: recall.event_receipt.mutation_hash,
    },
  };
  const signedReceipt = await signAsHousekeeper(receiptBody);
  const receiptVerification = verifyStoredPayloadSig(
    binding.signer_pubkey,
    signedReceipt.body,
    signedReceipt.nonce,
    signedReceipt.signedTs,
    signedReceipt.sigB64u,
  );
  assert(receiptVerification.valid, `tp_g0_receipt_signature_invalid:${receiptVerification.reason}`);
  const artifact = {
    body: signedReceipt.body,
    signer: {
      agent_id: signedReceipt.agentId,
      valid_from: signedReceipt.validFromIso,
      identity_tier: signedReceipt.identityTier,
    },
    nonce: signedReceipt.nonce,
    ts_signed: signedReceipt.signedTs,
    signature: signedReceipt.sigB64u,
  };
  const written = writeExclusive(`${ceremonyId}.receipt.json`, artifact);
  console.log(JSON.stringify({ success: true, ceremony_id: ceremonyId, receipt: written }, null, 2));
}

try {
  await main();
} catch (error) {
  console.error(`[FATAL] ${error.message}`);
  process.exitCode = 1;
} finally {
  await Promise.allSettled([pool.end(), agentPool.end()]);
}
