#!/usr/bin/env node

// Read-only projection of three retained native mutation terminal classes.

import { createHash } from 'node:crypto';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { agentPool, pool } from '../../db/connection.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  createMutMemPortableMutationBundleV2,
  evaluateMutMemPortableMutationBundleV2,
} from '../../services/security/protocol/mutmem-portable-mutation-v2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'artifacts/security/mutmem-v2/p1-live-mutation');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const hex = (value) => value == null ? null : Buffer.from(value).toString('hex');
const b64u = (value) => value == null ? null : Buffer.from(value).toString('base64url');

function object(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  try { return JSON.parse(value || '{}'); } catch { return {}; }
}

async function event(id) {
  const result = await pool.query(
    `SELECT id::text,operation,parent_event_id::text,metadata,
            encode(mutation_hash,'hex') mutation_hash
       FROM aimos_events WHERE id=$1::uuid`,
    [id],
  );
  if (result.rowCount !== 1) throw new Error(`p1_mutation_event_missing:${id}`);
  return { ...result.rows[0], metadata: object(result.rows[0].metadata) };
}

async function selectedRows() {
  const transition = await pool.query(
    `SELECT l.* FROM memory_valence_ledger l
      WHERE l.evidence_schema_version=2 AND l.target_scope='principal_state'
        AND EXISTS (
          SELECT 1 FROM aimos_memory_provenance p
           WHERE p.memory_id=l.memory_id AND p.event_type='REWEIGHT'
             AND p.body_json->>'valence_row_hash'=encode(l.row_hash,'hex')
        ) ORDER BY l.id LIMIT 1`,
  );
  const noop = await pool.query(
    `SELECT l.* FROM memory_valence_ledger l
      WHERE l.evidence_schema_version=2 AND l.target_scope='principal_state'
        AND EXISTS (
          SELECT 1 FROM aimos_events e
           WHERE e.operation='cognitive_weight_unchanged'
             AND e.metadata->>'valence_row_hash'=encode(l.row_hash,'hex')
        ) ORDER BY l.id LIMIT 1`,
  );
  const observation = await pool.query(
    `SELECT l.* FROM memory_valence_ledger l
      WHERE l.evidence_schema_version=2 AND l.target_scope='occurrence_observation'
        AND EXISTS (
          SELECT 1 FROM aimos_events e
           WHERE e.operation='mutation_occurrence_observation_retained'
             AND e.parent_event_id=l.outcome_event_id
        ) ORDER BY l.id LIMIT 1`,
  );
  if (!transition.rows[0] || !noop.rows[0] || !observation.rows[0]) {
    throw new Error('p1_mutation_terminal_population_incomplete');
  }
  return [
    ['authorized_transition', transition.rows[0]],
    ['signed_noop', noop.rows[0]],
    ['occurrence_observation', observation.rows[0]],
  ];
}

function outcomeFromRow(row) {
  return {
    schema: 'hom.aimos.mutation-outcome-evidence/v2',
    company_id: row.company_id,
    memory_id: String(row.memory_id),
    live_content_hash: hex(row.target_live_content_hash),
    occurrence_ref: hex(row.target_occurrence_ref),
    target_scope: row.target_scope,
    recall_event_id: String(row.recall_event_id),
    recall_event_mutation_hash: hex(row.recall_event_mutation_hash),
    recall_merkle_root: hex(row.recall_merkle_root),
    security_closure_sha256: hex(row.security_closure_hash),
    outcome_id: String(row.outcome_id),
  };
}

async function project(kind, row) {
  const outcome = outcomeFromRow(row);
  const [recallEvent, outcomeEvent] = await Promise.all([
    event(outcome.recall_event_id), event(String(row.outcome_event_id)),
  ]);
  const recallEvidence = (recallEvent.metadata.evidence || []).filter((entry) => (
    entry.memory_id === outcome.memory_id
    && entry.live_content_hash === outcome.live_content_hash
    && entry.occurrence_ref === outcome.occurrence_ref
  ));
  if (recallEvidence.length !== 1) throw new Error(`p1_mutation_recall_evidence_invalid:${kind}`);
  const recall = {
    event_id: recallEvent.id,
    mutation_hash: recallEvent.mutation_hash,
    merkle_root: recallEvent.metadata.merkle_root,
    security_closure_sha256: recallEvent.metadata.canary_final_security_closure_sha256,
    evidence: recallEvidence[0],
  };
  const valence = {
    row_hash: hex(row.row_hash),
    reward_sign: Number(row.reward_sign),
    body_json: object(row.body_json),
    signature_b64u: b64u(row.sig),
    signer_agent_id: row.signer_agent_id,
    signer_valid_from: new Date(row.signer_valid_from).toISOString(),
    cert_fingerprint: row.cert_fingerprint,
  };
  let terminal;
  let projection = null;
  if (kind === 'occurrence_observation') {
    const terminalResult = await pool.query(
      `SELECT id::text FROM aimos_events
        WHERE operation='mutation_occurrence_observation_retained'
          AND parent_event_id=$1::uuid ORDER BY ts,id LIMIT 2`,
      [row.outcome_event_id],
    );
    if (terminalResult.rowCount !== 1) throw new Error('p1_mutation_observation_terminal_ambiguous');
    const terminalEvent = await event(terminalResult.rows[0].id);
    terminal = { kind, event: terminalEvent };
  } else if (kind === 'signed_noop') {
    const terminalResult = await pool.query(
      `SELECT id::text FROM aimos_events
        WHERE operation='cognitive_weight_unchanged'
          AND metadata->>'valence_row_hash'=$1 ORDER BY ts,id LIMIT 2`,
      [hex(row.row_hash)],
    );
    if (terminalResult.rowCount !== 1) throw new Error('p1_mutation_noop_terminal_ambiguous');
    terminal = { kind, event: await event(terminalResult.rows[0].id) };
  } else {
    const transition = await pool.query(
      `SELECT p.provenance_id::text,p.memory_id::text,p.event_type,p.body_json,
              encode(p.mutation_hash,'hex') mutation_hash,
              c.projection_id::text,c.old_weight_milli,c.new_weight_milli,
              encode(c.prev_projection_hash,'hex') prev_projection_hash,
              encode(c.projection_hash,'hex') projection_hash,
              encode(c.transition_hash,'hex') transition_hash,
              encode(c.transition_sig,'base64') transition_sig_base64
         FROM aimos_memory_provenance p
         JOIN aimos_cognitive_weight_projections c
           ON c.memory_id=p.memory_id AND c.provenance_mutation_hash=p.mutation_hash
        WHERE p.memory_id=$1::uuid AND p.event_type='REWEIGHT'
          AND p.body_json->>'valence_row_hash'=$2`,
      [row.memory_id, hex(row.row_hash)],
    );
    if (transition.rowCount !== 1) throw new Error('p1_mutation_transition_ambiguous');
    const value = transition.rows[0];
    terminal = {
      kind,
      reweight_provenance: {
        provenance_id: value.provenance_id,
        memory_id: value.memory_id,
        event_type: value.event_type,
        mutation_hash: value.mutation_hash,
        body_json: object(value.body_json),
      },
    };
    projection = {
      projection_id: value.projection_id,
      memory_id: value.memory_id,
      provenance_mutation_hash: value.mutation_hash,
      old_weight_milli: Number(value.old_weight_milli),
      new_weight_milli: Number(value.new_weight_milli),
      prev_projection_hash: value.prev_projection_hash,
      projection_hash: value.projection_hash,
      transition_hash: value.transition_hash,
      transition_signature_b64u:
        Buffer.from(value.transition_sig_base64, 'base64').toString('base64url'),
    };
  }
  const bundle = createMutMemPortableMutationBundleV2({
    bundleId: `P1-LIVE-MUTATION-${kind}-${row.id}`,
    companyId: row.company_id,
    recallEvidenceSha256: sha(Buffer.from(canonicalJson(recall), 'utf8')),
    outcomeEvidence: outcome,
    recallReceipt: recall,
    outcomeEvent: {
      event_id: outcomeEvent.id,
      mutation_hash: outcomeEvent.mutation_hash,
      operation: outcomeEvent.operation,
      parent_event_id: outcomeEvent.parent_event_id,
      metadata: outcomeEvent.metadata,
    },
    valenceEvidence: valence,
    terminal,
    cognitiveProjection: projection,
  });
  const result = evaluateMutMemPortableMutationBundleV2(bundle);
  return { bundle, result, valence_row_id: String(row.id) };
}

async function main() {
  if (!process.argv.includes('--live')) throw new Error('p1_mutation_live_flag_required');
  const rows = await selectedRows();
  const projections = [];
  for (const [kind, row] of rows) projections.push(await project(kind, row));
  await mkdir(OUTPUT, { recursive: true, mode: 0o700 });
  const body = {
    schema: 'hom.aimos.mutmem-p1-live-mutation-projections/v1',
    private_identity_bearing_artifact: true,
    memory_write: false,
    domain_database_mutation: false,
    projections,
  };
  const bytes = Buffer.from(`${JSON.stringify(body, null, 2)}\n`, 'utf8');
  const artifact = path.join(OUTPUT, `${sha(bytes).slice(0, 24)}.json`);
  await writeFile(artifact, bytes, { mode: 0o600, flag: 'wx' });
  await chmod(artifact, 0o600);
  console.log(JSON.stringify({
    success: true,
    status: 'P1_LIVE_MUTATION_PROFILES_PROJECTED',
    terminal_kinds: projections.map((entry) => entry.result.terminal_kind),
    bundle_sha256s: projections.map((entry) => entry.bundle.bundle_sha256),
    valence_row_ids: projections.map((entry) => entry.valence_row_id),
    artifact,
    artifact_sha256: sha(bytes),
    memory_write: false,
    domain_database_mutation: false,
  }, null, 2));
}

main()
  .catch((error) => {
    console.error(`[FATAL] ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await Promise.allSettled([pool.end(), agentPool.end()]);
  });
