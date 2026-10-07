#!/usr/bin/env node

// Signed post-switch proof. Only the canonical service on 9100 backed by the
// private PostgreSQL port is an admissible target. SAVE is verified through
// both the retained memory row and its signed native terminal event.

import { randomUUID } from 'node:crypto';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { pool, agentPool, identityWriterPool,
  schedulerLockPool } from '../../db/connection.js';
import { AIMOS_INSTANCE, AIMOS_POSTGRES_PORT,
  resolveAimosServerPort } from '../../services/core/runtime-config.js';

function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}

async function signedCall(actor, method, target, body = {}) {
  const headers = await buildEnvelopeHeaders(actor, method, target, body);
  const response = await fetch(`http://127.0.0.1:9100${target}`, {
    method, headers: { ...headers, 'content-type': 'application/json' },
    ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(30_000),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function main() {
  const actor = cliValue('--agent-id');
  if (AIMOS_INSTANCE !== 'canonical' || AIMOS_POSTGRES_PORT !== 55432
      || resolveAimosServerPort() !== 9100
      || !/^[a-z][a-z0-9_-]{0,63}$/.test(String(actor || ''))) {
    throw new Error('cutover_serving_probe_target_invalid');
  }
  const status = await signedCall(actor, 'GET', '/aimos/status');
  const recall = await signedCall(actor, 'POST', '/aimos/recall', {
    query: 'HOM AIMOS Guide connection', limit: 2,
  });
  if (status.status !== 200 || status.body?.connected !== true
      || recall.status !== 200 || !recall.body?.recall_receipt) {
    throw new Error('cutover_serving_signed_read_failed');
  }
  const operationId = randomUUID();
  const key = `security:cutover:post-switch:${operationId}`;
  const save = await signedCall(actor, 'POST', '/aimos/save', {
    save_operation_id: operationId, key,
    value: 'The canonical HOM AIMOS service restarted on its private authenticated PostgreSQL cluster and accepted this signed SAVE. The retained row and terminal event verify that native writes work after the database cutover.',
    company_id: 'hom', scope: 'system', clearance_level: 5,
    memory_type: 'event_log', source: 'canonical-cutover-qualification',
  });
  if (save.status !== 200 || !save.body?.memory_id
      || !save.body?.terminal_event_id) {
    throw new Error('cutover_serving_signed_save_failed');
  }
  const retained = await pool.query(`SELECT id::text AS id, key,
    encode(content_hash, 'hex') AS content_hash
    FROM public.aimos_memories WHERE company_id='hom' AND id=$1`,
  [save.body.memory_id]);
  if (retained.rowCount !== 1 || retained.rows[0].key !== key) {
    throw new Error('cutover_serving_saved_row_missing');
  }
  const terminal = await readVerifiedEventById(save.body.terminal_event_id, 'hom');
  if (String(terminal?.id) !== String(save.body.terminal_event_id)
      || terminal.operation !== 'canonical_save_terminal') {
    throw new Error('cutover_serving_signed_terminal_invalid');
  }
  return Object.freeze({ result: 'cutover_serving_signed_proof_pass',
    signed_status: status.status, signed_recall: recall.status,
    signed_save: save.status, memory_id: retained.rows[0].id,
    terminal_event_id: String(terminal.id),
    memory_content_hash: retained.rows[0].content_hash,
    recall_receipt: true, postgres_port: AIMOS_POSTGRES_PORT,
    server_port: 9100, agent_id: actor });
}

main().then((result) => {
  process.stdout.write(`${JSON.stringify(result)}\n`);
}).catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}).finally(async () => {
  await Promise.allSettled([
    pool.end(), agentPool.end(), identityWriterPool.end(), schedulerLockPool.end(),
  ]);
});
