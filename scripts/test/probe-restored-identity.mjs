#!/usr/bin/env node

// Signed application proof for an isolated restored database. The caller must
// start server.js on a non-canonical HTTP port with a separate AIMOS instance,
// copy only the selected agent key into that instance's owner-only key root,
// and install temporary instance-scoped DB credentials. This command never
// targets the canonical HTTP port and never writes the source database.

import { randomUUID } from 'node:crypto';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { pool, agentPool, identityWriterPool, schedulerLockPool } from '../../db/connection.js';
import {
  AIMOS_INSTANCE, AIMOS_POSTGRES_PORT, resolveAimosServerPort,
} from '../../services/core/runtime-config.js';

function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}

async function signedCall(base, actor, method, target, body = {}) {
  const headers = await buildEnvelopeHeaders(actor, method, target, body);
  const response = await fetch(`${base}${target}`, {
    method,
    headers: { ...headers, 'content-type': 'application/json' },
    ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(180_000),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function main() {
  const actor = cliValue('--agent-id');
  const port = resolveAimosServerPort();
  if (!process.argv.includes('--disposable')
      || AIMOS_INSTANCE === 'canonical' || AIMOS_POSTGRES_PORT === 5432
      || port === 9100 || !/^[a-z][a-z0-9_-]{0,63}$/.test(String(actor || ''))) {
    throw new Error('restored_identity_probe_target_invalid');
  }
  const base = `http://127.0.0.1:${port}`;
  const status = await signedCall(base, actor, 'GET', '/aimos/status');
  const recall = await signedCall(base, actor, 'POST', '/aimos/recall', {
    query: 'HOM AIMOS Guide connection', limit: 2,
  });
  if (status.status !== 200 || status.body?.connected !== true
      || recall.status !== 200 || !recall.body?.recall_receipt) {
    throw new Error('restored_identity_signed_status_or_recall_failed');
  }

  const operationId = randomUUID();
  const key = `security:cutover:restore-proof:${operationId}`;
  const save = await signedCall(base, actor, 'POST', '/aimos/save', {
    save_operation_id: operationId,
    key,
    value: 'The isolated restored HOM AIMOS database accepted a signed SAVE after its master and agent identity rows were preserved through the PostgreSQL security cutover rehearsal. This retained note verifies the native write path and its signed terminal event.',
    company_id: 'hom', scope: 'system', clearance_level: 5,
    memory_type: 'event_log', source: 'canonical-cutover-qualification',
  });
  if (save.status !== 200 || !save.body?.memory_id || !save.body?.terminal_event_id) {
    throw new Error('restored_identity_signed_save_failed');
  }
  const retained = await pool.query(`SELECT id::text AS id, key,
    encode(content_hash, 'hex') AS content_hash
    FROM public.aimos_memories WHERE company_id='hom' AND id=$1`,
  [save.body.memory_id]);
  if (retained.rowCount !== 1 || retained.rows[0].key !== key) {
    throw new Error('restored_identity_saved_row_missing');
  }
  const terminal = await readVerifiedEventById(save.body.terminal_event_id, 'hom');
  if (String(terminal?.id) !== String(save.body.terminal_event_id)
      || terminal.operation !== 'canonical_save_terminal') {
    throw new Error('restored_identity_signed_terminal_invalid');
  }
  return Object.freeze({
    result: 'restored_identity_signed_proof_pass', instance: AIMOS_INSTANCE,
    postgres_port: AIMOS_POSTGRES_PORT, server_port: port, agent_id: actor,
    signed_status: status.status, signed_recall: recall.status,
    recall_receipt: true, signed_save: save.status,
    memory_id: retained.rows[0].id,
    memory_content_hash: retained.rows[0].content_hash,
    terminal_event_id: String(terminal.id), operation_id: operationId,
  });
}

main().then((receipt) => {
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
}).catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}).finally(async () => {
  await Promise.allSettled([
    pool.end(), agentPool.end(), identityWriterPool.end(), schedulerLockPool.end(),
  ]);
});
