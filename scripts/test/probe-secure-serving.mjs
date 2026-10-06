#!/usr/bin/env node

// Read-only signed smoke test for a disposable AIMOS installation. It prints
// status codes and receipt presence, never identity material or recall text.

import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { pool, agentPool, identityWriterPool, schedulerLockPool } from '../../db/connection.js';
import { resolveAimosServerPort } from '../../services/core/runtime-config.js';

function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}

async function signedCall(base, actor, method, path, body = {}) {
  const headers = await buildEnvelopeHeaders(actor, method, path, body);
  const response = await fetch(`${base}${path}`, {
    method, headers: { ...headers, 'content-type': 'application/json' },
    ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(30_000),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function main() {
  if (!process.argv.includes('--disposable')) throw new Error('disposable_probe_flag_required');
  const actor = cliValue('--agent-id');
  if (!/^[a-z][a-z0-9_-]{0,63}$/.test(String(actor || ''))) {
    throw new Error('disposable_probe_agent_invalid');
  }
  const base = `http://127.0.0.1:${resolveAimosServerPort()}`;
  const status = await signedCall(base, actor, 'GET', '/aimos/status');
  const recall = await signedCall(base, actor, 'POST', '/aimos/recall', {
    query: 'HOM AIMOS Guide connection', limit: 2,
  });
  const denied = [];
  for (const path of [
    '/tools/gmail/inbox', '/tools/drive/files', '/tools/stripe/account',
    '/briefing/today',
  ]) {
    const result = await signedCall(base, actor, 'GET', path);
    denied.push({ path, status: result.status });
  }
  const evidence = {
    status: status.status,
    connected: status.body?.connected === true,
    recall: recall.status,
    memories: Array.isArray(recall.body?.memories) ? recall.body.memories.length : 0,
    receipt: Boolean(recall.body?.recall_receipt),
    denied,
  };
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
  if (evidence.status !== 200 || !evidence.connected
      || evidence.recall !== 200 || evidence.memories < 1 || !evidence.receipt
      || denied.some((row) => row.status !== 403)) {
    throw new Error('secure_serving_signed_probe_failed');
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}).finally(async () => {
  await Promise.allSettled([
    pool.end(), agentPool.end(), identityWriterPool.end(), schedulerLockPool.end(),
  ]);
});
