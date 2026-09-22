// Actual canonical SAVE, independently observed commit, then actual SIGTERM.
// No production delay/hook. Ordinary postcommit publication runs in one
// microtask sequence; this proves after-durable-commit signal/durability, not
// an interrupt inside that synchronous publication sequence.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { pool, agentPool } from '../../db/connection.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { canonicalJson } from '../../services/security/agent-identity.js';
import { extractValidFromIso } from '../../services/security/housekeeper-signer.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { manageInstalledUserService } from '../../scripts/service/manage-user-service.mjs';

assert(process.argv.includes('--live-fire'));
const base = 'http://127.0.0.1:9100';
const key = `audit:r6:after-commit:${randomUUID()}`;
const operationId = randomUUID();
const body = { key, save_operation_id: operationId, value: 'R6 native durability observation: this retained memory verifies that a signed canonical SAVE remains verifiable after a controlled process stop following its database commit.', memory_type: 'event_log' };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, milliseconds, reason) {
  const end = performance.now() + milliseconds;
  while (performance.now() < end) { const value = await fn(); if (value) return value; await sleep(5); }
  throw new Error(reason);
}
let pending, signalSent = false, evidence, failure, pid;
try {
  const status = await manageInstalledUserService('status');
  assert(status.health.ready);
  assert.equal(status.definition.source_root, process.cwd());
  assert.equal(status.definition.database, 'aimos');
  assert.equal(status.definition.port, 9100);
  pid = Number(status.supervisor.detail.match(/\bpid = (\d+)/)?.[1]);
  assert(Number.isInteger(pid) && pid > 1 && pid !== process.pid);
  const headers = await buildEnvelopeHeaders('codex-auditor', 'POST', '/aimos/save', body);
  const operationKey = 'canonical-save:' + createHash('sha256').update(canonicalJson({
    schema: 'hom.aimos.canonical-save-operation/v1', company_id: 'hom',
    actor_agent_id: 'codex-auditor', actor_valid_from: extractValidFromIso(new Headers(headers).get('aimos-agent-cert')),
    operation_id: operationId,
  })).digest('hex');
  pending = fetch(base + '/aimos/save', { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(180000) })
    .then(async response => ({ status: response.status, body: await response.json() }))
    .catch(error => ({ error: error.name }));
  const committed = await until(async () => {
    const result = await pool.query(`SELECT m.id::text,encode(m.content_hash,'hex') AS content_hash,
        e.id::text AS terminal_id,e.metadata->'stages'->-1->'evidence'->>'operation_id' AS operation_id
      FROM aimos_memories m JOIN aimos_events e ON e.company_id=m.company_id
      AND e.operation='canonical_save_terminal'
      AND e.metadata->'stages'->-1->'evidence'->>'memory_id'=m.id::text
      WHERE m.company_id='hom' AND m.key=$1
        AND e.metadata->>'outcome'='SUCCESS'
        AND e.metadata->'stages'->-1->'evidence'->>'operation_id'=$2
        AND e.key=$3`, [key, operationId, operationKey]);
    assert(result.rows.length <= 1, 'target_save_not_unique');
    return result.rows[0];
  }, 180000, 'exact_save_commit_not_observed');
  const observedAt = new Date().toISOString();
  const afterHeaders = await buildEnvelopeHeaders('codex-auditor', 'GET', '/aimos/status', {});
  const afterNonce = new Headers(afterHeaders).get('aimos-agent-nonce');
  const signalSentAt = new Date().toISOString();
  process.kill(pid, 'SIGTERM'); signalSent = true;
  await sleep(30);
  try { process.kill(pid, 'SIGINT'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  let postDrain;
  try { postDrain = (await fetch(base + '/aimos/status', { headers: afterHeaders, signal: AbortSignal.timeout(2000) })).status; }
  catch { postDrain = 'CONNECTION_CLOSED'; }
  assert(postDrain === 503 || postDrain === 'CONNECTION_CLOSED');
  await until(() => { try { process.kill(pid, 0); return false; } catch { return true; } }, 40000, 'process_exit_timeout');
  const terminals = (await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='runtime_shutdown_terminal' AND metadata->>'pid'=$1", [String(pid)])).rows;
  assert.equal(terminals.length, 1);
  const shutdown = await readVerifiedEventById(terminals[0].id, 'hom');
  assert(['DRAINED', 'INDETERMINATE'].includes(shutdown.metadata.disposition));
  const started = await readVerifiedEventById(shutdown.metadata.start_event_id, 'hom');
  const save = await readVerifiedEventById(committed.terminal_id, 'hom');
  assert(BigInt(save.ledger_seq) < BigInt(started.ledger_seq));
  assert.equal(Number((await pool.query('SELECT count(*) AS n FROM aimos_request_receipts WHERE nonce=$1', [afterNonce])).rows[0].n), 0);
  const response = await pending;
  evidence = { at: new Date().toISOString(), pid, memory_key: key, ...committed,
    independently_observed_commit_at: observedAt, signal_sent_at: signalSentAt,
    scope: 'actual_signal_after_exact_durable_commit', in_publication_signal_handler_claimed: false,
    save_response_status: response.status || response.error, shutdown_terminal: shutdown.id,
    shutdown_disposition: shutdown.metadata.disposition, work_at_signal: started.metadata.work_at_signal,
    post_drain_admission: postDrain, post_drain_receipts: 0, save_terminal_verified: true };
} catch (error) { failure = error; }
finally {
  try {
    if (pending) await pending;
    if (signalSent) {
      const resumed = await manageInstalledUserService('restart');
      assert(resumed.health.ready);
      if (evidence) {
        const row = (await pool.query("SELECT encode(content_hash,'hex') AS h FROM aimos_memories WHERE id=$1", [evidence.id])).rows[0];
        assert.equal(row.h, evidence.content_hash);
        await readVerifiedEventById(evidence.terminal_id, 'hom');
        evidence.restart = { ready: true, scheduler_jobs: resumed.health.readiness.scheduler.registered_required_jobs,
          port: resumed.health.runtime.server_port, database: resumed.health.runtime.database_name };
        evidence.retained_after_restart = true;
        evidence.passed = true;
        console.log(JSON.stringify(evidence));
      }
    }
  } finally { await Promise.all([pool.end(), agentPool.end()]); }
}
if (failure) throw failure;
