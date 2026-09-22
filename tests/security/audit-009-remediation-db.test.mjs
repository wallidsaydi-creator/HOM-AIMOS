// Real native provider/effect owner over PostgreSQL and bounded HTTP fault
// peers. The peer is not an LLM and is never counted as model-quality evidence.
// Existing public Housekeeper identity only; no credential, enrollment or
// configuration mutation. The runner owns this exact schema-only database.
import assert from 'node:assert/strict';
import http from 'node:http';
import pg from 'pg';
import { performance } from 'node:perf_hooks';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { pool, agentPool } from '../../db/connection.js';
import { runProvider, runProviderWithFailover } from '../../services/core/providers.js';
import { runAgentWithFallback } from '../../services/orchestration/agent-tools.js';
import { callNativeLlm } from '../../services/shared/native-llm.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { reconstructMaterialEffectTraces } from '../../services/security/material-effect-owner.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database = process.argv[process.argv.indexOf('--aimos-db') + 1];
assert(/^aimos_test_security_audr4_[0-9]+_[a-f0-9]{6}$/.test(database));
const canonicalUrl = new URL(resolveAimosDatabaseUrl());
assert.equal(canonicalUrl.pathname, `/${database}`);
canonicalUrl.pathname = '/aimos';
const reader = new pg.Client({ connectionString: canonicalUrl.href, connectionTimeoutMillis: 3000 });
let requests = 0, connections = 0, mode = 'positive';
const sockets = new Set();
const peer = http.createServer((req, res) => {
  if (req.url !== '/api/chat' || req.method !== 'POST') { res.writeHead(404); res.end('{}'); return; }
  requests++;
  req.resume();
  res.setHeader('content-type', 'application/x-ndjson');
  if (mode === 'malformed') { res.end('{broken}\n'); return; }
  res.write(JSON.stringify({ message: { content: 'native transport result' }, done: false }) + '\n');
  if (mode === 'stall' || mode === 'abort') return;
  if (mode === 'endless') {
    const timer = setInterval(() => res.write('{}\n'), 10);
    res.once('close', () => clearInterval(timer)); return;
  }
  if (mode === 'incomplete') { res.end(); return; }
  if (mode === 'dropped') { setTimeout(() => res.destroy(), 10); return; }
  res.end('{"done":true}\n');
});
peer.on('connection', socket => { connections++; sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
const evidence = { database, mechanism: 'native_provider_HTTP_and_signed_PostgreSQL_effect_owner',
  model_inference: false, new_identity: false, credential_write: false, production_database_write: false, cases: [] };
let peerStarted = false;
try {
  for (const db of [pool, agentPool]) assert.equal((await db.query('SELECT current_database() AS name')).rows[0].name, database);
  await reader.connect();
  const master = (await reader.query(`SELECT id,master_pubkey,fingerprint,created_at,
    revocation_cert_hash,keychain_service,keychain_account FROM aimos_master_identity WHERE id=1`)).rows[0];
  const housekeeper = (await reader.query(`SELECT agent_id,pubkey,cert,device_fp,valid_from,
    valid_until,issued_at,revoked_at,chain_head,is_system_role FROM agent_identity identity
    WHERE agent_id='housekeeper' AND revoked_at IS NULL AND NOT EXISTS (
      SELECT 1 FROM aimos_agent_revocation_events revocation
      WHERE revocation.agent_id=identity.agent_id AND revocation.agent_valid_from=identity.valid_from)
    ORDER BY valid_from DESC LIMIT 1`)).rows[0];
  assert(master && housekeeper, 'existing_public_housekeeper_authority_required');
  await pool.query(`INSERT INTO aimos_master_identity
    (id,master_pubkey,fingerprint,created_at,revocation_cert_hash,keychain_service,keychain_account)
    VALUES($1,$2,$3,$4,$5,$6,$7)`, Object.values(master));
  await pool.query(`INSERT INTO agent_identity
    (agent_id,pubkey,cert,device_fp,valid_from,valid_until,issued_at,revoked_at,chain_head,is_system_role)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, Object.values(housekeeper));
  // This existing provider's native port must be free; never interrupt a user's model.
  await new Promise((resolve, reject) => { peer.once('error', reject); peer.listen(11434, '127.0.0.1', resolve); });
  peerStarted = true;
  for (const selected of ['positive', 'stall', 'endless', 'malformed', 'incomplete', 'dropped', 'preabort', 'abort', 'frozen_preabort', 'frozen_abort']) {
    mode = selected === 'frozen_abort' ? 'abort' : selected;
    const before = requests;
    const start = performance.now();
    const controller = new AbortController();
    const frozenReason = Object.freeze(new Error('r4_frozen_caller_reason'));
    if (selected.endsWith('preabort')) controller.abort(selected.startsWith('frozen') ? frozenReason : undefined);
    let abortTimer;
    if (selected === 'abort') abortTimer = setTimeout(() => controller.abort(), 120);
    if (selected === 'frozen_abort') abortTimer = setTimeout(() => controller.abort(frozenReason), 120);
    let result, failure;
    try {
      result = await runProvider({ provider: 'ollama', model: 'r4-transport-fault-probe',
        prompt: 'R4 native transport qualification; not a model benchmark.', onToken() {},
        useContext: { actorAgentId: 'housekeeper', signal: controller.signal,
          deadlineAt: performance.now() + 500 } });
    } catch (error) { failure = error; }
    finally { clearTimeout(abortTimer); }
    const elapsed = performance.now() - start;
    if (selected === 'positive') assert.equal(result, 'native transport result');
    else {
      assert(failure, `native_provider_did_not_reject:${selected}`);
      assert.equal(failure.httpOutcome, 'INDETERMINATE');
      if (selected.startsWith('frozen')) assert.equal(failure.cause, frozenReason);
    }
    if (selected.endsWith('preabort')) assert.equal(requests, before);
    else assert.equal(requests - before, 1, 'no_second_consequential_dispatch');
    // Includes actual signed begin/terminal database latency, not just fetch.
    assert(elapsed < 2500, '500ms HTTP budget plus 2000ms signed-ledger/scheduling tolerance exceeded');
    evidence.cases.push({ case: selected, elapsed_ms: elapsed, requests: requests - before,
      result: failure ? 'INDETERMINATE' : 'SUCCEEDED', error: failure?.name || null });
  }
  evidence.outer_owners = [];
  for (const owner of ['agent_malformed', 'agent_stall', 'agent_abort', 'provider_failover', 'native_llm']) {
    mode = owner.endsWith('stall') ? 'stall' : owner.endsWith('abort') ? 'abort' : 'malformed';
    const controller = new AbortController();
    const before = requests, start = performance.now();
    const useContext = Object.freeze({ companyId: 'hom', actorAgentId: 'housekeeper',
      actorValidFromIso: new Date(housekeeper.valid_from).toISOString(), identityTier: 'T1' });
    let timer, failure;
    if (mode === 'abort') timer = setTimeout(() => controller.abort(), 180);
    try {
      const deadlineAt = performance.now() + 500;
      if (owner.startsWith('agent_')) {
        await runAgentWithFallback({ id: 'housekeeper', name: 'Housekeeper', model: 'ollama:r4-first' },
          'R4 native context owner qualification.', 'Observe the bounded transport fault.', [], {
            modelPlan: ['ollama:r4-first', 'ollama:r4-forbidden-second'], onToken() {},
            signal: controller.signal, deadlineAt,
            toolExecutionOptions: { credentialUseContext: useContext },
          });
      } else if (owner === 'provider_failover') {
        await runProviderWithFailover({ provider: 'ollama', model: 'r4-first', prompt: 'R4 transport qualification.',
          useContext, onToken() {}, toolExecutionOptions: { signal: controller.signal, deadlineAt } });
      } else {
        await callNativeLlm({ provider: 'ollama', model: 'r4-first', prompt: 'R4 transport qualification.',
          useContext, signal: controller.signal, deadlineAt });
      }
    } catch (error) { failure = error; }
    finally { clearTimeout(timer); }
    assert(failure, `outer_owner_did_not_reject:${owner}`);
    assert.equal(failure.httpOutcome, 'INDETERMINATE', `${owner}:classification_lost`);
    assert.equal(requests - before, 1, `${owner}:second_consequential_dispatch`);
    assert(performance.now() - start < 2500, `${owner}:operation_budget_reset`);
    evidence.outer_owners.push({ owner, requests: requests - before, elapsed_ms: performance.now() - start,
      error: failure.name, disposition: failure.httpOutcome });
  }
  const rows = (await pool.query(`SELECT id FROM aimos_events WHERE operation IN
    ('material_effect_started','material_effect_terminal') ORDER BY ledger_seq`)).rows;
  const verified = [];
  for (const row of rows) verified.push(await readVerifiedEventById(row.id, 'hom'));
  const traces = reconstructMaterialEffectTraces(verified);
  const selected = traces.complete.filter(trace => trace.start.metadata.effect_operation === 'model_provider_inference');
  assert.equal(selected.length, evidence.cases.length + evidence.outer_owners.length);
  assert.equal(traces.open.length, 0);
  assert.equal(selected.filter(trace => trace.terminal.metadata.disposition === 'SUCCEEDED').length, 1);
  evidence.signed_terminal_pairs = selected.length;
  evidence.open_material_effects = 0;
  evidence.connections = connections;
} finally {
  if (peerStarted) { peer.closeAllConnections(); await new Promise(resolve => peer.close(resolve)); }
  await Promise.allSettled([reader.end(), pool.end(), agentPool.end()]);
}
assert.equal(sockets.size, 0, 'fault_peer_sockets_not_closed');
evidence.peer_stopped = true;
console.log(JSON.stringify(evidence, null, 2));
// Agent imports own process-lifetime resources. This is the runner's bounded
// child, not the product process; all owned peers, pools and traces settled above.
process.exit(0);
