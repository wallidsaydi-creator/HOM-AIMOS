// Real signed HTTP/PG task qualification. Test actors live only in the exact
// schema-only audit database. No Genesis, new provider or canonical grant.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import pg from 'pg';
import { pool, agentPool } from '../../db/connection.js';
import { AIMOS_AGENT_KEY_ROOT, resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { generateKeypair, issueCert, pubkeyFingerprint, signPayloadWithContext,
  createAgentRevocationProof, verifyAgentRevocationProof } from '../../services/security/agent-identity.js';
import { loadHousekeeperPrivkey } from '../../services/security/housekeeper-signer.js';
import { insertMaster, insertAgent, insertRevocationEvent } from '../../scripts/identity/db.js';
import { authGate } from '../../services/security/auth-gate.js';
import { getPermissions, setPermissions, verifyAuthorizationEventChain } from '../../services/core/permissions.js';
import { providerStatus } from '../../services/core/providers.js';
import { readVerifiedEventHistory } from '../../services/observe/event-ledger.js';
import { tasks } from '../../services/orchestration/agent-store.js';
import taskRouter from '../../routes/task.js';
import permissionsRouter from '../../routes/permissions.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database = process.argv[process.argv.indexOf('--aimos-db') + 1];
assert.match(database, /^aimos_test_security_aud003_[0-9]+_[a-f0-9]{6}$/);
assert.equal(new URL(resolveAimosDatabaseUrl()).pathname, `/${database}`);
const canonicalUrl = new URL(resolveAimosDatabaseUrl()); canonicalUrl.pathname = '/aimos';
const canonical = new pg.Pool({ connectionString: canonicalUrl.href, max: 1 });
const sha = value => createHash('sha256').update(value).digest('hex');
const protectedFiles = [path.join(AIMOS_AGENT_KEY_ROOT, 'housekeeper.key'),
  path.join(AIMOS_AGENT_KEY_ROOT, 'housekeeper.cert-cache.json'),
  new URL('../../architecture-authority.json', import.meta.url).pathname];
const fileState = () => protectedFiles.map(file => ({ file, sha256: existsSync(file) ? sha(readFileSync(file)) : null }));
const beforeFiles = fileState();
async function canonicalState() {
  const c = await canonical.connect();
  try {
    await c.query('BEGIN READ ONLY');
    const identities = (await c.query('SELECT agent_id,valid_from,valid_until,pubkey,cert,revoked_at FROM agent_identity ORDER BY agent_id,valid_from')).rows;
    const masters = (await c.query('SELECT * FROM aimos_master_identity ORDER BY id')).rows;
    const revocations = (await c.query('SELECT agent_id,agent_valid_from,mutation_hash FROM aimos_agent_revocation_events ORDER BY agent_id,agent_valid_from')).rows;
    const grants = (await c.query('SELECT company_id,subject_agent_id,subject_valid_from,mutation_hash FROM aimos_authorization_events ORDER BY company_id,subject_agent_id,subject_valid_from,capability,created_at')).rows;
    await c.query('COMMIT');
    return { identities, sha256: sha(JSON.stringify({ identities, masters, revocations, grants })) };
  } finally { c.release(); }
}
let canonicalBefore, server, base;
const requests = [], observations = [], admittedTasks = [];
function envelope(actor, method, url, body = {}) {
  assert.notEqual(actor.id, 'housekeeper', 'test_must_not_emit_housekeeper_http_authority');
  const nonce = randomBytes(16).toString('base64url'), ts = Math.floor(Date.now() / 1000);
  const sig = signPayloadWithContext(actor.privkey, body, method, url.split('?')[0], nonce, ts);
  return { 'Aimos-Agent-Cert': actor.cert, 'Aimos-Agent-Signature': sig,
    'Aimos-Agent-Nonce': nonce, 'Aimos-Agent-Timestamp': String(ts),
    'X-Aimos-Sig-Form': '3', 'Content-Type': 'application/json' };
}
async function call(actor, method, url, body = {}) {
  const headers = envelope(actor, method, url, body);
  const transcript = { actor: actor.id, method, url, body, headers }; requests.push(transcript);
  const response = await fetch(base + url, { method, headers,
    ...(method === 'GET' ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(15000) });
  const text = await response.text(); transcript.status = response.status; transcript.response = text;
  return { status: response.status, body: JSON.parse(text) };
}
async function grant(admin, subject, allowed) {
  const result = await call(admin, 'POST', '/permissions/set', { agent_id: subject.id, permissions: { delegate: allowed } });
  assert.equal(result.status, 200, JSON.stringify(result)); assert.equal(result.body.success, true);
  assert.equal((await getPermissions(subject.id, 'hom', { subjectValidFromIso: subject.epoch })).delegate, allowed);
}
async function createTask(actor, target = actor, alias = '/task') {
  const prompt = `AUD-003 private task ${randomBytes(12).toString('hex')}`;
  const result = await call(actor, 'POST', alias, { agentId: target.id, task: prompt, source: 'audit:aud-003',
    model: 'codex', allowWeb: false });
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.equal(result.body.status, 'blocked'); assert.equal(result.body.success, false);
  const record = tasks.get(result.body.taskId); assert(record);
  assert.equal(record.task, prompt); assert.equal(record.result, null);
  assert.equal(record.ownership.initiatingActorId, actor.id);
  assert.equal(record.ownership.initiatingActorValidFromIso, actor.epoch);
  assert(Object.isFrozen(record.ownership));
  assert.equal(Object.getOwnPropertyDescriptor(record, 'ownership').writable, false);
  assert.equal(Object.getOwnPropertyDescriptor(record, 'ownership').configurable, false);
  if (target.id !== actor.id) assert.deepEqual(record.ownership.delegation,
    { targetAgentId: target.id, targetValidFromIso: target.epoch });
  assert(record.ownership.requestAdmissionEventId && record.ownership.requestReceiptMutationHash);
  admittedTasks.push(JSON.parse(JSON.stringify(record)));
  return record;
}
async function visible(actor, record, allowed) {
  for (const alias of ['/task', '/tasks']) {
    const detail = await call(actor, 'GET', `${alias}/${record.id}`);
    assert.equal(detail.status, allowed ? 200 : 404, JSON.stringify(detail));
    if (allowed) { assert.equal(detail.body.task, record.task); assert.equal(detail.body.error, record.error); }
    else assert.deepEqual(detail.body, { error: 'Task not found' });
    const listed = await call(actor, 'GET', `${alias}?limit=500&status=blocked`);
    assert.equal(listed.status, 200);
    assert.equal(listed.body.some(row => row.id === record.id), allowed);
    for (const row of listed.body) assert.deepEqual(Object.keys(row).sort(),
      ['id','agent_id','source','priority','model','status','created_at'].sort());
    assert(!JSON.stringify(listed.body).includes(record.task));
  }
}
async function revoke(actor, master) {
  const proof = createAgentRevocationProof(master.privkey, { agentId: actor.id, agentValidFrom: actor.epoch,
    targetCert: actor.cert, masterFingerprint: pubkeyFingerprint(master.pubkey), reasonCode: 'isolated_audit_003_qualification' });
  const row = { agent_id: actor.id, agent_valid_from: actor.epoch, master_fingerprint: pubkeyFingerprint(master.pubkey),
    target_cert_hash: proof.targetCertHash, prior_identity_hash: proof.priorIdentityHash, signed_body: proof.body,
    content_hash: proof.contentHash, mutation_hash: proof.mutationHash, ts_signed: proof.signedTs, nonce: proof.nonce, sig: proof.sigBytes };
  assert.equal(verifyAgentRevocationProof(row, master.pubkey, actor.cert).valid, true);
  assert.equal((await insertRevocationEvent(row)).ok, true);
  return proof.mutationHash.toString('hex');
}
try {
  assert.equal((await pool.query('SELECT current_database() AS db')).rows[0].db, database);
  assert.deepEqual((await agentPool.query('SELECT current_database() AS db,current_user AS role')).rows[0], { db: database, role: 'agent_runtime' });
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM agent_identity')).rows[0].n, 0);
  canonicalBefore = await canonicalState();
  const hk = canonicalBefore.identities.filter(i => i.agent_id === 'housekeeper').at(-1); assert(hk);
  const now = Math.floor(Date.now() / 1000), device = sha(database);
  let hkEpoch = now - 300;
  while (canonicalBefore.identities.some(i => i.agent_id === 'housekeeper' && Date.parse(i.valid_from) === hkEpoch * 1000)) hkEpoch--;
  const hkCert = issueCert(loadHousekeeperPrivkey(), { v: 1, agent_id: 'housekeeper', pubkey: hk.pubkey, device_fp: device,
    valid_from: hkEpoch, valid_until: now + 3600, issuer: 'housekeeper', issued_at: now });
  await insertAgent({ agent_id: 'housekeeper', pubkey: hk.pubkey, cert: hkCert, device_fp: device,
    valid_from: new Date(hkEpoch * 1000).toISOString(), valid_until: new Date((now + 3600) * 1000).toISOString() });
  const master = generateKeypair(); await insertMaster(master.pubkey, pubkeyFingerprint(master.pubkey), null, null);
  async function enroll(id, epoch = now - 240, until = now + 3600) {
    assert(!canonicalBefore.identities.some(i => i.agent_id === id));
    const key = generateKeypair();
    const cert = issueCert(master.privkey, { v: 1, agent_id: id, pubkey: key.pubkey, device_fp: device,
      valid_from: epoch, valid_until: until, issuer: 'aimos-master', issued_at: now });
    const actor = { id, ...key, cert, epoch: new Date(epoch * 1000).toISOString() };
    await insertAgent({ agent_id: id, pubkey: key.pubkey, cert, device_fp: device,
      valid_from: actor.epoch, valid_until: new Date(until * 1000).toISOString() });
    return actor;
  }
  const suffix = randomBytes(4).toString('hex');
  const a = await enroll(`aud003a_${suffix}`), b = await enroll(`aud003b_${suffix}`), admin = await enroll(`aud003admin_${suffix}`);
  // Explicit scratch bootstrap only. All later delegation grants traverse the
  // existing admin-gated permissions HTTP route with real envelope signatures.
  const bootstrapBody = { agent_id: admin.id, permissions: { admin_override: true } };
  const bootstrapHeaders = envelope(admin, 'POST', '/permissions/set', bootstrapBody);
  await setPermissions(admin.id, bootstrapBody.permissions, { kind: 'verified_request', body: bootstrapBody,
    agentId: admin.id, validFromIso: admin.epoch, certString: admin.cert,
    signedTs: Number(bootstrapHeaders['Aimos-Agent-Timestamp']), nonce: bootstrapHeaders['Aimos-Agent-Nonce'],
    sigBytes: Buffer.from(bootstrapHeaders['Aimos-Agent-Signature'], 'base64url'), identityTier: 'T1',
    requestSigForm: 3, signedMethod: 'POST', signedPath: '/permissions/set', signedClaims: null }, 'hom');
  assert.equal((await getPermissions(admin.id, 'hom', { subjectValidFromIso: admin.epoch })).admin_override, true);
  assert.equal(providerStatus('codex'), 'unavailable', 'qualification_must_not_invoke_provider');
  const app = express(); app.use(express.json()); app.use(authGate);
  app.use('/task', taskRouter); app.use('/tasks', taskRouter); app.use('/permissions', permissionsRouter);
  app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));
  server = http.createServer(app); await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  for (const alias of ['/task', '/tasks']) {
    const denied = await call(a, 'POST', alias, { agentId: b.id, task: 'ungranted delegation', model: 'codex', allowWeb: false });
    assert.equal(denied.status, 403); assert.equal(denied.body.error, 'target_agent_not_authorized');
  }
  const ownA = await createTask(a), ownB = await createTask(b, b, '/tasks');
  await visible(a, ownA, true); await visible(b, ownA, false); await visible(a, ownB, false); await visible(b, ownB, true);
  for (const alias of ['/task', '/tasks']) {
    const page = await call(a, 'GET', `${alias}?limit=1&status=blocked`);
    assert.deepEqual(page.body.map(r => r.id), [ownA.id]);
    assert.deepEqual((await call(a, 'GET', `${alias}?status=completed`)).body, []);
    const missing = await call(a, 'GET', `${alias}/missing_${suffix}`);
    assert.deepEqual(missing, { status: 404, body: { error: 'Task not found' } });
    assert.equal((await call(a, 'DELETE', `${alias}/${ownA.id}`)).status, 404);
    assert.equal((await call(a, 'POST', `${alias}/${ownA.id}/cancel`)).status, 404);
    assert.equal(tasks.get(ownA.id), ownA);
  }
  observations.push({ case: 'native_owner_nonowner_and_pagination', aliases: 2, unsupported_cancellation_mutated_task: false });
  await grant(admin, a, true);
  const delegated = await createTask(a, b); await visible(a, delegated, true); await visible(b, delegated, true);
  await visible(admin, delegated, false);
  await grant(admin, a, false); await visible(b, delegated, false); await visible(a, delegated, true);
  await grant(admin, a, true); await visible(b, delegated, true);
  observations.push({ case: 'exact_grant_and_signed_false_successor', target_allowed: true, unrelated_admin_allowed: false, revoked_grant_allowed: false, owner_retained: true });
  const b2 = await enroll(b.id, now - 60); await visible(b2, delegated, false); await visible(b, delegated, true);
  const targetRevocation = await revoke(b, master);
  assert.equal((await call(b, 'GET', `/task/${delegated.id}`)).status, 401);
  const delegated2 = await createTask(a, b2, '/tasks'); await visible(b2, delegated2, true);
  observations.push({ case: 'target_epoch_and_revocation', revocation_hash: targetRevocation, fresh_epoch_inherits_old_task: false, fresh_target_task_allowed: true });
  const expiry = Math.floor(Date.now() / 1000) + 8;
  const short = await enroll(`aud003short_${suffix}`, now - 120, expiry);
  await grant(admin, short, true); const expiring = await createTask(short, b2);
  await visible(b2, expiring, true);
  while (Date.now() < (expiry + 1) * 1000) await new Promise(r => setTimeout(r, 100));
  await visible(b2, expiring, false);
  assert.equal((await getPermissions(short.id, 'hom', { subjectValidFromIso: short.epoch })).delegate, false);
  observations.push({ case: 'initiator_certificate_expiry', valid_until: new Date(expiry * 1000).toISOString(), post_expiry_allowed: false });
  const initiatorRevocation = await revoke(a, master); await visible(b2, delegated2, false);
  assert.equal((await call(a, 'GET', `/tasks/${ownA.id}`)).status, 401);
  const a2 = await enroll(a.id, now - 30); await grant(admin, a2, true);
  await visible(a2, ownA, false); await visible(b2, delegated2, false);
  const fresh = await createTask(a2, b2); await visible(a2, fresh, true); await visible(b2, fresh, true);
  observations.push({ case: 'initiator_revocation_and_new_epoch_grant', revocation_hash: initiatorRevocation, new_grant_lends_old_authority: false, fresh_delegation_allowed: true });
  // Controlled loss-of-owner fault on an actually admitted task, not invented
  // historical evidence. No DB or production record is changed.
  tasks.set(fresh.id, { ...fresh, ownership: null });
  await visible(a2, fresh, false); await visible(b2, fresh, false);
  tasks.set(fresh.id, fresh);
  observations.push({ case: 'admitted_task_missing_ownership_fault', disclosed: false, mutation_scope: 'isolated_process_map_only' });
  const events = await readVerifiedEventHistory('hom');
  const authorizations = (await pool.query(`SELECT e.*,i.pubkey AS actor_pubkey FROM aimos_authorization_events e
    JOIN agent_identity i ON i.agent_id=e.actor_agent_id AND i.valid_from=e.actor_valid_from ORDER BY e.created_at`)).rows;
  const groups = new Map();
  for (const row of authorizations) {
    const key = JSON.stringify([row.company_id,row.subject_agent_id,row.subject_valid_from]);
    if (!groups.has(key)) groups.set(key, []); groups.get(key).push(row);
  }
  for (const rows of groups.values()) assert.equal(verifyAuthorizationEventChain(rows, { companyId: 'hom', agentId: rows[0].subject_agent_id }).verified, true);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM aimos_memories')).rows[0].n, 0);
  assert.deepEqual(fileState(), beforeFiles); assert.equal((await canonicalState()).sha256, canonicalBefore.sha256);
  const directory = new URL('../../engineering/remediation/2026-09-05-system-audit/AUD-003/', import.meta.url);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const evidenceFile = new URL(`native-http-postgres-${database}.json`, directory);
  const evidence = { schema: 'hom.aimos.audit-003-native-boundary-evidence/v1', database, observed_at: new Date().toISOString(),
    test_master_pubkey: master.pubkey, test_master_fingerprint: pubkeyFingerprint(master.pubkey),
    bootstrap_admin: { body: bootstrapBody, headers: bootstrapHeaders, native_owner: 'setPermissions', http_admitted: false },
    observations, request_transcripts: requests, admitted_tasks: admittedTasks,
    identities: (await pool.query('SELECT agent_id,valid_from,valid_until,pubkey,cert FROM agent_identity ORDER BY agent_id,valid_from')).rows,
    revocations: (await pool.query('SELECT * FROM aimos_agent_revocation_events ORDER BY created_at')).rows,
    request_receipts: (await pool.query('SELECT * FROM aimos_request_receipts ORDER BY created_at,request_receipt_id')).rows,
    authorization_events: authorizations, events, canonical_identity_and_grant_sha256: canonicalBefore.sha256,
    protected_file_commitments: beforeFiles, private_key_material_retained: false, independent_key_custody_claimed: false,
    provider_invoked: false, tasks_completed: false, housekeeper_http_requests: 0, full_installer_or_custody_enrollment_claimed: false };
  const bytes = Buffer.from(JSON.stringify(evidence, null, 2) + '\n'); writeFileSync(evidenceFile, bytes, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ success: true, node: process.version, database, observations,
    native_request_count: requests.length, verified_event_count: events.length, verified_authorization_count: authorizations.length,
    canonical_identity_and_grants_unchanged: true, canonical_key_and_cache_unchanged: true, canonical_role_or_credential_changed: false,
    provider_invoked: false, tasks_completed: false, evidence_file: evidenceFile.pathname, evidence_sha256: sha(bytes) }, null, 2));
} finally {
  if (server) { server.closeAllConnections(); await new Promise(r => server.close(r)); }
  try { assert.deepEqual(fileState(), beforeFiles); if (canonicalBefore) assert.equal((await canonicalState()).sha256, canonicalBefore.sha256); }
  finally { await Promise.allSettled([pool.end(), agentPool.end(), canonical.end()]); }
}
