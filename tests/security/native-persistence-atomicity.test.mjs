#!/usr/bin/env node

import crypto from 'node:crypto';

import { agentPool, pool } from '../../db/connection.js';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import { getPermissions, setPermissions } from '../../services/core/permissions.js';
import {
  generateKeypair,
  issueCert,
  createAgentRevocationProof,
  pubkeyFingerprint,
  signPayloadWithContext,
  signPayloadWithEnvelopeClaims,
  verifyAgentRevocationProof,
} from '../../services/security/agent-identity.js';
import { genesisHashFor } from '../../services/security/identity-chain.js';
import { persistMemory } from '../../services/write/persist-memory.js';
import { recallAuthorizationService } from '../../services/security/recall-authorization.js';
import { resolveNativeRecallAuthority } from '../../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../../services/retrieval/native-recall-pipeline.js';
import { insertRevocationEvent } from '../../scripts/identity/db.js';

const databaseName = resolveAimosDatabaseName();
const liveFire = process.argv.includes('--live-fire');

if (!liveFire || !/^aimos_test_security_[a-z0-9_]+$/.test(databaseName)) {
  console.log('Native persistence live-fire skipped outside an aimos_test_security_* database.');
  process.exit(0);
}

let assertions = 0;

function assert(condition, label, detail = '') {
  if (!condition) {
    throw new Error(`${label}${detail ? `: ${detail}` : ''}`);
  }
  assertions += 1;
  console.log(`  ✓ ${label}`);
}

function memorySpec({ key, value, source, supersedesId = null, authority = 'housekeeper' }) {
  return {
    company_id: 'hom',
    agent_id: 'housekeeper',
    key,
    value,
    scope: 'system',
    clearance_level: 1,
    memory_type: 'test',
    source,
    supersedes_id: supersedesId,
    mutation_authority: authority,
  };
}

async function countByKey(key) {
  const result = await pool.query(
    `SELECT
       count(DISTINCT m.id)::int AS memories,
       count(DISTINCT p.provenance_id)::int AS provenance,
       count(DISTINCT se.id)::int AS supersession_events,
       count(DISTINCT ml.lineage_id)::int AS signed_lineage,
       count(DISTINCT (eme.entity, eme.entity_type, eme.memory_id))::int AS entity_edges
     FROM aimos_memories m
     LEFT JOIN aimos_memory_provenance p ON p.memory_id = m.id
     LEFT JOIN supersession_events se ON se.post_memory_id = m.id
     LEFT JOIN aimos_memory_lineage ml ON ml.child_id = m.id AND ml.attestation_tier = 'D2'
     LEFT JOIN entity_memory_edges eme ON eme.memory_id = m.id
     WHERE m.company_id = 'hom' AND m.key = $1`,
    [key]
  );
  return result.rows[0];
}

async function testRollbackAfterMemoryInsert(runId) {
  console.log('\n[ATOMICITY] provenance failure rolls back the complete native mutation');
  const key = `atomicity-rollback-${runId}`;
  const signedTs = Math.floor(Date.now() / 1000);
  const invalidEpochAuthority = {
    kind: 'verified_request',
    body: {
      company_id: 'hom',
      agent_id: 'missing-atomicity-agent',
      key,
      value: 'On 2026-07-11, atomicity.test.mjs verifies rollback because this deliberately invalid signer epoch must never leave a memory row.',
      ts_signed: signedTs,
    },
    agentId: 'missing-atomicity-agent',
    validFromIso: new Date(signedTs * 1000).toISOString(),
    certString: 'deliberately-invalid-epoch-cert',
    signedTs,
    nonce: crypto.randomBytes(16).toString('base64url'),
    sigBytes: crypto.randomBytes(64),
    identityTier: 'T1',
    claimedPrev: null,
  };

  let rejected = null;
  try {
    await persistMemory(memorySpec({
      key,
      value: invalidEpochAuthority.body.value,
      source: `test:native-persistence-rollback:${runId}`,
      authority: invalidEpochAuthority,
    }));
  } catch (error) {
    rejected = error;
  }

  assert(rejected !== null, 'invalid signer epoch rejects the mutation');
  assert(
    rejected?.envelopeReason === 'agent_not_active'
      || rejected?.envelopeReason === 'agent_epoch_scope_mismatch'
      || rejected?.code === '23503'
      || /foreign key|agent_identity/i.test(String(rejected?.message || '')),
    'failure occurs at the signer-epoch integrity boundary',
    `${rejected?.code || 'no-code'} ${rejected?.message || 'no-message'}`
  );

  const proof = await countByKey(key);
  assert(Number(proof.memories) === 0, 'memory insert rolled back');
  assert(Number(proof.provenance) === 0, 'provenance insert left no residue');
  assert(Number(proof.supersession_events) === 0, 'supersession insert left no residue');
  assert(Number(proof.signed_lineage) === 0, 'signed lineage insert left no residue');
  assert(Number(proof.entity_edges) === 0, 'graph-edge insert left no residue');
}

async function testSignedRevocationRollback(runId, master) {
  console.log('\n[REVOCATION] master-signed terminal event blocks the exact epoch atomically');
  const masterFingerprint = master.fingerprint;
  const identity = await enrollScratchAgent(`revoked-${runId}`, {
    privkey: master.privkey,
    fingerprint: masterFingerprint,
  });

  console.log('\n[RECALL AUTHORITY] master grant admits exact epoch; revocation terminates it');
  const grant = await recallAuthorizationService.commit({
    companyId: 'hom',
    subjectAgentId: identity.agentId,
    subjectValidFrom: identity.validFromIso,
    allowed: true,
    clearanceCeiling: 10,
    dataClassCeiling: 'restricted',
    masterPrivkeyB64u: master.privkey,
    masterFingerprint,
    reason: 'Disposable ordinary-agent native recall proof',
  });
  assert(Buffer.from(grant.mutationHash).length === 32, 'master-signed recall grant has a 32-byte mutation hash');

  const recallBody = {
    company_id: 'hom',
    query: 'how do I save a memory',
    limit: 2,
    clearance_level: 10,
  };
  const recallTs = Math.floor(Date.now() / 1000);
  const recallNonce = crypto.randomBytes(16).toString('base64url');
  const requestAuthority = {
    kind: 'verified_request',
    body: recallBody,
    agentId: identity.agentId,
    validFromIso: identity.validFromIso,
    certString: identity.cert,
    signedTs: recallTs,
    nonce: recallNonce,
    sigBytes: Buffer.from(
      signPayloadWithContext(identity.keys.privkey, recallBody, 'POST', '/aimos/recall', recallNonce, recallTs),
      'base64url'
    ),
    identityTier: 'T1',
    requestSigForm: 3,
    signedMethod: 'POST',
    signedPath: '/aimos/recall',
    signedClaims: null,
  };
  const executionContext = Object.freeze({
    actorAgentId: identity.agentId,
    actorValidFromIso: identity.validFromIso,
    companyId: 'hom',
    identityTier: 'T1',
  });
  const resolvedRecall = await resolveNativeRecallAuthority({
    rawCommand: recallBody,
    executionContext,
    requestAuthority,
    transportBinding: { transport: 'rest' },
  });
  assert(resolvedRecall.clearanceCeiling === 10, 'exact-epoch grant fixes the recall clearance ceiling');
  const recalled = await executeNativeRecall({ ip: '127.0.0.1', headers: {}, originalUrl: '/aimos/recall' }, resolvedRecall);
  assert(recalled.status === 200, 'ordinary agent native recall succeeds with master grant');
  assert(Array.isArray(recalled.body.memories) && recalled.body.memories.length > 0, 'ordinary agent recall returns nonblank admitted Guide memory');
  assert(/^[0-9a-f]{64}$/.test(recalled.body.recall_receipt?.merkle_root || ''), 'ordinary agent recall returns a 32-byte Merkle root');

  const proof = createAgentRevocationProof(master.privkey, {
    agentId: identity.agentId,
    agentValidFrom: identity.validFromIso,
    targetCert: identity.cert,
    masterFingerprint,
    reasonCode: 'isolated_atomicity_proof',
  });
  const committed = await insertRevocationEvent({
    agent_id: identity.agentId,
    agent_valid_from: identity.validFromIso,
    master_fingerprint: masterFingerprint,
    target_cert_hash: proof.targetCertHash,
    prior_identity_hash: proof.priorIdentityHash,
    signed_body: proof.body,
    content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    ts_signed: proof.signedTs,
    nonce: proof.nonce,
    sig: proof.sigBytes,
  });
  assert(committed.ok === true, 'revocation event commits for one exact epoch');

  const stored = await pool.query(
    `SELECT r.*, m.master_pubkey
       FROM aimos_agent_revocation_events r
       JOIN aimos_master_identity m ON m.id = r.master_identity_id
      WHERE r.revocation_event_id = $1`,
    [committed.revocation_event_id]
  );
  const verified = verifyAgentRevocationProof(stored.rows[0], master.pubkey, identity.cert);
  assert(verified.valid === true, 'stored revocation signature and hashes verify');

  const key = `atomicity-revoked-save-${runId}`;
  const body = {
    company_id: 'hom',
    agent_id: identity.agentId,
    key,
    value: 'On 2026-07-11, this revoked-epoch save must roll back because terminal identity evidence already committed.',
    scope: 'agent',
    clearance_level: 1,
    memory_type: 'test',
    source: `test:native-revocation:${runId}`,
  };
  const signedTs = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('base64url');
  body.ts_signed = signedTs;
  let rejected = null;
  try {
    await persistMemory({
      ...body,
      mutation_authority: {
        kind: 'verified_request',
        body,
        agentId: identity.agentId,
        validFromIso: identity.validFromIso,
        certString: identity.cert,
        signedTs,
        nonce,
        sigBytes: Buffer.from(
          signPayloadWithContext(identity.keys.privkey, body, 'POST', '/aimos/save', nonce, signedTs),
          'base64url'
        ),
        identityTier: 'T1',
        claimedPrev: null,
        requestSigForm: 3,
        signedMethod: 'POST',
        signedPath: '/aimos/save',
        signedClaims: null,
      },
    });
  } catch (error) {
    rejected = error;
  }
  assert(rejected?.envelopeReason === 'agent_revoked', 'revoked epoch is rejected at the transaction identity lock');
  const residue = await countByKey(key);
  assert(Number(residue.memories) === 0, 'revoked save leaves no memory');
  assert(Number(residue.provenance) === 0, 'revoked save leaves no provenance');
  const retained = await pool.query(
    `SELECT content_hash, mutation_hash FROM aimos_agent_revocation_events
      WHERE agent_id = $1 AND agent_valid_from = $2`,
    [identity.agentId, identity.validFromIso]
  );
  assert(retained.rows.length === 1, 'terminal revocation proof remains retained');
  assert(Buffer.from(retained.rows[0].content_hash).equals(proof.contentHash), 'retained revocation content hash matches');
  assert(Buffer.from(retained.rows[0].mutation_hash).equals(proof.mutationHash), 'retained revocation mutation hash matches');
  let recallDenied = null;
  try {
    await resolveNativeRecallAuthority({
      rawCommand: recallBody,
      executionContext,
      requestAuthority,
      transportBinding: { transport: 'rest' },
    });
  } catch (error) {
    recallDenied = error;
  }
  assert(recallDenied?.message === 'recall_actor_epoch_not_active', 'terminal revocation blocks recall for the exact granted epoch');
}

async function testParallelLinearChain(runId) {
  console.log('\n[CONCURRENCY] parallel same-key saves form one retained linear chain');
  const key = `atomicity-linear-${runId}`;
  const source = `test:native-persistence-linear:${runId}`;
  const writes = Array.from({ length: 5 }, (_, index) => persistMemory(memorySpec({
    key,
    value: `On 2026-07-11, atomicity.test.mjs created immutable parallel version ${index + 1} because every distinct save must remain retained in one verified chain.`,
    source,
  })));
  const results = await Promise.all(writes);

  assert(results.length === 5 && results.every((row) => row?.id), 'all five parallel saves committed');
  assert(new Set(results.map((row) => row.id)).size === 5, 'all committed memory ids are unique');

  const rowsResult = await pool.query(
    `SELECT id::text, supersedes_id::text
       FROM aimos_memories
      WHERE company_id = 'hom' AND key = $1
      ORDER BY created_at, id`,
    [key]
  );
  const rows = rowsResult.rows;
  const ids = new Set(rows.map((row) => row.id));
  const roots = rows.filter((row) => row.supersedes_id == null);
  assert(rows.length === 5, 'exactly five chain rows exist');
  assert(roots.length === 1, 'chain has exactly one genesis row');
  assert(rows.filter((row) => row.supersedes_id != null).every((row) => ids.has(row.supersedes_id)), 'every predecessor belongs to the same chain');

  const branchResult = await pool.query(
    `SELECT prior_memory_id, count(*)::int AS successors
       FROM supersession_events
      WHERE company_id = 'hom'
        AND post_memory_id = ANY($1::uuid[])
      GROUP BY prior_memory_id
     HAVING count(*) > 1`,
    [rows.map((row) => row.id)]
  );
  assert(branchResult.rowCount === 0, 'no predecessor has more than one successor');

  const proof = await countByKey(key);
  assert(Number(proof.memories) === 5, 'all chain memories are retained');
  assert(Number(proof.provenance) === 10, 'every chain memory has SAVE plus housekeeper BIND provenance');
  assert(Number(proof.supersession_events) === 4, 'chain has exactly N-1 supersession events');
  assert(Number(proof.signed_lineage) === 4, 'every supersession has one D2 signed lineage receipt');
}

async function testTransactionTimestampInversion(runId) {
  console.log('\n[CONCURRENCY] topology head survives transaction-timestamp inversion');
  const key = `atomicity-time-inversion-${runId}`;
  const source = `test:native-persistence-time-inversion:${runId}`;
  const oldClient = await agentPool.connect();
  try {
    await oldClient.query('BEGIN');
    await oldClient.query('SELECT set_config($1,$2,true)', ['app.current_client_id', 'hom']);
    await oldClient.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    await oldClient.query('SELECT transaction_timestamp()');
    await new Promise((resolve) => setTimeout(resolve, 25));

    const newerRoot = await persistMemory(memorySpec({
      key,
      value: 'On 2026-07-11, this newer transaction commits first and becomes the retained topology root so the regression can distinguish transaction time from chain order.',
      source,
    }));
    const olderTimestampSuccessor = await persistMemory({
      ...memorySpec({
        key,
        value: 'On 2026-07-11, this older transaction timestamp commits second and must supersede the topology root because the explicit predecessor link is canonical.',
        source,
      }),
      client: oldClient,
    });
    await oldClient.query('COMMIT');

    const third = await persistMemory(memorySpec({
      key,
      value: 'On 2026-07-11, this third save must follow the retained topology head regardless of created_at ordering, proving timestamps cannot redirect the immutable chain.',
      source,
    }));
    const chain = await pool.query(
      `SELECT id::text, supersedes_id::text, created_at
         FROM aimos_memories
        WHERE company_id = 'hom' AND key = $1`,
      [key]
    );
    const byId = new Map(chain.rows.map((row) => [row.id, row]));
    assert(chain.rowCount === 3, 'all three timestamp-inversion memories are retained');
    assert(
      new Date(byId.get(olderTimestampSuccessor.id).created_at) < new Date(byId.get(newerRoot.id).created_at),
      'the regression fixture contains a real transaction timestamp inversion'
    );
    assert(
      byId.get(olderTimestampSuccessor.id).supersedes_id === newerRoot.id,
      'the older timestamp row still supersedes the committed topology root'
    );
    assert(
      byId.get(third.id).supersedes_id === olderTimestampSuccessor.id,
      'the third save attaches to the topology head rather than the newest timestamp'
    );
  } catch (error) {
    try { await oldClient.query('ROLLBACK'); } catch { /* transaction may already be closed */ }
    throw error;
  } finally {
    oldClient.release();
  }
}

async function testExplicitForkLoserRollsBack(runId) {
  console.log('\n[CONCURRENCY] an explicit predecessor fork has one winner and no residue');
  const key = `atomicity-fork-${runId}`;
  const source = `test:native-persistence-fork:${runId}`;
  const root = await persistMemory(memorySpec({
    key,
    value: 'On 2026-07-11, atomicity.test.mjs created this immutable fork root because database enforcement must permit exactly one successor.',
    source,
  }));

  const candidates = await Promise.allSettled([
    persistMemory(memorySpec({
      key,
      value: 'On 2026-07-11, atomicity.test.mjs created fork candidate alpha; evidence requires exactly one candidate to commit.',
      source,
      supersedesId: root.id,
    })),
    persistMemory(memorySpec({
      key,
      value: 'On 2026-07-11, atomicity.test.mjs created fork candidate beta; therefore the losing transaction must leave no canonical residue.',
      source,
      supersedesId: root.id,
    })),
  ]);
  const fulfilled = candidates.filter((entry) => entry.status === 'fulfilled');
  const rejected = candidates.filter((entry) => entry.status === 'rejected');
  assert(fulfilled.length === 1, 'exactly one explicit fork candidate commits');
  assert(rejected.length === 1, 'exactly one explicit fork candidate is rejected');
  assert(
    ['AIMOS_INVALID_SUPERSEDES', '23505'].includes(rejected[0]?.reason?.code),
    'fork loser is rejected by current-predecessor validation or database uniqueness',
    rejected[0]?.reason?.code || 'no-code'
  );

  const proof = await countByKey(key);
  assert(Number(proof.memories) === 2, 'only root and winner remain');
  assert(Number(proof.provenance) === 4, 'only root and winner SAVE/BIND provenance remain');
  assert(Number(proof.supersession_events) === 1, 'only one successor edge remains');
  assert(Number(proof.signed_lineage) === 1, 'fork loser leaves no signed lineage residue');
}

async function enrollScratchAgent(runId, issuer = null) {
  const agentId = `atomicity-agent-${runId}`;
  const keys = generateKeypair();
  const now = Math.floor(Date.now() / 1000);
  const validFromIso = new Date((now - 60) * 1000).toISOString();
  const validUntilIso = new Date((now + 3600) * 1000).toISOString();
  const cert = issueCert(issuer?.privkey || keys.privkey, {
    v: 1,
    agent_id: agentId,
    pubkey: keys.pubkey,
    device_fp: `scratch-${runId}`,
    valid_from: now - 60,
    valid_until: now + 3600,
    issuer: issuer?.fingerprint || agentId,
    issued_at: now - 60,
  });
  await pool.query(
    `INSERT INTO agent_identity
       (agent_id, pubkey, cert, device_fp, valid_from, valid_until, issued_at, is_system_role)
     VALUES ($1, $2, $3, $4, $5, $6, $5, false)`,
    [agentId, keys.pubkey, cert, `scratch-${runId}`, validFromIso, validUntilIso]
  );
  return { agentId, keys, cert, validFromIso };
}

function verifiedAuthority(identity, body, claimedPrev, nonce = crypto.randomBytes(16).toString('base64url')) {
  const signedTs = Math.floor(Date.now() / 1000);
  body.ts_signed = signedTs;
  const signedClaims = {
    prev_chain_hash: claimedPrev.toString('base64url'),
    device_fp: null,
  };
  return {
    kind: 'verified_request',
    body,
    agentId: identity.agentId,
    validFromIso: identity.validFromIso,
    certString: identity.cert,
    signedTs,
    nonce,
    sigBytes: Buffer.from(
      signPayloadWithEnvelopeClaims(
        identity.keys.privkey,
        body,
        'POST',
        '/aimos/save',
        signedClaims,
        nonce,
        signedTs,
      ),
      'base64url'
    ),
    identityTier: 'T2',
    claimedPrev,
    requestSigForm: 4,
    signedMethod: 'POST',
    signedPath: '/aimos/save',
    signedClaims,
  };
}

async function testT2ChainRaceAndReplay(runId) {
  console.log('\n[T2 ATOMICITY] chain CAS has one winner and durable replay rollback');
  const masterKeys = generateKeypair();
  const master = {
    ...masterKeys,
    fingerprint: pubkeyFingerprint(masterKeys.pubkey),
  };
  await pool.query(
    `INSERT INTO aimos_master_identity (id, master_pubkey, fingerprint)
     VALUES (1, $1, $2)`,
    [master.pubkey, master.fingerprint]
  );
  const identity = await enrollScratchAgent(runId, master);
  await recallAuthorizationService.commit({
    companyId: 'hom',
    subjectAgentId: identity.agentId,
    subjectValidFrom: identity.validFromIso,
    allowed: true,
    writeAllowed: true,
    clearanceCeiling: 10,
    dataClassCeiling: 'restricted',
    masterPrivkeyB64u: master.privkey,
    masterFingerprint: master.fingerprint,
    reason: 'Disposable T2 atomicity save authority',
  });
  const initialHead = genesisHashFor(identity.agentId, identity.validFromIso);
  const bodies = [0, 1].map((index) => ({
    company_id: 'hom',
    agent_id: identity.agentId,
    key: `atomicity-t2-race-${runId}-${index}`,
    value: `On 2026-07-11, atomicity.test.mjs verified T2 race candidate ${index + 1} because exactly one chain claimant may commit.`,
    scope: 'agent',
    clearance_level: 1,
    memory_type: 'test',
    source: `test:native-persistence-t2:${runId}`,
  }));
  const race = await Promise.allSettled(bodies.map((body) => persistMemory({
    ...body,
    mutation_authority: verifiedAuthority(identity, body, initialHead),
  })));
  const winners = race.filter((entry) => entry.status === 'fulfilled');
  const losers = race.filter((entry) => entry.status === 'rejected');
  assert(winners.length === 1, 'exactly one T2 head claimant commits');
  assert(losers.length === 1, 'exactly one T2 head claimant rolls back');
  assert(losers[0]?.reason?.envelopeReason === 'fork_detected', 'T2 loser reports fork_detected');

  const raceProof = await pool.query(
    `SELECT count(DISTINCT m.id)::int AS memories,
            count(DISTINCT p.provenance_id)::int AS provenance,
            count(DISTINCT e.memory_id)::int AS envelopes
       FROM aimos_memories m
       LEFT JOIN aimos_memory_provenance p ON p.memory_id = m.id
       LEFT JOIN aimos_save_envelope e ON e.memory_id = m.id
      WHERE m.source = $1`,
    [`test:native-persistence-t2:${runId}`]
  );
  assert(Number(raceProof.rows[0].memories) === 1, 'T2 race leaves one memory');
  assert(Number(raceProof.rows[0].provenance) === 2, 'T2 race leaves one SAVE plus one BIND provenance row');
  assert(Number(raceProof.rows[0].envelopes) === 1, 'T2 race leaves one envelope row');

  const winnerHead = winners[0].value.envelope_commit.chainHash;
  const headAfterRace = await pool.query(
    `SELECT chain_head FROM agent_identity WHERE agent_id = $1 AND valid_from = $2`,
    [identity.agentId, identity.validFromIso]
  );
  assert(Buffer.from(headAfterRace.rows[0].chain_head).equals(winnerHead), 'agent chain head advances exactly to the winning envelope');

  const replayNonce = crypto.randomBytes(16).toString('base64url');
  const firstReplayBody = {
    company_id: 'hom',
    agent_id: identity.agentId,
    key: `atomicity-t2-replay-first-${runId}`,
    value: 'On 2026-07-11, atomicity.test.mjs committed the first nonce-bearing request as durable T2 evidence.',
    scope: 'agent',
    clearance_level: 1,
    memory_type: 'test',
    source: `test:native-persistence-t2-replay:${runId}`,
  };
  const firstReplay = await persistMemory({
    ...firstReplayBody,
    mutation_authority: verifiedAuthority(identity, firstReplayBody, winnerHead, replayNonce),
  });

  const duplicateBody = {
    company_id: 'hom',
    agent_id: identity.agentId,
    key: `atomicity-t2-replay-loser-${runId}`,
    value: 'On 2026-07-11, atomicity.test.mjs attempted a duplicate nonce; therefore no memory or chain advance may survive.',
    scope: 'agent',
    clearance_level: 1,
    memory_type: 'test',
    source: `test:native-persistence-t2-replay:${runId}`,
  };
  let replayError = null;
  try {
    await persistMemory({
      ...duplicateBody,
      mutation_authority: verifiedAuthority(identity, duplicateBody, firstReplay.envelope_commit.chainHash, replayNonce),
    });
  } catch (error) {
    replayError = error;
  }
  assert(replayError?.envelopeReason === 'replay_detected', 'duplicate nonce remains classified as replay_detected');

  const replayLoserProof = await countByKey(duplicateBody.key);
  assert(Number(replayLoserProof.memories) === 0, 'replay loser leaves no memory');
  assert(Number(replayLoserProof.provenance) === 0, 'replay loser leaves no provenance');
  const finalHead = await pool.query(
    `SELECT chain_head FROM agent_identity WHERE agent_id = $1 AND valid_from = $2`,
    [identity.agentId, identity.validFromIso]
  );
  assert(Buffer.from(finalHead.rows[0].chain_head).equals(firstReplay.envelope_commit.chainHash), 'replay loser chain-head update rolls back');

  console.log('\n[AUTHORIZATION] grant and revoke are retained signed events');
  const authorizationAuthority = (allowed) => {
    const body = { agent_id: identity.agentId, permissions: { internet: allowed } };
    const signedTs = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('base64url');
    return {
      kind: 'verified_request',
      body,
      agentId: identity.agentId,
      validFromIso: identity.validFromIso,
      certString: identity.cert,
      signedTs,
      nonce,
      sigBytes: Buffer.from(
        signPayloadWithContext(identity.keys.privkey, body, 'POST', '/permissions/set', nonce, signedTs),
        'base64url'
      ),
      identityTier: 'T1',
      requestSigForm: 3,
      signedMethod: 'POST',
      signedPath: '/permissions/set',
      signedClaims: null,
    };
  };
  await setPermissions(identity.agentId, { internet: true }, authorizationAuthority(true), 'hom');
  await setPermissions(identity.agentId, { internet: false }, authorizationAuthority(false), 'hom');
  const effectivePermissions = await getPermissions(identity.agentId, 'hom');
  assert(effectivePermissions.internet === false, 'latest signed revoke controls effective permission');
  const authorizationProof = await pool.query(
    `SELECT count(*)::int AS events,
            count(DISTINCT mutation_hash)::int AS mutation_hashes,
            count(*) FILTER (WHERE allowed)::int AS grants,
            count(*) FILTER (WHERE NOT allowed)::int AS revokes
       FROM aimos_authorization_events
      WHERE company_id = 'hom' AND subject_agent_id = $1 AND capability = 'internet'`,
    [identity.agentId]
  );
  assert(Number(authorizationProof.rows[0].events) === 2, 'grant and revoke rows are both retained');
  assert(Number(authorizationProof.rows[0].mutation_hashes) === 2, 'grant and revoke have distinct mutation hashes');
  assert(Number(authorizationProof.rows[0].grants) === 1 && Number(authorizationProof.rows[0].revokes) === 1, 'authorization history contains one grant and one revoke');
  return master;
}

async function main() {
  const runId = crypto.randomBytes(6).toString('hex');
  try {
    await testRollbackAfterMemoryInsert(runId);
    await testParallelLinearChain(runId);
    await testTransactionTimestampInversion(runId);
    await testExplicitForkLoserRollsBack(runId);
    const master = await testT2ChainRaceAndReplay(runId);
    await testSignedRevocationRollback(runId, master);
    console.log(`\nNative persistence atomicity: ${assertions}/${assertions} assertions passed.`);
  } finally {
    await Promise.allSettled([agentPool.end(), pool.end()]);
  }
}

main().catch((error) => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});
