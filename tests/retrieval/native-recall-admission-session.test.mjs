import assert from 'node:assert/strict';
import test from 'node:test';

import {
  NATIVE_RECALL_SESSION_SCALE_CONTRACT,
  admitNativeRecallCandidatesInVerifiedSession,
  createRequestLocalRecallEvidenceCache,
  openNativeRecallAdmissionSession,
} from '../../services/retrieval/native-recall.js';

const MEMORY_ID = '11111111-1111-4111-8111-111111111111';

test('native recall admission session reuses principal binding and same-snapshot verified evidence', async () => {
  const statements = [];
  let releases = 0;
  let verificationCalls = 0;
  const client = {
    async query(text, params) {
      statements.push({ text, params });
      if (/FROM agent_identity/.test(text)) return { rows: [{ active: 1 }] };
      return { rows: [] };
    },
    release() { releases += 1; },
  };
  const authority = {
    companyId: 'hom',
    actorAgentId: 'housekeeper',
    actorValidFromIso: '2026-08-10T00:00:00.000Z',
    identityTier: 'T1_SYSTEM_SELF',
    clearanceCeiling: 12,
    dataClassCeiling: 'restricted',
    authorityMutationHash: Buffer.alloc(32, 7),
    isHousekeeper: true,
    command: {},
  };
  const verifyEvidenceFn = async ({ memoryIds, client: suppliedClient }) => {
    verificationCalls += 1;
    assert.equal(suppliedClient, client);
    assert.deepEqual(memoryIds, [MEMORY_ID]);
    return {
      rejected: [],
      verified: new Set([MEMORY_ID]),
      proofs: new Map([[MEMORY_ID, {
        company_id: 'hom',
        subject_agent_id: 'housekeeper',
        scope: 'system',
        cube_scope: 'shared',
        memory_type: 'fact',
        clearance_level: 1,
        data_class: 'public',
        source: 'fixture',
        version_status: 'current',
      }]]),
    };
  };

  const session = await openNativeRecallAdmissionSession({
    authority,
    connectFn: async () => client,
    verifyEvidenceFn,
  });
  const row = { id: MEMORY_ID, key: 'fixture', value: 'signed evidence' };
  await session.read('WITH fixture AS (SELECT 1 AS value) SELECT value FROM fixture');
  const first = await session.admit([row]);
  const second = await session.admit([row]);
  await session.close({ commit: true });

  assert.equal(first.memories.length, 1);
  assert.equal(second.memories.length, 1);
  assert.equal(verificationCalls, 1);
  assert.deepEqual(first.evidence_cache, {
    schema: 'hom-aimos/request-local-recall-evidence-cache/v1',
    scope: 'request_local_repeatable_read_snapshot',
    cache_size: 1,
    hit_count: 0,
    miss_count: 1,
    verifier_call_count: 1,
    rejected_evidence_cached: false,
    authority: false,
    persistent: false,
  });
  assert.equal(second.evidence_cache.hit_count, 1);
  assert.equal(second.evidence_cache.miss_count, 1);
  assert.equal(statements.filter((entry) => entry.text
    === 'BEGIN ISOLATION LEVEL REPEATABLE READ').length, 1);
  assert.equal(statements.filter((entry) => /^SELECT set_config/.test(entry.text)).length, 1);
  const principalBinding = statements.find((entry) => /^SELECT set_config/.test(entry.text));
  assert.deepEqual(principalBinding.params.slice(-2), ['plan_cache_mode', 'force_generic_plan']);
  assert.equal(statements.filter((entry) => /FROM agent_identity/.test(entry.text)).length, 1);
  assert.equal(statements.filter((entry) => entry.text === 'COMMIT').length, 1);
  assert.equal(releases, 1);
  assert.equal(NATIVE_RECALL_SESSION_SCALE_CONTRACT.restricted_connections_per_request, 1);
  assert.equal(NATIVE_RECALL_SESSION_SCALE_CONTRACT.transaction_isolation, 'repeatable_read');
  assert.equal(NATIVE_RECALL_SESSION_SCALE_CONTRACT.transaction_access,
    'read_interface_with_authority_row_lock');
  assert.equal(NATIVE_RECALL_SESSION_SCALE_CONTRACT.verified_evidence_cache_scope,
    'request_local_repeatable_read_snapshot');
  assert.equal(statements.filter((entry) => /^WITH fixture/.test(entry.text)).length, 1);
  await assert.rejects(
    session.read('INSERT INTO forbidden_table VALUES (1)'),
    /recall_admission_session_closed|recall_admission_read_only_statement_required/,
  );
  await assert.rejects(session.admit([row]), /recall_admission_session_closed/);
});

test('request-local evidence cache never caches rejected evidence', async () => {
  let calls = 0;
  const cache = createRequestLocalRecallEvidenceCache(async ({ memoryIds }) => {
    calls += 1;
    return {
      verified: new Set(),
      proofs: new Map(),
      rejected: memoryIds.map((memoryId) => ({ memory_id: memoryId, reason: 'invalid' })),
    };
  });
  const first = await cache.verify({ memoryIds: [MEMORY_ID] });
  const second = await cache.verify({ memoryIds: [MEMORY_ID] });
  assert.equal(calls, 2);
  assert.equal(first.rejected.length, 1);
  assert.equal(second.rejected.length, 1);
  assert.equal(cache.stats().cache_size, 0);
  assert.equal(cache.stats().hit_count, 0);
  assert.equal(cache.stats().miss_count, 2);
  assert.equal(cache.stats().rejected_evidence_cached, false);
});

test('native recall shared read interface rejects mutation statements before SQL', async () => {
  const statements = [];
  const client = {
    async query(text) {
      statements.push(text);
      if (/FROM agent_identity/.test(text)) return { rows: [{ active: 1 }] };
      return { rows: [] };
    },
    release() {},
  };
  const session = await openNativeRecallAdmissionSession({
    authority: {
      companyId: 'hom', actorAgentId: 'housekeeper',
      actorValidFromIso: '2026-08-10T00:00:00.000Z', identityTier: 'T1_SYSTEM_SELF',
      clearanceCeiling: 12, dataClassCeiling: 'restricted',
      authorityMutationHash: Buffer.alloc(32, 7), isHousekeeper: true, command: {},
    },
    connectFn: async () => client,
  });
  await assert.rejects(
    session.read('WITH changed AS (DELETE FROM aimos_memories RETURNING id) SELECT * FROM changed'),
    /recall_admission_read_only_statement_required/,
  );
  assert.equal(statements.some((text) => /DELETE FROM aimos_memories/.test(text)), false);
  await session.close({ commit: false });
});

test('candidate admission is atomic: one unauthorized proposal rejects the complete lane', async () => {
  const allowedId = MEMORY_ID;
  const deniedId = '22222222-2222-4222-8222-222222222222';
  const authority = {
    companyId: 'hom', actorAgentId: 'codex-auditor',
    actorValidFromIso: '2026-08-10T00:00:00.000Z', identityTier: 'T2_AGENT',
    clearanceCeiling: 4, dataClassCeiling: 'confidential', command: {},
  };
  const client = { query: async () => ({ rows: [] }) };
  const proof = (clearanceLevel) => ({
    company_id: 'hom', subject_agent_id: 'codex-auditor', scope: 'agent',
    cube_scope: 'private', memory_type: 'fact', clearance_level: clearanceLevel,
    data_class: 'confidential', source: 'fixture', version_status: 'current',
  });

  await assert.rejects(
    admitNativeRecallCandidatesInVerifiedSession(
      [
        { id: allowedId, key: 'allowed', value: 'admissible proposal' },
        { id: deniedId, key: 'denied', value: 'over-clearance proposal' },
      ],
      authority,
      client,
      async () => ({
        rejected: [],
        verified: new Set([allowedId, deniedId]),
        proofs: new Map([[allowedId, proof(2)], [deniedId, proof(12)]]),
      }),
    ),
    (error) => {
      assert.match(error.message, /recall_candidate_authorization_failed/);
      assert.deepEqual(error.rejected, [{
        memory_id: deniedId,
        reason: 'recall_proof_not_allowed',
      }]);
      return true;
    },
  );
});

test('optional recall reads recover a failed SQL statement without aborting the shared snapshot', async () => {
  const statements = [];
  const client = {
    async query(text) {
      statements.push(text);
      if (/FROM agent_identity/.test(text)) return { rows: [{ active: 1 }] };
      if (/optional_failure/.test(text)) throw new Error('fixture_optional_sql_failure');
      if (/required_after_failure/.test(text)) return { rows: [{ value: 1 }] };
      return { rows: [] };
    },
    release() {},
  };
  const session = await openNativeRecallAdmissionSession({
    authority: {
      companyId: 'hom', actorAgentId: 'housekeeper',
      actorValidFromIso: '2026-08-10T00:00:00.000Z', identityTier: 'T1_SYSTEM_SELF',
      clearanceCeiling: 12, dataClassCeiling: 'restricted',
      authorityMutationHash: Buffer.alloc(32, 7), isHousekeeper: true, command: {},
    },
    connectFn: async () => client,
  });
  await assert.rejects(
    session.optionalRead('SELECT * FROM optional_failure'),
    /fixture_optional_sql_failure/,
  );
  const after = await session.read('SELECT * FROM required_after_failure');
  assert.equal(after.rows[0].value, 1);
  assert.ok(statements.some((text) => /^SAVEPOINT recall_optional_read_1$/.test(text)));
  assert.ok(statements.some((text) => /^ROLLBACK TO SAVEPOINT recall_optional_read_1$/.test(text)));
  assert.ok(statements.some((text) => /^RELEASE SAVEPOINT recall_optional_read_1$/.test(text)));
  await session.close({ commit: false });
});
