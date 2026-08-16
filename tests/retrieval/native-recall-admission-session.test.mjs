import assert from 'node:assert/strict';
import test from 'node:test';

import {
  openNativeRecallAdmissionSession,
} from '../../services/retrieval/native-recall.js';

const MEMORY_ID = '11111111-1111-4111-8111-111111111111';

test('native recall admission session reuses principal binding while verifying every batch', async () => {
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
  const first = await session.admit([row]);
  const second = await session.admit([row]);
  await session.close({ commit: true });

  assert.equal(first.memories.length, 1);
  assert.equal(second.memories.length, 1);
  assert.equal(verificationCalls, 2);
  assert.equal(statements.filter((entry) => entry.text === 'BEGIN').length, 1);
  assert.equal(statements.filter((entry) => /^SELECT set_config/.test(entry.text)).length, 1);
  const principalBinding = statements.find((entry) => /^SELECT set_config/.test(entry.text));
  assert.deepEqual(principalBinding.params.slice(-2), ['plan_cache_mode', 'force_generic_plan']);
  assert.equal(statements.filter((entry) => /FROM agent_identity/.test(entry.text)).length, 1);
  assert.equal(statements.filter((entry) => entry.text === 'COMMIT').length, 1);
  assert.equal(releases, 1);
  await assert.rejects(session.admit([row]), /recall_admission_session_closed/);
});
