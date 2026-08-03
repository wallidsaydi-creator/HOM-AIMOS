import test from 'node:test';
import assert from 'node:assert/strict';

import { lockVerifiedAuthorityEpoch } from '../../services/write/persist-memory.js';

test('verified housekeeper saves use an event-FK-compatible epoch lock', async () => {
  const statements = [];
  const client = {
    async query(sql, params = []) {
      statements.push({ sql, params });
      if (sql.includes('FROM agent_identity')) return { rows: [{ '?column?': 1 }] };
      if (sql.includes('FROM aimos_agent_revocation_events')) return { rows: [] };
      throw new Error(`unexpected SQL: ${sql}`);
    },
  };

  await lockVerifiedAuthorityEpoch(client, {
    kind: 'verified_request',
    agentId: 'housekeeper',
    validFromIso: '2026-07-13T00:00:00.000Z',
    identityTier: 'T1_SYSTEM_SELF',
  }, {
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    clearanceLevel: 1,
    dataClass: 'public',
  });

  const identityLock = statements.find(({ sql }) => sql.includes('FROM agent_identity'))?.sql || '';
  assert.match(identityLock, /FOR NO KEY UPDATE/);
  assert.doesNotMatch(identityLock, /FOR UPDATE/);
});
