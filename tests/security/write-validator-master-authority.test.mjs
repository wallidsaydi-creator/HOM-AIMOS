import test from 'node:test';
import assert from 'node:assert/strict';

import { checkWritePermission } from '../../services/write/write-validator.js';

const context = Object.freeze({
  actorAgentId: 'purpose-agent',
  actorValidFromIso: '2026-08-12T12:00:00.000Z',
  identityTier: 'T1',
  companyId: 'hom',
});

test('promoted master-signed T1 housekeeper retains intrinsic system write authority', async () => {
  let grantRead = false;
  const result = await checkWritePermission('housekeeper', 'guide:housekeeper:test', {
    identityTier: 'T1',
    verifiedAgentId: 'housekeeper',
    executionContext: {
      actorAgentId: 'housekeeper',
      actorValidFromIso: '2026-08-11T11:21:00.000Z',
      identityTier: 'T1',
      companyId: 'hom',
    },
    getMemoryAuthority: async () => {
      grantRead = true;
      return null;
    },
  });
  assert.equal(result.permitted, true);
  assert.equal(result.systemSelf, true);
  assert.equal(grantRead, false, 'housekeeper system authority must not use the ordinary-agent grant path');
});

test('T1 alone never grants intrinsic write authority to a non-housekeeper', async () => {
  const result = await checkWritePermission('other-agent', 'guide:housekeeper:test', {
    identityTier: 'T1',
    verifiedAgentId: 'other-agent',
    executionContext: {
      actorAgentId: 'other-agent',
      actorValidFromIso: '2026-08-11T11:21:00.000Z',
      identityTier: 'T1',
      companyId: 'hom',
    },
    getMemoryAuthority: async () => null,
  });
  assert.equal(result.permitted, false);
});

test('write validator consumes the exact master-signed memory grant for an envelope identity', async () => {
  let observed = null;
  const result = await checkWritePermission('purpose-agent', 's6:test', {
    executionContext: context,
    getMemoryAuthority: async (scope) => {
      observed = scope;
      return {
        allowed: true,
        writeAllowed: true,
        clearanceCeiling: 10,
        mutationHash: Buffer.alloc(32, 7),
        eventId: 'grant-event',
      };
    },
  });
  assert.equal(result.permitted, true);
  assert.equal(result.authority, 'master_signed_exact_epoch_memory_grant');
  assert.deepEqual(observed, {
    companyId: 'hom',
    subjectAgentId: 'purpose-agent',
    subjectValidFrom: '2026-08-12T12:00:00.000Z',
  });
});

test('write validator fails closed on wrong identity, revocation, and privileged scope below clearance 12', async () => {
  assert.equal((await checkWritePermission('other-agent', 's6:test', {
    executionContext: context,
    getMemoryAuthority: async () => ({ allowed: true, writeAllowed: true, clearanceCeiling: 10 }),
  })).permitted, false);
  assert.equal((await checkWritePermission('purpose-agent', 's6:test', {
    executionContext: context,
    getMemoryAuthority: async () => ({ allowed: false, writeAllowed: false, clearanceCeiling: 0 }),
  })).permitted, false);
  assert.equal((await checkWritePermission('purpose-agent', 'system:test', {
    executionContext: context,
    getMemoryAuthority: async () => ({ allowed: true, writeAllowed: true, clearanceCeiling: 10 }),
  })).permitted, false);
});
