import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  generateKeypair,
  signPayloadWithContext,
} from '../../services/security/agent-identity.js';
import { contentHash } from '../../services/security/identity-chain.js';
import { verifyAuthorizationEventChain } from '../../services/core/permissions.js';

function mutationHash(content, previous, capability, nonce, signedTs) {
  return createHash('sha256').update(Buffer.concat([
    content,
    previous || Buffer.alloc(0),
    Buffer.from(capability),
    Buffer.from(nonce),
    Buffer.from(String(signedTs)),
  ])).digest();
}

function row({ keys, body, allowed, previous = null, nonce, signedTs, id }) {
  const content = contentHash(body);
  const mutation = mutationHash(content, previous, 'memory_read', nonce, signedTs);
  return {
    authorization_event_id: id,
    company_id: 'hom',
    subject_agent_id: 'subject-agent',
    subject_valid_from: '2026-07-11T00:00:00.000Z',
    capability: 'memory_read',
    allowed,
    actor_agent_id: 'admin-agent',
    actor_valid_from: '2026-07-11T00:00:00.000Z',
    actor_pubkey: keys.pubkey,
    signed_body: body,
    content_hash: content,
    mutation_hash: mutation,
    prev_mutation_hash: previous,
    ts_signed: signedTs,
    nonce,
    sig: Buffer.from(signPayloadWithContext(keys.privkey, body, 'POST', '/permissions/set', nonce, signedTs), 'base64url'),
    request_sig_form: 3,
    signed_method: 'POST',
    signed_path: '/permissions/set',
    signed_claims: null,
  };
}

test('authorization reader verifies the complete signed grant/revoke chain', () => {
  const keys = generateKeypair();
  const grant = row({
    keys,
    body: { agent_id: 'subject-agent', permissions: { memory_read: true } },
    allowed: true,
    nonce: 'grant-nonce',
    signedTs: 1783728000,
    id: '00000000-0000-4000-8000-000000000001',
  });
  const revoke = row({
    keys,
    body: { agent_id: 'subject-agent', permissions: { memory_read: false } },
    allowed: false,
    previous: grant.mutation_hash,
    nonce: 'revoke-nonce',
    signedTs: 1783728060,
    id: '00000000-0000-4000-8000-000000000002',
  });

  const verification = verifyAuthorizationEventChain([revoke, grant], {
    companyId: 'hom',
    agentId: 'subject-agent',
  });
  assert.equal(verification.verified, true);
  assert.equal(verification.latestByCapability.get('memory_read'), revoke);
  assert.deepEqual(verification.orderedRows, [grant, revoke]);

  assert.throws(
    () => verifyAuthorizationEventChain([grant, { ...revoke, allowed: true }], {
      companyId: 'hom',
      agentId: 'subject-agent',
    }),
    /authorization_chain_row_mismatch/
  );
  assert.throws(
    () => verifyAuthorizationEventChain([grant, { ...revoke, mutation_hash: Buffer.alloc(32) }], {
      companyId: 'hom',
      agentId: 'subject-agent',
    }),
    /authorization_chain_hash_mismatch/
  );
  assert.throws(
    () => verifyAuthorizationEventChain([
      grant,
      { ...revoke, subject_valid_from: '2026-07-12T00:00:00.000Z' },
    ], {
      companyId: 'hom',
      agentId: 'subject-agent',
    }),
    /authorization_chain_row_mismatch/,
  );

  const alternate = row({
    keys,
    body: { agent_id: 'subject-agent', permissions: { memory_read: true } },
    allowed: true,
    previous: grant.mutation_hash,
    nonce: 'alternate-head-nonce',
    signedTs: 1783728120,
    id: '00000000-0000-4000-8000-000000000003',
  });
  assert.throws(
    () => verifyAuthorizationEventChain([grant, revoke, alternate], {
      companyId: 'hom',
      agentId: 'subject-agent',
    }),
    /authorization_chain_head_invalid/
  );

  const disconnected = row({
    keys,
    body: { agent_id: 'subject-agent', permissions: { memory_read: true } },
    allowed: true,
    previous: Buffer.alloc(32, 7),
    nonce: 'disconnected-nonce',
    signedTs: 1783728180,
    id: '00000000-0000-4000-8000-000000000004',
  });
  assert.throws(
    () => verifyAuthorizationEventChain([grant, disconnected], {
      companyId: 'hom',
      agentId: 'subject-agent',
    }),
    /authorization_chain_disconnected/
  );
});
