import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { cognitiveTransitionHash } from '../../services/security/protocol/mutmem-protocol.js';

const ROOT = new URL('../../', import.meta.url);

test('database enforces the constitutional cognitive interval without rewriting retained memory', async () => {
  const migration = await readFile(new URL('migrations/068-cognitive-weight-constitutional-bound.sql', ROOT), 'utf8');

  assert.match(migration, /retrieval_weight IS NOT NULL AND retrieval_weight >= 0\.1 AND retrieval_weight <= 3\.0/);
  assert.match(migration, /VALIDATE CONSTRAINT aimos_memories_cognitive_weight_bound/);
  assert.doesNotMatch(migration, /UPDATE\s+(?:public\.)?aimos_memories/i);
  assert.doesNotMatch(migration, /DELETE\s+FROM\s+(?:public\.)?aimos_memories/i);
});

test('all native cognitive mutation owners bind updates to signed provenance in one transaction', async () => {
  const [stdp, spiced] = await Promise.all([
    readFile(new URL('services/learning/stdp-kernel.js', ROOT), 'utf8'),
    readFile(new URL('services/dream/spiced-consolidator.js', ROOT), 'utf8'),
  ]);

  for (const source of [stdp, spiced]) {
    assert.match(source, /withTransaction\(async \(client\) => \{/);
    assert.match(source, /pg_advisory_xact_lock\(hashtextextended/);
    // Weight changes travel through the signed reweight function, NOT a raw
    // UPDATE: migration 080 revoked UPDATE(retrieval_weight) from agent_runtime,
    // so a raw `UPDATE aimos_memories` here would fail at runtime. The signed
    // function verifies the committed REWEIGHT provenance and enforces the bound.
    assert.match(source, /apply_signed_cognitive_reweight/);
    assert.doesNotMatch(source, /UPDATE aimos_memories/);
    assert.match(source, /commitGovernorMutation\(\{/);
    assert.match(source, /client/);
    assert.doesNotMatch(source, /SELECT retrieval_weight[^'`]*FOR UPDATE/);
  }
});

test('cognitive transition hash binds tenant, memory, exact quantized weights, and provenance', () => {
  const base = {
    companyId: 'hom',
    memoryId: '00112233-4455-6677-8899-aabbccddeeff',
    oldWeight: 0.1,
    newWeight: 3,
    provenanceMutationHash: Buffer.alloc(32),
  };
  const hash = cognitiveTransitionHash(base);
  assert.equal(hash.toString('hex'), '930a0a94bbb14afc2974aba6e4f0950ae2f50d746934ff1a6f4e749ca015c2b5');
  assert.notDeepEqual(cognitiveTransitionHash({ ...base, companyId: 'other' }), hash);
  assert.notDeepEqual(cognitiveTransitionHash({ ...base, memoryId: '10112233-4455-6677-8899-aabbccddeeff' }), hash);
  assert.notDeepEqual(cognitiveTransitionHash({ ...base, oldWeight: 0.101 }), hash);
  assert.notDeepEqual(cognitiveTransitionHash({ ...base, newWeight: 2.999 }), hash);
  assert.notDeepEqual(cognitiveTransitionHash({ ...base, provenanceMutationHash: Buffer.alloc(32, 1) }), hash);
});

test('forward correction removes all direct cognitive projection writers and public verifier access', async () => {
  const migration = await readFile(new URL('migrations/085-cognitive-transition-binding-and-acl.sql', ROOT), 'utf8');

  assert.match(migration, /c_transition_prefix[\s\S]*61696d6f732e636f676e69746976652d7472616e736974696f6e2f763200/i);
  assert.match(migration, /v_body->>'company_id'\s*<>\s*v_company_id/);
  assert.match(migration, /uuid_send\(p_memory_id\)[\s\S]*int8send\(v_old_milli::int8\)[\s\S]*int8send\(v_new_milli::int8\)[\s\S]*p_provenance_mutation_hash/);
  assert.match(migration, /pgsodium\.crypto_sign_verify_detached\(p_transition_sig, v_transition_hash, v_raw_pub\)/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE[\s\S]*aimos_cognitive_weight_projections FROM agent_runtime/);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.apply_signed_cognitive_reweight[\s\S]*FROM PUBLIC/);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.verify_cognitive_weight_chain\(uuid\) FROM PUBLIC/);
});
