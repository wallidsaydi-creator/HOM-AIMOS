#!/usr/bin/env node

import assert from 'node:assert/strict';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import { AIMOS_COMPANY_ID } from '../../services/core/runtime-config.js';
import { pool, agentPool, query, withTransaction } from '../../db/connection.js';
import { applyRewardSignal } from '../../services/learning/stdp-kernel.js';
import { commitGovernorMutation } from '../../services/governance/governor-provenance.js';

const databaseName = resolveAimosDatabaseName();
if (!process.argv.includes('--live-fire') || !/^aimos_test_security_[a-z0-9_]+$/.test(databaseName)) {
  console.log('cognitive weight DB proof skipped (requires --live-fire and disposable aimos_test_security_* database)');
  process.exit(0);
}

try {
  const memoryResult = await query(
    `SELECT id::text, retrieval_weight
       FROM aimos_memories
      WHERE company_id = $1 AND source = 'guide:genesis-install'
      ORDER BY created_at, id
      LIMIT 1`,
    [AIMOS_COMPANY_ID]
  );
  assert.equal(memoryResult.rowCount, 1, 'Genesis must provide a retained Guide memory for cognitive proof');
  const memoryId = memoryResult.rows[0].id;
  const beforeWeight = Number(memoryResult.rows[0].retrieval_weight);

  const delta = await applyRewardSignal(memoryId, -1, {
    coActivationScore: 0.5,
    eta: 0.2,
  });
  assert.ok(delta < 0, 'negative signed evidence must lower retrieval frequency');

  const state = await query(
    `SELECT m.retrieval_weight,
            p.old_weight_milli, p.new_weight_milli,
            p.provenance_mutation_hash, p.projection_hash,
            p.transition_hash, p.transition_sig
       FROM aimos_memories m
       JOIN aimos_cognitive_weight_projections p ON p.memory_id = m.id
      WHERE m.company_id = $1 AND m.id = $2::uuid`,
    [AIMOS_COMPANY_ID, memoryId]
  );
  assert.equal(state.rowCount, 1, 'one certified cognitive projection must be retained');
  const projection = state.rows[0];
  const afterWeight = Number(projection.retrieval_weight);
  assert.ok(afterWeight >= 0.1 && afterWeight <= 3, 'constitutional cognitive bound must hold');
  assert.ok(afterWeight < beforeWeight, 'live projection must match the negative evidence direction');
  assert.equal(Buffer.from(projection.provenance_mutation_hash).length, 32);
  assert.equal(Buffer.from(projection.projection_hash).length, 32);
  assert.equal(Buffer.from(projection.transition_hash).length, 32);
  assert.equal(Buffer.from(projection.transition_sig).length, 64);

  const verification = await withTransaction(
    (client) => client.query('SELECT * FROM public.verify_cognitive_weight_chain($1::uuid)', [memoryId]),
    { restricted: true, client_id: AIMOS_COMPANY_ID, agent_id: 'housekeeper' }
  );
  assert.equal(verification.rows[0]?.ok, true);
  assert.equal(Number(verification.rows[0]?.chain_length), 1);
  assert.equal(Number(verification.rows[0]?.sigs_verified), 1);
  assert.equal(verification.rows[0]?.reason, null);

  const acl = await query(
    `SELECT
       has_table_privilege('agent_runtime', 'public.aimos_cognitive_weight_projections', 'INSERT') AS runtime_insert,
       has_function_privilege(
         'agent_runtime',
         'public.apply_signed_cognitive_reweight(uuid,double precision,double precision,bytea,bytea)',
         'EXECUTE'
       ) AS runtime_execute,
       EXISTS (
         SELECT 1
           FROM information_schema.routine_privileges
          WHERE routine_schema = 'public'
            AND routine_name IN (
              'apply_signed_cognitive_reweight',
              'verify_cognitive_weight_chain',
              'verify_all_cognitive_weight_chains'
            )
            AND grantee = 'PUBLIC'
       ) AS public_execute`
  );
  assert.equal(acl.rows[0].runtime_insert, false, 'runtime must not insert projections directly');
  assert.equal(acl.rows[0].runtime_execute, true, 'runtime may invoke the certified writer');
  assert.equal(acl.rows[0].public_execute, false, 'PUBLIC must not execute cognitive authority functions');

  const attemptedWeight = Math.min(3, afterWeight + 0.01);
  let staleSignatureError = null;
  try {
    await withTransaction(async (client) => {
      const fresh = await commitGovernorMutation({
        memoryId,
        oldWeight: afterWeight,
        newWeight: attemptedWeight,
        judgeValence: 0.1,
        governorFlag: 'COGNITIVE_CHAIN_DB_PROOF',
        reason: 'stale_transition_signature_rejection',
        client,
      });
      assert.equal(fresh.ok, true);
      await client.query(
        'SELECT public.apply_signed_cognitive_reweight($1::uuid, $2, $3, $4, $5)',
        [
          memoryId,
          afterWeight,
          attemptedWeight,
          fresh.mutationHash,
          projection.transition_sig,
        ]
      );
    }, { restricted: true, client_id: AIMOS_COMPANY_ID, agent_id: 'housekeeper' });
  } catch (error) {
    staleSignatureError = String(error?.message || error);
  }
  assert.match(staleSignatureError || '', /cognitive_transition_sig_invalid/);

  const rollback = await query(
    `SELECT count(*)::int AS rows
       FROM aimos_memory_provenance
      WHERE memory_id = $1::uuid
        AND body_json->>'reason' = 'stale_transition_signature_rejection'`,
    [memoryId]
  );
  assert.equal(rollback.rows[0].rows, 0, 'rejected transition and its provisional provenance must roll back atomically');

  console.log(JSON.stringify({
    database_name: databaseName,
    memory_id: memoryId,
    before_weight: beforeWeight,
    after_weight: afterWeight,
    lower_bound_respected: afterWeight >= 0.1,
    chain_length: Number(verification.rows[0].chain_length),
    signatures_verified: Number(verification.rows[0].sigs_verified),
    provenance_mutation_hash: Buffer.from(projection.provenance_mutation_hash).toString('hex'),
    projection_hash: Buffer.from(projection.projection_hash).toString('hex'),
    transition_hash: Buffer.from(projection.transition_hash).toString('hex'),
    stale_signature_rejected: true,
    rejected_provenance_rolled_back: true,
    public_execute: false,
    direct_runtime_insert: false,
  }, null, 2));
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
