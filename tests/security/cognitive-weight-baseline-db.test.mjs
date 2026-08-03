#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { agentPool, pool, query, withTransaction } from '../../db/connection.js';
import { AIMOS_COMPANY_ID, resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import { commitGovernorMutation } from '../../services/governance/governor-provenance.js';
import { logEvent } from '../../services/observe/event-ledger.js';
import {
  extractValidFromIso,
  getHousekeeperCert,
  signCognitiveBaselineAsHousekeeper,
} from '../../services/security/housekeeper-signer.js';
import { verifyCognitiveWeightCorpus } from '../../services/security/cognitive-weight-verifier.js';

const databaseName = resolveAimosDatabaseName();
if (!process.argv.includes('--live-fire') || !/^aimos_test_security_[a-z0-9_]+$/.test(databaseName)) {
  console.log('cognitive baseline DB proof skipped (requires --live-fire and disposable aimos_test_security_* database)');
  process.exit(0);
}

const CID = AIMOS_COMPANY_ID;
const ownerExec = (sql, params = []) => withTransaction(
  (client) => client.query(sql, params),
  { restricted: false, client_id: CID, agent_id: 'housekeeper' },
);

try {
  const memories = await query(
    `SELECT id::text, content_hash
       FROM aimos_memories m
      WHERE company_id=$1 AND source='guide:genesis-install'
        AND NOT EXISTS (SELECT 1 FROM aimos_cognitive_weight_projections p WHERE p.memory_id=m.id)
      ORDER BY id LIMIT 2`,
    [CID],
  );
  assert.equal(memories.rowCount, 2);
  const [baselineMemory, unattestedMemory] = memories.rows;
  const observedWeight = Math.fround(1.2344);
  const observedMilli = Math.round(observedWeight * 1000);
  await ownerExec('UPDATE aimos_memories SET retrieval_weight=$2::real WHERE id=$1::uuid', [baselineMemory.id, observedWeight]);

  const cert = await getHousekeeperCert();
  const signerValidFromIso = extractValidFromIso(cert);
  const certFingerprint = createHash('sha256').update(String(cert), 'utf8').digest('hex');
  const observedTs = Math.floor(Date.now() / 1000);
  const baselineCommit = await withTransaction(async (client) => {
    const observedBytes = Buffer.alloc(4);
    observedBytes.writeFloatBE(observedWeight);
    const event = await logEvent(CID, 'housekeeper', 'cognitive_initial_weight_attested', baselineMemory.id, {
      schema: 'hom.aimos.cognitive-initial-weight/v1',
      observed_weight_float4: observedBytes.toString('hex'),
      weight_milli: observedMilli,
      observed_ts: observedTs,
      memory_content_hash: Buffer.from(baselineMemory.content_hash).toString('hex'),
      historical_origin_claimed: false,
      canonical_memory_mutation: false,
      reasoning: 'Disposable proof attested the exact retained pre-chain float without claiming historical REWEIGHT events.',
      source_knowledge: 'Certified Cognitive-Weight Trajectory v3 baseline proof',
    }, null, { client, returnReceipt: true });
    const eventMutationHash = Buffer.from(event.mutation_hash, 'hex');
    const signed = signCognitiveBaselineAsHousekeeper({
      companyId: CID,
      memoryId: baselineMemory.id,
      eventId: event.event_id,
      eventMutationHash,
      liveContentHash: Buffer.from(baselineMemory.content_hash),
      observedWeight,
      weightMilli: observedMilli,
      observedTs,
      signerValidFromIso,
      certFingerprint,
    });
    const result = await client.query(
      `SELECT public.commit_cognitive_weight_baseline(
         $1::uuid,$2::uuid,$3::bytea,$4::bytea,$5::real,$6::integer,
         $7::bigint,$8::timestamptz,$9::text,$10::bytea
       ) AS baseline_hash`,
      [baselineMemory.id, event.event_id, eventMutationHash, baselineMemory.content_hash,
        observedWeight, observedMilli, observedTs, signerValidFromIso,
        certFingerprint, signed.baselineSig],
    );
    return { event, signed, stored: Buffer.from(result.rows[0].baseline_hash) };
  }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  assert(baselineCommit.stored.equals(baselineCommit.signed.baselineHash));

  const baselineVerification = await withTransaction(
    (client) => client.query('SELECT * FROM public.verify_cognitive_weight_baseline($1::uuid)', [baselineMemory.id]),
    { restricted: true, client_id: CID, agent_id: 'housekeeper' },
  );
  assert.equal(baselineVerification.rows[0].ok, true);

  await withTransaction(async (client) => {
    const mutation = await commitGovernorMutation({
      memoryId: baselineMemory.id,
      oldWeight: observedWeight,
      newWeight: 1.5,
      judgeValence: 0.5,
      governorFlag: 'BASELINE_DB_PROOF',
      reason: 'baseline_anchor_transition',
      client,
    });
    assert.equal(mutation.ok, true);
    await client.query(
      'SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
      [baselineMemory.id, observedWeight, 1.5, mutation.mutationHash, mutation.transitionSig],
    );
  }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  const projection = await query(
    `SELECT old_weight,old_weight_milli,new_weight,new_weight_milli
       FROM aimos_cognitive_weight_projections WHERE memory_id=$1::uuid`,
    [baselineMemory.id],
  );
  assert.equal(projection.rowCount, 1);
  assert.equal(Number(projection.rows[0].old_weight), 1.234);
  assert.equal(Number(projection.rows[0].old_weight_milli), 1234);
  assert.equal(Number(projection.rows[0].new_weight), 1.5);

  await ownerExec('UPDATE aimos_memories SET retrieval_weight=$2::real WHERE id=$1::uuid', [unattestedMemory.id, observedWeight]);
  let unattestedError = null;
  try {
    await withTransaction(async (client) => {
      const mutation = await commitGovernorMutation({
        memoryId: unattestedMemory.id,
        oldWeight: observedWeight,
        newWeight: 1.5,
        judgeValence: 0.5,
        governorFlag: 'BASELINE_DB_PROOF',
        reason: 'unattested_transition_rejected',
        client,
      });
      await client.query(
        'SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
        [unattestedMemory.id, observedWeight, 1.5, mutation.mutationHash, mutation.transitionSig],
      );
    }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  } catch (error) { unattestedError = String(error?.message || error); }
  assert.match(unattestedError || '', /cognitive_initial_weight_attestation_required/);
  await ownerExec('UPDATE aimos_memories SET retrieval_weight=1.0::real WHERE id=$1::uuid', [unattestedMemory.id]);

  const privileges = await query(
    `SELECT has_table_privilege('agent_runtime','public.aimos_cognitive_weight_baselines','INSERT') AS can_insert,
            has_table_privilege('agent_runtime','public.aimos_cognitive_weight_baselines','UPDATE') AS can_update,
            has_table_privilege('agent_runtime','public.aimos_cognitive_weight_baselines','DELETE') AS can_delete`,
  );
  assert.deepEqual(privileges.rows[0], { can_insert: false, can_update: false, can_delete: false });

  const corpus = await verifyCognitiveWeightCorpus({ companyId: CID });
  assert.equal(corpus.parity, true);
  assert.equal(corpus.records.length, Number((await query('SELECT count(*)::int AS n FROM aimos_memories WHERE company_id=$1', [CID])).rows[0].n));
  assert.equal(corpus.records.every((row) => row.ok), true);
  const anchored = corpus.records.find((row) => row.memory_id === baselineMemory.id);
  assert.equal(anchored.certification_status, 'certified_chain');

  console.log(JSON.stringify({
    database_name: databaseName,
    baseline_memory_id: baselineMemory.id,
    baseline_hash: baselineCommit.stored.toString('hex'),
    event_mutation_hash: baselineCommit.event.mutation_hash,
    corpus_proof_root: corpus.proofRoot.toString('hex'),
    sql_portable_parity: corpus.parity,
    unattested_transition_rejected: true,
  }, null, 2));
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
