#!/usr/bin/env node

// Append one honest signed observation for every retained non-default weight
// that predates the certified cognitive transition chain. This never invents a
// REWEIGHT event or changes a memory. Each baseline is verified by PostgreSQL
// before insert; reruns append nothing once the exact state is attested.

import { createHash } from 'node:crypto';

import { agentPool, pool, query, withTransaction } from '../../db/connection.js';
import { AIMOS_COMPANY_ID, resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import {
  extractValidFromIso,
  getHousekeeperCert,
  signCognitiveBaselineAsHousekeeper,
} from '../../services/security/housekeeper-signer.js';
import { logEvent } from '../../services/observe/event-ledger.js';
import { verifyCognitiveWeightCorpus } from '../../services/security/cognitive-weight-verifier.js';

const live = process.argv.includes('--live');
const database = resolveAimosDatabaseName();
const companyArg = process.argv.find((arg) => arg.startsWith('--company-id='));
const companyId = companyArg ? companyArg.slice('--company-id='.length).trim() : AIMOS_COMPANY_ID;
if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(companyId)) {
  throw new Error('cognitive_company_id_invalid');
}

function merkleRoot(leaves) {
  if (!leaves.length) return createHash('sha256').update(Buffer.alloc(0)).digest();
  if (leaves.length === 1) {
    return createHash('sha256')
      .update(Buffer.concat([Buffer.from([0]), Buffer.from(leaves[0])]))
      .digest();
  }
  let split = 1;
  while ((split << 1) < leaves.length) split <<= 1;
  return createHash('sha256').update(Buffer.concat([
    Buffer.from([1]),
    merkleRoot(leaves.slice(0, split)),
    merkleRoot(leaves.slice(split)),
  ])).digest();
}

async function candidates() {
  const result = await query(
    `SELECT m.id::text, m.content_hash, m.retrieval_weight,
            round(m.retrieval_weight::double precision * 1000)::integer AS weight_milli
       FROM aimos_memories m
      WHERE m.company_id = $1
        AND float4send(m.retrieval_weight) <> float4send(1.0::real)
        AND NOT EXISTS (
          SELECT 1 FROM aimos_cognitive_weight_projections p
           WHERE p.company_id = m.company_id AND p.memory_id = m.id
        )
        AND NOT EXISTS (
          SELECT 1 FROM aimos_cognitive_weight_baselines b
           WHERE b.company_id = m.company_id AND b.memory_id = m.id
        )
      ORDER BY m.id`,
    [companyId],
  );
  return result.rows;
}

try {
  const rows = await candidates();
  if (!live) {
    console.log(JSON.stringify({
      database,
      company_id: companyId,
      mode: 'DRY_RUN',
      requiring_signed_baseline: rows.length,
      historical_origin_claimed: false,
      canonical_memory_mutation: false,
    }, null, 2));
  } else {
    const cert = await getHousekeeperCert();
    const signerValidFromIso = extractValidFromIso(cert);
    const certFingerprint = createHash('sha256').update(String(cert), 'utf8').digest('hex');
    const hashes = [];
    for (const row of rows) {
      const committed = await withTransaction(
        async (client) => {
          const observedTs = Math.floor(Date.now() / 1000);
          const observedWeightFloat4 = Buffer.alloc(4);
          observedWeightFloat4.writeFloatBE(Number(row.retrieval_weight));
          const event = await logEvent(
            companyId,
            'housekeeper',
            'cognitive_initial_weight_attested',
            row.id,
            {
              schema: 'hom.aimos.cognitive-initial-weight/v1',
              observed_weight_float4: observedWeightFloat4.toString('hex'),
              weight_milli: Number(row.weight_milli),
              observed_ts: observedTs,
              memory_content_hash: Buffer.from(row.content_hash).toString('hex'),
              historical_origin_claimed: false,
              canonical_memory_mutation: false,
              reasoning: 'Housekeeper observed one retained pre-chain weight exactly and bound it to the memory content hash without claiming its missing historical trajectory.',
              source_knowledge: 'Certified Cognitive-Weight Trajectory v3 retained initial-weight attestation',
            },
            null,
            { client, returnReceipt: true },
          );
          const eventMutationHash = Buffer.from(event.mutation_hash, 'hex');
          const signed = signCognitiveBaselineAsHousekeeper({
            companyId,
            memoryId: row.id,
            eventId: event.event_id,
            eventMutationHash,
            liveContentHash: Buffer.from(row.content_hash),
            observedWeight: Number(row.retrieval_weight),
            weightMilli: Number(row.weight_milli),
            observedTs,
            signerValidFromIso,
            certFingerprint,
          });
          const result = await client.query(
            `SELECT public.commit_cognitive_weight_baseline(
               $1::uuid,$2::uuid,$3::bytea,$4::bytea,$5::real,$6::integer,
               $7::bigint,$8::timestamptz,$9::text,$10::bytea
             ) AS baseline_hash`,
            [
              row.id,
              event.event_id,
              eventMutationHash,
              Buffer.from(row.content_hash),
              Number(row.retrieval_weight),
              Number(row.weight_milli),
              observedTs,
              signerValidFromIso,
              certFingerprint,
              signed.baselineSig,
            ],
          );
          return { result, event, signed };
        },
        { restricted: true, client_id: companyId, agent_id: 'housekeeper' },
      );
      const storedHash = Buffer.from(committed.result.rows[0].baseline_hash);
      if (!storedHash.equals(committed.signed.baselineHash)) throw new Error(`${row.id}: cognitive_baseline_hash_mismatch`);
      hashes.push(storedHash);
    }
    const root = merkleRoot(hashes);
    const batchTs = Math.floor(Date.now() / 1000);
    const receipt = hashes.length > 0
      ? await logEvent(companyId, 'housekeeper', 'cognitive_weight_baseline_batch', `cognitive-baseline:${batchTs}`, {
          schema: 'hom.aimos.cognitive-baseline-batch/v1',
          observed_ts: batchTs,
          baseline_count: hashes.length,
          baseline_merkle_root: root.toString('hex'),
          historical_origin_claimed: false,
          canonical_memory_mutation: false,
          reasoning: 'Housekeeper attested retained pre-chain non-default weights exactly as observed, without fabricating historical REWEIGHT events or changing any memory.',
          source_knowledge: 'Certified Cognitive-Weight Trajectory v3 retained-baseline doctrine; RFC 6962 domain-separated Merkle tree',
        }, null, { returnReceipt: true })
      : null;
    const portable = await verifyCognitiveWeightCorpus({ companyId });
    const portableRejected = portable.records.filter((row) => !row.ok);
    if (!portable.parity || portableRejected.length > 0) {
      throw new Error(`cognitive_baseline_corpus_verification_failed:${portableRejected.length}`);
    }
    const states = Object.values(portable.sqlRows.reduce((acc, row) => {
      const key = row.certification_status;
      acc[key] ||= { certification_status: key, count: 0, all_ok: true };
      acc[key].count += 1;
      acc[key].all_ok = acc[key].all_ok && Boolean(row.ok);
      return acc;
    }, {})).sort((a, b) => a.certification_status.localeCompare(b.certification_status));
    console.log(JSON.stringify({
      database,
      company_id: companyId,
      mode: 'LIVE',
      attested: hashes.length,
      baseline_merkle_root: root.toString('hex'),
      batch_event_id: receipt?.event_id || null,
      batch_event_mutation_hash: receipt?.mutation_hash || null,
      cognitive_corpus_proof_root: portable.proofRoot.toString('hex'),
      sql_portable_parity: portable.parity,
      states,
    }, null, 2));
  }
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
