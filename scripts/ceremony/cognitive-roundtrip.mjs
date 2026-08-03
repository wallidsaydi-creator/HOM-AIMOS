#!/usr/bin/env node

// Release proof for the signed cognitive path. It deliberately applies both
// negative and positive evidence to show bounded, reversible mutation without
// erasing memory or prior evidence.

import { pool, query } from '../../db/connection.js';
import { applyRewardSignal } from '../../services/learning/stdp-kernel.js';
import { valenceLedger } from '../../services/governance/valence-ledger.js';
import { verifyPayloadSig } from '../../services/security/agent-identity.js';

const memoryId = 'cc8d888b-54bf-49f9-afe3-e2b36988b03f';
const outcomes = [-1, -1, 1, 1, 1, 1, 1, 1];

try {
  const before = await query('SELECT retrieval_weight FROM aimos_memories WHERE id = $1', [memoryId]);
  if (!before.rows[0]) throw new Error('ceremony memory is missing');

  const trajectory = [];
  for (const reward of outcomes) {
    const delta = await applyRewardSignal(memoryId, reward, { coActivationScore: 0.5 });
    const current = await query('SELECT retrieval_weight FROM aimos_memories WHERE id = $1', [memoryId]);
    trajectory.push({ reward, delta_weight: delta, retrieval_weight: Number(current.rows[0].retrieval_weight) });
  }

  const pubkey = await query(
    `SELECT pubkey FROM agent_identity identity
      WHERE agent_id = 'housekeeper'
        AND NOT EXISTS (
          SELECT 1 FROM aimos_agent_revocation_events revocation
           WHERE revocation.agent_id = identity.agent_id
             AND revocation.agent_valid_from = identity.valid_from
        )
      ORDER BY valid_from DESC LIMIT 1`
  );
  const valenceProof = await valenceLedger.verifyValenceChain(memoryId, {
    pubkey: pubkey.rows[0]?.pubkey,
    verifySigFn: verifyPayloadSig
  });
  if (!valenceProof.ok) throw new Error(`valence chain invalid: ${JSON.stringify(valenceProof)}`);

  const reweights = await query(
    `SELECT body_json, nonce, ts_signed, sig, content_hash, mutation_hash
       FROM aimos_memory_provenance
      WHERE memory_id = $1 AND event_type = 'REWEIGHT'
      ORDER BY created_at DESC, provenance_id DESC LIMIT 8`,
    [memoryId]
  );
  const reweightSignaturesOk = reweights.rows.length === outcomes.length && reweights.rows.every((row) =>
    verifyPayloadSig(
      pubkey.rows[0]?.pubkey,
      row.body_json,
      row.nonce,
      Number(row.ts_signed),
      Buffer.from(row.sig).toString('base64url')
    ).valid
  );
  if (!reweightSignaturesOk) throw new Error('reweight provenance signatures invalid');

  const after = await query('SELECT retrieval_weight FROM aimos_memories WHERE id = $1', [memoryId]);
  const weights = trajectory.map((step) => step.retrieval_weight);
  console.log(JSON.stringify({
    memory_id: memoryId,
    before_weight: Number(before.rows[0].retrieval_weight),
    after_weight: Number(after.rows[0].retrieval_weight),
    minimum_weight: Math.min(...weights),
    maximum_weight: Math.max(...weights),
    lower_bound_respected: Math.min(...weights) >= 0.1,
    reversible: weights[1] < Number(before.rows[0].retrieval_weight)
      && Number(after.rows[0].retrieval_weight) > Number(before.rows[0].retrieval_weight),
    trajectory,
    valence_chain: {
      length: valenceProof.length,
      head_hash: Buffer.from(valenceProof.head).toString('hex'),
      signature_verified: true
    },
    reweight_provenance: reweights.rows.map((row) => ({
      content_hash: Buffer.from(row.content_hash).toString('hex'),
      mutation_hash: Buffer.from(row.mutation_hash).toString('hex')
    })),
    reweight_signatures_verified: true
  }, null, 2));
} finally {
  await pool.end();
}
