#!/usr/bin/env node

// Phase 5 — behavioral proof of the certified cognitive-weight chain.
// Complements cognitive-weight-chain-db.test.mjs (single-link) with the
// multi-link BIDIRECTIONAL trajectory (good→bad→good) and TAMPER-EVIDENCE on
// BOTH layers (SHA-256 chain + Ed25519 signature) + negative guards + existence
// preservation. Every behavior here was proven manually during Phases 2–3;
// this codifies it. Runs only under the isolated security harness against a
// disposable aimos_test_security_* database.
// SPEC: docs/security/cognitive-weight-chain-SPEC.md §7.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { resolveAimosDatabaseName, AIMOS_COMPANY_ID } from '../../services/core/runtime-config.js';
import { pool, agentPool, query, withTransaction } from '../../db/connection.js';
import { commitGovernorMutation } from '../../services/governance/governor-provenance.js';
import { applyRewardSignal } from '../../services/learning/stdp-kernel.js';
import { verifyCognitiveWeightCorpus } from '../../services/security/cognitive-weight-verifier.js';
import { canonicalJson } from '../../services/security/agent-identity.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { resolveNativeRecallAuthority } from '../../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../../services/retrieval/native-recall-pipeline.js';

const databaseName = resolveAimosDatabaseName();
if (!process.argv.includes('--live-fire') || !/^aimos_test_security_[a-z0-9_]+$/.test(databaseName)) {
  console.log('cognitive weight bidirectional DB proof skipped (requires --live-fire and disposable aimos_test_security_* database)');
  process.exit(0);
}

const CID = AIMOS_COMPANY_ID;
const evidenceFileIndex = process.argv.indexOf('--evidence-file');
const evidenceFile = evidenceFileIndex >= 0 ? process.argv[evidenceFileIndex + 1] : null;
const measuredTransitions = [];

function percentile(values, probability) {
  const ordered = [...values].sort((a, b) => a - b);
  const index = (ordered.length - 1) * probability;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return ordered[lower];
  return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function verify(memoryId) {
  return withTransaction(
    (client) => client.query('SELECT * FROM public.verify_cognitive_weight_chain($1::uuid)', [memoryId]),
    { restricted: true, client_id: CID, agent_id: 'housekeeper' }
  ).then((r) => r.rows[0]);
}

// One signed, chained transition through the real certified writer, with
// EXPLICIT old→new so direction and quantized magnitude are deterministic
// (applyRewardSignal's aggregate valence is not — a net-zero signal is a no-op).
// A DB-level tamper: the OWNER pool (agent_runtime cannot UPDATE at all), with
// the company GUC set so FORCE-RLS permits the write — i.e. an attacker with
// direct table access and tenant context. This is the threat the chain defends.
function ownerExec(sql, params) {
  return withTransaction((client) => client.query(sql, params),
    { restricted: false, client_id: CID, agent_id: 'housekeeper' });
}

async function reweight(memoryId, oldWeight, newWeight, reason, { measure = false } = {}) {
  const started = process.hrtime.bigint();
  const result = await withTransaction(async (client) => {
    const m = await commitGovernorMutation({
      memoryId, oldWeight, newWeight, judgeValence: newWeight > oldWeight ? 0.5 : -0.5,
      governorFlag: 'BIDIR_PROOF', reason, client,
    });
    assert.equal(m.ok, true, `commit ${reason}`);
    await client.query(
      'SELECT public.apply_signed_cognitive_reweight($1::uuid, $2, $3, $4, $5)',
      [memoryId, oldWeight, newWeight, m.mutationHash, m.transitionSig]
    );
    return {
      provenance_mutation_hash: Buffer.from(m.mutationHash).toString('hex'),
      transition_hash: Buffer.from(m.transitionHash).toString('hex'),
    };
  }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
  if (measure) {
    measuredTransitions.push({
      ordinal: measuredTransitions.length + 1,
      direction: newWeight > oldWeight ? 'up' : 'down',
      old_weight_milli: Math.round(oldWeight * 1000),
      new_weight_milli: Math.round(newWeight * 1000),
      latency_ms: latencyMs,
      ...result,
    });
  }
  return { ...result, latency_ms: latencyMs };
}

async function signedPostMutationRecall(memoryId) {
  const body = {
    company_id: CID,
    agent_id: 'housekeeper',
    memory_id: memoryId,
    limit: 1,
    clearance_level: 12,
    cache: false,
    semantic_cache: false,
  };
  const signed = await signAsHousekeeper(body, {
    method: 'POST',
    path: '/aimos/recall',
  });
  const requestAuthority = Object.freeze({
    kind: 'verified_request',
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    requestSigForm: signed.sigForm,
    signedMethod: signed.signedMethod,
    signedPath: signed.signedPath,
    signedClaims: signed.signedClaims,
  });
  const executionContext = Object.freeze({
    actorAgentId: signed.agentId,
    actorValidFromIso: signed.validFromIso,
    companyId: CID,
    identityTier: signed.identityTier,
  });
  const authority = await resolveNativeRecallAuthority({
    rawCommand: signed.body,
    executionContext,
    requestAuthority,
    transportBinding: { transport: 'rest' },
  });
  const recalled = await executeNativeRecall(
    { ip: '127.0.0.1', headers: {}, originalUrl: '/aimos/recall' },
    authority,
  );
  assert.equal(recalled.status, 200, 'post-mutation native recall succeeds');
  assert.equal(recalled.body.success, true, 'post-mutation native recall returns success');
  assert.equal(recalled.body.memories.length, 1, 'post-mutation exact recall returns one memory');
  assert.equal(String(recalled.body.memories[0].id), memoryId, 'post-mutation recall returns the mutated memory');
  const receipt = recalled.body.recall_receipt;
  assert.match(String(receipt?.merkle_root || ''), /^[0-9a-f]{64}$/, 'post-mutation recall returns a Merkle root');
  assert.equal(receipt.evidence?.length, 1, 'post-mutation receipt binds one recalled memory');
  assert.equal(String(receipt.evidence[0].memory_id), memoryId, 'post-mutation receipt binds the mutated memory');
  assert.match(String(receipt.event_receipt?.mutation_hash || ''), /^[0-9a-f]{64}$/, 'post-mutation recall event is ledgered');
  return {
    returned_memory_count: recalled.body.memories.length,
    receipt_evidence_count: receipt.evidence.length,
    command_hash: receipt.command_hash,
    merkle_root: receipt.merkle_root,
    event_id: receipt.event_receipt.event_id,
    event_mutation_hash: receipt.event_receipt.mutation_hash,
  };
}

try {
  // ── a retained Guide memory with NO existing chain (order-independent: other
  //    cognitive tests in the harness mutate a different Guide memory) ─────────
  const mem = await query(
    `SELECT m.id::text, m.retrieval_weight, m.is_active
       FROM aimos_memories m
      WHERE m.company_id = $1 AND m.source = 'guide:genesis-install'
        AND NOT EXISTS (
          SELECT 1 FROM aimos_cognitive_weight_projections p WHERE p.memory_id = m.id)
      ORDER BY m.created_at DESC, m.id DESC LIMIT 1`,
    [CID]
  );
  assert.equal(mem.rowCount, 1, 'Genesis must provide a retained Guide memory with a clean chain');
  const memoryId = mem.rows[0].id;
  assert.equal(mem.rows[0].is_active, true, 'memory starts active');

  // ── retained evidence may pass through neutral without being rolled back ──
  // -1 moves down; the balancing +1 makes cumulative valence zero and therefore
  // creates no transition, but its signed valence row must commit. A later +1
  // then crosses to positive and moves the same memory back up.
  const balanceMem = await query(
    `SELECT m.id::text
       FROM aimos_memories m
      WHERE m.company_id = $1 AND m.source = 'guide:genesis-install'
        AND m.id <> $2::uuid
        AND NOT EXISTS (
          SELECT 1 FROM aimos_cognitive_weight_projections p WHERE p.memory_id = m.id)
      ORDER BY m.created_at DESC, m.id DESC LIMIT 1`,
    [CID, memoryId]
  );
  assert.equal(balanceMem.rowCount, 1, 'second retained memory available for neutral-crossing proof');
  const balanceMemoryId = balanceMem.rows[0].id;
  const negativeDelta = await applyRewardSignal(balanceMemoryId, -1, { eta: 0.2 });
  const neutralDelta = await applyRewardSignal(balanceMemoryId, 1, { eta: 0.2 });
  assert.ok(negativeDelta < 0, 'negative evidence attenuates');
  assert.equal(neutralDelta, 0, 'balancing evidence creates no fictitious transition');
  const neutralState = await query(
    `SELECT
       (SELECT count(*)::int FROM memory_valence_ledger WHERE memory_id = $1::uuid) AS valence_rows,
       (SELECT count(*)::int FROM aimos_cognitive_weight_projections WHERE memory_id = $1::uuid) AS projection_rows,
       (SELECT count(*)::int FROM aimos_events WHERE operation = 'cognitive_weight_unchanged' AND key = $1::text) AS neutral_events`,
    [balanceMemoryId]
  );
  assert.equal(neutralState.rows[0].valence_rows, 2, 'both signed outcomes retained');
  assert.equal(neutralState.rows[0].projection_rows, 1, 'neutral evidence appends no REWEIGHT');
  assert.equal(neutralState.rows[0].neutral_events, 1, 'signed no-transition outcome retained');
  const positiveDelta = await applyRewardSignal(balanceMemoryId, 1, { eta: 0.2 });
  assert.ok(positiveDelta > 0, 'later positive evidence crosses neutral and elevates');
  const balanceChain = await verify(balanceMemoryId);
  assert.equal(balanceChain.ok, true, 'negative→neutral→positive evidence leaves a valid chain');
  assert.equal(Number(balanceChain.chain_length), 2, 'only the two real weight transitions are chained');

  // ── latency and storage: 20 signed transitions over the exact native
  //    provenance + certified-writer transaction boundary. The logical bytes
  //    are PostgreSQL row sizes; allocated relation deltas are reported
  //    separately because page allocation is block-granular. ────────────────
  const measureMem = await query(
    `SELECT m.id::text, m.retrieval_weight
       FROM aimos_memories m
      WHERE m.company_id = $1 AND m.source = 'guide:genesis-install'
        AND m.id <> ALL($2::uuid[])
        AND NOT EXISTS (
          SELECT 1 FROM aimos_cognitive_weight_projections p WHERE p.memory_id = m.id)
      ORDER BY m.created_at DESC, m.id DESC LIMIT 1`,
    [CID, [memoryId, balanceMemoryId]]
  );
  assert.equal(measureMem.rowCount, 1, 'third retained memory available for overhead measurement');
  const measureMemoryId = measureMem.rows[0].id;
  const relationBefore = await query(
    `SELECT
       pg_total_relation_size('public.aimos_memory_provenance')::bigint AS provenance_bytes,
       pg_total_relation_size('public.aimos_cognitive_weight_projections')::bigint AS projection_bytes`
  );
  let measuredWeight = Number(measureMem.rows[0].retrieval_weight);
  for (let ordinal = 0; ordinal < 20; ordinal += 1) {
    const next = ordinal % 2 === 0 ? 1.1 : 0.9;
    await reweight(measureMemoryId, measuredWeight, next, `publication_latency_${ordinal + 1}`, { measure: true });
    measuredWeight = next;
  }
  const relationAfter = await query(
    `SELECT
       pg_total_relation_size('public.aimos_memory_provenance')::bigint AS provenance_bytes,
       pg_total_relation_size('public.aimos_cognitive_weight_projections')::bigint AS projection_bytes`
  );
  const rowStorage = await query(
    `SELECT p.projection_id::text,
            pg_column_size(p)::int AS projection_row_bytes,
            pg_column_size(pr)::int AS provenance_row_bytes
       FROM aimos_cognitive_weight_projections p
       JOIN aimos_memory_provenance pr
         ON pr.memory_id=p.memory_id
        AND pr.mutation_hash=p.provenance_mutation_hash
      WHERE p.memory_id=$1::uuid
      ORDER BY p.applied_at,p.projection_id`,
    [measureMemoryId]
  );
  assert.equal(rowStorage.rowCount, measuredTransitions.length, 'one projection/provenance pair per measured transition');

  // ── good → bad → good: three explicit signed, chained transitions ──────────
  // Anchored to the memory's real starting weight so link1.old == live weight.
  const start = Number(mem.rows[0].retrieval_weight);        // genesis default (1.0)
  const wUp1 = Math.min(3.0, start + 0.3);                   // good ↑
  const wDown = Math.max(0.1, wUp1 - 0.4);                   // bad  ↓
  const wUp2 = Math.min(3.0, wDown + 0.5);                   // good ↑ again
  await reweight(memoryId, start, wUp1, 'bidir_up_1');
  await reweight(memoryId, wUp1, wDown, 'bidir_down');
  await reweight(memoryId, wDown, wUp2, 'bidir_up_2');

  // ── both layers verify: 3-link chain, 3 signatures, terminal fidelity ──────
  let v = await verify(memoryId);
  assert.equal(v.ok, true, 'intact bidirectional chain verifies');
  assert.equal(Number(v.chain_length), 3, 'three certified transitions');
  assert.equal(Number(v.sigs_verified), 3, 'every Ed25519 signature verified in-DB');
  assert.equal(v.reason, null);

  // the trajectory actually moved both ways (not a monotone ratchet)
  const millis = await query(
    `SELECT old_weight_milli, new_weight_milli
       FROM aimos_cognitive_weight_projections
      WHERE memory_id = $1::uuid ORDER BY applied_at`,
    [memoryId]
  );
  assert.equal(millis.rowCount, 3);
  assert.ok(millis.rows[0].new_weight_milli > millis.rows[0].old_weight_milli, 'link1 up');
  assert.ok(millis.rows[1].new_weight_milli < millis.rows[1].old_weight_milli, 'link2 down');
  assert.ok(millis.rows[2].new_weight_milli > millis.rows[2].old_weight_milli, 'link3 up');

  // ── TAMPER LAYER 1 (hash chain): edit the middle transition as a DB attacker.
  //    agent_runtime cannot; the owner pool can — that IS the threat model. ───
  const midOrig = millis.rows[1].new_weight_milli;
  const midBad = midOrig === 900 ? 901 : 900;
  await ownerExec(
    `UPDATE aimos_cognitive_weight_projections
        SET new_weight_milli = $2::integer,
            new_weight = ($2::integer::double precision / 1000.0)::real
      WHERE memory_id = $1::uuid AND new_weight_milli = $3`,
    [memoryId, midBad, midOrig]
  );
  v = await verify(memoryId);
  assert.equal(v.ok, false, 'tampered transition detected');
  // The milli is TRIPLE-bound — in the projection hash (§4.1), the transition
  // signature (§4.2), AND the signed provenance body — so tampering it trips
  // whichever binding the verifier checks first. All are cryptographic layers.
  assert.match(String(v.reason), /provenance_binding_invalid|hash_mismatch|continuity_break|signature_invalid/,
    `milli tamper must trip a cryptographic binding, got: ${v.reason}`);
  await ownerExec(
    `UPDATE aimos_cognitive_weight_projections
        SET new_weight_milli = $2::integer,
            new_weight = ($2::integer::double precision / 1000.0)::real
      WHERE memory_id = $1::uuid AND new_weight_milli = $3`,
    [memoryId, midOrig, midBad]
  );
  v = await verify(memoryId);
  assert.equal(v.ok, true, 'chain verifies again after restore');

  // ── TAMPER LAYER 2 (Ed25519 signature): flip one signature byte ────────────
  await ownerExec(
    `UPDATE aimos_cognitive_weight_projections
        SET transition_sig = set_byte(transition_sig, 0, (get_byte(transition_sig, 0) # 1))
      WHERE memory_id = $1::uuid AND new_weight_milli = $2`,
    [memoryId, millis.rows[2].new_weight_milli]
  );
  v = await verify(memoryId);
  assert.equal(v.ok, false, 'tampered signature detected');
  assert.equal(v.reason, 'signature_invalid', 'localized to the signature layer');
  await ownerExec(
    `UPDATE aimos_cognitive_weight_projections
        SET transition_sig = set_byte(transition_sig, 0, (get_byte(transition_sig, 0) # 1))
      WHERE memory_id = $1::uuid AND new_weight_milli = $2`,
    [memoryId, millis.rows[2].new_weight_milli]
  );
  v = await verify(memoryId);
  assert.equal(v.ok, true, 'chain verifies again after signature restore');

  // ── TAMPER terminal fidelity: change the live weight without touching chain ─
  const liveBefore = (await query('SELECT retrieval_weight FROM aimos_memories WHERE id = $1::uuid', [memoryId])).rows[0].retrieval_weight;
  const liveBad = Number(liveBefore) >= 2.5 ? 1.0 : 2.5;
  await ownerExec('UPDATE aimos_memories SET retrieval_weight = $2 WHERE id = $1::uuid', [memoryId, liveBad]);
  v = await verify(memoryId);
  assert.equal(v.ok, false, 'divergent live weight detected');
  assert.equal(v.reason, 'terminal_weight_mismatch');
  await ownerExec('UPDATE aimos_memories SET retrieval_weight = $2 WHERE id = $1::uuid', [memoryId, liveBefore]);
  v = await verify(memoryId);
  assert.equal(v.ok, true, 'chain verifies again after live-weight restore');
  const terminalWeight = Number((await query(
    'SELECT retrieval_weight FROM aimos_memories WHERE id = $1::uuid',
    [memoryId]
  )).rows[0].retrieval_weight);

  // ── AUTHORIZATION BOUNDARY: the runtime role cannot update the live weight
  //    or append a projection directly. This proves the database boundary,
  //    independent of application routing. ──────────────────────────────────
  let unauthorizedUpdateError = null;
  try {
    await withTransaction(
      (client) => client.query(
        'UPDATE public.aimos_memories SET retrieval_weight=$2 WHERE id=$1::uuid',
        [memoryId, 1.234]
      ),
      { restricted: true, client_id: CID, agent_id: 'housekeeper' }
    );
  } catch (error) {
    unauthorizedUpdateError = String(error?.message || error);
  }
  assert.match(unauthorizedUpdateError || '', /permission denied/i, 'runtime direct weight update rejected by PostgreSQL ACL');

  // A valid proof for one memory is not authority for another memory.
  let wrongMemoryError = null;
  try {
    await withTransaction(async (client) => {
      const proof = await commitGovernorMutation({
        memoryId,
        oldWeight: terminalWeight,
        newWeight: Math.min(3, terminalWeight + 0.01),
        judgeValence: 0.1,
        governorFlag: 'BIDIR_PROOF',
        reason: 'wrong_memory_probe',
        client,
      });
      assert.equal(proof.ok, true);
      const otherWeight = Number((await client.query(
        'SELECT retrieval_weight FROM aimos_memories WHERE id=$1::uuid',
        [balanceMemoryId]
      )).rows[0].retrieval_weight);
      await client.query(
        'SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
        [balanceMemoryId, otherWeight, Math.min(3, otherWeight + 0.01), proof.mutationHash, proof.transitionSig]
      );
    }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  } catch (error) {
    wrongMemoryError = String(error?.message || error);
  }
  assert.match(wrongMemoryError || '', /signed_cognitive_provenance_required|transition_mismatch/i,
    'cross-memory proof reuse rejected');

  // Tenant scope is part of the writer and signature commitments.
  let wrongCompanyError = null;
  try {
    await withTransaction(
      (client) => client.query(
        'SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
        [memoryId, terminalWeight, Math.min(3, terminalWeight + 0.01), Buffer.alloc(32), Buffer.alloc(64)]
      ),
      { restricted: true, client_id: 'not-hom', agent_id: 'housekeeper' }
    );
  } catch (error) {
    wrongCompanyError = String(error?.message || error);
  }
  assert.match(wrongCompanyError || '', /cognitive_memory_not_found|signed_cognitive_provenance_required/i,
    'cross-company scope rejected');

  // Two genesis children for one memory are structurally impossible even to
  // an owner-level direct-table attacker. The complete probe transaction rolls
  // back, including its two provisional signed provenance rows.
  const forkMem = await query(
    `SELECT m.id::text, m.retrieval_weight
       FROM aimos_memories m
      WHERE m.company_id=$1 AND m.source='guide:genesis-install'
        AND m.id <> ALL($2::uuid[])
        AND NOT EXISTS (
          SELECT 1 FROM aimos_cognitive_weight_projections p WHERE p.memory_id=m.id)
      ORDER BY m.created_at DESC,m.id DESC LIMIT 1`,
    [CID, [memoryId, balanceMemoryId, measureMemoryId]]
  );
  assert.equal(forkMem.rowCount, 1, 'fourth retained memory available for fork probe');
  let forkError = null;
  try {
    await withTransaction(async (client) => {
      const first = await commitGovernorMutation({
        memoryId: forkMem.rows[0].id,
        oldWeight: 1,
        newWeight: 1.1,
        judgeValence: 0.1,
        governorFlag: 'BIDIR_PROOF',
        reason: 'fork_probe_a',
        client,
      });
      const second = await commitGovernorMutation({
        memoryId: forkMem.rows[0].id,
        oldWeight: 1,
        newWeight: 1.2,
        judgeValence: 0.1,
        governorFlag: 'BIDIR_PROOF',
        reason: 'fork_probe_b',
        client,
      });
      assert.equal(first.ok, true);
      assert.equal(second.ok, true);
      await client.query(
        `INSERT INTO public.aimos_cognitive_weight_projections
           (company_id,memory_id,provenance_mutation_hash,old_weight,new_weight,
            old_weight_milli,new_weight_milli,prev_projection_hash,projection_hash,
            transition_hash,transition_sig)
         VALUES
           ($1,$2::uuid,$3,1::real,1.1::real,1000,1100,NULL,$4,$5,$6),
           ($1,$2::uuid,$7,1::real,1.2::real,1000,1200,NULL,$8,$9,$10)`,
        [
          CID, forkMem.rows[0].id,
          first.mutationHash, createHash('sha256').update('fork-a-projection').digest(),
          first.transitionHash, first.transitionSig,
          second.mutationHash, createHash('sha256').update('fork-b-projection').digest(),
          second.transitionHash, second.transitionSig,
        ]
      );
    }, { restricted: false, client_id: CID, agent_id: 'housekeeper' });
  } catch (error) {
    forkError = String(error?.message || error);
  }
  assert.match(forkError || '', /aimos_cwc_one_genesis|duplicate key/i, 'forked genesis rejected');

  // Temporarily make the exact signing epoch stale. Verification must fail,
  // then recover after restoring the retained identity row.
  const signerEpoch = await query(
    `SELECT DISTINCT i.agent_id,i.valid_from,i.valid_until
       FROM aimos_cognitive_weight_projections p
       JOIN aimos_memory_provenance pr
         ON pr.memory_id=p.memory_id AND pr.mutation_hash=p.provenance_mutation_hash
       JOIN agent_identity i
         ON i.agent_id=pr.agent_id AND i.valid_from=pr.agent_valid_from
      WHERE p.memory_id=$1::uuid`,
    [memoryId]
  );
  assert.equal(signerEpoch.rowCount, 1, 'one exact housekeeper epoch signs the proof chain');
  await ownerExec(
    `UPDATE agent_identity
        SET valid_until=valid_from + interval '1 millisecond'
      WHERE agent_id=$1 AND valid_from=$2`,
    [signerEpoch.rows[0].agent_id, signerEpoch.rows[0].valid_from]
  );
  v = await verify(memoryId);
  assert.equal(v.ok, false, 'stale signing epoch detected');
  assert.match(String(v.reason || ''), /epoch|provenance_identity|signature/i);
  await ownerExec(
    'UPDATE agent_identity SET valid_until=$3 WHERE agent_id=$1 AND valid_from=$2',
    [signerEpoch.rows[0].agent_id, signerEpoch.rows[0].valid_from, signerEpoch.rows[0].valid_until]
  );
  v = await verify(memoryId);
  assert.equal(v.ok, true, 'chain verifies again after exact epoch restore');

  // ── NEGATIVE GUARDS: no-op, discontinuity, and bounds rejected ─────────────
  let noopErr = null;
  try {
    await withTransaction(async (client) => {
      const p = await commitGovernorMutation({
        memoryId, oldWeight: terminalWeight, newWeight: terminalWeight,
        judgeValence: 0, governorFlag: 'BIDIR_PROOF', reason: 'noop_probe', client,
      });
      // commit may reject malformed no-op before the writer; if it returns ok, the writer must reject
      if (p.ok) {
        await client.query('SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
          [memoryId, terminalWeight, terminalWeight, p.mutationHash, p.transitionSig]);
      } else {
        throw new Error('cognitive_noop_reweight');
      }
    }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  } catch (e) { noopErr = String(e?.message || e); }
  assert.match(noopErr || '', /noop|malformed|out_of_bounds/i, 'no-op transition rejected');

  let discontinuityErr = null;
  try {
    await withTransaction(async (client) => {
      const staleOldWeight = Math.max(0.1, terminalWeight - 0.2);
      const proposedWeight = Math.min(3, terminalWeight + 0.01);
      const p = await commitGovernorMutation({
        memoryId,
        oldWeight: staleOldWeight,
        newWeight: proposedWeight,
        judgeValence: 0.1,
        governorFlag: 'BIDIR_PROOF',
        reason: 'discontinuity_probe',
        client,
      });
      assert.equal(p.ok, true);
      await client.query(
        'SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
        [memoryId, staleOldWeight, proposedWeight, p.mutationHash, p.transitionSig],
      );
    }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  } catch (e) { discontinuityErr = String(e?.message || e); }
  assert.match(
    discontinuityErr || '',
    /cognitive_(?:weight|chain)_discontinuity|old_weight|transition_mismatch/i,
    'stale old-weight discontinuity rejected',
  );

  let outOfBoundsErr = null;
  try {
    await withTransaction(async (client) => {
      const p = await commitGovernorMutation({
        memoryId,
        oldWeight: terminalWeight,
        newWeight: 0.09,
        judgeValence: -1,
        governorFlag: 'BIDIR_PROOF',
        reason: 'out_of_bounds_probe',
        client,
      });
      if (p.ok) {
        await client.query(
          'SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
          [memoryId, terminalWeight, 0.09, p.mutationHash, p.transitionSig],
        );
      } else {
        throw new Error('cognitive_weight_out_of_bounds');
      }
    }, { restricted: true, client_id: CID, agent_id: 'housekeeper' });
  } catch (e) { outOfBoundsErr = String(e?.message || e); }
  assert.match(outOfBoundsErr || '', /out_of_bounds|weight_malformed|range/i, 'out-of-bounds transition rejected');

  // ── EXISTENCE PRESERVED: attenuation never deleted or deactivated it ───────
  const still = await query(
    `SELECT is_active, retrieval_weight FROM aimos_memories WHERE company_id = $1 AND id = $2::uuid`,
    [CID, memoryId]
  );
  assert.equal(still.rowCount, 1, 'memory still exists after up/down/up');
  assert.equal(still.rows[0].is_active, true, 'memory never deactivated by weight movement');
  assert.ok(Number(still.rows[0].retrieval_weight) >= 0.1, 'weight floored at 0.1 — never zero, never gone');

  // ── Phase 6 — CORPUS-WIDE live tap: every cognitive chain in the running
  //    scratch corpus verifies, both layers, in one SQL call (SPEC §11). This is
  //    the "verify the whole ledger at any moment" guarantee, not just one memory.
  const corpus = await withTransaction(
    (client) => client.query('SELECT memory_id::text, ok, chain_length, sigs_verified, reason FROM public.verify_all_cognitive_weight_chains()'),
    { restricted: true, client_id: CID, agent_id: 'housekeeper' }
  );
  assert.ok(corpus.rowCount >= 1, 'at least one live cognitive chain to verify');
  for (const row of corpus.rows) {
    assert.equal(row.ok, true, `corpus chain ${row.memory_id} must verify (reason=${row.reason})`);
    assert.equal(Number(row.sigs_verified), Number(row.chain_length), `every link signed in ${row.memory_id}`);
  }
  const portable = await verifyCognitiveWeightCorpus({ companyId: CID });
  assert.equal(portable.parity, true, 'portable verifier and SQL verifier agree over the complete scratch corpus');
  assert.equal(portable.records.every((record) => record.ok), true, 'portable verifier accepts every scratch memory');
  const recallEvidence = await signedPostMutationRecall(memoryId);

  const latencies = measuredTransitions.map((row) => row.latency_ms);
  const logicalProjectionBytes = rowStorage.rows.reduce(
    (sum, row) => sum + Number(row.projection_row_bytes),
    0
  );
  const logicalProvenanceBytes = rowStorage.rows.reduce(
    (sum, row) => sum + Number(row.provenance_row_bytes),
    0
  );
  const evidenceBody = {
    schema: 'hom.aimos.mutation-integrity-live-suite/v1',
    database_name: databaseName,
    company_id: CID,
    intended_transition_measurements: 20,
    completed_transition_measurements: measuredTransitions.length,
    authorization_cases: {
      runtime_direct_update_rejected: true,
      wrong_memory_proof_rejected: true,
      wrong_company_scope_rejected: true,
      no_op_rejected: true,
      discontinuity_rejected: true,
      out_of_bounds_rejected: true,
      fork_rejected: true,
    },
    trajectory_cases: {
      bidirectional_up_down_up_verified: true,
      signed_negative_neutral_positive_evidence_retained: true,
      neutral_no_transition_verified: true,
      existence_preserved: true,
      lower_bound: 0.1,
      upper_bound: 3,
    },
    tamper_cases: {
      projection_hash_or_binding_tamper_detected: true,
      transition_signature_tamper_detected: true,
      terminal_weight_tamper_detected: true,
      stale_signer_epoch_detected: true,
    },
    verifier: {
      sql_corpus_records: corpus.rowCount,
      portable_corpus_records: portable.records.length,
      all_sql_records_ok: corpus.rows.every((row) => row.ok),
      all_portable_records_ok: portable.records.every((record) => record.ok),
      sql_portable_parity: portable.parity,
      portable_corpus_proof_root_sha256: Buffer.from(portable.proofRoot).toString('hex'),
    },
    signed_post_mutation_recall: recallEvidence,
    latency_ms: {
      n: latencies.length,
      mean: latencies.reduce((sum, value) => sum + value, 0) / latencies.length,
      median: percentile(latencies, 0.5),
      p95: percentile(latencies, 0.95),
      minimum: Math.min(...latencies),
      maximum: Math.max(...latencies),
      boundary: 'one native restricted transaction including housekeeper signatures, provenance append, certified projection append, and live-weight update',
    },
    logical_row_storage_bytes: {
      n: rowStorage.rowCount,
      projection_total: logicalProjectionBytes,
      provenance_total: logicalProvenanceBytes,
      combined_total: logicalProjectionBytes + logicalProvenanceBytes,
      combined_mean_per_transition: (logicalProjectionBytes + logicalProvenanceBytes) / rowStorage.rowCount,
      measurement: 'sum(pg_column_size(row)); excludes indexes and block-level free space',
    },
    allocated_relation_delta_bytes: {
      provenance: Number(relationAfter.rows[0].provenance_bytes) - Number(relationBefore.rows[0].provenance_bytes),
      projection: Number(relationAfter.rows[0].projection_bytes) - Number(relationBefore.rows[0].projection_bytes),
      measurement: 'pg_total_relation_size after minus before; block-granular and reported separately from logical row size',
    },
    measured_transitions: measuredTransitions,
  };
  const evidence = {
    ...evidenceBody,
    summary_sha256: sha256(canonicalJson(evidenceBody)),
  };
  if (evidenceFile) {
    fs.mkdirSync(path.dirname(evidenceFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    fs.chmodSync(evidenceFile, 0o600);
  }

  console.log(JSON.stringify({
    database_name: databaseName,
    memory_id: memoryId,
    chain_length: Number(v.chain_length),
    sigs_verified: Number(v.sigs_verified),
    trajectory: millis.rows.map((r) => `${r.old_weight_milli}->${r.new_weight_milli}`),
    corpus_chains_verified: corpus.rowCount,
    neutral_evidence_retained: true,
    neutral_crossing_memory_id: balanceMemoryId,
    hash_tamper_detected: true,
    signature_tamper_detected: true,
    terminal_tamper_detected: true,
    stale_signer_epoch_detected: true,
    noop_rejected: true,
    unauthorized_direct_update_rejected: true,
    wrong_memory_rejected: true,
    wrong_company_rejected: true,
    fork_rejected: true,
    existence_preserved: true,
    latency_measurements: measuredTransitions.length,
    logical_storage_bytes: evidence.logical_row_storage_bytes,
    sql_portable_parity: portable.parity,
    corpus_proof_root_sha256: Buffer.from(portable.proofRoot).toString('hex'),
    summary_sha256: evidence.summary_sha256,
    evidence_file: evidenceFile,
  }, null, 2));
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
