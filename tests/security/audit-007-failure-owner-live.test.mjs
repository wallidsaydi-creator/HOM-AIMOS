// Operator-authorized canonical validation. Existing memories/identities only.
// Not registered in the source suite: this appends signed diagnostic events.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pool, agentPool, withTransaction, getTransactionOutcome } from '../../db/connection.js';
import { commitGovernorMutation } from '../../services/governance/governor-provenance.js';
import { applyRewardSignal } from '../../services/learning/stdp-kernel.js';
import { logEvent, readVerifiedEventById } from '../../services/observe/event-ledger.js';

assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const retained = JSON.parse(readFileSync(new URL('../../artifacts/security/mutmem-v2/p1-live-mutation/91e60712a28084f582927ade.json', import.meta.url))).projections[0].bundle;
const evidence = retained.outcome_evidence;
const memoryId = evidence.memory_id;
const snapshot = async () => (await pool.query(`SELECT retrieval_weight,encode(content_hash,'hex') AS content_hash,
  (SELECT count(*)::int FROM aimos_memory_provenance WHERE memory_id=m.id) AS provenance,
  (SELECT count(*)::int FROM aimos_cognitive_weight_projections WHERE memory_id=m.id) AS projections
  FROM aimos_memories m WHERE m.company_id='hom' AND m.id=$1`, [memoryId])).rows[0];

try {
  assert.equal((await pool.query('SELECT current_database() AS name')).rows[0].name, 'aimos');
  const before = await snapshot();
  const beforeFailureSeq = (await pool.query(`SELECT coalesce(max(ledger_seq),0)::text AS seq
    FROM aimos_events WHERE operation='cognitive_weight_adjustment_failed' AND company_id='hom'
      AND key=$1 AND metadata->>'outcome_id'=$2`, [memoryId, evidence.outcome_id])).rows[0].seq;
  let replayError;
  try { await applyRewardSignal(memoryId, 1, { outcomeEvidence: evidence }); }
  catch (error) { replayError = error; }
  assert.equal(replayError?.message, 'event_operation_key_exists');
  const replayOutcome = getTransactionOutcome(replayError);
  assert.equal(replayOutcome?.state, 'NOT_COMMITTED');
  assert.equal(replayOutcome.rollbackAcknowledged, true);
  assert.deepEqual(await snapshot(), before);
  const failure = (await pool.query(`SELECT id FROM aimos_events WHERE operation='cognitive_weight_adjustment_failed'
    AND company_id='hom' AND key=$1 AND ledger_seq>$2 AND metadata->>'outcome_id'=$3 ORDER BY ledger_seq DESC LIMIT 1`,
  [memoryId, beforeFailureSeq, evidence.outcome_id])).rows[0];
  assert(failure, 'post_rollback_failure_record_missing');
  const verifiedFailure = await readVerifiedEventById(failure.id, 'hom');
  assert.equal(verifiedFailure.metadata.transaction_outcome.state, 'NOT_COMMITTED');
  assert.equal(verifiedFailure.metadata.transaction_outcome.rollbackAcknowledged, true);

  // The native transition signer rejects a no-change proposal after staging
  // provenance. The governor must propagate that error without nested logging.
  let staged, stageEvent, lateError;
  const start = performance.now();
  try {
    await withTransaction(async client => {
      await client.query("SET LOCAL statement_timeout='5s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      stageEvent = await logEvent('hom', 'housekeeper', 'aud007_rollback_validation_staged', memoryId, {
        reasoning: 'Operator-authorized validation stages this signed diagnostic inside a transaction that must roll back when the native transition signer rejects the no-change proposal.',
      }, null, { client, returnReceipt: true });
      const current = (await client.query('SELECT retrieval_weight FROM aimos_memories WHERE id=$1 AND company_id=$2', [memoryId, 'hom'])).rows[0];
      try {
        await commitGovernorMutation({ memoryId, oldWeight: Number(current.retrieval_weight),
          newWeight: Number(current.retrieval_weight), judgeValence: 0,
          governorFlag: 'AUD007_ROLLBACK_VALIDATION', reason: 'native_no_change_guard_validation', client });
        assert.fail('native_transition_accepted_no_change');
      } catch (error) {
        assert.equal(error.message, 'cognitive_transition_weight_malformed');
        staged = (await client.query(`SELECT mutation_hash FROM aimos_memory_provenance
          WHERE memory_id=$1 AND body_json->>'governor_flag'='AUD007_ROLLBACK_VALIDATION'
            AND xmin::text=mod(pg_current_xact_id()::text::numeric,4294967296)::text`, [memoryId])).rows[0];
        assert(staged, 'expected_staged_provenance_missing');
        throw error;
      }
    }, { restricted: true, client_id: 'hom', agent_id: 'housekeeper' });
  } catch (error) { lateError = error; }
  assert.equal(lateError?.message, 'cognitive_transition_weight_malformed');
  const lateOutcome = getTransactionOutcome(lateError);
  assert.equal(lateOutcome?.state, 'NOT_COMMITTED');
  assert.equal(lateOutcome.rollbackAcknowledged, true);
  assert.deepEqual(await snapshot(), before);
  const residue = (await pool.query(`SELECT
    (SELECT count(*)::int FROM aimos_memory_provenance WHERE memory_id=$1 AND mutation_hash=$2) AS provenance,
    (SELECT count(*)::int FROM aimos_cognitive_weight_projections WHERE memory_id=$1 AND provenance_mutation_hash=$2) AS projections,
    (SELECT count(*)::int FROM aimos_events WHERE id=ANY($3::uuid[])) AS events`,
  [memoryId, staged.mutation_hash, [stageEvent.event_id]])).rows[0];
  assert.deepEqual(residue, { provenance: 0, projections: 0, events: 0 });
  const terminal = await logEvent('hom', 'housekeeper', 'aud007_rollback_validation_terminal', memoryId, {
    status: 'NATIVE_TRANSITION_DENIAL_ROLLBACK_VERIFIED', transaction_outcome: lateOutcome,
    staged_event_id: stageEvent.event_id,
    staged_mutation_hash: staged.mutation_hash.toString('hex'), residue,
    reasoning: 'The native transition signer rejected a no-change proposal after real provenance signing and staging. The governor propagated the error; its owning restricted transaction acknowledged rollback, retained state is unchanged, and this terminal is signed only after releasing that transaction.',
  }, null, { returnReceipt: true });
  await readVerifiedEventById(terminal.event_id, 'hom');
  console.log(JSON.stringify({ at: new Date().toISOString(), memory_id: memoryId,
    replay_denied: true, replay_outcome: replayOutcome, replay_failure_event: failure.id,
    late_denial: lateError.message, late_outcome: lateOutcome, residue,
    terminal_event_id: terminal.event_id, elapsed_ms: Math.round(performance.now() - start),
    retained_memory_unchanged: true, new_identity: false, new_listener: false,
    governor_internal_transition_error_observed: true,
    scope: 'Actual STDP duplicate-outcome denial and native governor transition-signing error rollback; not a SQL-writer denial, simulated signer outage or every autonomous job failure.' }));
} finally { await Promise.all([pool.end(), agentPool.end()]); }
