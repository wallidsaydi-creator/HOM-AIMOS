// Housekeeper-owned descriptive usefulness, not trust or action authority.
// HOM adaptation: arithmetic mean of distinct completed-task reports. Sortify
// §2.3 motivates a feedback channel, not this mean, authorization or causality.
// SPICED/HeLa coactivation is NOT a usefulness label. Missing evidence is null.
import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical-json.js';

export const MEMORY_CREDIT_POLICY = 'hom.aimos.housekeeper-memory-credit/v1';
export const CREDIT_PROJECTION_OPERATION = 'memory_credit_projection';
export const CREDIT_DECISION_OPERATION = 'memory_credit_evaluation';
export const CREDIT_CHECKPOINT_OPERATION = 'memory_credit_observation_processed';
const admitted = new WeakSet();
const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function memoryCreditTarget(memoryId, contentHash, occurrenceRef) {
  if (!UUID.test(memoryId || '') || !HASH.test(contentHash || '') || !HASH.test(occurrenceRef || '')) {
    throw new Error('memory_credit_target_invalid');
  }
  return Object.freeze({ memory_id: memoryId, live_content_hash: contentHash, occurrence_ref: occurrenceRef });
}
export function memoryCreditKey(target) {
  return createHash('sha256').update(MEMORY_CREDIT_POLICY + '\0').update(canonicalJson(target)).digest('hex');
}
export function memoryCreditTransition(previous, usefulness) {
  const count = previous?.count ?? 0, sum = previous?.sum ?? 0;
  if (!Number.isSafeInteger(count) || count < 0 || count >= Number.MAX_SAFE_INTEGER
      || !Number.isFinite(sum) || sum < 0 || sum > count
      || typeof usefulness !== 'number' || !Number.isFinite(usefulness) || usefulness < 0 || usefulness > 1) {
    throw new Error('memory_credit_arithmetic_invalid');
  }
  const nextSum = sum + usefulness, nextCount = count + 1;
  if (nextSum > nextCount || !Number.isFinite(nextSum)) throw new Error('memory_credit_arithmetic_invalid');
  return Object.freeze({ sum: nextSum, count: nextCount, score: nextSum / nextCount });
}
// Only the verified event reader calls this constructor. Parsed wire/database
// objects cannot become scoring inputs by merely copying a schema string.
export function admitMemoryCreditProjection(target, event = null) {
  const m = event?.metadata;
  if (event && (m?.policy !== MEMORY_CREDIT_POLICY || canonicalJson(m.target) !== canonicalJson(target)
      || !Number.isSafeInteger(m.count) || m.count < 1 || !Number.isFinite(m.sum)
      || m.sum < 0 || m.sum > m.count || m.score !== m.sum / m.count
      || event.operation !== CREDIT_PROJECTION_OPERATION || event.key !== memoryCreditKey(target)
      || event.signer_agent_id !== 'housekeeper' || event.signed_body?.authority_kind !== 'housekeeper_autonomous')) {
    throw new Error('memory_credit_projection_invalid');
  }
  const value = Object.freeze({ policy: MEMORY_CREDIT_POLICY, target,
    state: event ? 'MEASURED_REPORTED_USEFULNESS' : 'UNMEASURED',
    score: event ? m.score : null, count: event ? m.count : 0,
    event_id: event?.id ?? null,
    mutation_hash: event ? Buffer.from(event.mutation_hash).toString('hex') : null,
    objective_quality_claimed: false, action_authority: false });
  admitted.add(value);
  return value;
}
export function memoryCreditValue(memory) {
  const credit = memory?.memory_credit;
  return credit && admitted.has(credit) ? credit.score : null;
}
export function memoryCreditEvidence(memory) {
  const credit = memory?.memory_credit;
  if (!credit || !admitted.has(credit)) throw new Error('memory_credit_admission_required');
  const proof = memory.provenance_proof;
  if (canonicalJson(credit.target) !== canonicalJson(memoryCreditTarget(String(memory.id),
    proof?.live_content_hash, proof?.disclosure_occurrence_ref))) throw new Error('memory_credit_target_substitution');
  return credit;
}
