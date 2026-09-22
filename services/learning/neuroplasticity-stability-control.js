/**
 * neuroplasticity-stability-control.js — certified trajectory controller
 *
 * This native cognitive-mutation primitive consumes the real,
 * database-verified append-only retrieval-weight trajectory and bounds the next
 * proposed transition. It never scores recall text, invents a lexical loss,
 * masks candidates, prunes memory, changes content, or writes state.
 *
 * Paper boundary:
 * - Neuroplasticity in Artificial Intelligence (2025) motivates dynamic
 *   stability/plasticity control, but its dropin/dropout algorithms operate on
 *   neural-network architecture and require empirical validation.
 * - HOM-AIMOS does not claim those algorithms. Its native state is a certified
 *   scalar trajectory, so the system adaptation is a trajectory-dependent
 *   trust region over log-weight motion.
 *
 * Let x_t = log(w_t), V_t = sum_i |x_i-x_{i-1}| and rho_t be the observed
 * direction-reversal rate. The permitted log step is
 *
 *   b_t = max(b_min, b_0 / (1 + V_t/log(3) + rho_t)).
 *
 * For the persisted grid m=1000*w and direction d=sign(m*-m), v3 uses
 *
 *   b_eff = max(b_t, |log((m+d)/m)|) when d != 0.
 *
 * Select the furthest integer m' between m and m* with
 * |log(m'/m)| <= b_eff. The nearest legal grid point is feasible, so nonzero
 * grid proposals cannot be lost to rounding. Monotonicity permits binary
 * search in O(log |m*-m|) time and O(1) space (at most 12 iterations here).
 * Signed ppm magnitudes round UP: ceil(1e6*actual) <= ceil(1e6*b_eff).
 * No historical v1/v2 decision is rewritten. This is a discrete local motion
 * bound, not a claim of convergence or the paper's architecture algorithm.
 */

import { createHash } from 'node:crypto';
import { canonicalJson } from '../security/protocol/canonical-json.js';

export const NEUROPLASTICITY_CONSTANTS = Object.freeze({
  schema: 'hom.aimos.certified-neuroplasticity-control/v3',
  minimum_weight_milli: 100,
  maximum_weight_milli: 3000,
  base_log_step: Math.log(1.3),
  minimum_log_step: Math.log(1.005),
  variation_scale: Math.log(3),
});

export const NEUROPLASTICITY_GUARDRAILS = Object.freeze({
  canonical_content: 'immutable',
  memory_existence: 'immutable',
  controlled_state: 'retrieval_weight_only',
  direct_database_write: false,
  input_requires_verified_cognitive_trajectory: true,
});

const HEX_32 = /^[0-9a-f]{64}$/;

function asMilli(value, code) {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(code);
  const milli = Math.round(number * 1000);
  if (milli < NEUROPLASTICITY_CONSTANTS.minimum_weight_milli
      || milli > NEUROPLASTICITY_CONSTANTS.maximum_weight_milli) {
    throw new Error(code);
  }
  return milli;
}

function direction(delta) {
  return delta > 0 ? 1 : delta < 0 ? -1 : 0;
}

function hashDecision(body) {
  return createHash('sha256')
    .update(Buffer.from(canonicalJson(body), 'utf8'))
    .digest('hex');
}

export function summarizeCertifiedTrajectory(rows = [], {
  currentWeight,
  expectedChainLength = null,
} = {}) {
  if (!Array.isArray(rows)) throw new Error('neuroplasticity_trajectory_rows_required');
  const currentMilli = asMilli(currentWeight, 'neuroplasticity_current_weight_invalid');
  if (expectedChainLength != null && Number(expectedChainLength) !== rows.length) {
    throw new Error('neuroplasticity_chain_length_mismatch');
  }
  let previousNewMilli = null;
  let previousDirection = 0;
  let reversals = 0;
  let totalVariation = 0;
  let headProjectionHash = '0'.repeat(64);

  rows.forEach((row, index) => {
    const oldMilli = Number(row.old_weight_milli);
    const newMilli = Number(row.new_weight_milli);
    const projectionHash = Buffer.isBuffer(row.projection_hash)
      ? row.projection_hash.toString('hex')
      : String(row.projection_hash || '').toLowerCase();
    if (!Number.isInteger(oldMilli) || !Number.isInteger(newMilli)
        || oldMilli < NEUROPLASTICITY_CONSTANTS.minimum_weight_milli
        || oldMilli > NEUROPLASTICITY_CONSTANTS.maximum_weight_milli
        || newMilli < NEUROPLASTICITY_CONSTANTS.minimum_weight_milli
        || newMilli > NEUROPLASTICITY_CONSTANTS.maximum_weight_milli
        || oldMilli === newMilli || !HEX_32.test(projectionHash)) {
      throw new Error('neuroplasticity_trajectory_row_invalid');
    }
    if (index > 0 && oldMilli !== previousNewMilli) {
      throw new Error('neuroplasticity_trajectory_continuity_invalid');
    }
    const stepDirection = direction(newMilli - oldMilli);
    if (previousDirection !== 0 && stepDirection !== previousDirection) reversals += 1;
    totalVariation += Math.abs(Math.log(newMilli / oldMilli));
    previousDirection = stepDirection;
    previousNewMilli = newMilli;
    headProjectionHash = projectionHash;
  });

  if (rows.length > 0 && previousNewMilli !== currentMilli) {
    throw new Error('neuroplasticity_trajectory_terminal_mismatch');
  }
  const reversalRate = rows.length > 1 ? reversals / (rows.length - 1) : 0;
  return Object.freeze({
    chain_length: rows.length,
    current_weight_milli: currentMilli,
    head_projection_hash: headProjectionHash,
    total_log_variation_ppm: Math.round(totalVariation * 1_000_000),
    reversal_count: reversals,
    reversal_rate_ppm: Math.round(reversalRate * 1_000_000),
  });
}

export function controlCertifiedTrajectoryProposal({
  memoryId,
  currentWeight,
  proposedWeight,
  trajectory,
  mutationOwner,
} = {}) {
  const currentMilli = asMilli(currentWeight, 'neuroplasticity_current_weight_invalid');
  const proposedMilli = asMilli(proposedWeight, 'neuroplasticity_proposed_weight_invalid');
  if (!trajectory || Number(trajectory.current_weight_milli) !== currentMilli
      || !HEX_32.test(String(trajectory.head_projection_hash || ''))) {
    throw new Error('neuroplasticity_verified_trajectory_required');
  }
  const totalVariation = Number(trajectory.total_log_variation_ppm) / 1_000_000;
  const reversalRate = Number(trajectory.reversal_rate_ppm) / 1_000_000;
  if (!Number.isSafeInteger(trajectory.chain_length) || trajectory.chain_length < 0
      || !Number.isSafeInteger(trajectory.reversal_count) || trajectory.reversal_count < 0
      || trajectory.reversal_count > Math.max(0, trajectory.chain_length - 1)
      || !Number.isSafeInteger(trajectory.total_log_variation_ppm)
      || !Number.isSafeInteger(trajectory.reversal_rate_ppm)
      || trajectory.reversal_rate_ppm !== (trajectory.chain_length > 1
        ? Math.round(trajectory.reversal_count / (trajectory.chain_length - 1) * 1_000_000) : 0)
      || (trajectory.chain_length === 0 && (trajectory.total_log_variation_ppm !== 0
        || trajectory.head_projection_hash !== '0'.repeat(64)))
      || !Number.isFinite(totalVariation) || totalVariation < 0
      || !Number.isFinite(reversalRate) || reversalRate < 0 || reversalRate > 1) {
    throw new Error('neuroplasticity_trajectory_summary_invalid');
  }

  const current = currentMilli / 1000;
  const proposed = proposedMilli / 1000;
  const requestedLogStep = Math.log(proposed / current);
  const continuousRadius = Math.max(
    NEUROPLASTICITY_CONSTANTS.minimum_log_step,
    NEUROPLASTICITY_CONSTANTS.base_log_step
      / (1 + (totalVariation / NEUROPLASTICITY_CONSTANTS.variation_scale) + reversalRate),
  );
  const stepDirection = direction(proposedMilli - currentMilli);
  const gridMinimum = stepDirection === 0 ? 0
    : Math.abs(Math.log((currentMilli + stepDirection) / currentMilli));
  const trustRadius = Math.max(continuousRadius, gridMinimum);
  let lower = 0;
  let upper = Math.abs(proposedMilli - currentMilli);
  while (lower < upper) {
    const steps = Math.floor((lower + upper + 1) / 2);
    const candidate = currentMilli + stepDirection * steps;
    if (Math.abs(Math.log(candidate / currentMilli)) <= trustRadius) lower = steps;
    else upper = steps - 1;
  }
  const controlledMilli = currentMilli + stepDirection * lower;
  const actualLogStep = Math.abs(Math.log(controlledMilli / currentMilli));
  const body = Object.freeze({
    schema: NEUROPLASTICITY_CONSTANTS.schema,
    memory_id: String(memoryId || ''),
    mutation_owner: String(mutationOwner || ''),
    trajectory_head_projection_hash: trajectory.head_projection_hash,
    trajectory_chain_length: Number(trajectory.chain_length),
    current_weight_milli: currentMilli,
    proposed_weight_milli: proposedMilli,
    controlled_weight_milli: controlledMilli,
    total_log_variation_ppm: Number(trajectory.total_log_variation_ppm),
    reversal_count: Number(trajectory.reversal_count),
    reversal_rate_ppm: Number(trajectory.reversal_rate_ppm),
    continuous_trust_radius_log_ppm: Math.ceil(continuousRadius * 1_000_000),
    grid_minimum_log_step_ppm: Math.ceil(gridMinimum * 1_000_000),
    trust_radius_log_ppm: Math.ceil(trustRadius * 1_000_000),
    requested_log_step_ppm: Math.round(requestedLogStep * 1_000_000),
    controlled_log_step_ppm: stepDirection * Math.ceil(actualLogStep * 1_000_000),
    canonical_content: 'immutable',
    memory_existence: 'immutable',
    controlled_state: 'retrieval_weight_only',
  });
  return Object.freeze({
    controlled_weight: controlledMilli / 1000,
    changed_by_controller: controlledMilli !== proposedMilli,
    decision: body,
    decision_sha256: hashDecision(body),
  });
}

export async function readCertifiedMutationTrajectory({
  client,
  companyId,
  memoryId,
} = {}) {
  if (!client || typeof client.query !== 'function' || !companyId || !memoryId) {
    throw new Error('neuroplasticity_trajectory_reader_input_invalid');
  }
  const verification = await client.query(
    'SELECT * FROM public.verify_cognitive_weight_chain($1::uuid)',
    [memoryId],
  );
  const verified = verification.rows[0];
  if (!verified || verified.ok !== true) {
    throw new Error(`neuroplasticity_cognitive_chain_invalid:${verified?.reason || 'missing'}`);
  }
  const live = await client.query(
    'SELECT retrieval_weight FROM aimos_memories WHERE company_id=$1 AND id=$2::uuid',
    [companyId, memoryId],
  );
  if (live.rowCount !== 1) throw new Error('neuroplasticity_memory_missing');
  const history = await client.query(
    `SELECT old_weight_milli,new_weight_milli,projection_hash
       FROM aimos_cognitive_weight_projections
      WHERE company_id=$1 AND memory_id=$2::uuid
      ORDER BY applied_at,projection_id`,
    [companyId, memoryId],
  );
  return summarizeCertifiedTrajectory(history.rows, {
    currentWeight: Number(live.rows[0].retrieval_weight),
    expectedChainLength: Number(verified.chain_length),
  });
}

export async function controlCertifiedMutationProposal({
  client,
  companyId,
  memoryId,
  currentWeight,
  proposedWeight,
  mutationOwner,
} = {}) {
  const trajectory = await readCertifiedMutationTrajectory({ client, companyId, memoryId });
  return controlCertifiedTrajectoryProposal({
    memoryId,
    currentWeight,
    proposedWeight,
    trajectory,
    mutationOwner,
  });
}
