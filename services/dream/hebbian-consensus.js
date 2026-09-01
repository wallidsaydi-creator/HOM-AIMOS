/**
 * hebbian-consensus.js — native signed co-activation consolidation
 *
 * Called by the Housekeeper nightly dream. The association source is the
 * retained, cryptographically verified native recall-receipt stream—not
 * semantic similarity and not a parallel pheromone store.
 *
 * HeLa-Mem equations adapted to the immutable Aladdin memory model:
 *
 *   w_ij = eta * sum_t I(v_i,v_j in K_t)       (lambda = 0; no decay)
 *   D(v_i) = sum_j w_ij
 *
 * A robust Tukey upper fence over supported positive D values supplies the
 * paper's unspecified delta_hub. Only hubs above that fence may receive a
 * bounded retrieval-frequency promotion. Non-hubs remain unchanged. There is
 * no isolated-node attenuation, forgetting, deletion, pruning, suppression,
 * deactivation, or canonical-content mutation.
 */

import { createHash } from 'node:crypto';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query, withTransaction } from '../../db/connection.js';
import { canonicalJson } from '../security/protocol/canonical-json.js';
import { commitGovernorMutation } from '../governance/governor-provenance.js';
import { logEvent, readVerifiedEventById } from '../observe/event-ledger.js';
import { resolvePrincipalStateMutationTargets } from '../learning/mutation-composition/target-resolver.js';
import { controlCertifiedMutationProposal } from '../learning/neuroplasticity-stability-control.js';

export const HEBBIAN_CONSTANTS = Object.freeze({
  schema: 'hom.aimos.hebbian-coactivation-consensus/v1',
  association_learning_rate: 0.02,
  mutation_learning_rate: 0.02,
  receipt_window: 128,
  minimum_supported_receipts: 2,
  minimum_distinct_neighbors: 2,
  minimum_threshold_population: 4,
  tukey_fence_multiplier: 1.5,
  maximum_log_step: Math.log(1.3),
  minimum_weight: 0.1,
  maximum_weight: 3.0,
  default_batches: 28,
  maximum_batch_size: 500,
  flag_key: 'HEBBIAN_CONSENSUS',
});

const COMPANY = AIMOS_COMPANY_ID;
const HEX_32 = /^[0-9a-f]{64}$/;

function sha(value) {
  return createHash('sha256').update(Buffer.from(canonicalJson(value), 'utf8')).digest('hex');
}

function quantileSorted(values, probability) {
  if (!values.length) return null;
  const position = (values.length - 1) * probability;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return values[lower];
  const fraction = position - lower;
  return values[lower] + ((values[upper] - values[lower]) * fraction);
}

export function deriveHubThreshold(rows = []) {
  const supported = rows
    .filter((row) => Number(row.receipt_count) >= HEBBIAN_CONSTANTS.minimum_supported_receipts
      && Number(row.neighbor_count) >= HEBBIAN_CONSTANTS.minimum_distinct_neighbors
      && Number(row.association_strength) > 0)
    .map((row) => Number(row.association_strength))
    .sort((left, right) => left - right);
  if (supported.length < HEBBIAN_CONSTANTS.minimum_threshold_population) {
    return Object.freeze({
      ready: false,
      reason: 'insufficient_supported_population',
      population: supported.length,
      q1: null,
      q3: null,
      threshold: null,
    });
  }
  const q1 = quantileSorted(supported, 0.25);
  const q3 = quantileSorted(supported, 0.75);
  const threshold = q3 + (HEBBIAN_CONSTANTS.tukey_fence_multiplier * (q3 - q1));
  return Object.freeze({
    ready: true,
    reason: null,
    population: supported.length,
    q1,
    q3,
    threshold,
  });
}

export function classifyConsensus(consensus, threshold) {
  const row = typeof consensus === 'number'
    ? { association_strength: consensus, receipt_count: Infinity, neighbor_count: Infinity }
    : consensus || {};
  if (threshold == null || !Number.isFinite(Number(threshold))) return 0;
  if (Number(row.receipt_count) < HEBBIAN_CONSTANTS.minimum_supported_receipts
      || Number(row.neighbor_count) < HEBBIAN_CONSTANTS.minimum_distinct_neighbors) return 0;
  return Number(row.association_strength) > Number(threshold) ? 1 : 0;
}

function parseMetadata(row) {
  return typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
}

function principalStateKey(companyId, contentHash, agentId) {
  return `${companyId}\0${contentHash}\0${agentId}`;
}

export async function buildVerifiedHebbianAssociationSnapshot({
  client,
  companyId = COMPANY,
  targets = [],
  receiptLimit = HEBBIAN_CONSTANTS.receipt_window,
} = {}) {
  if (!client || typeof client.query !== 'function' || !Array.isArray(targets)
      || !Number.isInteger(receiptLimit) || receiptLimit < 1
      || receiptLimit > HEBBIAN_CONSTANTS.receipt_window) {
    throw new Error('hebbian_association_snapshot_input_invalid');
  }
  const receiptRows = await client.query(
    `SELECT id
       FROM aimos_events
      WHERE company_id=$1 AND operation='recall_receipt' AND ledger_version=1
      ORDER BY ts DESC,id DESC
      LIMIT $2`,
    [companyId, receiptLimit],
  );
  const receipts = [];
  const evidenceIds = new Set();
  for (const locator of receiptRows.rows) {
    const receipt = await readVerifiedEventById(locator.id, companyId, { client });
    if (receipt.operation !== 'recall_receipt') throw new Error('hebbian_recall_receipt_operation_invalid');
    const metadata = parseMetadata(receipt);
    const evidence = Array.isArray(metadata?.evidence) ? metadata.evidence : [];
    const normalized = [];
    for (const item of evidence) {
      const memoryId = String(item?.memory_id || '').toLowerCase();
      const liveContentHash = String(item?.live_content_hash || '').toLowerCase();
      if (!memoryId || !HEX_32.test(liveContentHash)) {
        throw new Error('hebbian_recall_receipt_evidence_invalid');
      }
      evidenceIds.add(memoryId);
      normalized.push({ memory_id: memoryId, live_content_hash: liveContentHash });
    }
    receipts.push({
      event_id: String(receipt.id),
      mutation_hash: Buffer.from(receipt.mutation_hash).toString('hex'),
      evidence: normalized,
    });
  }

  const ids = [...evidenceIds];
  const memoryRows = ids.length
    ? await client.query(
      `SELECT id::text,encode(content_hash,'hex') AS live_content_hash,agent_id
         FROM aimos_memories
        WHERE company_id=$1 AND id=ANY($2::uuid[])`,
      [companyId, ids],
    )
    : { rows: [] };
  if (memoryRows.rows.length !== ids.length) throw new Error('hebbian_receipt_memory_missing');
  const memoryById = new Map(memoryRows.rows.map((row) => [String(row.id), row]));
  const stats = new Map();
  for (const receipt of receipts) {
    const keys = new Set();
    for (const item of receipt.evidence) {
      const memory = memoryById.get(item.memory_id);
      if (!memory || memory.live_content_hash !== item.live_content_hash) {
        throw new Error('hebbian_receipt_live_content_mismatch');
      }
      keys.add(principalStateKey(companyId, memory.live_content_hash, memory.agent_id));
    }
    const ordered = [...keys].sort();
    for (const key of ordered) {
      const row = stats.get(key) || { receipt_count: 0, coactivation_count: 0, neighbors: new Set() };
      row.receipt_count += 1;
      for (const neighbor of ordered) {
        if (neighbor === key) continue;
        row.coactivation_count += 1;
        row.neighbors.add(neighbor);
      }
      stats.set(key, row);
    }
  }

  const allRows = [...stats.entries()].map(([key, row]) => Object.freeze({
    principal_state_key: key,
    receipt_count: row.receipt_count,
    coactivation_count: row.coactivation_count,
    neighbor_count: row.neighbors.size,
    association_strength: HEBBIAN_CONSTANTS.association_learning_rate * row.coactivation_count,
  })).sort((left, right) => left.principal_state_key.localeCompare(right.principal_state_key));
  const threshold = deriveHubThreshold(allRows);
  const byKey = new Map(allRows.map((row) => [row.principal_state_key, row]));
  const targetRows = targets.map((target) => {
    const observed = byKey.get(target.principal_state_key);
    const row = Object.freeze({
      principal_state_key: target.principal_state_key,
      representative_memory_id: target.representative_memory_id,
      receipt_count: observed?.receipt_count || 0,
      coactivation_count: observed?.coactivation_count || 0,
      neighbor_count: observed?.neighbor_count || 0,
      association_strength: observed?.association_strength || 0,
    });
    return Object.freeze({ ...row, is_hub: classifyConsensus(row, threshold.threshold) === 1 });
  });
  const receiptRoot = sha(receipts.map((receipt) => ({
    event_id: receipt.event_id,
    mutation_hash: receipt.mutation_hash,
  })));
  const snapshotBody = Object.freeze({
    schema: HEBBIAN_CONSTANTS.schema,
    company_id: companyId,
    receipt_limit: receiptLimit,
    verified_receipt_count: receipts.length,
    verified_receipt_root_sha256: receiptRoot,
    association_learning_rate_ppm: Math.round(HEBBIAN_CONSTANTS.association_learning_rate * 1_000_000),
    edge_decay_rate_ppm: 0,
    threshold_method: 'tukey_upper_fence_supported_positive_strength',
    threshold_population: threshold.population,
    q1_strength_ppm: threshold.q1 == null ? null : Math.round(threshold.q1 * 1_000_000),
    q3_strength_ppm: threshold.q3 == null ? null : Math.round(threshold.q3 * 1_000_000),
    hub_threshold_ppm: threshold.threshold == null ? null : Math.round(threshold.threshold * 1_000_000),
    threshold_ready: threshold.ready,
    target_rows: targetRows.map((row) => ({
      principal_state_key_sha256: createHash('sha256').update(row.principal_state_key).digest('hex'),
      representative_memory_id: row.representative_memory_id,
      receipt_count: row.receipt_count,
      coactivation_count: row.coactivation_count,
      neighbor_count: row.neighbor_count,
      association_strength_ppm: Math.round(row.association_strength * 1_000_000),
      is_hub: row.is_hub,
    })),
    canonical_content: 'immutable',
    memory_existence: 'immutable',
  });
  return Object.freeze({
    threshold,
    targetRows: Object.freeze(targetRows),
    verifiedReceiptCount: receipts.length,
    verifiedReceiptRootSha256: receiptRoot,
    snapshot: snapshotBody,
    snapshotSha256: sha(snapshotBody),
  });
}

async function applyConsensusReweight(memoryId, consensus, deps = {}) {
  const companyId = deps.companyId || COMPANY;
  if (!consensus?.is_hub || !Number.isFinite(Number(consensus.hub_threshold))) {
    return { applied: false, reason: 'not_hub' };
  }
  const excess = Math.max(0, Number(consensus.association_strength) - Number(consensus.hub_threshold));
  const scale = Math.max(Number(consensus.hub_threshold), HEBBIAN_CONSTANTS.association_learning_rate);
  const deltaLog = Math.min(
    HEBBIAN_CONSTANTS.maximum_log_step,
    HEBBIAN_CONSTANTS.mutation_learning_rate * Math.log1p(excess / scale),
  );
  if (!(deltaLog > 0)) return { applied: false, reason: 'no_hub_excess' };

  return withTransaction(async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
      [`cognitive-reweight:${companyId}:${memoryId}`]);
    const current = await client.query(
      'SELECT retrieval_weight FROM aimos_memories WHERE company_id=$1 AND id=$2::uuid',
      [companyId, memoryId],
    );
    if (current.rowCount !== 1) throw new Error('hebbian_memory_missing');
    const oldWeight = Number(current.rows[0].retrieval_weight);
    const proposedWeight = Math.min(HEBBIAN_CONSTANTS.maximum_weight, oldWeight * Math.exp(deltaLog));
    const control = await controlCertifiedMutationProposal({
      client,
      companyId,
      memoryId,
      currentWeight: oldWeight,
      proposedWeight,
      mutationOwner: 'HEBBIAN_CONSENSUS',
    });
    const newWeight = control.controlled_weight;
    if (Math.round(newWeight * 1000) === Math.round(oldWeight * 1000)) {
      return { applied: false, reason: 'controlled_noop' };
    }
    const mutation = await commitGovernorMutation({
      memoryId,
      oldWeight,
      newWeight,
      judgeValence: Math.min(1, Number(consensus.association_strength)
        / Math.max(Number(consensus.hub_threshold), HEBBIAN_CONSTANTS.association_learning_rate)),
      governorFlag: HEBBIAN_CONSTANTS.flag_key,
      reason: 'verified_recall_coactivation_hub',
      extra: {
        association_schema: HEBBIAN_CONSTANTS.schema,
        association_strength: Number(consensus.association_strength),
        hub_threshold: Number(consensus.hub_threshold),
        receipt_count: Number(consensus.receipt_count),
        coactivation_count: Number(consensus.coactivation_count),
        neighbor_count: Number(consensus.neighbor_count),
        association_snapshot_sha256: String(consensus.association_snapshot_sha256),
        verified_receipt_root_sha256: String(consensus.verified_receipt_root_sha256),
        neuroplasticity_control: control.decision,
        neuroplasticity_control_sha256: control.decision_sha256,
        canonical_content: 'immutable',
        memory_existence: 'immutable',
        controlled_state: 'retrieval_weight_only',
        source_knowledge: 'HeLa-Mem Eq.1 co-activation with lambda=0 and Eq.2 hub strength; HOM-AIMOS immutable-memory adaptation',
      },
      client,
    });
    if (!mutation.ok) throw new Error(`hebbian_commit_failed:${mutation.reason}`);
    await client.query(
      'SELECT public.apply_signed_cognitive_reweight($1::uuid,$2,$3,$4,$5)',
      [memoryId, oldWeight, newWeight, mutation.mutationHash, mutation.transitionSig],
    );
    return {
      applied: true,
      oldWeight,
      newWeight,
      neuroplasticityControlSha256: control.decision_sha256,
    };
  }, { restricted: true, client_id: companyId, agent_id: 'housekeeper' });
}

async function selectBatch(batchIndex, batchCount, { companyId = COMPANY } = {}) {
  const selected = await query(
    `SELECT id::text
       FROM aimos_memories
      WHERE company_id=$1
        AND (((hashtextextended(
                    encode(content_hash,'hex') || ':' || length(agent_id)::text || ':' || agent_id,
                    0
                  ) % $2) + $2) % $2)=$3
      ORDER BY encode(content_hash,'hex'),agent_id,id`,
    [companyId, batchCount, batchIndex],
  );
  if (selected.rowCount > HEBBIAN_CONSTANTS.maximum_batch_size) {
    throw new Error('hebbian_principal_state_batch_bound_exceeded');
  }
  return selected.rows.map((row) => row.id);
}

export async function runHebbianConsensusBatch(
  batchIndex,
  batchCount = HEBBIAN_CONSTANTS.default_batches,
  deps = {},
) {
  const companyId = deps.companyId || COMPANY;
  const readFlag = deps.readFlag;
  if (typeof readFlag !== 'function') {
    return Object.freeze({ enabled: false, reviewed: 0, elevated: 0, neutral: 0, reason: 'signed_flag_reader_required' });
  }
  let enabled = false;
  try {
    enabled = await readFlag(HEBBIAN_CONSTANTS.flag_key, { strict: true });
  } catch (error) {
    return Object.freeze({
      enabled: false,
      reviewed: 0,
      elevated: 0,
      neutral: 0,
      reason: `signed_activation_head_unavailable:${String(error?.message || error)}`,
    });
  }
  if (!enabled) {
    return Object.freeze({ enabled: false, reviewed: 0, elevated: 0, neutral: 0, reason: 'signed_activation_head_not_enabled' });
  }

  let start = null;
  try {
    const ids = await selectBatch(batchIndex, batchCount, { companyId });
    const targetResolution = await withTransaction(
      (client) => resolvePrincipalStateMutationTargets({
        memoryIds: ids,
        companyId,
        client,
        maximumIds: HEBBIAN_CONSTANTS.maximum_batch_size,
      }),
      { restricted: true, client_id: companyId, agent_id: 'housekeeper' },
    );
    const association = await withTransaction(
      (client) => buildVerifiedHebbianAssociationSnapshot({
        client,
        companyId,
        targets: targetResolution.targets,
      }),
      { restricted: true, client_id: companyId, agent_id: 'housekeeper' },
    );
    start = await logEvent(companyId, 'housekeeper', 'hebbian_consensus_batch_started',
      `dream:hebbian:${batchIndex}`, {
        schema: HEBBIAN_CONSTANTS.schema,
        batch_index: batchIndex,
        batch_count: batchCount,
        retained_target_rows: ids.length,
        unique_principal_state_targets: targetResolution.targets.length,
        association_snapshot_sha256: association.snapshotSha256,
        verified_receipt_root_sha256: association.verifiedReceiptRootSha256,
        threshold_ready: association.threshold.ready,
        hub_threshold: association.threshold.threshold,
        reasoning: 'Housekeeper began one bounded consensus pass from cryptographically verified native recall co-activation evidence.',
      }, null, { returnReceipt: true });

    const stats = { enabled: true, reviewed: 0, elevated: 0, neutral: 0 };
    for (const row of association.targetRows) {
      stats.reviewed += 1;
      if (!row.is_hub) { stats.neutral += 1; continue; }
      const result = await applyConsensusReweight(row.representative_memory_id, {
        ...row,
        hub_threshold: association.threshold.threshold,
        association_snapshot_sha256: association.snapshotSha256,
        verified_receipt_root_sha256: association.verifiedReceiptRootSha256,
      }, { companyId });
      if (result.applied) stats.elevated += 1;
      else stats.neutral += 1;
    }

    const terminal = await logEvent(companyId, 'housekeeper', 'hebbian_consensus_batch_terminal',
      `dream:hebbian:${batchIndex}`, {
        schema: HEBBIAN_CONSTANTS.schema,
        status: 'SUCCEEDED',
        ...stats,
        batch_index: batchIndex,
        batch_count: batchCount,
        association_snapshot_sha256: association.snapshotSha256,
        verified_receipt_root_sha256: association.verifiedReceiptRootSha256,
        hub_threshold: association.threshold.threshold,
        canonical_content: 'immutable',
        memory_existence: 'immutable',
        controlled_state: 'retrieval_weight_only',
        reasoning: 'Housekeeper completed one signed co-activation hub pass; non-hubs remained retained and unchanged.',
      }, start.event_id, { returnReceipt: true });
    return Object.freeze({
      ...stats,
      association_snapshot_sha256: association.snapshotSha256,
      terminal_event_id: terminal.event_id,
    });
  } catch (error) {
    try {
      await logEvent(companyId, 'housekeeper', 'hebbian_consensus_batch_terminal',
        `dream:hebbian:${batchIndex}`, {
          schema: HEBBIAN_CONSTANTS.schema,
          status: 'FAILED',
          error: String(error?.message || error),
          batch_index: batchIndex,
          batch_count: batchCount,
          reasoning: 'Housekeeper retained the terminal failure of the bounded consensus pass; no failure was converted into a successful or skipped mutation.',
        }, start?.event_id || null);
    } catch (terminalError) {
      throw new AggregateError(
        [error, terminalError],
        'hebbian_consensus_failure_terminal_unavailable',
      );
    }
    throw error;
  }
}

export default {
  buildVerifiedHebbianAssociationSnapshot,
  deriveHubThreshold,
  classifyConsensus,
  runHebbianConsensusBatch,
  HEBBIAN_CONSTANTS,
};
