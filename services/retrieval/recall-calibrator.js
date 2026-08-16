// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: native-recall-pipeline.js, Genesis, signed calibration feedback,
//              and the housekeeper calibration cycle
// → Calls: restricted event-ledger stream + housekeeper identity
// Pipeline: RECALL | Position: signed belief calibration authority
// ─────────────────────────────────────────────────────────────────────────────

/**
 * recall-calibrator.js — signed closed-loop recall calibration
 *
 * Paper authority reviewed before implementation:
 *   Let the Agent Steer: Closed-Loop Ranking Optimization via Influence
 *   Exchange (Sortify), §2.3. Belief channel:
 *
 *     y_hat_t = alpha_t x_t + beta_t
 *     e_t = y_t - y_hat_t
 *     alpha_{t+1} = alpha_t + eta e_t x_t
 *     beta_{t+1}  = beta_t  + eta e_t
 *
 *   eta = 0.2 in the cited implementation.
 *
 * Sortify's Preference channel is an asymmetric multiplicative constraint
 * penalty. It is not an affine transform of a memory trust score, so Aimos
 * deliberately does not claim or expose a fake Preference calibrator.
 *
 * ORCA was also reviewed. ORCA requires trained hidden-state probes,
 * instance-reset fast weights, and LTT over a held-out calibration split for
 * the complete deployed procedure. None of those prerequisites exists here;
 * therefore no ORCA-like threshold, interval, or TTT placeholder is exported.
 *
 * Authority model:
 *   - calibration genesis, observation batches, and parameter updates are
 *     housekeeper-signed events in the universal append-only event ledger;
 *   - the complete signer stream is verified before reconstruction;
 *   - update transitions are recomputed from retained observations;
 *   - one immutable snapshot is used for an entire recall and cache namespace;
 *   - no observation is processed twice: the signed event sequence is the
 *     append-only watermark, with no processed flag, expiry, or deletion.
 */

import { createHash } from 'node:crypto';
import { withTransaction } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { canonicalJson } from '../security/agent-identity.js';
import {
  logEvent,
  readVerifiedEventHistory,
} from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const SCHEMA = 'hom.aimos.recall-calibration/v1';
const GENESIS_OPERATION = 'recall_calibration_genesis';
const OBSERVATION_OPERATION = 'recall_calibration_observation_batch';
const UPDATE_OPERATION = 'recall_calibration_update';
const FORMULA_VERSION = 'sortify-belief-lms/eta-0.2/aimos-guardrails-v1';
const LEARNING_RATE = 0.2;
const ALPHA_MIN = 0.1;
const ALPHA_MAX = 3.0;
const BETA_MIN = -0.5;
const BETA_MAX = 0.5;
const CACHE_TTL_MS = 30_000;
const snapshotCache = new Map();

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function clamp01(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) throw new Error('calibration_score_invalid');
  return Math.max(0, Math.min(1, numeric));
}

function sameNumber(left, right, epsilon = 1e-12) {
  return Number.isFinite(Number(left))
    && Number.isFinite(Number(right))
    && Math.abs(Number(left) - Number(right)) <= epsilon;
}

function calibrationStep(state, observations) {
  let alpha = Number(state.alpha);
  let beta = Number(state.beta);
  let corrections = 0;
  for (const observation of observations) {
    const x = clamp01(observation.raw_score);
    const y = clamp01(observation.observed_usefulness);
    const prediction = alpha * x + beta;
    const error = y - prediction;
    alpha = Math.max(ALPHA_MIN, Math.min(ALPHA_MAX, alpha + LEARNING_RATE * error * x));
    beta = Math.max(BETA_MIN, Math.min(BETA_MAX, beta + LEARNING_RATE * error));
    if (Math.abs(error) > 0.01) corrections += 1;
  }
  return { alpha, beta, learning_rate: LEARNING_RATE, corrections };
}

function calibrationRows(rows) {
  return rows
    .filter((row) => [GENESIS_OPERATION, OBSERVATION_OPERATION, UPDATE_OPERATION].includes(row.operation))
    .map((row, index) => ({ ...row, calibration_seq: index + 1 }));
}

function metadataOf(row) {
  return typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
}

export function reconstructCalibrationSnapshot(rows = []) {
  const relevant = calibrationRows(rows);
  let state = null;
  let calibrationEvent = null;
  let lastObservationSequence = 0;
  let verifiedObservationCount = 0;
  const observations = [];

  for (const row of relevant) {
    const metadata = metadataOf(row);
    const calibrationSequence = Number(row.calibration_seq);
    if (metadata?.schema !== SCHEMA || metadata?.formula_version !== FORMULA_VERSION) {
      throw new Error('calibration_event_schema_invalid');
    }
    if (row.operation === GENESIS_OPERATION) {
      if (state !== null
        || !sameNumber(metadata.alpha, 1)
        || !sameNumber(metadata.beta, 0)
        || !sameNumber(metadata.learning_rate, LEARNING_RATE)
        || Number(metadata.last_observation_seq) !== 0) {
        throw new Error('calibration_genesis_invalid');
      }
      state = { alpha: 1, beta: 0, learning_rate: LEARNING_RATE };
      calibrationEvent = row;
      continue;
    }
    if (state === null) throw new Error('calibration_genesis_missing');
    if (row.operation === OBSERVATION_OPERATION) {
      if (!Array.isArray(metadata.observations) || metadata.observations.length === 0) {
        throw new Error('calibration_observation_batch_empty');
      }
      for (const observation of metadata.observations) {
        if (
          !/^[0-9a-f-]{36}$/i.test(String(observation.memory_id || ''))
          || !/^[0-9a-f-]{36}$/i.test(String(observation.recall_event_id || ''))
          || !/^[0-9a-f]{64}$/i.test(String(observation.recall_mutation_hash || ''))
          || !/^[0-9a-f]{64}$/i.test(String(observation.calibration_mutation_hash || ''))
        ) {
          throw new Error('calibration_observation_reference_invalid');
        }
        clamp01(observation.raw_score);
        clamp01(observation.calibrated_score);
        clamp01(observation.observed_usefulness);
        observations.push({
          ...observation,
          event_sequence: calibrationSequence,
          ledger_sequence: Number(row.ledger_seq),
          signer_valid_from: row.signer_valid_from
            ? new Date(row.signer_valid_from).toISOString()
            : null,
          event_id: row.id,
          event_mutation_hash: Buffer.from(row.mutation_hash).toString('hex'),
        });
        verifiedObservationCount += 1;
      }
      continue;
    }

    const pending = observations.filter((observation) => (
      observation.event_sequence > lastObservationSequence
      && observation.event_sequence <= Number(metadata.last_observation_seq)
    ));
    const expectedSequences = [...new Set(pending.map((observation) => observation.event_sequence))];
    if (
      metadata.previous_calibration_event_id !== calibrationEvent.id
      || metadata.previous_calibration_mutation_hash !== Buffer.from(calibrationEvent.mutation_hash).toString('hex')
      || !sameNumber(metadata.old_alpha, state.alpha)
      || !sameNumber(metadata.old_beta, state.beta)
      || canonicalJson(metadata.observation_event_sequences || []) !== canonicalJson(expectedSequences)
      || pending.length !== Number(metadata.observation_count)
      || pending.length === 0
    ) {
      throw new Error('calibration_update_precondition_invalid');
    }
    const next = calibrationStep(state, pending);
    if (
      !sameNumber(metadata.new_alpha, next.alpha)
      || !sameNumber(metadata.new_beta, next.beta)
      || !sameNumber(metadata.learning_rate, LEARNING_RATE)
      || Number(metadata.corrections) !== next.corrections
    ) {
      throw new Error('calibration_update_transition_invalid');
    }
    state = { alpha: next.alpha, beta: next.beta, learning_rate: LEARNING_RATE };
    lastObservationSequence = Number(metadata.last_observation_seq);
    calibrationEvent = row;
  }

  if (state === null || calibrationEvent === null) throw new Error('calibration_genesis_missing');
  const pendingObservationCount = observations.filter(
    (observation) => observation.event_sequence > lastObservationSequence,
  ).length;
  return Object.freeze({
    schema: SCHEMA,
    formulaVersion: FORMULA_VERSION,
    alpha: state.alpha,
    beta: state.beta,
    learningRate: state.learning_rate,
    calibrationEventId: calibrationEvent.id,
    calibrationMutationHash: Buffer.from(calibrationEvent.mutation_hash).toString('hex'),
    calibrationEventSequence: Number(calibrationEvent.ledger_seq),
    lastObservationSequence,
    verifiedObservationCount,
    pendingObservationCount,
  });
}

async function readVerifiedStream(companyId, client) {
  // Housekeeper custody promotion starts a new independently verified signer
  // epoch. Calibration is one logical append-only stream across those epochs,
  // so reading only the current epoch would make the retained Genesis event
  // disappear. The history owner verifies every complete epoch before these
  // rows are assigned a stable calibration-stream sequence.
  return readVerifiedEventHistory(companyId, { client });
}

async function loadSnapshotWithClient(companyId, client) {
  const rows = await readVerifiedStream(companyId, client);
  return { rows, snapshot: reconstructCalibrationSnapshot(rows) };
}

export async function getVerifiedCalibrationSnapshot(companyId = COMPANY, { client = null } = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('calibration_company_required');
  if (!client) {
    const cached = snapshotCache.get(company);
    if (cached && (Date.now() - cached.fetchedAt) < CACHE_TTL_MS) return cached.snapshot;
  }
  const snapshot = client
    ? (await loadSnapshotWithClient(company, client)).snapshot
    : await withTransaction(
        async (tx) => (await loadSnapshotWithClient(company, tx)).snapshot,
        { restricted: true, client_id: company, agent_id: 'housekeeper' },
      );
  if (!client) snapshotCache.set(company, { snapshot, fetchedAt: Date.now() });
  return snapshot;
}

export async function ensureCalibrationGenesis(companyId = COMPANY) {
  const company = String(companyId || '').trim();
  const receipt = await withTransaction(async (client) => {
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`${company.length}:${company}:recall-calibration`],
    );
    const rows = await readVerifiedStream(company, client);
    const existing = calibrationRows(rows);
    if (existing.length) return null;
    return logEvent(company, 'recall-calibrator', GENESIS_OPERATION, FORMULA_VERSION, {
      schema: SCHEMA,
      formula_version: FORMULA_VERSION,
      alpha: 1,
      beta: 0,
      learning_rate: LEARNING_RATE,
      last_observation_seq: 0,
      reasoning: 'Genesis installed the signed identity calibration state before recall became ready.',
      source_knowledge: 'Sortify §2.3 Belief channel LMS; eta=0.2',
    }, null, { client, returnReceipt: true });
  }, { restricted: true, client_id: company, agent_id: 'housekeeper' });
  snapshotCache.delete(company);
  const snapshot = await getVerifiedCalibrationSnapshot(company);
  return { created: Boolean(receipt), receipt, snapshot };
}

export function calibrateBelief(rawScore, snapshot) {
  if (!snapshot || snapshot.schema !== SCHEMA) throw new Error('verified_calibration_snapshot_required');
  return clamp01(snapshot.alpha * clamp01(rawScore) + snapshot.beta);
}

export function applyCalibrationSnapshot(memories = [], snapshot) {
  if (!snapshot || snapshot.schema !== SCHEMA) throw new Error('verified_calibration_snapshot_required');
  for (const memory of memories) {
    if (memory?._calibration_applied === true) {
      if (memory.calibration_mutation_hash !== snapshot.calibrationMutationHash) {
        throw new Error('mixed_calibration_snapshot');
      }
      continue;
    }
    const raw = Number.isFinite(Number(memory?.rerank_score))
      ? clamp01(memory.rerank_score)
      : Number.isFinite(Number(memory?.recall_confidence))
        ? clamp01(memory.recall_confidence)
        : 0.5;
    const calibrated = calibrateBelief(raw, snapshot);
    memory._raw_rerank = raw;
    if (Number.isFinite(Number(memory?.rerank_score))) memory.rerank_score = calibrated;
    memory.calibrated_recall_score = calibrated;
    memory.calibration_event_id = snapshot.calibrationEventId;
    memory.calibration_mutation_hash = snapshot.calibrationMutationHash;
    memory.calibration_formula_version = snapshot.formulaVersion;
    memory._calibration_applied = true;
  }
  return memories;
}

function normalizeFeedbackLabels(labels) {
  if (!Array.isArray(labels) || labels.length === 0 || labels.length > 100) {
    throw new Error('calibration_labels_invalid');
  }
  return labels.map((label) => ({
    memory_id: String(label.memory_id || ''),
    recall_event_id: String(label.recall_event_id || ''),
    recall_mutation_hash: String(label.recall_mutation_hash || '').toLowerCase(),
    calibration_mutation_hash: String(label.calibration_mutation_hash || '').toLowerCase(),
    raw_score: clamp01(label.raw_score),
    calibrated_score: clamp01(label.calibrated_score),
    observed_usefulness: clamp01(label.observed_usefulness),
    label_source: String(label.label_source || '').trim(),
  }));
}

export async function recordCalibrationObservationBatch({
  companyId = COMPANY,
  labels,
  authority,
} = {}) {
  const company = String(companyId || '').trim();
  if (!authority?.actorAgentId || !authority?.actorValidFromIso || !authority?.requestReceiptId) {
    throw new Error('verified_calibration_feedback_authority_required');
  }
  const normalized = normalizeFeedbackLabels(labels);
  if (normalized.some((label) => !label.label_source)) throw new Error('calibration_label_source_required');

  return withTransaction(async (client) => {
    const rows = await readVerifiedStream(company, client);
    reconstructCalibrationSnapshot(rows);
    const byId = new Map(rows.map((row) => [String(row.id), row]));
    for (const label of normalized) {
      const recall = byId.get(label.recall_event_id);
      const metadata = recall ? metadataOf(recall) : null;
      const evidence = Array.isArray(metadata?.evidence) ? metadata.evidence : [];
      const item = evidence.find((entry) => entry.memory_id === label.memory_id);
      if (
        recall?.operation !== 'recall_receipt'
        || Buffer.from(recall.mutation_hash).toString('hex') !== label.recall_mutation_hash
        || !item
        || !sameNumber(item.raw_calibration_score, label.raw_score)
        || !sameNumber(item.calibrated_score, label.calibrated_score)
        || item.calibration_mutation_hash !== label.calibration_mutation_hash
      ) {
        throw new Error('calibration_feedback_prediction_binding_invalid');
      }
    }
    return logEvent(company, 'recall-calibrator', OBSERVATION_OPERATION, authority.requestReceiptId, {
      schema: SCHEMA,
      formula_version: FORMULA_VERSION,
      evaluator_agent_id: authority.actorAgentId,
      evaluator_valid_from: new Date(authority.actorValidFromIso).toISOString(),
      request_receipt_id: authority.requestReceiptId,
      request_receipt_mutation_hash: authority.requestReceiptMutationHash,
      observations: normalized,
      observation_set_hash: sha256(Buffer.from(canonicalJson(normalized), 'utf8')).toString('hex'),
      reasoning: 'A verified evaluator attached bounded usefulness labels to exact signed recall predictions.',
      source_knowledge: 'Sortify closed-loop Belief observation; access alone is not usefulness',
    }, null, { client, returnReceipt: true, authority });
  }, { restricted: true, client_id: company, agent_id: 'housekeeper' });
}

export async function runCalibrationUpdate(companyId = COMPANY) {
  const company = String(companyId || '').trim();
  const result = await withTransaction(async (client) => {
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`${company.length}:${company}:recall-calibration`],
    );
    const { rows, snapshot } = await loadSnapshotWithClient(company, client);
    const pendingRows = calibrationRows(rows).filter(
      (row) => row.operation === OBSERVATION_OPERATION
        && Number(row.calibration_seq) > snapshot.lastObservationSequence,
    );
    const pending = pendingRows.flatMap((row) => metadataOf(row).observations || []);
    if (!pending.length) return { updated: false, snapshot, receipt: null };
    const next = calibrationStep(snapshot, pending);
    const lastObservationSequence = Math.max(...pendingRows.map((row) => Number(row.calibration_seq)));
    const sequences = pendingRows.map((row) => Number(row.calibration_seq));
    const receipt = await logEvent(company, 'recall-calibrator', UPDATE_OPERATION, FORMULA_VERSION, {
      schema: SCHEMA,
      formula_version: FORMULA_VERSION,
      previous_calibration_event_id: snapshot.calibrationEventId,
      previous_calibration_mutation_hash: snapshot.calibrationMutationHash,
      old_alpha: snapshot.alpha,
      old_beta: snapshot.beta,
      new_alpha: next.alpha,
      new_beta: next.beta,
      learning_rate: LEARNING_RATE,
      corrections: next.corrections,
      observation_count: pending.length,
      observation_event_sequences: sequences,
      observation_event_root: sha256(Buffer.from(canonicalJson(
        pendingRows.map((row) => Buffer.from(row.mutation_hash).toString('hex')),
      ), 'utf8')).toString('hex'),
      last_observation_seq: lastObservationSequence,
      reasoning: 'Housekeeper applied the Sortify Belief LMS transition to each retained, previously unprocessed signed observation.',
      source_knowledge: 'Sortify §2.3 LMS continuous calibration, equations alpha/beta with eta=0.2',
    }, null, { client, returnReceipt: true });
    return { updated: true, previous: snapshot, next, receipt };
  }, { restricted: true, client_id: company, agent_id: 'housekeeper' });
  snapshotCache.delete(company);
  return { ...result, snapshot: await getVerifiedCalibrationSnapshot(company) };
}

export async function getCalibrationStatus(companyId = COMPANY) {
  const snapshot = await getVerifiedCalibrationSnapshot(companyId);
  return {
    signed_genesis_present: true,
    formula_version: snapshot.formulaVersion,
    alpha: snapshot.alpha,
    beta: snapshot.beta,
    learning_rate: snapshot.learningRate,
    calibration_event_id: snapshot.calibrationEventId,
    calibration_mutation_hash: snapshot.calibrationMutationHash,
    verified_observations: snapshot.verifiedObservationCount,
    pending_observations: snapshot.pendingObservationCount,
    ready_for_prediction: true,
    ready_for_quality_claim: snapshot.verifiedObservationCount > 0 && snapshot.pendingObservationCount === 0,
  };
}

export function buildOrcaCalibrationReadiness(status = {}, {
  deployedProcedure = 'aimos_recall_linear_hybrid',
  riskTolerance = 0.1,
  failureProbability = 0.05,
} = {}) {
  return {
    source_paper: 'Online Reasoning Calibration: Test-Time Training Enables Generalizable Conformal LLM Reasoning',
    deployed_procedure: deployedProcedure,
    orca_implemented: false,
    current_calibrator: 'Sortify Belief LMS with signed event reconstruction',
    signed_genesis_present: status.signed_genesis_present === true,
    target_risk: { delta: riskTolerance, epsilon: failureProbability, active: false },
    missing_for_full_orca: [
      'trained hidden-state correctness probe',
      'instance-reset test-time fast weights',
      'held-out on-policy LTT calibration split',
      'fixed-sequence p-value testing for the complete deployed procedure',
    ],
    ranking_improvement_claimed: false,
    calibration_quality_metrics_required: ['Brier score', 'expected calibration error', 'held-out quality gate'],
  };
}

export function clearCalibrationSnapshotCache() {
  snapshotCache.clear();
}

export default {
  ensureCalibrationGenesis,
  getVerifiedCalibrationSnapshot,
  reconstructCalibrationSnapshot,
  calibrateBelief,
  applyCalibrationSnapshot,
  recordCalibrationObservationBatch,
  runCalibrationUpdate,
  getCalibrationStatus,
  buildOrcaCalibrationReadiness,
  clearCalibrationSnapshotCache,
};
