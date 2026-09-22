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
import { withTransaction, agentPool } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { canonicalJson } from '../security/agent-identity.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { computeVerifiedLegacyOccurrenceReference } from './content-state-occurrence/legacy-occurrence-reference.js';
import { readVerifiedRequestReceiptByMutationHash, verifyRequestReceiptProof } from '../security/request-receipt-ledger.js';
import { MEMORY_CREDIT_POLICY, CREDIT_PROJECTION_OPERATION, CREDIT_DECISION_OPERATION,
  CREDIT_CHECKPOINT_OPERATION, memoryCreditTarget, memoryCreditKey, memoryCreditTransition,
  admitMemoryCreditProjection } from '../security/protocol/memory-credit.js';
import {
  logEvent,
  readVerifiedEventHistory,
  readVerifiedEventsByIds,
  prepareEventMetadata,
  requestEnvelopeDigest,
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
  return readVerifiedEventHistory(companyId, {
    client,
    operations: [GENESIS_OPERATION, OBSERVATION_OPERATION, UPDATE_OPERATION],
  });
}

async function loadSnapshotWithClient(companyId, client) {
  const rows = await readVerifiedStream(companyId, client);
  const relevant = calibrationRows(rows).filter(row => row.operation !== OBSERVATION_OPERATION);
  const head = relevant.length
    ? Object.freeze({
        event_id: String(relevant.at(-1).id),
        mutation_hash: Buffer.from(relevant.at(-1).mutation_hash).toString('hex'),
      })
    : null;
  return { rows, snapshot: reconstructCalibrationSnapshot(rows), head };
}

async function readCalibrationStreamHead(companyId, client) {
  const result = await client.query(
    `SELECT id::text AS event_id,
            encode(mutation_hash, 'hex') AS mutation_hash
       FROM public.aimos_events
      WHERE company_id = $1
        AND signer_agent_id = 'housekeeper'
        AND operation = ANY($2::text[])
        AND ledger_version = 1
      ORDER BY signer_valid_from DESC, ledger_seq DESC
      LIMIT 1`,
    [companyId, [GENESIS_OPERATION, UPDATE_OPERATION]],
  );
  const row = result.rows?.[0];
  return row ? Object.freeze({
    event_id: String(row.event_id),
    mutation_hash: String(row.mutation_hash).toLowerCase(),
  }) : null;
}

export async function getVerifiedCalibrationSnapshot(companyId = COMPANY, { client = null } = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('calibration_company_required');
  const cached = snapshotCache.get(company);
  if (cached && client) {
    const head = await readCalibrationStreamHead(company, client);
    if (canonicalJson(head) === canonicalJson(cached.head)) {
      snapshotCache.set(company, { ...cached, fetchedAt: Date.now() });
      return cached.snapshot;
    }
  }
  if (cached && !client && (Date.now() - cached.fetchedAt) < CACHE_TTL_MS) return cached.snapshot;
  const loaded = client
    ? await loadSnapshotWithClient(company, client)
    : await withTransaction(
        async (tx) => loadSnapshotWithClient(company, tx),
        { restricted: true, client_id: company, agent_id: 'housekeeper' },
      );
  const snapshot = loaded.snapshot;
  snapshotCache.set(company, { snapshot, head: loaded.head, fetchedAt: Date.now() });
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
  return labels.map((label) => {
    if (!label || typeof label !== 'object' || Array.isArray(label)
      || ['raw_score', 'calibrated_score', 'observed_usefulness'].some(field =>
        typeof label[field] !== 'number' || !Number.isFinite(label[field])
        || label[field] < 0 || label[field] > 1)) throw new Error('calibration_label_domain_invalid');
    return ({
    memory_id: String(label.memory_id || ''),
    recall_event_id: String(label.recall_event_id || ''),
    recall_mutation_hash: String(label.recall_mutation_hash || '').toLowerCase(),
    calibration_mutation_hash: String(label.calibration_mutation_hash || '').toLowerCase(),
    raw_score: clamp01(label.raw_score),
    calibrated_score: clamp01(label.calibrated_score),
    observed_usefulness: clamp01(label.observed_usefulness),
    label_source: String(label.label_source || '').trim(),
    ...(label.evaluation == null ? {} : { evaluation: normalizeEvaluation(label.evaluation) }),
    });
  });
}

export async function recordCalibrationObservationBatch({
  companyId = COMPANY,
  labels,
  authority,
  signedBody,
} = {}) {
  const company = String(companyId || '').trim();
  if (!authority?.actorAgentId || !authority?.actorValidFromIso || !authority?.requestReceiptId) {
    throw new Error('verified_calibration_feedback_authority_required');
  }
  const normalized = normalizeFeedbackLabels(labels);
  if (normalized.some((label) => !label.label_source)) throw new Error('calibration_label_source_required');
  if (!signedBody || canonicalJson(signedBody.labels) !== canonicalJson(labels)
      || (signedBody.company_id != null && signedBody.company_id !== company)) {
    throw new Error('calibration_feedback_body_binding_invalid');
  }
  if (canonicalJson(prepareEventMetadata(signedBody)) !== canonicalJson(signedBody)
      || canonicalJson(prepareEventMetadata(normalized)) !== canonicalJson(normalized)) {
    throw new Error('calibration_feedback_redaction_invalid');
  }
  const evaluationKey = label => `${label.recall_event_id}:${label.memory_id}`;
  const evaluationKeys = new Set(normalized.map(evaluationKey));
  if (evaluationKeys.size !== normalized.length) throw new Error('calibration_feedback_duplicate_evaluation');

  return withTransaction(async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
      [`${company.length}:${company}:recall-calibration`]);
    const request = await readVerifiedRequestReceiptByMutationHash({ companyId: company,
      requestReceiptMutationHash: authority.requestReceiptMutationHash,
      client });
    if (request.requestReceiptId !== authority.requestReceiptId || request.actorAgentId !== authority.actorAgentId
        || request.signedMethod !== 'POST' || request.signedPath !== '/aimos/recall/calibration/observe'
        || request.actorValidFromIso !== new Date(authority.actorValidFromIso).toISOString()
        || request.requestHash !== sha256(Buffer.from(canonicalJson(signedBody), 'utf8')).toString('hex')) {
      throw new Error('calibration_feedback_request_binding_invalid');
    }
    // Feedback changes retained calibration state. Consume the same exact-epoch
    // master-signed memory write grant as native memory operations, not the
    // unrelated generic tool-capability chain. Lock against grant/revocation
    // changes until this observation commits.
    const validFrom = request.actorValidFromIso;
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
      [`${company.length}:${company}${authority.actorAgentId.length}:${authority.actorAgentId}${validFrom}`]);
    const actor = await client.query(`SELECT 1 FROM agent_identity ai
      WHERE ai.agent_id=$1 AND ai.valid_from=$2
        AND ai.valid_from<=clock_timestamp() AND ai.valid_until>clock_timestamp()
        AND NOT EXISTS (SELECT 1 FROM aimos_agent_revocation_events r
          WHERE r.agent_id=ai.agent_id AND r.agent_valid_from=ai.valid_from)
      FOR SHARE`, [authority.actorAgentId, validFrom]);
    if (!actor.rows[0]) throw new Error('calibration_feedback_active_actor_required');
    const grant = await recallAuthorizationService.getEffective({ companyId: company,
      subjectAgentId: authority.actorAgentId, subjectValidFrom: validFrom, client });
    if (!grant?.allowed || !grant.writeAllowed) {
      throw new Error('calibration_feedback_memory_write_grant_required');
    }
    await getVerifiedCalibrationSnapshot(company, { client });
    const matches = await client.query(`SELECT DISTINCT e.id FROM unnest($2::jsonb[]) patterns(p)
      JOIN LATERAL (SELECT id FROM aimos_events WHERE company_id=$1
        AND operation='recall_calibration_observation_batch' AND ledger_version=1
        AND signer_agent_id='housekeeper' AND metadata @> patterns.p LIMIT 1) e ON true`,
    [company, normalized.map(label => JSON.stringify({ evaluator_agent_id: authority.actorAgentId,
      observations: [{ recall_event_id: label.recall_event_id, memory_id: label.memory_id }] }))]);
    const previous = await readVerifiedEventsByIds(matches.rows.map(row => row.id), company, { client });
    for (const row of previous.values()) {
      const prior = metadataOf(row);
      if (row.operation === OBSERVATION_OPERATION && prior.evaluator_agent_id === authority.actorAgentId
          && prior.observations.some(label => evaluationKeys.has(evaluationKey(label)))) {
        throw new Error('calibration_feedback_evaluation_already_recorded');
      }
    }
    await verifyFeedbackBody(client, company, request.requestReceiptId, signedBody);
    // The calibration stream deliberately excludes recall receipts. Resolve
    // exact receipts through the native verifier in this same transaction.
    const byId = await readVerifiedEventsByIds(normalized.map(label => label.recall_event_id), company, { client });
    for (const label of normalized) {
      const recall = byId.get(label.recall_event_id);
      const metadata = recall ? metadataOf(recall) : null;
      const evidence = Array.isArray(metadata?.evidence) ? metadata.evidence : [];
      const item = evidence.find((entry) => entry.memory_id === label.memory_id);
      if (
        recall?.operation !== 'recall_receipt'
        || recall.signed_body?.subject_agent_id !== authority.actorAgentId
        || metadata.authority_mutation_hash !== grant.mutationHash.toString('hex')
        || Buffer.from(recall.mutation_hash).toString('hex') !== label.recall_mutation_hash
        || !item
        || !sameNumber(item.raw_calibration_score, label.raw_score)
        || !sameNumber(item.calibrated_score, label.calibrated_score)
        || item.calibration_mutation_hash !== label.calibration_mutation_hash
      ) {
        throw new Error('calibration_feedback_prediction_binding_invalid');
      }
      if (recall.signed_body.actor_agent_id !== authority.actorAgentId) {
        const actionId = metadata.derived_tool_action_event_id;
        if (!actionId) throw new Error('calibration_feedback_recipient_invalid');
        const action = (await readVerifiedEventsByIds([actionId], company, { client })).get(actionId);
        if (action.operation !== 'tool_execution_started'
          || action.signed_body.actor_agent_id !== authority.actorAgentId
          || action.metadata.native_tool_profile?.tool !== 'aimos_recall') {
          throw new Error('calibration_feedback_recipient_invalid');
        }
      }
      if (![item.live_content_hash, item.occurrence_ref,
        item.origin_disclosure?.disclosure_label_sha256].every(value => /^[0-9a-f]{64}$/.test(value || ''))) {
        throw new Error('calibration_feedback_target_binding_invalid');
      }
      // Derived exclusively from the verified disclosure, never from client
      // copies. A later content/occurrence cannot inherit this evaluation.
      label.target_binding = {
        schema: 'hom.aimos.recall-feedback-target/v1',
        live_content_hash: item.live_content_hash,
        occurrence_ref: item.occurrence_ref,
        origin_disclosure_sha256: item.origin_disclosure.disclosure_label_sha256,
        confidentiality: item.origin_disclosure.confidentiality,
      };
      // Resolve submitted references before retaining a work item. A caller
      // cannot poison the Housekeeper queue with nonexistent native events.
      if (label.evaluation) await evaluateHousekeeperCredit(label, {
        metadata: { evaluator_agent_id: authority.actorAgentId },
      }, company, client, { beforeObservationCommit: true });
    }
    return logEvent(company, 'recall-calibrator', OBSERVATION_OPERATION, authority.requestReceiptId, {
      schema: SCHEMA,
      formula_version: FORMULA_VERSION,
      evaluator_agent_id: authority.actorAgentId,
      evaluator_valid_from: new Date(authority.actorValidFromIso).toISOString(),
      request_receipt_id: authority.requestReceiptId,
      request_receipt_mutation_hash: authority.requestReceiptMutationHash,
      memory_grant_event_id: grant.eventId,
      memory_grant_mutation_hash: grant.mutationHash.toString('hex'),
      observations: normalized,
      feedback_body: signedBody,
      measurement_kind: 'authenticated_evaluator_reported_usefulness',
      credit_update_authority: 'housekeeper_policy_only',
      credit_policy: MEMORY_CREDIT_POLICY,
      independent_or_objective_evaluation_claimed: false,
      observation_set_hash: sha256(Buffer.from(canonicalJson(normalized), 'utf8')).toString('hex'),
      reasoning: 'A verified evaluator attached bounded usefulness labels to exact signed recall predictions.',
      source_knowledge: 'Sortify closed-loop Belief observation; access alone is not usefulness',
    }, null, { client, returnReceipt: true, authority });
  }, { restricted: true, client_id: company, agent_id: 'housekeeper' });
}

export async function runCalibrationUpdate(companyId = COMPANY) {
  const company = String(companyId || '').trim();
  // External usefulness reports include the evaluator's private context. They
  // cannot update a brain-wide affine model (no implicit declassification).
  // Retained historical LMS transitions remain replayable byte-for-byte.
  const credit = await runHousekeeperMemoryCredit(company);
  return { updated: false, receipt: null, credit, snapshot: await getVerifiedCalibrationSnapshot(company) };
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
    feedback_processing: 'housekeeper_private_policy',
    ready_for_prediction: true,
    ready_for_quality_claim: false,
    feedback_policy: MEMORY_CREDIT_POLICY,
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

function normalizeEvaluation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || canonicalJson(Object.keys(value).sort()) !== canonicalJson(['model_context_event_id', 'run_terminal_event_id'])
    || Object.values(value).some(id => !/^[0-9a-f-]{36}$/.test(id))) {
    throw new Error('calibration_evaluation_reference_invalid');
  }
  return { run_terminal_event_id: value.run_terminal_event_id, model_context_event_id: value.model_context_event_id };
}

const hashOf = row => Buffer.from(row.mutation_hash).toString('hex');
async function verifyFeedbackBody(client, company, receiptId, body) {
  const source = (await client.query(`SELECT r.*,i.pubkey FROM aimos_request_receipts r
    JOIN agent_identity i ON i.agent_id=r.actor_agent_id AND i.valid_from=r.actor_valid_from
    WHERE r.company_id=$1 AND r.request_receipt_id=$2`, [company, receiptId])).rows[0];
  if (!source || !verifyRequestReceiptProof(source, { body, pubkey: source.pubkey }).valid) {
    throw new Error('memory_credit_feedback_signature_invalid');
  }
}
const eventBefore = (left, right) => new Date(left.signer_valid_from).getTime() < new Date(right.signer_valid_from).getTime()
  || (new Date(left.signer_valid_from).getTime() === new Date(right.signer_valid_from).getTime()
    && BigInt(left.ledger_seq) < BigInt(right.ledger_seq));
function creditOccurrenceRef(company, memoryId, p) {
  return Number(p.occurrence_sig_form_version) === 3 ? p.occurrence_mutation_hash
    : computeVerifiedLegacyOccurrenceReference({ company_id: company, memory_id: memoryId,
      provenance_id: p.occurrence_provenance_id, mutation_hash_hex: p.occurrence_mutation_hash,
      agent_id: p.occurrence_signer_agent_id, signer_valid_from_unix_ms: new Date(p.occurrence_signer_valid_from).getTime(),
      cert_fingerprint_hex: p.occurrence_cert_fingerprint, event_type: p.occurrence_event_type,
      sig_form_version: Number(p.occurrence_sig_form_version) });
}
async function verifiedEvent(id, company, client) {
  return (await readVerifiedEventsByIds([id], company, { client })).get(id);
}
function creditReject(reason) { return { accepted: false, reason }; }

// Native provenance, task completion and actual model input are three separate
// predicates. A successful retrieval alone is not a successful use of memory.
export async function evaluateHousekeeperCredit(label, observation, company, client, { beforeObservationCommit = false } = {}) {
  if (!label.evaluation) return creditReject('completed_native_evaluation_required');
  const { verifyNativeResultOrigin, verifyToolContextReceipt } = await import('../orchestration/tool-action-ledger.js');
  const { memoryProvenanceLedger } = await import('../security/memory-provenance.js');
  const actor = observation.metadata.evaluator_agent_id;
  const terminal = await verifiedEvent(label.evaluation.run_terminal_event_id, company, client);
  const model = await verifiedEvent(label.evaluation.model_context_event_id, company, client);
  if (terminal.operation !== 'agent_run_terminal' || terminal.metadata.status !== 'completed'
      || model.operation !== 'model_context_completed') return creditReject('completed_native_evaluation_required');
  const start = await verifiedEvent(terminal.parent_event_id, company, client);
  const context = await verifiedEvent(model.parent_event_id, company, client);
  if (start.operation !== 'agent_run_started' || context.operation !== 'tool_context_prepared'
    || terminal.metadata.start_event_id !== start.id || terminal.metadata.start_mutation_hash !== hashOf(start)
    || start.key !== terminal.key || start.metadata.run_id !== terminal.metadata.run_id
    || context.metadata.run_id !== start.metadata.run_id || context.parent_event_id !== start.parent_event_id) {
    return creditReject('evaluation_run_context_mismatch');
  }
  const admission = await verifiedEvent(start.parent_event_id, company, client);
  const request = await readVerifiedRequestReceiptByMutationHash({ companyId: company,
    requestReceiptMutationHash: admission.metadata.request_receipt_mutation_hash, client });
  const digest = admission.signed_body.request_envelope_digest;
  const envelopeRow = (await client.query(`SELECT r.*,i.cert FROM aimos_request_receipts r
    JOIN agent_identity i ON i.agent_id=r.actor_agent_id AND i.valid_from=r.actor_valid_from
    WHERE r.company_id=$1 AND r.request_receipt_id=$2`, [company, request.requestReceiptId])).rows[0];
  const expectedDigest = requestEnvelopeDigest({ actorAgentId: request.actorAgentId,
    actorValidFromIso: request.actorValidFromIso, requestSigForm: envelopeRow.request_sig_form,
    signedMethod: request.signedMethod, signedPath: request.signedPath, signedTs: request.signedTs,
    nonce: envelopeRow.nonce, certString: envelopeRow.cert, sigBytes: Buffer.from(envelopeRow.sig) });
  if (admission.operation !== 'request_admission_verified' || request.actorAgentId !== actor
      || admission.key !== request.requestReceiptId
      || admission.metadata.request_receipt_id !== request.requestReceiptId
      || admission.metadata.request_hash !== request.requestHash
      || admission.metadata.actor_agent_id !== request.actorAgentId
      || admission.metadata.actor_valid_from !== request.actorValidFromIso
      || admission.metadata.signed_method !== request.signedMethod || admission.metadata.signed_path !== request.signedPath
      || request.signedMethod !== 'POST' || ![`/agents/${actor}/run`, `/agents/${actor}/stream`].includes(request.signedPath)
      || !/^[0-9a-f]{64}$/.test(digest || '') || digest !== expectedDigest
      || [start, terminal, context, model, admission].some(row => row.signer_agent_id !== 'housekeeper'
        || row.signed_body.authority_kind !== 'housekeeper_observation_of_verified_request'
        || row.signed_body.actor_agent_id !== actor || row.signed_body.request_envelope_digest !== digest
        || row.signed_body.actor_valid_from !== request.actorValidFromIso)
      || !eventBefore(start, context) || !eventBefore(context, model) || !eventBefore(model, terminal)
      || (!beforeObservationCommit && !eventBefore(terminal, observation))) return creditReject('evaluation_request_binding_invalid');
  const origin = model.metadata.result_origin;
  if (!origin) return creditReject('evaluation_classification_required');
  if (model.key !== context.id || model.metadata.context_event_id !== context.id) return creditReject('evaluation_context_terminal_mismatch');
  await verifyToolContextReceipt({ event_id: context.id, mutation_sha256: hashOf(context),
    input_sha256: context.metadata.native_input_snapshot.input_sha256 }, { companyId: company, client });
  const classification = await verifyNativeResultOrigin({ terminal_event_id: model.id,
    terminal_mutation_sha256: hashOf(model), action_event_id: context.id, action_mutation_sha256: hashOf(context),
    classification_sha256: origin.classification_sha256, result_sha256: origin.result_sha256,
    disclosed_result_sha256: origin.disclosed_result_sha256, result_kind: 'model', tool: null }, { companyId: company, client });
  const recall = await verifiedEvent(label.recall_event_id, company, client);
  const item = recall.metadata.evidence?.find(entry => entry.memory_id === label.memory_id);
  if (recall.operation !== 'recall_receipt' || hashOf(recall) !== label.recall_mutation_hash
      || recall.signed_body.subject_agent_id !== actor || !item
      || !sameNumber(item.raw_calibration_score, label.raw_score)
      || !sameNumber(item.calibrated_score, label.calibrated_score)
      || item.calibration_mutation_hash !== label.calibration_mutation_hash) return creditReject('evaluation_recall_mismatch');
  const toolRef = classification.input_snapshot.tool_results.find(ref => ref.tool === 'aimos_recall'
    && ref.action_event_id === recall.metadata.derived_tool_action_event_id);
  if (!toolRef) return creditReject('recall_result_not_consumed');
  const toolOrigin = await verifyNativeResultOrigin(toolRef, { companyId: company, client });
  const toolStart = await verifiedEvent(toolRef.action_event_id, company, client);
  const toolEnd = await verifiedEvent(toolRef.terminal_event_id, company, client);
  const derivedDigest = requestEnvelopeDigest({ agentId: toolStart.signer_agent_id,
    validFromIso: new Date(toolStart.signer_valid_from).toISOString(), requestSigForm: 1,
    signedTs: Number(toolStart.ts_signed), nonce: toolStart.nonce,
    certString: toolStart.cert, sigBytes: Buffer.from(toolStart.sig) });
  if (toolEnd.metadata.disposition !== 'SUCCEEDED' || toolStart.signed_body.request_envelope_digest !== digest
    || toolStart.signed_body.actor_agent_id !== actor
    || toolStart.metadata.request_admission_event_id !== admission.id
    || recall.signed_body.actor_agent_id !== toolStart.signer_agent_id
    || recall.signed_body.actor_valid_from !== new Date(toolStart.signer_valid_from).toISOString()
    || recall.signed_body.request_envelope_digest !== derivedDigest
    || recall.metadata.outer_request_hash !== sha256(Buffer.from(canonicalJson(toolStart.signed_body), 'utf8')).toString('hex')
    || !eventBefore(toolStart, recall) || !eventBefore(recall, toolEnd) || !eventBefore(toolEnd, model)
    || ![classification, toolOrigin].every(o => o.memory_inputs.some(input => input.memory_id === label.memory_id
      && input.content_sha256 === item.live_content_hash))) return creditReject('evaluation_consumed_target_mismatch');
  const verified = await memoryProvenanceLedger.verifyRecallEvidence({ memoryIds: [label.memory_id], client });
  const proof = verified.proofs.get(label.memory_id);
  if (!proof || verified.rejected.length || proof.live_content_hash !== item.live_content_hash
      || proof.binding_mutation_hash !== item.binding_mutation_hash
      || creditOccurrenceRef(company, label.memory_id, proof) !== item.occurrence_ref) return creditReject('evaluation_target_no_longer_current');
  const target = memoryCreditTarget(label.memory_id, item.live_content_hash, item.occurrence_ref);
  if (label.target_binding?.live_content_hash !== target.live_content_hash
      || label.target_binding?.occurrence_ref !== target.occurrence_ref) return creditReject('evaluation_target_binding_invalid');
  // The feedback request itself is unclassified external context. Without an
  // explicit declassification owner, its floor is restricted/12 and private to
  // its evaluator, even if that evaluator says its context was public.
  const privateTarget = proof.cube_scope === 'private' || ['private', 'agent', proof.subject_agent_id].includes(proof.scope);
  const readers = [...new Set([actor, ...classification.private_subject_ids, ...toolOrigin.private_subject_ids])];
  if (!privateTarget || proof.subject_agent_id !== actor || readers.some(id => id !== actor)
      || proof.data_class !== 'restricted' || proof.clearance_level !== 12) return creditReject('evaluation_no_write_down');
  return { accepted: true, target,
    evaluation_key: sha256(Buffer.from(canonicalJson({ policy: MEMORY_CREDIT_POLICY,
      run_start: start.id, target }), 'utf8')).toString('hex'),
    visibility: { subject_agent_id: actor, scope: proof.scope, cube_scope: proof.cube_scope,
      data_class: proof.data_class, clearance_level: proof.clearance_level },
    run_terminal_event_id: terminal.id, run_terminal_mutation_hash: hashOf(terminal),
    model_context_event_id: model.id, model_context_mutation_hash: hashOf(model),
    shared_calibration_eligible: false };
}

async function creditHead(company, key, client) {
  const result = await client.query(`SELECT id FROM aimos_events WHERE company_id=$1 AND key=$2
    AND operation='memory_credit_projection' AND ledger_version=1 AND signer_agent_id='housekeeper'
    ORDER BY signer_valid_from DESC,ledger_seq DESC LIMIT 1`, [company, key]);
  return result.rows.length ? verifiedEvent(result.rows[0].id, company, client) : null;
}

async function verifyCreditTransition(event, company, client) {
  const m = event.metadata;
  admitMemoryCreditProjection(m.target, event);
  const ids = [m.evaluation_event_id, ...(m.previous_event_id ? [m.previous_event_id] : [])];
  const refs = await readVerifiedEventsByIds(ids, company, { client });
  const evaluation = refs.get(m.evaluation_event_id), previous = m.previous_event_id ? refs.get(m.previous_event_id) : null;
  if (!evaluation || evaluation.operation !== CREDIT_DECISION_OPERATION
      || evaluation.signed_body.authority_kind !== 'housekeeper_autonomous'
      || hashOf(evaluation) !== m.evaluation_mutation_hash || evaluation.metadata.accepted !== true
      || evaluation.metadata.policy !== MEMORY_CREDIT_POLICY
      || canonicalJson(evaluation.metadata.target) !== canonicalJson(m.target)
      || event.parent_event_id !== evaluation.id
      || !eventBefore(evaluation, event)
      || (previous ? hashOf(previous) : null) !== m.previous_mutation_hash) throw new Error('memory_credit_transition_binding_invalid');
  if (previous) {
    admitMemoryCreditProjection(m.target, previous);
    if (!eventBefore(previous, evaluation)) throw new Error('memory_credit_transition_order_invalid');
  }
  const next = memoryCreditTransition(previous?.metadata, evaluation.metadata.observed_usefulness);
  if (m.count !== next.count || m.sum !== next.sum || m.score !== next.score) throw new Error('memory_credit_transition_arithmetic_invalid');
}

export async function runHousekeeperMemoryCredit(company = COMPANY) {
  return withTransaction(async client => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`${company.length}:${company}:recall-calibration`]);
    const heads = await client.query(`SELECT id FROM aimos_events WHERE company_id=$1
      AND operation='memory_credit_observation_processed' AND signer_agent_id='housekeeper'
      AND authority_kind='housekeeper_autonomous' AND ledger_version=1
      ORDER BY signer_valid_from DESC,ledger_seq DESC LIMIT 1`, [company]);
    let afterEpoch = '1970-01-01T00:00:00.000Z', afterSequence = 0;
    if (heads.rows.length) {
      const checkpoint = await verifiedEvent(heads.rows[0].id, company, client);
      const observation = await verifiedEvent(checkpoint.key, company, client);
      if (checkpoint.metadata.policy !== MEMORY_CREDIT_POLICY || observation.operation !== OBSERVATION_OPERATION
          || checkpoint.metadata.observation_mutation_hash !== hashOf(observation)
          || !eventBefore(observation, checkpoint)) throw new Error('memory_credit_checkpoint_invalid');
      afterEpoch = new Date(observation.signer_valid_from).toISOString();
      afterSequence = observation.ledger_seq;
    }
    const pending = await client.query(`SELECT e.id FROM aimos_events e WHERE e.company_id=$1
      AND e.operation='recall_calibration_observation_batch' AND e.ledger_version=1
      AND e.signer_agent_id='housekeeper' AND (e.signer_valid_from,e.ledger_seq)>($2::timestamptz,$3::bigint)
      ORDER BY e.signer_valid_from,e.ledger_seq LIMIT 100`, [company, afterEpoch, afterSequence]);
    let accepted = 0, retained = 0;
    const receipts = [];
    for (const id of pending.rows.map(row => row.id)) {
      const observation = await verifiedEvent(id, company, client), m = observation.metadata;
      if (observation.operation !== OBSERVATION_OPERATION || !Array.isArray(m.observations)) throw new Error('memory_credit_observation_invalid');
      if (m.observations.some(label => label.evaluation)) {
        const request = await readVerifiedRequestReceiptByMutationHash({ companyId: company,
          requestReceiptMutationHash: m.request_receipt_mutation_hash, client });
        if (m.credit_policy !== MEMORY_CREDIT_POLICY || request.actorAgentId !== m.evaluator_agent_id
            || request.actorValidFromIso !== m.evaluator_valid_from
            || request.signedMethod !== 'POST' || request.signedPath !== '/aimos/recall/calibration/observe'
            || request.requestHash !== sha256(Buffer.from(canonicalJson(m.feedback_body), 'utf8')).toString('hex')
            || canonicalJson(normalizeFeedbackLabels(m.feedback_body.labels)) !== canonicalJson(m.observations.map(({ target_binding, ...label }) => label))) {
          throw new Error('memory_credit_feedback_request_invalid');
        }
        await verifyFeedbackBody(client, company, request.requestReceiptId, m.feedback_body);
      }
      const decisions = [];
      for (const label of m.observations) {
        const decision = await evaluateHousekeeperCredit(label, observation, company, client);
        if (decision.accepted) {
          const duplicate = await client.query(`SELECT id FROM aimos_events WHERE company_id=$1
            AND operation=$2 AND key=$3 AND ledger_version=1 LIMIT 1`, [company, CREDIT_DECISION_OPERATION, decision.evaluation_key]);
          if (duplicate.rows.length) {
            const priorDecision = await verifiedEvent(duplicate.rows[0].id, company, client);
            if (priorDecision.signed_body.authority_kind !== 'housekeeper_autonomous') throw new Error('memory_credit_decision_owner_invalid');
            decisions.push({ memory_id: label.memory_id, accepted: false, reason: 'evaluation_already_counted' });
            retained += 1;
            continue;
          }
          const key = memoryCreditKey(decision.target), previous = await creditHead(company, key, client);
          admitMemoryCreditProjection(decision.target, previous);
          if (previous) await verifyCreditTransition(previous, company, client);
          const next = memoryCreditTransition(previous?.metadata, label.observed_usefulness);
          const evaluation = await logEvent(company, 'housekeeper', CREDIT_DECISION_OPERATION, decision.evaluation_key, {
            policy: MEMORY_CREDIT_POLICY, ...decision, observation_event_id: id,
            observation_mutation_hash: hashOf(observation), observed_usefulness: label.observed_usefulness,
            reasoning: 'Housekeeper verified completed-task input use, exact target, evaluator attribution and no-write-down; this is reported utility, not truth.'
          }, id, { client, returnReceipt: true, exclusiveOperationKey: true });
          const projection = await logEvent(company, 'housekeeper', CREDIT_PROJECTION_OPERATION, key, {
            policy: MEMORY_CREDIT_POLICY, target: decision.target, visibility: decision.visibility,
            previous_event_id: previous?.id ?? null, previous_mutation_hash: previous ? hashOf(previous) : null,
            evaluation_event_id: evaluation.event_id, evaluation_mutation_hash: evaluation.mutation_hash,
            ...next, objective_quality_claimed: false, action_authority: false,
            reasoning: 'Housekeeper appended one distinct completed-task usefulness measurement to the exact content occurrence; historical memory rows are unchanged.'
          }, evaluation.event_id, { client, returnReceipt: true });
          receipts.push(projection); accepted += 1;
        } else retained += 1;
        decisions.push({ memory_id: label.memory_id, accepted: decision.accepted, reason: decision.reason || 'accepted' });
      }
      await logEvent(company, 'housekeeper', CREDIT_CHECKPOINT_OPERATION, id, {
        policy: MEMORY_CREDIT_POLICY, observation_mutation_hash: hashOf(observation), decisions,
        shared_calibration_changed: false,
        reasoning: 'Housekeeper retained every report and recorded its eligibility; excluded evidence neither changes ranking nor shared calibration.'
      }, id, { client, returnReceipt: true, exclusiveOperationKey: true });
    }
    return { processed: pending.rows.length, accepted, retained, receipts };
  }, { restricted: true, client_id: company, agent_id: 'housekeeper' });
}

// Request-local owner: the supplied native admission client holds one
// repeatable-read snapshot. No full-brain scan or cross-request proof cache.
export function createMemoryCreditReader(company, client) {
  const cache = new Map();
  return async memories => {
    const targets = memories.map(memory => memoryCreditTarget(String(memory.id),
      memory.provenance_proof?.live_content_hash, memory.provenance_proof?.disclosure_occurrence_ref));
    const missing = [...new Map(targets.filter(target => !cache.has(memoryCreditKey(target)))
      .map(target => [memoryCreditKey(target), target])).entries()];
    for (let offset = 0; offset < missing.length; offset += 100) {
      const batch = missing.slice(offset, offset + 100);
      const heads = await client.query(`SELECT k.key,e.id FROM unnest($2::text[]) k(key)
        LEFT JOIN LATERAL (SELECT id FROM aimos_events WHERE company_id=$1 AND key=k.key
          AND operation='memory_credit_projection' AND ledger_version=1 AND signer_agent_id='housekeeper'
          ORDER BY signer_valid_from DESC,ledger_seq DESC LIMIT 1) e ON true`, [company, batch.map(([key]) => key)]);
      const events = await readVerifiedEventsByIds(heads.rows.filter(row => row.id).map(row => row.id), company, { client });
      if (heads.rows.length !== batch.length || new Set(heads.rows.map(row => row.key)).size !== batch.length) throw new Error('memory_credit_head_census_invalid');
      for (const event of events.values()) await verifyCreditTransition(event, company, client);
      const byKey = new Map(heads.rows.map(row => [row.key, row.id ? events.get(row.id) : null]));
      for (const [key, target] of batch) cache.set(key, admitMemoryCreditProjection(target, byKey.get(key)));
    }
    return memories.map((memory, index) => {
      const memory_credit = cache.get(memoryCreditKey(targets[index]));
      return { ...memory, credit_score: memory_credit.score, memory_credit };
    });
  };
}

export async function readMemoryCreditCacheFrontier(company, authority, client) {
  if (authority.clearanceCeiling !== 12 || authority.dataClassCeiling !== 'restricted') return MEMORY_CREDIT_POLICY;
  const head = await client.query(`SELECT id FROM aimos_events WHERE company_id=$1
    AND operation='memory_credit_projection' AND ledger_version=1 AND signer_agent_id='housekeeper'
    AND metadata#>>'{visibility,subject_agent_id}'=$2
    ORDER BY signer_valid_from DESC,ledger_seq DESC LIMIT 1`, [company, authority.actorAgentId]);
  if (!head.rows.length) return MEMORY_CREDIT_POLICY;
  const event = await verifiedEvent(head.rows[0].id, company, client);
  if (event.signed_body.authority_kind !== 'housekeeper_autonomous'
    || event.metadata.visibility?.subject_agent_id !== authority.actorAgentId) throw new Error('memory_credit_frontier_invalid');
  return hashOf(event);
}

// Housekeeper diagnostics have no caller-supplied occurrence proofs. Resolve
// their bounded selected rows through the same native provenance owner first.
export async function readMemoryCreditsForRows(company, rows, { client = null } = {}) {
  const read = async tx => {
    const { memoryProvenanceLedger } = await import('../security/memory-provenance.js');
    const proofs = await memoryProvenanceLedger.verifyRecallEvidence({ memoryIds: rows.map(row => String(row.id)), client: tx });
    if (proofs.rejected.length || proofs.proofs.size !== rows.length) throw new Error('memory_credit_provenance_required');
    const admitted = rows.map(row => {
      const p = proofs.proofs.get(String(row.id));
      const ref = creditOccurrenceRef(company, String(row.id), p);
      return { ...row, provenance_proof: { ...p, disclosure_occurrence_ref: ref } };
    });
    return createMemoryCreditReader(company, tx)(admitted);
  };
  if (client) return read(client);
  const tx = await agentPool.connect();
  try {
    await tx.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await tx.query("SELECT set_config('app.current_client_id',$1,true),set_config('app.current_agent_id','housekeeper',true)", [company]);
    const result = await read(tx);
    await tx.query('COMMIT');
    return result;
  } catch (error) {
    await tx.query('ROLLBACK');
    throw error;
  } finally { tx.release(); }
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
