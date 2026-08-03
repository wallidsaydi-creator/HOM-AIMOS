// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into DREAM memory-integrity diagnostics
// Purpose: Deep SVDD one-class anomaly detection — flags memory embeddings that
//          fall outside the learned normal-data hypersphere
// Called by: jobs/nightly-dream.js Stage 13
// Calls: observe/event-ledger.js
// Pipeline: DREAM
// ─────────────────────────────────────────────────────────────────────────────

/**
 * svdd-anomaly.js — Deep SVDD one-class anomaly detection for memory integrity
 * Source: SynForceNet (2026)
 * Additive Batch8 authority: Learning from Many and Adapting to the Unknown
 * in Open-set Test Streams. Aimos exposes novelty diagnostics only; center
 * updates, ranking changes, and canonical memory mutation stay guarded.
 *
 * Trains only on normal data. Anomalies = memories whose embeddings fall
 * outside the learned hypersphere. Center updated via EMA.
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from './event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const EMA_ALPHA = 0.01;        // Center update rate (slow — stable center)
const EPSILON = 0.05;           // Anomaly distance threshold
let CENTER = null;              // Initialized from first-epoch embeddings

function parseEmbedding(value) {
  if (Array.isArray(value)) return value.map((n) => Number(n) || 0);
  if (typeof value !== 'string') return null;
  const body = value.trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!body) return null;
  const parsed = body.split(',').map((part) => Number(part.trim()));
  return parsed.every((n) => Number.isFinite(n)) ? parsed : null;
}

/**
 * Initialize center from current memory embeddings
 */
export async function initializeCenter({ companyId = COMPANY } = {}) {
  const res = await query(`
    SELECT AVG(embedding) as center_embedding
    FROM aimos_memories
    WHERE company_id = $1 AND embedding IS NOT NULL
  `, [companyId]);
  CENTER = parseEmbedding(res.rows[0]?.center_embedding);
  return { initialized: Array.isArray(CENTER), dimensions: CENTER?.length || 0 };
}

/**
 * Update center via EMA: c_new = (1-alpha)*c_old + alpha*c_batch
 */
export function updateCenter(batchMeanEmbedding) {
  const batch = parseEmbedding(batchMeanEmbedding);
  if (!batch) return;
  if (!Array.isArray(CENTER)) { CENTER = batch; return; }
  CENTER = CENTER.map((c, i) =>
    (1 - EMA_ALPHA) * c + EMA_ALPHA * (batch[i] || 0)
  );
}

/**
 * Compute anomaly score: distance from center
 * anomaly = distance > epsilon
 */
export function scoreAnomaly(embedding) {
  const vector = parseEmbedding(embedding);
  if (!Array.isArray(CENTER) || !vector) return { score: 0, anomaly: false };
  const distance = Math.sqrt(
    CENTER.reduce((sum, c, i) => sum + Math.pow(c - (vector[i] || 0), 2), 0)
  );
  return {
    score: Math.round(distance * 10000) / 10000,
    anomaly: distance > EPSILON,
    threshold: EPSILON
  };
}

export async function runSVDDMemoryIntegrityCheck({ companyId = COMPANY, limit = 50 } = {}) {
  const center = await initializeCenter({ companyId });
  if (!center.initialized) {
    return {
      initialized: false,
      checked: 0,
      anomalyCount: 0,
      anomalies: [],
      threshold: EPSILON,
      diagnostic_only: true,
      canonical_memory_changed: false,
    };
  }

  const sampleLimit = Math.max(1, Math.min(500, Number(limit) || 50));
  const rows = await query(
    `SELECT id, key, embedding::text AS embedding
     FROM aimos_memories
     WHERE company_id = $1 AND embedding IS NOT NULL
     ORDER BY created_at DESC
     LIMIT $2`,
    [companyId, sampleLimit]
  );

  const scored = rows.rows.map((row) => {
    const result = scoreAnomaly(row.embedding);
    return {
      id: row.id,
      key: row.key,
      score: result.score,
      anomaly: result.anomaly,
      threshold: result.threshold,
    };
  });
  const anomalies = scored
    .filter((row) => row.anomaly)
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const eventId = await logEvent(companyId, 'svdd-anomaly', 'svdd_anomaly_check', `svdd:${Date.now()}`, {
    reasoning: `SVDD memory-integrity diagnostic initialized a ${center.dimensions}-dimension normal-memory center and scored ${scored.length} recent memory embedding(s); anomalies=${anomalies.length}.`,
    source_knowledge: 'Deep SVDD one-class anomaly detection; Learning from Many and Adapting to the Unknown in Open-set Test Streams',
    initialized: true,
    dimensions: center.dimensions,
    checked: scored.length,
    anomalyCount: anomalies.length,
    threshold: EPSILON,
    anomalies,
    diagnostic_only: true,
    ranking_math_changed: false,
    canonical_memory_changed: false,
  });

  return {
    initialized: true,
    dimensions: center.dimensions,
    checked: scored.length,
    anomalyCount: anomalies.length,
    anomalies,
    threshold: EPSILON,
    eventId,
    diagnostic_only: true,
    canonical_memory_changed: false,
  };
}

export function buildOpenSetNoveltyDiagnostics(embedding, { label = null } = {}) {
  const scored = scoreAnomaly(embedding);
  const status = !CENTER || !embedding
    ? 'not_initialized'
    : scored.anomaly
      ? 'open_set_candidate'
      : 'in_distribution';

  return {
    source_papers: [
      'Learning from Many and Adapting to the Unknown in Open-set Test Streams',
      'Deep SVDD one-class anomaly detection',
    ],
    label,
    status,
    score: scored.score,
    threshold: scored.threshold ?? EPSILON,
    action: status === 'open_set_candidate'
      ? 'escalate_or_quarantine_until_evidence_supported'
      : status === 'not_initialized'
        ? 'initialize_normal_memory_center_before_claiming_novelty'
        : 'allow_normal_processing',
    diagnostic_only: true,
    center_updated: false,
    ranking_math_changed: false,
    canonical_memory_changed: false,
    guarded_math: {
      open_set_test_stream_adaptation: false,
      svdd_training_update: false,
      prototype_alignment_update: false,
    },
  };
}

export { EMA_ALPHA, EPSILON };
