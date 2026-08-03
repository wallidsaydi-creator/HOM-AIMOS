/**
 * codebook-service.js — Online centroid codebook for TurboQuant retrieval
 *
 * Practical Aimos design:
 * - keep centroids in the same 768d space as stored embeddings
 * - assign each memory to a prototype/codebook centroid
 * - store residual = embedding - centroid for asymmetric reranking
 * - update centroids online with stable EMA / bootstrap averaging
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';

const COMPANY = AIMOS_COMPANY_ID;
const EMBEDDING_DIM = 768;
const MAX_CENTROIDS = 256;
const MIN_BOOTSTRAP_CENTROIDS = 16;
const NEW_CENTROID_SIM_THRESHOLD = 0.82;
const CENTROID_EMA_MOMENTUM = 0.99;

function parseVector(raw) {
  if (!raw) return null;
  if (Array.isArray(raw)) return raw.map(Number);
  if (ArrayBuffer.isView(raw)) return Array.from(raw, Number);
  if (typeof raw === 'string') {
    const cleaned = raw.trim().replace(/^\[/, '').replace(/\]$/, '');
    if (!cleaned) return [];
    return cleaned.split(',').map(Number);
  }
  return null;
}

function zeroVector(length = EMBEDDING_DIM) {
  return new Float32Array(length).fill(0);
}

function normalizeVector(input, expectedLength = EMBEDDING_DIM) {
  const parsed = parseVector(input);
  if (!Array.isArray(parsed) || parsed.length !== expectedLength) {
    return null;
  }

  let norm = 0;
  const normalized = new Float32Array(expectedLength);

  for (let i = 0; i < expectedLength; i++) {
    const value = Number(parsed[i]);
    if (!Number.isFinite(value)) return null;
    normalized[i] = value;
    norm += value * value;
  }

  if (norm <= 0) {
    return normalized;
  }

  const scale = 1 / Math.sqrt(norm);
  for (let i = 0; i < expectedLength; i++) {
    normalized[i] *= scale;
  }

  return normalized;
}

function cosineSimilarity(a, b) {
  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  return dot / (Math.sqrt(normA) * Math.sqrt(normB) || 1);
}

function subtractVectors(a, b) {
  const residual = new Float32Array(a.length);
  for (let i = 0; i < a.length; i++) {
    residual[i] = a[i] - b[i];
  }
  return residual;
}

function blendCentroid(current, sample, accessCount) {
  const alpha = accessCount < 25
    ? 1 / Math.max(accessCount + 1, 1)
    : (1 - CENTROID_EMA_MOMENTUM);

  const blended = new Float32Array(current.length);
  for (let i = 0; i < current.length; i++) {
    blended[i] = ((1 - alpha) * current[i]) + (alpha * sample[i]);
  }

  return normalizeVector(blended);
}

function findNextQuantIdx(usedIndices) {
  const used = new Set(usedIndices);
  for (let idx = 0; idx < MAX_CENTROIDS; idx++) {
    if (!used.has(idx)) return idx;
  }
  return null;
}

function shouldAllocateCentroid(bestSimilarity, centroidCount) {
  if (centroidCount >= MAX_CENTROIDS) return false;
  if (centroidCount < MIN_BOOTSTRAP_CENTROIDS) return true;
  return bestSimilarity < NEW_CENTROID_SIM_THRESHOLD;
}

async function fetchCentroids(companyId = COMPANY) {
  const { rows } = await query(
    `SELECT quant_idx, centroid, access_count
     FROM aimos_codebook
     WHERE company_id = $1
     ORDER BY quant_idx ASC`,
    [companyId]
  );

  return rows
    .map((row) => ({
      quant_idx: Number(row.quant_idx),
      centroid: normalizeVector(row.centroid),
      access_count: Number(row.access_count || 0),
    }))
    .filter((row) => row.centroid);
}

async function persistCentroid(companyId, quantIdx, centroid, accessCount = 1) {
  await query(
    `INSERT INTO aimos_codebook (company_id, quant_idx, centroid, access_count, updated_at)
     VALUES ($1, $2, $3::vector, $4, NOW())
     ON CONFLICT (company_id, quant_idx) DO UPDATE SET
       centroid = EXCLUDED.centroid,
       access_count = EXCLUDED.access_count,
       updated_at = NOW()`,
    [companyId, quantIdx, JSON.stringify(Array.from(centroid)), accessCount]
  );
}

async function updateAssignedCentroid(companyId, assigned, sample) {
  const nextAccessCount = assigned.access_count + 1;
  const nextCentroid = blendCentroid(assigned.centroid, sample, assigned.access_count);
  if (!nextCentroid) return;

  await persistCentroid(companyId, assigned.quant_idx, nextCentroid, nextAccessCount);
}

/**
 * Quantize a 768d embedding into (quant_idx, residual) in Aimos embedding space.
 */
export async function quantize(embedding, companyId = COMPANY) {
  const vector = normalizeVector(embedding);
  if (!vector) {
    throw new Error('TurboQuant requires a finite 768d embedding');
  }

  const centroids = await fetchCentroids(companyId);

  if (centroids.length === 0) {
    await persistCentroid(companyId, 0, vector, 1);
    return {
      quant_idx: 0,
      residual: zeroVector(),
      centroid: vector,
    };
  }

  const scored = centroids
    .map((centroid) => ({
      ...centroid,
      similarity: cosineSimilarity(vector, centroid.centroid),
    }))
    .sort((a, b) => {
      if (b.similarity !== a.similarity) return b.similarity - a.similarity;
      return a.quant_idx - b.quant_idx;
    });

  const best = scored[0];

  if (shouldAllocateCentroid(best.similarity, centroids.length)) {
    const nextQuantIdx = findNextQuantIdx(centroids.map((centroid) => centroid.quant_idx));
    if (nextQuantIdx !== null) {
      await persistCentroid(companyId, nextQuantIdx, vector, 1);
      return {
        quant_idx: nextQuantIdx,
        residual: zeroVector(),
        centroid: vector,
      };
    }
  }

  const residual = subtractVectors(vector, best.centroid);
  await updateAssignedCentroid(companyId, best, vector);

  return {
    quant_idx: best.quant_idx,
    residual,
    centroid: best.centroid,
    similarity: best.similarity,
  };
}

/**
 * Lightweight shortlist helper for debugging / future tuning.
 */
export async function getCentroidShortlist(queryEmbedding, companyId = COMPANY, limit = 8) {
  const vector = normalizeVector(queryEmbedding);
  if (!vector) return [];

  const centroids = await fetchCentroids(companyId);
  return centroids
    .map((centroid) => ({
      quant_idx: centroid.quant_idx,
      similarity: cosineSimilarity(vector, centroid.centroid),
      access_count: centroid.access_count,
    }))
    .sort((a, b) => {
      if (b.similarity !== a.similarity) return b.similarity - a.similarity;
      return a.quant_idx - b.quant_idx;
    })
    .slice(0, Math.max(1, Math.min(Number(limit) || 8, MAX_CENTROIDS)));
}

/**
 * Nightly centroid maintenance hook.
 * The current online updates keep the codebook fresh; deeper batch re-centering can plug in here.
 */
export async function updateCentroids(companyId = COMPANY) {
  return fetchCentroids(companyId);
}

export default {
  quantize,
  getCentroidShortlist,
  updateCentroids,
};
