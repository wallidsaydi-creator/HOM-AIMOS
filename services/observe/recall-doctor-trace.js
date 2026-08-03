/**
 * recall-doctor-trace.js — explicit Aimos Recall candidate trace tap
 *
 * Status: diagnostic-only. This module may be imported by routes/aimos.js only
 * for an explicit `doctor_trace=1` request. It must never rank, filter, mutate,
 * call paper operators, or change answer text.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Consumes the native recall candidate array after native ranking.
 * 2. → Emits compact, body-free trace metadata for doctor sidecar analysis.
 * 3. ✕ Does not mutate rank, confidence, memory content, answer text, or DB.
 */

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function finiteNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function round(value, fallback = null) {
  const n = finiteNumber(value, null);
  return n == null ? fallback : Number(n.toFixed(6));
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactObject(value) {
  return plainObject(value) ? value : null;
}

function outputCalibrationProjection(memory = {}) {
  const projection = {};
  const fields = [
    'key',
    'memory_id',
    'session_id',
    'project_id',
    'day',
    'source',
    'memory_type',
    'created_at',
    'createdAt',
    'ts_created',
    'valid_from',
    'valid_until',
    'raw_distance',
    'similarity',
    'similarity_basis',
    'calibrated_recall_score',
    '_raw_rerank',
    'rerank_score',
    'recall_confidence',
    'score',
    'confidence',
    'score_components',
    'rank_diagnostics',
    'low_frequency_salience',
    'salience_reason',
    'salience_score',
    'salience_penalty',
    'retrieval_frequency_band',
    'retrieval_frequency_reason',
    'retrieval_access_count',
    'access_count',
    'retrieval_last_accessed_at',
    'last_accessed_at',
    'retrieval_access_age_days',
    'retrieval_frequency_basis',
    'deep_recall_override',
    'deep_recall_rank_eligible',
    'deep_recall_override_reason',
    'freshness_state',
    'verified_by',
    'verification_basis',
  ];
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(memory, field)) continue;
    const value = memory[field];
    // Native normalization ignores Date objects. Omitting them preserves that
    // typed in-process behavior across the JSON diagnostic boundary.
    if (value instanceof Date || value === undefined) continue;
    if (plainObject(value) || Array.isArray(value)
      || value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
      projection[field] = value;
    }
  }
  return projection;
}

function provenanceProjection(memory = {}) {
  const proof = exactObject(memory.provenance_proof);
  if (!proof) return null;
  return {
    live_content_hash: typeof proof.live_content_hash === 'string'
      ? proof.live_content_hash
      : null,
    save_mutation_hash: typeof proof.save_mutation_hash === 'string'
      ? proof.save_mutation_hash
      : null,
    binding_mutation_hash: typeof proof.binding_mutation_hash === 'string'
      ? proof.binding_mutation_hash
      : null,
  };
}

function extractScore(memory = {}, index = 0, next = null) {
  const diagnostics = memory.rank_diagnostics || {};
  const components = memory.score_components || memory.confidence?.components || {};
  const similarity = finiteNumber(memory.similarity, null);
  const calibratedRecall = finiteNumber(memory.calibrated_recall_score, null);
  const rawRerank = finiteNumber(memory._raw_rerank, null);
  const rerank = finiteNumber(memory.rerank_score, null);
  const confidence = finiteNumber(memory.recall_confidence, null);
  const directScore = finiteNumber(memory.score, null);
  const finalScore = finiteNumber(diagnostics.final_score, finiteNumber(confidence, finiteNumber(rerank, similarity)));
  const nextScore = next
    ? finiteNumber(next.rank_diagnostics?.final_score, finiteNumber(next.recall_confidence, finiteNumber(next.rerank_score, next.similarity)))
    : null;
  return {
    rank: index + 1,
    id: memory.id || null,
    key: memory.key || null,
    memory_type: memory.memory_type || null,
    retrieval_source: memory.retrieval_source || diagnostics.retrieval_source || null,
    similarity: round(similarity),
    similarity_basis: memory.similarity_basis || null,
    calibrated_recall_score: round(calibratedRecall),
    raw_rerank_score: round(rawRerank),
    rerank_score: round(rerank),
    recall_confidence: round(confidence),
    final_score: round(finalScore),
    epistemic_relevance_inputs: {
      calibrated_recall_score: calibratedRecall,
      raw_rerank: rawRerank,
      rerank_score: rerank,
      recall_confidence: confidence,
      score: directScore,
    },
    output_calibration_projection: outputCalibrationProjection(memory),
    provenance_proof_projection: provenanceProjection(memory),
    next_margin: nextScore == null || finalScore == null ? null : round(finalScore - nextScore),
    score_components: {
      semantic: round(components.semantic),
      lexical: round(components.lexical ?? components.keyword),
      bm25: round(components.bm25),
      temporal: round(components.temporal ?? components.recency),
      authority: round(components.authority),
      type_authority: round(components.type_authority),
      freshness_delta: round(components.freshness_delta, 0),
    },
    score_deltas: {
      rerank_minus_similarity: rerank == null || similarity == null ? null : round(rerank - similarity),
      confidence_minus_similarity: confidence == null || similarity == null ? null : round(confidence - similarity),
      final_minus_similarity: finalScore == null || similarity == null ? null : round(finalScore - similarity),
    },
  };
}

export function buildRecallDoctorCandidateTrace({
  queryText = '',
  memories = [],
  recallBreadthPolicy = {},
  maxCandidates = 200,
} = {}) {
  const allMemories = asArray(memories);
  const limit = Math.max(1, Math.min(200, Number(maxCandidates) || 200));
  const rows = allMemories.slice(0, limit).map((memory, index) => {
    const score = extractScore(memory, index, allMemories[index + 1] || null);
    return {
      ...score,
      value_length: String(memory?.value || '').length,
      body_omitted: true,
    };
  });
  return {
    diagnostic_only: true,
    sidecar: 'recall_doctor',
    candidate_scope: 'pre_response_candidate_set',
    query: String(queryText || '').slice(0, 500),
    candidate_count: allMemories.length,
    emitted_count: rows.length,
    body_policy: 'canonical memory body omitted from doctor trace',
    recall_breadth_policy: {
      profile: recallBreadthPolicy.profile || null,
      response_limit: recallBreadthPolicy.response_limit ?? null,
      vector_limit: recallBreadthPolicy.vector_limit ?? null,
      bm25_limit: recallBreadthPolicy.bm25_limit ?? null,
      temporal_limit: recallBreadthPolicy.temporal_limit ?? null,
      graph_hops: recallBreadthPolicy.graph_hops ?? null,
    },
    guardrails: {
      native_hot_path: false,
      mutates_rank: false,
      mutates_confidence: false,
      mutates_memory: false,
      mutates_answer_text: false,
      writes_aimos_db: false,
      calls_native_paper_operator: false,
    },
    candidate_set: rows,
  };
}

export default {
  buildRecallDoctorCandidateTrace,
};
