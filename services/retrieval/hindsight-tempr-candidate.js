/**
 * Dormant same-set TEMPR-D candidate.
 *
 * The candidate consumes only memories already admitted and selected by the
 * authoritative retrieval path. It may reorder that fixed set; it cannot read
 * the database, expand the set, disclose independently, or persist state.
 */

import { createHash } from 'node:crypto';

import { hindsightMemoryGraphScores } from './hindsight-memory-graph.js';

export const TEMPR_D_GUARDRAILS = Object.freeze({
  dormant: true,
  exact_candidate_set_only: true,
  uses_database: false,
  uses_environment_authority: false,
  mutates_memory: false,
  persists_opinions: false,
  deletes_memory: false,
  suppresses_memory: false,
  applies_age_decay: false,
  disclosure_authority: false,
  admission_authority: false,
  neural_cross_encoder_implemented: false,
});

function fail(code) {
  throw new Error(`hindsight_tempr_candidate:${code}`);
}

function parseEmbedding(value) {
  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    const vector = Array.from(value, Number);
    return vector.length && vector.every(Number.isFinite) ? vector : null;
  }
  const text = String(value || '').trim();
  if (!text.startsWith('[') || !text.endsWith(']')) return null;
  const vector = text.slice(1, -1).split(',').map(Number);
  return vector.length && vector.every(Number.isFinite) ? vector : null;
}

function parseRecord(value) {
  try {
    const parsed = JSON.parse(String(value || ''));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function memoryText(memory) {
  const record = parseRecord(memory?.value);
  return String(
    record.content
      || record.text
      || record.composed_text
      || record.summary
      || memory?.value
      || memory?.key
      || '',
  ).trim();
}

function asState(memory) {
  const id = String(memory?.id || '').trim().toLowerCase();
  const text = memoryText(memory);
  const embedding = parseEmbedding(memory?.embedding);
  if (!id || !text || !embedding) fail('memory_shape_invalid');
  if (!memory?.provenance_proof) fail('unadmitted_memory');
  const record = parseRecord(memory?.value);
  const occurredStart = memory.occurred_start
    || memory.occurred_at
    || record.occurred_start
    || record.observed_at
    || memory.created_at
    || null;
  const occurredEnd = memory.occurred_end
    || memory.ended_at
    || record.occurred_end
    || occurredStart;
  return Object.freeze({
    id,
    text,
    embedding,
    entities: Array.isArray(memory.entities) ? memory.entities : [],
    causal_links: Array.isArray(memory.causal_links) ? memory.causal_links : [],
    interval: Object.freeze({ start: occurredStart, end: occurredEnd }),
    memory: Object.freeze({
      id,
      key: memory.key || null,
      value: text,
      source: memory.source || null,
      session_id: memory.session_id || record.session_id || null,
      memory_type: memory.memory_type || null,
      confidence: memory.confidence ?? null,
      created_at: memory.created_at || null,
      updated_at: memory.updated_at || memory.created_at || null,
      occurred_at: occurredStart,
      ended_at: occurredEnd,
    }),
  });
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function commitment(domain, ids) {
  return sha256(`${domain}\0${ids.join('\0')}`);
}

export function rerankHindsightTemprDeterministic({
  queryText = '',
  queryEmbedding,
  queryInterval = null,
  memories = [],
} = {}) {
  if (!String(queryText).trim()) fail('query_text_required');
  const embedding = parseEmbedding(queryEmbedding);
  if (!embedding) fail('query_embedding_invalid');
  if (!Array.isArray(memories) || memories.length === 0) fail('memories_required');

  const states = memories.map(asState);
  const ids = states.map((state) => state.id);
  if (new Set(ids).size !== ids.length) fail('duplicate_memory_id');

  const score = hindsightMemoryGraphScores({
    queryText,
    queryEmbedding: embedding,
    queryInterval,
    states,
    tokenBudget: Number.MAX_SAFE_INTEGER,
  });
  const priorRank = new Map(ids.map((id, index) => [id, index]));
  const ranked = states.map((state) => ({
    id: state.id,
    score: score.scoreById.get(state.id) || 0,
    prior_rank: priorRank.get(state.id) + 1,
    diagnostics: score.diagnosticsById.get(state.id),
  })).sort((left, right) => right.score - left.score
    || left.prior_rank - right.prior_rank
    || left.id.localeCompare(right.id));

  const outputIds = ranked.map((row) => row.id);
  const inputSet = [...ids].sort();
  const outputSet = [...outputIds].sort();
  if (JSON.stringify(inputSet) !== JSON.stringify(outputSet)) fail('candidate_set_changed');

  const inputRank = commitment('hom-aimos/tempr-d-input-rank/v1', ids);
  const outputRank = commitment('hom-aimos/tempr-d-output-rank/v1', outputIds);
  const decision = Object.freeze({
    schema: 'hom-aimos/hindsight-tempr-d-decision/v1',
    input_set_sha256: commitment('hom-aimos/tempr-d-input-set/v1', inputSet),
    output_set_sha256: commitment('hom-aimos/tempr-d-input-set/v1', outputSet),
    input_rank_sha256: inputRank,
    output_rank_sha256: outputRank,
    query_sha256: sha256(`hom-aimos/tempr-d-query/v1\0${String(queryText)}\0${JSON.stringify(queryInterval)}`),
    decision_sha256: sha256(`hom-aimos/tempr-d-decision/v1\0${inputRank}\0${outputRank}`),
  });

  return Object.freeze({
    ranked: Object.freeze(ranked.map(Object.freeze)),
    decision,
    diagnostics: Object.freeze({
      rank_changes: ranked.filter((row, index) => row.prior_rank !== index + 1).length,
      graph_stats: score.graph_stats,
      channel_stats: score.channel_stats,
      token_budget_is_diagnostic_only: true,
      exact_candidate_set_preserved: true,
    }),
    guardrails: TEMPR_D_GUARDRAILS,
  });
}
