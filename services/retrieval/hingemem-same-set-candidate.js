/**
 * Dormant HingeMem-R same-set candidate.
 *
 * It consumes only memories already admitted and ordered by authoritative
 * MAGMA. It builds a transient boundary hypergraph and may reorder that exact
 * set. Adaptive stop is diagnostic-only and has no disclosure authority.
 */

import { createHash } from 'node:crypto';

import { hingeMemScores } from './hingemem-boundary-hypergraph.js';

export const HINGEMEM_R_GUARDRAILS = Object.freeze({
  dormant: true,
  exact_candidate_set_only: true,
  adaptive_stop_diagnostic_only: true,
  uses_database: false,
  uses_environment_authority: false,
  mutates_memory: false,
  persists_hypergraph: false,
  merges_canonical_memory: false,
  deletes_memory: false,
  suppresses_memory: false,
  applies_age_decay: false,
  disclosure_authority: false,
  admission_authority: false,
  model_boundary_extractor_implemented: false,
  model_query_planner_implemented: false,
  weighted_topic_softmax_implemented: false,
});

function fail(code) {
  throw new Error(`hingemem_same_set_candidate:${code}`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function commitment(domain, ids) {
  return sha256(`${domain}\0${ids.join('\0')}`);
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

function asStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry?.name ?? entry?.label ?? entry ?? '').trim()).filter(Boolean);
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

function occurredAt(memory, record) {
  return memory?.occurred_start
    || memory?.occurred_at
    || record?.occurred_start
    || record?.observed_at
    || memory?.created_at
    || null;
}

function suppliedElements(memory, record) {
  const boundary = record?.boundary_elements && typeof record.boundary_elements === 'object'
    ? record.boundary_elements
    : {};
  const observed = occurredAt(memory, record);
  const date = Number.isFinite(Date.parse(observed)) ? new Date(observed).toISOString() : null;
  return Object.freeze({
    person: asStringArray(boundary.person).length
      ? asStringArray(boundary.person)
      : asStringArray(memory?.entities || record?.persons),
    time: asStringArray(boundary.time).length
      ? asStringArray(boundary.time)
      : (date ? [date] : []),
    location: asStringArray(boundary.location).length
      ? asStringArray(boundary.location)
      : asStringArray(record?.locations),
    topic: asStringArray(boundary.topic).length
      ? asStringArray(boundary.topic)
      : asStringArray(record?.topics),
  });
}

function asState(memory) {
  const id = String(memory?.id || '').trim().toLowerCase();
  const text = memoryText(memory);
  const embedding = parseEmbedding(memory?.embedding);
  if (!id || !text || !embedding) fail('memory_shape_invalid');
  if (!memory?.provenance_proof) fail('unadmitted_memory');
  const record = parseRecord(memory?.value);
  const boundaryReasons = asStringArray(record?.boundary_reasons || record?.boundary?.reasons);
  return Object.freeze({
    id,
    text,
    embedding,
    boundary_elements: suppliedElements(memory, record),
    boundary_reasons: Object.freeze(boundaryReasons),
    memory: Object.freeze({
      id,
      key: memory?.key || null,
      value: text,
      source: memory?.source || null,
      session_id: memory?.session_id || record?.session_id || null,
      memory_type: memory?.memory_type || null,
      created_at: memory?.created_at || null,
      occurred_at: occurredAt(memory, record),
    }),
  });
}

export function rerankHingeMemSameSet({
  queryText = '',
  queryEmbedding,
  memories = [],
} = {}) {
  if (!String(queryText).trim()) fail('query_text_required');
  const embedding = parseEmbedding(queryEmbedding);
  if (!embedding) fail('query_embedding_invalid');
  if (!Array.isArray(memories) || memories.length === 0) fail('memories_required');

  const states = memories.map(asState);
  const ids = states.map((state) => state.id);
  if (new Set(ids).size !== ids.length) fail('duplicate_memory_id');

  const scores = hingeMemScores({
    queryText,
    queryEmbedding: embedding,
    states,
  });
  const priorRank = new Map(ids.map((id, index) => [id, index + 1]));
  const ranked = states.map((state) => {
    const diagnostic = scores.diagnosticsById.get(state.id);
    if (!diagnostic) fail('candidate_score_missing');
    return {
      id: state.id,
      score: Number(scores.scoreById.get(state.id) || 0),
      prior_rank: priorRank.get(state.id),
      diagnostics: diagnostic,
    };
  }).sort((left, right) => right.score - left.score
    || left.prior_rank - right.prior_rank
    || left.id.localeCompare(right.id));

  const outputIds = ranked.map((row) => row.id);
  const inputSet = [...ids].sort();
  const outputSet = [...outputIds].sort();
  if (JSON.stringify(inputSet) !== JSON.stringify(outputSet)) fail('candidate_set_changed');

  const inputRank = commitment('hom-aimos/hingemem-r-input-rank/v1', ids);
  const outputRank = commitment('hom-aimos/hingemem-r-output-rank/v1', outputIds);
  const decision = Object.freeze({
    schema: 'hom-aimos/hingemem-r-decision/v1',
    input_set_sha256: commitment('hom-aimos/hingemem-r-input-set/v1', inputSet),
    output_set_sha256: commitment('hom-aimos/hingemem-r-input-set/v1', outputSet),
    input_rank_sha256: inputRank,
    output_rank_sha256: outputRank,
    query_sha256: sha256(`hom-aimos/hingemem-r-query/v1\0${String(queryText)}`),
    decision_sha256: sha256(`hom-aimos/hingemem-r-decision/v1\0${inputRank}\0${outputRank}`),
  });

  return Object.freeze({
    ranked: Object.freeze(ranked.map(Object.freeze)),
    decision,
    diagnostics: Object.freeze({
      rank_changes: ranked.filter((row, index) => row.prior_rank !== index + 1).length,
      raw_boundary_count: scores.raw_boundary_count,
      hyperedge_count: scores.hyperedge_count,
      node_count: scores.node_count,
      selected_count_diagnostic_only: scores.selected_count,
      query_plan: scores.query_plan,
      exact_candidate_set_preserved: true,
      adaptive_stop_has_disclosure_authority: false,
    }),
    guardrails: HINGEMEM_R_GUARDRAILS,
  });
}
