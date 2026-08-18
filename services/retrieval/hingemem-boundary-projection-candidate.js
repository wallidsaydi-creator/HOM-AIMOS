/**
 * Dormant HingeMem-B evidence-linked boundary projection candidate.
 *
 * This is an AIMOS adaptation of HingeMem's boundary-guided memory stage. It
 * partitions already-admitted retained evidence into transient semantic event
 * projections. Every projection binds the exact source identities and content
 * hashes. It never summarizes, merges, mutates, or persists canonical memory.
 *
 * Topic clustering, model boundary extraction, model query planning, adaptive
 * stopping, learned subspaces, database access, and signing are intentionally
 * absent. A projection is signature-ready evidence, not signed evidence, until
 * a later benefit proof authorizes the native housekeeper custody design.
 */

import { createHash } from 'node:crypto';

export const HINGEMEM_B_CONSTANTS = Object.freeze({
  maximum_states: 4096,
  marginal_maximum_states: 256,
  maximum_segment_size: 6,
  semantic_mad_multiplier: 1.5,
  temporal_gap_ms: 30 * 60 * 1000,
  boundary_projection_limit: 20,
  boundary_member_limit: 80,
  marginal_rank_limit: 40,
  rrf_k: 60,
});

export const HINGEMEM_BOUNDARY_MARGINAL_CONTRACT = Object.freeze({
  schema: 'hom-aimos/hingemem-boundary-marginal-gear/v1',
  architecture_role: 'dormant_graph_family_subgear_candidate',
  paper_authority: 'HingeMem_equations_1_to_5_and_table_3_boundary_memory_node_indexing',
  adaptation: 'deterministic_transient_source_bound_boundary_projection',
  maximum_input_states: HINGEMEM_B_CONSTANTS.marginal_maximum_states,
  maximum_emitted_ranks: HINGEMEM_B_CONSTANTS.marginal_rank_limit,
  graph_family_outer_channels: 1,
  candidate_set_authority: false,
  graph_only_discoveries: false,
  disclosure_authority: false,
  persistence_authority: false,
  signing_authority: false,
  mutation_authority: false,
  deletion_authority: false,
  model_authority: false,
  policy_authority: false,
  database_authority: false,
  environment_authority: false,
  runtime_wired: false,
  time_complexity: 'O(n_d_plus_n_log_n)',
  space_complexity: 'O(n_d_plus_n)',
});

export const HINGEMEM_B_GUARDRAILS = Object.freeze({
  dormant: true,
  transient_projection_only: true,
  source_partition_required: true,
  source_provenance_required: true,
  source_content_hash_required: true,
  signature_required_before_persistence: true,
  projection_is_currently_signed: false,
  uses_database: false,
  uses_environment_authority: false,
  uses_model_boundary_extractor: false,
  uses_topic_clustering: false,
  uses_model_query_planner: false,
  uses_adaptive_stop: false,
  mutates_memory: false,
  merges_canonical_memory: false,
  deletes_memory: false,
  suppresses_memory: false,
  applies_age_decay: false,
  admission_authority: false,
  disclosure_authority: false,
});

function fail(code) {
  throw new Error(`hingemem_boundary_projection:${code}`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function normalizeId(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeText(value) {
  return String(value || '').trim().replace(/\s+/g, ' ');
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

function normalizedSha256(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return bytes.length === 32 ? bytes.toString('hex') : null;
  }
  const text = String(value || '').trim();
  if (/^[a-f0-9]{64}$/i.test(text)) return text.toLowerCase();
  try {
    const bytes = Buffer.from(text, text.includes('-') || text.includes('_') ? 'base64url' : 'base64');
    return bytes.length === 32 ? bytes.toString('hex') : null;
  } catch {
    return null;
  }
}

function memoryText(memory, record) {
  if (Array.isArray(record.turns)) {
    const turns = record.turns.map((turn) => normalizeText(turn?.content)).filter(Boolean);
    if (turns.length) return turns.join('\n');
  }
  return normalizeText(record.content || record.text || record.composed_text || memory.value || memory.key);
}

function asStringSet(values) {
  return [...new Set((Array.isArray(values) ? values : [])
    .map((value) => normalizeText(value?.name ?? value?.label ?? value))
    .filter(Boolean))].sort();
}

function speakers(record) {
  return asStringSet(Array.isArray(record.turns) ? record.turns.map((turn) => turn?.speaker) : record.speakers);
}

function validTime(value) {
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

function sourceState(memory) {
  const id = normalizeId(memory?.id);
  const record = parseRecord(memory?.value);
  const embedding = parseEmbedding(memory?.embedding);
  const contentHash = [
    memory?.content_hash,
    memory?.provenance_proof?.live_content_hash,
    memory?.provenance_proof?.content_hash,
  ].map(normalizedSha256).find(Boolean);
  const text = memoryText(memory, record);
  const sessionId = normalizeText(memory?.session_id || record.session_id || memory?.source);
  const observed = memory?.occurred_start || record.valid_from || record.observed_at || memory?.created_at;
  const turnSequence = Math.min(...(Array.isArray(record.turn_sequences)
    ? record.turn_sequences.map(Number).filter(Number.isSafeInteger)
    : [Number.MAX_SAFE_INTEGER]));
  if (!id || !text || !sessionId || !embedding) fail('source_shape_invalid');
  if (!contentHash) fail('source_content_hash_invalid');
  if (!memory?.provenance_proof) fail('source_provenance_missing');
  return Object.freeze({
    id,
    key: String(memory?.key || ''),
    text,
    embedding: Object.freeze(embedding),
    content_hash: contentHash,
    session_id: sessionId,
    observed_ms: validTime(observed),
    observed_at: validTime(observed) === null ? null : new Date(validTime(observed)).toISOString(),
    turn_sequence: Number.isFinite(turnSequence) ? turnSequence : Number.MAX_SAFE_INTEGER,
    speakers: Object.freeze(speakers(record)),
  });
}

export function isHingeMemBoundaryInputEligible(memory) {
  try {
    sourceState(memory);
    return true;
  } catch {
    return false;
  }
}

function cosine(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length || left.length === 0) return null;
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  for (let index = 0; index < left.length; index += 1) {
    const a = Number(left[index]);
    const b = Number(right[index]);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
    dot += a * b;
    leftNorm += a * a;
    rightNorm += b * b;
  }
  const denominator = Math.sqrt(leftNorm) * Math.sqrt(rightNorm);
  return denominator > 0 ? Math.max(-1, Math.min(1, dot / denominator)) : null;
}

function median(values) {
  const sorted = values.map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return 0;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function semanticThreshold(states) {
  const distances = [];
  for (let index = 1; index < states.length; index += 1) {
    const similarity = cosine(states[index - 1].embedding, states[index].embedding);
    if (similarity !== null) distances.push(1 - similarity);
  }
  const center = median(distances);
  const mad = median(distances.map((value) => Math.abs(value - center)));
  return center + (HINGEMEM_B_CONSTANTS.semantic_mad_multiplier * mad);
}

function jaccard(left, right) {
  const a = new Set(left);
  const b = new Set(right);
  if (a.size === 0 && b.size === 0) return 1;
  const intersection = [...a].filter((value) => b.has(value)).length;
  return intersection / new Set([...a, ...b]).size;
}

function explicitTransition(text) {
  return /\b(?:anyway|by the way|speaking of|moving on|on another note|another thing|later that day|the next day)\b/i.test(text);
}

function averageEmbedding(states) {
  const dimensions = states[0].embedding.length;
  const vector = Array(dimensions).fill(0);
  for (const state of states) {
    if (state.embedding.length !== dimensions) fail('embedding_dimension_mismatch');
    for (let index = 0; index < dimensions; index += 1) vector[index] += state.embedding[index];
  }
  const averaged = vector.map((value) => value / states.length);
  const norm = Math.sqrt(averaged.reduce((sum, value) => sum + (value * value), 0));
  return Object.freeze(norm > 0 ? averaged.map((value) => value / norm) : averaged);
}

function projectionFor(states, ordinal, reasons) {
  const sourceIds = states.map((state) => state.id);
  const sourceHashes = states.map((state) => state.content_hash);
  const payload = {
    schema: 'hom-aimos/hingemem-boundary-projection/v1',
    session_id: states[0].session_id,
    ordinal,
    source_memory_ids: sourceIds,
    source_content_hashes: sourceHashes,
    source_text_sha256: sha256(states.map((state) => state.text).join('\0')),
    valid_from: states.find((state) => state.observed_at)?.observed_at || null,
    valid_until: [...states].reverse().find((state) => state.observed_at)?.observed_at || null,
    speakers: asStringSet(states.flatMap((state) => state.speakers)),
    boundary_reasons: [...new Set(reasons)].sort(),
    topic_cluster: null,
  };
  const projectionSha256 = sha256(`hom-aimos/hingemem-boundary-projection/v1\0${JSON.stringify(payload)}`);
  return Object.freeze({
    ...payload,
    projection_sha256: projectionSha256,
    embedding: averageEmbedding(states),
    signature_state: 'unsigned_transient_candidate',
  });
}

function partitionSession(states) {
  if (!states.length) return [];
  const threshold = semanticThreshold(states);
  const projections = [];
  let segment = [states[0]];
  let reasons = ['session_start'];
  for (let index = 1; index < states.length; index += 1) {
    const previous = states[index - 1];
    const current = states[index];
    const nextReasons = [];
    const similarity = cosine(previous.embedding, current.embedding);
    if (similarity !== null && (1 - similarity) > threshold) nextReasons.push('semantic_shift');
    if (previous.observed_ms !== null && current.observed_ms !== null
      && current.observed_ms - previous.observed_ms > HINGEMEM_B_CONSTANTS.temporal_gap_ms) nextReasons.push('change_time');
    if (jaccard(previous.speakers, current.speakers) < 1) nextReasons.push('change_person');
    if (explicitTransition(current.text)) nextReasons.push('explicit_marker');
    if (segment.length >= HINGEMEM_B_CONSTANTS.maximum_segment_size) nextReasons.push('maximum_span');
    if (nextReasons.length) {
      projections.push(projectionFor(segment, projections.length + 1, reasons));
      segment = [current];
      reasons = nextReasons;
    } else {
      segment.push(current);
    }
  }
  projections.push(projectionFor(segment, projections.length + 1, reasons));
  return projections;
}

export function buildHingeMemBoundaryProjection(memories = []) {
  if (!Array.isArray(memories) || memories.length === 0) fail('sources_required');
  if (memories.length > HINGEMEM_B_CONSTANTS.maximum_states) fail('source_cap_exceeded');
  const states = memories.map(sourceState);
  const ids = states.map((state) => state.id);
  if (new Set(ids).size !== ids.length) fail('duplicate_source_id');
  const sessions = new Map();
  for (const state of states) {
    const rows = sessions.get(state.session_id) || [];
    rows.push(state);
    sessions.set(state.session_id, rows);
  }
  const projections = [];
  for (const sessionId of [...sessions.keys()].sort()) {
    const ordered = sessions.get(sessionId).sort((left, right) => (left.observed_ms ?? Number.MAX_SAFE_INTEGER)
      - (right.observed_ms ?? Number.MAX_SAFE_INTEGER)
      || left.turn_sequence - right.turn_sequence
      || left.key.localeCompare(right.key)
      || left.id.localeCompare(right.id));
    projections.push(...partitionSession(ordered));
  }
  const projectedIds = projections.flatMap((projection) => projection.source_memory_ids).sort();
  if (JSON.stringify(projectedIds) !== JSON.stringify([...ids].sort())) fail('source_partition_incomplete');
  const projectionSetSha256 = sha256(`hom-aimos/hingemem-boundary-projection-set/v1\0${projections
    .map((projection) => projection.projection_sha256).join('\0')}`);
  return Object.freeze({
    projections: Object.freeze(projections),
    decision: Object.freeze({
      schema: 'hom-aimos/hingemem-boundary-projection-set/v1',
      source_count: states.length,
      projection_count: projections.length,
      source_partition_complete: true,
      projection_set_sha256: projectionSetSha256,
    }),
    guardrails: HINGEMEM_B_GUARDRAILS,
  });
}

function rankBoundaryProjectionMembers({
  queryEmbedding,
  scopeMemories,
  projectionState = null,
} = {}) {
  const query = parseEmbedding(queryEmbedding);
  if (!query) fail('query_embedding_invalid');
  if (!Array.isArray(scopeMemories) || scopeMemories.length === 0) fail('scope_memories_required');
  const scopeStates = scopeMemories.map(sourceState);
  const scopeById = new Map(scopeStates.map((state) => [state.id, state]));
  const built = projectionState || buildHingeMemBoundaryProjection(scopeMemories);
  if (!Array.isArray(built?.projections) || !built.projections.length) fail('projection_state_invalid');

  const rankedProjections = built.projections.map((projection) => ({
    projection,
    score: cosine(query, projection.embedding) ?? -1,
  })).sort((left, right) => right.score - left.score
    || left.projection.projection_sha256.localeCompare(right.projection.projection_sha256))
    .slice(0, HINGEMEM_B_CONSTANTS.boundary_projection_limit);

  const boundaryRows = [];
  for (let projectionIndex = 0; projectionIndex < rankedProjections.length; projectionIndex += 1) {
    const row = rankedProjections[projectionIndex];
    const members = row.projection.source_memory_ids.map((id) => scopeById.get(id)).filter(Boolean)
      .map((state) => ({ id: state.id, member_score: cosine(query, state.embedding) ?? -1 }))
      .sort((left, right) => right.member_score - left.member_score || left.id.localeCompare(right.id));
    for (const member of members) {
      boundaryRows.push({
        id: member.id,
        projection_score: row.score,
        member_score: member.member_score,
        projection_rank: projectionIndex + 1,
        projection_sha256: row.projection.projection_sha256,
      });
    }
  }
  boundaryRows.sort((left, right) => right.projection_score - left.projection_score
    || right.member_score - left.member_score
    || left.projection_rank - right.projection_rank
    || left.id.localeCompare(right.id));
  const boundaryRank = new Map();
  for (const row of boundaryRows) {
    if (!boundaryRank.has(row.id) && boundaryRank.size < HINGEMEM_B_CONSTANTS.boundary_member_limit) {
      boundaryRank.set(row.id, Object.freeze({ ...row, rank: boundaryRank.size + 1 }));
    }
  }
  return Object.freeze({
    built,
    boundary_rows: Object.freeze([...boundaryRank.values()]),
  });
}

export function composeHingeMemBoundaryMarginalGear({
  queryEmbedding,
  admittedMemories = [],
  projectionState = null,
  rankLimit = HINGEMEM_B_CONSTANTS.marginal_rank_limit,
} = {}) {
  if (!Array.isArray(admittedMemories) || admittedMemories.length === 0) fail('admitted_memories_required');
  if (admittedMemories.length > HINGEMEM_B_CONSTANTS.marginal_maximum_states) {
    fail('marginal_input_cap_exceeded');
  }
  if (admittedMemories.some((memory) => memory?.canary_admitted !== true)) {
    fail('canary_admission_required');
  }
  const outputLimit = Math.max(1, Math.min(
    HINGEMEM_B_CONSTANTS.marginal_rank_limit,
    Math.floor(Number(rankLimit) || HINGEMEM_B_CONSTANTS.marginal_rank_limit),
  ));
  const ranked = rankBoundaryProjectionMembers({
    queryEmbedding,
    scopeMemories: admittedMemories,
    projectionState,
  });
  const ranks = ranked.boundary_rows.slice(0, outputLimit).map((row, index) => Object.freeze({
    id: row.id,
    rank: index + 1,
    score: Number((((row.projection_score + 1) + (row.member_score + 1)) / 4).toFixed(12)),
    projection_rank: row.projection_rank,
    projection_sha256: row.projection_sha256,
  }));
  const rankCommitment = sha256(`hom-aimos/hingemem-boundary-marginal-ranks/v1\0${ranks
    .map((row) => `${row.id}:${row.rank}:${row.score}:${row.projection_sha256}`)
    .join('\0')}`);
  const decisionBody = {
    schema: HINGEMEM_BOUNDARY_MARGINAL_CONTRACT.schema,
    projection_set_sha256: ranked.built.decision.projection_set_sha256,
    rank_commitment_sha256: rankCommitment,
    source_count: ranked.built.decision.source_count,
    projection_count: ranked.built.decision.projection_count,
    emitted_rank_count: ranks.length,
    source_partition_complete: ranked.built.decision.source_partition_complete,
    candidate_set_authority: false,
    graph_only_discovery_count: 0,
    disclosure_authority: false,
    automatic_activation: false,
  };
  return Object.freeze({
    ranks: Object.freeze(ranks),
    discovered_memories: Object.freeze([]),
    decision: Object.freeze({
      ...decisionBody,
      decision_sha256: sha256(`hom-aimos/hingemem-boundary-marginal-decision/v1\0${JSON.stringify(decisionBody)}`),
    }),
    diagnostics: Object.freeze({
      source_count: ranked.built.decision.source_count,
      projection_count: ranked.built.decision.projection_count,
      boundary_rank_count: ranks.length,
      topic_clustering_used: false,
      adaptive_stop_used: false,
      model_boundary_extractor_used: false,
    }),
    guardrails: HINGEMEM_B_GUARDRAILS,
    contract: HINGEMEM_BOUNDARY_MARGINAL_CONTRACT,
  });
}

export function retrieveHingeMemBoundaryProjection({
  queryEmbedding,
  baselineMemories = [],
  scopeMemories = [],
  projectionState = null,
  limit = 20,
} = {}) {
  if (!parseEmbedding(queryEmbedding)) fail('query_embedding_invalid');
  if (!Array.isArray(baselineMemories) || baselineMemories.length === 0) fail('baseline_required');
  const boundary = rankBoundaryProjectionMembers({ queryEmbedding, scopeMemories, projectionState });
  const built = boundary.built;
  const boundaryRank = new Map(boundary.boundary_rows.map((row) => [row.id, row.rank]));

  const baselineIds = baselineMemories.map((memory) => normalizeId(memory?.id));
  if (baselineIds.some((id) => !id) || new Set(baselineIds).size !== baselineIds.length) fail('baseline_identity_invalid');
  const baselineRank = new Map(baselineIds.map((id, index) => [id, index + 1]));
  const union = new Set([...baselineIds, ...boundaryRank.keys()]);
  const ranked = [...union].map((id) => ({
    id,
    score: (baselineRank.has(id) ? 1 / (HINGEMEM_B_CONSTANTS.rrf_k + baselineRank.get(id)) : 0)
      + (boundaryRank.has(id) ? 1 / (HINGEMEM_B_CONSTANTS.rrf_k + boundaryRank.get(id)) : 0),
    baseline_rank: baselineRank.get(id) || null,
    boundary_rank: boundaryRank.get(id) || null,
  })).sort((left, right) => right.score - left.score
    || (left.baseline_rank ?? Number.MAX_SAFE_INTEGER) - (right.baseline_rank ?? Number.MAX_SAFE_INTEGER)
    || (left.boundary_rank ?? Number.MAX_SAFE_INTEGER) - (right.boundary_rank ?? Number.MAX_SAFE_INTEGER)
    || left.id.localeCompare(right.id))
    .slice(0, Math.max(1, Math.min(Number(limit) || 20, 20)));

  const outputIds = ranked.map((row) => row.id);
  const decisionSha256 = sha256(`hom-aimos/hingemem-b-retrieval/v1\0${built.decision.projection_set_sha256}\0${outputIds.join('\0')}`);
  return Object.freeze({
    ranked: Object.freeze(ranked.map(Object.freeze)),
    decision: Object.freeze({
      schema: 'hom-aimos/hingemem-b-retrieval/v1',
      projection_set_sha256: built.decision.projection_set_sha256,
      baseline_rank_sha256: sha256(`hom-aimos/hingemem-b-baseline/v1\0${baselineIds.join('\0')}`),
      output_rank_sha256: sha256(`hom-aimos/hingemem-b-output/v1\0${outputIds.join('\0')}`),
      decision_sha256: decisionSha256,
    }),
    diagnostics: Object.freeze({
      projection_count: built.projections.length,
      boundary_discovered_count: outputIds.filter((id) => !baselineRank.has(id)).length,
      topic_clustering_used: false,
      adaptive_stop_used: false,
    }),
    guardrails: HINGEMEM_B_GUARDRAILS,
  });
}
