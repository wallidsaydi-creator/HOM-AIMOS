/**
 * deterministic-reranker.js — bounded HAGE-inspired post-MAGMA candidate.
 *
 * Paper authority: HAGE.pdf (source SHA-256
 * 867feac3e32d553c4f0815f9b760d5e7ede5515fcd4698e32003d597bc66b5f5).
 *
 * This is not a trained HAGE policy. It preserves the exact provenance-admitted
 * MAGMA candidate set and applies a deterministic, query-conditioned relational
 * rerank only. It owns no database, identity, signing, policy, checkpoint,
 * persistence, disclosure, Canary, epistemic, SABER, or environment authority.
 */

import { createHash } from 'node:crypto';

export const HAGE_D_CONTRACT = Object.freeze({
  schema: 'hom-aimos/hage-deterministic-reranker/v1',
  identity: 'HAGE-inspired deterministic proxy',
  paper_sha256: '867feac3e32d553c4f0815f9b760d5e7ede5515fcd4698e32003d597bc66b5f5',
  upstream_owner: 'master-signed enforced MAGMA candidate',
  maximum_nodes: 20,
  maximum_edges_per_node: 8,
  propagation_hops: 2,
  edge_threshold: 0.35,
  baseline_weight: 0.65,
  direct_weight: 0.15,
  propagated_weight: 0.20,
  environment_authority: false,
  database_authority: false,
  persistence_authority: false,
  disclosure_authority: false,
  canary_authority: false,
  epistemic_authority: false,
  saber_runtime_authority: false,
  changes_candidate_set: false,
  applies_decay: false,
  deletes_memory: false,
  suppresses_memory: false,
});

const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'by', 'did', 'do', 'does',
  'for', 'from', 'had', 'has', 'have', 'he', 'her', 'hers', 'him', 'his', 'how',
  'i', 'in', 'is', 'it', 'its', 'me', 'my', 'of', 'on', 'or', 'our', 'she',
  'that', 'the', 'their', 'them', 'they', 'this', 'to', 'was', 'we', 'were',
  'what', 'when', 'where', 'which', 'who', 'why', 'with', 'would', 'you', 'your',
]);

function fail(code) {
  throw new Error(`hage_deterministic:${code}`);
}

function clamp01(value) {
  if (!Number.isFinite(value)) fail('non_finite_score');
  return Math.max(0, Math.min(1, value));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function vector(value, dimensions, code) {
  if (!Array.isArray(value) && !ArrayBuffer.isView(value)) fail(`${code}_not_vector`);
  if (value.length !== dimensions) fail(`${code}_dimension`);
  const result = Array.from(value, Number);
  if (result.some((entry) => !Number.isFinite(entry))) fail(`${code}_non_finite`);
  const norm = Math.sqrt(result.reduce((sum, entry) => sum + (entry * entry), 0));
  if (!(norm > 0)) fail(`${code}_zero_norm`);
  return Object.freeze(result.map((entry) => entry / norm));
}

function cosine(left, right) {
  let total = 0;
  for (let index = 0; index < left.length; index += 1) total += left[index] * right[index];
  return Math.max(-1, Math.min(1, total));
}

function tokens(value) {
  return new Set(String(value || '').toLowerCase().match(/[\p{L}\p{N}]+/gu)
    ?.filter((token) => token.length >= 3 && !STOP_WORDS.has(token)) || []);
}

function overlap(left, right) {
  if (!left.size || !right.size) return 0;
  let common = 0;
  for (const token of left) if (right.has(token)) common += 1;
  return common / Math.sqrt(left.size * right.size);
}

function temporalProfile(queryText) {
  return /\b(after|before|between|during|earlier|later|last|next|recent|when|day|week|month|year|timeline)\b/i
    .test(String(queryText || ''));
}

function dayAffinity(left, right) {
  const leftMs = Date.parse(left || '');
  const rightMs = Date.parse(right || '');
  if (!Number.isFinite(leftMs) || !Number.isFinite(rightMs)) return 0;
  const days = Math.abs(leftMs - rightMs) / 86_400_000;
  return Math.exp(-Math.min(365, days) / 45);
}

function normalizedMemories(memories, queryDimensions) {
  if (!Array.isArray(memories) || memories.length < 2) fail('memories_required');
  if (memories.length > HAGE_D_CONTRACT.maximum_nodes) fail('node_cap_exceeded');
  const seen = new Set();
  return Object.freeze(memories.map((memory, index) => {
    if (!memory || typeof memory !== 'object' || Array.isArray(memory)) fail('memory_invalid');
    const id = String(memory.id || '').trim().toLowerCase();
    if (!id || seen.has(id)) fail('memory_id_invalid');
    seen.add(id);
    return Object.freeze({
      id,
      baseline_rank: index + 1,
      value: String(memory.value || memory.key || ''),
      created_at: memory.created_at ? String(memory.created_at) : '',
      embedding: vector(memory.embedding, queryDimensions, `memory_embedding_${index}`),
    });
  }));
}

function baselinePrior(rank, count) {
  return count === 1 ? 1 : 1 - ((rank - 1) / (count - 1));
}

export function rerankHageDeterministic({ queryText = '', queryEmbedding, memories } = {}) {
  if ((!Array.isArray(queryEmbedding) && !ArrayBuffer.isView(queryEmbedding))
    || queryEmbedding.length < 2 || queryEmbedding.length > 4096) fail('query_embedding_invalid');
  const query = vector(queryEmbedding, queryEmbedding.length, 'query_embedding');
  const nodes = normalizedMemories(memories, query.length);
  const temporalEnabled = temporalProfile(queryText);
  const tokenById = new Map(nodes.map((node) => [node.id, tokens(node.value)]));
  const directById = new Map(nodes.map((node) => [node.id, clamp01((cosine(query, node.embedding) + 1) / 2)]));
  const priorById = new Map(nodes.map((node) => [node.id, baselinePrior(node.baseline_rank, nodes.length)]));
  const adjacency = new Map(nodes.map((node) => [node.id, []]));
  const edges = [];

  for (const left of nodes) {
    const candidates = [];
    for (const right of nodes) {
      if (left.id === right.id) continue;
      const semantic = clamp01((cosine(left.embedding, right.embedding) + 1) / 2);
      const entity = clamp01(overlap(tokenById.get(left.id), tokenById.get(right.id)));
      const temporal = temporalEnabled ? dayAffinity(left.created_at, right.created_at) : 0;
      const weight = temporalEnabled
        ? clamp01((0.50 * semantic) + (0.25 * entity) + (0.25 * temporal))
        : clamp01((0.70 * semantic) + (0.30 * entity));
      if (weight < HAGE_D_CONTRACT.edge_threshold) continue;
      candidates.push(Object.freeze({
        from: left.id,
        to: right.id,
        weight,
        semantic,
        entity,
        temporal,
      }));
    }
    candidates.sort((a, b) => b.weight - a.weight || a.to.localeCompare(b.to));
    const admitted = candidates.slice(0, HAGE_D_CONTRACT.maximum_edges_per_node);
    adjacency.set(left.id, Object.freeze(admitted));
    edges.push(...admitted);
  }

  const seedById = new Map(nodes.map((node) => [
    node.id,
    (0.55 * priorById.get(node.id)) + (0.45 * directById.get(node.id)),
  ]));
  let signalById = new Map(seedById);
  for (let hop = 0; hop < HAGE_D_CONTRACT.propagation_hops; hop += 1) {
    const next = new Map();
    for (const node of nodes) {
      let incoming = 0;
      for (const source of nodes) {
        const edge = (adjacency.get(source.id) || []).find((entry) => entry.to === node.id);
        if (!edge) continue;
        incoming = Math.max(incoming, signalById.get(source.id) * edge.weight);
      }
      next.set(node.id, clamp01((0.50 * seedById.get(node.id)) + (0.50 * incoming)));
    }
    signalById = next;
  }

  const scored = nodes.map((node) => {
    const score = clamp01(
      (HAGE_D_CONTRACT.baseline_weight * priorById.get(node.id))
      + (HAGE_D_CONTRACT.direct_weight * directById.get(node.id))
      + (HAGE_D_CONTRACT.propagated_weight * signalById.get(node.id)),
    );
    return Object.freeze({
      id: node.id,
      baseline_rank: node.baseline_rank,
      score,
      baseline_prior: priorById.get(node.id),
      direct_similarity: directById.get(node.id),
      propagated_signal: signalById.get(node.id),
    });
  }).sort((a, b) => b.score - a.score || a.baseline_rank - b.baseline_rank || a.id.localeCompare(b.id));

  const baselineIds = nodes.map((node) => node.id);
  const selectedIds = scored.map((row) => row.id);
  if (selectedIds.length !== baselineIds.length
    || selectedIds.some((id) => !seenIn(baselineIds, id))) fail('candidate_set_changed');

  const edgeProjection = edges
    .map((edge) => ({
      from: edge.from,
      to: edge.to,
      weight: Number(edge.weight.toFixed(12)),
      semantic: Number(edge.semantic.toFixed(12)),
      entity: Number(edge.entity.toFixed(12)),
      temporal: Number(edge.temporal.toFixed(12)),
    }))
    .sort((a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to));
  const graphCommitment = sha256(`hom-aimos/hage-d-graph/v1\0${canonical(edgeProjection)}`);
  const decisionBody = {
    schema: HAGE_D_CONTRACT.schema,
    identity: HAGE_D_CONTRACT.identity,
    temporal_enabled: temporalEnabled,
    input_count: baselineIds.length,
    output_count: selectedIds.length,
    selected_memory_ids: selectedIds,
    baseline_memory_ids_sha256: sha256(`hom-aimos/hage-d-baseline/v1\0${baselineIds.join('\0')}`),
    selected_memory_ids_sha256: sha256(`hom-aimos/hage-d-selected/v1\0${selectedIds.join('\0')}`),
    graph_commitment_sha256: graphCommitment,
    graph_edges: edgeProjection.length,
    candidate_set_preserved: true,
    canonical_memory_mutated: false,
    retention_changed: false,
    disclosure_authority: false,
    saber_runtime_authority: false,
  };
  const decisionSha256 = sha256(`hom-aimos/hage-d-decision/v1\0${canonical(decisionBody)}`);
  return Object.freeze({
    ranked: Object.freeze(scored),
    decision: Object.freeze({ ...decisionBody, decision_sha256: decisionSha256 }),
    diagnostics: Object.freeze({
      temporal_enabled: temporalEnabled,
      temporal_edge_contribution_count: edgeProjection.filter((edge) => edge.temporal > 0).length,
      graph_edges: edgeProjection.length,
      mean_out_degree: edges.length / nodes.length,
      rank_changes: selectedIds.filter((id, index) => id !== baselineIds[index]).length,
    }),
  });
}

function seenIn(values, target) {
  return values.includes(target);
}

