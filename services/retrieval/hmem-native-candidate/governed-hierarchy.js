/**
 * AIMOS-native governed hierarchy candidate derived from H-MEM.
 *
 * Paper authority:
 * - H-MEM: Hierarchical Memory for High-Efficiency Long-Term Reasoning in
 *   LLM Agents (paper SHA-256 is bound by the H2 preregistration).
 *
 * Retained technique:
 * - four-level top-down semantic routing with positional child pointers.
 *
 * AIMOS adaptation:
 * - deterministic balanced spherical clustering replaces LLM-generated
 *   hierarchy labels;
 * - the pinned stored embedding is the only semantic representation;
 * - verified security influence may prevent a retained memory from steering a
 *   centroid without deleting it from the complete hierarchy;
 * - this pure candidate neither reads nor writes a database and has no caller.
 */

import { createHash } from 'node:crypto';

export const HMEM_H2_VERSION = 'hom-aimos/hmem-h2-governed-hierarchy/v1';

export const HMEM_H2_DEFAULTS = Object.freeze({
  dimension: 768,
  target_sizes: Object.freeze([128, 32, 12]),
  branch_cap: 8,
  iterations: 8,
  beam_width: 4,
  episode_per_parent: 10,
  result_limit: 10,
  episode_weight: 0.8,
  path_weight: 0.2,
});

export const HMEM_H2_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  suppresses_canonical_memory: false,
  parses_epistemic_labels: false,
  requires_verified_security_projection_in_security_mode: true,
  zero_influence_retained_in_complete_hierarchy: true,
  zero_influence_excluded_from_ordinary_candidate_output: true,
});

function sha256(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function finiteInteger(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(number)));
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}

function vector(value, dimension) {
  let parsed = null;
  if (Array.isArray(value) || ArrayBuffer.isView(value)) parsed = Array.from(value, Number);
  else {
    const text = String(value || '').trim();
    if (text.startsWith('[') && text.endsWith(']')) parsed = text.slice(1, -1).split(',').map(Number);
  }
  if (!parsed?.length || parsed.length !== dimension || parsed.some((entry) => !Number.isFinite(entry))) return null;
  const norm = Math.sqrt(parsed.reduce((sum, entry) => sum + (entry * entry), 0));
  if (!Number.isFinite(norm) || norm === 0) return null;
  return parsed.map((entry) => entry / norm);
}

function cosine(left, right) {
  let score = 0;
  for (let index = 0; index < left.length; index += 1) score += left[index] * right[index];
  return Math.max(-1, Math.min(1, score));
}

function normalizedWeightedMean(members, fallback) {
  const dimension = fallback.length;
  const aggregate = Array.from({ length: dimension }, () => 0);
  let total = 0;
  for (const member of members) {
    const weight = boundedNumber(member.centroid_influence, 1, 0, 1);
    if (weight <= 0) continue;
    total += weight;
    for (let index = 0; index < dimension; index += 1) aggregate[index] += member.embedding[index] * weight;
  }
  if (total <= 0) return [...fallback];
  const norm = Math.sqrt(aggregate.reduce((sum, entry) => sum + (entry * entry), 0));
  if (!Number.isFinite(norm) || norm === 0) return [...fallback];
  return aggregate.map((entry) => entry / norm);
}

function stableMembers(states, { dimension, securityMode }) {
  const byId = new Map();
  for (const state of Array.isArray(states) ? states : []) {
    if (!state || typeof state !== 'object') continue;
    const id = String(state.id || '').trim();
    if (!id || byId.has(id)) continue;
    const embedding = vector(state.embedding ?? state.memory?.embedding, dimension);
    if (!embedding) throw new Error(`hmem_h2_embedding_invalid:${id}`);
    if (securityMode === 'verified' && state.security_projection_verified !== true) {
      throw new Error(`hmem_h2_security_projection_unverified:${id}`);
    }
    const influence = securityMode === 'verified'
      ? boundedNumber(state.centroid_influence, 0, 0, 1)
      : 1;
    byId.set(id, Object.freeze({
      id,
      embedding: Object.freeze(embedding),
      centroid_influence: influence,
      security_projection_verified: securityMode === 'verified',
      state,
    }));
  }
  return [...byId.values()].sort((left, right) => left.id.localeCompare(right.id));
}

function initialCentroids(members, count) {
  const mean = normalizedWeightedMean(members, members[0].embedding);
  const first = [...members].sort((left, right) => {
    const delta = cosine(right.embedding, mean) - cosine(left.embedding, mean);
    return Math.abs(delta) > 1e-15 ? delta : left.id.localeCompare(right.id);
  })[0];
  const seeds = [first];
  while (seeds.length < count) {
    const next = [...members].filter((member) => !seeds.some((seed) => seed.id === member.id))
      .map((member) => ({
        member,
        minimum_distance: Math.min(...seeds.map((seed) => 1 - cosine(member.embedding, seed.embedding))),
      }))
      .sort((left, right) => {
        const delta = right.minimum_distance - left.minimum_distance;
        return Math.abs(delta) > 1e-15 ? delta : left.member.id.localeCompare(right.member.id);
      })[0]?.member;
    if (!next) break;
    seeds.push(next);
  }
  return seeds.map((seed) => ({ id: seed.id, vector: [...seed.embedding] }));
}

function assignmentCommitment(assignments) {
  return sha256(`hom-aimos/hmem-h2-assignments/v1\0${assignments
    .flatMap((cluster, index) => cluster.map((member) => `${member.id}:${index}`))
    .sort()
    .join('\0')}`);
}

function balancedPartition(members, count, iterations) {
  if (count <= 1 || members.length <= 1) return [members];
  let centroids = initialCentroids(members, count);
  let previousCommitment = null;
  let assignments = [];
  const capacity = Math.ceil(members.length / centroids.length);

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    assignments = Array.from({ length: centroids.length }, () => []);
    const rankedMembers = members.map((member) => {
      const choices = centroids.map((centroid, index) => ({
        index,
        id: centroid.id,
        similarity: cosine(member.embedding, centroid.vector),
      })).sort((left, right) => {
        const delta = right.similarity - left.similarity;
        return Math.abs(delta) > 1e-15 ? delta : left.id.localeCompare(right.id);
      });
      return {
        member,
        choices,
        margin: choices[0].similarity - (choices[1]?.similarity ?? -1),
      };
    }).sort((left, right) => {
      const delta = right.margin - left.margin;
      return Math.abs(delta) > 1e-15 ? delta : left.member.id.localeCompare(right.member.id);
    });

    for (const row of rankedMembers) {
      const selected = row.choices.find((choice) => assignments[choice.index].length < capacity)
        || row.choices[0];
      assignments[selected.index].push(row.member);
    }

    const commitment = assignmentCommitment(assignments);
    centroids = assignments.map((cluster, index) => ({
      id: [...cluster].sort((left, right) => left.id.localeCompare(right.id))[0]?.id || centroids[index].id,
      vector: normalizedWeightedMean(cluster, centroids[index].vector),
    }));
    if (commitment === previousCommitment) break;
    previousCommitment = commitment;
  }

  return assignments
    .map((cluster) => [...cluster].sort((left, right) => left.id.localeCompare(right.id)))
    .sort((left, right) => left[0].id.localeCompare(right[0].id));
}

function nodeId(level, memberIds) {
  return `h2:${level}:${sha256(`${HMEM_H2_VERSION}\0${level}\0${memberIds.join('\0')}`).slice(0, 24)}`;
}

function episodeNode(member, parentId) {
  return {
    id: `episode:${member.id}`,
    level: 'episode',
    parent_id: parentId,
    memory_id: member.id,
    vector: member.embedding,
    children: [],
    member_ids: [member.id],
    centroid_member_ids: member.centroid_influence > 0 ? [member.id] : [],
    ordinary_output_eligible: member.centroid_influence > 0,
    centroid_influence: member.centroid_influence,
    source_state: member.state,
  };
}

function buildNode(cluster, levelIndex, parentId, config, levels) {
  const level = ['domain', 'category', 'trace'][levelIndex];
  const memberIds = cluster.map((member) => member.id).sort();
  const positive = cluster.filter((member) => member.centroid_influence > 0);
  const centroid = normalizedWeightedMean(positive, cluster[0].embedding);
  const id = nodeId(level, memberIds);
  const node = {
    id,
    level,
    parent_id: parentId,
    vector: centroid,
    children: [],
    member_ids: memberIds,
    centroid_member_ids: positive.map((member) => member.id).sort(),
    ordinary_output_eligible: true,
  };
  levels[level].push(node);

  if (levelIndex === 2) {
    node.children = cluster.map((member) => {
      const episode = episodeNode(member, id);
      levels.episode.push(episode);
      return episode;
    });
    return node;
  }

  const target = config.target_sizes[levelIndex + 1];
  const count = Math.min(config.branch_cap, Math.max(1, Math.ceil(cluster.length / target)));
  node.children = balancedPartition(cluster, count, config.iterations)
    .map((childCluster) => buildNode(childCluster, levelIndex + 1, id, config, levels));
  return node;
}

function attachZeroInfluence(zeroMembers, levels) {
  if (!zeroMembers.length) return;
  if (!levels.trace.length) throw new Error('hmem_h2_trace_layer_missing');
  for (const member of zeroMembers) {
    const parent = [...levels.trace].sort((left, right) => {
      const delta = cosine(member.embedding, right.vector) - cosine(member.embedding, left.vector);
      return Math.abs(delta) > 1e-15 ? delta : left.id.localeCompare(right.id);
    })[0];
    const episode = episodeNode(member, parent.id);
    parent.children.push(episode);
    parent.children.sort((left, right) => left.id.localeCompare(right.id));
    parent.member_ids = [...new Set([...parent.member_ids, member.id])].sort();
    levels.episode.push(episode);
  }
}

function vectorCommitment(value) {
  return sha256(value.map((entry) => Number(entry).toFixed(12)).join(','));
}

function hierarchyCommitments(levels, config) {
  const semanticNodes = [];
  const completeNodes = [];
  for (const level of ['domain', 'category', 'trace', 'episode']) {
    for (const node of [...levels[level]].sort((left, right) => left.id.localeCompare(right.id))) {
      const common = {
        id: node.id,
        level: node.level,
        parent_id: node.parent_id || null,
        vector_sha256: vectorCommitment(node.vector),
        child_ids: node.children.map((child) => child.id).sort(),
      };
      semanticNodes.push({ ...common, member_ids: [...node.centroid_member_ids].sort() });
      completeNodes.push({ ...common, member_ids: [...node.member_ids].sort() });
    }
  }
  const parameters = sha256(`${HMEM_H2_VERSION}\0${canonical(config)}`);
  return Object.freeze({
    parameters_sha256: parameters,
    semantic_root_sha256: sha256(`${HMEM_H2_VERSION}/semantic\0${canonical(semanticNodes)}\0${parameters}`),
    complete_root_sha256: sha256(`${HMEM_H2_VERSION}/complete\0${canonical(completeNodes)}\0${parameters}`),
  });
}

export function buildGovernedHmemHierarchy(states = [], options = {}) {
  const config = Object.freeze({
    dimension: finiteInteger(options.dimension, HMEM_H2_DEFAULTS.dimension, 1, 4096),
    target_sizes: Object.freeze((Array.isArray(options.targetSizes)
      ? options.targetSizes
      : HMEM_H2_DEFAULTS.target_sizes).map((value, index) => finiteInteger(
      value,
      HMEM_H2_DEFAULTS.target_sizes[index],
      2,
      100_000,
    ))),
    branch_cap: finiteInteger(options.branchCap, HMEM_H2_DEFAULTS.branch_cap, 2, 32),
    iterations: finiteInteger(options.iterations, HMEM_H2_DEFAULTS.iterations, 1, 64),
    security_mode: options.securityMode === 'verified' ? 'verified' : 'off',
  });
  if (config.target_sizes.length !== 3) throw new Error('hmem_h2_target_size_contract_invalid');
  const members = stableMembers(states, { dimension: config.dimension, securityMode: config.security_mode });
  if (!members.length) throw new Error('hmem_h2_states_required');
  const positive = members.filter((member) => member.centroid_influence > 0);
  const zero = members.filter((member) => member.centroid_influence === 0);
  if (!positive.length) throw new Error('hmem_h2_no_routable_centroid_members');

  const levels = { domain: [], category: [], trace: [], episode: [] };
  const rootCount = Math.min(config.branch_cap, Math.max(1, Math.ceil(positive.length / config.target_sizes[0])));
  const roots = balancedPartition(positive, rootCount, config.iterations)
    .map((cluster) => buildNode(cluster, 0, null, config, levels));
  attachZeroInfluence(zero, levels);
  for (const level of Object.values(levels)) level.sort((left, right) => left.id.localeCompare(right.id));
  const commitments = hierarchyCommitments(levels, config);
  return Object.freeze({
    version: HMEM_H2_VERSION,
    config,
    roots: Object.freeze(roots),
    levels: Object.freeze(Object.fromEntries(
      Object.entries(levels).map(([level, nodes]) => [level, Object.freeze(nodes)]),
    )),
    counts: Object.freeze(Object.fromEntries(Object.entries(levels).map(([level, nodes]) => [level, nodes.length]))),
    retained_memory_count: members.length,
    ordinary_output_eligible_count: positive.length,
    zero_influence_retained_count: zero.length,
    complete_reachability: levels.episode.length === members.length,
    commitments,
    guardrails: HMEM_H2_GUARDRAILS,
  });
}

function rankedChildren(queryVector, children, limit) {
  return [...children].map((node) => ({ node, similarity: cosine(queryVector, node.vector) }))
    .sort((left, right) => {
      const delta = right.similarity - left.similarity;
      return Math.abs(delta) > 1e-15 ? delta : left.node.id.localeCompare(right.node.id);
    })
    .slice(0, limit);
}

export function routeGovernedHmem(queryEmbedding, hierarchy, options = {}) {
  if (!hierarchy || hierarchy.version !== HMEM_H2_VERSION) throw new Error('hmem_h2_hierarchy_invalid');
  const query = vector(queryEmbedding, hierarchy.config.dimension);
  if (!query) throw new Error('hmem_h2_query_embedding_invalid');
  const beamWidth = finiteInteger(options.beamWidth, HMEM_H2_DEFAULTS.beam_width, 1, 32);
  const episodePerParent = finiteInteger(
    options.episodePerParent,
    HMEM_H2_DEFAULTS.episode_per_parent,
    1,
    200,
  );
  const limit = finiteInteger(options.limit, HMEM_H2_DEFAULTS.result_limit, 1, 200);
  const episodeWeight = boundedNumber(options.episodeWeight, HMEM_H2_DEFAULTS.episode_weight, 0, 1);
  const pathWeight = 1 - episodeWeight;

  let frontier = rankedChildren(query, hierarchy.roots, beamWidth)
    .map((row) => ({ node: row.node, path: [row.node.id], path_similarities: [row.similarity] }));
  for (const level of ['category', 'trace']) {
    const next = [];
    for (const parent of frontier) {
      for (const child of rankedChildren(
        query,
        parent.node.children.filter((node) => node.level === level),
        beamWidth,
      )) {
        next.push({
          node: child.node,
          path: [...parent.path, child.node.id],
          path_similarities: [...parent.path_similarities, child.similarity],
        });
      }
    }
    frontier = next;
  }

  const episodes = [];
  for (const parent of frontier) {
    const eligible = parent.node.children.filter((node) => node.level === 'episode' && node.ordinary_output_eligible);
    for (const child of rankedChildren(query, eligible, episodePerParent)) {
      const pathScore = parent.path_similarities.reduce((sum, entry) => sum + entry, 0)
        / parent.path_similarities.length;
      episodes.push({
        memory_id: child.node.memory_id,
        state: child.node.source_state,
        episode_similarity: child.similarity,
        path_similarity: pathScore,
        score: (episodeWeight * child.similarity) + (pathWeight * pathScore),
        path: [...parent.path, child.node.id],
      });
    }
  }
  const byMemory = new Map();
  for (const row of episodes) {
    const current = byMemory.get(row.memory_id);
    if (!current || row.score > current.score) byMemory.set(row.memory_id, row);
  }
  const ranked = [...byMemory.values()].sort((left, right) => {
    const delta = right.score - left.score;
    return Math.abs(delta) > 1e-15 ? delta : left.memory_id.localeCompare(right.memory_id);
  }).slice(0, limit).map((row, index) => Object.freeze({
    rank: index + 1,
    memory_id: row.memory_id,
    state: row.state,
    score: Number(row.score.toFixed(12)),
    episode_similarity: Number(row.episode_similarity.toFixed(12)),
    path_similarity: Number(row.path_similarity.toFixed(12)),
    path: Object.freeze(row.path),
  }));
  const decisionBody = {
    version: HMEM_H2_VERSION,
    hierarchy_root_sha256: hierarchy.commitments.complete_root_sha256,
    query_vector_sha256: vectorCommitment(query),
    beam_width: beamWidth,
    episode_per_parent: episodePerParent,
    episode_weight: episodeWeight,
    path_weight: pathWeight,
    selected_memory_ids: ranked.map((row) => row.memory_id),
    selected_paths: ranked.map((row) => row.path),
  };
  return Object.freeze({
    ranked: Object.freeze(ranked),
    selected_memory_ids: Object.freeze(ranked.map((row) => row.memory_id)),
    candidate_pool_count: byMemory.size,
    decision_sha256: sha256(`${HMEM_H2_VERSION}/decision\0${canonical(decisionBody)}`),
    hierarchy_root_sha256: hierarchy.commitments.complete_root_sha256,
    formula: '0.80*cosine(query,episode)+0.20*mean_path_cosine',
    guardrails: HMEM_H2_GUARDRAILS,
  });
}

export default {
  HMEM_H2_VERSION,
  HMEM_H2_DEFAULTS,
  HMEM_H2_GUARDRAILS,
  buildGovernedHmemHierarchy,
  routeGovernedHmem,
};
