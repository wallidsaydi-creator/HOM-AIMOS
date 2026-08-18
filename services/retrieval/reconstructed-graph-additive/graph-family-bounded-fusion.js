/**
 * reconstructed-graph-additive/graph-family-bounded-fusion.js
 *
 * Pure native combiner for correlated graph sub-gears. The native outer
 * fusion receives one structural channel regardless of how many graph
 * implementations exist. Max reciprocal-rank pooling is idempotent: copying a
 * graph signal cannot multiply graph-family voting mass.
 */

import { createHash } from 'node:crypto';

const DEFAULT_RRF_K = 60;
const MAX_FAMILY_RANKS = 50;

export const GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/graph-family-bounded-fusion/v1',
  equation: 'max_reciprocal_rank_pooling',
  rrf_k: DEFAULT_RRF_K,
  maximum_outer_channels: 1,
  duplicate_signal_idempotent: true,
  content_state_projection_optional: true,
  one_outer_rank_per_verified_content_state: true,
  candidate_set_authority: false,
  disclosure_authority: false,
  mutation_authority: false,
  environment_authority: false,
  runtime_wired: true,
});

function fail(code) {
  throw new Error(`graph_family_bounded_fusion:${code}`);
}

function normalizeGearRanks(gear, gearName) {
  const seen = new Set();
  return (Array.isArray(gear?.ranks) ? gear.ranks : [])
    .map((row, index) => ({
      id: String(row?.id || row?.memory_id || '').trim().toLowerCase(),
      rank: Number.isInteger(Number(row?.rank)) ? Number(row.rank) : index + 1,
      source_score: Number(row?.score),
      gear: gearName,
    }))
    .filter((row) => row.id && row.rank > 0 && Number.isFinite(row.source_score))
    .sort((left, right) => left.rank - right.rank || right.source_score - left.source_score || left.id.localeCompare(right.id))
    .filter((row) => {
      if (seen.has(row.id)) return false;
      seen.add(row.id);
      return true;
    });
}

function hash(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function buildContentStateIndex(projection) {
  if (projection == null) return null;
  if (!Array.isArray(projection?.occurrence_view)
    || !/^[0-9a-f]{64}$/.test(String(projection?.decision?.decision_sha256 || ''))) {
    fail('content_state_projection_invalid');
  }
  const byMemoryId = new Map();
  for (const occurrence of projection.occurrence_view) {
    const id = String(occurrence?.memory_id || '').trim().toLowerCase();
    const company = String(occurrence?.company_id || '').trim();
    const liveContentHash = String(occurrence?.live_content_hash || '').trim().toLowerCase();
    if (!id || !company || !/^[0-9a-f]{64}$/.test(liveContentHash)) {
      fail('content_state_projection_invalid');
    }
    const stateKey = `${company}\0${liveContentHash}`;
    const prior = byMemoryId.get(id);
    if (prior && prior !== stateKey) fail('content_state_projection_invalid');
    byMemoryId.set(id, stateKey);
  }
  return Object.freeze({
    byMemoryId,
    decisionSha256: projection.decision.decision_sha256,
  });
}

export function fuseBoundedGraphFamily({
  magmaGear,
  candidateGears = [],
  rrfK = DEFAULT_RRF_K,
  limit = MAX_FAMILY_RANKS,
  contentStateProjection = null,
} = {}) {
  const offset = Number(rrfK);
  const outputLimit = Math.max(1, Math.min(MAX_FAMILY_RANKS, Math.floor(Number(limit) || MAX_FAMILY_RANKS)));
  if (!Number.isFinite(offset) || offset < 1) fail('rrf_k_invalid');
  const gears = [
    ...(magmaGear ? [{ name: 'magma', gear: magmaGear }] : []),
    ...(Array.isArray(candidateGears) ? candidateGears : []).map((entry, index) => ({
      name: String(entry?.name || `candidate_${index + 1}`).trim().toLowerCase(),
      gear: entry?.gear,
    })),
  ];
  if (!gears.length) fail('subgear_required');
  if (gears.some((entry) => !entry.name)) fail('gear_name_invalid');
  const nameSet = new Set();
  for (const entry of gears) {
    if (nameSet.has(entry.name)) fail('duplicate_gear_name');
    nameSet.add(entry.name);
  }

  const contentStateIndex = buildContentStateIndex(contentStateProjection);
  const bestByState = new Map();
  const sourcesByState = new Map();
  let inputOccurrenceRankCount = 0;
  for (let gearIndex = 0; gearIndex < gears.length; gearIndex += 1) {
    const entry = gears[gearIndex];
    for (const rankRow of normalizeGearRanks(entry.gear, entry.name)) {
      inputOccurrenceRankCount += 1;
      const stateKey = contentStateIndex?.byMemoryId.get(rankRow.id) || rankRow.id;
      if (contentStateIndex && !contentStateIndex.byMemoryId.has(rankRow.id)) {
        fail('content_state_mapping_missing');
      }
      const utility = 1 / (offset + rankRow.rank);
      const prior = bestByState.get(stateKey);
      const candidate = { ...rankRow, utility, gear_index: gearIndex };
      if (!prior
        || candidate.utility > prior.utility
        || (candidate.utility === prior.utility && candidate.gear_index < prior.gear_index)) {
        bestByState.set(stateKey, candidate);
      }
      const sources = sourcesByState.get(stateKey) || new Set();
      sources.add(entry.name);
      sourcesByState.set(stateKey, sources);
    }
  }

  const ranks = [...bestByState.entries()]
    .map(([stateKey, row]) => ({
      id: row.id,
      score: row.utility,
      winning_gear: row.gear,
      contributing_gears: [...sourcesByState.get(stateKey)].sort(),
    }))
    .sort((left, right) => right.score - left.score
      || (left.winning_gear === 'magma' ? -1 : 0) - (right.winning_gear === 'magma' ? -1 : 0)
      || left.id.localeCompare(right.id))
    .slice(0, outputLimit)
    .map((row, index) => Object.freeze({ ...row, rank: index + 1 }));

  const discoveredById = new Map();
  for (const memory of Array.isArray(magmaGear?.discovered_memories) ? magmaGear.discovered_memories : []) {
    const id = String(memory?.id || memory?.memory_id || '').trim().toLowerCase();
    if (id && memory?.provenance_proof && !discoveredById.has(id)) discoveredById.set(id, memory);
  }
  const decisionBody = {
    schema: GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT.schema,
    equation: GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT.equation,
    rrf_k: offset,
    subgear_count: gears.length,
    subgear_names: Object.freeze(gears.map((entry) => entry.name)),
    magma_active: gears.some((entry) => entry.name === 'magma'),
    outer_channel_count: ranks.length ? 1 : 0,
    emitted_rank_count: ranks.length,
    magma_discovery_count: discoveredById.size,
    candidate_discovery_count: 0,
    duplicate_signal_idempotent: true,
    content_state_projection_decision_sha256: contentStateIndex?.decisionSha256 || null,
    input_occurrence_rank_count: inputOccurrenceRankCount,
    emitted_state_rank_count: ranks.length,
    collapsed_occurrence_rank_count: inputOccurrenceRankCount - ranks.length,
    content_state_deduplicated: Boolean(contentStateIndex),
    rank_commitment_sha256: hash(ranks),
    disclosure_authority: false,
  };

  return Object.freeze({
    ranks: Object.freeze(ranks),
    discovered_memories: Object.freeze([...discoveredById.values()]),
    decision: Object.freeze({ ...decisionBody, decision_sha256: hash(decisionBody) }),
    contract: GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT,
  });
}
