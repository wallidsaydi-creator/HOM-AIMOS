/**
 * reconstructed-graph-additive/graph-family-bounded-fusion.js
 *
 * Pure dormant combiner for correlated graph sub-gears. The native outer
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
  candidate_set_authority: false,
  disclosure_authority: false,
  mutation_authority: false,
  environment_authority: false,
  runtime_wired: false,
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

export function fuseBoundedGraphFamily({
  magmaGear,
  candidateGears = [],
  rrfK = DEFAULT_RRF_K,
  limit = MAX_FAMILY_RANKS,
} = {}) {
  const offset = Number(rrfK);
  const outputLimit = Math.max(1, Math.min(MAX_FAMILY_RANKS, Math.floor(Number(limit) || MAX_FAMILY_RANKS)));
  if (!Number.isFinite(offset) || offset < 1) fail('rrf_k_invalid');
  const gears = [
    { name: 'magma', gear: magmaGear },
    ...(Array.isArray(candidateGears) ? candidateGears : []).map((entry, index) => ({
      name: String(entry?.name || `candidate_${index + 1}`).trim().toLowerCase(),
      gear: entry?.gear,
    })),
  ];
  if (gears.some((entry) => !entry.name)) fail('gear_name_invalid');
  const nameSet = new Set();
  for (const entry of gears) {
    if (nameSet.has(entry.name)) fail('duplicate_gear_name');
    nameSet.add(entry.name);
  }

  const bestById = new Map();
  const sourcesById = new Map();
  for (let gearIndex = 0; gearIndex < gears.length; gearIndex += 1) {
    const entry = gears[gearIndex];
    for (const rankRow of normalizeGearRanks(entry.gear, entry.name)) {
      const utility = 1 / (offset + rankRow.rank);
      const prior = bestById.get(rankRow.id);
      const candidate = { ...rankRow, utility, gear_index: gearIndex };
      if (!prior
        || candidate.utility > prior.utility
        || (candidate.utility === prior.utility && candidate.gear_index < prior.gear_index)) {
        bestById.set(rankRow.id, candidate);
      }
      const sources = sourcesById.get(rankRow.id) || new Set();
      sources.add(entry.name);
      sourcesById.set(rankRow.id, sources);
    }
  }

  const ranks = [...bestById.entries()]
    .map(([id, row]) => ({
      id,
      score: row.utility,
      winning_gear: row.gear,
      contributing_gears: [...sourcesById.get(id)].sort(),
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
    outer_channel_count: ranks.length ? 1 : 0,
    emitted_rank_count: ranks.length,
    magma_discovery_count: discoveredById.size,
    candidate_discovery_count: 0,
    duplicate_signal_idempotent: true,
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
