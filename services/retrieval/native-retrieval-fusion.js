/**
 * native-retrieval-fusion.js — deterministic fusion for native retrieval gears
 *
 * Vector distance, sparse lexical/BM25 evidence, QuIM, QMD, HyDE, entity/PPR
 * graph evidence, and MAGMA traversal are peers. No gear owns disclosure or
 * replaces the candidate set. Each gear emits one non-overlapping rank list;
 * this module combines those lists with Reciprocal Rank Fusion (Cormack et al.,
 * 2009; MAGMA Eq. 4), while retaining every provenance-admitted candidate for
 * the later epistemic, Canary, SABER, Aladdin, and signed-recall boundaries.
 *
 * The fusion is pure, deterministic, bounded by its admitted input population,
 * and carries no environment, database, activation, or mutation authority.
 */

import { createHash } from 'node:crypto';

export const NATIVE_RETRIEVAL_FUSION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/native-retrieval-fusion/v1',
  equation: 'weighted_reciprocal_rank_fusion',
  paper_authority: 'Cormack_et_al_2009_and_MAGMA_equation_4',
  rrf_k: 60,
  gears: Object.freeze([
    'vector',
    'bm25',
    'lexical',
    'temporal',
    'quim',
    'qmd',
    'hyde',
    'entity',
    'concept_ppr',
    'magma',
  ]),
  candidate_set_monotone: true,
  time_complexity: 'O(sum_channel_lengths + candidate_count_log_candidate_count)',
  space_complexity: 'O(candidate_count + sum_channel_lengths)',
  disclosure_authority: false,
  mutation_authority: false,
  environment_authority: false,
});

const RRF_K = NATIVE_RETRIEVAL_FUSION_CONTRACT.rrf_k;
const GEAR_WEIGHTS = Object.freeze(Object.fromEntries(
  NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.map((gear) => [gear, 1]),
));

function fail(code) {
  throw new Error(`native_retrieval_fusion:${code}`);
}

function memoryId(memory) {
  return String(memory?.id || memory?.memory_id || '').trim().toLowerCase();
}

function finiteNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function rankedBy(memories, selector, direction = 'desc', predicate = null) {
  return memories
    .filter((memory) => !predicate || predicate(memory))
    .map((memory, index) => ({
      id: memoryId(memory),
      score: selector(memory),
      original_index: index,
    }))
    .filter((row) => row.id && Number.isFinite(row.score))
    .sort((left, right) => {
      const scoreOrder = direction === 'asc'
        ? left.score - right.score
        : right.score - left.score;
      return scoreOrder || left.original_index - right.original_index || left.id.localeCompare(right.id);
    })
    .map((row) => row.id);
}

function normalizeMagmaRanks(magmaGear) {
  const ranks = Array.isArray(magmaGear?.ranks) ? magmaGear.ranks : [];
  const seen = new Set();
  const normalized = ranks
    .map((entry, index) => ({
      id: String(entry?.id || entry?.memory_id || '').trim().toLowerCase(),
      score: finiteNumber(entry?.score),
      rank: Number.isInteger(Number(entry?.rank)) ? Number(entry.rank) : index + 1,
    }))
    .sort((left, right) => left.rank - right.rank || right.score - left.score || left.id.localeCompare(right.id))
  const ids = [];
  for (const entry of normalized) {
    if (!entry.id || entry.score == null || seen.has(entry.id)) continue;
    seen.add(entry.id);
    ids.push(entry.id);
  }
  return ids;
}

function channelCommitment(channels) {
  return createHash('sha256').update(JSON.stringify(channels)).digest('hex');
}

/**
 * Fuse all native retrieval gears. MAGMA may add already-admitted graph
 * discoveries, but it cannot remove a baseline candidate or bypass the later
 * disclosure owners.
 */
export function fuseNativeRetrievalGears({
  admittedMemories,
  magmaGear = null,
  temporalBias = false,
  rrfK = RRF_K,
} = {}) {
  if (!Array.isArray(admittedMemories)) {
    fail('admitted_memories_required');
  }
  const offset = Number(rrfK);
  if (!Number.isFinite(offset) || offset < 1) fail('rrf_k_invalid');

  const baselineById = new Map();
  for (const memory of admittedMemories) {
    const id = memoryId(memory);
    if (!id || !memory?.provenance_proof) fail('unadmitted_baseline_candidate');
    if (!baselineById.has(id)) baselineById.set(id, memory);
  }
  const baselineIds = [...baselineById.keys()];

  const candidateById = new Map(baselineById);
  for (const memory of Array.isArray(magmaGear?.discovered_memories) ? magmaGear.discovered_memories : []) {
    const id = memoryId(memory);
    if (!id || !memory?.provenance_proof) fail('unadmitted_magma_discovery');
    if (!candidateById.has(id)) candidateById.set(id, memory);
  }
  const candidates = [...candidateById.values()];

  const channels = [];
  const addChannel = (gear, ids) => {
    if (!Object.hasOwn(GEAR_WEIGHTS, gear)) fail('unknown_gear');
    const unique = [];
    const seen = new Set();
    for (const raw of ids) {
      const id = String(raw || '').trim().toLowerCase();
      if (!id || seen.has(id) || !candidateById.has(id)) continue;
      seen.add(id);
      unique.push(id);
    }
    if (unique.length) channels.push(Object.freeze({ gear, weight: GEAR_WEIGHTS[gear], ids: Object.freeze(unique) }));
  };

  addChannel('vector', rankedBy(candidates, (memory) => finiteNumber(memory?.raw_distance), 'asc'));
  addChannel('bm25', rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.bm25_rank ?? memory?.bm25_score),
    'desc',
    (memory) => Number(memory?.bm25_rank ?? memory?.bm25_score) > 0,
  ));
  addChannel('lexical', rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.rerank_score),
    'desc',
    (memory) => {
      const source = String(memory?.retrieval_source || '');
      return Number(memory?.rerank_score) > 0
        && source !== 'quim_lookup'
        && !source.startsWith('qmd_')
        && source !== 'multi_stage_hyde';
    },
  ));
  addChannel('quim', rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.rerank_score),
    'desc',
    (memory) => memory?.retrieval_source === 'quim_lookup' && Number(memory?.rerank_score) > 0,
  ));
  addChannel('qmd', rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.rerank_score),
    'desc',
    (memory) => String(memory?.retrieval_source || '').startsWith('qmd_')
      && Number(memory?.rerank_score) > 0,
  ));
  addChannel('hyde', rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.rerank_score),
    'desc',
    (memory) => memory?.retrieval_source === 'multi_stage_hyde'
      && Number(memory?.rerank_score) > 0,
  ));
  addChannel('entity', rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.entity_hits),
    'desc',
    (memory) => Number(memory?.entity_hits) > 0,
  ));
  addChannel('concept_ppr', rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.ppr_score),
    'desc',
    (memory) => Number(memory?.ppr_score) > 0,
  ));
  const magmaRankIds = normalizeMagmaRanks(magmaGear);
  addChannel('magma', magmaRankIds);

  if (temporalBias) {
    const temporalIds = candidates
      .map((memory, index) => ({ id: memoryId(memory), timestamp: Date.parse(memory?.created_at || ''), index }))
      .filter((entry) => entry.id && Number.isFinite(entry.timestamp))
      .sort((left, right) => right.timestamp - left.timestamp || left.index - right.index || left.id.localeCompare(right.id))
      .map((entry) => entry.id);
    addChannel('temporal', temporalIds);
  }

  const scoreById = new Map();
  const gearsById = new Map();
  for (const channel of channels) {
    channel.ids.forEach((id, index) => {
      scoreById.set(id, (scoreById.get(id) || 0) + (channel.weight / (offset + index + 1)));
      const gears = gearsById.get(id) || [];
      gears.push(channel.gear);
      gearsById.set(id, gears);
    });
  }

  const fused = [...candidateById.keys()]
    .map((id, originalIndex) => ({ id, score: scoreById.get(id) || 0, originalIndex }))
    .sort((left, right) => right.score - left.score
      || left.originalIndex - right.originalIndex
      || left.id.localeCompare(right.id));
  const maximumScore = fused[0]?.score || 1;
  const ordered = Object.freeze(fused.map((entry, index) => Object.freeze({
    ...candidateById.get(entry.id),
    native_fusion_rank: index + 1,
    native_fusion_score: Number((entry.score / maximumScore).toFixed(6)),
    native_fusion_rrf_score: Number(entry.score.toFixed(12)),
    native_fusion_gears: Object.freeze([...(gearsById.get(entry.id) || [])]),
  })));

  const selectedIds = ordered.map((memory) => memoryId(memory));
  if (baselineIds.some((id) => !selectedIds.includes(id))) fail('baseline_candidate_removed');

  const decisionBody = {
    schema: NATIVE_RETRIEVAL_FUSION_CONTRACT.schema,
    equation: NATIVE_RETRIEVAL_FUSION_CONTRACT.equation,
    rrf_k: offset,
    baseline_count: baselineIds.length,
    magma_discovery_count: candidateById.size - baselineById.size,
    magma_input_rank_count: Array.isArray(magmaGear?.ranks) ? magmaGear.ranks.length : 0,
    magma_normalized_rank_count: magmaRankIds.length,
    magma_admitted_rank_count: channels.find((channel) => channel.gear === 'magma')?.ids.length || 0,
    fused_count: ordered.length,
    candidate_set_monotone: true,
    baseline_candidate_set_preserved: baselineIds.every((id) => selectedIds.includes(id)),
    channels: channels.map((channel) => ({ gear: channel.gear, weight: channel.weight, count: channel.ids.length })),
    channel_commitment_sha256: channelCommitment(channels),
    selected_memory_ids: selectedIds,
    canonical_memory_mutated: false,
    retention_changed: false,
    disclosure_authority: false,
  };
  const decisionSha256 = createHash('sha256').update(JSON.stringify(decisionBody)).digest('hex');

  return Object.freeze({
    memories: ordered,
    decision: Object.freeze({ ...decisionBody, decision_sha256: decisionSha256 }),
  });
}
