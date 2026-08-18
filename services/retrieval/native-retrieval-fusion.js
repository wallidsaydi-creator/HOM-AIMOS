/**
 * native-retrieval-fusion.js — deterministic fusion for native retrieval gears
 *
 * Vector distance, sparse lexical/BM25 evidence, QuIM, QMD, HyDE, entity/PPR,
 * and the bounded graph-family channel are peers. No gear owns disclosure or
 * replaces the candidate set. Each gear emits one non-overlapping rank list;
 * this module combines those lists with Reciprocal Rank Fusion (Cormack et al.,
 * 2009; MAGMA Eq. 4), while retaining every provenance-admitted candidate for
 * the later epistemic, Canary, SABER, Aladdin, and signed-recall boundaries.
 *
 * The fusion is pure, deterministic, bounded by its admitted input population,
 * and carries no environment, database, activation, or mutation authority.
 */

import { createHash } from 'node:crypto';
import { canonicalJson } from '../security/protocol/canonical-json.js';

export const NATIVE_RETRIEVAL_FUSION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/native-retrieval-fusion/v3-final-gearbox',
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
    'graph_family',
  ]),
  candidate_set_monotone: true,
  content_state_first_gear_set: Object.freeze([
    'vector',
    'bm25',
    'lexical',
    'quim',
    'temporal',
    'entity',
    'qmd',
    'hyde',
    'graph_family',
    'concept_ppr',
  ]),
  content_state_gear_rule: 'one_rank_per_verified_content_state_keep_all_candidates',
  production_phases: Object.freeze([
    'pre_reconstructed_graph',
    'pre_concept_ppr',
    'final_post_concept_ppr',
  ]),
  pure_evaluation_phase: 'pure_evaluation',
  final_production_phase: 'final_post_concept_ppr',
  graph_family_channel_key: 'graph_family',
  graph_family_outer_channel_count: 1,
  graph_family_role: 'single_outer_channel_for_all_graph_subgears',
  tie_break_rule: 'score_then_memory_id_lexicographic',
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

function qmdScore(memory) {
  const direct = finiteNumber(memory?.qmd_score);
  if (direct != null) return direct;
  return String(memory?.retrieval_source || '').startsWith('qmd_')
    ? finiteNumber(memory?.rerank_score)
    : null;
}

function hydeScore(memory) {
  const direct = finiteNumber(memory?.hyde_score);
  if (direct != null) return direct;
  return memory?.retrieval_source === 'multi_stage_hyde'
    ? finiteNumber(memory?.rerank_score)
    : null;
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
      return scoreOrder || left.id.localeCompare(right.id) || left.original_index - right.original_index;
    })
    .map((row) => row.id);
}

function normalizeGraphFamilyRanks(graphFamilyGear) {
  const ranks = Array.isArray(graphFamilyGear?.ranks) ? graphFamilyGear.ranks : [];
  const seen = new Set();
  const normalized = ranks
    .map((entry, index) => ({
      id: String(entry?.id || entry?.memory_id || '').trim().toLowerCase(),
      score: finiteNumber(entry?.score),
      rank: Number.isInteger(Number(entry?.rank)) ? Number(entry.rank) : index + 1,
    }))
    .filter((entry) => entry.rank > 0)
    .sort((left, right) => left.rank - right.rank || right.score - left.score || left.id.localeCompare(right.id));
  const ids = [];
  for (const entry of normalized) {
    if (!entry.id || entry.score == null || seen.has(entry.id)) continue;
    seen.add(entry.id);
    ids.push(entry.id);
  }
  return ids;
}

function channelCommitment(channels) {
  return createHash('sha256')
    .update(Buffer.from(canonicalJson(channels), 'utf8'))
    .digest('hex');
}

function normalizeFusionPhase(value) {
  const phase = String(value || NATIVE_RETRIEVAL_FUSION_CONTRACT.pure_evaluation_phase).trim();
  const allowed = new Set([
    ...NATIVE_RETRIEVAL_FUSION_CONTRACT.production_phases,
    NATIVE_RETRIEVAL_FUSION_CONTRACT.pure_evaluation_phase,
  ]);
  if (!allowed.has(phase)) fail('fusion_phase_invalid');
  return phase;
}

function verifyGraphFamilyContract(gear, required) {
  const decision = gear?.decision;
  const isGraphFamily = decision?.schema === 'hom-aimos/graph-family-bounded-fusion/v1';
  if (required && !isGraphFamily) fail('graph_family_contract_required');
  if (!isGraphFamily) return Object.freeze({
    verified: false,
    outerChannelCount: null,
    subgearCount: null,
    decisionSha256: null,
  });
  const ranks = Array.isArray(gear?.ranks) ? gear.ranks : [];
  const outerChannelCount = Number(decision.outer_channel_count);
  const subgearCount = Number(decision.subgear_count);
  if (![0, 1].includes(outerChannelCount)
      || outerChannelCount !== (ranks.length ? 1 : 0)
      || !Number.isInteger(subgearCount) || subgearCount < 1
      || decision.duplicate_signal_idempotent !== true
      || !/^[0-9a-f]{64}$/.test(String(decision.decision_sha256 || ''))) {
    fail('graph_family_contract_invalid');
  }
  return Object.freeze({
    verified: true,
    outerChannelCount,
    subgearCount,
    decisionSha256: decision.decision_sha256,
  });
}

function contentStateIndex(projection, protectedGears, candidateById) {
  const gears = new Set(Array.isArray(protectedGears) ? protectedGears : []);
  for (const gear of gears) {
    if (!NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set.includes(gear)) {
      fail('content_state_gear_not_authorized');
    }
  }
  if (!gears.size) return Object.freeze({
    gears, byMemoryId: new Map(), representativeByState: new Map(), decisionSha256: null,
  });
  if (!projection || !Array.isArray(projection.occurrence_view)
      || !Array.isArray(projection.state_view)
      || !/^[0-9a-f]{64}$/.test(String(projection?.decision?.decision_sha256 || ''))) {
    fail('content_state_projection_invalid');
  }
  const eligibleStates = new Set(projection.state_view
    .filter((state) => state?.rank_eligible === true)
    .map((state) => `${state.company_id}\0${state.live_content_hash}`));
  const byMemoryId = new Map();
  const occurrenceByRef = new Map();
  const candidateMembersByState = new Map();
  for (const occurrence of projection.occurrence_view) {
    const id = String(occurrence?.memory_id || '').trim().toLowerCase();
    const company = String(occurrence?.company_id || '');
    const hash = String(occurrence?.live_content_hash || '').trim().toLowerCase();
    if (!id || !company || !/^[0-9a-f]{64}$/.test(hash)) fail('content_state_projection_invalid');
    const stateKey = `${company}\0${hash}`;
    const existing = byMemoryId.get(id);
    if (existing && existing.stateKey !== stateKey) fail('content_state_projection_invalid');
    byMemoryId.set(id, Object.freeze({ stateKey, rankEligible: eligibleStates.has(stateKey) }));
    const occurrenceRef = String(occurrence?.occurrence_ref || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(occurrenceRef) || occurrenceByRef.has(occurrenceRef)) {
      fail('content_state_projection_invalid');
    }
    occurrenceByRef.set(occurrenceRef, Object.freeze({
      memoryId: id,
      stateKey,
      occurrenceRef,
      lineage: occurrence.lineage,
      rankEligible: occurrence.rank_eligible === true,
    }));
    if (occurrence.rank_eligible === true && candidateById.has(id)) {
      if (!candidateMembersByState.has(stateKey)) candidateMembersByState.set(stateKey, []);
      candidateMembersByState.get(stateKey).push(occurrenceByRef.get(occurrenceRef));
    }
  }
  const representativeByState = new Map();
  for (const state of projection.state_view) {
    if (state?.rank_eligible !== true) continue;
    const stateKey = `${state.company_id}\0${state.live_content_hash}`;
    const witness = occurrenceByRef.get(String(state.disclosure_witness_occurrence_ref || '').toLowerCase());
    if (!witness || witness.stateKey !== stateKey) fail('content_state_projection_invalid');
    const candidateMembers = candidateMembersByState.get(stateKey) || [];
    if (!candidateMembers.length) continue;
    const selected = candidateById.has(witness.memoryId)
      ? witness
      : candidateMembers.sort((left, right) => (
          Number(right.lineage?.is_current_head) - Number(left.lineage?.is_current_head)
          || Number(right.lineage?.signed_time_ms || 0) - Number(left.lineage?.signed_time_ms || 0)
          || left.occurrenceRef.localeCompare(right.occurrenceRef)
        ))[0];
    representativeByState.set(stateKey, selected.memoryId);
  }
  return Object.freeze({
    gears,
    byMemoryId,
    representativeByState,
    decisionSha256: projection.decision.decision_sha256,
  });
}

function collapseChannelByContentState(gear, ids, index) {
  const uniqueIds = [];
  const seenIds = new Set();
  for (const raw of ids) {
    const id = String(raw || '').trim().toLowerCase();
    if (!id || seenIds.has(id)) continue;
    seenIds.add(id);
    uniqueIds.push(id);
  }
  if (!index.gears.has(gear)) {
    return Object.freeze({ ids: Object.freeze(uniqueIds), inputCount: uniqueIds.length, collapsedCount: 0 });
  }
  const selected = [];
  const seenStates = new Set();
  for (const id of uniqueIds) {
    const state = index.byMemoryId.get(id);
    if (!state) fail('content_state_mapping_missing');
    if (!state.rankEligible || seenStates.has(state.stateKey)) continue;
    const representativeId = index.representativeByState.get(state.stateKey);
    if (!representativeId) fail('content_state_projection_invalid');
    seenStates.add(state.stateKey);
    selected.push(representativeId);
  }
  return Object.freeze({
    ids: Object.freeze(selected),
    inputCount: uniqueIds.length,
    collapsedCount: uniqueIds.length - selected.length,
  });
}

/**
 * Fuse all native retrieval gears. The graph-family gear may add already-
 * admitted discoveries, but it cannot remove a baseline candidate or bypass
 * the later disclosure owners. `magmaGear` remains a research-only input alias
 * for retained historical evaluators; production uses `graphFamilyGear`.
 */
export function fuseNativeRetrievalGears({
  admittedMemories,
  graphFamilyGear = null,
  magmaGear = null,
  temporalBias = false,
  rrfK = RRF_K,
  contentStateProjection = null,
  contentStateGears = [],
  fusionPhase = NATIVE_RETRIEVAL_FUSION_CONTRACT.pure_evaluation_phase,
  requireGraphFamilyContract = false,
} = {}) {
  if (!Array.isArray(admittedMemories)) {
    fail('admitted_memories_required');
  }
  const offset = Number(rrfK);
  if (!Number.isFinite(offset) || offset < 1) fail('rrf_k_invalid');
  const normalizedPhase = normalizeFusionPhase(fusionPhase);
  if (graphFamilyGear && magmaGear) fail('graph_family_legacy_alias_conflict');
  const outerGraphFamilyGear = graphFamilyGear || magmaGear || null;
  const graphFamilyContract = verifyGraphFamilyContract(
    outerGraphFamilyGear,
    requireGraphFamilyContract,
  );

  const baselineById = new Map();
  for (const memory of admittedMemories) {
    const id = memoryId(memory);
    if (!id || !memory?.provenance_proof) fail('unadmitted_baseline_candidate');
    if (!baselineById.has(id)) baselineById.set(id, memory);
  }
  const baselineIds = [...baselineById.keys()];

  const candidateById = new Map(baselineById);
  for (const memory of Array.isArray(outerGraphFamilyGear?.discovered_memories)
    ? outerGraphFamilyGear.discovered_memories : []) {
    const id = memoryId(memory);
    if (!id || !memory?.provenance_proof) fail('unadmitted_graph_family_discovery');
    if (!candidateById.has(id)) candidateById.set(id, memory);
  }
  const candidates = [...candidateById.values()];
  const stateIndex = contentStateIndex(contentStateProjection, contentStateGears, candidateById);

  const channels = [];
  const addChannel = (gear, ids) => {
    if (!Object.hasOwn(GEAR_WEIGHTS, gear)) fail('unknown_gear');
    const eligibleIds = ids.filter((raw) => candidateById.has(String(raw || '').trim().toLowerCase()));
    const collapsed = collapseChannelByContentState(gear, eligibleIds, stateIndex);
    if (collapsed.ids.length) channels.push(Object.freeze({
      gear,
      weight: GEAR_WEIGHTS[gear],
      ids: collapsed.ids,
      input_count: collapsed.inputCount,
      content_state_deduplicated: stateIndex.gears.has(gear),
      collapsed_occurrence_count: collapsed.collapsedCount,
    }));
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
    qmdScore,
    'desc',
    (memory) => Number(qmdScore(memory)) > 0,
  ));
  addChannel('hyde', rankedBy(
    candidates,
    hydeScore,
    'desc',
    (memory) => Number(hydeScore(memory)) > 0,
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
  const graphFamilyRankIds = normalizeGraphFamilyRanks(outerGraphFamilyGear);
  addChannel('graph_family', graphFamilyRankIds);

  if (temporalBias) {
    const temporalIds = candidates
      .map((memory, index) => ({ id: memoryId(memory), timestamp: Date.parse(memory?.created_at || ''), index }))
      .filter((entry) => entry.id && Number.isFinite(entry.timestamp))
      .sort((left, right) => right.timestamp - left.timestamp || left.id.localeCompare(right.id) || left.index - right.index)
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
      || left.id.localeCompare(right.id)
      || left.originalIndex - right.originalIndex);
  const maximumScore = fused[0]?.score || 1;
  const ordered = Object.freeze(fused.map((entry, index) => Object.freeze({
    ...candidateById.get(entry.id),
    native_fusion_rank: index + 1,
    native_fusion_score: Number((entry.score / maximumScore).toFixed(6)),
    native_fusion_rrf_score: Number(entry.score.toFixed(12)),
    native_fusion_gears: Object.freeze([...(gearsById.get(entry.id) || [])]),
  })));

  const selectedIds = ordered.map((memory) => memoryId(memory));
  const selectedIdSet = new Set(selectedIds);
  if (baselineIds.some((id) => !selectedIdSet.has(id))) fail('baseline_candidate_removed');

  const decisionBody = {
    schema: NATIVE_RETRIEVAL_FUSION_CONTRACT.schema,
    equation: NATIVE_RETRIEVAL_FUSION_CONTRACT.equation,
    fusion_phase: normalizedPhase,
    final_production_fusion:
      normalizedPhase === NATIVE_RETRIEVAL_FUSION_CONTRACT.final_production_phase,
    rrf_k: offset,
    baseline_count: baselineIds.length,
    graph_family_discovery_count: candidateById.size - baselineById.size,
    graph_family_input_rank_count: Array.isArray(outerGraphFamilyGear?.ranks)
      ? outerGraphFamilyGear.ranks.length : 0,
    graph_family_normalized_rank_count: graphFamilyRankIds.length,
    graph_family_admitted_rank_count:
      channels.find((channel) => channel.gear === 'graph_family')?.ids.length || 0,
    graph_family_channel_key: NATIVE_RETRIEVAL_FUSION_CONTRACT.graph_family_channel_key,
    graph_family_contract_verified: graphFamilyContract.verified,
    graph_family_outer_channel_count: graphFamilyContract.outerChannelCount,
    graph_family_subgear_count: graphFamilyContract.subgearCount,
    graph_family_decision_sha256: graphFamilyContract.decisionSha256,
    fused_count: ordered.length,
    candidate_set_monotone: true,
    baseline_candidate_set_preserved: baselineIds.every((id) => selectedIdSet.has(id)),
    channels: channels.map((channel) => ({ gear: channel.gear, weight: channel.weight, count: channel.ids.length })),
    content_state_projection_decision_sha256: stateIndex.decisionSha256,
    content_state_gears: Object.freeze([...stateIndex.gears].sort()),
    duplicate_occurrence_votes_rejected: channels.reduce(
      (sum, channel) => sum + Number(channel.collapsed_occurrence_count || 0), 0,
    ),
    channel_state_accounting: channels.map((channel) => ({
      gear: channel.gear,
      input_count: channel.input_count,
      output_count: channel.ids.length,
      content_state_deduplicated: channel.content_state_deduplicated,
      collapsed_occurrence_count: channel.collapsed_occurrence_count,
    })),
    channel_commitment_sha256: channelCommitment(channels),
    selected_memory_ids: selectedIds,
    canonical_memory_mutated: false,
    retention_changed: false,
    disclosure_authority: false,
  };
  const decisionSha256 = channelCommitment(decisionBody);

  return Object.freeze({
    memories: ordered,
    decision: Object.freeze({ ...decisionBody, decision_sha256: decisionSha256 }),
  });
}

/**
 * Reconstruct per-channel rank evidence for retained, source-bound experiments.
 * This pure export has no canonical caller and is intentionally separate from
 * fuseNativeRetrievalGears so experiment instrumentation cannot add work to the
 * production recall path or change its decision commitment.
 */
export function deriveNativeRetrievalGearEvidence({
  admittedMemories,
  graphFamilyGear = null,
  magmaGear = null,
  temporalBias = false,
  rrfK = RRF_K,
  contentStateProjection = null,
  contentStateGears = [],
} = {}) {
  if (!Array.isArray(admittedMemories)) fail('admitted_memories_required');
  const offset = Number(rrfK);
  if (!Number.isFinite(offset) || offset < 1) fail('rrf_k_invalid');
  if (graphFamilyGear && magmaGear) fail('graph_family_legacy_alias_conflict');
  const outerGraphFamilyGear = graphFamilyGear || magmaGear || null;

  const candidateById = new Map();
  for (const memory of admittedMemories) {
    const id = memoryId(memory);
    if (!id || !memory?.provenance_proof) fail('unadmitted_baseline_candidate');
    if (!candidateById.has(id)) candidateById.set(id, memory);
  }
  const baselineCount = candidateById.size;
  for (const memory of Array.isArray(outerGraphFamilyGear?.discovered_memories)
    ? outerGraphFamilyGear.discovered_memories
    : []) {
    const id = memoryId(memory);
    if (!id || !memory?.provenance_proof) fail('unadmitted_graph_family_discovery');
    if (!candidateById.has(id)) candidateById.set(id, memory);
  }
  const candidates = [...candidateById.values()];
  const stateIndex = contentStateIndex(contentStateProjection, contentStateGears, candidateById);
  const channelRows = new Map();
  const productionChannels = [];

  const record = (gear, producer) => {
    const startedAt = performance.now();
    const proposed = producer().filter(
      (raw) => candidateById.has(String(raw || '').trim().toLowerCase()),
    );
    const collapsed = collapseChannelByContentState(gear, proposed, stateIndex);
    const ids = collapsed.ids;
    channelRows.set(gear, Object.freeze({
      ids,
      input_count: collapsed.inputCount,
      content_state_deduplicated: stateIndex.gears.has(gear),
      collapsed_occurrence_count: collapsed.collapsedCount,
      runtime_ms: Number((performance.now() - startedAt).toFixed(6)),
    }));
    if (ids.length) {
      productionChannels.push(Object.freeze({
        gear,
        weight: GEAR_WEIGHTS[gear],
        ids,
        input_count: collapsed.inputCount,
        content_state_deduplicated: stateIndex.gears.has(gear),
        collapsed_occurrence_count: collapsed.collapsedCount,
      }));
    }
  };

  record('vector', () => rankedBy(candidates, (memory) => finiteNumber(memory?.raw_distance), 'asc'));
  record('bm25', () => rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.bm25_rank ?? memory?.bm25_score),
    'desc',
    (memory) => Number(memory?.bm25_rank ?? memory?.bm25_score) > 0,
  ));
  record('lexical', () => rankedBy(
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
  record('quim', () => rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.rerank_score),
    'desc',
    (memory) => memory?.retrieval_source === 'quim_lookup' && Number(memory?.rerank_score) > 0,
  ));
  record('qmd', () => rankedBy(
    candidates,
    qmdScore,
    'desc',
    (memory) => Number(qmdScore(memory)) > 0,
  ));
  record('hyde', () => rankedBy(
    candidates,
    hydeScore,
    'desc',
    (memory) => Number(hydeScore(memory)) > 0,
  ));
  record('entity', () => rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.entity_hits),
    'desc',
    (memory) => Number(memory?.entity_hits) > 0,
  ));
  record('concept_ppr', () => rankedBy(
    candidates,
    (memory) => finiteNumber(memory?.ppr_score),
    'desc',
    (memory) => Number(memory?.ppr_score) > 0,
  ));
  record('graph_family', () => normalizeGraphFamilyRanks(outerGraphFamilyGear));
  record('temporal', () => temporalBias
    ? candidates
      .map((memory, index) => ({ id: memoryId(memory), timestamp: Date.parse(memory?.created_at || ''), index }))
      .filter((entry) => entry.id && Number.isFinite(entry.timestamp))
      .sort((left, right) => right.timestamp - left.timestamp
        || left.id.localeCompare(right.id)
        || left.index - right.index)
      .map((entry) => entry.id)
    : []);

  const channels = NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.map((gear) => {
    const row = channelRows.get(gear) || Object.freeze({ ids: Object.freeze([]), runtime_ms: 0 });
    return Object.freeze({
      gear,
      weight: GEAR_WEIGHTS[gear],
      status: row.ids.length ? 'executed_nonempty' : 'executed_empty',
      count: row.ids.length,
      input_count: row.input_count ?? row.ids.length,
      content_state_deduplicated: row.content_state_deduplicated ?? false,
      collapsed_occurrence_count: row.collapsed_occurrence_count ?? 0,
      ids: row.ids,
      rank_commitment_sha256: channelCommitment(row.ids),
      runtime_ms: row.runtime_ms,
      failure_code: null,
    });
  });
  const body = {
    schema: 'hom-aimos/native-retrieval-channel-evidence/v1',
    fusion_phase: NATIVE_RETRIEVAL_FUSION_CONTRACT.pure_evaluation_phase,
    tie_break_rule: NATIVE_RETRIEVAL_FUSION_CONTRACT.tie_break_rule,
    rrf_k: offset,
    baseline_count: baselineCount,
    candidate_count: candidateById.size,
    channels,
    channel_commitment_sha256: channelCommitment(productionChannels),
    content_state_projection_decision_sha256: stateIndex.decisionSha256,
    content_state_gears: Object.freeze([...stateIndex.gears].sort()),
    duplicate_occurrence_votes_rejected: channels.reduce(
      (sum, channel) => sum + Number(channel.collapsed_occurrence_count || 0), 0,
    ),
    disclosure_authority: false,
    persistence_authority: false,
    mutation_authority: false,
    environment_authority: false,
  };
  const commitmentBody = {
    ...body,
    channels: channels.map(({ runtime_ms: _runtimeMs, ...channel }) => channel),
  };
  return Object.freeze({
    ...body,
    evidence_sha256: channelCommitment(commitmentBody),
  });
}
