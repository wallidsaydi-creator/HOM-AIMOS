/**
 * Dormant AIMOS Cue-Tag-Content reconstruction kernel informed by:
 * - Ji, Li, and Hooi, "Memory is Reconstructed, Not Retrieved: Graph Memory
 *   for LLM Agents" (ICML 2026).
 *
 * Paper-faithful pure operators:
 * - heterogeneous graph M=(C,V,R), with R subset C x G x V
 * - phi_{c->g}(c) = {g | (c,g,.) in R}
 * - phi_{(c,g)->v}(c,g) = {v | (c,g,v) in R}
 * - phi_{v->(c,g)}(v) = {(c,g) | (c,g,v) in R}
 * - monotone reconstruction state S(t)=(Z(t),H(t))
 *
 * Deliberate AIMOS adaptations and limits:
 * - cues and tags are deterministic lexical projections, not the paper's LLM
 *   distillation functions;
 * - action selection, routing, and stopping are deterministic diagnostics,
 *   not the paper's f_select, f_route, or model answer-sufficiency policy;
 * - the graph is transient and restricted to the admitted candidate window;
 * - this module has no database, signing, persistence, server, or model access.
 */

export const RECONSTRUCTED_GRAPH_CONSTANTS = Object.freeze({
  max_steps: 3,
  max_states: 240,
  max_cues_per_content: 8,
  max_tags_per_content: 12,
  top_seed_cues: 8,
  route_cap_per_step: 18,
  lexical_coverage_sufficiency_threshold: 0.8,
});

export const RECONSTRUCTED_GRAPH_ACTIONS = Object.freeze({
  cue_to_tag: 'cue_to_tag',
  cue_tag_to_content: 'cue_tag_to_content',
  content_to_cue_tag: 'content_to_cue_tag',
});

export const RECONSTRUCTED_GRAPH_GUARDRAILS = Object.freeze({
  dormant: true,
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  suppresses_memory: false,
  uses_environment_authority: false,
  accesses_database: false,
  persists_graph: false,
  uses_model_policy: false,
  injects_answers: false,
  candidate_window_only: true,
  routing_prunes_transient_paths_only: true,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'and', 'before', 'being',
  'between', 'could', 'current', 'during', 'for', 'from', 'had', 'has',
  'have', 'into', 'many', 'more', 'most', 'that', 'the', 'their', 'there',
  'these', 'this', 'those', 'through', 'was', 'were', 'what', 'when',
  'where', 'which', 'while', 'with', 'would',
]);

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.trunc(parsed)));
}

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokens(value = '') {
  return normalizeText(value)
    .split(/\s+/)
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function uniqueSorted(values = []) {
  return [...new Set(values.filter(Boolean).map(String))].sort((a, b) => a.localeCompare(b));
}

function lexicalSimilarity(left = '', right = '') {
  const a = new Set(tokens(left));
  const b = new Set(tokens(right));
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const token of a) if (b.has(token)) hits += 1;
  return hits / Math.sqrt(a.size * b.size);
}

function cueTokens(text = '', maximum = RECONSTRUCTED_GRAPH_CONSTANTS.max_cues_per_content) {
  const named = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)]
    .map((match) => normalizeText(match[0]));
  const salient = tokens(text).filter((token) => token.length >= 5);
  return uniqueSorted([...named, ...salient]).slice(0, maximum);
}

function tagsForText(text = '') {
  const patterns = [
    ['time', /\b(after|before|between|last|current|currently|now|when|days?|months?|\d{4})\b/i],
    ['person', /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/],
    ['preference', /\b(like|prefer|favorite|enjoy|recommend|dislike)\b/i],
    ['possession', /\b(own|have|bought|purchased|currently have)\b/i],
    ['travel', /\b(airline|airport|flight|flew|trip|travel)\b/i],
    ['event', /\b(event|joined|attended|visited|walk|cleanup)\b/i],
    ['identity', /\b(member|community|identity|considered|who)\b/i],
    ['procedure', /\b(step|strategy|workflow|tool|action|procedure)\b/i],
  ];
  return uniqueSorted([
    ...patterns.filter(([, pattern]) => pattern.test(text)).map(([tag]) => tag),
    ...tokens(text).slice(0, 4).map((token) => `term:${token}`),
  ]).slice(0, RECONSTRUCTED_GRAPH_CONSTANTS.max_tags_per_content);
}

function normalizeStates(states = []) {
  if (!Array.isArray(states)) return [];
  const seen = new Set();
  const normalized = [];
  for (const state of states) {
    if (!state || typeof state !== 'object' || state.id === undefined || state.id === null) continue;
    const stateId = String(state.id).trim();
    const text = String(state.text ?? state.memory?.value ?? '').trim();
    if (!stateId || !text || seen.has(stateId)) continue;
    seen.add(stateId);
    normalized.push({ state_id: stateId, text });
    if (normalized.length >= RECONSTRUCTED_GRAPH_CONSTANTS.max_states) break;
  }
  return normalized;
}

function indexValues(map) {
  return Object.fromEntries(
    [...map.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, values]) => [key, uniqueSorted(values)]),
  );
}

function cueTagKey(cueId, tagId) {
  return `${cueId}\u0000${tagId}`;
}

export function buildRelationIndexes(relations = []) {
  const tagsByCue = new Map();
  const contentsByCueTag = new Map();
  const cueTagsByContent = new Map();

  for (const relation of Array.isArray(relations) ? relations : []) {
    if (!relation?.c || !relation?.g || !relation?.v) continue;
    if (!tagsByCue.has(relation.c)) tagsByCue.set(relation.c, []);
    tagsByCue.get(relation.c).push(relation.g);

    const pairKey = cueTagKey(relation.c, relation.g);
    if (!contentsByCueTag.has(pairKey)) contentsByCueTag.set(pairKey, []);
    contentsByCueTag.get(pairKey).push(relation.v);

    if (!cueTagsByContent.has(relation.v)) cueTagsByContent.set(relation.v, []);
    cueTagsByContent.get(relation.v).push(pairKey);
  }

  return {
    tags_by_cue: indexValues(tagsByCue),
    contents_by_cue_tag: indexValues(contentsByCueTag),
    cue_tags_by_content: indexValues(cueTagsByContent),
  };
}

export function buildCueTagContentGraph(states = []) {
  const C = new Map();
  const G = new Map();
  const V = new Map();
  const relations = new Map();

  for (const state of normalizeStates(states)) {
    const contentId = `v:${state.state_id}`;
    V.set(contentId, {
      id: contentId,
      state_id: state.state_id,
      text: state.text,
      layer: /\b(prefer|usually|fact|summary|profile)\b/i.test(state.text) ? 'semantic' : 'episodic',
    });

    const cues = cueTokens(state.text);
    const tags = tagsForText(state.text);
    for (const cue of cues) {
      const cueId = `c:${cue}`;
      C.set(cueId, { id: cueId, cue });
      for (const tag of tags) {
        const tagId = `g:${tag}`;
        G.set(tagId, { id: tagId, tag });
        const relation = { c: cueId, g: tagId, v: contentId };
        relations.set(`${relation.c}\u0000${relation.g}\u0000${relation.v}`, relation);
      }
    }
  }

  const R = [...relations.values()].sort((left, right) => (
    left.c.localeCompare(right.c)
    || left.g.localeCompare(right.g)
    || left.v.localeCompare(right.v)
  ));
  return {
    C: [...C.values()].sort((left, right) => left.id.localeCompare(right.id)),
    G: [...G.values()].sort((left, right) => left.id.localeCompare(right.id)),
    V: [...V.values()].sort((left, right) => left.id.localeCompare(right.id)),
    R,
    indexes: buildRelationIndexes(R),
    construction: 'deterministic_lexical_aimos_adaptation_not_paper_llm_distillation',
    candidate_window_only: true,
  };
}

function relationIndexes(graph = {}) {
  return graph?.indexes && typeof graph.indexes === 'object'
    ? graph.indexes
    : buildRelationIndexes(graph?.R);
}

export function phiCueToTag(graph = {}, cueIds = []) {
  const indexes = relationIndexes(graph);
  return uniqueSorted(uniqueSorted(cueIds).flatMap((cueId) => indexes.tags_by_cue?.[cueId] || []));
}

export function phiCueTagToContent(graph = {}, cueIds = [], tagIds = []) {
  const cues = uniqueSorted(cueIds);
  const tags = uniqueSorted(tagIds);
  if (!cues.length || !tags.length) return [];
  const indexes = relationIndexes(graph);
  const contents = [];
  for (const cueId of cues) {
    for (const tagId of tags) {
      contents.push(...(indexes.contents_by_cue_tag?.[cueTagKey(cueId, tagId)] || []));
    }
  }
  return uniqueSorted(contents);
}

export function phiContentToCueTag(graph = {}, contentIds = []) {
  const indexes = relationIndexes(graph);
  const pairs = [];
  for (const contentId of uniqueSorted(contentIds)) {
    for (const pairKey of indexes.cue_tags_by_content?.[contentId] || []) {
      const [cue, tag] = pairKey.split('\u0000');
      if (cue && tag) pairs.push({ c: cue, g: tag });
    }
  }
  return [...new Map(pairs.map((pair) => [`${pair.c}\u0000${pair.g}`, pair])).values()]
    .sort((left, right) => left.c.localeCompare(right.c) || left.g.localeCompare(right.g));
}

function seedCues(graph = {}, queryText = '') {
  const qCues = cueTokens(queryText, RECONSTRUCTED_GRAPH_CONSTANTS.top_seed_cues);
  return (Array.isArray(graph.C) ? graph.C : [])
    .map((cue) => ({
      id: cue.id,
      score: Math.max(qCues.includes(cue.cue) ? 1 : 0, lexicalSimilarity(queryText, cue.cue)),
    }))
    .filter((row) => row.score > 0)
    .sort((left, right) => right.score - left.score || left.id.localeCompare(right.id))
    .slice(0, RECONSTRUCTED_GRAPH_CONSTANTS.top_seed_cues)
    .map((row) => row.id);
}

function nodeLabels(graph = {}) {
  return new Map([
    ...(Array.isArray(graph.C) ? graph.C : []).map((node) => [node.id, node.cue]),
    ...(Array.isArray(graph.G) ? graph.G : []).map((node) => [node.id, node.tag]),
    ...(Array.isArray(graph.V) ? graph.V : []).map((node) => [node.id, node.text]),
  ]);
}

export function selectDeterministicReconstructionActions(activeIds = []) {
  const active = new Set(uniqueSorted(activeIds));
  const hasCue = [...active].some((id) => id.startsWith('c:'));
  const hasTag = [...active].some((id) => id.startsWith('g:'));
  const hasContent = [...active].some((id) => id.startsWith('v:'));
  return [
    hasCue ? RECONSTRUCTED_GRAPH_ACTIONS.cue_to_tag : null,
    hasCue && hasTag ? RECONSTRUCTED_GRAPH_ACTIONS.cue_tag_to_content : null,
    hasContent ? RECONSTRUCTED_GRAPH_ACTIONS.content_to_cue_tag : null,
  ].filter(Boolean);
}

export function traverseReconstructionActions(graph = {}, activeIds = [], actions = []) {
  const active = uniqueSorted(activeIds);
  const cues = active.filter((id) => id.startsWith('c:'));
  const tags = active.filter((id) => id.startsWith('g:'));
  const contents = active.filter((id) => id.startsWith('v:'));
  const candidates = [];

  for (const action of uniqueSorted(actions)) {
    if (action === RECONSTRUCTED_GRAPH_ACTIONS.cue_to_tag) {
      candidates.push(...phiCueToTag(graph, cues));
    } else if (action === RECONSTRUCTED_GRAPH_ACTIONS.cue_tag_to_content) {
      candidates.push(...phiCueTagToContent(graph, cues, tags));
    } else if (action === RECONSTRUCTED_GRAPH_ACTIONS.content_to_cue_tag) {
      for (const pair of phiContentToCueTag(graph, contents)) candidates.push(pair.c, pair.g);
    }
  }
  return uniqueSorted(candidates);
}

export function routeLexicalReconstructionCandidates(graph = {}, queryText = '', candidateIds = []) {
  const labels = nodeLabels(graph);
  return uniqueSorted(candidateIds)
    .filter((id) => labels.has(id))
    .map((id) => ({
      id,
      score: clamp01(lexicalSimilarity(queryText, labels.get(id))),
      text: labels.get(id),
      policy: 'deterministic_lexical_aimos_adaptation_not_paper_f_route',
    }))
    .sort((left, right) => right.score - left.score || left.id.localeCompare(right.id))
    .slice(0, RECONSTRUCTED_GRAPH_CONSTANTS.route_cap_per_step);
}

export function lexicalCoverageSufficiency(queryText = '', history = []) {
  const queryTokens = new Set(tokens(queryText));
  if (!queryTokens.size) {
    return { sufficient: false, coverage: 0, covered_tokens: 0, query_tokens: 0 };
  }
  const historyTokens = new Set((Array.isArray(history) ? history : []).flatMap((row) => tokens(row?.text ?? row)));
  let covered = 0;
  for (const token of queryTokens) if (historyTokens.has(token)) covered += 1;
  const coverage = covered / queryTokens.size;
  return {
    sufficient: coverage >= RECONSTRUCTED_GRAPH_CONSTANTS.lexical_coverage_sufficiency_threshold,
    coverage,
    covered_tokens: covered,
    query_tokens: queryTokens.size,
  };
}

export function reconstructMemoryState({
  graph = {},
  queryText = '',
  steps = RECONSTRUCTED_GRAPH_CONSTANTS.max_steps,
} = {}) {
  const stepLimit = boundedInteger(
    steps,
    RECONSTRUCTED_GRAPH_CONSTANTS.max_steps,
    0,
    RECONSTRUCTED_GRAPH_CONSTANTS.max_steps,
  );
  const Z = new Set(seedCues(graph, queryText));
  const H = [];
  const historyIds = new Set();
  const activationCounts = new Map();
  const trace = [];
  let terminationReason = Z.size ? 'max_steps' : 'no_seed_cues';

  for (let step = 0; step < stepLimit && Z.size; step += 1) {
    const activeBefore = uniqueSorted([...Z]);
    const actions = selectDeterministicReconstructionActions(activeBefore);
    const generated = traverseReconstructionActions(graph, activeBefore, actions);
    for (const id of generated.filter((candidateId) => candidateId.startsWith('v:'))) {
      activationCounts.set(id, (activationCounts.get(id) || 0) + 1);
    }
    const repeated = generated.filter((id) => Z.has(id));
    const novelCandidates = generated.filter((id) => !Z.has(id));
    const routed = routeLexicalReconstructionCandidates(graph, queryText, novelCandidates);
    const newHistoryIds = [];

    for (const row of routed) {
      Z.add(row.id);
      if (row.id.startsWith('v:') && !historyIds.has(row.id)) {
        historyIds.add(row.id);
        H.push({ ...row, activated_step: step + 1 });
        newHistoryIds.push(row.id);
      }
    }

    const sufficiency = lexicalCoverageSufficiency(queryText, H);
    const noProgress = routed.length === 0;
    const stagnation = generated.length > 0 && novelCandidates.length === 0;
    if (!actions.length) terminationReason = 'no_actions';
    else if (!generated.length) terminationReason = 'no_candidates';
    else if (stagnation) terminationReason = 'stagnation';
    else if (noProgress) terminationReason = 'routing_empty';
    else if (sufficiency.sufficient) terminationReason = 'lexical_coverage_sufficient';
    else terminationReason = step + 1 >= stepLimit ? 'max_steps' : 'continue';

    trace.push({
      step: step + 1,
      policy: 'deterministic_lexical_aimos_adaptation_not_paper_llm_policy',
      actions,
      active_before: activeBefore.length,
      generated_count: generated.length,
      repeated_activation_count: repeated.length,
      novel_candidate_count: novelCandidates.length,
      routed_count: routed.length,
      active_after: Z.size,
      new_history_ids: newHistoryIds,
      history_size: H.length,
      lexical_coverage: Number(sufficiency.coverage.toFixed(6)),
      no_progress: noProgress,
      stagnation_detected: stagnation,
      termination_reason: terminationReason,
    });

    if (terminationReason !== 'continue' && terminationReason !== 'max_steps') break;
  }

  return {
    Z: uniqueSorted([...Z]),
    H,
    activation_counts: Object.fromEntries(
      [...activationCounts.entries()].sort(([left], [right]) => left.localeCompare(right)),
    ),
    trace,
    termination_reason: terminationReason,
    policy: 'deterministic_lexical_aimos_adaptation_not_paper_f_select_or_f_route',
    candidate_window_only: true,
  };
}

export function reconstructedGraphMemoryScores({ queryText = '', states = [] } = {}) {
  const graph = buildCueTagContentGraph(states);
  const reconstruction = reconstructMemoryState({ graph, queryText });
  const activeValues = new Set(reconstruction.Z.filter((id) => id.startsWith('v:')));
  const historyById = new Map(reconstruction.H.map((row) => [row.id, row]));
  const relationCountByValue = new Map();
  for (const relation of graph.R) {
    relationCountByValue.set(relation.v, (relationCountByValue.get(relation.v) || 0) + 1);
  }
  const maxDegree = Math.max(1, ...relationCountByValue.values());

  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const content of graph.V) {
    const history = historyById.get(content.id);
    const direct = lexicalSimilarity(queryText, content.text);
    const reconstructed = history?.score || 0;
    const score = clamp01(Math.max(direct, reconstructed));
    scoreById.set(content.state_id, score);
    diagnosticsById.set(content.state_id, {
      active: activeValues.has(content.id),
      direct_similarity: Number(direct.toFixed(6)),
      reconstructed_score: Number(reconstructed.toFixed(6)),
      activation_count: reconstruction.activation_counts[content.id] || 0,
      activated_step: history?.activated_step ?? null,
      relation_degree: Number(((relationCountByValue.get(content.id) || 0) / maxDegree).toFixed(6)),
      layer: content.layer,
    });
  }

  return {
    scoreById,
    diagnosticsById,
    graph_stats: {
      cues: graph.C.length,
      tags: graph.G.length,
      contents: graph.V.length,
      relations: graph.R.length,
    },
    reconstruction_steps: reconstruction.trace,
    termination_reason: reconstruction.termination_reason,
    active_count: reconstruction.Z.length,
    reconstructed_context_count: reconstruction.H.length,
    unique_reconstructed_context_count: new Set(reconstruction.H.map((row) => row.id)).size,
    policy: reconstruction.policy,
    guardrails: RECONSTRUCTED_GRAPH_GUARDRAILS,
    exact_formulas: [
      'R subset C x G x V',
      'phi_c_to_g(c)={g | (c,g,.) in R}',
      'phi_cg_to_v(c,g)={v | (c,g,v) in R}',
      'phi_v_to_cg(v)={(c,g) | (c,g,v) in R}',
      'S(t)=(Z(t),H(t)); Z and H are set-monotone',
    ],
    unimplemented_paper_components: [
      'LLM cue and tag distillation',
      'LLM action selection f_select',
      'LLM routing f_route',
      'model answer-sufficiency decision',
      'persistent multi-granular graph access',
    ],
  };
}
