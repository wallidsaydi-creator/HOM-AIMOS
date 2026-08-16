/**
 * Dormant Mnemis-inspired dual-route hierarchical-graph kernel based on:
 * - Mnemis: Dual-Route Retrieval on Hierarchical Graphs for Long-Term LLM Memory
 *
 * Paper-aligned components implemented here:
 * - transient Episodes, Entities, Edges, and Episodic Edges
 * - exact cosine over supplied vectors and corpus-aware BM25 over text
 * - object-class-separated reciprocal rank fusion (RRF)
 * - multi-level Category nodes and parent/child Category Edges
 * - many-to-many entity/category membership and compression diagnostics
 * - unordered System-2 selection kept separate from ranked System-1 results
 *
 * Explicit AIMOS adaptations:
 * - entity extraction and hierarchy labels are deterministic lexical projections;
 *   they are not the paper's model extraction or category-generation stages
 * - System-2 traversal is a deterministic positive-relevance policy; it is not
 *   the paper's model-guided node-selection and early-stopping policy
 * - the returned score is a bounded System-1 evidence diagnostic because the
 *   paper's final model reranker is intentionally not fabricated
 *
 * The kernel only inspects an already-admitted candidate window. It performs no
 * database access, persistence, server work, canonical mutation, deletion,
 * pruning, decay, environment-owned configuration, or live recall wiring.
 */

export const MNEMIS_CONSTANTS = Object.freeze({
  rrf_k: 60,
  system1_top_k: 10,
  min_category_children: 2,
  max_hierarchy_layers: 4,
  max_states: 256,
  max_entities_per_episode: 12,
});

export const MNEMIS_GUARDRAILS = Object.freeze({
  dormant: true,
  candidate_window_only: true,
  uses_model_policy: false,
  uses_environment_authority: false,
  accesses_database: false,
  persists_graph: false,
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  query_rewrite: false,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'from', 'have', 'many', 'more', 'most',
  'that', 'their', 'there', 'these', 'this', 'those', 'through', 'what',
  'when', 'where', 'which', 'while', 'with', 'would',
]);

function clamp01(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(1, number));
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
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

function unique(values = []) {
  return [...new Set(asArray(values).filter(Boolean))];
}

function dateIso(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function stateText(state = {}) {
  return String(state?.text || state?.memory?.value || '').trim();
}

function finiteVector(value) {
  return Array.isArray(value)
    && value.length > 0
    && value.every((entry) => Number.isFinite(Number(entry)))
    ? value.map(Number)
    : null;
}

export function cosineSimilarityMnemis(left, right) {
  const a = finiteVector(left);
  const b = finiteVector(right);
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let index = 0; index < a.length; index += 1) {
    dot += a[index] * b[index];
    normA += a[index] ** 2;
    normB += b[index] ** 2;
  }
  if (normA === 0 || normB === 0) return 0;
  return Math.max(-1, Math.min(1, dot / Math.sqrt(normA * normB)));
}

function tokenFrequency(value = '') {
  const frequency = new Map();
  for (const token of tokens(value)) frequency.set(token, (frequency.get(token) || 0) + 1);
  return frequency;
}

export function bm25ScoresMnemis(queryText, documents, { k1 = 1.2, b = 0.75 } = {}) {
  const rows = asArray(documents)
    .map((document) => ({ id: String(document?.id || ''), text: String(document?.text || '') }))
    .filter((document) => document.id && document.text);
  const queryTerms = unique(tokens(queryText));
  if (!rows.length || !queryTerms.length) return new Map();

  const frequencies = rows.map((document) => tokenFrequency(document.text));
  const lengths = rows.map((document) => tokens(document.text).length);
  const averageLength = Math.max(1, lengths.reduce((sum, length) => sum + length, 0) / rows.length);
  const documentFrequency = new Map();
  for (const term of queryTerms) {
    documentFrequency.set(term, frequencies.reduce((count, frequency) => count + (frequency.has(term) ? 1 : 0), 0));
  }

  const scores = new Map();
  rows.forEach((document, index) => {
    let score = 0;
    for (const term of queryTerms) {
      const frequency = frequencies[index].get(term) || 0;
      if (!frequency) continue;
      const df = documentFrequency.get(term) || 0;
      const idf = Math.log(1 + ((rows.length - df + 0.5) / (df + 0.5)));
      const denominator = frequency + (k1 * (1 - b + (b * lengths[index] / averageLength)));
      score += idf * ((frequency * (k1 + 1)) / denominator);
    }
    scores.set(document.id, score);
  });
  return scores;
}

function lexicalRelevance(queryText, text) {
  const queryTokens = new Set(tokens(queryText));
  const textTokens = new Set(tokens(text));
  if (!queryTokens.size || !textTokens.size) return 0;
  let overlap = 0;
  for (const token of queryTokens) if (textTokens.has(token)) overlap += 1;
  return overlap / Math.sqrt(queryTokens.size * textTokens.size);
}

function normalizeStates(states, maximumStates = MNEMIS_CONSTANTS.max_states) {
  const maximum = Math.max(
    1,
    Math.min(2048, Math.floor(Number(maximumStates) || MNEMIS_CONSTANTS.max_states)),
  );
  const rows = [];
  const seen = new Set();
  for (const state of asArray(states)) {
    const id = String(state?.id || '').trim();
    const text = stateText(state);
    if (!id || !text || seen.has(id)) continue;
    seen.add(id);
    rows.push(state);
    if (rows.length >= maximum) break;
  }
  return rows;
}

function salientTerms(text = '', maximum = MNEMIS_CONSTANTS.max_entities_per_episode) {
  const named = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)]
    .map((match) => normalizeText(match[0]));
  const lexical = tokens(text).filter((token) => token.length >= 5);
  return unique([...named, ...lexical]).slice(0, maximum);
}

function semanticCategories(text = '') {
  const patterns = [
    ['temporal', /\b(after|before|between|last|first|current|currently|now|days?|months?|years?)\b/i],
    ['identity', /\b(member|community|person|who|called|named|identity|considered)\b/i],
    ['preference', /\b(prefer|favorite|like|enjoy|recommend|dislike)\b/i],
    ['possession', /\b(own|have|bought|purchased|currently have|how many)\b/i],
    ['travel', /\b(airline|airport|flight|flew|hotel|trip|travel)\b/i],
    ['event', /\b(event|attended|joined|visited|walk|cleanup|concert|launch)\b/i],
    ['procedure', /\b(step|strategy|workflow|tool|procedure|plan|review)\b/i],
    ['security', /\b(security|encrypt|credential|attack|poison|tamper|provenance)\b/i],
  ];
  const matched = patterns.filter(([, pattern]) => pattern.test(text)).map(([label]) => label);
  return matched.length ? matched : [`topic:${tokens(text)[0] || 'memory'}`];
}

function parentCategory(label) {
  if (['temporal', 'travel', 'event'].includes(label)) return 'experience';
  if (['identity', 'preference', 'possession'].includes(label)) return 'personal';
  if (['procedure', 'security'].includes(label)) return 'knowledge';
  return 'general';
}

function averageVectorsMnemis(vectors = []) {
  const finite = vectors.map(finiteVector).filter(Boolean);
  if (!finite.length) return null;
  const dimension = finite[0].length;
  const aligned = finite.filter((vector) => vector.length === dimension);
  if (!aligned.length) return null;
  return Array.from({ length: dimension }, (_, index) => (
    aligned.reduce((sum, vector) => sum + vector[index], 0) / aligned.length
  ));
}

export function buildMnemisBaseGraph(
  states = [],
  maximumStates = MNEMIS_CONSTANTS.max_states,
) {
  const episodes = [];
  const entityMap = new Map();
  const edgeMap = new Map();
  const episodicEdgeMap = new Map();

  for (const state of normalizeStates(states, maximumStates)) {
    const stateId = String(state.id);
    const text = stateText(state);
    const episodeId = `episode:${stateId}`;
    const categories = semanticCategories(text);
    const episode = {
      id: episodeId,
      state_id: stateId,
      text,
      embedding: finiteVector(state.embedding || state.memory?.embedding),
      valid_at: dateIso(state.memory?.created_at) || dateIso(state.interval?.start),
      categories,
    };
    episodes.push(episode);

    const entityIds = [];
    for (const term of salientTerms(text)) {
      const entityId = `entity:${term}`;
      entityIds.push(entityId);
      const previous = entityMap.get(entityId) || {
        id: entityId,
        name: term,
        summary_fragments: [],
        tags: [],
        episode_idx: [],
        embedding: null,
        embedding_fragments: [],
      };
      previous.summary_fragments.push(text.slice(0, 180));
      previous.tags.push(...categories);
      previous.episode_idx.push(episodeId);
      if (episode.embedding) previous.embedding_fragments.push(episode.embedding);
      entityMap.set(entityId, previous);
      episodicEdgeMap.set(`${entityId}\0${episodeId}`, {
        id: `episodic:${entityId}:${episodeId}`,
        entity_id: entityId,
        episode_id: episodeId,
      });
    }

    for (let leftIndex = 0; leftIndex < entityIds.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < entityIds.length; rightIndex += 1) {
        const pair = [entityIds[leftIndex], entityIds[rightIndex]].sort();
        const key = `${pair[0]}\0${pair[1]}\0${episodeId}`;
        edgeMap.set(key, {
          id: `edge:${pair[0]}:${pair[1]}:${episodeId}`,
          source_entity_id: pair[0],
          target_entity_id: pair[1],
          fact: `${pair[0].slice(7)} and ${pair[1].slice(7)} co-occur in the admitted episode`,
          episode_idx: [episodeId],
          embedding: episode.embedding,
          valid_at: episode.valid_at,
          invalid_at: null,
        });
      }
    }
  }

  const entities = [...entityMap.values()].map((entity) => ({
    id: entity.id,
    name: entity.name,
    summary: unique(entity.summary_fragments).join(' '),
    tags: unique(entity.tags).sort(),
    episode_idx: unique(entity.episode_idx).sort(),
    embedding: averageVectorsMnemis(entity.embedding_fragments),
  }));

  return {
    episodes,
    entities,
    edges: [...edgeMap.values()],
    episodic_edges: [...episodicEdgeMap.values()],
  };
}

function makeCategory(id, label, layer, childIds, searchText, standalone = false) {
  return {
    id,
    label,
    tag: `layer_${layer}`,
    layer,
    child_ids: unique(childIds).sort(),
    search_text: normalizeText(searchText),
    standalone,
  };
}

export function buildMnemisHierarchy(graph = {}, minChildren = MNEMIS_CONSTANTS.min_category_children) {
  const entities = asArray(graph?.entities);
  if (!entities.length) {
    return { levels: [{ layer: 0, nodes: [] }], categories: [], category_edges: [], root_ids: [], terminated_reason: 'no_entities' };
  }
  const minimum = Math.max(2, Math.floor(Number(minChildren) || MNEMIS_CONSTANTS.min_category_children));
  const levels = [{ layer: 0, nodes: entities.map((entity) => ({ ...entity, layer: 0 })) }];
  const categories = [];
  const categoryEdges = [];

  const leafGroups = new Map();
  for (const entity of entities) {
    for (const label of entity.tags?.length ? entity.tags : ['general']) {
      if (!leafGroups.has(label)) leafGroups.set(label, []);
      leafGroups.get(label).push(entity.id);
    }
  }
  const layerOne = [...leafGroups.entries()].map(([label, childIds]) => {
    const children = unique(childIds);
    const childText = entities.filter((entity) => children.includes(entity.id)).map((entity) => `${entity.name} ${entity.summary}`).join(' ');
    return makeCategory(`category:1:${label}`, label, 1, children, `${label} ${childText}`, children.length < minimum);
  }).sort((a, b) => a.id.localeCompare(b.id));
  for (const node of layerOne) {
    categories.push(node);
    for (const childId of node.child_ids) categoryEdges.push({ parent_id: node.id, child_id: childId, parent_layer: 1, child_layer: 0 });
  }
  levels.push({ layer: 1, nodes: layerOne });

  let previous = layerOne;
  if (previous.length > 1 && levels.length < MNEMIS_CONSTANTS.max_hierarchy_layers) {
    const parentGroups = new Map();
    for (const node of previous) {
      const label = parentCategory(node.label);
      if (!parentGroups.has(label)) parentGroups.set(label, []);
      parentGroups.get(label).push(node);
    }
    const layerTwo = [...parentGroups.entries()].map(([label, childNodes]) => makeCategory(
      `category:2:${label}`,
      label,
      2,
      childNodes.map((node) => node.id),
      `${label} ${childNodes.map((node) => node.search_text).join(' ')}`,
      childNodes.length < minimum,
    )).sort((a, b) => a.id.localeCompare(b.id));
    if (layerTwo.length <= previous.length) {
      for (const node of layerTwo) {
        categories.push(node);
        for (const childId of node.child_ids) categoryEdges.push({ parent_id: node.id, child_id: childId, parent_layer: 2, child_layer: 1 });
      }
      levels.push({ layer: 2, nodes: layerTwo });
      previous = layerTwo;
    }
  }

  if (previous.length > 1 && levels.length < MNEMIS_CONSTANTS.max_hierarchy_layers) {
    const root = makeCategory(
      'category:3:memory',
      'memory',
      3,
      previous.map((node) => node.id),
      previous.map((node) => node.search_text).join(' '),
      previous.length < minimum,
    );
    categories.push(root);
    for (const childId of root.child_ids) categoryEdges.push({ parent_id: root.id, child_id: childId, parent_layer: 3, child_layer: 2 });
    levels.push({ layer: 3, nodes: [root] });
    previous = [root];
  }

  return {
    levels,
    categories,
    category_edges: categoryEdges,
    root_ids: previous.map((node) => node.id),
    terminated_reason: levels.length >= MNEMIS_CONSTANTS.max_hierarchy_layers ? 'maximum_layer_limit' : 'single_root_or_no_further_reduction',
  };
}

function rankByScore(rows, cap) {
  return rows
    .filter((row) => Number.isFinite(row.score) && row.score > 0)
    .sort((left, right) => right.score - left.score || left.id.localeCompare(right.id))
    .slice(0, cap);
}

function objectRankLists(rows, queryText, queryEmbedding, textOf, embeddingOf, cap) {
  const bm25 = bm25ScoresMnemis(queryText, rows.map((row) => ({ id: row.id, text: textOf(row) })));
  const lexical = rankByScore(rows.map((row) => ({ id: row.id, row, score: bm25.get(row.id) || 0 })), cap);
  const embedding = rankByScore(rows.map((row) => ({
    id: row.id,
    row,
    score: cosineSimilarityMnemis(queryEmbedding, embeddingOf(row)),
  })), cap);
  return { lexical, embedding };
}

export function reciprocalRankFusionMnemis(rankLists = [], k = MNEMIS_CONSTANTS.rrf_k) {
  const denominatorOffset = Math.max(1, Number.isFinite(Number(k)) ? Number(k) : MNEMIS_CONSTANTS.rrf_k);
  const fused = new Map();
  for (const list of asArray(rankLists)) {
    asArray(list).forEach((item, index) => {
      const id = String(item?.id || item || '');
      if (!id) return;
      const previous = fused.get(id) || { id, score: 0, sources: 0 };
      previous.score += 1 / (denominatorOffset + index + 1);
      previous.sources += 1;
      fused.set(id, previous);
    });
  }
  return [...fused.values()].sort((left, right) => right.score - left.score || left.id.localeCompare(right.id));
}

export function mnemisSystem1(graph = {}, queryText = '', queryEmbedding = null) {
  const episodeLists = objectRankLists(
    asArray(graph?.episodes), queryText, queryEmbedding, (row) => row.text, (row) => row.embedding,
    MNEMIS_CONSTANTS.system1_top_k,
  );
  const entityLists = objectRankLists(
    asArray(graph?.entities), queryText, queryEmbedding, (row) => `${row.name} ${row.summary}`, (row) => row.embedding,
    MNEMIS_CONSTANTS.system1_top_k,
  );
  const edgeLists = objectRankLists(
    asArray(graph?.edges), queryText, queryEmbedding, (row) => row.fact, (row) => row.embedding,
    MNEMIS_CONSTANTS.system1_top_k,
  );
  return {
    episode_ranks: reciprocalRankFusionMnemis([episodeLists.embedding, episodeLists.lexical]).slice(0, MNEMIS_CONSTANTS.system1_top_k),
    entity_ranks: reciprocalRankFusionMnemis([entityLists.embedding, entityLists.lexical]).slice(0, MNEMIS_CONSTANTS.system1_top_k),
    edge_ranks: reciprocalRankFusionMnemis([edgeLists.embedding, edgeLists.lexical]).slice(0, MNEMIS_CONSTANTS.system1_top_k),
    rank_sources: {
      episodes: { embedding: episodeLists.embedding.length, bm25: episodeLists.lexical.length },
      entities: { embedding: entityLists.embedding.length, bm25: entityLists.lexical.length },
      edges: { embedding: edgeLists.embedding.length, bm25: edgeLists.lexical.length },
    },
  };
}

export function mnemisGlobalSelection(graph = {}, queryText = '', hierarchyOverride = null) {
  const hierarchy = hierarchyOverride && Array.isArray(hierarchyOverride.categories)
    ? hierarchyOverride
    : buildMnemisHierarchy(graph);
  const categoryById = new Map(hierarchy.categories.map((category) => [category.id, category]));
  const entityById = new Map(asArray(graph?.entities).map((entity) => [entity.id, entity]));
  const selectedCategories = [];
  const selectedEntityIds = new Set();
  const queue = [...hierarchy.root_ids];
  const visited = new Set();

  while (queue.length) {
    const id = queue.shift();
    if (!id || visited.has(id)) continue;
    visited.add(id);
    const category = categoryById.get(id);
    if (!category) continue;
    const relevance = lexicalRelevance(queryText, `${category.label} ${category.search_text}`);
    if (relevance <= 0) continue;
    selectedCategories.push({ ...category, relevance });
    for (const childId of category.child_ids) {
      if (categoryById.has(childId)) queue.push(childId);
      else if (entityById.has(childId)) selectedEntityIds.add(childId);
    }
  }

  const selectedEpisodeIds = new Set();
  for (const entityId of selectedEntityIds) {
    for (const episodeId of entityById.get(entityId)?.episode_idx || []) selectedEpisodeIds.add(episodeId);
  }
  const selectedEdgeIds = new Set();
  for (const edge of asArray(graph?.edges)) {
    if (selectedEntityIds.has(edge.source_entity_id) || selectedEntityIds.has(edge.target_entity_id)) {
      selectedEdgeIds.add(edge.id);
      for (const episodeId of edge.episode_idx || []) selectedEpisodeIds.add(episodeId);
      selectedEntityIds.add(edge.source_entity_id);
      selectedEntityIds.add(edge.target_entity_id);
    }
  }

  return {
    hierarchy,
    selected_categories: selectedCategories.sort((a, b) => b.layer - a.layer || a.id.localeCompare(b.id)),
    selected_entity_ids: [...selectedEntityIds].sort(),
    selected_edge_ids: [...selectedEdgeIds].sort(),
    selected_episode_ids: [...selectedEpisodeIds].sort(),
    ordering: 'unordered_set',
    selection_policy: 'deterministic_positive_lexical_relevance_aimos_adaptation',
  };
}

function rankToEpisodeList(ranks, graph, objectClass) {
  const entityById = new Map(asArray(graph?.entities).map((row) => [row.id, row]));
  const edgeById = new Map(asArray(graph?.edges).map((row) => [row.id, row]));
  const seen = new Set();
  const result = [];
  for (const rank of asArray(ranks)) {
    const episodeIds = objectClass === 'episode'
      ? [rank.id]
      : objectClass === 'entity'
        ? (entityById.get(rank.id)?.episode_idx || [])
        : (edgeById.get(rank.id)?.episode_idx || []);
    for (const episodeId of episodeIds) {
      if (!seen.has(episodeId)) {
        seen.add(episodeId);
        result.push({ id: episodeId });
      }
    }
  }
  return result;
}

/**
 * Project the paper's class-separated System-1 retrieval evidence back onto
 * Episodes. This is intentionally independent from the model-guided System-2
 * hierarchy and from any final reranker: callers receive one deterministic,
 * bounded evidence rank over the supplied graph and no candidate authority.
 */
export function mnemisSystem1EpisodeEvidence(
  graph = {},
  queryText = '',
  queryEmbedding = null,
) {
  const system1 = mnemisSystem1(graph, queryText, queryEmbedding);
  const episodeEvidence = reciprocalRankFusionMnemis([
    rankToEpisodeList(system1.episode_ranks, graph, 'episode'),
    rankToEpisodeList(system1.entity_ranks, graph, 'entity'),
    rankToEpisodeList(system1.edge_ranks, graph, 'edge'),
  ]);
  const maximum = Math.max(0, ...episodeEvidence.map((row) => row.score));
  return {
    ranks: episodeEvidence.map((row, index) => ({
      ...row,
      rank: index + 1,
      normalized_score: maximum > 0 ? clamp01(row.score / maximum) : 0,
    })),
    rank_sources: system1.rank_sources,
    object_rank_count:
      system1.episode_ranks.length
      + system1.entity_ranks.length
      + system1.edge_ranks.length,
    system1,
  };
}

export function mnemisScores({ queryText = '', queryEmbedding = null, states = [] } = {}) {
  const admittedStates = normalizeStates(states);
  const graph = buildMnemisBaseGraph(admittedStates);
  const system1Evidence = mnemisSystem1EpisodeEvidence(
    graph,
    queryText,
    queryEmbedding,
  );
  const system1 = system1Evidence.system1;
  const system2 = mnemisGlobalSelection(graph, queryText);
  const normalizedByEpisode = new Map(
    system1Evidence.ranks.map((row) => [row.id, row.normalized_score]),
  );
  const system2EpisodeIds = new Set(system2.selected_episode_ids);
  const scoreById = new Map();
  const diagnosticsById = new Map();

  for (const state of admittedStates) {
    const stateId = String(state.id);
    const episodeId = `episode:${stateId}`;
    const score = normalizedByEpisode.get(episodeId) || 0;
    scoreById.set(stateId, score);
    diagnosticsById.set(stateId, {
      system1_evidence_score: score,
      selected_by_system2: system2EpisodeIds.has(episodeId),
      system2_is_unordered: true,
    });
  }

  return {
    scoreById,
    diagnosticsById,
    graph_stats: {
      episodes: graph.episodes.length,
      entities: graph.entities.length,
      edges: graph.edges.length,
      episodic_edges: graph.episodic_edges.length,
      categories: system2.hierarchy.categories.length,
      category_edges: system2.hierarchy.category_edges.length,
      hierarchy_layers: system2.hierarchy.levels.length,
    },
    system1_count: system1Evidence.object_rank_count,
    system2_count: system2.selected_episode_ids.length,
    union_count: new Set([
      ...system1Evidence.ranks.map((row) => row.id),
      ...system2.selected_episode_ids,
    ]).size,
    selected_categories: system2.selected_categories.map((category) => category.label),
    system1,
    system2,
    formula: 'System1 objects: RRF(d)=sum_r 1/(k+rank_r(d)); output score=normalized episode-evidence RRF; System2 remains an unordered selected set pending the paper reranker',
    guardrails: MNEMIS_GUARDRAILS,
    unimplemented_paper_components: [
      'LLM entity and edge extraction, reflection, and deduplication',
      'LLM category generation and many-to-many assignment',
      'LLM System-2 node selection and early stopping',
      'final model reranking across System-1 and System-2 object classes',
    ],
  };
}
