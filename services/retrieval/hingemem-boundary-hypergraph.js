/**
 * Dormant HingeMem boundary-hypergraph kernel.
 *
 * Paper authority:
 * - HingeMem: Boundary Guided Long-Term Memory with Query Adaptive Retrieval
 *   for Scalable Dialogues, Sections 3.2-3.3, Equations (1)-(6).
 *
 * Paper-faithful pure kernels implemented here:
 * - boundary memory B_i=(N_i,H_i) and four typed node indices;
 * - hyperedge h=(P,T,L,C,d,r);
 * - field-aware Jaccard and strict recursive merge threshold J>0.8;
 * - long-term representation M={N,H,C_common,C_rare};
 * - additive rerank xi_hat=xi+Omega_S+Omega_T;
 * - precision stop at xi_hat>0.8*max(xi_hat);
 * - judgment stop after stable softmax at p_i>0.8*max(p);
 * - recall stop using the intended descending-score knee described by the
 *   prose/figure/appendix. The printed inequality reverses that score drop and
 *   is recorded as a paper ambiguity rather than copied as a false rule.
 *
 * Explicit AIMOS adaptations and exclusions:
 * - boundary extraction and query planning are deterministic diagnostics, not
 *   the paper's LLM-produced structures;
 * - node salience combines the paper's frequency, centrality, and diversity
 *   dimensions with an explicitly equal-weight deterministic adaptation;
 * - Omega_T uses signed lexical rare-minus-common proximity because the
 *   paper's learned feature subspaces and weighted topic softmax are absent;
 * - an supplied finite embedding is used for xi when available; otherwise xi
 *   is an explicitly lexical similarity adaptation;
 * - all construction and selection is transient. No canonical memory is
 *   merged, deleted, suppressed, rewritten, or assigned age-based authority.
 */

export const HINGEMEM_CONSTANTS = Object.freeze({
  merge_jaccard_threshold: 0.8,
  knee_lambda: 0.1,
  relative_maximum: 0.8,
  recall_maximum_floor: 0.5,
  max_hyperedges: 260,
  max_description_chars: 1600,
});

export const HINGEMEM_GUARDRAILS = Object.freeze({
  dormant: true,
  mutates_canonical_memory: false,
  persists_hypergraph: false,
  prunes_canonical_memory: false,
  applies_age_decay: false,
  deletes_memory: false,
  suppresses_memory: false,
  injects_answers: false,
  uses_database: false,
  uses_environment_authority: false,
  adaptive_stop_is_transient_read_selection_only: true,
  paper_recall_stop_sign_ambiguity_disclosed: true,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'event', 'events', 'from', 'have', 'many',
  'more', 'most', 'that', 'their', 'there', 'these', 'this', 'those',
  'through', 'time', 'what', 'when', 'where', 'which', 'while', 'with', 'would',
]);

const MONTH_RE = /\b(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec)\b/i;
const EXPLICIT_MARKER_RE = /\b(later|afterward|then|after|before|next|previously|last|currently|now|meanwhile)\b/i;
const BOUNDARY_REASONS = new Set(['change_person', 'change_time', 'change_location', 'topic_shift', 'explicit_marker']);
const ELEMENT_TYPES = Object.freeze(['person', 'time', 'location', 'topic']);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function clamp01(value) {
  return clamp(value, 0, 1);
}

function normalizeText(value = '') {
  return String(value ?? '')
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
  return [...new Set((Array.isArray(values) ? values : []).filter(Boolean))];
}

function overlap(left = [], right = []) {
  const a = new Set(Array.isArray(left) ? left : []);
  const b = new Set(Array.isArray(right) ? right : []);
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const item of a) if (b.has(item)) hits += 1;
  return clamp01(hits / Math.sqrt(a.size * b.size));
}

function lexicalSimilarity(left = '', right = '') {
  return overlap(tokens(left), tokens(right));
}

function finiteVector(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const vector = value.map(Number);
  return vector.every(Number.isFinite) ? vector : null;
}

function cosineSimilarity(left, right) {
  const a = finiteVector(left);
  const b = finiteVector(right);
  if (!a || !b || a.length !== b.length) return null;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return null;
  return clamp(dot / Math.sqrt(normA * normB), -1, 1);
}

function dateToken(value = '') {
  const text = String(value ?? '');
  const iso = text.match(/\b\d{4}-\d{2}-\d{2}\b/);
  if (iso) return iso[0];
  const month = text.match(MONTH_RE);
  const year = text.match(/\b(19|20)\d{2}\b/);
  if (month && year) return `${month[0].toLowerCase()}:${year[0]}`;
  if (month) return month[0].toLowerCase();
  if (year) return year[0];
  return '';
}

function normalizeElementValues(value) {
  if (!Array.isArray(value)) return [];
  return unique(value.map((entry) => normalizeText(isRecord(entry) ? entry.name : entry)).filter(Boolean)).sort();
}

function properNouns(text = '') {
  return unique([...String(text ?? '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)]
    .map((match) => normalizeText(match[0]))
    .filter((value) => value.length >= 3 && !MONTH_RE.test(value))).sort();
}

function topicTokens(text = '', max = 5) {
  const counts = new Map();
  for (const token of tokens(text)) counts.set(token, (counts.get(token) || 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, max)
    .map(([token]) => token);
}

function locationTokens(text = '') {
  const patterns = [
    /\b(?:at|in|near|from|to)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b/g,
    /\b(airport|beach|park|restaurant|hotel|office|school|clinic|museum|station|shoreline)\b/gi,
  ];
  const values = [];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    for (const match of String(text ?? '').matchAll(pattern)) values.push(normalizeText(match[1] || match[0]));
  }
  return unique(values).sort().slice(0, 4);
}

function typedElementSet(hyperedge = {}) {
  const values = [];
  for (const type of ELEMENT_TYPES) {
    for (const value of Array.isArray(hyperedge?.[type]) ? hyperedge[type] : []) {
      const normalized = normalizeText(value);
      if (normalized) values.push(`${type}:${normalized}`);
    }
  }
  return unique(values).sort();
}

export function fieldAwareJaccard(left = {}, right = {}) {
  const a = new Set(typedElementSet(left));
  const b = new Set(typedElementSet(right));
  if (!a.size && !b.size) return 1;
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const value of a) if (b.has(value)) hits += 1;
  return hits / new Set([...a, ...b]).size;
}

function boundaryReasons(previous, current, explicitReasons = []) {
  const supplied = unique(explicitReasons.map((reason) => String(reason).toLowerCase()))
    .filter((reason) => BOUNDARY_REASONS.has(reason));
  if (supplied.length) return supplied;
  if (!previous) return ['explicit_marker'];
  const reasons = [];
  if (overlap(previous.person, current.person) < 0.5) reasons.push('change_person');
  if (overlap(previous.time, current.time) < 0.5) reasons.push('change_time');
  if (overlap(previous.location, current.location) < 0.5) reasons.push('change_location');
  if (overlap(previous.topic, current.topic) < 0.42) reasons.push('topic_shift');
  if (EXPLICIT_MARKER_RE.test(current.description)) reasons.push('explicit_marker');
  return unique(reasons);
}

function stateElements(state, text) {
  const memory = isRecord(state.memory) ? state.memory : {};
  const supplied = isRecord(state.boundary_elements)
    ? state.boundary_elements
    : (isRecord(memory.boundary_elements) ? memory.boundary_elements : {});
  return {
    person: normalizeElementValues(supplied.person).length
      ? normalizeElementValues(supplied.person)
      : properNouns(text).slice(0, 5),
    time: normalizeElementValues(supplied.time).length
      ? normalizeElementValues(supplied.time)
      : unique([dateToken(text), dateToken(memory.created_at)]).filter(Boolean).sort(),
    location: normalizeElementValues(supplied.location).length
      ? normalizeElementValues(supplied.location)
      : locationTokens(text),
    topic: normalizeElementValues(supplied.topic).length
      ? normalizeElementValues(supplied.topic)
      : topicTokens(text, 6),
  };
}

function makeHyperedge(state, index, previous) {
  if (!isRecord(state)) return null;
  const memory = isRecord(state.memory) ? state.memory : {};
  const id = String(state.id ?? memory.id ?? '').trim();
  const text = String(state.text ?? memory.value ?? '').trim();
  if (!id || !text) return null;
  const elements = stateElements(state, text);
  const hyperedge = {
    id,
    state_ids: [id],
    ...elements,
    description: text.slice(0, HINGEMEM_CONSTANTS.max_description_chars),
    embedding: finiteVector(state.embedding ?? memory.embedding ?? memory.vector),
    embedding_count: finiteVector(state.embedding ?? memory.embedding ?? memory.vector) ? 1 : 0,
    source_index: index,
    reasons: [],
  };
  const explicitReasons = Array.isArray(state.boundary_reasons)
    ? state.boundary_reasons
    : (Array.isArray(memory.boundary_reasons) ? memory.boundary_reasons : []);
  hyperedge.reasons = boundaryReasons(previous, hyperedge, explicitReasons);
  return hyperedge;
}

function mergedEmbedding(left, right) {
  const a = finiteVector(left.embedding);
  const b = finiteVector(right.embedding);
  const countA = a ? Math.max(1, Number(left.embedding_count) || 1) : 0;
  const countB = b ? Math.max(1, Number(right.embedding_count) || 1) : 0;
  if (!a && !b) return { embedding: null, embedding_count: 0 };
  if (!a) return { embedding: [...b], embedding_count: countB };
  if (!b) return { embedding: [...a], embedding_count: countA };
  if (a.length !== b.length) return { embedding: null, embedding_count: 0 };
  const total = countA + countB;
  return {
    embedding: a.map((value, index) => ((value * countA) + (b[index] * countB)) / total),
    embedding_count: total,
  };
}

function mergeHyperedges(left, right) {
  const vector = mergedEmbedding(left, right);
  return {
    id: `${left.id}+${right.id}`,
    state_ids: unique([...(left.state_ids || []), ...(right.state_ids || [])]).sort(),
    person: unique([...(left.person || []), ...(right.person || [])]).sort(),
    time: unique([...(left.time || []), ...(right.time || [])]).sort(),
    location: unique([...(left.location || []), ...(right.location || [])]).sort(),
    topic: unique([...(left.topic || []), ...(right.topic || [])]).sort(),
    description: `${left.description || ''}\n${right.description || ''}`
      .slice(0, HINGEMEM_CONSTANTS.max_description_chars),
    ...vector,
    source_index: Math.min(left.source_index ?? 0, right.source_index ?? 0),
    reasons: unique([...(left.reasons || []), ...(right.reasons || [])]).sort(),
  };
}

export function recursivelyMergeHyperedges(hyperedges = [], threshold = HINGEMEM_CONSTANTS.merge_jaccard_threshold) {
  const rows = Array.isArray(hyperedges) ? hyperedges.filter(isRecord).map((row) => structuredClone(row)) : [];
  const mergeThreshold = clamp(threshold, 0, 1);
  while (rows.length > 1) {
    let best = { i: -1, j: -1, score: mergeThreshold };
    for (let i = 0; i < rows.length; i += 1) {
      for (let j = i + 1; j < rows.length; j += 1) {
        const score = fieldAwareJaccard(rows[i], rows[j]);
        if (score > best.score) best = { i, j, score };
      }
    }
    if (best.i < 0) break;
    const merged = mergeHyperedges(rows[best.i], rows[best.j]);
    rows.splice(best.j, 1);
    rows.splice(best.i, 1, merged);
  }
  return rows;
}

function nodeKey(type, name) {
  return `${type}:${normalizeText(name)}`;
}

function buildNodes(hyperedges) {
  const nodeMap = new Map();
  for (const hyperedge of hyperedges) {
    const allKeys = typedElementSet(hyperedge);
    for (const type of ELEMENT_TYPES) {
      for (const name of hyperedge[type] || []) {
        const id = nodeKey(type, name);
        const node = nodeMap.get(id) || {
          id,
          type,
          name,
          mentions: 0,
          hyperedges: new Set(),
          co_nodes: new Set(),
        };
        node.mentions += 1;
        node.hyperedges.add(hyperedge.id);
        for (const key of allKeys) if (key !== id) node.co_nodes.add(key);
        nodeMap.set(id, node);
      }
    }
  }

  const nodes = [...nodeMap.values()];
  const maxMentions = Math.max(1, ...nodes.map((node) => node.mentions));
  const maxPeers = Math.max(1, nodes.length - 1);
  return nodes
    .map((node) => {
      const frequency = node.mentions / maxMentions;
      const centrality = node.hyperedges.size / Math.max(1, hyperedges.length);
      const diversity = node.co_nodes.size / maxPeers;
      return {
        id: node.id,
        type: node.type,
        name: node.name,
        mentions: node.mentions,
        hyperedges: [...node.hyperedges].sort(),
        salience: clamp01((frequency + centrality + diversity) / 3),
        salience_components: Object.freeze({ frequency, centrality, diversity }),
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
}

export function buildBoundaryHypergraph(states = []) {
  const source = Array.isArray(states) ? states : [];
  const raw = [];
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < source.length && raw.length < HINGEMEM_CONSTANTS.max_hyperedges; index += 1) {
    const hyperedge = makeHyperedge(source[index], index, previous);
    if (!hyperedge || seen.has(hyperedge.id)) continue;
    seen.add(hyperedge.id);
    raw.push(hyperedge);
    previous = hyperedge;
  }

  const H = recursivelyMergeHyperedges(raw);
  const N = buildNodes(H);
  const topicCounts = new Map();
  for (const hyperedge of H) {
    for (const topic of hyperedge.topic || []) topicCounts.set(topic, (topicCounts.get(topic) || 0) + 1);
  }
  const topics = [...topicCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return {
    N,
    H,
    C_common: topics.filter(([, count]) => count > 1).map(([topic]) => topic),
    C_rare: topics.filter(([, count]) => count === 1).map(([topic]) => topic),
    raw_boundary_count: raw.length,
  };
}

export function hingeMemQueryPlan(queryText = '') {
  const query = String(queryText ?? '');
  const person = properNouns(query);
  const time = unique([dateToken(query)]).filter(Boolean);
  const location = locationTokens(query);
  const topic = topicTokens(query, 8);
  const type = /\b(all|list|how many|count|total|everything)\b/i.test(query)
    ? 'recall_priority'
    : /\b(would|should|considered|likely|is it true|did|does|exist)\b/i.test(query)
      ? 'judgment'
      : 'precision_priority';
  const priorities = [];
  if (/\b(after|before|between|when|last|currently|now|days?|months?)\b/i.test(query)) priorities.push('time');
  if (person.length) priorities.push('person');
  if (location.length) priorities.push('location');
  if (topic.length) priorities.push('topic');
  return {
    type,
    targeted_indices: { person, time, location, topic },
    priorities: unique(priorities),
    producer: 'deterministic_aimos_adaptation_not_paper_llm',
  };
}

function priorityWeights(priorities) {
  const ordered = unique((Array.isArray(priorities) ? priorities : []).filter((type) => ELEMENT_TYPES.includes(type)));
  const raw = ordered.map((type, index) => [type, 1 / (index + 1)]);
  const total = raw.reduce((sum, [, weight]) => sum + weight, 0) || 1;
  return new Map(raw.map(([type, weight]) => [type, weight / total]));
}

function structuralOmega(hyperedge, plan, nodeById) {
  const weights = priorityWeights(plan?.priorities);
  let score = 0;
  for (const [type, weight] of weights) {
    const requested = new Set((plan?.targeted_indices?.[type] || []).map(normalizeText));
    const candidates = (hyperedge?.[type] || []).filter((name) => requested.size === 0 || requested.has(normalizeText(name)));
    if (!candidates.length) continue;
    const salience = candidates.reduce((sum, name) => sum + (nodeById.get(nodeKey(type, name))?.salience || 0), 0) / candidates.length;
    score += weight * salience;
  }
  return clamp01(score);
}

function maximumTopicSimilarity(queryText, topics) {
  let maximum = 0;
  for (const topic of Array.isArray(topics) ? topics : []) {
    maximum = Math.max(maximum, lexicalSimilarity(queryText, topic));
  }
  return maximum;
}

function topicOmega(queryText, common, rare) {
  const overlapSet = new Set((common || []).filter((topic) => (rare || []).includes(topic)));
  const commonOnly = (common || []).filter((topic) => !overlapSet.has(topic));
  const rareOnly = (rare || []).filter((topic) => !overlapSet.has(topic));
  return clamp(
    maximumTopicSimilarity(queryText, rareOnly) - maximumTopicSimilarity(queryText, commonOnly),
    -1,
    1,
  );
}

export function rerankHyperedges({
  queryText = '',
  queryEmbedding = null,
  hypergraph = {},
  plan = hingeMemQueryPlan(queryText),
} = {}) {
  const edges = Array.isArray(hypergraph?.H) ? hypergraph.H : [];
  const nodeById = new Map((Array.isArray(hypergraph?.N) ? hypergraph.N : []).map((node) => [String(node.id), node]));
  return edges
    .filter(isRecord)
    .map((hyperedge) => {
      const dense = cosineSimilarity(queryEmbedding, hyperedge.embedding);
      const xi = dense === null ? lexicalSimilarity(queryText, hyperedge.description) : dense;
      const omegaS = structuralOmega(hyperedge, plan, nodeById);
      const omegaT = topicOmega(queryText, hypergraph.C_common || [], hypergraph.C_rare || []);
      return {
        hyperedge,
        xi,
        xi_source: dense === null ? 'lexical_adaptation' : 'cosine_embedding',
        omegaS,
        omegaT,
        xi_hat: xi + omegaS + omegaT,
      };
    })
    .filter((row) => Number.isFinite(row.xi_hat))
    .sort((a, b) => b.xi_hat - a.xi_hat || a.hyperedge.id.localeCompare(b.hyperedge.id));
}

function stableSoftmax(values) {
  if (!Array.isArray(values) || values.length === 0) return [];
  const maximum = Math.max(...values);
  const exponents = values.map((value) => Math.exp(value - maximum));
  const total = exponents.reduce((sum, value) => sum + value, 0);
  return total > 0 ? exponents.map((value) => value / total) : values.map(() => 0);
}

export function adaptiveStop(ranked = [], plan = {}, lambda = HINGEMEM_CONSTANTS.knee_lambda) {
  const rows = Array.isArray(ranked)
    ? ranked.filter((row) => isRecord(row) && Number.isFinite(row.xi_hat))
    : [];
  if (!rows.length) return [];
  const ordered = [...rows].sort((a, b) => b.xi_hat - a.xi_hat || String(a.hyperedge?.id).localeCompare(String(b.hyperedge?.id)));
  const maximum = ordered[0].xi_hat;

  if (plan?.type === 'recall_priority') {
    const knee = clamp(lambda, 0, Number.MAX_SAFE_INTEGER);
    const floor = maximum * HINGEMEM_CONSTANTS.recall_maximum_floor;
    for (let index = 0; index + 1 < ordered.length; index += 1) {
      const gap = ordered[index].xi_hat - ordered[index + 1].xi_hat;
      if (gap > knee && ordered[index].xi_hat > floor) return ordered.slice(0, index + 1);
    }
    return ordered.filter((row) => row.xi_hat > floor);
  }

  if (plan?.type === 'judgment') {
    const probabilities = stableSoftmax(ordered.map((row) => row.xi_hat));
    const maxProbability = Math.max(...probabilities);
    return ordered.filter((_, index) => probabilities[index] > HINGEMEM_CONSTANTS.relative_maximum * maxProbability);
  }

  return ordered.filter((row) => row.xi_hat > HINGEMEM_CONSTANTS.relative_maximum * maximum);
}

function normalizedAdditiveScores(ranked) {
  const maximum = Math.max(0, ...ranked.map((row) => row.xi_hat));
  if (!(maximum > 0)) return new Map(ranked.map((row) => [row.hyperedge.id, 0]));
  return new Map(ranked.map((row) => [row.hyperedge.id, clamp01(Math.max(0, row.xi_hat) / maximum)]));
}

export function hingeMemScores({ queryText = '', queryEmbedding = null, states = [] } = {}) {
  const hypergraph = buildBoundaryHypergraph(states);
  const queryPlan = hingeMemQueryPlan(queryText);
  const ranked = rerankHyperedges({ queryText, queryEmbedding, hypergraph, plan: queryPlan });
  const selected = adaptiveStop(ranked, queryPlan);
  const selectedIds = new Set(selected.map((row) => row.hyperedge.id));
  const normalized = normalizedAdditiveScores(ranked);
  const scoreById = new Map();
  const diagnosticsById = new Map();

  for (const row of ranked) {
    for (const stateId of row.hyperedge.state_ids || []) {
      const id = String(stateId);
      const score = normalized.get(row.hyperedge.id) || 0;
      scoreById.set(id, Math.max(scoreById.get(id) || 0, score));
      diagnosticsById.set(id, {
        hyperedge_id: row.hyperedge.id,
        xi: Number(row.xi.toFixed(6)),
        xi_source: row.xi_source,
        omega_s: Number(row.omegaS.toFixed(6)),
        omega_t: Number(row.omegaT.toFixed(6)),
        xi_hat_raw: Number(row.xi_hat.toFixed(6)),
        score_normalized: Number(score.toFixed(6)),
        selected_by_adaptive_stop: selectedIds.has(row.hyperedge.id),
      });
    }
  }

  if (Array.isArray(states)) {
    for (const state of states) {
      if (!isRecord(state)) continue;
      const id = String(state.id ?? state.memory?.id ?? '').trim();
      if (!id || scoreById.has(id)) continue;
      scoreById.set(id, 0);
      diagnosticsById.set(id, {
        hyperedge_id: null,
        xi: 0,
        xi_source: 'invalid_or_out_of_bound',
        omega_s: 0,
        omega_t: 0,
        xi_hat_raw: 0,
        score_normalized: 0,
        selected_by_adaptive_stop: false,
      });
    }
  }

  return {
    scoreById,
    diagnosticsById,
    hyperedge_count: hypergraph.H.length,
    node_count: hypergraph.N.length,
    raw_boundary_count: hypergraph.raw_boundary_count,
    query_plan: queryPlan,
    selected_count: selected.length,
    common_topic_count: hypergraph.C_common.length,
    rare_topic_count: hypergraph.C_rare.length,
    guardrails: HINGEMEM_GUARDRAILS,
    formula: 'xi_hat=xi+Omega_S+Omega_T; merge iff J>0.8; output_score=max(0,xi_hat)/max_j(max(0,xi_hat_j))',
  };
}
