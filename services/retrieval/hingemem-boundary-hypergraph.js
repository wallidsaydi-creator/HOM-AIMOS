/**
 * Native HingeMem boundary-hypergraph recall operator from:
 * - HingeMem.pdf
 *
 * Implemented formulas / techniques:
 * - boundary-triggered memory `B_i = (N_i, H_i)`
 * - four-element index: person, time, location, topic
 * - hyperedge schema `h = (P~, T~, L~, C~, d, r)`
 * - finite boundary reason set: person/time/location/topic/explicit-marker
 * - field-aware Jaccard merge `J(h_i,h_j)=|N(h_i)∩N(h_j)|/|N(h_i)∪N(h_j)|`
 * - recursive merge threshold `J > 0.8`
 * - long-term memory state `M = {N, H, C_common, C_rare}`
 * - query-adaptive plan: query type, target indices, ordered element priorities
 * - hyperedge rerank `xi_hat = xi + Omega_S(N_hat(h_i)|p_i) + Omega_T(q|C_common,C_rare)`
 * - adaptive stopping categories: recall-priority, precision-priority, judgment
 * - knee parameter `lambda_knee = 0.1`
 *
 * Aimos adaptation:
 * - builds a transient boundary hypergraph over returned recall candidates
 * - adaptive stopping is diagnostic only; no canonical candidate is pruned
 * - scoring is monotone and bounded, preserving previous recall calibration
 */

export const HINGEMEM_CONSTANTS = Object.freeze({
  merge_jaccard_threshold: 0.8,
  knee_lambda: 0.1,
  rare_topic_bonus: 0.12,
  common_topic_bonus: 0.06,
  max_hyperedges: 260,
});

export const HINGEMEM_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  adaptive_stop_is_diagnostic_only: true,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'event', 'events', 'from', 'have', 'many',
  'more', 'most', 'that', 'their', 'there', 'these', 'this', 'those',
  'through', 'time', 'what', 'when', 'where', 'which', 'while', 'with', 'would',
]);

const MONTH_RE = /\b(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec)\b/i;
const EXPLICIT_MARKER_RE = /\b(later|afterward|then|after|before|next|previously|last|currently|now|meanwhile)\b/i;

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
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
  return [...new Set(values.filter(Boolean))];
}

function overlap(left = [], right = []) {
  const a = new Set(left);
  const b = new Set(right);
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const item of a) if (b.has(item)) hits += 1;
  return hits / Math.sqrt(a.size * b.size);
}

function lexicalSimilarity(left = '', right = '') {
  return clamp01(overlap(tokens(left), tokens(right)));
}

function dateToken(value = '') {
  const text = String(value || '');
  const iso = text.match(/\b\d{4}-\d{2}-\d{2}\b/);
  if (iso) return iso[0];
  const month = text.match(MONTH_RE);
  const year = text.match(/\b(19|20)\d{2}\b/);
  if (month && year) return `${month[0].toLowerCase()}:${year[0]}`;
  if (month) return month[0].toLowerCase();
  if (year) return year[0];
  return '';
}

function properNouns(text = '') {
  return unique([...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)]
    .map((match) => match[0].toLowerCase())
    .filter((value) => value.length >= 3 && !MONTH_RE.test(value)));
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
  const out = [];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    for (const match of String(text || '').matchAll(pattern)) out.push((match[1] || match[0]).toLowerCase());
  }
  return unique(out).slice(0, 4);
}

function elementSet(hyperedge = {}) {
  return unique([
    ...(hyperedge.person || []),
    ...(hyperedge.time || []),
    ...(hyperedge.location || []),
    ...(hyperedge.topic || []),
  ]);
}

export function fieldAwareJaccard(left = {}, right = {}) {
  const a = new Set(elementSet(left));
  const b = new Set(elementSet(right));
  if (!a.size && !b.size) return 1;
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const value of a) if (b.has(value)) hits += 1;
  return hits / new Set([...a, ...b]).size;
}

function boundaryReasons(previous = null, current = {}) {
  if (!previous) return ['explicit_marker'];
  const reasons = [];
  if (overlap(previous.person, current.person) < 0.5) reasons.push('change_person');
  if (overlap(previous.time, current.time) < 0.5) reasons.push('change_time');
  if (overlap(previous.location, current.location) < 0.5) reasons.push('change_location');
  if (overlap(previous.topic, current.topic) < 0.42) reasons.push('topic_shift');
  if (EXPLICIT_MARKER_RE.test(current.description || '')) reasons.push('explicit_marker');
  return reasons.length ? reasons : ['same_segment'];
}

function makeHyperedge(state = {}, index = 0, previous = null) {
  const text = state.text || state.memory?.value || '';
  const time = unique([dateToken(text), dateToken(state.memory?.created_at || '')]).filter(Boolean);
  const hyperedge = {
    id: String(state.id || `h:${index + 1}`),
    state_ids: [String(state.id || `h:${index + 1}`)],
    person: properNouns(text).slice(0, 5),
    time,
    location: locationTokens(text),
    topic: topicTokens(text, 6),
    description: text.slice(0, 1600),
    source_index: index,
    reasons: [],
  };
  hyperedge.reasons = boundaryReasons(previous, hyperedge);
  return hyperedge;
}

function mergeHyperedges(left = {}, right = {}) {
  return {
    id: `${left.id}+${right.id}`,
    state_ids: unique([...(left.state_ids || []), ...(right.state_ids || [])]),
    person: unique([...(left.person || []), ...(right.person || [])]),
    time: unique([...(left.time || []), ...(right.time || [])]),
    location: unique([...(left.location || []), ...(right.location || [])]),
    topic: unique([...(left.topic || []), ...(right.topic || [])]),
    description: `${left.description || ''}\n${right.description || ''}`.slice(0, 2400),
    source_index: Math.min(left.source_index ?? 0, right.source_index ?? 0),
    reasons: unique([...(left.reasons || []), ...(right.reasons || []), 'jaccard_merge']),
  };
}

function recursivelyMergeHyperedges(hyperedges = [], threshold = HINGEMEM_CONSTANTS.merge_jaccard_threshold) {
  const rows = [...hyperedges];
  let changed = true;
  while (changed) {
    changed = false;
    let best = { i: -1, j: -1, score: threshold };
    for (let i = 0; i < rows.length; i += 1) {
      for (let j = i + 1; j < rows.length; j += 1) {
        const score = fieldAwareJaccard(rows[i], rows[j]);
        if (score > best.score) best = { i, j, score };
      }
    }
    if (best.i >= 0) {
      const merged = mergeHyperedges(rows[best.i], rows[best.j]);
      rows.splice(best.j, 1);
      rows.splice(best.i, 1, merged);
      changed = true;
    }
  }
  return rows;
}

function nodeKey(type = '', name = '') {
  return `${type}:${normalizeText(name)}`;
}

export function buildBoundaryHypergraph(states = []) {
  const raw = [];
  let previous = null;
  for (const [index, state] of (states || []).slice(0, HINGEMEM_CONSTANTS.max_hyperedges).entries()) {
    const hyperedge = makeHyperedge(state, index, previous);
    raw.push(hyperedge);
    previous = hyperedge;
  }
  const H = recursivelyMergeHyperedges(raw);
  const nodeMap = new Map();
  for (const hyperedge of H) {
    for (const [type, values] of [
      ['person', hyperedge.person],
      ['time', hyperedge.time],
      ['location', hyperedge.location],
      ['topic', hyperedge.topic],
    ]) {
      for (const value of values || []) {
        const key = nodeKey(type, value);
        const existing = nodeMap.get(key) || { id: key, type, name: value, mentions: 0, hyperedges: new Set(), salience: 0 };
        existing.mentions += 1;
        existing.hyperedges.add(hyperedge.id);
        nodeMap.set(key, existing);
      }
    }
  }
  const N = [...nodeMap.values()].map((node) => ({
    ...node,
    hyperedges: [...node.hyperedges],
    salience: clamp01((0.55 * Math.log1p(node.mentions) / Math.log(8)) + (0.45 * Math.min(1, node.hyperedges.length / Math.max(1, H.length)))),
  }));
  const topicCounts = new Map();
  for (const hyperedge of H) for (const topic of hyperedge.topic || []) topicCounts.set(topic, (topicCounts.get(topic) || 0) + 1);
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
  const q = String(queryText || '');
  const person = properNouns(q);
  const time = unique([dateToken(q)]).filter(Boolean);
  const location = locationTokens(q);
  const topic = topicTokens(q, 8);
  const type = /\b(all|list|how many|count|total|everything)\b/i.test(q)
    ? 'recall_priority'
    : /\b(would|should|considered|likely|is it true)\b/i.test(q)
      ? 'judgment'
      : 'precision_priority';
  const priorities = [];
  if (/\b(after|before|between|when|last|currently|now|days?|months?)\b/i.test(q)) priorities.push('time');
  if (person.length) priorities.push('person');
  if (location.length) priorities.push('location');
  priorities.push('topic');
  return {
    type,
    targeted_indices: { person, time, location, topic },
    priorities: unique(priorities),
  };
}

function structuralOmega(hyperedge = {}, plan = {}) {
  const weights = { person: 0.28, time: 0.28, location: 0.18, topic: 0.26 };
  let score = 0;
  let mass = 0;
  for (const key of plan.priorities || []) {
    const queryValues = plan.targeted_indices?.[key] || [];
    if (!queryValues.length) continue;
    const edgeValues = hyperedge[key] || [];
    score += (weights[key] || 0.2) * overlap(queryValues, edgeValues);
    mass += weights[key] || 0.2;
  }
  return mass ? clamp01(score / mass) : 0;
}

function topicOmega(queryText = '', hyperedge = {}, common = [], rare = []) {
  const qTokens = tokens(queryText);
  const edgeTopics = hyperedge.topic || [];
  const base = overlap(qTokens, edgeTopics);
  const rareHit = edgeTopics.some((topic) => rare.includes(topic) && qTokens.includes(topic)) ? HINGEMEM_CONSTANTS.rare_topic_bonus : 0;
  const commonHit = edgeTopics.some((topic) => common.includes(topic) && qTokens.includes(topic)) ? HINGEMEM_CONSTANTS.common_topic_bonus : 0;
  return clamp01(base + rareHit + commonHit);
}

export function rerankHyperedges({ queryText = '', hypergraph = {}, plan = hingeMemQueryPlan(queryText) } = {}) {
  const ranked = (hypergraph.H || []).map((hyperedge) => {
    const xi = lexicalSimilarity(queryText, hyperedge.description);
    const omegaS = structuralOmega(hyperedge, plan);
    const omegaT = topicOmega(queryText, hyperedge, hypergraph.C_common || [], hypergraph.C_rare || []);
    return {
      hyperedge,
      xi,
      omegaS,
      omegaT,
      xi_hat: clamp01((0.54 * xi) + (0.30 * omegaS) + (0.16 * omegaT)),
    };
  }).sort((a, b) => b.xi_hat - a.xi_hat || a.hyperedge.id.localeCompare(b.hyperedge.id));
  return ranked;
}

export function adaptiveStop(ranked = [], plan = {}, lambda = HINGEMEM_CONSTANTS.knee_lambda) {
  if (!ranked.length) return [];
  if (plan.type === 'recall_priority') {
    const max = ranked[0].xi_hat || 1;
    return ranked.filter((row) => row.xi_hat >= Math.max(0.05, max * lambda));
  }
  if (plan.type === 'judgment') return ranked.slice(0, Math.min(6, ranked.length));
  let stop = ranked.length;
  for (let i = 1; i < ranked.length; i += 1) {
    const gap = (ranked[i - 1].xi_hat || 0) - (ranked[i].xi_hat || 0);
    if (gap >= lambda) {
      stop = i;
      break;
    }
  }
  return ranked.slice(0, Math.max(1, Math.min(stop, 8)));
}

export function hingeMemScores({ queryText = '', states = [] } = {}) {
  const hypergraph = buildBoundaryHypergraph(states);
  const queryPlan = hingeMemQueryPlan(queryText);
  const ranked = rerankHyperedges({ queryText, hypergraph, plan: queryPlan });
  const selected = adaptiveStop(ranked, queryPlan);
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const row of ranked) {
    const selectedBoost = selected.some((candidate) => candidate.hyperedge.id === row.hyperedge.id) ? 0.12 : 0;
    for (const stateId of row.hyperedge.state_ids || []) {
      const score = clamp01(row.xi_hat + selectedBoost);
      scoreById.set(String(stateId), Math.max(scoreById.get(String(stateId)) || 0, score));
      diagnosticsById.set(String(stateId), {
        hyperedge_id: row.hyperedge.id,
        xi: Number(row.xi.toFixed(6)),
        omega_s: Number(row.omegaS.toFixed(6)),
        omega_t: Number(row.omegaT.toFixed(6)),
        selected_by_adaptive_stop: selected.some((candidate) => candidate.hyperedge.id === row.hyperedge.id),
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
    formula: 'xi_hat = 0.54*xi + 0.30*Omega_S + 0.16*Omega_T; J_merge > 0.8; diagnostic adaptive stop by query type',
  };
}
