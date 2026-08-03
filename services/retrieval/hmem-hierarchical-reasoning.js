/**
 * Native H-MEM hierarchy recall operator from:
 * - H-MEM- Hierarchical Memory for High-Efficiency Long-Term Reasoning in LLM Agents.pdf
 *
 * Implemented formulas / techniques:
 * - hierarchical memory units `M(1), M(2), ..., M(L)`
 * - four abstraction levels: section, subsection, subsub-section, content
 * - positional index pointers from parent units to subordinate units
 * - recursive retrieval `M_k = TopK_{y in Child(x)}(sim(q,y)); x in M_k`
 * - similarity ignores positional index and uses content vector only
 * - confidence-weighted memory injection
 * - top-k routing with `k=10`
 * - complexity reporting `O(a*10^6*D)` versus `O((a+k*300)*D)`
 *
 * Aimos adaptation:
 * - builds a transient hierarchy over returned recall candidates
 * - uses hierarchical routing as a monotone recall signal
 * - never removes candidates and never mutates canonical memory
 */

export const HMEM_CONSTANTS = Object.freeze({
  levels: ['section', 'subsection', 'subsub_section', 'content'],
  top_k: 10,
  per_parent_child_cap: 300,
  million_scale_reference: 1_000_000,
  vector_dim: 64,
});

export const HMEM_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  positional_index_is_pointer_not_similarity_feature: true,
});

const STOPWORDS = new Set(['about', 'after', 'and', 'are', 'between', 'current', 'from', 'have', 'many', 'that', 'the', 'this', 'what', 'when', 'which', 'with']);

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
  return normalizeText(value).split(/\s+/).filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

export function hashVector(text = '', dim = HMEM_CONSTANTS.vector_dim) {
  const vector = Array.from({ length: dim }, () => 0);
  for (const token of tokens(text)) {
    let hash = 2166136261;
    for (let i = 0; i < token.length; i += 1) {
      hash ^= token.charCodeAt(i);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    vector[hash % dim] += 1;
  }
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + (value * value), 0)) || 1;
  return vector.map((value) => value / norm);
}

export function cosine(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let dot = 0;
  let ln = 0;
  let rn = 0;
  for (let i = 0; i < n; i += 1) {
    const l = Number(left[i]) || 0;
    const r = Number(right[i]) || 0;
    dot += l * r;
    ln += l * l;
    rn += r * r;
  }
  return dot / ((Math.sqrt(ln) || 1) * (Math.sqrt(rn) || 1));
}

function semanticSimilarity(query = '', text = '') {
  return clamp01((cosine(hashVector(query), hashVector(text)) + 1) / 2);
}

function sectionLabel(state = {}) {
  const text = `${state.memory?.source || ''} ${state.memory?.memory_type || ''} ${state.text || ''}`;
  const patterns = [
    ['travel', /\b(airline|airport|flight|flew|hotel|trip|travel)\b/i],
    ['event', /\b(attended|event|joined|walk|cleanup|festival)\b/i],
    ['preference', /\b(enjoy|favorite|like|prefer|recommend)\b/i],
    ['current_state', /\b(currently|now|own|still|recent)\b/i],
    ['temporal', /\b(after|before|between|days?|last|when)\b/i],
  ];
  return patterns.find(([, pattern]) => pattern.test(text))?.[0] || tokens(text)[0] || 'general';
}

function subsectionLabel(state = {}) {
  return String(state.memory?.session_id || state.memory?.source || state.memory?.memory_type || 'session').toLowerCase();
}

function subsubSectionLabel(state = {}) {
  const key = String(state.memory?.key || state.id || 'memory').toLowerCase();
  const parts = key.split(/[:/_-]+/).filter(Boolean);
  return parts.slice(-2).join(':') || key;
}

function makeNode({ id, level, text, children = [], positionIndex = [] }) {
  return {
    id,
    level,
    text,
    vector: hashVector(text),
    children,
    position_index: positionIndex,
  };
}

export function buildHierarchicalMemory(states = []) {
  const contentNodes = (states || []).map((state, index) => makeNode({
    id: `content:${state.id}`,
    level: 'content',
    text: state.text || state.memory?.value || '',
    children: [],
    positionIndex: [index],
  }));
  const byContent = new Map(contentNodes.map((node, index) => [String(states[index]?.id), node]));
  const subsubMap = new Map();
  const subsectionMap = new Map();
  const sectionMap = new Map();

  for (const state of states || []) {
    const content = byContent.get(String(state.id));
    const section = sectionLabel(state);
    const subsection = subsectionLabel(state);
    const subsub = subsubSectionLabel(state);
    const subsubId = `subsub:${section}:${subsection}:${subsub}`;
    if (!subsubMap.has(subsubId)) subsubMap.set(subsubId, makeNode({ id: subsubId, level: 'subsub_section', text: `${section} ${subsection} ${subsub}`, children: [] }));
    subsubMap.get(subsubId).children.push(content);

    const subsectionId = `subsection:${section}:${subsection}`;
    if (!subsectionMap.has(subsectionId)) subsectionMap.set(subsectionId, makeNode({ id: subsectionId, level: 'subsection', text: `${section} ${subsection}`, children: [] }));
    const subNode = subsubMap.get(subsubId);
    if (!subsectionMap.get(subsectionId).children.includes(subNode)) subsectionMap.get(subsectionId).children.push(subNode);

    const sectionId = `section:${section}`;
    if (!sectionMap.has(sectionId)) sectionMap.set(sectionId, makeNode({ id: sectionId, level: 'section', text: section, children: [] }));
    const subsectionNode = subsectionMap.get(subsectionId);
    if (!sectionMap.get(sectionId).children.includes(subsectionNode)) sectionMap.get(sectionId).children.push(subsectionNode);
  }

  const sections = [...sectionMap.values()];
  const attachPointers = (node) => {
    node.position_index = node.children.flatMap((child) => child.position_index || []).slice(0, 512);
    node.text = [node.text, ...node.children.map((child) => child.text).slice(0, 8)].join(' ');
    node.vector = hashVector(node.text);
    node.children.forEach(attachPointers);
  };
  sections.forEach(attachPointers);
  return {
    levels: {
      section: sections,
      subsection: [...subsectionMap.values()],
      subsub_section: [...subsubMap.values()],
      content: contentNodes,
    },
    roots: sections,
  };
}

export function recursiveTopK(query = '', roots = [], k = HMEM_CONSTANTS.top_k) {
  let frontier = (roots || [])
    .map((node) => ({ node, score: semanticSimilarity(query, node.text), path: [node.id] }))
    .sort((a, b) => b.score - a.score || a.node.id.localeCompare(b.node.id))
    .slice(0, k);
  const visited = [...frontier];
  while (frontier.some((row) => row.node.children?.length)) {
    const next = [];
    for (const row of frontier) {
      const children = row.node.children || [];
      for (const child of children) {
        next.push({
          node: child,
          score: semanticSimilarity(query, child.text),
          path: [...row.path, child.id],
        });
      }
    }
    if (!next.length) break;
    frontier = next
      .sort((a, b) => b.score - a.score || a.node.id.localeCompare(b.node.id))
      .slice(0, k);
    visited.push(...frontier);
  }
  return visited;
}

export function confidenceWeight(score = 0, depth = 1, branching = 1) {
  const routeDepth = Math.min(1, Math.max(0, depth / HMEM_CONSTANTS.levels.length));
  const focus = 1 / Math.sqrt(Math.max(1, branching));
  return clamp01((0.72 * clamp01(score)) + (0.18 * routeDepth) + (0.10 * focus));
}

export function hmemComplexity({ a = 1, k = HMEM_CONSTANTS.top_k, d = HMEM_CONSTANTS.vector_dim } = {}) {
  return {
    baseline_ops: a * HMEM_CONSTANTS.million_scale_reference * d,
    hmem_ops: (a + (k * HMEM_CONSTANTS.per_parent_child_cap)) * d,
    formula: 'O(a*10^6*D) vs O((a+k*300)*D)',
  };
}

export function hmemScores({ queryText = '', states = [] } = {}) {
  const hierarchy = buildHierarchicalMemory((states || []).slice(0, 300));
  const route = recursiveTopK(queryText, hierarchy.roots, HMEM_CONSTANTS.top_k);
  const contentRoutes = route.filter((row) => row.node.level === 'content');
  const byContentId = new Map();
  for (const row of contentRoutes) {
    const stateId = row.node.id.replace(/^content:/, '');
    const weighted = confidenceWeight(row.score, row.path.length, route.length);
    byContentId.set(stateId, Math.max(byContentId.get(stateId) || 0, weighted));
  }
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const direct = semanticSimilarity(queryText, state.text || '');
    const routed = byContentId.get(String(state.id)) || 0;
    const score = clamp01((0.58 * routed) + (0.42 * direct));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      routed_score: Number(routed.toFixed(6)),
      direct_content_similarity: Number(direct.toFixed(6)),
      selected_by_recursive_route: routed > 0,
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: HMEM_CONSTANTS,
    guardrails: HMEM_GUARDRAILS,
    hierarchy_counts: Object.fromEntries(Object.entries(hierarchy.levels).map(([level, rows]) => [level, rows.length])),
    route_count: route.length,
    complexity: hmemComplexity({ a: Math.max(1, states.length), k: HMEM_CONSTANTS.top_k }),
    formula: 'M_k=TopK_{y in Child(x)} sim(q,y); confidence=0.72*sim+0.18*depth+0.10/sqrt(branching)',
  };
}
