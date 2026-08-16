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
 * - selected-memory relevance score carried as the confidence reference
 * - top-k routing with `k=10`
 * - complexity reporting `O(a*10^6*D)` versus `O((a+k*300)*D)`
 *
 * Aimos adaptation:
 * - builds a transient hierarchy over returned recall candidates
 * - keeps the original deterministic lexical route as a dormant B0 comparator
 * - exposes a separate dense route that accepts AIMOS's pinned local embedding
 *   vectors; it does not train or replace the embedding model
 * - the hierarchy labels remain AIMOS heuristics rather than the paper's
 *   extraction-model-produced semantic hierarchy
 * - in-memory exact sorting is used instead of FAISS
 * - never removes candidates and never mutates canonical memory
 */

export const HMEM_CONSTANTS = Object.freeze({
  levels: ['section', 'subsection', 'subsub_section', 'content'],
  top_k: 10,
  per_parent_child_cap: 300,
  million_scale_reference: 1_000_000,
  vector_dim: 64,
  dense_vector_dim: 768,
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

function finiteInteger(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function validStates(states) {
  if (!Array.isArray(states)) return [];
  const unique = new Map();
  for (const state of states) {
    if (!state || typeof state !== 'object') continue;
    const id = String(state.id || '').trim();
    if (!id || unique.has(id)) continue;
    unique.set(id, state);
  }
  return [...unique.values()];
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
  const safeDim = finiteInteger(dim, HMEM_CONSTANTS.vector_dim, 1, 4096);
  const vector = Array.from({ length: safeDim }, () => 0);
  for (const token of tokens(text)) {
    let hash = 2166136261;
    for (let i = 0; i < token.length; i += 1) {
      hash ^= token.charCodeAt(i);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    vector[hash % safeDim] += 1;
  }
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + (value * value), 0)) || 1;
  return vector.map((value) => value / norm);
}

export function cosine(left = [], right = []) {
  if (!Array.isArray(left) || !Array.isArray(right)) return 0;
  if (left.length === 0 || left.length !== right.length) return 0;
  const n = left.length;
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
  return clamp01(cosine(hashVector(query), hashVector(text)));
}

function denseVector(value, expectedDimension = HMEM_CONSTANTS.dense_vector_dim) {
  let vector = null;
  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    vector = Array.from(value, Number);
  } else {
    const text = String(value || '').trim();
    if (text.startsWith('[') && text.endsWith(']')) {
      vector = text.slice(1, -1).split(',').map(Number);
    }
  }
  if (!vector?.length || vector.some((entry) => !Number.isFinite(entry))) return null;
  if (expectedDimension != null && vector.length !== expectedDimension) return null;
  const norm = Math.sqrt(vector.reduce((sum, entry) => sum + (entry * entry), 0));
  if (!Number.isFinite(norm) || norm === 0) return null;
  return vector.map((entry) => entry / norm);
}

function denseSimilarity(queryVector, candidateVector) {
  const similarity = cosine(queryVector, candidateVector);
  return Number.isFinite(similarity) ? Math.max(-1, Math.min(1, similarity)) : -1;
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
  const normalizedStates = validStates(states);
  const contentNodes = normalizedStates.map((state, index) => makeNode({
    id: `content:${state.id}`,
    level: 'content',
    text: state.text || state.memory?.value || '',
    children: [],
    positionIndex: [index],
  }));
  const byContent = new Map(contentNodes.map((node, index) => [String(normalizedStates[index].id), node]));
  const subsubMap = new Map();
  const subsectionMap = new Map();
  const sectionMap = new Map();

  for (const state of normalizedStates) {
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
  const attachPointers = (node, visiting = new Set()) => {
    if (visiting.has(node.id)) throw new Error(`hmem_hierarchy_cycle:${node.id}`);
    if (!node.children.length) return node;

    visiting.add(node.id);
    for (const child of node.children) attachPointers(child, visiting);
    visiting.delete(node.id);

    node.position_index = [...new Set(node.children.flatMap((child) => child.position_index || []))]
      .sort((a, b) => a - b)
      .slice(0, 512);
    node.text = [node.text, ...node.children.map((child) => child.text).slice(0, 8)].join(' ');
    node.vector = hashVector(node.text);
    return node;
  };
  sections.forEach((node) => attachPointers(node));
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
  const safeK = finiteInteger(k, HMEM_CONSTANTS.top_k, 0, 1000);
  if (safeK === 0) return [];
  const uniqueRoots = new Map();
  for (const node of Array.isArray(roots) ? roots : []) {
    if (!node || typeof node !== 'object') continue;
    const id = String(node.id || '').trim();
    if (!id || uniqueRoots.has(id)) continue;
    uniqueRoots.set(id, node);
  }
  let frontier = [...uniqueRoots.values()]
    .map((node) => ({ node, score: semanticSimilarity(query, node.text), path: [String(node.id)] }))
    .sort((a, b) => b.score - a.score || String(a.node.id).localeCompare(String(b.node.id)))
    .slice(0, safeK);
  const visited = [...frontier];
  const seenIds = new Set(frontier.map((row) => String(row.node.id)));
  while (frontier.some((row) => row.node.children?.length)) {
    const nextById = new Map();
    for (const row of frontier) {
      const children = Array.isArray(row.node.children) ? row.node.children : [];
      const rankedChildren = children
        .filter((child) => child && typeof child === 'object' && String(child.id || '').trim())
        .map((child) => ({
          node: child,
          score: semanticSimilarity(query, child.text),
          path: [...row.path, String(child.id)],
        }))
        .filter((childRow) => !seenIds.has(String(childRow.node.id)))
        .sort((a, b) => b.score - a.score || String(a.node.id).localeCompare(String(b.node.id)))
        .slice(0, safeK);
      for (const childRow of rankedChildren) {
        const childId = String(childRow.node.id);
        const current = nextById.get(childId);
        if (!current || childRow.score > current.score
          || (childRow.score === current.score && childRow.path.join('\u0000') < current.path.join('\u0000'))) {
          nextById.set(childId, childRow);
        }
      }
    }
    const next = [...nextById.values()]
      .sort((a, b) => b.score - a.score || String(a.node.id).localeCompare(String(b.node.id)));
    if (!next.length) break;
    frontier = next;
    for (const row of frontier) seenIds.add(String(row.node.id));
    visited.push(...frontier);
  }
  return visited;
}

export function recursiveDenseTopK(
  queryVector = [],
  roots = [],
  k = HMEM_CONSTANTS.top_k,
  { expectedDimension = HMEM_CONSTANTS.dense_vector_dim } = {},
) {
  const normalizedQuery = denseVector(queryVector, expectedDimension);
  if (!normalizedQuery) throw new Error('hmem_dense_query_vector_invalid');
  const safeK = finiteInteger(k, HMEM_CONSTANTS.top_k, 0, 1000);
  if (safeK === 0) return [];

  const uniqueRoots = new Map();
  for (const node of Array.isArray(roots) ? roots : []) {
    if (!node || typeof node !== 'object') continue;
    const id = String(node.id || '').trim();
    if (!id || uniqueRoots.has(id)) continue;
    const vector = denseVector(node.vector, expectedDimension);
    if (!vector) throw new Error(`hmem_dense_node_vector_invalid:${id}`);
    uniqueRoots.set(id, { ...node, vector });
  }

  let frontier = [...uniqueRoots.values()]
    .map((node) => ({
      node,
      score: denseSimilarity(normalizedQuery, node.vector),
      path: [String(node.id)],
    }))
    .sort((left, right) => right.score - left.score || String(left.node.id).localeCompare(String(right.node.id)))
    .slice(0, safeK);
  const visited = [...frontier];
  const seenIds = new Set(frontier.map((row) => String(row.node.id)));

  while (frontier.some((row) => row.node.children?.length)) {
    const nextById = new Map();
    for (const row of frontier) {
      const rankedChildren = (Array.isArray(row.node.children) ? row.node.children : [])
        .filter((child) => child && typeof child === 'object' && String(child.id || '').trim())
        .map((child) => {
          const childId = String(child.id);
          const vector = denseVector(child.vector, expectedDimension);
          if (!vector) throw new Error(`hmem_dense_node_vector_invalid:${childId}`);
          return {
            node: { ...child, vector },
            score: denseSimilarity(normalizedQuery, vector),
            path: [...row.path, childId],
          };
        })
        .filter((childRow) => !seenIds.has(String(childRow.node.id)))
        .sort((left, right) => right.score - left.score || String(left.node.id).localeCompare(String(right.node.id)))
        .slice(0, safeK);
      for (const childRow of rankedChildren) {
        const childId = String(childRow.node.id);
        const current = nextById.get(childId);
        if (!current || childRow.score > current.score
          || (childRow.score === current.score && childRow.path.join('\u0000') < current.path.join('\u0000'))) {
          nextById.set(childId, childRow);
        }
      }
    }
    const next = [...nextById.values()]
      .sort((left, right) => right.score - left.score || String(left.node.id).localeCompare(String(right.node.id)));
    if (!next.length) break;
    frontier = next;
    for (const row of frontier) seenIds.add(String(row.node.id));
    visited.push(...frontier);
  }
  return visited;
}

export async function buildDenseHierarchicalMemory(
  states = [],
  {
    embedText,
    expectedDimension = HMEM_CONSTANTS.dense_vector_dim,
  } = {},
) {
  if (typeof embedText !== 'function') throw new Error('hmem_dense_embedder_required');
  const normalizedStates = validStates(states);
  const hierarchy = buildHierarchicalMemory(normalizedStates);
  const stateByContentId = new Map(normalizedStates.map((state) => [`content:${state.id}`, state]));
  const visited = new Set();

  const attachDenseVector = async (node) => {
    if (visited.has(node.id)) return;
    visited.add(node.id);
    for (const child of Array.isArray(node.children) ? node.children : []) {
      await attachDenseVector(child);
    }
    const state = stateByContentId.get(node.id);
    const supplied = denseVector(state?.embedding ?? state?.memory?.embedding, expectedDimension);
    const embedded = supplied || denseVector(await embedText(node.text), expectedDimension);
    if (!embedded) throw new Error(`hmem_dense_embedding_invalid:${node.id}`);
    node.vector = embedded;
  };

  for (const root of hierarchy.roots) await attachDenseVector(root);
  return {
    ...hierarchy,
    vector_contract: Object.freeze({
      representation: 'dense_unit_vector',
      dimension: expectedDimension,
      training_required: false,
      hierarchy_source: 'aimos_deterministic_heuristic',
      paper_hierarchy_parity: false,
      index_backend: 'in_memory_exact_sort',
      paper_faiss_parity: false,
    }),
  };
}

export async function hmemDenseCandidate({
  queryVector = [],
  states = [],
  embedText,
  expectedDimension = HMEM_CONSTANTS.dense_vector_dim,
  topK = HMEM_CONSTANTS.top_k,
} = {}) {
  const normalizedStates = validStates(states);
  const normalizedQuery = denseVector(queryVector, expectedDimension);
  if (!normalizedQuery) throw new Error('hmem_dense_query_vector_invalid');
  const hierarchy = await buildDenseHierarchicalMemory(normalizedStates, {
    embedText,
    expectedDimension,
  });
  const route = recursiveDenseTopK(normalizedQuery, hierarchy.roots, topK, { expectedDimension });
  const selected = route
    .filter((row) => row.node.level === 'content')
    .sort((left, right) => right.score - left.score || String(left.node.id).localeCompare(String(right.node.id)))
    .slice(0, finiteInteger(topK, HMEM_CONSTANTS.top_k, 0, 1000));
  const stateById = new Map(normalizedStates.map((state) => [String(state.id), state]));
  const ranked = selected.map((row, index) => {
    const memoryId = row.node.id.replace(/^content:/, '');
    return Object.freeze({
      rank: index + 1,
      memory_id: memoryId,
      cosine_similarity: Number(row.score.toFixed(9)),
      confidence_reference: Number(row.score.toFixed(9)),
      path: Object.freeze([...row.path]),
      state: stateById.get(memoryId),
    });
  });
  return Object.freeze({
    ranked: Object.freeze(ranked),
    selected_memory_ids: Object.freeze(ranked.map((row) => row.memory_id)),
    route_count: route.length,
    hierarchy_counts: Object.freeze(
      Object.fromEntries(Object.entries(hierarchy.levels).map(([level, rows]) => [level, rows.length])),
    ),
    vector_contract: hierarchy.vector_contract,
    guardrails: HMEM_GUARDRAILS,
    formula: 'M_k=union_{x in M_{k-1}} TopK_{y in Child(x)} cosine(q,y)',
  });
}

export function confidenceWeight(score = 0, depth = 1, branching = 1) {
  void depth;
  void branching;
  return clamp01(score);
}

export function hmemComplexity({ a = 1, k = HMEM_CONSTANTS.top_k, d = HMEM_CONSTANTS.vector_dim } = {}) {
  return {
    baseline_ops: a * HMEM_CONSTANTS.million_scale_reference * d,
    hmem_ops: (a + (k * HMEM_CONSTANTS.per_parent_child_cap)) * d,
    formula: 'O(a*10^6*D) vs O((a+k*300)*D)',
  };
}

export function hmemScores({ queryText = '', states = [] } = {}) {
  const normalizedStates = validStates(states);
  const hierarchy = buildHierarchicalMemory(normalizedStates.slice(0, 300));
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
  for (const state of normalizedStates) {
    const direct = semanticSimilarity(queryText, state.text || state.memory?.value || '');
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
    complexity: hmemComplexity({ a: Math.max(1, normalizedStates.length), k: HMEM_CONSTANTS.top_k }),
    formula: 'M_k=TopK_{y in Child(x)} sim(q,y); confidence=selected_similarity_score',
  };
}
