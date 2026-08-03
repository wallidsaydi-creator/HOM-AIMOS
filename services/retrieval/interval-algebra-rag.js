/**
 * interval-algebra-rag.js - interval-aware RAG and grounded tiered retrieval operators
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * retrieval/index.js.
 * Runtime note: pure deterministic math/state transformations. This file does
 * not call providers, mutate memory, prune evidence, apply canonical decay, or
 * delete records. In recall it contributes interval-aware evidence signals to
 * bounded native scoring.
 *
 * Paper authority:
 * - IA-RAG.pdf
 * - Mitigating LLM Hallucinations through Domain-Grounded Tiered Retrieval.pdf
 */

export const ALADDIN_INTERVAL_RAG_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Operators produce derived interval graphs, retrieval plans, and verification diagnostics only.',
});

export const ALLEN_INTERVAL_RELATIONS = Object.freeze([
  'before',
  'meets',
  'overlaps',
  'starts',
  'during',
  'finishes',
  'equals',
  'after',
  'met_by',
  'overlapped_by',
  'started_by',
  'contains',
  'finished_by',
]);

export const IA_RAG_DEFAULTS = Object.freeze({
  top_q_neighbors: 50,
  tau_sem: 0.8,
  min_cluster_size: 2,
  max_levels: 4,
  threshold_decay_factor: 0.95,
  min_threshold: 0.6,
  max_threshold: 0.85,
  max_workers: 32,
  top_k_macro: 10,
  top_k_interval: 20,
});

export const IA_RAG_FORWARD_RELATIONS = Object.freeze([
  'before',
  'meets',
  'overlaps',
  'starts',
  'during',
  'finishes',
  'equals',
]);

export const IA_RAG_BACKWARD_RELATIONS = Object.freeze([
  'after',
  'met_by',
  'overlapped_by',
  'started_by',
  'contains',
  'finished_by',
  'equals',
]);

export const TIERED_RETRIEVAL_DEFAULTS = Object.freeze({
  intrinsic_threshold: 0.78,
  retrieved_threshold: 0.62,
  context_threshold: 0.42,
  entropy_threshold: 0.35,
  tiers: ['domain', 'trusted', 'general'],
});

function text(value) {
  return String(value ?? '').trim();
}

function normText(value) {
  return text(value).toLowerCase();
}

function tokenize(value) {
  return normText(value).split(/[^a-z0-9]+/).filter(Boolean);
}

function finiteOr(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function dateToNumber(value, fallback = NaN) {
  if (value === -Infinity || value === Infinity) return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : fallback;
  const raw = text(value);
  if (!raw) return fallback;
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) return Number(raw);
  const parsed = Date.parse(raw.length === 4 ? `${raw}-01-01T00:00:00Z` : raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function dot(a = [], b = []) {
  const n = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < n; i += 1) sum += (Number(a[i]) || 0) * (Number(b[i]) || 0);
  return sum;
}

function norm(vector = []) {
  return Math.sqrt(vector.reduce((sum, value) => sum + (Number(value) || 0) ** 2, 0));
}

export function cosineSimilarity(a = [], b = []) {
  const denom = norm(a) * norm(b);
  return denom ? dot(a, b) / denom : 0;
}

export function tokenJaccard(left = '', right = '') {
  const a = new Set(tokenize(left));
  const b = new Set(tokenize(right));
  if (!a.size && !b.size) return 0;
  let intersection = 0;
  for (const token of a) if (b.has(token)) intersection += 1;
  return intersection / (a.size + b.size - intersection || 1);
}

export function normalizeInterval(input = {}) {
  const startRaw = input.start ?? input.tstart ?? input.from ?? input.begin ?? input.time ?? input.timestamp;
  const endRaw = input.end ?? input.tend ?? input.to ?? input.finish ?? input.time ?? input.timestamp ?? startRaw;
  let start = dateToNumber(startRaw, -Infinity);
  let end = dateToNumber(endRaw, Infinity);
  if (start > end) [start, end] = [end, start];
  return {
    start,
    end,
    start_raw: startRaw ?? null,
    end_raw: endRaw ?? null,
    bounded: Number.isFinite(start) && Number.isFinite(end),
  };
}

export function createIntervalEventUnit({
  id,
  session,
  content,
  start,
  end,
  factuality = 1,
  source = '',
  embedding = [],
  metadata = {},
} = {}) {
  const interval = normalizeInterval({ start, end });
  return {
    id: text(id || metadata.id || content).slice(0, 160),
    session: text(session || metadata.session || ''),
    content: text(content || metadata.content || ''),
    interval,
    factuality: factuality ? 1 : 0,
    source: text(source || metadata.source || ''),
    embedding: Array.isArray(embedding) ? embedding.map(value => Number(value) || 0) : [],
    metadata: { ...metadata },
  };
}

export function allenRelation(left = {}, right = {}) {
  const a = left.interval ? left.interval : normalizeInterval(left);
  const b = right.interval ? right.interval : normalizeInterval(right);
  if (a.start === b.start && a.end === b.end) return 'equals';
  if (a.end < b.start) return 'before';
  if (a.end === b.start) return 'meets';
  if (a.start > b.end) return 'after';
  if (a.start === b.end) return 'met_by';
  if (a.start === b.start && a.end < b.end) return 'starts';
  if (a.start === b.start && a.end > b.end) return 'started_by';
  if (a.end === b.end && a.start > b.start) return 'finishes';
  if (a.end === b.end && a.start < b.start) return 'finished_by';
  if (a.start > b.start && a.end < b.end) return 'during';
  if (a.start < b.start && a.end > b.end) return 'contains';
  if (a.start < b.start && a.end > b.start && a.end < b.end) return 'overlaps';
  if (a.start > b.start && a.start < b.end && a.end > b.end) return 'overlapped_by';
  return 'overlaps';
}

export function semanticCompatibility(left = {}, right = {}, tau = IA_RAG_DEFAULTS.tau_sem) {
  const vectorScore = left.embedding?.length && right.embedding?.length
    ? cosineSimilarity(left.embedding, right.embedding)
    : 0;
  const lexicalScore = tokenJaccard(left.content || left.text || '', right.content || right.text || '');
  const score = Math.max(vectorScore, lexicalScore);
  return {
    compatible: score >= tau ? 1 : 0,
    score,
    threshold: tau,
    method: vectorScore >= lexicalScore ? 'cosine' : 'token_jaccard',
  };
}

export function topQNeighbors(events = [], event = {}, {
  q = IA_RAG_DEFAULTS.top_q_neighbors,
  tauSem = IA_RAG_DEFAULTS.tau_sem,
} = {}) {
  const target = event.id ? event : createIntervalEventUnit(event);
  return events
    .filter(row => text(row.id) !== text(target.id))
    .map(row => ({ event: row, ...semanticCompatibility(target, row, tauSem) }))
    .filter(row => row.compatible)
    .sort((a, b) => b.score - a.score || text(a.event.id).localeCompare(text(b.event.id)))
    .slice(0, q);
}

export function buildIntervalEventGraph(events = [], {
  tauSem = IA_RAG_DEFAULTS.tau_sem,
  q = IA_RAG_DEFAULTS.top_q_neighbors,
} = {}) {
  const nodes = events.map(event => event.interval ? event : createIntervalEventUnit(event));
  const edges = [];
  for (const node of nodes) {
    for (const neighbor of topQNeighbors(nodes, node, { q, tauSem })) {
      edges.push({
        from: node.id,
        to: neighbor.event.id,
        relation: allenRelation(node, neighbor.event),
        semantic_score: neighbor.score,
        semantic_method: neighbor.method,
      });
    }
  }
  return {
    aladdin: ALADDIN_INTERVAL_RAG_GUARDRAILS,
    nodes,
    edges,
    defaults: IA_RAG_DEFAULTS,
  };
}

export function connectedComponents(graph = {}) {
  const adjacency = new Map();
  for (const node of graph.nodes || []) adjacency.set(node.id, new Set());
  for (const edge of graph.edges || []) {
    if (!adjacency.has(edge.from)) adjacency.set(edge.from, new Set());
    if (!adjacency.has(edge.to)) adjacency.set(edge.to, new Set());
    adjacency.get(edge.from).add(edge.to);
    adjacency.get(edge.to).add(edge.from);
  }
  const seen = new Set();
  const components = [];
  for (const id of adjacency.keys()) {
    if (seen.has(id)) continue;
    const queue = [id];
    const component = [];
    seen.add(id);
    while (queue.length) {
      const current = queue.shift();
      component.push(current);
      for (const next of adjacency.get(current) || []) {
        if (seen.has(next)) continue;
        seen.add(next);
        queue.push(next);
      }
    }
    components.push(component);
  }
  return components;
}

export function macroEventUnit(componentIds = [], graph = {}) {
  const byId = new Map((graph.nodes || []).map(node => [node.id, node]));
  const members = componentIds.map(id => byId.get(id)).filter(Boolean);
  const starts = members.map(row => row.interval.start).filter(Number.isFinite);
  const ends = members.map(row => row.interval.end).filter(Number.isFinite);
  return {
    id: `meu:${componentIds.join('+')}`,
    children: componentIds,
    content: members.map(row => row.content).filter(Boolean).join(' '),
    interval: {
      start: starts.length ? Math.min(...starts) : -Infinity,
      end: ends.length ? Math.max(...ends) : Infinity,
      bounded: Boolean(starts.length && ends.length),
    },
    source_count: new Set(members.map(row => row.source).filter(Boolean)).size,
    size: members.length,
  };
}

export function localThresholdForLevel(level = 0, {
  maxThreshold = IA_RAG_DEFAULTS.max_threshold,
  minThreshold = IA_RAG_DEFAULTS.min_threshold,
  thresholdDecayFactor = IA_RAG_DEFAULTS.threshold_decay_factor,
} = {}) {
  const scheduled = maxThreshold * (thresholdDecayFactor ** Math.max(0, Number(level) || 0));
  return Math.max(minThreshold, Math.min(maxThreshold, scheduled));
}

export function buildTemporalHierarchy(events = [], options = {}) {
  const maxLevels = finiteOr(options.maxLevels, IA_RAG_DEFAULTS.max_levels);
  const minClusterSize = finiteOr(options.minClusterSize, IA_RAG_DEFAULTS.min_cluster_size);
  const levels = [];
  let currentEvents = events.map(event => event.interval ? event : createIntervalEventUnit(event));
  for (let level = 0; level < maxLevels && currentEvents.length; level += 1) {
    const tauSem = options.tauSem ?? localThresholdForLevel(level, options);
    const graph = buildIntervalEventGraph(currentEvents, { tauSem, q: options.q ?? IA_RAG_DEFAULTS.top_q_neighbors });
    const components = connectedComponents(graph);
    const macros = components
      .filter(component => component.length >= minClusterSize)
      .map(component => macroEventUnit(component, graph));
    levels.push({ level, graph, components, macros, tauSem });
    if (!macros.length || macros.length === currentEvents.length) break;
    currentEvents = macros.map(row => createIntervalEventUnit({
      id: row.id,
      content: row.content,
      start: row.interval.start,
      end: row.interval.end,
      source: 'macro_event_unit',
      metadata: { children: row.children, level: level + 1 },
    }));
  }
  const containment = [];
  for (const level of levels) {
    for (const macro of level.macros) {
      for (const child of macro.children) containment.push({ macro: macro.id, child, level: level.level + 1 });
    }
  }
  return {
    aladdin: ALADDIN_INTERVAL_RAG_GUARDRAILS,
    levels,
    containment,
  };
}

export function queryTemporalWindow(question = '', { referenceDate = new Date() } = {}) {
  const q = normText(question);
  const explicit = q.match(/\b(?:19|20)\d{2}(?:-\d{2}(?:-\d{2})?)?\b/g) || [];
  const monthNames = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december'];
  const monthMatches = [...q.matchAll(/\b(january|february|march|april|may|june|july|august|september|october|november|december)\b/g)].map(match => match[1]);
  if (monthMatches.length) {
    const year = Number((q.match(/\b(?:19|20)\d{2}\b/) || [new Date(referenceDate).getUTCFullYear()])[0]);
    const indexes = monthMatches.map(month => monthNames.indexOf(month)).filter(index => index >= 0).sort((a, b) => a - b);
    const startMonth = indexes[0];
    const endMonth = indexes.at(-1);
    const start = Date.UTC(year, startMonth, 1);
    const end = Date.UTC(year, endMonth + 1, 0, 23, 59, 59, 999);
    return { start, end, source: monthMatches.length > 1 ? 'multi_month_scope' : 'month_scope', months: monthMatches };
  }
  if (explicit.length >= 2) {
    const values = explicit.map(value => dateToNumber(value, NaN)).filter(Number.isFinite).sort((a, b) => a - b);
    if (values.length >= 2) return { start: values[0], end: values.at(-1), source: 'explicit_range' };
  }
  if (explicit.length === 1) {
    const start = dateToNumber(explicit[0], NaN);
    if (Number.isFinite(start)) return { start, end: start, source: 'explicit_point' };
  }
  return { start: -Infinity, end: Infinity, source: 'unbounded' };
}

export function traversalGate(interval = {}, window = {}) {
  const row = interval.interval ? interval.interval : normalizeInterval(interval);
  const scope = window.interval ? window.interval : normalizeInterval({ start: window.start, end: window.end });
  if (row.end < scope.start) return 'F';
  if (row.start > scope.end) return 'R';
  return 'B';
}

export function queryEventSimilarity(query = '', event = {}) {
  const lexical = tokenJaccard(query, event.content || event.text || '');
  const factual = event.factuality === 0 ? 0.5 : 1;
  return lexical * factual;
}

export function topKForestRetrieval({ query = '', hierarchy = {}, kMacro = IA_RAG_DEFAULTS.top_k_macro, kInterval = IA_RAG_DEFAULTS.top_k_interval } = {}) {
  const macros = (hierarchy.levels || []).flatMap(level => level.macros.map(row => ({ ...row, level: level.level })));
  const intervals = (hierarchy.levels?.[0]?.graph?.nodes || []);
  const rankedMacros = macros
    .map(row => ({ ...row, score: queryEventSimilarity(query, row) }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, kMacro);
  const rankedIntervals = intervals
    .map(row => ({ ...row, score: queryEventSimilarity(query, row) }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, kInterval);
  return { macro_hits: rankedMacros, interval_hits: rankedIntervals };
}

export function intervalSupportSets({ graph = {}, seeds = [], window = { start: -Infinity, end: Infinity } } = {}) {
  const seedIds = new Set(seeds.map(row => text(row.id || row)));
  const byId = new Map((graph.nodes || []).map(node => [node.id, node]));
  const support = [];
  for (const edge of graph.edges || []) {
    const startsAtSeed = seedIds.has(edge.from);
    const endsAtSeed = seedIds.has(edge.to);
    if (!startsAtSeed && !endsAtSeed) continue;
    const targetId = startsAtSeed ? edge.to : edge.from;
    const rel = startsAtSeed ? edge.relation : allenRelation(byId.get(targetId), byId.get(edge.to));
    const target = byId.get(targetId);
    if (!target) continue;
    const gate = traversalGate(target, window);
    const allowed = gate === 'B'
      || (gate === 'F' && IA_RAG_FORWARD_RELATIONS.includes(rel))
      || (gate === 'R' && IA_RAG_BACKWARD_RELATIONS.includes(rel));
    if (allowed) support.push({ ...target, support_relation: rel, traversal_gate: gate, support_from: startsAtSeed ? edge.from : edge.to });
  }
  return support;
}

export function intervalAwareRetrieve({ query = '', events = [], referenceDate = new Date(), options = {} } = {}) {
  const hierarchy = buildTemporalHierarchy(events, options);
  const window = queryTemporalWindow(query, { referenceDate });
  const graph = hierarchy.levels?.[0]?.graph || buildIntervalEventGraph(events, options);
  const direct = topKForestRetrieval({ query, hierarchy, kMacro: options.kMacro, kInterval: options.kInterval });
  const support = intervalSupportSets({ graph, seeds: direct.interval_hits, window });
  const merged = new Map();
  for (const row of [...direct.interval_hits, ...support]) {
    const previous = merged.get(row.id);
    if (!previous || (Number(row.score) || 0) > (Number(previous.score) || 0)) merged.set(row.id, row);
  }
  return {
    aladdin: ALADDIN_INTERVAL_RAG_GUARDRAILS,
    query,
    temporal_window: window,
    hierarchy,
    direct,
    support,
    target_events: [...merged.values()].sort((a, b) => (Number(b.score) || 0) - (Number(a.score) || 0)),
  };
}

export function intrinsicVerification({ answer = '', score = 0, threshold = TIERED_RETRIEVAL_DEFAULTS.intrinsic_threshold, constraintViolations = [] } = {}) {
  const ok = text(answer) && (Number(score) || 0) >= threshold && !constraintViolations.length;
  return {
    passed: Boolean(ok),
    should_exit: Boolean(ok),
    score: Number(score) || 0,
    threshold,
    constraint_violations: [...constraintViolations],
  };
}

export function detectDomain(query = '', domains = []) {
  const tokens = new Set(tokenize(query));
  const scored = domains.map(domain => {
    const keywords = (domain.keywords || []).map(normText);
    const score = keywords.reduce((sum, keyword) => sum + (tokens.has(keyword) || normText(query).includes(keyword) ? 1 : 0), 0);
    return { id: text(domain.id || domain.name), score, domain };
  }).sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  return scored[0]?.score > 0 ? scored[0] : { id: 'general', score: 0, domain: null };
}

export function scoreRetrievedDocument(query = '', document = {}) {
  const content = text(document.content || document.text || document.body || document);
  const base = Math.max(tokenJaccard(query, content), Number(document.score) || 0);
  const authority = document.trusted || document.source_tier === 'trusted' || document.source_tier === 'domain' ? 0.1 : 0;
  return Math.min(1, base + authority);
}

export function routeTieredRetrieval({ query = '', domains = [], domain = null, domainCorpus = [], trustedCorpus = [], generalCorpus = [] } = {}) {
  const detected = domain || detectDomain(query, domains);
  const tiers = [];
  if (detected.id !== 'general') tiers.push({ tier: 'domain', documents: domainCorpus });
  tiers.push({ tier: 'trusted', documents: trustedCorpus });
  tiers.push({ tier: 'general', documents: generalCorpus });
  return tiers.map(stage => ({
    tier: stage.tier,
    documents: stage.documents.map((document, index) => ({
      ...document,
      tier: stage.tier,
      original_index: index,
      retrieved_score: scoreRetrievedDocument(query, document),
    })).sort((a, b) => b.retrieved_score - a.retrieved_score || a.original_index - b.original_index),
  }));
}

export function refinedContextFilter({ query = '', documents = [], threshold = TIERED_RETRIEVAL_DEFAULTS.context_threshold } = {}) {
  return documents
    .map(document => ({ ...document, context_score: scoreRetrievedDocument(query, document) }))
    .filter(document => document.context_score >= threshold)
    .sort((a, b) => b.context_score - a.context_score || (a.original_index || 0) - (b.original_index || 0));
}

export function atomicClaims(answer = '') {
  return text(answer)
    .split(/(?:[.;]\s+|\n+|\s+\band\b\s+)/i)
    .map(claim => claim.trim())
    .filter(Boolean);
}

export function verifyAtomicClaims({ claims = [], context = [], threshold = TIERED_RETRIEVAL_DEFAULTS.context_threshold } = {}) {
  const rows = claims.map(claim => {
    const matches = context
      .map(document => ({ document, score: scoreRetrievedDocument(claim, document) }))
      .sort((a, b) => b.score - a.score);
    const best = matches[0] || { document: null, score: 0 };
    return {
      claim,
      supported: best.score >= threshold,
      support_score: best.score,
      support: best.document,
    };
  });
  return {
    claims: rows,
    groundedness: rows.length ? rows.filter(row => row.supported).length / rows.length : 0,
    hallucination_rate: rows.length ? rows.filter(row => !row.supported).length / rows.length : 0,
  };
}

export function semanticEntropy(probabilities = []) {
  const rows = probabilities.map(Number).filter(value => Number.isFinite(value) && value > 0);
  const total = rows.reduce((sum, value) => sum + value, 0) || 1;
  return -rows.reduce((sum, value) => {
    const p = value / total;
    return sum + p * Math.log(p);
  }, 0);
}

export function adaptiveHaltingCriteria({
  intrinsic = null,
  retrievedScore = 0,
  entropy = 0,
  intrinsicThreshold = TIERED_RETRIEVAL_DEFAULTS.intrinsic_threshold,
  retrievedThreshold = TIERED_RETRIEVAL_DEFAULTS.retrieved_threshold,
  entropyThreshold = TIERED_RETRIEVAL_DEFAULTS.entropy_threshold,
} = {}) {
  if (intrinsic?.should_exit) return { halt: true, reason: 'intrinsic_verified' };
  if ((Number(retrievedScore) || 0) >= retrievedThreshold && (Number(entropy) || 0) <= entropyThreshold) {
    return { halt: true, reason: 'retrieved_confident_low_entropy' };
  }
  if ((Number(retrievedScore) || 0) < retrievedThreshold) return { halt: false, reason: 'needs_tier_escalation' };
  return { halt: false, reason: 'needs_extrinsic_verification' };
}

export function domainGroundedTieredRetrieval({
  query = '',
  draftAnswer = '',
  intrinsicScore = 0,
  constraintViolations = [],
  domains = [],
  domainCorpus = [],
  trustedCorpus = [],
  generalCorpus = [],
  thresholds = {},
} = {}) {
  const config = { ...TIERED_RETRIEVAL_DEFAULTS, ...thresholds };
  const intrinsic = intrinsicVerification({
    answer: draftAnswer,
    score: intrinsicScore,
    threshold: config.intrinsic_threshold,
    constraintViolations,
  });
  if (intrinsic.should_exit) {
    return { aladdin: ALADDIN_INTERVAL_RAG_GUARDRAILS, query, intrinsic, tiers: [], context: [], verification: null, output_policy: 'early_exit' };
  }
  const routed = routeTieredRetrieval({ query, domains, domainCorpus, trustedCorpus, generalCorpus });
  const context = [];
  const exhausted = [];
  for (const stage of routed) {
    const filtered = refinedContextFilter({ query, documents: stage.documents, threshold: config.context_threshold });
    exhausted.push({ tier: stage.tier, retrieved: stage.documents.length, retained: filtered.length });
    context.push(...filtered);
    if (filtered.length) break;
  }
  const claims = atomicClaims(draftAnswer);
  const verification = verifyAtomicClaims({ claims, context, threshold: config.context_threshold });
  const bestRetrievedScore = context[0]?.context_score || 0;
  const halt = adaptiveHaltingCriteria({
    intrinsic,
    retrievedScore: bestRetrievedScore,
    entropy: semanticEntropy(context.map(row => row.context_score)),
    retrievedThreshold: config.retrieved_threshold,
    entropyThreshold: config.entropy_threshold,
  });
  return {
    aladdin: ALADDIN_INTERVAL_RAG_GUARDRAILS,
    query,
    intrinsic,
    tiers: exhausted,
    context,
    verification,
    halt,
    output_policy: context.length ? 'regenerate_with_verified_context' : 'abstain_or_apologize',
  };
}

export function reliabilityMetrics(rows = []) {
  const n = rows.length || 1;
  const correct = rows.filter(row => row.correct === true).length;
  const grounded = rows.filter(row => row.grounded === true).length;
  const hallucinated = rows.filter(row => row.hallucinated === true).length;
  const ties = rows.filter(row => row.tie === true).length;
  const wins = rows.filter(row => row.win === true).length;
  const baselineWins = rows.filter(row => row.baseline_win === true).length;
  return {
    exact_match: correct / n,
    groundedness: grounded / n,
    hallucination_rate: hallucinated / n,
    tie_rate: ties / n,
    win_rate: wins / n,
    baseline_win_rate: baselineWins / n,
    combined_ties: (ties + rows.filter(row => row.ambiguous === true).length) / n,
  };
}

export function numericalProximity(predicted, expected, tolerance = 0) {
  const p = Number(predicted);
  const e = Number(expected);
  if (!Number.isFinite(p) || !Number.isFinite(e)) return false;
  return Math.abs(p - e) <= tolerance;
}
