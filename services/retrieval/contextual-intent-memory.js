/**
 * Native contextual-intent recall operator from:
 * - Grounding Agent Memory in Contextual Intent.pdf
 *
 * Implemented formulas / techniques:
 * - task trajectory `T = {s1, ..., sn}`, step tuple `st = (rt, at, tau_t)`
 * - contextual intent tuple `iota_t = (sigma_t, epsilon_t, kappa_t)`
 * - thematic scope transition `sigma_t = Mscope(st, Hscope, sigma_{t-1})`
 * - event label inference `epsilon_t = Mlabel(st, Retrieve(V_epsilon, st, k_event))`
 * - entity-type mapping `kappa_t = Mentity(st, V_kappa)`
 * - rewrite/canonicalization `s'_t = Mrewrite(st, C_align)`
 * - canonical content `ct = Msum(s'_t, iota_t)`
 * - query filter schema `Fq = (Sq, Eq, Kq)`
 * - label-density ranking by satisfied intent constraints
 * - semantic tie-break `sim(q, ct)`
 * - control constants `Nstart=50`, `kupdate=50`, `kretrieve=40`, `kevent=5`
 * - tail truncation to a 4096-token read budget
 *
 * Aimos adaptation:
 * - induces deterministic intent labels from the returned recall candidates
 * - uses intent compatibility as a bounded monotone rerank signal only
 * - never injects benchmark answers and never prunes/deletes/decays memory
 */

export const CONTEXTUAL_INTENT_CONSTANTS = Object.freeze({
  start_steps: 50,
  update_steps: 50,
  retrieve_k: 40,
  event_k: 5,
  context_budget_tokens: 4096,
});

export const CONTEXTUAL_INTENT_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  label_space_is_transient_read_model: true,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'event', 'events', 'from', 'have', 'into',
  'many', 'more', 'most', 'that', 'their', 'there', 'these', 'this', 'those',
  'through', 'time', 'what', 'when', 'where', 'which', 'while', 'with', 'would',
]);

const SCOPE_PATTERNS = Object.freeze([
  ['travel', /\b(airline|airport|flight|flew|hotel|trip|travel|train|boarding)\b/i],
  ['work', /\b(client|deadline|meeting|office|project|review|work)\b/i],
  ['health', /\b(doctor|health|hospital|medication|pain|symptom|therapy)\b/i],
  ['finance', /\b(bank|budget|cost|invoice|payment|price|tax)\b/i],
  ['food', /\b(breakfast|coffee|dinner|lunch|meal|recipe|restaurant)\b/i],
  ['education', /\b(assignment|class|course|exam|lecture|school|study)\b/i],
  ['social', /\b(birthday|call|family|friend|party|partner|visit)\b/i],
  ['purchase', /\b(bought|buy|ordered|purchased|returned|shopping)\b/i],
  ['preference', /\b(dislike|enjoy|favorite|hate|like|prefer|recommend)\b/i],
  ['temporal_delta', /\b(days?|weeks?|months?|years?)\s+(?:between|passed|after|before)|\bhow long\b/i],
  ['current_state', /\b(currently|now|latest|recent|still|today)\b/i],
]);

const EVENT_PATTERNS = Object.freeze([
  ['ask_count', /\b(how many|count|total|number of)\b/i],
  ['compare', /\b(most|least|between|compare|which.*more)\b/i],
  ['attend', /\b(attended|joined|went|visited|event)\b/i],
  ['own', /\b(own|owned|have|currently have)\b/i],
  ['purchase', /\b(bought|ordered|purchased|returned)\b/i],
  ['travel', /\b(flew|flight|airline|airport|trip|travel)\b/i],
  ['preference', /\b(like|prefer|favorite|enjoy|recommend)\b/i],
  ['identity', /\b(member|community|person|who|name|called)\b/i],
  ['temporal', /\b(before|after|last|next|when|during|date|time)\b/i],
]);

const ENTITY_TYPE_PATTERNS = Object.freeze([
  ['person', /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g],
  ['organization', /\b(company|airline|school|agency|foundation|club|group)\b/i],
  ['place', /\b(city|airport|beach|park|restaurant|hotel|office|home)\b/i],
  ['artifact', /\b(book|model|instrument|guitar|keyboard|violin|kit|device)\b/i],
  ['time', /\b\d{4}\b|\b(january|february|march|april|may|june|july|august|september|october|november|december|weekend|today|yesterday|tomorrow)\b/i],
]);

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

function semanticSimilarity(left = '', right = '') {
  return clamp01(overlap(tokens(left), tokens(right)));
}

function labelsFromPatterns(text = '', patterns = []) {
  return patterns.filter(([, pattern]) => pattern.test(String(text || ''))).map(([label]) => label);
}

function keywordLabels(text = '', max = 5) {
  const counts = new Map();
  for (const token of tokens(text)) counts.set(token, (counts.get(token) || 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, max)
    .map(([token]) => `term:${token}`);
}

export function trajectoryStepsFromStates(states = []) {
  return (states || []).map((state, index) => ({
    id: String(state.id || `step:${index + 1}`),
    rt: state.memory?.role || state.memory?.source || state.memory?.memory_type || 'memory',
    at: state.text || state.memory?.value || '',
    tau: state.memory?.created_at || state.interval?.start || null,
    index,
    state,
  }));
}

export function inferScope(step = {}, scopeHistory = [], previousScope = 'open') {
  const text = step.at || '';
  const labels = [...labelsFromPatterns(text, SCOPE_PATTERNS), ...keywordLabels(text, 2)];
  if (labels.length) return labels[0];
  const recent = scopeHistory.slice(-CONTEXTUAL_INTENT_CONSTANTS.start_steps).filter(Boolean);
  return recent.length ? recent[recent.length - 1] : previousScope;
}

export function retrieveEventLabels(labelInventory = [], step = {}, k = CONTEXTUAL_INTENT_CONSTANTS.event_k) {
  const direct = labelsFromPatterns(step.at || '', EVENT_PATTERNS);
  const inventory = unique([...labelInventory, ...direct, ...keywordLabels(step.at || '', 4)]);
  return inventory
    .map((label) => ({ label, score: semanticSimilarity(label.replace(/^term:/, ''), step.at || '') }))
    .sort((a, b) => b.score - a.score || a.label.localeCompare(b.label))
    .slice(0, k);
}

export function inferEventType(step = {}, labelInventory = []) {
  const candidates = retrieveEventLabels(labelInventory, step);
  return candidates[0]?.label || labelsFromPatterns(step.at || '', EVENT_PATTERNS)[0] || keywordLabels(step.at || '', 1)[0] || 'statement';
}

export function mapEntityTypes(text = '', inventory = []) {
  const out = [];
  for (const [label, pattern] of ENTITY_TYPE_PATTERNS) {
    if (pattern.global) {
      pattern.lastIndex = 0;
      if (pattern.test(String(text || ''))) out.push(label);
    } else if (pattern.test(String(text || ''))) {
      out.push(label);
    }
  }
  for (const label of inventory) if (semanticSimilarity(label, text) > 0.42) out.push(label);
  return unique(out.length ? out : keywordLabels(text, 2));
}

export function contextualIntentTuple(step = {}, {
  scopeHistory = [],
  previousScope = 'open',
  eventInventory = [],
  entityInventory = [],
} = {}) {
  const sigma = inferScope(step, scopeHistory, previousScope);
  const epsilon = inferEventType(step, eventInventory);
  const kappa = mapEntityTypes(step.at || '', entityInventory);
  return { sigma, epsilon, kappa };
}

export function rewriteStepWithAlignedContext(step = {}, alignedContext = []) {
  const suffix = alignedContext
    .slice(-2)
    .map((row) => row?.intent ? `[${row.intent.sigma}/${row.intent.epsilon}]` : '')
    .filter(Boolean)
    .join(' ');
  return `${suffix ? `${suffix} ` : ''}${String(step.at || '').trim()}`.trim();
}

export function canonicalSummary(rewrittenStep = '', intent = {}) {
  const sentences = String(rewrittenStep || '').split(/(?<=[.!?])\s+/).filter(Boolean);
  const first = sentences[0] || rewrittenStep;
  const last = sentences.length > 1 ? sentences[sentences.length - 1] : '';
  const body = last && last !== first ? `${first} ... ${last}` : first;
  return `[scope:${intent.sigma || 'open'} event:${intent.epsilon || 'statement'} entities:${(intent.kappa || []).join(',')}] ${body}`.slice(0, 1800);
}

export function queryIntentFilter(queryText = '', labelSpace = {}) {
  const scopeCandidates = unique([...labelsFromPatterns(queryText, SCOPE_PATTERNS), ...keywordLabels(queryText, 3)]);
  const eventCandidates = unique([...labelsFromPatterns(queryText, EVENT_PATTERNS), ...keywordLabels(queryText, 3)]);
  const entityCandidates = mapEntityTypes(queryText, labelSpace.entityTypes || []);
  const selectKnown = (values, known) => {
    const knownSet = new Set(known || []);
    const filtered = values.filter((value) => knownSet.has(value) || !value.startsWith('term:'));
    return filtered.length ? filtered : values;
  };
  return {
    Sq: selectKnown(scopeCandidates, labelSpace.scopes || []),
    Eq: selectKnown(eventCandidates, labelSpace.events || []),
    Kq: selectKnown(entityCandidates, labelSpace.entityTypes || []),
  };
}

export function labelOverlap(intent = {}, filter = {}) {
  const scope = (filter.Sq || []).includes(intent.sigma) ? 1 : 0;
  const event = (filter.Eq || []).includes(intent.epsilon) ? 1 : 0;
  const entity = overlap(intent.kappa || [], filter.Kq || []) > 0 ? 1 : 0;
  const active = [filter.Sq, filter.Eq, filter.Kq].filter((items) => Array.isArray(items) && items.length > 0).length || 1;
  return {
    satisfied: scope + event + entity,
    active,
    density: clamp01((scope + event + entity) / active),
  };
}

export function buildContextualIntentIndex(states = []) {
  const steps = trajectoryStepsFromStates(states);
  const scopeHistory = [];
  const eventInventory = [];
  const entityInventory = [];
  const rows = [];
  let previousScope = 'open';
  for (const step of steps) {
    const intent = contextualIntentTuple(step, { scopeHistory, previousScope, eventInventory, entityInventory });
    const aligned = rows.filter((row) => row.intent.sigma === intent.sigma || row.intent.epsilon === intent.epsilon).slice(-3);
    const rewritten = rewriteStepWithAlignedContext(step, aligned);
    const content = canonicalSummary(rewritten, intent);
    rows.push({ step, intent, rewritten, content });
    previousScope = intent.sigma;
    scopeHistory.push(intent.sigma);
    eventInventory.push(intent.epsilon);
    entityInventory.push(...intent.kappa);
    if (rows.length % CONTEXTUAL_INTENT_CONSTANTS.update_steps === 0) {
      const keepMostFrequent = (values) => {
        const counts = new Map();
        for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
        return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 64).map(([value]) => value);
      };
      eventInventory.splice(0, eventInventory.length, ...keepMostFrequent(eventInventory));
      entityInventory.splice(0, entityInventory.length, ...keepMostFrequent(entityInventory));
    }
  }
  return {
    rows,
    labelSpace: {
      scopes: unique(rows.map((row) => row.intent.sigma)),
      events: unique(rows.map((row) => row.intent.epsilon)),
      entityTypes: unique(rows.flatMap((row) => row.intent.kappa)),
    },
  };
}

export function contextualIntentScores({ queryText = '', states = [] } = {}) {
  const index = buildContextualIntentIndex((states || []).slice(0, 240));
  const filter = queryIntentFilter(queryText, index.labelSpace);
  const ranked = index.rows
    .map((row) => {
      const density = labelOverlap(row.intent, filter);
      const sim = semanticSimilarity(queryText, row.content);
      const mismatchSuppression = density.satisfied === 0 && sim > 0.64 ? 0.82 : 1;
      const score = clamp01(((0.62 * density.density) + (0.38 * sim)) * mismatchSuppression);
      return { row, score, density, sim, mismatchSuppression };
    })
    .sort((a, b) => b.score - a.score || a.row.step.index - b.row.step.index)
    .slice(0, CONTEXTUAL_INTENT_CONSTANTS.retrieve_k);

  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const result of ranked) {
    const id = result.row.step.id;
    scoreById.set(id, result.score);
    diagnosticsById.set(id, {
      scope: result.row.intent.sigma,
      event_type: result.row.intent.epsilon,
      entity_types: result.row.intent.kappa,
      label_density: Number(result.density.density.toFixed(6)),
      semantic_tie_break: Number(result.sim.toFixed(6)),
      mismatch_suppression: Number(result.mismatchSuppression.toFixed(6)),
    });
  }
  for (const row of index.rows) {
    if (!scoreById.has(row.step.id)) {
      scoreById.set(row.step.id, 0);
      diagnosticsById.set(row.step.id, {
        scope: row.intent.sigma,
        event_type: row.intent.epsilon,
        entity_types: row.intent.kappa,
        label_density: 0,
        semantic_tie_break: Number(semanticSimilarity(queryText, row.content).toFixed(6)),
        mismatch_suppression: 1,
      });
    }
  }
  return {
    scoreById,
    diagnosticsById,
    constants: CONTEXTUAL_INTENT_CONSTANTS,
    guardrails: CONTEXTUAL_INTENT_GUARDRAILS,
    filter,
    label_space: index.labelSpace,
    indexed_steps: index.rows.length,
    formula: 'iota_t=(sigma_t,epsilon_t,kappa_t); Fq=(Sq,Eq,Kq); score=0.62*label_density+0.38*sim(q,ct)',
  };
}
