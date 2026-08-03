/**
 * Native AI Hippocampus memory-system recall operator from:
 * - The AI Hippocampus- How Far are We From Human Memory?.pdf
 *
 * Implemented formulas / techniques:
 * - implicit, explicit, and agentic memory taxonomy
 * - Complementary Learning Systems decomposition:
 *   parameter/implicit memory plus hippocampal explicit episodic index
 * - rapid episodic indexing that binds entities, times, and events
 * - explicit memory representations: free text, vector, and graph carriers
 * - RAG as on-demand explicit memory retrieval over external stores
 * - agentic persistent cross-interaction state
 * - Atkinson-Shiffrin sensory / short-term / long-term mapping
 * - associative pattern separation and pattern completion over cue bindings
 * - retrieval controller that triggers explicit memory based on task demand
 *
 * Aimos adaptation:
 * - uses Aimos recall candidates as explicit hippocampal episodes
 * - implicit/model-memory editing rows are represented as diagnostics only
 * - no model parameter editing, deletion, pruning, or canonical mutation
 */

export const AI_HIPPOCAMPUS_CONSTANTS = Object.freeze({
  max_cues: 10,
  pattern_completion_cap: 24,
});

export const AI_HIPPOCAMPUS_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  edits_model_parameters: false,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'from', 'have', 'many', 'more', 'most',
  'that', 'their', 'there', 'these', 'this', 'those', 'through', 'what',
  'when', 'where', 'which', 'while', 'with', 'would',
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

function stateText(state = {}) {
  return String(state.text || state.memory?.value || '').trim();
}

function lexicalCosine(left = '', right = '') {
  const a = new Set(tokens(left));
  const b = new Set(tokens(right));
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const token of a) if (b.has(token)) hits += 1;
  return hits / Math.sqrt(a.size * b.size);
}

function cues(text = '') {
  const named = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)].map((match) => normalizeText(match[0]));
  return unique([...named, ...tokens(text).filter((token) => token.length >= 5)]).slice(0, AI_HIPPOCAMPUS_CONSTANTS.max_cues);
}

export function classifyMemoryParadigm(text = '') {
  if (/\b(agent|plan|tool|workflow|task|persistent|interaction|session)\b/i.test(text)) return 'agentic';
  if (/\b(retrieve|external|graph|vector|index|episode|memory|source|evidence)\b/i.test(text)) return 'explicit';
  return 'implicit';
}

export function memoryStageFor(text = '') {
  if (/\b(raw|sensory|input|capture|ingest|loader)\b/i.test(text)) return 'sensory';
  if (/\b(current|scratchpad|working|short|context|now)\b/i.test(text)) return 'short_term';
  return 'long_term';
}

export function buildHippocampalIndex(states = []) {
  const episodes = [];
  const cueToEpisodes = new Map();
  const graphEdges = [];
  for (const state of states || []) {
    const text = stateText(state);
    const episode = {
      id: String(state.id),
      text,
      paradigm: classifyMemoryParadigm(text),
      stage: memoryStageFor(text),
      cues: cues(text),
      vector: tokens(text),
      time: state.memory?.created_at || null,
    };
    episodes.push(episode);
    for (const cue of episode.cues) {
      const list = cueToEpisodes.get(cue) || [];
      list.push(episode.id);
      cueToEpisodes.set(cue, unique(list));
      graphEdges.push({ from: `cue:${cue}`, to: `episode:${episode.id}`, type: 'binds' });
    }
  }
  return { episodes, cueToEpisodes, graphEdges };
}

export function patternSeparation(index = {}) {
  const signatures = new Map();
  for (const episode of index.episodes || []) {
    signatures.set(episode.id, episode.cues.join('|') || episode.id);
  }
  return signatures;
}

export function hippocampalPatternCompletion({ index = buildHippocampalIndex([]), queryText = '' } = {}) {
  const queryCues = cues(queryText);
  const candidateIds = new Set();
  for (const cue of queryCues) {
    for (const id of index.cueToEpisodes.get(cue) || []) candidateIds.add(id);
  }
  const candidates = (index.episodes || [])
    .filter((episode) => candidateIds.has(episode.id) || lexicalCosine(queryText, episode.text) > 0)
    .map((episode) => {
      const cueOverlap = episode.cues.filter((cue) => queryCues.includes(cue)).length / Math.max(1, queryCues.length);
      const explicitBoost = episode.paradigm === 'explicit' ? 0.10 : 0;
      const agenticBoost = /\b(plan|should|recommend|current|next)\b/i.test(queryText) && episode.paradigm === 'agentic' ? 0.10 : 0;
      return {
        episode,
        score: clamp01((0.50 * lexicalCosine(queryText, episode.text)) + (0.30 * cueOverlap) + explicitBoost + agenticBoost),
      };
    })
    .sort((a, b) => b.score - a.score || a.episode.id.localeCompare(b.episode.id))
    .slice(0, AI_HIPPOCAMPUS_CONSTANTS.pattern_completion_cap);
  return { query_cues: queryCues, candidates };
}

export function retrievalDemand(queryText = '') {
  const explicit = /\b(what|who|which|when|how many|list|evidence|remember|recall|current|currently)\b/i.test(queryText) ? 1 : 0;
  const relational = /\b(after|before|between|because|why|member|prefer|recommend)\b/i.test(queryText) ? 1 : 0;
  return clamp01((0.60 * explicit) + (0.40 * relational));
}

export function aiHippocampusScores({ queryText = '', states = [] } = {}) {
  const index = buildHippocampalIndex(states);
  const separation = patternSeparation(index);
  const completion = hippocampalPatternCompletion({ index, queryText });
  const demand = retrievalDemand(queryText);
  const candidateScore = new Map(completion.candidates.map((row) => [row.episode.id, row.score]));
  const scoreById = new Map();
  for (const episode of index.episodes) {
    const stageBoost = episode.stage === 'long_term' ? 0.10 : episode.stage === 'short_term' ? 0.08 : 0.04;
    scoreById.set(episode.id, clamp01((0.62 * (candidateScore.get(episode.id) || 0)) + (0.20 * demand) + stageBoost + (0.08 * lexicalCosine(queryText, episode.text))));
  }
  return {
    scoreById,
    index_stats: {
      episodes: index.episodes.length,
      cues: index.cueToEpisodes.size,
      graph_edges: index.graphEdges.length,
      separated_patterns: separation.size,
    },
    paradigm_counts: index.episodes.reduce((acc, episode) => {
      acc[episode.paradigm] = (acc[episode.paradigm] || 0) + 1;
      return acc;
    }, {}),
    stage_counts: index.episodes.reduce((acc, episode) => {
      acc[episode.stage] = (acc[episode.stage] || 0) + 1;
      return acc;
    }, {}),
    retrieval_demand: demand,
    completed_count: completion.candidates.length,
    formula: 'CLS: implicit + explicit hippocampal index; completion_score=0.50*cos+0.30*cue_overlap+paradigm_boost',
    guardrails: AI_HIPPOCAMPUS_GUARDRAILS,
  };
}
