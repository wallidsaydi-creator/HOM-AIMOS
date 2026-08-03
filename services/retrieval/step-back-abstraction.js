/**
 * Native abstraction operator from:
 * - TAKE A STEP BACK- EVOKING REASONING VIA ABSTRACTION IN LARGE LANGUAGE MODELS.pdf
 *
 * Implemented formulas / techniques:
 * - abstraction followed by reasoning
 * - first-principle retrieval before original-question scoring
 * - deterministic abstraction classes instead of prompt guidance
 * - retrieval-augmented abstraction signal
 *
 * Aimos adaptation:
 * - no LLM prompt layer and no answer injection
 * - computes a bounded cognitive/retrieval signal inside recall
 * - no pruning, deletion, decay, or canonical memory mutation
 */

const PRINCIPLES = [
  {
    id: 'temporal_delta',
    pattern: /\b(how many|how long|days?|weeks?|months?|years?|between|elapsed|passed|before|after)\b/i,
    abstraction: 'temporal relation and duration computation',
    terms: ['before', 'after', 'between', 'elapsed', 'duration', 'date', 'time', 'timeline'],
  },
  {
    id: 'ordered_sequence',
    pattern: /\b(first|last|before|after|next|previous|earliest|latest|order|sequence)\b/i,
    abstraction: 'ordering over a timeline',
    terms: ['first', 'last', 'before', 'after', 'timeline', 'sequence', 'order'],
  },
  {
    id: 'aggregation',
    pattern: /\b(how many|count|total|most|least|all|list|which ones|number of)\b/i,
    abstraction: 'complete set enumeration and aggregation',
    terms: ['count', 'total', 'all', 'list', 'many', 'frequency', 'aggregate'],
  },
  {
    id: 'current_state',
    pattern: /\b(currently|current|now|still|latest|recently|as of|present)\b/i,
    abstraction: 'validity at query time and supersession',
    terms: ['current', 'now', 'latest', 'recent', 'still', 'valid', 'updated'],
  },
  {
    id: 'preference',
    pattern: /\b(prefer|favorite|like|enjoy|recommend|choice|better|least|most)\b/i,
    abstraction: 'preference evidence and stable user taste',
    terms: ['prefer', 'favorite', 'like', 'enjoy', 'recommend', 'taste', 'choice'],
  },
  {
    id: 'speaker_binding',
    pattern: /\b(i|me|my|mine|you|your|he|she|they|who|person|member|considered)\b/i,
    abstraction: 'speaker and entity binding',
    terms: ['speaker', 'person', 'identity', 'member', 'name', 'he', 'she', 'they'],
  },
  {
    id: 'causal_explanation',
    pattern: /\b(why|reason|because|cause|explain|led to|resulted)\b/i,
    abstraction: 'causal explanation over evidence',
    terms: ['why', 'reason', 'because', 'cause', 'explain', 'result'],
  },
];

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'being', 'between', 'could', 'does',
  'from', 'have', 'into', 'many', 'more', 'most', 'that', 'their', 'there',
  'these', 'this', 'what', 'when', 'where', 'which', 'while', 'with', 'would',
]);

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function tokenize(text = '') {
  return String(text || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s-]/gu, ' ')
    .split(/\s+/)
    .map((token) => token.replace(/^-+|-+$/g, ''))
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function overlapScore(leftTerms = [], rightText = '') {
  const left = new Set(leftTerms.map((term) => String(term).toLowerCase()).filter(Boolean));
  const right = new Set(tokenize(rightText));
  if (!left.size || !right.size) return 0;
  let hit = 0;
  for (const term of left) {
    if (right.has(term)) hit += 1;
  }
  return clamp01(hit / Math.sqrt(left.size * right.size));
}

export function extractAbstractionPrinciples(queryText = '') {
  const matched = PRINCIPLES
    .filter((principle) => principle.pattern.test(String(queryText || '')))
    .map((principle) => ({
      id: principle.id,
      abstraction: principle.abstraction,
      terms: principle.terms,
    }));
  if (matched.length) return matched;
  return [{
    id: 'semantic_evidence',
    abstraction: 'direct evidence retrieval',
    terms: tokenize(queryText).slice(0, 8),
  }];
}

export function deriveStepBackQuestion(queryText = '') {
  const principles = extractAbstractionPrinciples(queryText);
  const primary = principles[0];
  return {
    original_question: String(queryText || ''),
    abstraction_question: `What evidence principle is needed for ${primary.abstraction}?`,
    primary_principle: primary.id,
    principles,
    scheme: 'abstraction_then_original_reasoning',
  };
}

export function stepBackRetrieveSignals({
  queryText = '',
  contexts = [],
} = {}) {
  const stepBack = deriveStepBackQuestion(queryText);
  const queryTerms = tokenize(queryText);
  const principleTerms = [...new Set(stepBack.principles.flatMap((principle) => principle.terms))];
  const scoreById = new Map();
  const componentsById = new Map();

  for (const context of contexts || []) {
    const text = context.text || context.value || '';
    const abstractionScore = overlapScore(principleTerms, text);
    const originalScore = overlapScore(queryTerms, text);
    const jointScore = Math.sqrt(abstractionScore * originalScore);
    const score = clamp01((abstractionScore * 0.48) + (originalScore * 0.36) + (jointScore * 0.16));
    scoreById.set(String(context.id), score);
    componentsById.set(String(context.id), {
      abstraction: Number(abstractionScore.toFixed(6)),
      original_question: Number(originalScore.toFixed(6)),
      joint: Number(jointScore.toFixed(6)),
      primary_principle: stepBack.primary_principle,
    });
  }

  return {
    scoreById,
    componentsById,
    step_back: stepBack,
    formula: 'score = 0.48 * abstraction + 0.36 * original + 0.16 * sqrt(abstraction * original)',
  };
}

export function applyStepBackFirstPrinciple({ queryText = '', evidenceText = '' } = {}) {
  const stepBack = deriveStepBackQuestion(queryText);
  const principleTerms = [...new Set(stepBack.principles.flatMap((principle) => principle.terms))];
  return {
    ...stepBack,
    evidence_alignment: overlapScore(principleTerms, evidenceText),
  };
}
