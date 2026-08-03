// ═══════════════════════════════════════════════════════════════════════════════
// DEEP RECALL OVERRIDE
// ═══════════════════════════════════════════════════════════════════════════════
// Purpose: Keep low-frequency memories fully rank-eligible when the user gives
// an exact key, strong identifier, or highly specific semantic cue.
//
// Formal rule:
// exact_key_match OR strong_identifier_match OR high_specificity_semantic_match
//   => salience_penalty = 0
// identity_truth_declaration_match extends the same rule for current-truth
// identity questions when the memory contains an explicit identity declaration.
//
// Aladdin boundary: this module annotates and orders an in-memory recall pack.
// It does not delete, suppress, prune, decay, or mutate canonical memory rows.
// ═══════════════════════════════════════════════════════════════════════════════

function finiteRecallNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function hasIdentityTruthCue(queryText = '') {
  const q = normalizeDeepRecallText(queryText);
  if (!/\b(identity|identite|runtime|executive|operator|agent|canonical|name)\b/.test(q)) return false;
  return /\b(identity|runtime identity|executive runtime|operator identity|agent identity|canonical identity|canonical name|identity name)\b/.test(q)
    || (/\bwhat\b/.test(q) && /\b(identity|name)\b/.test(q) && /\b(runtime|executive|operator|agent|canonical)\b/.test(q))
    || (/\bwho\b/.test(q) && /\b(runtime|executive|operator|agent)\b/.test(q));
}

function hasExplicitIdentityDeclaration(textSurface = '') {
  const text = normalizeDeepRecallText(textSurface);
  return /\bidentity\s*:\s*.{0,160}\b(executive runtime|runtime for|canonical|confirmed|ceo level|orchestrator)\b/.test(text)
    || /\bidentity confirmed\b.{0,160}\b(executive runtime|runtime for|canonical|ceo level|orchestrator)\b/.test(text);
}

function roundRecallScore(value, fallback = null) {
  const number = finiteRecallNumber(value, fallback);
  return Number.isFinite(number) ? Number(number.toFixed(4)) : fallback;
}

const DEEP_RECALL_STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'because', 'before', 'between', 'could',
  'does', 'done', 'from', 'have', 'into', 'like', 'more', 'most', 'need',
  'only', 'that', 'then', 'there', 'this', 'what', 'when', 'where', 'which',
  'with', 'would', 'your',
]);

export function normalizeDeepRecallText(value = '') {
  return String(value || '')
    .replace(/\\[nrt]/g, ' ')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9:_./-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function deepRecallTokens(value = '') {
  return normalizeDeepRecallText(value)
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !DEEP_RECALL_STOPWORDS.has(token));
}

export function deepRecallIdentifiers(value = '') {
  const normalized = normalizeDeepRecallText(value);
  const matches = normalized.match(/\b(?:[a-z][a-z0-9_]+:[a-z0-9][a-z0-9_.:/-]{5,}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[a-z0-9][a-z0-9_.:-]{11,})\b/g) || [];
  return [...new Set(matches.filter((token) => token.length >= 8))];
}

export function buildDeepRecallOverride(memory = {}, queryText = '', lexicalCalibration = {}) {
  const queryNorm = normalizeDeepRecallText(queryText);
  const keyNorm = normalizeDeepRecallText(memory?.key || '');
  const idNorm = normalizeDeepRecallText(memory?.id || memory?.memory_id || '');
  const sourceNorm = normalizeDeepRecallText(memory?.source || '');
  const queryIdentifiers = deepRecallIdentifiers(queryText);
  const memoryIdentifiers = [
    keyNorm,
    idNorm,
    sourceNorm,
    ...deepRecallIdentifiers(`${memory?.key || ''} ${memory?.id || ''} ${memory?.memory_id || ''} ${memory?.source || ''}`),
  ].filter((token) => token.length >= 8);

  const exactKeyMatch = keyNorm.length >= 8 && (queryNorm === keyNorm || queryNorm.includes(keyNorm));
  const strongIdentifierMatch = Boolean(memory?.identifier_match?.exact)
    || memoryIdentifiers.some((identifier) => queryNorm.includes(identifier))
    || queryIdentifiers.some((identifier) => memoryIdentifiers.includes(identifier));

  const queryTokens = lexicalCalibration?.terms?.length
    ? lexicalCalibration.terms.filter((token) => token.length >= 3 && !DEEP_RECALL_STOPWORDS.has(token))
    : deepRecallTokens(queryText);
  const textSurface = normalizeDeepRecallText([
    memory?.key,
    memory?.memory_type,
    memory?.source,
    String(memory?.value || '').slice(0, 6000),
  ].filter(Boolean).join(' '));
  const matchedTokens = queryTokens.filter((token) => textSurface.includes(token));
  const overlapRatio = queryTokens.length > 0 ? matchedTokens.length / queryTokens.length : 0;
  const rawDistance = finiteRecallNumber(memory?.raw_distance, null);
  const semanticSimilarity = rawDistance == null
    ? finiteRecallNumber(memory?.similarity, finiteRecallNumber(memory?.rerank_score, 0))
    : Math.max(0, Math.min(1, 1 - rawDistance));
  const rerank = finiteRecallNumber(memory?.rerank_score, 0) || 0;
  const querySpecificity = queryTokens.length + (queryIdentifiers.length * 2);
  const highSpecificitySemanticMatch = querySpecificity >= 5
    && overlapRatio >= 0.45
    && (semanticSimilarity >= 0.82 || rerank >= 0.72);
  const identityTruthDeclarationMatch = hasIdentityTruthCue(queryText)
    && hasExplicitIdentityDeclaration(textSurface)
    && overlapRatio >= 0.25;

  const applied = exactKeyMatch || strongIdentifierMatch || identityTruthDeclarationMatch || highSpecificitySemanticMatch;
  const priority = exactKeyMatch
    ? 3
    : strongIdentifierMatch
      ? 2
      : identityTruthDeclarationMatch
        ? 1
        : highSpecificitySemanticMatch
          ? 1
          : 0;
  const reason = exactKeyMatch
    ? 'exact_key_match'
    : strongIdentifierMatch
      ? 'strong_identifier_match'
      : identityTruthDeclarationMatch
        ? 'identity_truth_declaration_match'
        : highSpecificitySemanticMatch
          ? 'high_specificity_semantic_match'
          : 'no_deep_recall_override';

  return {
    applied,
    reason,
    priority,
    exact_key_match: exactKeyMatch,
    strong_identifier_match: strongIdentifierMatch,
    high_specificity_semantic_match: highSpecificitySemanticMatch,
    identity_truth_declaration_match: identityTruthDeclarationMatch,
    query_specificity: querySpecificity,
    semantic_similarity: roundRecallScore(semanticSimilarity, 0),
    token_overlap: roundRecallScore(overlapRatio, 0),
    matched_token_count: matchedTokens.length,
  };
}

export function annotateDeepRecallOverrides(memories = [], queryText = '', lexicalCalibration = {}) {
  const counts = {
    exact_key_match: 0,
    strong_identifier_match: 0,
    high_specificity_semantic_match: 0,
    identity_truth_declaration_match: 0,
  };
  if (!Array.isArray(memories)) {
    return {
      annotated_count: 0,
      override_count: 0,
      override_counts: counts,
      rule: 'exact_key_match OR strong_identifier_match OR high_specificity_semantic_match OR identity_truth_declaration_match => salience_penalty=0',
    };
  }

  let overrideCount = 0;
  for (const memory of memories) {
    const override = buildDeepRecallOverride(memory, queryText, lexicalCalibration);
    memory.deep_recall_override = override;
    if (!override.applied) continue;
    overrideCount += 1;
    if (override.exact_key_match) counts.exact_key_match += 1;
    else if (override.strong_identifier_match) counts.strong_identifier_match += 1;
    else if (override.identity_truth_declaration_match) counts.identity_truth_declaration_match += 1;
    else if (override.high_specificity_semantic_match) counts.high_specificity_semantic_match += 1;
    memory.salience_penalty = 0;
    memory.deep_recall_rank_eligible = true;
    memory.deep_recall_override_reason = override.reason;
  }

  return {
    annotated_count: memories.length,
    override_count: overrideCount,
    override_counts: counts,
    rule: 'exact_key_match OR strong_identifier_match OR high_specificity_semantic_match OR identity_truth_declaration_match => salience_penalty=0',
  };
}

export function compareDeepRecallOverride(a = {}, b = {}) {
  const aPriority = Number(a?.deep_recall_override?.priority || 0);
  const bPriority = Number(b?.deep_recall_override?.priority || 0);
  if (aPriority !== bPriority) return bPriority - aPriority;
  if (aPriority > 0) {
    const aScore = finiteRecallNumber(a?.deep_recall_override?.semantic_similarity, 0) || 0;
    const bScore = finiteRecallNumber(b?.deep_recall_override?.semantic_similarity, 0) || 0;
    if (aScore !== bScore) return bScore - aScore;
    const aOverlap = finiteRecallNumber(a?.deep_recall_override?.token_overlap, 0) || 0;
    const bOverlap = finiteRecallNumber(b?.deep_recall_override?.token_overlap, 0) || 0;
    if (aOverlap !== bOverlap) return bOverlap - aOverlap;
  }
  return 0;
}

export function applyDeepRecallOverrideRanking(memories = []) {
  if (!Array.isArray(memories) || !memories.some((memory) => memory?.deep_recall_override?.applied)) {
    return memories;
  }
  return memories
    .map((memory, index) => ({ memory, index }))
    .sort((a, b) => compareDeepRecallOverride(a.memory, b.memory) || a.index - b.index)
    .map((item) => item.memory);
}
