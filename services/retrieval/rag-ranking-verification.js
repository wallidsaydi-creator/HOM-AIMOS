/**
 * rag-ranking-verification.js - RAG ranking, evaluation, and verification operators
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * retrieval/index.js.
 * Runtime note: deterministic math/state transformations only. This file does
 * not call providers, mutate memory, prune evidence, apply decay, delete
 * records, or call providers. In recall it contributes RankRAG/RAGVUE/Reason
 * and Verify evidence signals to bounded native scoring.
 *
 * Paper authority:
 * - RAGVUE.pdf
 * - RankRAG.pdf
 * - Reason and Verify.pdf
 * - Retrieving, Rethinking and Revising.pdf
 */

export const ALADDIN_RAG_RANKING_VERIFICATION_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Operators return derived ranking, metric, verification, and revision states only.',
});

export const RAGVUE_DEFAULTS = Object.freeze({
  relevance_threshold: 0.7,
  unsupported_claim_score: 0,
  metric_scale_min: 0,
  metric_scale_max: 1,
});

export const RANKRAG_DEFAULTS = Object.freeze({
  chunk_words: 150,
  positive_4gram_recall: 0.5,
  negative_4gram_recall: 0.1,
  context_size_k: 5,
  top_n_8b: 100,
  top_n_70b: 30,
  deterministic_temperature: 0,
});

export const REASON_VERIFY_DEFAULTS = Object.freeze({
  bm25_top_k: 20,
  rerank_top_m: 5,
  overlap_threshold: 0.3,
  evidence_threshold: 0.5,
  max_demonstrations: 4,
});

export const COV_RAG_DEFAULTS = Object.freeze({
  retrieval_top_k: 5,
  citation_threshold: 0.5,
  truthfulness_threshold: 0.5,
  correctness_threshold: 0.5,
  bias_max_for_high_quality: 0.3,
  conciseness_min_for_high_quality: 0.5,
});

export const RATIONALE_LABELS = Object.freeze({
  CORRECT_EXPLICIT: 'correct_explicit',
  CORRECT_IMPLICIT: 'correct_implicit',
  CORRECT_ADDITIONAL_INFO: 'correct_additional_info',
  CORRECT_MISSING_CONTEXT: 'correct_missing_context',
  INCORRECT_FALSE_INFO: 'incorrect_false_info',
  INCORRECT_DEVIATING_INFO: 'incorrect_deviating_info',
  INCORRECT_ILLOGICAL: 'incorrect_illogical',
  INCORRECT_MISSING_EVIDENCE: 'incorrect_missing_evidence',
});

const STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'has',
  'have', 'how', 'i', 'in', 'is', 'it', 'of', 'on', 'or', 'that', 'the',
  'this', 'to', 'was', 'were', 'what', 'when', 'where', 'which', 'who',
  'why', 'with',
]);

function text(value) {
  return String(value ?? '').trim();
}

function normText(value) {
  return text(value).toLowerCase();
}

export function tokenize(value = '', { keepStopwords = false } = {}) {
  return normText(value)
    .replace(/[^a-z0-9_:-]+/g, ' ')
    .split(/\s+/)
    .map(token => token.trim())
    .filter(token => token && (keepStopwords || !STOPWORDS.has(token)));
}

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function mean(values = []) {
  const rows = values.map(Number).filter(Number.isFinite);
  return rows.length ? rows.reduce((sum, value) => sum + value, 0) / rows.length : 0;
}

function stddev(values = []) {
  const rows = values.map(Number).filter(Number.isFinite);
  if (rows.length < 2) return 0;
  const m = mean(rows);
  return Math.sqrt(rows.reduce((sum, value) => sum + (value - m) ** 2, 0) / (rows.length - 1));
}

export function ngrams(tokens = [], n = 4) {
  const rows = Array.isArray(tokens) ? tokens : tokenize(tokens, { keepStopwords: true });
  if (rows.length < n) return [];
  return Array.from({ length: rows.length - n + 1 }, (_, index) => rows.slice(index, index + n).join(' '));
}

export function ngramRecall(candidate = '', reference = '', n = 4) {
  const referenceGrams = new Set(ngrams(reference, n));
  if (!referenceGrams.size) return 0;
  const candidateGrams = new Set(ngrams(candidate, n));
  let hits = 0;
  for (const gram of referenceGrams) if (candidateGrams.has(gram)) hits += 1;
  return hits / referenceGrams.size;
}

export function lexicalOverlapScore(query = '', evidence = '') {
  const q = tokenize(query);
  if (!q.length) return 0;
  const e = new Set(tokenize(evidence));
  return q.filter(token => e.has(token)).length / q.length;
}

export function chunkWords(document = '', chunkWordsCount = RANKRAG_DEFAULTS.chunk_words) {
  const words = text(document).split(/\s+/).filter(Boolean);
  const size = Math.max(1, Number(chunkWordsCount) || RANKRAG_DEFAULTS.chunk_words);
  const chunks = [];
  for (let index = 0; index < words.length; index += size) {
    chunks.push({ id: `chunk:${chunks.length + 1}`, text: words.slice(index, index + size).join(' '), start_word: index, end_word: Math.min(words.length, index + size) });
  }
  return chunks;
}

export function classifyRankRagChunk(chunk = '', answer = '', {
  positiveThreshold = RANKRAG_DEFAULTS.positive_4gram_recall,
  negativeThreshold = RANKRAG_DEFAULTS.negative_4gram_recall,
} = {}) {
  const recall = ngramRecall(chunk, answer, 4);
  return {
    recall_4gram: recall,
    label: recall >= positiveThreshold ? 'relevant' : recall <= negativeThreshold ? 'hard_negative' : 'ambiguous',
  };
}

export function rankRagPseudoPairs(document = '', answer = '', options = {}) {
  return chunkWords(document, options.chunkWords || RANKRAG_DEFAULTS.chunk_words)
    .map(chunk => ({ ...chunk, ...classifyRankRagChunk(chunk.text, answer, options) }));
}

export function probabilityOfTrue(logitsOrProbability = {}) {
  if (typeof logitsOrProbability === 'number') return clamp01(logitsOrProbability);
  if (logitsOrProbability.true_probability != null) return clamp01(logitsOrProbability.true_probability);
  const trueLogit = Number(logitsOrProbability.True ?? logitsOrProbability.true ?? 0);
  const falseLogit = Number(logitsOrProbability.False ?? logitsOrProbability.false ?? 0);
  const max = Math.max(trueLogit, falseLogit);
  const t = Math.exp(trueLogit - max);
  const f = Math.exp(falseLogit - max);
  return t / (t + f || 1);
}

export function contextRelevanceScore(query = '', context = {}) {
  if (context.true_probability != null || context.True != null) return probabilityOfTrue(context);
  const body = text(context.text || context.content || context.value || context);
  const lexical = lexicalOverlapScore(query, body);
  const supplied = Number(context.score ?? context.relevance_score ?? context.rerank_score);
  return Number.isFinite(supplied) ? clamp01(Math.max(lexical, supplied)) : lexical;
}

export function rankContextsByRelevance(query = '', contexts = [], { topN = contexts.length, topK = RANKRAG_DEFAULTS.context_size_k } = {}) {
  const candidates = contexts.slice(0, Math.max(0, Number(topN) || contexts.length))
    .map((context, index) => ({
      ...context,
      id: context.id || context.key || `ctx:${index + 1}`,
      original_rank: index + 1,
      relevance_score: contextRelevanceScore(query, context),
    }))
    .sort((a, b) => b.relevance_score - a.relevance_score || a.original_rank - b.original_rank);
  return {
    ranked: candidates,
    top_k: candidates.slice(0, Math.max(1, Number(topK) || RANKRAG_DEFAULTS.context_size_k)),
    top_n: Math.max(0, Number(topN) || contexts.length),
    k: Math.max(1, Number(topK) || RANKRAG_DEFAULTS.context_size_k),
  };
}

export function rankRagPipeline({ query = '', retrievedContexts = [], topN = RANKRAG_DEFAULTS.top_n_8b, topK = RANKRAG_DEFAULTS.context_size_k } = {}) {
  const ranking = rankContextsByRelevance(query, retrievedContexts, { topN, topK });
  return {
    aladdin: ALADDIN_RAG_RANKING_VERIFICATION_GUARDRAILS,
    stage: 'retrieve_rerank_generate_plan',
    query,
    top_n: ranking.top_n,
    top_k: ranking.k,
    ranked_contexts: ranking.ranked,
    generation_context: ranking.top_k.map(row => row.text || row.content || row.value || '').join('\n\n'),
    generation_temperature: RANKRAG_DEFAULTS.deterministic_temperature,
  };
}

export function addedTimeOverheadRatio({ retrievalTime = 0, rerankTimePerContext = 0, contextCount = 0, generationTime = 0 } = {}) {
  const retrieval = Math.max(0, Number(retrievalTime) || 0);
  const rerank = Math.max(0, Number(rerankTimePerContext) || 0) * Math.max(0, Number(contextCount) || 0);
  const generation = Math.max(0, Number(generationTime) || 0);
  return { total: retrieval + rerank + generation, retrieval, rerank, generation };
}

export function answerRecallAtK(contexts = [], answers = [], k = 5) {
  const needles = answers.map(normText).filter(Boolean);
  if (!needles.length) return 0;
  const haystack = contexts.slice(0, k).map(row => normText(row.text || row.content || row.value || row)).join(' ');
  return needles.some(answer => haystack.includes(answer)) ? 1 : 0;
}

export function exactMatch(prediction = '', expected = '') {
  const normalize = value => normText(value).replace(/[^\w\s]+/g, '').replace(/\s+/g, ' ').trim();
  return normalize(prediction) === normalize(expected) ? 1 : 0;
}

export function normalizeDatasetRatios(ratios = {}) {
  const entries = Object.entries(ratios).map(([key, value]) => [key, Math.max(0, Number(value) || 0)]);
  const total = entries.reduce((sum, [, value]) => sum + value, 0) || 1;
  return Object.fromEntries(entries.map(([key, value]) => [key, value / total]));
}

export function rankRagPrompt({ mode = 'qa', question = '', passages = [], claim = '', answerStyle = 'mixed' } = {}) {
  const passageText = passages.map((passage, index) => `Passage ${passage.id || index + 1}: ${text(passage.text || passage.content || passage)}`).join('\n');
  if (mode === 'single_passage_ranking') {
    return `Return True if the passage is relevant to the question, otherwise False.\nQuestion: ${text(question)}\n${passageText}`;
  }
  if (mode === 'multi_passage_ranking') {
    return `Return all relevant passage ids.\nQuestion: ${text(question)}\n${passageText}`;
  }
  if (mode === 'claim_boolean') {
    return `Answer the following question with True or False. Is the claim '${text(claim)}' correct?\n${passageText}`;
  }
  const instruction = {
    short: 'Answer the above question with a short phrase.',
    full: 'Please give a full and complete answer for the question.',
    number: 'Answer the following question with a number from the context or through math arithmetic.',
    mixed: 'Answer the following question with a short span, or a full and complete answer.',
  }[answerStyle] || 'Answer the question from the passages.';
  return `${instruction}\n${passageText}\nQuestion: ${text(question)}`;
}

export function chunkRelevanceGate(score = 0, tau = RAGVUE_DEFAULTS.relevance_threshold) {
  return clamp01(score) >= tau;
}

export function retrievalRelevance(scores = [], tau = RAGVUE_DEFAULTS.relevance_threshold) {
  const rows = scores.map(Number).filter(Number.isFinite);
  if (!rows.length) return 0;
  return rows.filter(score => chunkRelevanceGate(score, tau)).length / rows.length;
}

export function atomicQuestionAspects(question = '') {
  const clauses = text(question)
    .replace(/\?/g, '')
    .split(/\b(?:and|or|between|with|including|plus)\b|[,;]/i)
    .map(part => part.trim())
    .filter(Boolean);
  const fallback = tokenize(question).filter(token => token.length > 2);
  const aspects = clauses.length > 1 ? clauses : fallback;
  return [...new Set(aspects.map(aspect => normText(aspect)).filter(Boolean))];
}

export function coveredAspects(aspects = [], textValue = '') {
  const body = normText(textValue);
  return aspects.filter(aspect => {
    const tokensInAspect = tokenize(aspect);
    if (!tokensInAspect.length) return false;
    const hits = tokensInAspect.filter(token => body.includes(token)).length;
    return hits / tokensInAspect.length >= 0.6;
  });
}

export function retrievalCoverage(question = '', contexts = []) {
  const aspects = atomicQuestionAspects(question);
  const contextText = contexts.map(row => row.text || row.content || row.value || row).join(' ');
  const covered = coveredAspects(aspects, contextText);
  return {
    score: aspects.length ? covered.length / aspects.length : 0,
    aspects,
    covered_aspects: covered,
  };
}

export function answerCompleteness(question = '', answer = '') {
  const aspects = atomicQuestionAspects(question);
  const covered = coveredAspects(aspects, answer);
  return {
    score: aspects.length ? covered.length / aspects.length : 0,
    aspects,
    covered_aspects: covered,
  };
}

export function decomposeAtomicClaims(answer = '') {
  return text(answer)
    .split(/(?:[.;]\s+|\n+|\s+\band\b\s+)/i)
    .map(claim => claim.trim())
    .filter(Boolean);
}

export function extractStrictAnchors(value = '') {
  const raw = text(value);
  return {
    entities: raw.match(/\b[A-Z][A-Za-z0-9_-]*(?:\s+[A-Z][A-Za-z0-9_-]*)*\b/g) || [],
    dates: raw.match(/\b(?:19|20)\d{2}(?:-\d{2}(?:-\d{2})?)?\b/g) || [],
    numbers: raw.match(/\b\d+(?:\.\d+)?%?\b/g) || [],
  };
}

export function strictEvidenceMatch(claim = '', contexts = []) {
  const body = normText(contexts.map(row => row.text || row.content || row.value || row).join(' '));
  const claimTokens = tokenize(claim);
  const lexical = claimTokens.length ? claimTokens.filter(token => body.includes(token)).length / claimTokens.length : 0;
  const anchors = extractStrictAnchors(claim);
  const anchorValues = [...anchors.entities, ...anchors.dates, ...anchors.numbers].map(normText);
  const anchorMatch = anchorValues.every(anchor => body.includes(anchor));
  return {
    supported: lexical >= 0.65 && anchorMatch,
    lexical,
    anchors,
    anchor_match: anchorMatch,
  };
}

export function strictFaithfulness(answer = '', contexts = []) {
  const claims = decomposeAtomicClaims(answer);
  const rows = claims.map(claim => ({ claim, ...strictEvidenceMatch(claim, contexts) }));
  const supported = rows.filter(row => row.supported).length;
  const hallucinated = rows.filter(row => !row.supported).length;
  return {
    score: supported + hallucinated ? supported / (supported + hallucinated) : 0,
    supported_count: supported,
    hallucinated_count: hallucinated,
    claims: rows,
  };
}

export function clarityScore(answer = '') {
  const sentences = text(answer).split(/[.!?]+/).map(row => row.trim()).filter(Boolean);
  const words = text(answer).split(/\s+/).filter(Boolean);
  if (!words.length) return { score: 0, reasons: ['empty_answer'] };
  const avgSentence = words.length / Math.max(1, sentences.length);
  const longPenalty = avgSentence > 32 ? 0.2 : 0;
  const punctuationPenalty = /[^\w\s.,;:!?'"()/%+-]/.test(answer) ? 0.1 : 0;
  const repetitionPenalty = 1 - (new Set(words.map(normText)).size / words.length);
  return {
    score: clamp01(1 - longPenalty - punctuationPenalty - repetitionPenalty * 0.3),
    average_sentence_words: avgSentence,
    repetition_ratio: repetitionPenalty,
  };
}

export function calibrationScore(scores = []) {
  const rows = scores.map(Number).filter(Number.isFinite).map(clamp01);
  if (!rows.length) return 0;
  return clamp01(1 - (Math.max(...rows) - Math.min(...rows)));
}

export function descriptiveStats(scores = []) {
  const rows = scores.map(Number).filter(Number.isFinite);
  return { mean: mean(rows), standard_deviation: stddev(rows), count: rows.length };
}

function rankValues(values = []) {
  const sorted = [...values].map((value, index) => ({ value, index })).sort((a, b) => a.value - b.value);
  const ranks = Array(values.length).fill(0);
  for (let i = 0; i < sorted.length; i += 1) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1].value === sorted[i].value) j += 1;
    const rank = (i + j + 2) / 2;
    for (let k = i; k <= j; k += 1) ranks[sorted[k].index] = rank;
    i = j;
  }
  return ranks;
}

export function spearmanCorrelation(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  if (n < 2) return 0;
  const a = rankValues(left.slice(0, n).map(Number));
  const b = rankValues(right.slice(0, n).map(Number));
  const ma = mean(a);
  const mb = mean(b);
  const numerator = a.reduce((sum, value, index) => sum + (value - ma) * (b[index] - mb), 0);
  const denomA = Math.sqrt(a.reduce((sum, value) => sum + (value - ma) ** 2, 0));
  const denomB = Math.sqrt(b.reduce((sum, value) => sum + (value - mb) ** 2, 0));
  return denomA && denomB ? numerator / (denomA * denomB) : 0;
}

export function ragvueMetricSelection({ question = '', contexts = [], answer = '' } = {}) {
  const metrics = [];
  if (question && contexts.length) metrics.push('retrieval_relevance', 'retrieval_coverage');
  if (question && answer) metrics.push('answer_relevance', 'answer_completeness', 'clarity');
  if (answer && contexts.length) metrics.push('strict_faithfulness');
  return metrics;
}

export function ragvueEvaluate({ question = '', contexts = [], answer = '', judgeScores = [] } = {}) {
  const contextScores = contexts.map(context => contextRelevanceScore(question, context));
  const metrics = {};
  if (contexts.length) {
    metrics.retrieval_relevance = retrievalRelevance(contextScores);
    metrics.retrieval_coverage = retrievalCoverage(question, contexts).score;
  }
  if (answer) {
    metrics.answer_completeness = answerCompleteness(question, answer).score;
    metrics.clarity = clarityScore(answer).score;
  }
  if (answer && contexts.length) metrics.strict_faithfulness = strictFaithfulness(answer, contexts).score;
  if (judgeScores.length) metrics.calibration = calibrationScore(judgeScores);
  return {
    aladdin: ALADDIN_RAG_RANKING_VERIFICATION_GUARDRAILS,
    selected_metrics: ragvueMetricSelection({ question, contexts, answer }),
    metrics,
    diagnostic_state: ragvueDiagnosticState(metrics),
  };
}

export function ragvueDiagnosticState(metrics = {}) {
  const failures = Object.entries(metrics)
    .filter(([, value]) => Number(value) < 0.5)
    .map(([metric]) => metric);
  return {
    status: failures.length ? 'needs_review' : 'pass',
    failures,
    separates_retrieval_and_generation: true,
  };
}

export function bm25Search(query = '', documents = [], { k = REASON_VERIFY_DEFAULTS.bm25_top_k, k1 = 1.2, b = 0.75 } = {}) {
  const qTokens = tokenize(query);
  const docs = documents.map((document, index) => ({
    id: document.id || document.key || `doc:${index + 1}`,
    text: text(document.text || document.content || document.value || document),
    tokens: tokenize(document.text || document.content || document.value || document),
    original: document,
  }));
  const avgdl = mean(docs.map(doc => doc.tokens.length)) || 1;
  const df = new Map();
  for (const token of new Set(qTokens)) {
    df.set(token, docs.filter(doc => doc.tokens.includes(token)).length);
  }
  return docs.map(doc => {
    let score = 0;
    for (const token of qTokens) {
      const freq = doc.tokens.filter(row => row === token).length;
      if (!freq) continue;
      const idf = Math.log(1 + (docs.length - (df.get(token) || 0) + 0.5) / ((df.get(token) || 0) + 0.5));
      score += idf * ((freq * (k1 + 1)) / (freq + k1 * (1 - b + b * doc.tokens.length / avgdl)));
    }
    return { ...doc.original, id: doc.id, text: doc.text, bm25_score: score };
  }).sort((a, b) => b.bm25_score - a.bm25_score).slice(0, k);
}

export function bgeStyleRerank(query = '', candidates = [], { m = REASON_VERIFY_DEFAULTS.rerank_top_m } = {}) {
  return candidates.map((candidate, index) => ({
    ...candidate,
    rerank_score: contextRelevanceScore(query, candidate),
    rerank_input: `[CLS] ${text(query)} [SEP] ${text(candidate.text || candidate.content || candidate.value || candidate)} [SEP]`,
    original_rank: index + 1,
  })).sort((a, b) => b.rerank_score - a.rerank_score || a.original_rank - b.original_rank).slice(0, m);
}

export function evidenceScore(evidence = []) {
  return mean(evidence.map(row => row.rerank_score ?? row.score ?? 0));
}

export function shouldRewriteQuery({ query = '', evidence = [], overlapThreshold = REASON_VERIFY_DEFAULTS.overlap_threshold, evidenceThreshold = REASON_VERIFY_DEFAULTS.evidence_threshold } = {}) {
  const evidenceText = evidence.map(row => row.text || row.content || row.value || row).join(' ');
  const overlap = lexicalOverlapScore(query, evidenceText);
  const eScore = evidenceScore(evidence);
  return {
    should_rewrite: overlap < overlapThreshold || eScore < evidenceThreshold,
    overlap,
    evidence_score: eScore,
    overlap_threshold: overlapThreshold,
    evidence_threshold: evidenceThreshold,
  };
}

export function rewriteQueryDeterministic(query = '', glossary = {}) {
  const tokensInQuery = text(query).split(/\s+/);
  const expanded = tokensInQuery.map(token => glossary[token] || glossary[normText(token)] || token);
  return [...new Set(expanded.join(' ').split(/\s+/).filter(Boolean))].join(' ');
}

export function segmentRationale(rationale = '') {
  const pieces = text(rationale)
    .split(/(?<=[.!?])\s+|;\s+|\s+\b(?:because|therefore|so)\b\s+/i)
    .map(row => row.replace(/^(?:because|therefore|so)\s+/i, '').trim())
    .filter(Boolean);
  const merged = [];
  for (const piece of pieces) {
    if (tokenize(piece).length < 2 && merged.length) merged[merged.length - 1] += ` ${piece}`;
    else merged.push(piece);
  }
  return merged;
}

export function supportIndicator(label = '') {
  const normalized = normText(label).replace(/[- ]+/g, '_');
  return normalized.startsWith('correct') ? 1 : 0;
}

export function classifyRationaleStatement(statement = '', evidence = []) {
  const match = strictEvidenceMatch(statement, evidence);
  if (match.supported && match.anchor_match) return RATIONALE_LABELS.CORRECT_EXPLICIT;
  if (match.lexical >= 0.65) return RATIONALE_LABELS.CORRECT_IMPLICIT;
  if (match.lexical >= 0.35) return RATIONALE_LABELS.CORRECT_MISSING_CONTEXT;
  return RATIONALE_LABELS.INCORRECT_MISSING_EVIDENCE;
}

export function verifyRationale({ question = '', evidence = [], rationale = '' } = {}) {
  const statements = segmentRationale(rationale);
  const rows = statements.map(statement => {
    const label = classifyRationaleStatement(statement, evidence);
    return { statement, label, support: supportIndicator(label) };
  });
  return {
    question,
    statements: rows,
    faithfulness: rows.length ? rows.reduce((sum, row) => sum + row.support, 0) / rows.length : 0,
  };
}

export function cohenKappa(labelsA = [], labelsB = []) {
  const n = Math.min(labelsA.length, labelsB.length);
  if (!n) return 0;
  const a = labelsA.slice(0, n).map(text);
  const b = labelsB.slice(0, n).map(text);
  const labels = [...new Set([...a, ...b])];
  const observed = a.filter((label, index) => label === b[index]).length / n;
  let expected = 0;
  for (const label of labels) {
    expected += (a.filter(row => row === label).length / n) * (b.filter(row => row === label).length / n);
  }
  return expected === 1 ? 1 : (observed - expected) / (1 - expected);
}

export function perCategoryF1(predicted = [], gold = []) {
  const labels = [...new Set([...predicted, ...gold].map(text))];
  return Object.fromEntries(labels.map(label => {
    const tp = predicted.filter((row, index) => text(row) === label && text(gold[index]) === label).length;
    const fp = predicted.filter((row, index) => text(row) === label && text(gold[index]) !== label).length;
    const fn = predicted.filter((row, index) => text(row) !== label && text(gold[index]) === label).length;
    const precision = tp / (tp + fp || 1);
    const recall = tp / (tp + fn || 1);
    return [label, { precision, recall, f1: (2 * precision * recall) / (precision + recall || 1) }];
  }));
}

export function dynamicDemonstrationSelection(queryVector = [], demonstrations = [], { k = REASON_VERIFY_DEFAULTS.max_demonstrations, excludeDocumentId = null } = {}) {
  const cosine = (a = [], bvec = []) => {
    const denom = Math.sqrt(a.reduce((sum, value) => sum + value ** 2, 0)) * Math.sqrt(bvec.reduce((sum, value) => sum + value ** 2, 0));
    return denom ? a.reduce((sum, value, index) => sum + value * (bvec[index] || 0), 0) / denom : 0;
  };
  const selected = [];
  const seenLabels = new Set();
  const candidates = demonstrations
    .filter(row => !excludeDocumentId || row.document_id !== excludeDocumentId)
    .map((row, index) => ({ ...row, similarity: cosine(queryVector, row.embedding || []), original_index: index }))
    .sort((a, b) => b.similarity - a.similarity || a.original_index - b.original_index);
  for (const row of candidates) {
    if (selected.length >= k) break;
    if (row.label && seenLabels.has(row.label) && candidates.some(other => other.label && !seenLabels.has(other.label))) continue;
    selected.push(row);
    if (row.label) seenLabels.add(row.label);
  }
  for (const row of candidates) {
    if (selected.length >= k) break;
    if (!selected.some(item => item.original_index === row.original_index)) selected.push(row);
  }
  return selected;
}

export function reasonAndVerifyPipeline({ query = '', documents = [], rationale = '', glossary = {} } = {}) {
  const candidates = bm25Search(query, documents);
  const evidence = bgeStyleRerank(query, candidates);
  const rewrite = shouldRewriteQuery({ query, evidence });
  const finalQuery = rewrite.should_rewrite ? rewriteQueryDeterministic(query, glossary) : query;
  const verification = verifyRationale({ question: finalQuery, evidence, rationale });
  return {
    aladdin: ALADDIN_RAG_RANKING_VERIFICATION_GUARDRAILS,
    query,
    final_query: finalQuery,
    candidates,
    evidence,
    rewrite,
    verification,
    answer_unavailable: evidence.length === 0,
  };
}

export function covVerificationTuple(input = {}) {
  const raw = input || {};
  const scores = raw.sy || raw.answerScores || {};
  return {
    sk: clamp01(raw.sk ?? raw.referenceScore),
    sy: {
      correctness: clamp01(scores.correctness),
      citation_accuracy: clamp01(scores.citation_accuracy),
      truthfulness: clamp01(scores.truthfulness),
      bias: clamp01(scores.bias),
      conciseness: clamp01(scores.conciseness),
    },
    n: Boolean(raw.n ?? raw.judgement),
    x_prime: text(raw.x_prime ?? raw.revisedQuery),
  };
}

export function reRetrievalIndicator(tuple = {}, {
  citationThreshold = COV_RAG_DEFAULTS.citation_threshold,
  truthfulnessThreshold = COV_RAG_DEFAULTS.truthfulness_threshold,
  correctnessThreshold = COV_RAG_DEFAULTS.correctness_threshold,
} = {}) {
  const row = covVerificationTuple({ referenceScore: tuple.sk, answerScores: tuple.sy, judgement: tuple.n, revisedQuery: tuple.x_prime });
  const weakAnswer = row.sy.correctness < correctnessThreshold || row.sy.citation_accuracy < citationThreshold || row.sy.truthfulness < truthfulnessThreshold;
  return {
    should_reretrieve: Boolean(row.x_prime && (!row.n || row.sk < citationThreshold || weakAnswer)),
    weak_answer: weakAnswer,
    tuple: row,
  };
}

export function covRagLoss({ ragLogProbability = 0, covLogProbability = 0 } = {}) {
  return {
    LRAG: Number(ragLogProbability) || 0,
    LCoV: Number(covLogProbability) || 0,
    objective: (Number(ragLogProbability) || 0) + (Number(covLogProbability) || 0),
  };
}

export function verificationRank(scores = []) {
  const rows = scores.map(Number).filter(Number.isFinite);
  return rows.length ? rows.reduce((sum, value) => sum + value, 0) / rows.length : 0;
}

export function truthState(answerScores = {}) {
  const correctness = clamp01(answerScores.correctness);
  const truthfulness = clamp01(answerScores.truthfulness);
  const citation = clamp01(answerScores.citation_accuracy);
  if (correctness >= 0.5 && truthfulness >= 0.5 && citation >= 0.5) return 'true';
  if (correctness < 0.5 && truthfulness < 0.5) return 'false';
  return 'unclear';
}

export function highQualityCovSample(tuple = {}) {
  const row = covVerificationTuple({ referenceScore: tuple.sk, answerScores: tuple.sy, judgement: tuple.n, revisedQuery: tuple.x_prime });
  return row.sy.correctness === 1
    && row.sy.citation_accuracy === 1
    && row.sy.truthfulness === 1
    && row.sy.bias < COV_RAG_DEFAULTS.bias_max_for_high_quality
    && row.sy.conciseness > COV_RAG_DEFAULTS.conciseness_min_for_high_quality;
}

export function covRagPipeline({ question = '', references = [], answer = '', verification = {}, retriever = null } = {}) {
  const firstReferences = references.slice(0, COV_RAG_DEFAULTS.retrieval_top_k);
  const tuple = covVerificationTuple(verification);
  const indicator = reRetrievalIndicator(tuple);
  const secondReferences = indicator.should_reretrieve && typeof retriever === 'function'
    ? retriever(tuple.x_prime).slice(0, COV_RAG_DEFAULTS.retrieval_top_k)
    : [];
  return {
    aladdin: ALADDIN_RAG_RANKING_VERIFICATION_GUARDRAILS,
    question,
    first_references: firstReferences,
    answer,
    verification_tuple: tuple,
    reretrieval_indicator: indicator,
    revised_query: tuple.x_prime,
    second_references: secondReferences,
    next_action: indicator.should_reretrieve ? 'reretrieve_with_revised_query' : 'accept_or_finalize',
  };
}

export function multiIterationCovRag({ question = '', rounds = [], maxRounds = 3 } = {}) {
  const history = [];
  let currentQuestion = question;
  for (const round of rounds.slice(0, maxRounds)) {
    const result = covRagPipeline({ ...round, question: currentQuestion });
    history.push(result);
    if (!result.reretrieval_indicator.should_reretrieve) break;
    currentQuestion = result.revised_query || currentQuestion;
  }
  return { question, history, final_question: currentQuestion, rounds_used: history.length };
}

export function revisionNeeded({ answer = '', goldenAnswer = '', referenceScore = 0, answerScores = {} } = {}) {
  return exactMatch(answer, goldenAnswer) === 0
    && clamp01(referenceScore) < COV_RAG_DEFAULTS.citation_threshold
    && truthState(answerScores) !== 'true';
}
