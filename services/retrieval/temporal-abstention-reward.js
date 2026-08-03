/**
 * Native abstention/reward operator from:
 * - WHEN SILENCE IS GOLDEN- CAN LLMS LEARN TO ABSTAIN IN TEMPORAL QA AND BEYOND?.pdf
 *
 * Implemented formulas / techniques:
 * - QA with abstention state: answer iff evidence is answerable, otherwise abstain
 * - D_train / D_test tuple schema `(q, c, a)`
 * - `o_i = pi_theta(q_i, e_i)` output contract
 * - GRPO clipped objective with advantage normalization
 * - KL penalty term and beta / epsilon / group-size constants
 * - `R_format`, exact match, ROUGE-L, piecewise `R_ans`, and total reward
 * - `tc = ExtractTimeRelated(q, c)` with `tc subset c`
 * - `KG_k = Top-k(Sim(q, s_i))`, `s_i=[h_i;r_i;t_i;tau_i]`
 * - output agreement, no-answer gate, and temporal KG top-k evidence
 *
 * Aimos adaptation:
 * - computes bounded evidence sufficiency and abstention diagnostics inside recall
 * - no model fine-tuning, no prompt guidance, no answer injection
 * - no pruning, deletion, decay, or canonical memory mutation
 */

export const TEMPORAL_ABSTENTION_CONSTANTS = Object.freeze({
  lora_rank: 32,
  lora_dropout: 0.1,
  learning_rate: 1e-5,
  weight_decay: 1e-2,
  grpo_group_size: 4,
  beta: 0.01,
  epsilon: 0.2,
  kg_top_k: 10,
  format_reward: 0.5,
});

export const TEMPORAL_ABSTENTION_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
});

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

export function clip(value, min = 1 - TEMPORAL_ABSTENTION_CONSTANTS.epsilon, max = 1 + TEMPORAL_ABSTENTION_CONSTANTS.epsilon) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
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
  return normalizeText(value).split(/\s+/).filter((token) => token.length >= 2);
}

function tokenSet(value = '') {
  return new Set(tokens(value));
}

export function exactMatch(output = '', answer = '') {
  return normalizeText(output) === normalizeText(answer) ? 1 : 0;
}

function lcsLength(left = [], right = []) {
  const dp = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));
  for (let i = 1; i <= left.length; i += 1) {
    for (let j = 1; j <= right.length; j += 1) {
      dp[i][j] = left[i - 1] === right[j - 1]
        ? dp[i - 1][j - 1] + 1
        : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[left.length][right.length];
}

export function rougeL(output = '', answer = '') {
  const left = tokens(output);
  const right = tokens(answer);
  if (!left.length || !right.length) return 0;
  const lcs = lcsLength(left, right);
  const precision = lcs / left.length;
  const recall = lcs / right.length;
  return precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
}

export function formatReward(output = '') {
  const text = String(output || '');
  return /<think>[\s\S]*?<\/think>\s*<answer>[\s\S]*?<\/answer>/i.test(text)
    ? TEMPORAL_ABSTENTION_CONSTANTS.format_reward
    : 0;
}

export function answerReward(output = '', answer = '') {
  const out = normalizeText(output).replace(/^no answer$/i, 'no answer');
  const gold = normalizeText(answer).replace(/^no answer$/i, 'no answer');
  const outNo = out === 'no answer' || out === 'noanswer';
  const goldNo = gold === 'no answer' || gold === 'noanswer';
  if (outNo && goldNo) return 1;
  if (!outNo && !goldNo) return clamp01(rougeL(out, gold) + exactMatch(out, gold));
  return 0;
}

export function totalAbstentionReward(output = '', answer = '') {
  return formatReward(output) + answerReward(output.replace(/<\/?answer>/gi, '').replace(/<think>[\s\S]*?<\/think>/gi, ''), answer);
}

export function advantageNormalize(rewards = []) {
  const rows = rewards.map(Number).filter(Number.isFinite);
  if (!rows.length) return [];
  const mean = rows.reduce((sum, value) => sum + value, 0) / rows.length;
  const variance = rows.reduce((sum, value) => sum + ((value - mean) ** 2), 0) / rows.length;
  const std = Math.sqrt(variance) || 1;
  return rows.map((value) => (value - mean) / std);
}

export function klDivergenceCategorical(policy = [], reference = []) {
  const left = policy.map(Number);
  const right = reference.map(Number);
  let out = 0;
  for (let i = 0; i < left.length; i += 1) {
    const p = Math.max(1e-12, left[i] || 0);
    const q = Math.max(1e-12, right[i] || 0);
    out += p * Math.log(p / q);
  }
  return out;
}

export function grpoObjective({
  policyProb = [],
  oldPolicyProb = [],
  referenceProb = [],
  rewards = [],
  beta = TEMPORAL_ABSTENTION_CONSTANTS.beta,
  epsilon = TEMPORAL_ABSTENTION_CONSTANTS.epsilon,
} = {}) {
  const advantages = advantageNormalize(rewards);
  const terms = [];
  for (let i = 0; i < advantages.length; i += 1) {
    const ratio = (Number(policyProb[i]) || 0) / Math.max(1e-12, Number(oldPolicyProb[i]) || 0);
    terms.push(Math.min(ratio * advantages[i], clip(ratio, 1 - epsilon, 1 + epsilon) * advantages[i]));
  }
  const mean = terms.length ? terms.reduce((sum, value) => sum + value, 0) / terms.length : 0;
  return mean - ((Number(beta) || 0) * klDivergenceCategorical(policyProb, referenceProb));
}

function lexicalSimilarity(left = '', right = '') {
  const l = tokenSet(left);
  const r = tokenSet(right);
  if (!l.size || !r.size) return 0;
  let hit = 0;
  for (const token of l) if (r.has(token)) hit += 1;
  return clamp01(hit / Math.sqrt(l.size * r.size));
}

export function extractTimeRelatedContext(question = '', context = '') {
  const temporal = /\b(today|now|currently|before|after|during|while|when|until|since|between|first|last|latest|earliest|day|week|month|year|yesterday|tomorrow|ago|recently|date|time|\d{4})\b/i;
  const questionTemporal = temporal.test(question);
  const sentences = String(context || '').split(/(?<=[.!?])\s+/).filter(Boolean);
  const selected = sentences.filter((sentence) => temporal.test(sentence) || lexicalSimilarity(question, sentence) >= 0.24);
  return {
    subset: selected.join(' '),
    selected,
    is_subset: selected.every((sentence) => String(context || '').includes(sentence)),
    question_temporal: questionTemporal,
  };
}

export function temporalKgSentence(fact = {}) {
  return [fact.subject || fact.h, fact.predicate || fact.r, fact.object || fact.t, fact.timestamp || fact.tau || fact.time]
    .filter(Boolean)
    .join(' ');
}

export function topKTemporalKgFacts(question = '', facts = [], { k = TEMPORAL_ABSTENTION_CONSTANTS.kg_top_k } = {}) {
  return (facts || [])
    .map((fact) => ({ fact, sentence: temporalKgSentence(fact), score: lexicalSimilarity(question, temporalKgSentence(fact)) }))
    .sort((a, b) => b.score - a.score || a.sentence.localeCompare(b.sentence))
    .slice(0, Math.max(0, k));
}

export function outputAgreement(outputs = []) {
  const rows = outputs.map(normalizeText).filter(Boolean);
  if (rows.length <= 1) return rows.length;
  let pairs = 0;
  let total = 0;
  for (let i = 0; i < rows.length; i += 1) {
    for (let j = i + 1; j < rows.length; j += 1) {
      total += lexicalSimilarity(rows[i], rows[j]);
      pairs += 1;
    }
  }
  return pairs ? clamp01(total / pairs) : 0;
}

export function assessAbstentionNeed({
  question = '',
  contexts = [],
  facts = [],
} = {}) {
  const evidenceText = contexts.map((context) => context.text || context.value || '').join(' ');
  const temporalContext = extractTimeRelatedContext(question, evidenceText);
  const kgTop = topKTemporalKgFacts(question, facts);
  const evidenceScore = Math.max(
    lexicalSimilarity(question, temporalContext.subset),
    kgTop[0]?.score || 0,
  );
  const hasContradiction = /\b(not|never|no longer|instead|correction|actually|wrong)\b/i.test(evidenceText)
    && /\b(current|currently|now|latest|still)\b/i.test(question);
  const ambiguous = evidenceScore > 0 && evidenceScore < 0.18 && contexts.length > 1;
  return {
    should_abstain: evidenceScore < 0.10 || ambiguous,
    contradictory_context: hasContradiction,
    ambiguous_context: ambiguous,
    evidence_score: Number(evidenceScore.toFixed(6)),
    temporal_context: temporalContext,
    kg_top_count: kgTop.length,
  };
}

export function temporalAbstentionEvidenceScores({
  queryText = '',
  states = [],
  contexts = [],
  facts = [],
} = {}) {
  const contextRows = contexts.length ? contexts : states.map((state) => ({ id: state.id, text: state.text }));
  const abstention = assessAbstentionNeed({ question: queryText, contexts: contextRows, facts });
  const scoreById = new Map();
  const diagnosticsById = new Map();
  const kgTop = topKTemporalKgFacts(queryText, facts);

  for (const state of states || []) {
    const text = state.text || state.value || '';
    const tc = extractTimeRelatedContext(queryText, text);
    const lexical = lexicalSimilarity(queryText, text);
    const temporal = lexicalSimilarity(queryText, tc.subset);
    const kgScore = kgTop.some((row) => String(row.fact.qualifiers?.memory_id || row.fact.memory_id || row.fact.id || '') === String(state.id))
      ? Math.max(...kgTop.map((row) => row.score), 0)
      : 0;
    const sufficiency = abstention.should_abstain ? 0 : abstention.evidence_score;
    const score = clamp01((lexical * 0.34) + (temporal * 0.30) + (kgScore * 0.18) + (sufficiency * 0.18));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      lexical: Number(lexical.toFixed(6)),
      temporal_context_score: Number(temporal.toFixed(6)),
      kg_score: Number(kgScore.toFixed(6)),
      selected_temporal_sentences: tc.selected.length,
    });
  }

  return {
    scoreById,
    diagnosticsById,
    abstention,
    constants: TEMPORAL_ABSTENTION_CONSTANTS,
    formula: 'R = R_format + R_ans; GRPO uses clipped ratio * advantage minus beta * KL; recall score uses bounded evidence sufficiency',
  };
}
