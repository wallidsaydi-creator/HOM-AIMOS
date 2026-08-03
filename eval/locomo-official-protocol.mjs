/**
 * Native LoCoMo QA compatibility contract.
 *
 * Upstream authority (pinned 2024 ACL release):
 * https://github.com/snap-research/locomo/tree/3eb6f2c585f5e1699204e3c3bdf7adc5c28cb376
 *
 * The scoring rules below follow task_eval/evaluation.py at that revision.
 * The Porter implementation follows NLTK PorterStemmer's default
 * NLTK_EXTENSIONS mode, which is the stemmer imported by upstream LoCoMo.
 * The algorithm is described in Porter, M. (1980), "An algorithm for suffix
 * stripping", Program 14(3), 130-137. NLTK is Apache-2.0 licensed.
 */

import { createHash } from 'node:crypto';

export const LOCOMO_OFFICIAL_PROTOCOL = 'locomo-upstream-qa-v1';
export const LOCOMO_OFFICIAL_REVISION = '3eb6f2c585f5e1699204e3c3bdf7adc5c28cb376';
export const LOCOMO_OFFICIAL_DATASET_SHA256 = '79fa87e90f04081343b8c8debecb80a9a6842b76a7aa537dc9fdf651ea698ff4';
export const LOCOMO_OFFICIAL_TOP_K = 25;
export const LOCOMO_OFFICIAL_SOURCES = Object.freeze({
  repository: `https://github.com/snap-research/locomo/tree/${LOCOMO_OFFICIAL_REVISION}`,
  evaluation: Object.freeze({
    path: 'task_eval/evaluation.py',
    sha256: '8e3be5d57ff2ff9ec5cd05939592f468c5f3f1fd95d13e431932bdf6bf0fd6fd',
  }),
  prompts: Object.freeze({
    path: 'task_eval/gpt_utils.py',
    sha256: '5fc977375878199735acd28fba5ae6f4d657fa0e000c0d2918a90c07b6035793',
  }),
  rag_configuration: Object.freeze({
    path: 'scripts/evaluate_rag_gpts.sh',
    sha256: '7a066d13578e2793c00dc2850b2fb81caf34975763a8547bb3f09b99b6d544a2',
  }),
  license: Object.freeze({
    id: 'CC-BY-NC-4.0',
    path: 'LICENSE.txt',
    sha256: '41003d4a74749c0220e33dd415042164b5a1093ed401f36277234f772d22d3d0',
  }),
});

const CATEGORY_IDS = Object.freeze({
  'multi-hop': 1,
  temporal: 2,
  'open-domain': 3,
  'single-hop': 4,
  adversarial: 5,
});

const IRREGULAR_STEMS = new Map(Object.entries({
  sky: 'sky',
  skies: 'sky',
  dying: 'die',
  lying: 'lie',
  tying: 'tie',
  news: 'news',
  innings: 'inning',
  inning: 'inning',
  outings: 'outing',
  outing: 'outing',
  cannings: 'canning',
  canning: 'canning',
  howe: 'howe',
  proceed: 'proceed',
  exceed: 'exceed',
  succeed: 'succeed',
}));

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function isConsonant(word, index) {
  if ('aeiou'.includes(word[index])) return false;
  if (word[index] !== 'y') return true;
  return index === 0 ? true : !isConsonant(word, index - 1);
}

function measure(stem) {
  let count = 0;
  for (let index = 1; index < stem.length; index += 1) {
    if (!isConsonant(stem, index - 1) && isConsonant(stem, index)) count += 1;
  }
  return count;
}

function containsVowel(stem) {
  for (let index = 0; index < stem.length; index += 1) {
    if (!isConsonant(stem, index)) return true;
  }
  return false;
}

function endsDoubleConsonant(word) {
  return word.length >= 2
    && word.at(-1) === word.at(-2)
    && isConsonant(word, word.length - 1);
}

function endsCvc(word) {
  return (word.length >= 3
      && isConsonant(word, word.length - 3)
      && !isConsonant(word, word.length - 2)
      && isConsonant(word, word.length - 1)
      && !'wxy'.includes(word.at(-1)))
    || (word.length === 2 && !isConsonant(word, 0) && isConsonant(word, 1));
}

function replaceSuffix(word, suffix, replacement) {
  return suffix ? `${word.slice(0, -suffix.length)}${replacement}` : `${word}${replacement}`;
}

function applyRules(word, rules) {
  for (const [suffix, replacement, condition] of rules) {
    if (suffix === '*d' && endsDoubleConsonant(word)) {
      const stem = word.slice(0, -2);
      return !condition || condition(stem) ? `${stem}${replacement}` : word;
    }
    if (word.endsWith(suffix)) {
      const stem = replaceSuffix(word, suffix, '');
      return !condition || condition(stem) ? `${stem}${replacement}` : word;
    }
  }
  return word;
}

function step1a(word) {
  if (word.endsWith('ies') && word.length === 4) return replaceSuffix(word, 'ies', 'ie');
  return applyRules(word, [
    ['sses', 'ss'],
    ['ies', 'i'],
    ['ss', 'ss'],
    ['s', ''],
  ]);
}

function step1b(word) {
  if (word.endsWith('ied')) return replaceSuffix(word, 'ied', word.length === 4 ? 'ie' : 'i');
  if (word.endsWith('eed')) {
    const stem = replaceSuffix(word, 'eed', '');
    return measure(stem) > 0 ? `${stem}ee` : word;
  }
  let intermediate = null;
  for (const suffix of ['ed', 'ing']) {
    if (word.endsWith(suffix)) {
      const stem = replaceSuffix(word, suffix, '');
      if (containsVowel(stem)) {
        intermediate = stem;
        break;
      }
    }
  }
  if (intermediate == null) return word;
  return applyRules(intermediate, [
    ['at', 'ate'],
    ['bl', 'ble'],
    ['iz', 'ize'],
    ['*d', intermediate.at(-1), () => !'lsz'.includes(intermediate.at(-1))],
    ['', 'e', (stem) => measure(stem) === 1 && endsCvc(stem)],
  ]);
}

function step1c(word) {
  return applyRules(word, [
    ['y', 'i', (stem) => stem.length > 1 && isConsonant(stem, stem.length - 1)],
  ]);
}

function step2(word) {
  if (word.endsWith('alli') && measure(replaceSuffix(word, 'alli', '')) > 0) {
    return step2(replaceSuffix(word, 'alli', 'al'));
  }
  const positive = (stem) => measure(stem) > 0;
  return applyRules(word, [
    ['ational', 'ate', positive],
    ['tional', 'tion', positive],
    ['enci', 'ence', positive],
    ['anci', 'ance', positive],
    ['izer', 'ize', positive],
    ['bli', 'ble', positive],
    ['alli', 'al', positive],
    ['entli', 'ent', positive],
    ['eli', 'e', positive],
    ['ousli', 'ous', positive],
    ['ization', 'ize', positive],
    ['ation', 'ate', positive],
    ['ator', 'ate', positive],
    ['alism', 'al', positive],
    ['iveness', 'ive', positive],
    ['fulness', 'ful', positive],
    ['ousness', 'ous', positive],
    ['aliti', 'al', positive],
    ['iviti', 'ive', positive],
    ['biliti', 'ble', positive],
    ['fulli', 'ful', positive],
    ['logi', 'log', () => measure(word.slice(0, -3)) > 0],
  ]);
}

function step3(word) {
  const positive = (stem) => measure(stem) > 0;
  return applyRules(word, [
    ['icate', 'ic', positive],
    ['ative', '', positive],
    ['alize', 'al', positive],
    ['iciti', 'ic', positive],
    ['ical', 'ic', positive],
    ['ful', '', positive],
    ['ness', '', positive],
  ]);
}

function step4(word) {
  const greaterThanOne = (stem) => measure(stem) > 1;
  return applyRules(word, [
    ['al', '', greaterThanOne],
    ['ance', '', greaterThanOne],
    ['ence', '', greaterThanOne],
    ['er', '', greaterThanOne],
    ['ic', '', greaterThanOne],
    ['able', '', greaterThanOne],
    ['ible', '', greaterThanOne],
    ['ant', '', greaterThanOne],
    ['ement', '', greaterThanOne],
    ['ment', '', greaterThanOne],
    ['ent', '', greaterThanOne],
    ['ion', '', (stem) => measure(stem) > 1 && 'st'.includes(stem.at(-1))],
    ['ou', '', greaterThanOne],
    ['ism', '', greaterThanOne],
    ['ate', '', greaterThanOne],
    ['iti', '', greaterThanOne],
    ['ous', '', greaterThanOne],
    ['ive', '', greaterThanOne],
    ['ize', '', greaterThanOne],
  ]);
}

function step5a(word) {
  if (!word.endsWith('e')) return word;
  const stem = replaceSuffix(word, 'e', '');
  if (measure(stem) > 1 || (measure(stem) === 1 && !endsCvc(stem))) return stem;
  return word;
}

function step5b(word) {
  return applyRules(word, [['ll', 'l', () => measure(word.slice(0, -1)) > 1]]);
}

export function nltkPorterStem(word) {
  const normalized = String(word || '').toLowerCase();
  if (IRREGULAR_STEMS.has(normalized)) return IRREGULAR_STEMS.get(normalized);
  if (normalized.length <= 2) return normalized;
  return step5b(step5a(step4(step3(step2(step1c(step1b(step1a(normalized))))))));
}

export function normalizeOfficialLocomoAnswer(value) {
  return String(value ?? '')
    .toLowerCase()
    .replaceAll(',', '')
    .replace(/[!"#$%&'()*+\-./:;<=>?@[\\\]^_`{|}~]/g, '')
    .replace(/\b(?:a|an|the|and)\b/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .join(' ');
}

export function officialLocomoF1Score(prediction, groundTruth) {
  const predictionTokens = normalizeOfficialLocomoAnswer(prediction).split(' ').filter(Boolean).map(nltkPorterStem);
  const groundTruthTokens = normalizeOfficialLocomoAnswer(groundTruth).split(' ').filter(Boolean).map(nltkPorterStem);
  if (!predictionTokens.length || !groundTruthTokens.length) return 0;
  const predictionCounts = new Map();
  for (const token of predictionTokens) predictionCounts.set(token, (predictionCounts.get(token) || 0) + 1);
  const groundCounts = new Map();
  for (const token of groundTruthTokens) groundCounts.set(token, (groundCounts.get(token) || 0) + 1);
  let common = 0;
  for (const [token, count] of predictionCounts) common += Math.min(count, groundCounts.get(token) || 0);
  if (!common) return 0;
  const precision = common / predictionTokens.length;
  const recall = common / groundTruthTokens.length;
  return (2 * precision * recall) / (precision + recall);
}

function officialMultiAnswerF1(prediction, groundTruth) {
  const predictions = String(prediction ?? '').split(',').map((value) => value.trim());
  const groundTruths = String(groundTruth ?? '').split(',').map((value) => value.trim());
  return groundTruths.reduce((sum, gold) => {
    const best = Math.max(...predictions.map((candidate) => officialLocomoF1Score(candidate, gold)));
    return sum + best;
  }, 0) / groundTruths.length;
}

export function officialLocomoScore(prediction, groundTruth, category) {
  const categoryId = typeof category === 'number' ? category : CATEGORY_IDS[String(category || '').toLowerCase()];
  if (!categoryId) throw new Error(`locomo_official_category_invalid:${category}`);
  let gold = String(groundTruth ?? '');
  if (categoryId === 3) gold = gold.split(';')[0].trim();
  if ([2, 3, 4].includes(categoryId)) return officialLocomoF1Score(prediction, gold);
  if (categoryId === 1) return officialMultiAnswerF1(prediction, gold);
  const output = String(prediction ?? '').toLowerCase();
  return output.includes('no information available') || output.includes('not mentioned') ? 1 : 0;
}

export function officialAdversarialOptions(questionId, goldAnswer) {
  const notMentioned = 'Not mentioned in the conversation';
  // The pinned LoCoMo release stores category-5 answers as JSON null.
  // Python str.format renders that upstream distractor as the literal "None".
  const renderedGold = goldAnswer == null || String(goldAnswer) === '' ? 'None' : String(goldAnswer);
  const goldFirst = Number.parseInt(sha256(Buffer.from(String(questionId), 'utf8')).slice(0, 2), 16) % 2 === 0;
  const options = goldFirst
    ? { a: renderedGold, b: notMentioned }
    : { a: notMentioned, b: renderedGold };
  return Object.freeze({
    options,
    correct_option: goldFirst ? 'b' : 'a',
    ordering: 'question-id-sha256-parity',
  });
}

export function prepareOfficialLocomoInput(input, goldAnswer) {
  if (input.benchmark !== 'locomo') throw new Error('locomo_official_benchmark_required');
  if (input.category !== 'adversarial') return { ...input, protocol: LOCOMO_OFFICIAL_PROTOCOL };
  const choice = officialAdversarialOptions(input.question_id, goldAnswer);
  return {
    ...input,
    protocol: LOCOMO_OFFICIAL_PROTOCOL,
    official_adversarial_options: choice.options,
    official_adversarial_option_ordering: choice.ordering,
  };
}

function parseSessionExchange(memory) {
  try {
    const parsed = typeof memory?.value === 'string' ? JSON.parse(memory.value) : memory?.value;
    if (!parsed || !Array.isArray(parsed.turns)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function cleanContextText(value) {
  return String(value ?? '').replaceAll('\\', '\\\\').replaceAll('"', '\\"').trim();
}

export function buildOfficialLocomoContext(memories) {
  return (memories || []).map((memory) => {
    const record = parseSessionExchange(memory);
    if (!record) throw new Error(`locomo_official_session_exchange_invalid:${memory?.id || 'unknown'}`);
    const firstObservedAt = record.turns.find((turn) => turn?.observed_at)?.observed_at || record.valid_from;
    const date = String(firstObservedAt || 'Date unavailable');
    const turns = record.turns.map((turn) => {
      const speaker = cleanContextText(turn.speaker || turn.role || 'Speaker');
      const content = cleanContextText(turn.content);
      const image = Array.isArray(turn.image_context) && turn.image_context.length
        ? ` and shared ${cleanContextText(turn.image_context.join(' '))}.`
        : '';
      return `${speaker} said, "${content}"${image}`;
    });
    return `DATE: ${date}\nCONVERSATION:\n${turns.join('\n')}`;
  }).join('\n\n');
}

export function buildOfficialLocomoPrompt(input, memories) {
  const context = buildOfficialLocomoContext(memories);
  let question = input.question;
  if (input.category === 'temporal') {
    question += ' Use DATE of CONVERSATION to answer with an approximate date.';
  } else if (input.category === 'adversarial') {
    const options = input.official_adversarial_options;
    if (typeof options?.a !== 'string' || typeof options?.b !== 'string') {
      throw new Error('locomo_official_adversarial_options_missing');
    }
    question += ` Select the correct answer: (a) ${options.a} (b) ${options.b}.`;
  }
  const instruction = input.category === 'adversarial'
    ? `Based on the above context, answer the following question. Question: ${question} Short answer:`
    : `Based on the above context, write an answer in the form of a short phrase for the following question.\nAnswer with exact words from the context whenever possible. Question: ${question} Short answer:`;
  return `${context}\n\n${instruction}`;
}

export function normalizeOfficialLocomoPrediction(rawAnswer, input) {
  const raw = String(rawAnswer ?? '').trim();
  if (input.category !== 'adversarial') return raw;
  const lowered = raw.toLowerCase();
  let option = null;
  if (lowered.length === 1) option = lowered.includes('a') ? 'a' : 'b';
  else if (lowered.length === 3) option = lowered.includes('(a)') ? 'a' : 'b';
  return option ? input.official_adversarial_options[option] : raw;
}

export function officialLocomoProtocolManifest() {
  return {
    id: LOCOMO_OFFICIAL_PROTOCOL,
    upstream_revision: LOCOMO_OFFICIAL_REVISION,
    dataset_sha256: LOCOMO_OFFICIAL_DATASET_SHA256,
    upstream_sources: LOCOMO_OFFICIAL_SOURCES,
    qa_metric: 'upstream-category-aware-token-f1',
    reader_prompt: 'upstream-single-question-rag',
    adversarial_option_ordering: 'question-id-sha256-parity (deterministic replacement for upstream unseeded random order)',
    rag_top_k: LOCOMO_OFFICIAL_TOP_K,
    memory_unit: 'HOM native composed session_exchange',
  };
}
