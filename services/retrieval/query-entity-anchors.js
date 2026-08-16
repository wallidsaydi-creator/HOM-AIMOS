/**
 * query-entity-anchors.js — deterministic query entity anchors
 *
 * Shared by native entity recall and Concept/PPR. It performs no model call,
 * persistence, ranking, or authority decision. The rules mirror the canonical
 * save-time provisional entity anchors so phrase-to-passage traversal starts
 * from the same normalized vocabulary.
 */

const SENTENCE_PREFIX_STOPWORDS = /^(The|This|That|These|Those|When|What|Where|Which|Here|There|After|Before|During|About|Also|Just|Some|Each|Every|Most|Many|For)$/;
const SYMBOL_STOPWORDS = /^(THE|AND|FOR|BUT|NOT|ALL|ARE|WAS|HAS|HAD|GET|SET|PUT|RUN|API|SQL|URL|CSS|DNS|SSH|LLM|NLP|RAG|AAR)$/;

export function normalizeEntityAnchor(value) {
  return String(value || '')
    .normalize('NFKC')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

export function extractQueryEntityAnchors(text, limit = 20) {
  const entities = [];
  const seen = new Set();
  const add = (name, type) => {
    const normalized = normalizeEntityAnchor(name);
    const identity = `${type}:${normalized}`;
    if (normalized.length < 2 || normalized.length > 80 || seen.has(identity)) return;
    seen.add(identity);
    entities.push({ name: normalized, type });
  };
  const source = String(text || '');
  for (const match of source.matchAll(/\b([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,3})\b/g)) {
    const phrase = match[1];
    if (!SENTENCE_PREFIX_STOPWORDS.test(phrase.split(/\s+/)[0])) add(phrase, 'proper_noun');
  }
  for (const match of source.matchAll(/\b(\d{4}-\d{2}-\d{2})\b/g)) add(match[1], 'date');
  for (const match of source.matchAll(/\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:,?\s*\d{4})?)\b/gi)) add(match[1], 'date');
  for (const match of source.matchAll(/\$[\d,]+(?:\.\d{2})?/g)) add(match[0], 'amount');
  for (const match of source.matchAll(/€[\d,]+(?:\.\d{2})?/g)) add(match[0], 'amount');
  for (const match of source.matchAll(/(https?:\/\/[^\s"'<>]+)/g)) add(match[1].slice(0, 80), 'url');
  for (const match of source.matchAll(/\b([A-Z]{2,5})\b/g)) {
    if (!SYMBOL_STOPWORDS.test(match[1])) add(match[1], 'symbol');
  }
  return entities.slice(0, Math.max(0, Number(limit || 20)));
}

export default { extractQueryEntityAnchors, normalizeEntityAnchor };
