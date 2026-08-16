// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: memory-epistemic-classifier.js and epistemic-edit certification
// → Calls: node:crypto only
// Pipeline: SECURITY | Pure retained-memory epistemic decision owner
// Paper basis: PoisonedRAG; RAGShield; RAGCHECKER; Reason and Verify;
//              The Semantic Illusion
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

export const MEMORY_EPISTEMIC_CLASSIFIER_VERSION = 'aimos-memory-epistemic-v1';
export const MEMORY_EPISTEMIC_SCHEMA = 'aimos.memory-epistemic-classification/v1';

export const MEMORY_EPISTEMIC_LABELS = Object.freeze([
  'unverified',
  'supported',
  'disputed',
  'poison_suspect',
  'poison_likely',
  'poison_confirmed',
  'poison_refuted',
]);

const REFERENCE_MEMORY_TYPES = new Set([
  'research',
  'book_extract',
  'bibliographic_reference',
  'declarative',
  'framework',
  'architecture',
]);
const INTERACTION_MEMORY_TYPES = new Set([
  'session_exchange',
  'session',
  'directive',
  'heartbeat',
  'after_action_review',
]);

const INTERROGATIVE_START = /^(?:who|what|when|where|why|how|which|whose|whom|is|are|was|were|do|does|did|can|could|should|would|will|has|have|had)\b/i;
const NUMBER_OR_UNIT = /(?:[$€£]\s*\d[\d,.]*|\b\d+(?:\.\d+)?\s*(?:%|percent|years?|months?|days?|hours?|miles?|kilometers?|games?|people|dollars?|euros?|pounds?)?\b)/gi;

function clampInt(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.max(min, Math.min(max, Math.round(number)));
}

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}%$€£]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenSet(value = '') {
  return new Set(normalizeText(value).split(' ').filter((token) => token.length >= 2));
}

function jaccard(left, right) {
  if (!left.size || !right.size) return 0;
  let intersection = 0;
  for (const token of left) if (right.has(token)) intersection += 1;
  const union = left.size + right.size - intersection;
  return union ? intersection / union : 0;
}

function normalizedStructuredValues(value = '') {
  return [...String(value || '').matchAll(NUMBER_OR_UNIT)]
    .map((match) => normalizeText(match[0]))
    .filter(Boolean);
}

export function extractLeadingQuestion(value = '') {
  const source = String(value || '').trim();
  if (!source) return null;

  const boundary = source.search(/[?!.](?=\s*[A-Z0-9"'“‘])/);
  if (boundary < 8 || boundary > 320) return null;
  const question = source.slice(0, boundary).trim();
  const continuation = source.slice(boundary + 1).trim();
  const words = normalizeText(question).split(' ').filter(Boolean);
  if (words.length < 3 || words.length > 48 || continuation.length < 12) return null;
  const startsInterrogative = INTERROGATIVE_START.test(question);
  const startsLowercase = /^\p{Ll}/u.test(question);
  if (!startsInterrogative && !startsLowercase) return null;
  return {
    question,
    continuation,
    starts_interrogative: startsInterrogative,
    starts_lowercase: startsLowercase,
    fingerprint: createHash('sha256').update(normalizeText(question), 'utf8').digest('hex'),
  };
}

function isReferenceLike(memory = {}) {
  const memoryType = String(memory.memory_type || memory.memoryType || '').toLowerCase();
  if (INTERACTION_MEMORY_TYPES.has(memoryType)) return false;
  const source = String(memory.source || '').toLowerCase();
  const key = String(memory.key || '').toLowerCase();
  return REFERENCE_MEMORY_TYPES.has(memoryType)
    || /(?:^|:)(?:reference|research|corpus|document|paper|book)(?::|$)/.test(key)
    || /^(?:benchmark|import|web|corpus|paper|book|research):/.test(source);
}

function sameSource(left, right) {
  const a = String(left?.source || '').trim().toLowerCase();
  const b = String(right?.source || '').trim().toLowerCase();
  return Boolean(a && b && a === b);
}

function compareIndependentAnswer(candidate, peer) {
  const leftQuestion = extractLeadingQuestion(candidate.value);
  const rightQuestion = extractLeadingQuestion(peer.value);
  if (!leftQuestion || !rightQuestion || leftQuestion.fingerprint !== rightQuestion.fingerprint) return 'unrelated';
  if (sameSource(candidate, peer)) return 'same_source';

  const leftValues = new Set(normalizedStructuredValues(leftQuestion.continuation));
  const rightValues = new Set(normalizedStructuredValues(rightQuestion.continuation));
  if (leftValues.size && rightValues.size) {
    const shared = [...leftValues].some((value) => rightValues.has(value));
    return shared ? 'support' : 'contradiction';
  }

  const similarity = jaccard(tokenSet(leftQuestion.continuation), tokenSet(rightQuestion.continuation));
  if (similarity >= 0.55) return 'support';
  return 'indeterminate';
}

export function classifyRetainedMemoryEpistemics(memory = {}, peers = [], explicitEvidence = null) {
  const leading = extractLeadingQuestion(memory.value);
  const referencePrefix = Boolean(leading && isReferenceLike(memory));
  const strongQueryShape = Boolean(
    referencePrefix && (leading.starts_interrogative || leading.starts_lowercase),
  );
  const related = leading
    ? peers.filter((peer) => {
        const peerLeading = extractLeadingQuestion(peer?.value);
        return peerLeading?.fingerprint === leading.fingerprint;
      })
    : [];
  const cluster = [memory, ...related.filter((peer) => String(peer.id) !== String(memory.id))];
  const uniqueById = [...new Map(cluster.map((row, index) => [String(row.id || `row:${index}`), row])).values()];
  const sameLureCluster = referencePrefix && uniqueById.length >= 2;
  const sourceSet = new Set(uniqueById.map((row) => String(row.source || '').trim().toLowerCase()).filter(Boolean));
  const sourceConcentration = sameLureCluster && sourceSet.size === 1;

  let independentSupportCount = 0;
  let contradictionCount = 0;
  for (const peer of related) {
    const relation = compareIndependentAnswer(memory, peer);
    if (relation === 'support') independentSupportCount += 1;
    if (relation === 'contradiction') contradictionCount += 1;
  }

  let scoreMilli = 0;
  if (strongQueryShape) scoreMilli += 450;
  if (sameLureCluster) scoreMilli += strongQueryShape ? 250 : 700;
  if (sourceConcentration) scoreMilli += 100;
  scoreMilli += Math.min(2, contradictionCount) * 200;
  scoreMilli -= Math.min(2, independentSupportCount) * 250;
  scoreMilli = clampInt(scoreMilli, 0, 1000);

  let label = scoreMilli >= 750
    ? 'poison_likely'
    : scoreMilli >= 500
      ? 'poison_suspect'
      : 'unverified';

  if (explicitEvidence?.label === 'poison_confirmed' || explicitEvidence?.label === 'poison_refuted') {
    label = explicitEvidence.label;
    scoreMilli = clampInt(explicitEvidence.confidence_milli ?? 1000, 0, 1000);
  } else if (explicitEvidence?.label === 'supported' || explicitEvidence?.label === 'disputed') {
    label = explicitEvidence.label;
    scoreMilli = clampInt(explicitEvidence.confidence_milli ?? 800, 0, 1000);
  }

  return {
    schema: MEMORY_EPISTEMIC_SCHEMA,
    classifier_version: MEMORY_EPISTEMIC_CLASSIFIER_VERSION,
    memory_id: String(memory.id || memory.memory_id || ''),
    live_content_hash: Buffer.isBuffer(memory.content_hash)
      ? memory.content_hash.toString('hex')
      : String(memory.live_content_hash || memory.content_hash || ''),
    label,
    confidence_milli: scoreMilli,
    signals: {
      reference_query_prefix: referencePrefix,
      reference_query_lure: strongQueryShape || sameLureCluster,
      starts_interrogative: Boolean(leading?.starts_interrogative),
      starts_lowercase: Boolean(leading?.starts_lowercase),
      leading_question_sha256: leading?.fingerprint || null,
      same_lure_cluster: sameLureCluster,
      lure_cluster_size: uniqueById.length,
      source_concentration: sourceConcentration,
      independent_source_count: sourceSet.size,
      independent_support_count: independentSupportCount,
      contradiction_count: contradictionCount,
      explicit_evidence: explicitEvidence ? {
        label: explicitEvidence.label || null,
        evidence_sha256: explicitEvidence.evidence_sha256 || null,
      } : null,
    },
  };
}

export function classifyRetainedMemoryBatch(memories = [], explicitEvidenceById = new Map()) {
  const rows = Array.isArray(memories) ? memories : [];
  const groups = new Map();
  for (const memory of rows) {
    const fingerprint = extractLeadingQuestion(memory?.value)?.fingerprint || null;
    if (!fingerprint) continue;
    const members = groups.get(fingerprint) || [];
    members.push(memory);
    groups.set(fingerprint, members);
  }
  return rows.map((memory) => classifyRetainedMemoryEpistemics(
    memory,
    (groups.get(extractLeadingQuestion(memory?.value)?.fingerprint) || [])
      .filter((peer) => String(peer.id) !== String(memory.id)),
    explicitEvidenceById.get(String(memory.id)) || null,
  ));
}

