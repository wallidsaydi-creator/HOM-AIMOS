// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: services/write/persist-memory.js after canonical row insertion
// → Calls: services/observe/event-ledger.js + restricted DB projection writer
// Pipeline: SAVE | Position: retained-memory epistemic classification owner
// Papers: PoisonedRAG; RAGShield; RAGCHECKER; Reason and Verify;
//         The Semantic Illusion
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Native retained-memory epistemic classifier.
 *
 * Classification is not admission. The canonical observation is saved first
 * and remains retained. This owner appends a signed, reversible label bound to
 * the memory id and live content hash. It never rejects content, changes the
 * original scope/type/value, or mutates retrieval_weight.
 */

import { createHash } from 'node:crypto';
import { logEvent } from '../observe/event-ledger.js';

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

  // PoisonedRAG's black-box construction often concatenates a lower-case
  // question with a period and an answer-like sentence. Ordinary question
  // punctuation is handled as well. Requiring an answer continuation avoids
  // treating a standalone user question as poisoned reference evidence.
  const boundary = source.search(/[?!.](?=\s*[A-Z0-9"'“‘])/);
  if (boundary < 8 || boundary > 320) return null;
  const question = source.slice(0, boundary).trim();
  const continuation = source.slice(boundary + 1).trim();
  const words = normalizeText(question).split(' ').filter(Boolean);
  if (words.length < 3 || words.length > 48 || continuation.length < 12) return null;
  const startsInterrogative = INTERROGATIVE_START.test(question);
  const startsLowercase = /^\p{Ll}/u.test(question);
  // Retrieval queries are commonly lower-case search fragments. Requiring a
  // query-shaped prefix prevents ordinary capitalized article prose from
  // becoming a false cluster merely because two documents share an opening.
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

/**
 * Classify one already-retained memory against a bounded peer set.
 * The result is deterministic and integer-quantized for stable audit replay.
 */
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
  // A lone query-shaped prefix is useful response-local suspicion but is not
  // enough to persist a poison label. The canonical recall owner already
  // handles that weak signal per query; this chain requires compound evidence.
  if (strongQueryShape) scoreMilli += 450;
  // Some official retrieval targets are terse search fragments rather than
  // grammatical questions. A single fragment is not enough to label; two
  // independently retained passages with the exact same unusual prefix are.
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

function shouldAppendTransition(currentLabel, currentConfidence, next) {
  if (!next || next.label === 'unverified') return false;
  const current = String(currentLabel || 'unverified');
  if (current !== next.label) return true;
  return Number(next.confidence_milli) > Number(currentConfidence || 0);
}

/** Commit one signed classification and its current projection in one tx. */
export async function commitMemoryEpistemicClassification({
  client,
  companyId,
  subjectAgentId,
  classification,
  currentLabel = 'unverified',
  currentConfidenceMilli = 0,
  parentEventId = null,
  authority = null,
  provenance = null,
}) {
  if (!client) throw new Error('epistemic_classification_client_required');
  if (!shouldAppendTransition(currentLabel, currentConfidenceMilli, classification)) {
    return { appended: false, classification };
  }
  if (!/^[0-9a-f]{64}$/.test(classification.live_content_hash)) {
    throw new Error('epistemic_classification_live_hash_invalid');
  }

  const receipt = await logEvent(
    companyId,
    subjectAgentId,
    'memory_epistemic_classified',
    `epistemic:${classification.memory_id}`,
    {
      ...classification,
      provenance: provenance || null,
      retention: 'retained_canonical_unchanged',
      original_content_changed: false,
      original_scope_changed: false,
      original_memory_type_changed: false,
      retrieval_weight_changed: false,
      reasoning: `Retained memory classified as '${classification.label}' from reproducible epistemic evidence; classification is not admission or deletion.`,
      source_knowledge: 'PoisonedRAG; RAGShield; RAGCHECKER; Reason and Verify; The Semantic Illusion',
    },
    parentEventId,
    { client, authority, returnReceipt: true },
  );

  const applied = await client.query(
    `SELECT encode(public.apply_signed_memory_epistemic_classification(
       $1::uuid, $2::text, $3::integer, $4::uuid, $5::bytea
     ), 'hex') AS classification_hash`,
    [
      classification.memory_id,
      classification.label,
      classification.confidence_milli,
      receipt.event_id,
      Buffer.from(classification.live_content_hash, 'hex'),
    ],
  );

  return {
    appended: true,
    classification,
    receipt: {
      event_id: receipt.event_id,
      ledger_seq: receipt.ledger_seq,
      mutation_hash: receipt.mutation_hash,
      content_hash: receipt.content_hash,
    },
    classification_hash: applied.rows[0]?.classification_hash || null,
  };
}

function escapeLike(value = '') {
  return String(value).replace(/[\\%_]/g, (character) => `\\${character}`);
}

function retainedPeerKeyPattern(key = '', sessionId = '') {
  const session = String(sessionId || '').trim();
  if (session) return `${escapeLike(`sess:${session}:`)}%`;
  const match = String(key || '').match(/^(sess:[^:]+:)/i);
  return match ? `${escapeLike(match[1])}%` : '';
}

/**
 * Classify the newly retained row and promote existing members of a newly
 * established lure cluster in the same canonical transaction.
 */
export async function classifyAndCommitRetainedMemoryGroup({
  client,
  companyId,
  subjectAgentId,
  memoryId,
  key,
  source,
  sessionId = null,
  parentEventId = null,
  authority = null,
  provenance = null,
}) {
  if (!client) throw new Error('epistemic_classification_client_required');
  const keyPattern = retainedPeerKeyPattern(key, sessionId);
  const sourceName = String(source || '').trim();
  const rows = await client.query(
    `SELECT id, key, value, source, memory_type, content_hash,
            current_epistemic_label, current_epistemic_confidence_milli
       FROM public.aimos_memories
      WHERE company_id = $1
        AND (
          ($2::text <> '' AND key LIKE $2 ESCAPE '\\')
          OR ($2::text = '' AND $3::text <> ''
              AND source = $3 AND created_at >= NOW() - INTERVAL '1 hour')
          OR id = $4::uuid
        )
      ORDER BY created_at DESC, id DESC
      LIMIT 256`,
    [companyId, keyPattern, sourceName, memoryId],
  );
  const decisions = classifyRetainedMemoryBatch(rows.rows);
  const byId = new Map(rows.rows.map((row) => [String(row.id), row]));
  const commits = [];

  for (const classification of decisions) {
    if (!['poison_suspect', 'poison_likely'].includes(classification.label)) continue;
    const row = byId.get(classification.memory_id);
    if (!row) continue;
    const commit = await commitMemoryEpistemicClassification({
      client,
      companyId,
      subjectAgentId,
      classification,
      currentLabel: row.current_epistemic_label,
      currentConfidenceMilli: row.current_epistemic_confidence_milli,
      parentEventId,
      authority,
      provenance: {
        ...(provenance || {}),
        classification_trigger_memory_id: String(memoryId),
      },
    });
    if (commit.appended) commits.push(commit);
  }

  const currentDecision = decisions.find((decision) => decision.memory_id === String(memoryId)) || null;
  const currentCommit = commits.find((commit) => commit.classification.memory_id === String(memoryId)) || null;
  return {
    classification: currentDecision || {
      schema: MEMORY_EPISTEMIC_SCHEMA,
      classifier_version: MEMORY_EPISTEMIC_CLASSIFIER_VERSION,
      memory_id: String(memoryId),
      label: 'unverified',
      confidence_milli: 0,
      signals: {},
    },
    current_commit: currentCommit,
    appended_transitions: commits.length,
    related_memory_ids_reclassified: commits
      .map((commit) => commit.classification.memory_id)
      .filter((id) => id !== String(memoryId)),
  };
}
