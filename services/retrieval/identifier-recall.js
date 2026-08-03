/**
 * identifier-recall.js — Wave 1 identifier-safe artifact recall
 *
 * Paper authorities:
 * - "Generative Retrieval Overcomes Limitations of Dense Retrieval but
 *   Struggles with Identifier Ambiguity" (Batch 6/7): use identifiers as a
 *   first-class retrieval surface, but never pretend an ambiguous identifier is
 *   a unique document.
 * - "From Guessing to Placeholding: A Cost-Theoretic Framework for
 *   Uncertainty-Aware Code Completion" (Batch 6/7): when evidence is
 *   underspecified or ambiguous, emit an explicit placeholder/insufficiency
 *   payload instead of fabricating a hard answer.
 *
 * Scope: additive read path only. This service does not alter calibrated
 * ranking, MVS, STDP, or write-quality math.
 */
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query as defaultQuery } from '../../db/connection.js';

export const IDENTIFIER_RECALL_STATUS = {
  NO_HINTS: 'no_identifier_hints',
  EXACT_MATCH: 'exact_match',
  CANDIDATE_MATCH: 'candidate_match',
  AMBIGUOUS: 'identifier_ambiguity',
  NOT_FOUND: 'identifier_not_found',
};

const UUID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/ig;
const EXPLICIT_IDENTIFIER_PATTERN = /\b(?:key|id|memory|artifact|record|source)\s*(?:=|:|is|named|called)?\s*["'`]?([a-z0-9][a-z0-9_.:/-]{7,})["'`]?/ig;
const COLON_KEY_PATTERN = /\b[a-z][a-z0-9_]+:[a-z0-9][a-z0-9_.:/-]{5,}\b/ig;
const STRUCTURED_TOKEN_PATTERN = /\b[a-z0-9][a-z0-9_.:-]{11,}\b/ig;
const IDENTIFIER_CUE_PATTERN = /\b(?:key|id|memory|artifact|record|source|session_debrief|ai_adr|batch\d+|extract|reference|paper)\b/i;
const MAX_IDENTIFIER_HINTS = 8;

const NON_IDENTIFIER_TOKENS = new Set([
  'architecture',
  'reasoning',
  'implementation',
  'retrieval',
  'temporal',
  'continuity',
  'connected',
]);

function normalizeHint(value = '') {
  return String(value || '')
    .trim()
    .replace(/^[("'`<\[]+/, '')
    .replace(/[)"'`>\],.;:]+$/, '')
    .trim();
}

function addHint(hints, seen, raw) {
  const hint = normalizeHint(raw);
  if (hint.length < 8) return;
  if (NON_IDENTIFIER_TOKENS.has(hint.toLowerCase())) return;
  const key = hint.toLowerCase();
  if (seen.has(key)) return;
  seen.add(key);
  hints.push(hint);
}

export function extractIdentifierHints(queryText = '') {
  const text = String(queryText || '');
  const hints = [];
  const seen = new Set();

  for (const match of text.matchAll(UUID_PATTERN)) {
    addHint(hints, seen, match[0]);
  }
  for (const match of text.matchAll(EXPLICIT_IDENTIFIER_PATTERN)) {
    addHint(hints, seen, match[1]);
  }
  for (const match of text.matchAll(COLON_KEY_PATTERN)) {
    addHint(hints, seen, match[0]);
  }
  for (const match of text.matchAll(STRUCTURED_TOKEN_PATTERN)) {
    const token = normalizeHint(match[0]);
    const separatorCount = (token.match(/[-_:./]/g) || []).length;
    if (separatorCount >= 2 || /^batch\d+/i.test(token) || /^ai_adr:/i.test(token)) {
      addHint(hints, seen, token);
    }
  }

  return hints.slice(0, MAX_IDENTIFIER_HINTS);
}

export function hasIdentifierRecallCue({ queryText = '', key = '', memoryId = '' } = {}) {
  if (String(key || '').trim() || String(memoryId || '').trim()) return true;
  const hints = extractIdentifierHints(queryText);
  if (hints.length === 0) return false;
  return IDENTIFIER_CUE_PATTERN.test(String(queryText || ''));
}

function escapeLike(value = '') {
  return String(value).replace(/[\\%_]/g, (char) => `\\${char}`);
}

function buildPlaceholder(status, diagnostics = {}) {
  if (![IDENTIFIER_RECALL_STATUS.AMBIGUOUS, IDENTIFIER_RECALL_STATUS.NOT_FOUND, IDENTIFIER_RECALL_STATUS.NO_HINTS].includes(status)) {
    return null;
  }

  return {
    type: 'identifier_placeholder',
    reason: status,
    action: status === IDENTIFIER_RECALL_STATUS.AMBIGUOUS
      ? 'choose_a_candidate_or_supply_exact_key'
      : 'supply_exact_key_or_memory_id',
    source_papers: [
      'Generative Retrieval Overcomes Limitations of Dense Retrieval but Struggles with Identifier Ambiguity',
      'From Guessing to Placeholding',
    ],
    candidate_count: diagnostics.candidate_count || 0,
    ranking_math_changed: false,
  };
}

function decorateRow(row, status) {
  const exact = status === IDENTIFIER_RECALL_STATUS.EXACT_MATCH;
  return {
    ...row,
    identifier_match: {
      status,
      exact,
      paper: 'Generative Retrieval identifier ambiguity guard',
    },
    similarity: exact ? 1 : 0,
    rerank_score: exact ? 1 : 0,
    recall_confidence: exact ? 1 : 0,
  };
}

export async function lookupIdentifierCandidates({
  queryText = '',
  exactKey = '',
  memoryId = '',
  companyId = AIMOS_COMPANY_ID,
  agentId,
  clearanceLevel = 10,
  limit = 10,
  memoryTypeFilter = '',
  sourceFilter = '',
  dataClassFilter = null,
  queryFn = defaultQuery,
} = {}) {
  if (!agentId) throw new Error('lookupIdentifierCandidates: agentId is required (no default)');
  const explicitKey = normalizeHint(exactKey);
  const explicitMemoryId = normalizeHint(memoryId);
  const hints = [
    ...extractIdentifierHints(queryText),
    explicitKey,
    explicitMemoryId,
  ].filter(Boolean);
  const uniqueHints = [...new Map(hints.map((hint) => [hint.toLowerCase(), hint])).values()].slice(0, MAX_IDENTIFIER_HINTS);

  if (uniqueHints.length === 0) {
    const diagnostics = {
      status: IDENTIFIER_RECALL_STATUS.NO_HINTS,
      hints: [],
      candidate_count: 0,
      ranking_math_changed: false,
    };
    return {
      status: IDENTIFIER_RECALL_STATUS.NO_HINTS,
      memories: [],
      candidates: [],
      diagnostics,
      placeholder: buildPlaceholder(IDENTIFIER_RECALL_STATUS.NO_HINTS, diagnostics),
    };
  }

  const params = [companyId, clearanceLevel, agentId];
  let whereClause = `
    company_id = $1
    AND clearance_level <= $2
    AND (clearance_level > 2 OR agent_id = $3 OR agent_id IS NULL)
  `;

  if (Array.isArray(dataClassFilter) && dataClassFilter.length > 0) {
    params.push(dataClassFilter);
    whereClause += ` AND COALESCE(data_class, 'public') = ANY($${params.length}::text[])`;
  }

  if (memoryTypeFilter) {
    params.push(memoryTypeFilter);
    whereClause += ` AND memory_type = $${params.length}`;
  }

  if (sourceFilter) {
    params.push(sourceFilter);
    whereClause += ` AND source = $${params.length}`;
  }

  const matchClauses = [];
  for (const hint of uniqueHints) {
    params.push(hint);
    const exactParam = params.length;
    matchClauses.push(`key = $${exactParam}`);
    matchClauses.push(`id::text = $${exactParam}`);

    params.push(`%${escapeLike(hint)}%`);
    matchClauses.push(`key ILIKE $${params.length} ESCAPE '\\'`);
  }

  whereClause += ` AND (${matchClauses.join(' OR ')})`;

  params.push(uniqueHints);
  const exactHintsParam = params.length;
  params.push(Math.min(Math.max(Number(limit || 10), 1), 50));
  const limitParam = params.length;

  const result = await queryFn(
    `SELECT id, key, value, agent_id, memory_type, scope, source, clearance_level,
            retrieval_weight, created_at, updated_at, last_verified_at,
            verified_by, verification_basis, freshness_state
     FROM aimos_memories
     WHERE ${whereClause}
     ORDER BY
       CASE WHEN key = ANY($${exactHintsParam}::text[]) OR id::text = ANY($${exactHintsParam}::text[]) THEN 0 ELSE 1 END,
       LENGTH(key) ASC,
       updated_at DESC
     LIMIT $${limitParam}`,
    params
  );

  const rows = result.rows || [];
  const exactHintSet = new Set(uniqueHints.map((hint) => hint.toLowerCase()));
  const exactRows = rows.filter((row) =>
    exactHintSet.has(String(row.key || '').toLowerCase()) ||
    exactHintSet.has(String(row.id || '').toLowerCase())
  );

  if (exactRows.length > 0) {
    const memories = exactRows.map((row) => decorateRow(row, IDENTIFIER_RECALL_STATUS.EXACT_MATCH));
    const diagnostics = {
      status: IDENTIFIER_RECALL_STATUS.EXACT_MATCH,
      hints: uniqueHints,
      candidate_count: rows.length,
      returned_count: memories.length,
      ambiguity_guard: true,
      ranking_math_changed: false,
    };
    return {
      status: IDENTIFIER_RECALL_STATUS.EXACT_MATCH,
      memories,
      candidates: rows,
      diagnostics,
      placeholder: null,
    };
  }

  if (rows.length === 0) {
    const diagnostics = {
      status: IDENTIFIER_RECALL_STATUS.NOT_FOUND,
      hints: uniqueHints,
      candidate_count: 0,
      ambiguity_guard: true,
      ranking_math_changed: false,
    };
    return {
      status: IDENTIFIER_RECALL_STATUS.NOT_FOUND,
      memories: [],
      candidates: [],
      diagnostics,
      placeholder: buildPlaceholder(IDENTIFIER_RECALL_STATUS.NOT_FOUND, diagnostics),
    };
  }

  const distinctKeys = new Set(rows.map((row) => String(row.key || row.id || '').toLowerCase()));
  if (distinctKeys.size > 1) {
    const diagnostics = {
      status: IDENTIFIER_RECALL_STATUS.AMBIGUOUS,
      hints: uniqueHints,
      candidate_count: rows.length,
      candidate_keys: rows.map((row) => row.key || row.id).filter(Boolean),
      ambiguity_guard: true,
      ranking_math_changed: false,
    };
    return {
      status: IDENTIFIER_RECALL_STATUS.AMBIGUOUS,
      memories: [],
      candidates: rows,
      diagnostics,
      placeholder: buildPlaceholder(IDENTIFIER_RECALL_STATUS.AMBIGUOUS, diagnostics),
    };
  }

  const memories = rows.slice(0, 1).map((row) => decorateRow(row, IDENTIFIER_RECALL_STATUS.CANDIDATE_MATCH));
  const diagnostics = {
    status: IDENTIFIER_RECALL_STATUS.CANDIDATE_MATCH,
    hints: uniqueHints,
    candidate_count: rows.length,
    returned_count: memories.length,
    ambiguity_guard: true,
    ranking_math_changed: false,
  };

  return {
    status: IDENTIFIER_RECALL_STATUS.CANDIDATE_MATCH,
    memories,
    candidates: rows,
    diagnostics,
    placeholder: null,
  };
}
