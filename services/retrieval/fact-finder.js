/**
 * fact-finder.js — Retrieval Agent 1: Structured Fact Matching
 * Source: ASMR pipeline (MemGPT, Packer 2023), HippoRAG (Gutierrez 2024)
 * Additive Batch9 Wave1 authority: Fast-Slow Planning and RNNs Are Not
 * Transformers (Yet). Typed declarative/episodic fact search now surfaces
 * all-pass failures to the orchestrator so slow-path diagnostics can be honest;
 * fact ranking and memory filters remain unchanged.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: retrieval-orchestrator.js (Parallel agent 1)
 * 2. → Pulls from: aimos_memories (Vector + SQL keyword search)
 * 3. → Pulls from: memory_type_filter (Declarative vs Episodic)
 * 4. ↔ Interacts with: context-builder.js (Provides initial seed facts)
 *
 * LOGIC GUIDE: Searches for direct facts and explicit statements. 
 * Prevents book chunks from drowning entity records via strict type filtering.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { sessionKeyLikePattern } from '../shared/session-scope.js';

// ─── Live DB search (used when no searchFn is injected) ───────────────────────
// Lazy-imported to allow test mocking without a live DB.
async function defaultSearchFn(pool, query, opts = {}) {
  const { limit = 10, clientId, companyId = AIMOS_COMPANY_ID, sessionId } = opts;

  // Keyword match on value + key for direct fact retrieval.
  // Splits query into tokens and matches any token against value/key text.
  const tokens = query
    .toLowerCase()
    .split(/\W+/)
    .filter(t => t.length > 2)
    .slice(0, 8);

  if (tokens.length === 0) return [];

  // Build a parameterised ILIKE query across tokens
  // Also filter to entity-bearing memory types so book chunks don't dominate
  const conditions = tokens.map((_, i) => `(LOWER(m.value) LIKE $${i + 2} OR LOWER(m.key) LIKE $${i + 2})`);
  const params = [companyId, ...tokens.map(t => `%${t}%`)];

  if (clientId) {
    conditions.push(`m.agent_id = $${params.length + 1}`);
    params.push(clientId);
  }

  // ── SESSION SCOPING: filter to session-ingested data ──────────────────
  // When sessionId is provided, restrict to keys prefixed with "sess:<id>:"
  // This prevents retrieval from pulling all 10K+ memories.
  let sessionClause = '';
  if (sessionId) {
    params.push(sessionKeyLikePattern(sessionId));
    sessionClause = `AND m.key LIKE $${params.length} ESCAPE '\\'`;
  }

  // Restrict to fact-bearing types so raw book extracts do not crowd out
  // entity records, episodic facts, or native retained conversation turns.
  const sql = `
    SELECT
      m.id::text,
      m.key,
      m.value,
      m.memory_type,
      m.source,
      m.credit_score AS confidence_score,
      m.created_at,
      m.is_correction,
      m.supersedes_id
    FROM aimos_memories m
    WHERE m.company_id = $1
      AND m.memory_type IN ('declarative', 'episodic', 'conversation_feed', 'session_exchange')
      ${sessionClause}
      AND (${conditions.join(' OR ')})
    ORDER BY m.created_at DESC
    LIMIT ${Math.min(Number(limit) || 10, 50)}
  `;

  const result = await pool.query(sql, params);

  return result.rows.map(r => ({
    id: r.id,
    key: r.key,
    value: r.value,
    memory_type: r.memory_type,
    source: r.source || 'aimos',
    confidence: parseFloat(r.confidence_score) || 0.7,
    entities: [],
    created_at: r.created_at
  }));
}

// ─── Typed Aimos vector search (used when searchFn is provided) ──────────────

/**
 * Run the injected searchFn across declarative facts, episodic facts, and
 * retained conversation turns, then merge and deduplicate.
 *
 * This prevents book chunks (tacit_knowledge, book_extract) from swamping
 * the cosine-similarity results against short entity record values.
 *
 * @param {Function} searchFn
 * @param {string} query
 * @param {Object} opts
 * @returns {Promise<Array>}
 */
async function typedVectorSearch(searchFn, query, opts = {}) {
  const requestedLimit = Math.max(1, Number(opts.limit || 10));

  const [declarativeResults, episodicResults, conversationResults, exchangeResults] = await Promise.allSettled([
    searchFn(query, { ...opts, limit: requestedLimit, memory_type_filter: 'declarative', mode: 'factual' }),
    searchFn(query, { ...opts, limit: requestedLimit, memory_type_filter: 'episodic', mode: 'factual' }),
    searchFn(query, { ...opts, limit: requestedLimit, memory_type_filter: 'conversation_feed', mode: 'factual' }),
    searchFn(query, { ...opts, limit: requestedLimit, memory_type_filter: 'session_exchange', mode: 'factual' }),
  ]);

  if (declarativeResults.status === 'rejected'
    && episodicResults.status === 'rejected'
    && conversationResults.status === 'rejected'
    && exchangeResults.status === 'rejected') {
    throw new Error(`typed fact search failed: ${declarativeResults.reason?.message || episodicResults.reason?.message || conversationResults.reason?.message || exchangeResults.reason?.message || 'unknown error'}`);
  }

  const declarative = declarativeResults.status === 'fulfilled' ? (declarativeResults.value || []) : [];
  const episodic    = episodicResults.status    === 'fulfilled' ? (episodicResults.value    || []) : [];
  const conversation = conversationResults.status === 'fulfilled' ? (conversationResults.value || []) : [];
  const exchanges = exchangeResults.status === 'fulfilled' ? (exchangeResults.value || []) : [];

  // Merge and deduplicate by id (preserve declaration order — declarative first)
  const seen = new Set();
  const merged = [];
  for (const item of [...declarative, ...episodic, ...conversation, ...exchanges]) {
    const key = item.id ?? item.memory_id ?? JSON.stringify(item.value);
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(item);
    }
  }

  return merged.slice(0, requestedLimit);
}

/**
 * Find facts matching a query.
 *
 * @param {string} query - User question or search phrase
 * @param {Object} opts
 * @param {Function} [opts.searchFn]   - Async (query, opts) => [{id, key, value, confidence, source, entities}]
 *                                       If omitted, uses live DB keyword search (requires opts.pool)
 * @param {Object}   [opts.pool]       - pg Pool instance (required when searchFn not provided)
 * @param {number}   [opts.limit=10]   - Max results
 * @param {string}   [opts.clientId]   - Filter by agent/client id
 * @param {string}   [opts.companyId]  - Tenant scope (defaults to COMPANY_ID env)
 * @param {string}   [opts.sessionId]  - Session scope for ASMR-ingested data filtering
 * @returns {Promise<{ facts: Array, latencyMs: number, agentType: string, queryUsed: string }>}
 */
export async function findFacts(query, opts = {}) {
  const start = Date.now();
  const { searchFn, pool, limit = 10, clientId, companyId, sessionId } = opts;

  if (!searchFn && !pool) {
    throw new Error('fact-finder: either searchFn or pool is required');
  }

  let rawResults;
  if (searchFn) {
    // Use typed dual-pass search: declarative + episodic to surface entity records
    rawResults = await typedVectorSearch(searchFn, query, { limit, clientId, companyId, sessionId });
  } else {
    rawResults = await defaultSearchFn(pool, query, { limit, clientId, companyId, sessionId });
  }

  const facts = (rawResults || []).map(r => ({
    id: r.id,
    value: r.value,
    key: r.key,
    confidence: typeof r.confidence === 'number' ? r.confidence
      : typeof r.rerank_score === 'number' ? r.rerank_score
      : 0.5,
    source: r.source || 'aimos',
    entities: Array.isArray(r.entities) ? r.entities : [],
    memoryType: r.memory_type || r.memoryType || null
  }));

  // Sort descending by confidence so highest-quality facts bubble up
  facts.sort((a, b) => b.confidence - a.confidence);

  return {
    facts,
    latencyMs: Date.now() - start,
    agentType: 'fact-finder',
    queryUsed: query
  };
}
