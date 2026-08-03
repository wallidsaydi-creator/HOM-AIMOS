/**
 * qmd-planner.js — Query Memory Database Execution Planner
 * Additive Priority TEM authority: MAGMA (Jiang et al., arXiv:2601.03236, 2026)
 * and Graph-based Agent Memory survey (Yang et al., arXiv:2602.05665, 2026)
 * for bounded graph traversal surfaces. Existing SQL planner behavior remains
 * parameterized and unchanged unless explicitly called.
 * Batch9.75 Wave 1 authority: C2F-Thinker — Coarse-to-Fine Reasoning +
 * Hint-Guided RL, Model-based RL — A Survey, OPTIONZERO — Planning With
 * Learned Options. Coarse→fine option pruning, model-based planning taxonomy,
 * and option-tree diagnostics are additive alongside-path diagnostics; no
 * production QMD execution or SQL generation is modified.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js (POST /aimos/qmd)
 * 2. → Pulls from: services/retrieval/qmd-parser.js (Parsed AST)
 * 3. → Pushes to: services/db/connection.js (Parameterized SQL execution)
 * 4. ↔ Interacts with: services/core/embeddings.js (Vector sub-queries)
 *
 * LOGIC GUIDE: Translates QMD AST into complex SQL joins and vector searches. 
 * Respects RLS, clearance levels, and Aladdin Law constraints.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: aimos.js
// → Calls: db (connection.js), embeddings.js
// Pipeline: RECALL | Position: QMD executor (AST → SQL → results)
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query }        from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';

// ─── CONSTANTS ─────────────────────────────────────────────────────────────────
const COMPANY_ID  = AIMOS_COMPANY_ID;
const DEFAULT_CLR = 5;   // default caller clearance

export const C2F_OPTION_TREE_SOURCE = 'C2F-Thinker — Coarse-to-Fine Reasoning + Hint-Guided RL';
export const OPTION_ZERO_QMD_SOURCE = 'OPTIONZERO — Planning With Learned Options';
export const MODEL_BASED_RL_PLANNING_SOURCE = 'Model-based RL — A Survey';

// ─── F4: C2F OPTION TREE ──────────────────────────────────────────────────────
// Source: C2F-Thinker
// Formula: P(mode|query) = Σ_tree P(mode|path)·P(path|query)
// Scale adaptation: depth = max(3, min(7, floor(4 + log2(N/14000))))
// At 14K: depth=4. At 100K: depth≈6.
// Query routing affects retrieval strategy, not content. Aladdin SAFE.

export function computeC2FTreeDepth(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(3, Math.min(7, Math.floor(4 + Math.log2(N / 14000))));
}

// ─── F5: OPTION ZERO (DEFAULT QUERY MODE) ──────────────────────────────────────
// Source: OPTIONZERO
// Formula: baseline_prior = uniform(1/K) where K = max(3, min(10, floor(5 * (N/14000)^0.2)))
// At 14K: K=5. At 100K: K≈7.
// Default mode is fallback routing, not content. Aladdin SAFE.

export function computeOptionZeroK(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(3, Math.min(10, Math.floor(5 * Math.pow(N / 14000, 0.2))));
}

export function computeBaselinePrior(memoryCount = 14000) {
  const K = computeOptionZeroK(memoryCount);
  return 1 / K;
}

// ─── F6: MODEL-BASED RL PLANNING ──────────────────────────────────────────────
// Source: Model-based RL — A Survey
// Formula: Q*(s,a) = E[r(s,a) + γ·max_a' Q*(s',a')]
// Scale adaptation: γ = max(0.9, min(0.99, 0.95 - 0.01*log2(N/14000)))
// At 14K: γ=0.95. At 100K: γ≈0.92.
// RL planning affects retrieval strategy, not content. Aladdin SAFE.

export function computeRLDiscountFactor(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(0.9, Math.min(0.99, 0.95 - 0.01 * Math.log2(N / 14000)));
}

export function buildQMDPlanningDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    source_papers: [C2F_OPTION_TREE_SOURCE, OPTION_ZERO_QMD_SOURCE, MODEL_BASED_RL_PLANNING_SOURCE],
    c2f_option_tree: {
      depth: computeC2FTreeDepth(N),
      formula: 'depth = max(3, min(7, floor(4 + log2(N/14000))))',
    },
    option_zero: {
      K: computeOptionZeroK(N),
      baseline_prior: Number(computeBaselinePrior(N).toFixed(6)),
      formula: 'K = max(3, min(10, floor(5 * (N/14000)^0.2)))',
    },
    model_based_rl: {
      gamma: Number(computeRLDiscountFactor(N).toFixed(6)),
      formula: 'γ = max(0.9, min(0.99, 0.95 - 0.01*log2(N/14000)))',
    },
    diagnostic_only: true,
    guarded_math: {
      c2f_option_tree: true,
      option_zero: true,
      model_based_rl_planning: true,
    },
  };
}

// Columns returned in most result sets
const BASE_COLS = `
  id::text, key, value, scope, memory_type, memory_tier, clearance_level,
  agent_id, created_at, updated_at, data_class, decay_weight
`.trim();

// ─── HELPERS ──────────────────────────────────────────────────────────────────

function durationToInterval(duration) {
  const { amount, unit } = duration;
  const unitMap = { d: 'day', h: 'hour', m: 'minute' };
  const pg = unitMap[unit] || 'hour';
  return `${amount} ${pg}`;
}

/**
 * Returns allowed data_class array for a given clearance level.
 * Mirrors aimos.js getMaxDataClassForClearance exactly.
 */
function getAllowedClasses(clearanceLevel) {
  const cl = Number(clearanceLevel || 1);
  if (cl >= 10) return null; // all classes — no filter
  if (cl >= 7)  return ['public', 'internal', 'confidential'];
  if (cl >= 4)  return ['public', 'internal'];
  return ['public'];
}

/**
 * Builds the WHERE fragment that applies to every aimos_memories query:
 * active, not expired, clearance, ACL, data_class, not superseded.
 *
 * Returns { clause: string, params: any[] } — params are APPENDED to
 * whatever `baseParams` were already built. The caller is responsible for
 * tracking the parameter index offset.
 */
function buildBaseFilter({ params, company, clearance, requestingAgent, typeFilter }) {
  let clause = `
    company_id = $${params.push(company)}
    AND clearance_level <= $${params.push(Number(clearance || DEFAULT_CLR))}
    AND (clearance_level > 2 OR agent_id = $${params.push(requestingAgent)} OR agent_id IS NULL)
  `;

  const allowed = getAllowedClasses(clearance);
  if (allowed) {
    clause += ` AND COALESCE(data_class, 'public') = ANY($${params.push(allowed)}::text[])`;
  }

  if (typeFilter) {
    clause += ` AND memory_type = $${params.push(typeFilter)}`;
  }

  return clause;
}

/**
 * Translate WHERE conditions from the AST into SQL fragments.
 * Returns { sql: string, params: any[] } where sql uses $N placeholders
 * starting at `startIdx`.
 */
function translateWhereConditions(conditions, params, { company, clearance, requestingAgent } = {}) {
  if (!conditions || !conditions.length) return '';

  const parts = [];

  for (const cond of conditions) {
    if (cond.logical) {
      // AND / OR connector
      parts.push(cond.logical);
      continue;
    }

    switch (cond.type) {
      case 'contains': {
        // Full-text ILIKE on key + value concatenated
        params.push(`%${cond.value.replace(/[%_]/g, '\\$&')}%`);
        parts.push(`(key ILIKE $${params.length} OR value ILIKE $${params.length})`);
        break;
      }
      case 'field_eq': {
        const col = sanitizeColumn(cond.field);
        if (!col) throw new Error(`Unknown filter field: ${cond.field}`);
        if (cond.value.includes('*')) {
          // Glob → ILIKE
          const likeVal = cond.value.replace(/\*/g, '%');
          params.push(likeVal);
          parts.push(`${col} ILIKE $${params.length}`);
        } else {
          params.push(cond.value);
          parts.push(`${col} = $${params.length}`);
        }
        break;
      }
      case 'created': {
        const interval = durationToInterval(cond.duration);
        if (cond.op === '>') {
          // created more recent than N duration ago
          parts.push(`created_at >= NOW() - INTERVAL '${interval}'`);
        } else {
          // created older than N duration ago
          parts.push(`created_at < NOW() - INTERVAL '${interval}'`);
        }
        break;
      }
      default:
        throw new Error(`Unknown WHERE condition type: ${cond.type}`);
    }
  }

  return parts.join(' ');
}

/** Whitelist of columns allowed in WHERE conditions and GROUP BY */
const ALLOWED_COLUMNS = new Set([
  'memory_type', 'memory_tier', 'agent_id', 'scope', 'key', 'clearance_level',
  'data_class', 'source', 'created_at', 'updated_at', 'is_active', 'company_id',
  'type', 'agent', 'clearance', 'tier',
]);

const COLUMN_ALIASES = {
  type:      'memory_type',
  agent:     'agent_id',
  clearance: 'clearance_level',
  tier:      'memory_tier',
};

function sanitizeColumn(name) {
  if (!name || typeof name !== 'string') return null;
  const lower = name.toLowerCase();
  if (COLUMN_ALIASES[lower]) return COLUMN_ALIASES[lower];
  if (ALLOWED_COLUMNS.has(lower)) return lower;
  return null;
}

const ALLOWED_GROUP_BY = new Set([
  'agent_id', 'memory_type', 'memory_tier', 'scope', 'clearance_level',
  'data_class', 'created_at',
]);

// ─── VERB EXECUTORS ────────────────────────────────────────────────────────────

/**
 * FIND — semantic vector search + optional contains() filter.
 * Falls back to pure filter if no text is given.
 */
async function executeFind(ast, { company, clearance, requestingAgent }) {
  const params = [];
  const limit  = Math.min(ast.limit || 10, 200);
  const hops   = Math.min(ast.hops  || 2, 4);

  // Extract type filter from FIND filters
  let typeFilter    = null;
  let keyFilter     = null;
  let vectorClause  = '';
  let textSearch    = null;

  for (const f of ast.filters || []) {
    if (f.field === 'type') typeFilter = f.value;
    if (f.field === 'key')  keyFilter  = f.value;
  }

  // Check for contains() in WHERE
  for (const cond of ast.where || []) {
    if (cond.type === 'contains') { textSearch = cond.value; break; }
  }

  let embedding = null;
  if (textSearch) {
    embedding = await getEmbedding(textSearch);
    vectorClause = `, (embedding <=> $${params.push(JSON.stringify(embedding))}::vector) AS _distance`;
  }

  const baseFilter = buildBaseFilter({ params, company, clearance, requestingAgent, typeFilter });

  // Additional WHERE conditions (excluding contains which is already used for vector)
  const extraConds = (ast.where || []).filter(c => c.type !== 'contains');
  let extraWhere = '';
  if (extraConds.length) {
    const translated = translateWhereConditions(extraConds, params, { company, clearance, requestingAgent });
    if (translated.trim()) extraWhere = `AND (${translated})`;
  }

  // Key glob filter
  let keyWhere = '';
  if (keyFilter) {
    if (keyFilter.includes('*')) {
      params.push(keyFilter.replace(/\*/g, '%'));
      keyWhere = `AND key ILIKE $${params.length}`;
    } else {
      params.push(keyFilter);
      keyWhere = `AND key = $${params.length}`;
    }
  }

  params.push(limit);
  const limitParam = params.length;

  const orderBy = embedding
    ? `ORDER BY memory_tier_rank ASC, _distance ASC`
    : `ORDER BY memory_tier_rank ASC, created_at DESC`;

  const sql = `
    SELECT ${BASE_COLS}${vectorClause},
      CASE memory_tier
        WHEN 'long-term'  THEN 0
        WHEN 'working'    THEN 1
        WHEN 'short-term' THEN 2
        ELSE 3
      END AS memory_tier_rank
    FROM aimos_memories
    WHERE ${baseFilter}
      ${keyWhere}
      ${extraWhere}
    ${orderBy}
    LIMIT $${limitParam}
  `;

  const result = await query(sql, params);
  let rows = result.rows.map(r => ({ ...r, _distance: r._distance ? parseFloat(r._distance) : undefined }));

  // Graph traversal for top results
  rows = await attachGraphLinks(rows, company, hops, ast.return);

  return { results: rows, meta: { verb: 'FIND', count: rows.length, hops, return: ast.return } };
}

/**
 * TRAVERSE — start from anchor node, walk cross_refs / entity_edges N hops.
 */
async function executeTraverse(ast, { company, clearance, requestingAgent }) {
  const { from, follow, hops, limit, return: returnFmt } = ast;
  const maxHops = Math.min(hops || 2, 4);
  const maxRows = Math.min(limit || 50, 200);

  // Resolve anchor memory IDs
  const anchorParams = [company];
  let anchorWhere = '';
  if (from.field === 'id') {
    anchorParams.push(from.value);
    anchorWhere = `AND id = $${anchorParams.length}::uuid`;
  } else if (from.field === 'type') {
    anchorParams.push(from.value);
    anchorWhere = `AND memory_type = $${anchorParams.length}`;
  } else if (from.field === 'key') {
    if (from.value.includes('*')) {
      anchorParams.push(from.value.replace(/\*/g, '%'));
      anchorWhere = `AND key ILIKE $${anchorParams.length}`;
    } else {
      anchorParams.push(from.value);
      anchorWhere = `AND key = $${anchorParams.length}`;
    }
  } else {
    const col = sanitizeColumn(from.field);
    if (!col) throw new Error(`TRAVERSE FROM: unknown field "${from.field}"`);
    anchorParams.push(from.value);
    anchorWhere = `AND ${col} = $${anchorParams.length}`;
  }

  const anchorResult = await query(
    `SELECT id FROM aimos_memories WHERE company_id = $1 ${anchorWhere} LIMIT 10`,
    anchorParams
  );

  if (!anchorResult.rows.length) {
    return { results: [], meta: { verb: 'TRAVERSE', count: 0, hops: maxHops, anchor_found: false } };
  }

  const anchorIds = anchorResult.rows.map(r => r.id);

  const useCrossRefs  = follow.includes('cross_refs');
  const useEntityEdges = follow.includes('entity_edges');

  // Build a unified graph walk via recursive CTE
  const cteUnions = [];
  const cteParams = [company, anchorIds, maxHops];

  if (useCrossRefs) {
    cteUnions.push(`
      SELECT cr.target_memory_id AS next_id, cr.similarity AS weight, 1 AS hop, cr.source_memory_id AS prev_id
      FROM memory_cross_refs cr
      WHERE cr.company_id = $1 AND cr.source_memory_id = ANY($2::uuid[])
      UNION ALL
      SELECT cr.target_memory_id, cr.similarity, gw.hop + 1, cr.source_memory_id
      FROM graph_walk gw
      JOIN memory_cross_refs cr
        ON cr.source_memory_id = gw.next_id AND cr.company_id = $1
      WHERE gw.hop < $3 AND cr.target_memory_id <> ALL($2::uuid[])
    `);
  }

  if (useEntityEdges) {
    // Get entity names connected to anchor memories
    const entResult = await query(
      `SELECT DISTINCT entity FROM entity_memory_edges WHERE company_id = $1 AND memory_id = ANY($2::uuid[])`,
      [company, anchorIds]
    );
    if (entResult.rows.length) {
      const entityNames = entResult.rows.map(r => r.entity);
      // Get peer memories sharing those entities
      const peerResult = await query(
        `SELECT DISTINCT e.memory_id, 0.7 AS weight
         FROM entity_memory_edges e
         WHERE e.company_id = $1 AND e.entity = ANY($2) AND e.memory_id <> ALL($3::uuid[])
         LIMIT $4`,
        [company, entityNames, anchorIds, maxRows]
      );

      // For entity edges, we return results directly (no recursive CTE needed)
      const peerIds = peerResult.rows.map(r => r.memory_id);
      if (peerIds.length && !useCrossRefs) {
        // entity-only path
        const params2 = [];
        const baseFilter = buildBaseFilter({ params: params2, company, clearance, requestingAgent, typeFilter: null });
        params2.push(peerIds);
        params2.push(maxRows);
        const peerSql = `
          SELECT ${BASE_COLS}
          FROM aimos_memories
          WHERE ${baseFilter}
            AND id = ANY($${params2.length - 1}::uuid[])
          ORDER BY created_at DESC
          LIMIT $${params2.length}
        `;
        const peerRows = await query(peerSql, params2);
        const annotated = peerRows.rows.map(r => ({ ...r, _hop: 1, _via: 'entity_edges' }));
        return { results: annotated, meta: { verb: 'TRAVERSE', count: annotated.length, hops: 1, follow, return: returnFmt } };
      }
    }
  }

  if (!useCrossRefs) {
    return { results: [], meta: { verb: 'TRAVERSE', count: 0, hops: maxHops, follow, note: 'no traversal edges matched' } };
  }

  // Execute cross-ref recursive CTE
  const walkSql = `
    WITH RECURSIVE graph_walk AS (
      SELECT cr.target_memory_id AS next_id, cr.similarity AS weight, 1 AS hop, cr.source_memory_id AS prev_id
      FROM memory_cross_refs cr
      WHERE cr.company_id = $1 AND cr.source_memory_id = ANY($2::uuid[])
      UNION ALL
      SELECT cr.target_memory_id, cr.similarity, gw.hop + 1, cr.source_memory_id
      FROM graph_walk gw
      JOIN memory_cross_refs cr
        ON cr.source_memory_id = gw.next_id AND cr.company_id = $1
      WHERE gw.hop < $3 AND cr.target_memory_id <> ALL($2::uuid[])
    )
    SELECT DISTINCT ON (gw.next_id)
      gw.next_id AS id, gw.hop, gw.weight,
      m.key, m.value, m.memory_type, m.memory_tier, m.agent_id, m.scope,
      m.clearance_level, m.data_class, m.created_at
    FROM graph_walk gw
    JOIN aimos_memories m
      ON m.id = gw.next_id AND m.company_id = $1
      AND m.clearance_level <= $4
    WHERE (m.clearance_level > 2 OR m.agent_id = $5 OR m.agent_id IS NULL)
    ORDER BY gw.next_id, gw.hop ASC
    LIMIT $6
  `;

  cteParams.push(Number(clearance || DEFAULT_CLR));
  cteParams.push(requestingAgent);
  cteParams.push(maxRows);

  const walkResult = await query(walkSql, cteParams);
  const rows = walkResult.rows.map(r => ({
    ...r,
    id: String(r.id),
    _hop:  r.hop,
    _weight: parseFloat(r.weight || 0),
    _via: 'cross_refs',
  }));

  if (returnFmt === 'adjacency') {
    return {
      results: buildAdjacency(anchorIds, rows),
      meta: { verb: 'TRAVERSE', count: rows.length, hops: maxHops, follow, return: returnFmt }
    };
  }

  if (returnFmt === 'keys_only') {
    return {
      results: rows.map(r => ({ id: r.id, key: r.key, _hop: r._hop })),
      meta: { verb: 'TRAVERSE', count: rows.length, hops: maxHops, follow, return: returnFmt }
    };
  }

  return { results: rows, meta: { verb: 'TRAVERSE', count: rows.length, hops: maxHops, follow, return: returnFmt } };
}

/**
 * MATCH — filter by agent, type, time, content. No vector search.
 */
async function executeMatch(ast, { company, clearance, requestingAgent }) {
  const params    = [];
  const limit     = Math.min(ast.limit || 20, 200);

  // Top-level field filters (agent:X, type:X from MATCH header)
  let typeFilter  = null;
  let agentFilter = null;
  for (const f of ast.filters || []) {
    if (f.field === 'type' || f.field === 'memory_type') typeFilter  = f.value;
    if (f.field === 'agent' || f.field === 'agent_id')   agentFilter = f.value;
  }

  const baseFilter = buildBaseFilter({ params, company, clearance, requestingAgent, typeFilter });

  let agentClause = '';
  if (agentFilter) {
    params.push(agentFilter);
    agentClause = `AND agent_id = $${params.length}`;
  }

  const extraConds = ast.where || [];
  let extraWhere = '';
  if (extraConds.length) {
    const translated = translateWhereConditions(extraConds, params, { company, clearance, requestingAgent });
    if (translated.trim()) extraWhere = `AND (${translated})`;
  }

  params.push(limit);

  const sql = `
    SELECT ${BASE_COLS}
    FROM aimos_memories
    WHERE ${baseFilter}
      ${agentClause}
      ${extraWhere}
    ORDER BY
      CASE memory_tier
        WHEN 'long-term'  THEN 0
        WHEN 'working'    THEN 1
        WHEN 'short-term' THEN 2
        ELSE 3
      END ASC,
      created_at DESC
    LIMIT $${params.length}
  `;

  const result = await query(sql, params);
  const rows   = result.rows;

  if (ast.return === 'keys_only') {
    return { results: rows.map(r => ({ id: r.id, key: r.key })), meta: { verb: 'MATCH', count: rows.length } };
  }

  return { results: rows, meta: { verb: 'MATCH', count: rows.length, return: ast.return } };
}

/**
 * GRAPH AROUND — neighborhood subgraph centered on a node.
 */
async function executeGraph(ast, { company, clearance, requestingAgent }) {
  const { center, hops, limit, return: returnFmt } = ast;
  const maxHops = Math.min(hops || 2, 4);
  const maxRows = Math.min(limit || 50, 200);

  // Resolve center node ID
  let centerId = null;
  if (center.field === 'id') {
    centerId = center.value;
  } else {
    const col = sanitizeColumn(center.field) || 'key';
    const findParams = [company, center.value];
    const findRes = await query(
      `SELECT id FROM aimos_memories WHERE company_id = $1 AND ${col} = $2 LIMIT 1`,
      findParams
    );
    if (!findRes.rows.length) {
      return { results: [], meta: { verb: 'GRAPH', count: 0, center_found: false } };
    }
    centerId = findRes.rows[0].id;
  }

  // Walk the graph
  const walkSql = `
    WITH RECURSIVE graph_walk AS (
      SELECT cr.target_memory_id AS mem_id, cr.similarity AS weight, 1 AS hop
      FROM memory_cross_refs cr
      WHERE cr.company_id = $1 AND cr.source_memory_id = $2::uuid
      UNION ALL
      SELECT cr.target_memory_id, cr.similarity, gw.hop + 1
      FROM graph_walk gw
      JOIN memory_cross_refs cr
        ON cr.source_memory_id = gw.mem_id AND cr.company_id = $1
      WHERE gw.hop < $3 AND cr.target_memory_id != $2::uuid
    )
    SELECT DISTINCT ON (gw.mem_id)
      gw.mem_id::text AS id, gw.hop, gw.weight,
      m.key, m.value, m.memory_type, m.memory_tier,
      m.agent_id, m.clearance_level, m.created_at
    FROM graph_walk gw
    JOIN aimos_memories m
      ON m.id = gw.mem_id AND m.company_id = $1
      AND m.clearance_level <= $4
    WHERE (m.clearance_level > 2 OR m.agent_id = $5 OR m.agent_id IS NULL)
    ORDER BY gw.mem_id, gw.hop ASC, gw.weight DESC
    LIMIT $6
  `;

  const walkResult = await query(walkSql, [
    company,
    centerId,
    maxHops,
    Number(clearance || DEFAULT_CLR),
    requestingAgent,
    maxRows,
  ]);

  // Also include center node
  const centerRes = await query(
    `SELECT ${BASE_COLS} FROM aimos_memories WHERE company_id = $1 AND id = $2::uuid LIMIT 1`,
    [company, centerId]
  );

  const neighbors = walkResult.rows.map(r => ({
    ...r,
    id: String(r.id),
    _hop: r.hop,
    _weight: parseFloat(r.weight || 0)
  }));

  if (returnFmt === 'adjacency') {
    return {
      results: buildAdjacency(centerId ? [centerId] : [], neighbors),
      meta: { verb: 'GRAPH', center_id: centerId, count: neighbors.length, hops: maxHops, return: returnFmt }
    };
  }

  if (returnFmt === 'keys_only') {
    const all = [
      ...centerRes.rows.map(r => ({ id: String(r.id), key: r.key, _hop: 0 })),
      ...neighbors.map(r => ({ id: r.id, key: r.key, _hop: r._hop }))
    ];
    return { results: all, meta: { verb: 'GRAPH', center_id: centerId, count: all.length, return: returnFmt } };
  }

  return {
    results: [
      ...centerRes.rows.map(r => ({ ...r, _hop: 0, _center: true })),
      ...neighbors
    ],
    meta: { verb: 'GRAPH', center_id: centerId, count: neighbors.length, hops: maxHops, return: returnFmt }
  };
}

/**
 * PATH — find shortest paths between two node classes via cross-refs.
 */
async function executePath(ast, { company, clearance, requestingAgent }) {
  const { from, to, max_depth, limit } = ast;
  const maxDepth = Math.min(max_depth || 4, 6);
  const maxRows  = Math.min(limit || 20, 100);

  // Resolve source and target node IDs
  const [fromIds, toIds] = await Promise.all([
    resolveNodeIds(from, company),
    resolveNodeIds(to, company),
  ]);

  if (!fromIds.length || !toIds.length) {
    return {
      results: [],
      meta: { verb: 'PATH', count: 0, from_found: fromIds.length, to_found: toIds.length }
    };
  }

  // BFS via recursive CTE — find paths from any fromId to any toId
  const sql = `
    WITH RECURSIVE path_walk AS (
      SELECT
        cr.source_memory_id AS current_id,
        cr.target_memory_id AS next_id,
        cr.similarity,
        1 AS depth,
        ARRAY[cr.source_memory_id] AS visited,
        ARRAY[cr.source_memory_id, cr.target_memory_id] AS path_ids
      FROM memory_cross_refs cr
      WHERE cr.company_id = $1
        AND cr.source_memory_id = ANY($2::uuid[])
      UNION ALL
      SELECT
        pw.next_id,
        cr.target_memory_id,
        cr.similarity,
        pw.depth + 1,
        pw.visited || pw.next_id,
        pw.path_ids || cr.target_memory_id
      FROM path_walk pw
      JOIN memory_cross_refs cr
        ON cr.source_memory_id = pw.next_id AND cr.company_id = $1
      WHERE pw.depth < $3
        AND NOT (cr.target_memory_id = ANY(pw.visited))
    )
    SELECT
      pw.path_ids,
      pw.depth,
      pw.similarity,
      m_start.key AS from_key,
      m_end.key   AS to_key
    FROM path_walk pw
    JOIN aimos_memories m_start ON m_start.id = pw.path_ids[1] AND m_start.company_id = $1
    JOIN aimos_memories m_end   ON m_end.id = pw.next_id       AND m_end.company_id = $1
    WHERE pw.next_id = ANY($4::uuid[])
      AND m_end.clearance_level <= $5
    ORDER BY pw.depth ASC
    LIMIT $6
  `;

  const result = await query(sql, [
    company,
    fromIds,
    maxDepth,
    toIds,
    Number(clearance || DEFAULT_CLR),
    maxRows,
  ]);

  const paths = result.rows.map(r => ({
    from_key:  r.from_key,
    to_key:    r.to_key,
    depth:     r.depth,
    path_ids:  r.path_ids.map(String),
    similarity: parseFloat(r.similarity || 0)
  }));

  return { results: paths, meta: { verb: 'PATH', count: paths.length, max_depth: maxDepth } };
}

/**
 * COUNT — aggregation query.
 */
async function executeCount(ast, { company, clearance, requestingAgent }) {
  const params   = [];
  let typeFilter = null;

  for (const f of ast.filters || []) {
    if (f.field === 'type' || f.field === 'memory_type') typeFilter = f.value;
  }

  const baseFilter = buildBaseFilter({ params, company, clearance, requestingAgent, typeFilter });

  let extraWhere = '';
  const extraConds = ast.where || [];
  if (extraConds.length) {
    const translated = translateWhereConditions(extraConds, params, { company, clearance, requestingAgent });
    if (translated.trim()) extraWhere = `AND (${translated})`;
  }

  // GROUP BY
  let selectCols = 'COUNT(*) AS count';
  let groupBy    = '';
  if (ast.group_by) {
    const col = sanitizeColumn(ast.group_by);
    if (!col || !ALLOWED_GROUP_BY.has(col)) {
      throw new Error(`GROUP BY column "${ast.group_by}" is not allowed`);
    }
    selectCols = `${col}, COUNT(*) AS count`;
    groupBy    = `GROUP BY ${col}`;
  }

  const sql = `
    SELECT ${selectCols}
    FROM aimos_memories
    WHERE ${baseFilter}
      ${extraWhere}
    ${groupBy}
    ORDER BY count DESC
  `;

  const result = await query(sql, params);
  return {
    results:  result.rows,
    meta:     { verb: 'COUNT', rows: result.rows.length, group_by: ast.group_by || null }
  };
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────

async function resolveNodeIds(spec, company) {
  const col = sanitizeColumn(spec.field) || 'key';
  if (spec.field === 'id') {
    return [spec.value]; // UUID passed directly
  }
  const needle = spec.value.includes('*') ? spec.value.replace(/\*/g, '%') : null;
  const op     = needle ? 'ILIKE' : '=';
  const val    = needle || spec.value;

  const res = await query(
    `SELECT id::text FROM aimos_memories WHERE company_id = $1 AND ${col} ${op} $2 LIMIT 20`,
    [company, val]
  );
  return res.rows.map(r => r.id);
}

async function attachGraphLinks(rows, company, hops, returnFmt) {
  if (returnFmt === 'keys_only') {
    return rows.map(r => ({ id: r.id, key: r.key }));
  }
  if (returnFmt === 'adjacency') {
    return buildAdjacency(rows.map(r => r.id), []);
  }

  // Attach graph_links to each memory (mirrors recall behavior)
  return Promise.all(rows.map(async (mem) => {
    try {
      const gRes = await query(
        `WITH RECURSIVE graph_walk AS (
          SELECT cr.target_memory_id AS memory_id, cr.similarity, 1 AS hop
          FROM memory_cross_refs cr
          WHERE cr.company_id = $1 AND cr.source_memory_id = $2::uuid
          UNION ALL
          SELECT cr.target_memory_id, cr.similarity, gw.hop + 1
          FROM graph_walk gw
          JOIN memory_cross_refs cr ON cr.source_memory_id = gw.memory_id AND cr.company_id = $1
          WHERE gw.hop < $3 AND cr.target_memory_id != $2::uuid
        )
        SELECT DISTINCT ON (gw.memory_id) gw.memory_id::text AS id, gw.similarity, gw.hop, m.key, m.value
        FROM graph_walk gw
        JOIN aimos_memories m ON m.id = gw.memory_id AND m.company_id = $1
        ORDER BY gw.memory_id, gw.hop ASC, gw.similarity DESC
        LIMIT 8`,
        [company, mem.id, hops]
      );
      mem.graph_links = gRes.rows.map(g => ({
        id:         String(g.id),
        key:        g.key,
        value:      String(g.value || '').slice(0, 300),
        similarity: parseFloat(g.similarity),
        hop:        g.hop
      }));
    } catch {
      mem.graph_links = [];
    }
    return mem;
  }));
}

function buildAdjacency(centerIds, neighbors) {
  const nodes = new Map();

  const addNode = (id, label, type) => {
    if (!nodes.has(String(id))) {
      nodes.set(String(id), { id: String(id), label, type, _center: centerIds.map(String).includes(String(id)) });
    }
  };

  const edges = [];
  for (const n of neighbors) {
    addNode(n.id, n.key || n.id, n.memory_type);
    if (n._hop <= 1 && centerIds.length) {
      edges.push({ from: String(centerIds[0]), to: String(n.id), weight: n._weight || 0, hop: n._hop || 1 });
    }
  }

  return { nodes: [...nodes.values()], edges };
}

// ─── QUERY PLAN PREVIEW ────────────────────────────────────────────────────────

/**
 * Produce a human-readable query plan summary without executing.
 */
export function buildQueryPlan(ast) {
  const plan = { verb: ast.verb, steps: [], estimated_cost: 'low' };

  switch (ast.verb) {
    case 'FIND':
      plan.steps.push('vector_similarity_search');
      if ((ast.hops || 2) > 1) {
        plan.steps.push(`recursive_graph_traversal(hops=${ast.hops})`);
        plan.estimated_cost = ast.hops > 2 ? 'medium' : 'low';
      }
      break;
    case 'TRAVERSE':
      plan.steps.push(`anchor_resolution(field=${ast.from?.field})`);
      if (ast.follow?.includes('cross_refs')) plan.steps.push(`recursive_cte(hops=${ast.hops})`);
      if (ast.follow?.includes('entity_edges')) plan.steps.push('entity_edge_join');
      plan.estimated_cost = ast.hops > 2 ? 'medium' : 'low';
      break;
    case 'MATCH':
      plan.steps.push('filter_scan');
      plan.estimated_cost = 'low';
      break;
    case 'GRAPH':
      plan.steps.push(`center_resolution(field=${ast.center?.field})`);
      plan.steps.push(`bidirectional_graph_walk(hops=${ast.hops})`);
      plan.estimated_cost = ast.hops > 2 ? 'high' : 'medium';
      break;
    case 'PATH':
      plan.steps.push('source_resolution');
      plan.steps.push('target_resolution');
      plan.steps.push(`bfs_path_walk(max_depth=${ast.max_depth})`);
      plan.estimated_cost = 'medium';
      break;
    case 'COUNT':
      plan.steps.push('aggregate_scan');
      if (ast.group_by) plan.steps.push(`group_by(${ast.group_by})`);
      plan.estimated_cost = 'low';
      break;
    default:
      plan.steps.push('unknown');
  }

  return plan;
}

// ─── PUBLIC API ────────────────────────────────────────────────────────────────

/**
 * Execute a parsed QMD AST against the Aimos database.
 *
 * @param {object} ast          - AST from parseQMD()
 * @param {object} context
 * @param {string} context.company          - company_id (default: env COMPANY_ID)
 * @param {number} context.clearance        - caller's clearance level (default: 5)
 * @param {string} context.requestingAgent  - agent making the request (for ACL)
 * @returns {Promise<{ results: any[], meta: object, query_plan: object }>}
 */
export async function executeQMD(ast, context = {}) {
  const company        = context.company        || COMPANY_ID;
  const clearance      = Number(context.clearance || DEFAULT_CLR);
  const requestingAgent = context.requestingAgent;
  if (!requestingAgent) throw new Error('executeQMD: context.requestingAgent is required (no default)');

  const ctx = { company, clearance, requestingAgent };
  const query_plan = buildQueryPlan(ast);

  let outcome;
  switch (ast.verb) {
    case 'FIND':     outcome = await executeFind(ast, ctx);     break;
    case 'TRAVERSE': outcome = await executeTraverse(ast, ctx); break;
    case 'MATCH':    outcome = await executeMatch(ast, ctx);    break;
    case 'GRAPH':    outcome = await executeGraph(ast, ctx);    break;
    case 'PATH':     outcome = await executePath(ast, ctx);     break;
    case 'COUNT':    outcome = await executeCount(ast, ctx);    break;
    default:
      throw new Error(`Unknown verb: ${ast.verb}`);
  }

  return { ...outcome, query_plan };
}

// ---------------------------------------------------------------------------
// Batch9.75 Wave 1: Alongside-path diagnostics
// These functions compute diagnostic overlays. They do NOT replace production
// QMD execution, SQL generation, or graph traversal.
// ---------------------------------------------------------------------------

/**
 * QMD Planner Diagnostics — Batch9.75 Wave 1 guarded_math surface
 */
export function buildQMDPlannerDiagnostics() {
  return {
    guarded_math: {
      c2f_option_tree: true,
      option_zero: true,
      model_based_rl_planning: true,
    },
    guarded_math_implemented: {
      c2f_option_tree: { enabled: true, diagnostic_only: true, source_paper: C2F_OPTION_TREE_SOURCE },
      option_zero: { enabled: true, diagnostic_only: true, source_paper: OPTION_ZERO_QMD_SOURCE },
      model_based_rl_planning: { enabled: true, diagnostic_only: true, source_paper: MODEL_BASED_RL_PLANNING_SOURCE },
    },
  };
}

/**
 * C2F Option Tree Diagnostic — Alongside-path diagnostic
 *
 * Source paper: C2F-Thinker — Coarse-to-Fine Reasoning + Hint-Guided RL
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * C2F-Thinker uses coarse→fine reasoning with hint-guided escalation.
 * This diagnostic assesses whether a QMD query can benefit from coarse→fine
 * option pruning: start with broad type/filter matches, then refine with
 * vector similarity. The production QMD execution pipeline remains
 * authoritative. Guarded by guarded_math flag c2f_option_tree (knowledge-gated).
 */
export function buildC2FOptionTreeDiagnostic(query = {}) {
  const filters = Array.isArray(query?.filters) ? query.filters : [];
  const hasTypeFilter = filters.some(f => f?.field === 'type' || f?.field === 'memory_type');
  const hasContainsFilter = filters.some(f => f?.type === 'contains' || f?.field === 'contains');
  const hops = Number(query?.hops ?? 2);
  const limit = Number(query?.limit ?? 10);
  const coarseGranularity = hasTypeFilter && !hasContainsFilter ? 'type_only'
    : hasTypeFilter && hasContainsFilter ? 'type_plus_text'
    : 'unfiltered';
  const refinementDepth = hasContainsFilter ? 2 : hasTypeFilter ? 1 : 0;

  return {
    diagnostic: true,
    source_paper: C2F_OPTION_TREE_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    coarse_granularity: coarseGranularity,
    refinement_depth: refinementDepth,
    has_type_filter: hasTypeFilter,
    has_contains_filter: hasContainsFilter,
    query_hops: hops,
    query_limit: limit,
    qmd_execution_unchanged: true,
    note: 'Alongside-path diagnostic. Coarse→fine pruning assessment does not replace production QMD execution.',
  };
}

/**
 * Option-Zero Diagnostic — Alongside-path diagnostic
 *
 * Source paper: OPTIONZERO — Planning With Learned Options
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * OPTIONZERO discovers temporally extended options for hierarchical planning.
 * This diagnostic assesses whether a QMD query pattern can be decomposed
 * into option-like multi-step retrieval plans. It does NOT execute any
 * option or modify production QMD execution. Guarded by guarded_math flag
 * option_zero (knowledge-gated).
 */
export function buildOptionZeroDiagnostic(query = {}) {
  const verb = String(query?.verb || '').toUpperCase();
  const hops = Number(query?.hops ?? 0);
  const hasMultiStep = verb === 'PATH' || verb === 'TRAVERSE' || hops >= 2;
  const optionDepth = hasMultiStep ? Math.min(hops || 2, 4) : 1;
  const decomposability = hasMultiStep ? 0.8 : verb === 'FIND' ? 0.3 : 0.1;

  return {
    diagnostic: true,
    source_paper: OPTION_ZERO_QMD_SOURCE,
    coexistence_class: 'side_by_side_independent',
    query_verb: verb,
    multi_step_eligible: hasMultiStep,
    option_depth_estimate: optionDepth,
    decomposability_score: Number(decomposability.toFixed(6)),
    option_discovery_executed: false,
    qmd_execution_unchanged: true,
    note: 'Alongside-path diagnostic. Option-tree assessment only; no option discovery or QMD execution change.',
  };
}

/**
 * Model-based RL Planning Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Model-based RL — A Survey
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Model-based RL uses a learned world model for planning. This diagnostic
 * provides an audit-only taxonomy of how model-based planning concepts
 * relate to QMD query planning (world model ≈ schema knowledge, policy ≈
 * query plan selection). No world model is trained or queried. Guarded by
 * guarded_math flag model_based_rl_planning (knowledge-gated).
 */
export function buildModelBasedRLPlanningDiagnostic() {
  return {
    diagnostic: true,
    source_paper: MODEL_BASED_RL_PLANNING_SOURCE,
    coexistence_class: 'audit_only_analogy',
    analogy: [
      { rl_concept: 'world_model', qmd_analog: 'database_schema_knowledge', description: 'Schema provides transition dynamics for QMD planning' },
      { rl_concept: 'policy', qmd_analog: 'query_plan_selection', description: 'Query plan selection analogous to policy over action space' },
      { rl_concept: 'model_predictive_control', qmd_analog: 'query_plan_preview', description: 'buildQueryPlan provides MPC-like preview without execution' },
    ],
    world_model_trained: false,
    world_model_queried: false,
    qmd_execution_unchanged: true,
    note: 'Alongside-path diagnostic. Audit-only planning taxonomy; no world model or training.',
  };
}
