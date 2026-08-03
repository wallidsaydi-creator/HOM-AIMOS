/**
 * magma-lineage-retriever.js — MAGMA-compatible bounded lineage evidence paths
 * Source: MAGMA: A Multi-Graph based Agentic Memory Architecture for AI Agents
 * (Jiang et al., arXiv:2601.03236, 2026)
 * Supporting source: Graph-based Agent Memory: Taxonomy, Techniques, and
 * Applications (Yang et al., arXiv:2602.05665, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js when recall-mode-planner selects lineage mode
 * 2. → Pulls from: concept_edges for semantic/concept paths
 * 3. → Pulls from: entity_memory_edges for entity paths
 * 4. → Pulls from: memory_cross_refs for semantic/zettelkasten paths
 * 5. → Pulls from: aimos_events and timestamp neighborhoods for temporal/causal evidence
 *
 * LOGIC GUIDE:
 * MAGMA retrieves over orthogonal graph views: semantic, temporal, causal, and
 * entity. This service implements a bounded evidence-path layer over the tables
 * Aimos already has. It does not change PPR, embedding, MVS, or calibration math.
 *
 * Additive Batch8 authority: HeLa-Mem: Hebbian Learning and Associative Memory
 * for LLM Agents. Aimos maps HeLa-Mem to diagnostic co-recall edge candidates:
 * w_ij_next = min(cap, (1 - lambda) * w_ij_observed + eta * I(pair co-recalled
 * in K_t)). This is read-path diagnostic output only: no persistence, no PPR
 * change, no ranking change, and no STDP formula change.
 */

import { query as defaultQuery } from '../../db/connection.js';

const MAX_LIMIT = 50;
const MAX_ANCHORS = 5;
const DEFAULT_MAX_HOPS = 2;
const TEMPORAL_WINDOW_HOURS = 6;
const HELA_MEM_MAX_ASSOCIATIVE_CANDIDATES = 12;
const HELA_MEM_ETA = 0.15;
const HELA_MEM_DECAY_LAMBDA = 0.05;
const HELA_MEM_STRENGTH_CAP = 1.0;

function clampLimit(limit) {
  return Math.min(Math.max(Number(limit || 10), 1), MAX_LIMIT);
}

function clampHops(maxHops) {
  const parsed = Number(maxHops || DEFAULT_MAX_HOPS);
  return Math.min(Math.max(Number.isFinite(parsed) ? parsed : DEFAULT_MAX_HOPS, 1), 3);
}

function asIso(value) {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function truncate(text, max = 500) {
  const value = String(text || '').replace(/\s+/g, ' ').trim();
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function extractUuid(text) {
  const match = String(text || '').match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i);
  return match?.[0] || null;
}

function contentNeedle(queryText, planner) {
  return String(planner?.content_hint || queryText || '')
    .replace(/\b(show|what|is|are|connected|related|lineage|memory|led|around|session|decision|this|the|to|from|of|please)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function selectGraphViews(queryText, planner) {
  const text = `${queryText || ''} ${planner?.content_hint || ''}`.toLowerCase();
  const views = new Set();

  if (/\b(why|because|caused|led to|led from|decision|reasoning|rationale|followed from|consequences?)\b/.test(text)) {
    views.add('causal');
  }
  if (/\b(when|around|before|after|during|session|timeline|happened|date|yesterday|today|last night|last week|april|march|january|february|may|june|july|august|september|october|november|december|\d{4}-\d{2}-\d{2})\b/.test(text)) {
    views.add('temporal');
  }
  if (/\b(entity|person|provider|model|paper|service|memory|connected|related|linked)\b/.test(text)) {
    views.add('entity');
  }
  if (/\b(similar|semantic|concept|topic|cluster|related|connected|lineage)\b/.test(text) || views.size === 0) {
    views.add('semantic');
  }

  return Array.from(views);
}

function memoryNode(row, table = 'aimos_memories') {
  if (!row) return null;
  return {
    id: String(row.id),
    key: row.key || null,
    memory_type: row.memory_type || null,
    source: row.source || table,
    table,
    created_at: asIso(row.created_at || row.ts),
    excerpt: truncate(row.value || row.metadata || row.key || row.operation || ''),
    metadata: {
      agent_id: row.agent_id || null,
      scope: row.scope || null,
      data_class: row.data_class || null,
    },
  };
}

function eventNode(row) {
  if (!row) return null;
  const metadata = typeof row.metadata === 'object' ? row.metadata : {};
  return {
    id: String(row.id),
    key: row.key || `event:${row.operation}`,
    memory_type: 'aimos_event',
    source: 'aimos_events',
    table: 'aimos_events',
    created_at: asIso(row.ts),
    excerpt: truncate(`${row.operation || 'event'}${row.key ? ` — ${row.key}` : ''}`),
    metadata: {
      agent_id: row.agent_id || null,
      operation: row.operation || null,
      ...metadata,
    },
  };
}

function makePath({ view, edgeType, source, target, hop = 1, confidence = 0.7, metadata = {} }) {
  const safeSource = source || null;
  const safeTarget = target || null;
  return {
    path_id: `${view}:${edgeType}:${safeSource?.id || 'anchor'}:${safeTarget?.id || 'target'}:${hop}`,
    graph_view: view,
    edge_type: edgeType,
    hop,
    confidence: Number(Math.max(0, Math.min(1, confidence)).toFixed(3)),
    source: safeSource,
    target: safeTarget,
    source_metadata: {
      paper: 'MAGMA',
      graph_view: view,
      bounded: true,
      ...metadata,
    },
  };
}

async function resolveAnchors({
  queryFn,
  companyId,
  agentId,
  clearanceLevel,
  queryText,
  planner,
  dataClassFilter,
}) {
  const explicitId = extractUuid(queryText);
  const params = [companyId, clearanceLevel, agentId];
  let whereClause = `
    company_id = $1
    AND clearance_level <= $2
    AND (clearance_level > 2 OR agent_id = $3 OR agent_id IS NULL)
  `;

  if (Array.isArray(dataClassFilter) && dataClassFilter.length) {
    params.push(dataClassFilter);
    whereClause += ` AND COALESCE(data_class, 'public') = ANY($${params.length}::text[])`;
  }

  if (explicitId) {
    params.push(explicitId);
    whereClause += ` AND id = $${params.length}::uuid`;
  } else {
    const needle = contentNeedle(queryText, planner);
    if (needle.length >= 3) {
      params.push(`%${needle}%`);
      whereClause += ` AND (key ILIKE $${params.length} OR value ILIKE $${params.length})`;
    } else {
      whereClause += ` AND memory_type IN ('session_debrief', 'session_reasoning', 'after_action_review', 'procedural')`;
    }
  }

  const result = await queryFn(
    `SELECT id, key, value, agent_id, memory_type, scope, source, clearance_level,
            data_class, created_at, updated_at
     FROM aimos_memories
     WHERE ${whereClause}
     ORDER BY
       CASE
         WHEN key LIKE 'ai_adr:%' THEN 0
         WHEN memory_type = 'session_reasoning' THEN 1
         WHEN memory_type = 'session_debrief' THEN 2
         ELSE 3
       END,
       created_at DESC
     LIMIT ${MAX_ANCHORS}`,
    params
  );

  return (result.rows || []).map((row) => memoryNode(row)).filter(Boolean);
}

async function readSemanticPaths({ queryFn, companyId, anchorIds, limit }) {
  if (!anchorIds.length) return [];
  const paths = [];

  const crossRefs = await queryFn(
    `SELECT cr.source_memory_id, cr.target_memory_id, cr.similarity,
            sm.key AS source_key, sm.value AS source_value, sm.memory_type AS source_memory_type,
            sm.source AS source_source, sm.agent_id AS source_agent_id, sm.scope AS source_scope,
            sm.data_class AS source_data_class, sm.created_at AS source_created_at,
            tm.key AS target_key, tm.value AS target_value, tm.memory_type AS target_memory_type,
            tm.source AS target_source, tm.agent_id AS target_agent_id, tm.scope AS target_scope,
            tm.data_class AS target_data_class, tm.created_at AS target_created_at
     FROM memory_cross_refs cr
     JOIN aimos_memories sm ON sm.id = cr.source_memory_id AND sm.company_id = cr.company_id
     JOIN aimos_memories tm ON tm.id = cr.target_memory_id AND tm.company_id = cr.company_id
     WHERE cr.company_id = $1
       AND (cr.source_memory_id = ANY($2::uuid[]) OR cr.target_memory_id = ANY($2::uuid[]))
     ORDER BY cr.similarity DESC
     LIMIT $3`,
    [companyId, anchorIds, limit]
  );

  for (const row of crossRefs.rows || []) {
    paths.push(makePath({
      view: 'semantic',
      edgeType: 'semantic_cross_ref',
      source: memoryNode({
        id: row.source_memory_id,
        key: row.source_key,
        value: row.source_value,
        memory_type: row.source_memory_type,
        source: row.source_source,
        agent_id: row.source_agent_id,
        scope: row.source_scope,
        data_class: row.source_data_class,
        created_at: row.source_created_at,
      }),
      target: memoryNode({
        id: row.target_memory_id,
        key: row.target_key,
        value: row.target_value,
        memory_type: row.target_memory_type,
        source: row.target_source,
        agent_id: row.target_agent_id,
        scope: row.target_scope,
        data_class: row.target_data_class,
        created_at: row.target_created_at,
      }),
      confidence: Number(row.similarity || 0.7),
      metadata: { table: 'memory_cross_refs' },
    }));
  }

  const conceptEdges = await queryFn(
    `SELECT ce.source_id, ce.target_id, ce.edge_type, ce.weight,
            sm.key AS source_key, sm.value AS source_value, sm.memory_type AS source_memory_type,
            sm.source AS source_source, sm.agent_id AS source_agent_id, sm.scope AS source_scope,
            sm.data_class AS source_data_class, sm.created_at AS source_created_at,
            tm.key AS target_key, tm.value AS target_value, tm.memory_type AS target_memory_type,
            tm.source AS target_source, tm.agent_id AS target_agent_id, tm.scope AS target_scope,
            tm.data_class AS target_data_class, tm.created_at AS target_created_at
     FROM concept_edges ce
     JOIN aimos_memories sm ON sm.id = ce.source_id AND sm.company_id = ce.company_id
     JOIN aimos_memories tm ON tm.id = ce.target_id AND tm.company_id = ce.company_id
     WHERE ce.company_id = $1
       AND (ce.source_id = ANY($2::uuid[]) OR ce.target_id = ANY($2::uuid[]))
     ORDER BY ce.weight DESC, ce.created_at DESC
     LIMIT $3`,
    [companyId, anchorIds, limit]
  ).catch(() => ({ rows: [] }));

  for (const row of conceptEdges.rows || []) {
    paths.push(makePath({
      view: 'semantic',
      edgeType: row.edge_type || 'concept_edge',
      source: memoryNode({
        id: row.source_id,
        key: row.source_key,
        value: row.source_value,
        memory_type: row.source_memory_type,
        source: row.source_source,
        agent_id: row.source_agent_id,
        scope: row.source_scope,
        data_class: row.source_data_class,
        created_at: row.source_created_at,
      }),
      target: memoryNode({
        id: row.target_id,
        key: row.target_key,
        value: row.target_value,
        memory_type: row.target_memory_type,
        source: row.target_source,
        agent_id: row.target_agent_id,
        scope: row.target_scope,
        data_class: row.target_data_class,
        created_at: row.target_created_at,
      }),
      confidence: Number(row.weight || 0.7),
      metadata: { table: 'concept_edges' },
    }));
  }

  return paths.slice(0, limit);
}

async function readEntityPaths({ queryFn, companyId, anchorIds, limit }) {
  if (!anchorIds.length) return [];
  const result = await queryFn(
    `SELECT ae.memory_id AS source_id, ae.entity, ae.entity_type,
            pe.memory_id AS target_id,
            sm.key AS source_key, sm.value AS source_value, sm.memory_type AS source_memory_type,
            sm.source AS source_source, sm.agent_id AS source_agent_id, sm.scope AS source_scope,
            sm.data_class AS source_data_class, sm.created_at AS source_created_at,
            tm.key AS target_key, tm.value AS target_value, tm.memory_type AS target_memory_type,
            tm.source AS target_source, tm.agent_id AS target_agent_id, tm.scope AS target_scope,
            tm.data_class AS target_data_class, tm.created_at AS target_created_at
     FROM entity_memory_edges ae
     JOIN entity_memory_edges pe ON pe.company_id = ae.company_id
       AND LOWER(pe.entity) = LOWER(ae.entity)
       AND pe.memory_id <> ae.memory_id
     JOIN aimos_memories sm ON sm.id = ae.memory_id AND sm.company_id = ae.company_id
     JOIN aimos_memories tm ON tm.id = pe.memory_id AND tm.company_id = ae.company_id
     WHERE ae.company_id = $1
       AND ae.memory_id = ANY($2::uuid[])
     ORDER BY ae.entity, tm.created_at DESC
     LIMIT $3`,
    [companyId, anchorIds, limit]
  ).catch(() => ({ rows: [] }));

  return (result.rows || []).map((row) => makePath({
    view: 'entity',
    edgeType: `shared_entity:${row.entity_type || 'unknown'}`,
    source: memoryNode({
      id: row.source_id,
      key: row.source_key,
      value: row.source_value,
      memory_type: row.source_memory_type,
      source: row.source_source,
      agent_id: row.source_agent_id,
      scope: row.source_scope,
      data_class: row.source_data_class,
      created_at: row.source_created_at,
    }),
    target: memoryNode({
      id: row.target_id,
      key: row.target_key,
      value: row.target_value,
      memory_type: row.target_memory_type,
      source: row.target_source,
      agent_id: row.target_agent_id,
      scope: row.target_scope,
      data_class: row.target_data_class,
      created_at: row.target_created_at,
    }),
    confidence: 0.78,
    metadata: { table: 'entity_memory_edges', entity: row.entity, entity_type: row.entity_type || 'unknown' },
  }));
}

async function readTemporalPaths({ queryFn, companyId, agentId, anchorNodes, limit }) {
  const paths = [];
  for (const anchor of anchorNodes) {
    if (!anchor.created_at) continue;
    const anchorMs = Date.parse(anchor.created_at);
    const from = new Date(anchorMs - TEMPORAL_WINDOW_HOURS * 60 * 60 * 1000).toISOString();
    const to = new Date(anchorMs + TEMPORAL_WINDOW_HOURS * 60 * 60 * 1000).toISOString();

    const memories = await queryFn(
      `SELECT id, key, value, agent_id, memory_type, scope, source, data_class, created_at
       FROM aimos_memories
       WHERE company_id = $1
         AND id <> $2::uuid
         AND created_at >= $3::timestamptz
         AND created_at <= $4::timestamptz
       ORDER BY ABS(EXTRACT(EPOCH FROM (created_at - $5::timestamptz))) ASC
       LIMIT $6`,
      [companyId, anchor.id, from, to, anchor.created_at, limit]
    ).catch(() => ({ rows: [] }));

    for (const row of memories.rows || []) {
      paths.push(makePath({
        view: 'temporal',
        edgeType: 'temporal_adjacency',
        source: anchor,
        target: memoryNode(row),
        confidence: 0.72,
        metadata: { table: 'aimos_memories', window_hours: TEMPORAL_WINDOW_HOURS },
      }));
    }

    const events = await queryFn(
      `SELECT id, agent_id, operation, key, metadata, ts
       FROM aimos_events
       WHERE company_id = $1
         AND ts >= $2::timestamptz
         AND ts <= $3::timestamptz
         AND ($4::text = '' OR agent_id = $4)
       ORDER BY ABS(EXTRACT(EPOCH FROM (ts - $5::timestamptz))) ASC
       LIMIT $6`,
      [companyId, from, to, agentId || '', anchor.created_at, limit]
    ).catch(() => ({ rows: [] }));

    for (const row of events.rows || []) {
      paths.push(makePath({
        view: 'temporal',
        edgeType: 'event_temporal_adjacency',
        source: anchor,
        target: eventNode(row),
        confidence: 0.7,
        metadata: { table: 'aimos_events', window_hours: TEMPORAL_WINDOW_HOURS },
      }));
    }
  }

  return paths.slice(0, limit);
}

async function readCausalPaths({ queryFn, companyId, anchorNodes, queryText, planner, limit }) {
  const anchorIds = anchorNodes.map((node) => node.id);
  const needle = contentNeedle(queryText, planner);
  const params = [companyId, anchorIds];
  let textClause = '';
  if (needle.length >= 3) {
    params.push(`%${needle}%`);
    textClause = `OR m.key ILIKE $${params.length} OR m.value ILIKE $${params.length}`;
  }
  params.push(limit);

  const reasoning = await queryFn(
    `SELECT m.id, m.key, m.value, m.agent_id, m.memory_type, m.scope, m.source, m.data_class, m.created_at
     FROM aimos_memories m
     WHERE m.company_id = $1
       AND (
         m.id = ANY($2::uuid[])
         OR m.supersedes_id = ANY($2::uuid[])
         OR m.memory_type IN ('session_reasoning', 'after_action_review')
         OR m.key LIKE 'ai_adr:%'
         ${textClause}
       )
     ORDER BY
       CASE
         WHEN m.key LIKE 'ai_adr:%' THEN 0
         WHEN m.memory_type = 'session_reasoning' THEN 1
         WHEN m.memory_type = 'after_action_review' THEN 2
         ELSE 3
       END,
       m.created_at DESC
     LIMIT $${params.length}`,
    params
  ).catch(() => ({ rows: [] }));

  const anchor = anchorNodes[0] || null;
  return (reasoning.rows || [])
    .filter((row) => !anchorIds.includes(String(row.id)))
    .map((row) => makePath({
      view: 'causal',
      edgeType: row.key?.startsWith('ai_adr:') ? 'ai_adr_decision_lineage' : 'reasoning_artifact',
      source: anchor,
      target: memoryNode(row),
      confidence: 0.8,
      metadata: { table: 'aimos_memories', causal_basis: 'reasoning_or_decision_artifact' },
    }))
    .slice(0, limit);
}

function uniquePaths(paths, limit) {
  const seen = new Set();
  const out = [];
  for (const path of paths) {
    const key = `${path.graph_view}:${path.edge_type}:${path.source?.id}:${path.target?.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(path);
    if (out.length >= limit) break;
  }
  return out;
}

function memoriesFromPaths(paths, limit) {
  const seen = new Set();
  const memories = [];
  for (const path of paths) {
    for (const node of [path.source, path.target]) {
      if (!node || node.table !== 'aimos_memories' || seen.has(node.id)) continue;
      seen.add(node.id);
      memories.push({
        id: node.id,
        key: node.key,
        value: node.excerpt,
        agent_id: node.metadata?.agent_id || null,
        memory_type: node.memory_type || 'declarative',
        scope: node.metadata?.scope || 'lineage',
        source: node.source || 'aimos',
        clearance_level: 10,
        data_class: node.metadata?.data_class || 'public',
        created_at: node.created_at,
        updated_at: node.created_at,
        similarity: path.confidence,
        rerank_score: path.confidence,
        recall_confidence: path.confidence,
        magma_role: node.id === path.source?.id ? 'path_source' : 'path_target',
      });
      if (memories.length >= limit) return memories;
    }
  }
  return memories;
}

export function buildBoundedAssociativeEdgeCandidates(paths = [], limit = HELA_MEM_MAX_ASSOCIATIVE_CANDIDATES) {
  const candidateLimit = Math.max(1, Math.min(Number(limit || HELA_MEM_MAX_ASSOCIATIVE_CANDIDATES), HELA_MEM_MAX_ASSOCIATIVE_CANDIDATES));
  const pairs = new Map();

  for (const path of paths || []) {
    const source = path?.source;
    const target = path?.target;
    if (!source?.id || !target?.id || source.id === target.id) continue;
    if (source.table !== 'aimos_memories' || target.table !== 'aimos_memories') continue;

    const ordered = [source, target].sort((a, b) => String(a.id).localeCompare(String(b.id)));
    const pairKey = `${ordered[0].id}:${ordered[1].id}`;
    const confidence = Math.max(0, Math.min(1, Number(path.confidence || 0) || 0));
    const existing = pairs.get(pairKey) || {
      source_id: ordered[0].id,
      target_id: ordered[1].id,
      source_key: ordered[0].key || null,
      target_key: ordered[1].key || null,
      co_recall_count: 0,
      observed_strength: 0,
      supporting_edge_types: new Set(),
      supporting_graph_views: new Set(),
      source_tables: new Set(),
    };

    existing.co_recall_count += 1;
    existing.observed_strength = Math.max(existing.observed_strength, confidence);
    if (path.edge_type) existing.supporting_edge_types.add(path.edge_type);
    if (path.graph_view) existing.supporting_graph_views.add(path.graph_view);
    if (path.source_metadata?.table) existing.source_tables.add(path.source_metadata.table);
    pairs.set(pairKey, existing);
  }

  return Array.from(pairs.values())
    .map((candidate) => {
      const coActivationSignal = Math.min(1, candidate.co_recall_count);
      const nextStrength = Math.min(
        HELA_MEM_STRENGTH_CAP,
        (1 - HELA_MEM_DECAY_LAMBDA) * candidate.observed_strength + HELA_MEM_ETA * coActivationSignal
      );
      const delta = Math.max(0, nextStrength - candidate.observed_strength);
      return {
        source_id: candidate.source_id,
        target_id: candidate.target_id,
        source_key: candidate.source_key,
        target_key: candidate.target_key,
        edge_type: 'hebbian_co_recall_candidate',
        co_recall_count: candidate.co_recall_count,
        observed_strength: Number(candidate.observed_strength.toFixed(3)),
        hebbian_strength: Number(nextStrength.toFixed(3)),
        strength_delta: Number(delta.toFixed(3)),
        spreading_activation_score: Number((nextStrength * Math.log1p(candidate.co_recall_count)).toFixed(3)),
        supporting_edge_types: Array.from(candidate.supporting_edge_types).sort(),
        supporting_graph_views: Array.from(candidate.supporting_graph_views).sort(),
        source_tables: Array.from(candidate.source_tables).sort(),
        diagnostic_only: true,
        persistence_changed: false,
        ranking_math_changed: false,
        ppr_math_changed: false,
      };
    })
    .sort((a, b) => b.hebbian_strength - a.hebbian_strength || b.co_recall_count - a.co_recall_count)
    .slice(0, candidateLimit);
}

export async function retrieveMagmaLineage({
  queryText = '',
  planner,
  companyId,
  agentId,
  clearanceLevel = 10,
  limit = 10,
  maxHops = DEFAULT_MAX_HOPS,
  dataClassFilter = null,
  queryFn = defaultQuery,
} = {}) {
  const startedAt = Date.now();
  const maxRows = clampLimit(limit);
  const hops = clampHops(maxHops);
  const views = selectGraphViews(queryText, planner);
  const anchors = await resolveAnchors({
    queryFn,
    companyId,
    agentId,
    clearanceLevel,
    queryText,
    planner,
    dataClassFilter,
  });
  const anchorIds = anchors.map((node) => node.id);

  if (!anchorIds.length) {
    return {
      memories: [],
      paths: [],
      anchor_nodes: [],
      selected_views: views,
      diagnostics: {
        anchor_count: 0,
        path_count: 0,
        max_hops: hops,
        fallback_reason: 'no_anchor_nodes',
        retrieval_path: 'magma_existing_aimos_tables',
        latency_ms: Date.now() - startedAt,
      },
    };
  }

  const pathLimit = Math.max(maxRows * 2, maxRows);
  const pathGroups = [];
  if (views.includes('causal')) {
    pathGroups.push(...await readCausalPaths({ queryFn, companyId, anchorNodes: anchors, queryText, planner, limit: pathLimit }));
  }
  if (views.includes('temporal')) {
    pathGroups.push(...await readTemporalPaths({ queryFn, companyId, agentId, anchorNodes: anchors, limit: pathLimit }));
  }
  if (views.includes('entity')) {
    pathGroups.push(...await readEntityPaths({ queryFn, companyId, anchorIds, limit: pathLimit }));
  }
  if (views.includes('semantic')) {
    pathGroups.push(...await readSemanticPaths({ queryFn, companyId, anchorIds, limit: pathLimit }));
  }

  const paths = uniquePaths(pathGroups, pathLimit);
  const memories = memoriesFromPaths(paths, maxRows);
  const associativeCandidates = buildBoundedAssociativeEdgeCandidates(paths, pathLimit);

  return {
    memories,
    paths: paths.slice(0, maxRows),
    anchor_nodes: anchors,
    selected_views: views,
    diagnostics: {
      anchor_count: anchors.length,
      path_count: paths.length,
      returned_count: memories.length,
      selected_views: views,
      max_hops: hops,
      graph_substrate: {
        semantic: ['memory_cross_refs', 'concept_edges'],
        temporal: ['aimos_memories.created_at', 'aimos_events.ts'],
        causal: ['session_reasoning', 'ai_adr', 'supersession'],
        entity: ['entity_memory_edges'],
      },
      bounded: true,
      batch8_authority: {
        associative_memory: 'HeLa-Mem: Hebbian Learning and Associative Memory for LLM Agents',
      },
      associative_candidates: associativeCandidates,
      hela_mem_candidate_count: associativeCandidates.length,
      hela_mem_formula: {
        rule: 'w_ij_next = min(cap, (1 - lambda) * w_ij_observed + eta * I(pair co-recalled in K_t))',
        eta: HELA_MEM_ETA,
        lambda: HELA_MEM_DECAY_LAMBDA,
        cap: HELA_MEM_STRENGTH_CAP,
      },
      hela_mem_guardrails: {
        diagnostic_only: true,
        persistence_changed: false,
        ranking_math_changed: false,
        ppr_math_changed: false,
        stdp_formula_changed: false,
        canonical_memory_preserved: true,
      },
      fallback_reason: paths.length ? null : 'no_lineage_paths',
      retrieval_path: 'magma_existing_aimos_tables',
      latency_ms: Date.now() - startedAt,
    },
  };
}

export { selectGraphViews };
