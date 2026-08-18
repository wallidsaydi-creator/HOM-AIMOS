/**
 * magma-native-reader.js — principal-scoped native MAGMA topology gear
 *
 * This reader is MAGMA's canonical bounded database-read path. It consumes an
 * already resolved, signature-bound native
 * recall authority; it does not obtain authority from process environment,
 * request text, or a MAGMA-owned configuration surface.
 *
 * The query applies the same company, identity, clearance, data-class, scope,
 * and command filters to every requested graph endpoint. Returned rows are not
 * disclosed directly: the canonical provenance admission owner revalidates the
 * actor epoch, signed grant, live content, and disclosure proof before this
 * module returns them.
 *
 * Source authority: MAGMA (Jiang et al., arXiv:2601.03236), adapted under the
 * HOM-AIMOS signed-recall and Aladdin full-retention contracts.
 */

import { createHash } from 'node:crypto';

import { agentPool } from '../../db/connection.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { sessionKeyLikePattern } from '../shared/session-scope.js';
import {
  admitNativeRecallCandidates,
  admitNativeRecallCandidatesInVerifiedSession,
} from './native-recall.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DATA_CLASS_ORDER = Object.freeze(['public', 'internal', 'confidential', 'restricted']);
const MAX_CANDIDATE_IDS = 200;
const MAX_SEMANTIC_EDGES_PER_FRONTIER = 8;
const MAX_ENTITY_NAMES_PER_FRONTIER = 4;
const MAX_ENTITY_NAMES_SCANNED_PER_FRONTIER = 16;
const MAX_ENTITY_NEIGHBORS_PER_NAME = 4;
const MAX_TEMPORAL_EDGES_PER_FRONTIER = 2;
const MAGMA_TOPOLOGY_RELATIONS = new Set(['semantic', 'entity', 'temporal']);

export const MAGMA_NATIVE_READER_CONTRACT = Object.freeze({
  schema: 'hom-aimos/magma-native-reader/v2',
  native_retrieval_gear: true,
  runtime_mode: false,
  canonical_caller: 'magma-native-candidate',
  maximum_candidate_ids: MAX_CANDIDATE_IDS,
  authority_source: 'resolved_native_recall_authority',
  execution_authority: 'verified_agent_or_role_identity_envelope',
  governance_owner: 'housekeeper',
  environment_authority: false,
  database_writes: false,
  grant_authority: false,
  canonical_memory_mutation: false,
  retention_change: false,
  disclosure_owner: 'admitNativeRecallCandidates',
  topology_reads_content: false,
  eligible_scope_materialization: 'not_materialized_predicate_pushdown',
  topology_access_strategy: 'bounded_indexed_lateral_expansion_before_join',
  maximum_semantic_edges_per_frontier: MAX_SEMANTIC_EDGES_PER_FRONTIER,
  maximum_entity_names_per_frontier: MAX_ENTITY_NAMES_PER_FRONTIER,
  maximum_entity_names_scanned_per_frontier: MAX_ENTITY_NAMES_SCANNED_PER_FRONTIER,
  maximum_entity_neighbors_per_name: MAX_ENTITY_NEIGHBORS_PER_NAME,
  entity_neighbor_domain: 'current_bounded_graph_workspace',
  entity_candidate_materialization: 'once_per_topology_read',
  maximum_temporal_edges_per_frontier: MAX_TEMPORAL_EDGES_PER_FRONTIER,
  maximum_rows_per_frontier: MAX_SEMANTIC_EDGES_PER_FRONTIER
    + (MAX_ENTITY_NAMES_PER_FRONTIER * MAX_ENTITY_NEIGHBORS_PER_NAME)
    + MAX_TEMPORAL_EDGES_PER_FRONTIER,
  required_indexes: Object.freeze([
    'memory_cross_refs(company_id,source_memory_id)',
    'memory_cross_refs(company_id,target_memory_id)',
    'entity_memory_edges(company_id,memory_id)',
    'entity_memory_edges(company_id,entity,memory_id)',
    'aimos_memories(company_id,created_at,id)',
    'aimos_memories(company_id,source,memory_type,created_at,id)',
  ]),
  semantic_edge_requires_signed_projection: true,
  entity_edge_evidence: 'endpoint_provenance_plus_recall_decision_receipt_required',
  retained_quarantine_graph_admission: false,
  retained_quarantine_policy:
    'retained_in_canonical_memory_and_central_candidates_but_ineligible_as_magma_anchor_or_endpoint',
});

function fail(code) {
  throw new Error(`magma_native_reader:${code}`);
}

function preparedQueryName(prefix, text) {
  const digest = createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 24);
  return `${prefix}_${digest}`;
}

function normalizeAuthority(authority) {
  if (!authority || typeof authority !== 'object' || Array.isArray(authority)) fail('authority_required');
  const companyId = String(authority.companyId || '').trim();
  const actorAgentId = String(authority.actorAgentId || '').trim();
  const actorValidFromIso = String(authority.actorValidFromIso || '').trim();
  const clearanceCeiling = Number(authority.clearanceCeiling);
  const dataClassCeiling = String(authority.dataClassCeiling || '').trim().toLowerCase();
  const authorityMutationHash = authority.authorityMutationHash;

  if (!companyId) fail('company_required');
  if (!actorAgentId) fail('actor_required');
  if (!Number.isFinite(Date.parse(actorValidFromIso))) fail('actor_epoch_invalid');
  if (!Number.isInteger(clearanceCeiling) || clearanceCeiling < 0 || clearanceCeiling > 12) {
    fail('clearance_invalid');
  }
  const classIndex = DATA_CLASS_ORDER.indexOf(dataClassCeiling);
  if (classIndex < 0) fail('data_class_ceiling_invalid');
  if (!Buffer.isBuffer(authorityMutationHash) || authorityMutationHash.length !== 32) {
    fail('authority_mutation_hash_invalid');
  }

  return Object.freeze({
    authority,
    companyId,
    actorAgentId,
    actorValidFromIso: new Date(actorValidFromIso).toISOString(),
    clearanceCeiling,
    allowedDataClasses: Object.freeze(DATA_CLASS_ORDER.slice(0, classIndex + 1)),
    authorityMutationHash,
    isHousekeeper: authority.isHousekeeper === true,
    command: authority.command && typeof authority.command === 'object' ? authority.command : {},
  });
}

function normalizeCandidateIds(candidateIds) {
  if (!Array.isArray(candidateIds)) fail('candidate_ids_required');
  const ids = [];
  const seen = new Set();
  for (const raw of candidateIds) {
    const id = String(raw?.id || raw || '').trim().toLowerCase();
    if (!UUID_PATTERN.test(id)) fail('candidate_id_invalid');
    if (seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
    if (ids.length > MAX_CANDIDATE_IDS) fail('candidate_limit_exceeded');
  }
  if (!ids.length) fail('candidate_ids_empty');
  return Object.freeze(ids);
}

function normalizeQueryEmbedding(value) {
  if ((!Array.isArray(value) && !ArrayBuffer.isView(value)) || value.length < 1 || value.length > 4096) {
    fail('query_embedding_invalid');
  }
  const embedding = Array.from(value, Number);
  if (embedding.some((entry) => !Number.isFinite(entry))) fail('query_embedding_invalid');
  return Object.freeze(embedding);
}

function commandScopeClauses(scope, params, alias = 'm') {
  const clauses = [];
  const command = scope.command;
  const addExact = (value, sql) => {
    const normalized = String(value || '').trim();
    if (!normalized) return;
    params.push(normalized);
    clauses.push(sql.replace('$?', `$${params.length}`));
  };
  addExact(command.source_filter, `${alias}.source = $?`);
  addExact(command.memory_type_filter, `${alias}.memory_type = $?`);
  addExact(command.key, `${alias}.key = $?`);
  addExact(command.memory_id, `${alias}.id = $?::uuid`);
  if (String(command.session_id || '').trim()) {
    params.push(sessionKeyLikePattern(String(command.session_id).trim()));
    clauses.push(`${alias}.key LIKE $${params.length} ESCAPE '\\'`);
  }
  return clauses;
}

/**
 * Build the fail-closed evidence query. Values remain positional parameters;
 * no authority, identity, filter, or candidate id is interpolated into SQL.
 */
export function buildMagmaNativeEvidenceQuery({ recallAuthority, candidateIds } = {}) {
  const scope = normalizeAuthority(recallAuthority);
  const ids = normalizeCandidateIds(candidateIds);
  const params = [
    scope.companyId,
    scope.clearanceCeiling,
    [...scope.allowedDataClasses],
    scope.actorAgentId,
    scope.isHousekeeper,
    [...ids],
  ];
  const clauses = [
    'm.company_id = $1',
    'm.clearance_level <= $2',
    "COALESCE(m.data_class, 'public') = ANY($3::text[])",
    `(m.scope = ANY(ARRAY['global','executive','system']::text[])
      OR (m.scope = ANY(ARRAY['agent','private',$4]::text[]) AND m.agent_id = $4)
      OR ((m.scope = 'quarantine' OR m.memory_type = 'quarantine') AND (m.agent_id = $4 OR $5::boolean)))`,
    '(m.clearance_level > 2 OR m.agent_id = $4 OR m.agent_id IS NULL)',
    'm.id = ANY($6::uuid[])',
    "NOT (m.scope = 'quarantine' OR m.memory_type = 'quarantine' OR COALESCE(m.retrieval_weight, 1.0) = 0.1)",
  ];

  clauses.push(...commandScopeClauses(scope, params));

  const text = `SELECT m.id::text, m.key, m.value, m.agent_id, m.memory_type,
                  m.scope, m.source, m.clearance_level, m.data_class,
                  m.created_at, m.updated_at, m.embedding::text,
                  m.retrieval_weight, m.content_hash
             FROM aimos_memories m
            WHERE ${clauses.join('\n              AND ')}
            ORDER BY array_position($6::uuid[], m.id), m.id`;
  return Object.freeze({
    text,
    preparedName: preparedQueryName('magma_native_evidence_v2', text),
    params: Object.freeze(params),
    orderedCandidateIds: ids,
    scope,
  });
}

/**
 * Build a bounded, identifier-only graph topology query. Semantic edges must
 * carry a signed projection event. Entity memberships are treated as derived
 * hints only; their exact use must be bound into the later signed recall
 * decision because the legacy table has no per-edge receipt column.
 */
export function buildMagmaNativeTopologyQuery({
  recallAuthority,
  frontierIds,
  queryEmbedding,
  entityCandidateIds = frontierIds,
} = {}) {
  const scope = normalizeAuthority(recallAuthority);
  const frontier = normalizeCandidateIds(frontierIds);
  const embedding = normalizeQueryEmbedding(queryEmbedding);
  const entityCandidates = normalizeCandidateIds(entityCandidateIds);
  const params = [
    scope.companyId,
    scope.clearanceCeiling,
    [...scope.allowedDataClasses],
    scope.actorAgentId,
    scope.isHousekeeper,
    [...frontier],
    JSON.stringify(embedding),
  ];
  const clauses = [
    'm.company_id = $1',
    'm.clearance_level <= $2',
    "COALESCE(m.data_class, 'public') = ANY($3::text[])",
    `(m.scope = ANY(ARRAY['global','executive','system']::text[])
      OR (m.scope = ANY(ARRAY['agent','private',$4]::text[]) AND m.agent_id = $4)
      OR ((m.scope = 'quarantine' OR m.memory_type = 'quarantine') AND (m.agent_id = $4 OR $5::boolean)))`,
    '(m.clearance_level > 2 OR m.agent_id = $4 OR m.agent_id IS NULL)',
    "NOT (m.scope = 'quarantine' OR m.memory_type = 'quarantine' OR COALESCE(m.retrieval_weight, 1.0) = 0.1)",
  ];
  clauses.push(...commandScopeClauses(scope, params));
  params.push([...entityCandidates]);
  const entityCandidateParameter = `$${params.length}`;

  const text = `WITH eligible AS NOT MATERIALIZED (
              SELECT m.id, m.created_at, m.embedding, m.content_hash
                FROM aimos_memories m
               WHERE ${clauses.join('\n                 AND ')}
            ),
            frontier AS MATERIALIZED (
              SELECT e.id, e.created_at, e.embedding, e.content_hash
                FROM eligible e
               WHERE e.id = ANY($6::uuid[])
            ),
            entity_candidate_scope AS MATERIALIZED (
              SELECT candidate.id AS memory_id,
                     candidate.embedding,
                     candidate.content_hash,
                     membership.entity
                FROM eligible candidate
                JOIN entity_memory_edges membership
                  ON membership.company_id = $1
                 AND membership.memory_id = candidate.id
               WHERE candidate.id = ANY(${entityCandidateParameter}::uuid[])
            ),
            semantic_edges AS (
              SELECT f.id AS source_id,
                     neighbor.target_id,
                     neighbor.edge_weight,
                     neighbor.query_similarity,
                     neighbor.target_content_hash,
                     neighbor.authority_event_id
                FROM frontier f
                CROSS JOIN LATERAL (
                  SELECT bounded.target_id, bounded.edge_weight,
                         bounded.query_similarity, bounded.target_content_hash,
                         bounded.authority_event_id
                    FROM (
                      (SELECT cr.target_memory_id AS target_id,
                              cr.similarity::float8 AS edge_weight,
                              1 - (target.embedding <=> $7::vector) AS query_similarity,
                              target.content_hash AS target_content_hash,
                              cr.authority_event_id::text AS authority_event_id
                         FROM memory_cross_refs cr
                         JOIN eligible target ON target.id = cr.target_memory_id
                        WHERE cr.company_id = $1
                          AND cr.source_memory_id = f.id
                          AND cr.authority_event_id IS NOT NULL
                        ORDER BY cr.similarity DESC, cr.target_memory_id
                        LIMIT ${MAX_SEMANTIC_EDGES_PER_FRONTIER})
                      UNION ALL
                      (SELECT cr.source_memory_id AS target_id,
                              cr.similarity::float8 AS edge_weight,
                              1 - (target.embedding <=> $7::vector) AS query_similarity,
                              target.content_hash AS target_content_hash,
                              cr.authority_event_id::text AS authority_event_id
                         FROM memory_cross_refs cr
                         JOIN eligible target ON target.id = cr.source_memory_id
                        WHERE cr.company_id = $1
                          AND cr.target_memory_id = f.id
                          AND cr.authority_event_id IS NOT NULL
                        ORDER BY cr.similarity DESC, cr.source_memory_id
                        LIMIT ${MAX_SEMANTIC_EDGES_PER_FRONTIER})
                    ) bounded
                   ORDER BY bounded.edge_weight DESC, bounded.target_id
                   LIMIT ${MAX_SEMANTIC_EDGES_PER_FRONTIER}
                ) neighbor
            ),
            entity_edges AS (
              SELECT f.id AS source_id,
                     neighbor.target_id,
                     entity_anchor.entity AS qualifier,
                     neighbor.edge_weight,
                     neighbor.query_similarity,
                     neighbor.target_content_hash
                FROM frontier f
                CROSS JOIN LATERAL (
                  SELECT bounded_anchor.entity,
                         (SELECT count(*)
                            FROM entity_memory_edges density
                           WHERE density.company_id = $1
                             AND density.entity = bounded_anchor.entity) AS entity_degree
                    FROM (
                      SELECT DISTINCT ae.entity
                        FROM entity_memory_edges ae
                       WHERE ae.company_id = $1
                         AND ae.memory_id = f.id
                       ORDER BY ae.entity
                       LIMIT ${MAX_ENTITY_NAMES_SCANNED_PER_FRONTIER}
                    ) bounded_anchor
                   ORDER BY entity_degree ASC, bounded_anchor.entity
                   LIMIT ${MAX_ENTITY_NAMES_PER_FRONTIER}
                ) entity_anchor
                CROSS JOIN LATERAL (
                  SELECT candidate.memory_id AS target_id,
                         1 - (candidate.embedding <=> $7::vector) AS edge_weight,
                         1 - (candidate.embedding <=> $7::vector) AS query_similarity,
                         candidate.content_hash AS target_content_hash
                    FROM entity_candidate_scope candidate
                   WHERE candidate.entity = entity_anchor.entity
                     AND candidate.memory_id <> f.id
                   ORDER BY candidate.embedding <=> $7::vector, candidate.memory_id
                   LIMIT ${MAX_ENTITY_NEIGHBORS_PER_NAME}
                ) neighbor
            ),
            temporal_edges AS (
              SELECT f.id AS source_id,
                     neighbor.id AS target_id,
                     1::float8 AS edge_weight,
                     neighbor.query_similarity,
                     neighbor.target_content_hash,
                     neighbor.direction AS qualifier
                FROM frontier f
                CROSS JOIN LATERAL (
                  (SELECT prior.id, 'prior'::text AS direction,
                          1 - (prior.embedding <=> $7::vector) AS query_similarity,
                          prior.content_hash AS target_content_hash
                     FROM eligible prior
                    WHERE prior.created_at < f.created_at
                    ORDER BY prior.created_at DESC, prior.id
                    LIMIT 1)
                  UNION ALL
                  (SELECT following.id, 'following'::text AS direction,
                          1 - (following.embedding <=> $7::vector) AS query_similarity,
                          following.content_hash AS target_content_hash
                     FROM eligible following
                    WHERE following.created_at > f.created_at
                    ORDER BY following.created_at, following.id
                    LIMIT 1)
                ) neighbor
            )
            SELECT 'semantic'::text AS relation, source_id::text, target_id::text,
                   edge_weight, query_similarity,
                   encode(target_content_hash,'hex') AS target_content_hash,
                   NULL::text AS qualifier, authority_event_id,
                   'signed_memory_cross_ref'::text AS evidence_kind
              FROM semantic_edges
            UNION ALL
            SELECT 'entity', source_id::text, target_id::text,
                   edge_weight, query_similarity, encode(target_content_hash,'hex'),
                   qualifier, NULL::text,
                   'derived_entity_membership'::text
              FROM entity_edges
            UNION ALL
            SELECT 'temporal', source_id::text, target_id::text,
                   1::float8, query_similarity, encode(target_content_hash,'hex'),
                   qualifier, NULL::text,
                   'signed_endpoint_origin_time'::text
              FROM temporal_edges
            ORDER BY relation, source_id, edge_weight DESC, target_id, qualifier`;
  return Object.freeze({
    text,
    preparedName: preparedQueryName('magma_native_topology_v2', text),
    params: Object.freeze(params),
    frontierIds: frontier,
    entityCandidateIds: entityCandidates,
    scope,
  });
}

export async function openMagmaNativeReadSession({
  recallAuthority,
  connectFn = () => agentPool.connect(),
} = {}) {
  const scope = normalizeAuthority(recallAuthority);
  const client = await connectFn();
  let closed = false;
  try {
    await client.query('BEGIN READ ONLY');
    // Establish both signed principal dimensions in one parameterized database
    // round trip.  This preserves transaction-local RLS authority while
    // avoiding a repeated setup trip for every bounded topology/evidence read.
    await client.query(
      `SELECT set_config($1,$2,true),
              set_config($3,$4,true),
              set_config($5,$6,true)`,
      [
        'app.current_client_id', scope.companyId,
        'app.current_agent_id', scope.actorAgentId,
        'plan_cache_mode', 'force_custom_plan',
      ],
    );

    // The transaction is deliberately READ ONLY. This is a snapshot
    // revalidation, so it must not request a row-locking clause; the canonical
    // provenance admission owner revalidates the actor and grant again before
    // any discovered endpoint can enter the recall candidate set.
    const identity = await client.query(
      `SELECT 1
         FROM agent_identity ai
        WHERE ai.agent_id = $1
          AND ai.valid_from = $2
          AND NOT EXISTS (
            SELECT 1
              FROM aimos_agent_revocation_events r
             WHERE r.agent_id = ai.agent_id
               AND r.agent_valid_from = ai.valid_from
          )`,
      [scope.actorAgentId, scope.actorValidFromIso],
    );
    if (!identity.rows[0]) fail('actor_epoch_not_active');

    if (!scope.isHousekeeper) {
      const grant = await recallAuthorizationService.getEffective({
        companyId: scope.companyId,
        subjectAgentId: scope.actorAgentId,
        subjectValidFrom: scope.actorValidFromIso,
        client,
      });
      if (!grant?.allowed || !Buffer.from(grant.mutationHash).equals(scope.authorityMutationHash)) {
        fail('authority_changed_during_read');
      }
    }
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* read connection may already be closed */ }
    client.release();
    throw error;
  }

  return Object.freeze({
    scope,
    query: async (text, params, { preparedName = null } = {}) => {
      if (closed) fail('read_session_closed');
      return preparedName
        ? client.query({ name: preparedName, text, values: params })
        : client.query(text, params);
    },
    admit: async (memories) => {
      if (closed) fail('read_session_closed');
      return admitNativeRecallCandidatesInVerifiedSession(memories, scope.authority, client);
    },
    close: async ({ commit = false } = {}) => {
      if (closed) return;
      closed = true;
      try {
        await client.query(commit ? 'COMMIT' : 'ROLLBACK');
      } finally {
        client.release();
      }
    },
  });
}

async function executeVerifiedRead(statement) {
  const session = await openMagmaNativeReadSession({ recallAuthority: statement.scope.authority });
  try {
    const result = await session.query(statement.text, statement.params, {
      preparedName: statement.preparedName,
    });
    await session.close({ commit: true });
    return result;
  } catch (error) {
    try { await session.close({ commit: false }); } catch { /* preserve the read failure */ }
    throw error;
  }
}

/**
 * Read candidate evidence through native authority and provenance admission.
 * This function performs no graph scoring and has no canonical caller yet.
 */
export async function readMagmaNativeEvidence({
  recallAuthority,
  candidateIds,
  queryFn = null,
  admitFn = admitNativeRecallCandidates,
} = {}) {
  const statement = buildMagmaNativeEvidenceQuery({ recallAuthority, candidateIds });
  const result = queryFn
    ? await queryFn(statement.text, statement.params, { preparedName: statement.preparedName })
    : await executeVerifiedRead(statement);
  const rows = Array.isArray(result?.rows) ? result.rows : [];
  const admitted = await admitFn(rows, recallAuthority);
  const admittedRows = Array.isArray(admitted?.memories) ? admitted.memories : [];
  const byId = new Map(admittedRows.map((row) => [String(row.id).toLowerCase(), row]));
  const ordered = statement.orderedCandidateIds.map((id) => byId.get(id)).filter(Boolean);

  return Object.freeze({
    memories: Object.freeze(ordered),
    rejected: Object.freeze(Array.isArray(admitted?.rejected) ? [...admitted.rejected] : []),
    decision: Object.freeze({
      schema: MAGMA_NATIVE_READER_CONTRACT.schema,
      requested_count: statement.orderedCandidateIds.length,
      scoped_row_count: rows.length,
      admitted_count: ordered.length,
      omitted_count: statement.orderedCandidateIds.length - ordered.length,
      company_id: statement.scope.companyId,
      actor_agent_id: statement.scope.actorAgentId,
      actor_valid_from: statement.scope.actorValidFromIso,
      clearance_ceiling: statement.scope.clearanceCeiling,
      data_class_ceiling: statement.scope.authority.dataClassCeiling,
      authority_mutation_hash: statement.scope.authorityMutationHash.toString('hex'),
      database_write_performed: false,
      canonical_memory_mutated: false,
      retention_changed: false,
      canary_or_epistemic_disclosure_authority: false,
    }),
  });
}

export async function readMagmaNativeTopology({
  recallAuthority,
  frontierIds,
  queryEmbedding,
  entityCandidateIds = frontierIds,
  queryFn = null,
} = {}) {
  const statement = buildMagmaNativeTopologyQuery({
    recallAuthority,
    frontierIds,
    queryEmbedding,
    entityCandidateIds,
  });
  const result = queryFn
    ? await queryFn(statement.text, statement.params, { preparedName: statement.preparedName })
    : await executeVerifiedRead(statement);
  const frontier = new Set(statement.frontierIds);
  const edges = [];
  for (const row of Array.isArray(result?.rows) ? result.rows : []) {
    const relation = String(row.relation || '').trim().toLowerCase();
    const sourceId = String(row.source_id || '').trim().toLowerCase();
    const targetId = String(row.target_id || '').trim().toLowerCase();
    if (!MAGMA_TOPOLOGY_RELATIONS.has(relation)) fail('topology_relation_invalid');
    if (!UUID_PATTERN.test(sourceId) || !UUID_PATTERN.test(targetId) || sourceId === targetId) {
      fail('topology_endpoint_invalid');
    }
    if (!frontier.has(sourceId)) fail('topology_source_outside_frontier');
    if (relation === 'semantic' && !String(row.authority_event_id || '').trim()) {
      fail('semantic_edge_unsigned');
    }
    edges.push(Object.freeze({
      relation,
      source_id: sourceId,
      target_id: targetId,
      edge_weight: Number.isFinite(Number(row.edge_weight)) ? Number(row.edge_weight) : 0,
      query_similarity: Number.isFinite(Number(row.query_similarity))
        ? Math.max(-1, Math.min(1, Number(row.query_similarity)))
        : 0,
      target_content_hash: /^[0-9a-f]{64}$/.test(String(row.target_content_hash || '').toLowerCase())
        ? String(row.target_content_hash).toLowerCase()
        : null,
      qualifier: row.qualifier == null ? null : String(row.qualifier),
      authority_event_id: row.authority_event_id == null ? null : String(row.authority_event_id),
      evidence_kind: String(row.evidence_kind || ''),
    }));
  }
  const maximumRows = statement.frontierIds.length * MAGMA_NATIVE_READER_CONTRACT.maximum_rows_per_frontier;
  if (edges.length > maximumRows) fail('topology_row_cap_exceeded');

  return Object.freeze({
    edges: Object.freeze(edges),
    decision: Object.freeze({
      schema: 'hom-aimos/magma-native-topology/v2',
      frontier_count: statement.frontierIds.length,
      entity_candidate_pool_count: statement.entityCandidateIds.length,
      entity_neighbor_domain: MAGMA_NATIVE_READER_CONTRACT.entity_neighbor_domain,
      entity_candidate_materialization:
        MAGMA_NATIVE_READER_CONTRACT.entity_candidate_materialization,
      edge_count: edges.length,
      semantic_edges: edges.filter((edge) => edge.relation === 'semantic').length,
      entity_edges: edges.filter((edge) => edge.relation === 'entity').length,
      temporal_edges: edges.filter((edge) => edge.relation === 'temporal').length,
      causal_edges: 0,
      access_strategy: MAGMA_NATIVE_READER_CONTRACT.topology_access_strategy,
      maximum_rows_per_frontier: MAGMA_NATIVE_READER_CONTRACT.maximum_rows_per_frontier,
      content_read: false,
      content_state_hash_read: true,
      database_write_performed: false,
      entity_edge_receipt_required_at_recall_decision: edges.some((edge) => edge.relation === 'entity'),
    }),
  });
}
