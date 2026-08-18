import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  MAGMA_NATIVE_READER_CONTRACT,
  buildMagmaNativeEvidenceQuery,
  buildMagmaNativeTopologyQuery,
  openMagmaNativeReadSession,
  readMagmaNativeEvidence,
  readMagmaNativeTopology,
} from '../../services/retrieval/magma-native-reader.js';

const IDS = Object.freeze([
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
]);

function authority(overrides = {}) {
  return {
    companyId: 'hom',
    actorAgentId: 'signed-agent',
    actorValidFromIso: '2026-08-10T00:00:00.000Z',
    clearanceCeiling: 7,
    dataClassCeiling: 'confidential',
    authorityMutationHash: Buffer.alloc(32, 7),
    isHousekeeper: false,
    command: {},
    ...overrides,
  };
}

test('MAGMA native reader is a permanent bounded gear, read-only, and has no ENV authority', () => {
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.native_retrieval_gear, true);
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.runtime_mode, false);
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.canonical_caller, 'magma-native-candidate');
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.execution_authority, 'verified_agent_or_role_identity_envelope');
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.governance_owner, 'housekeeper');
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.grant_authority, false);
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.environment_authority, false);
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.database_writes, false);
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.retention_change, false);
  assert.equal(
    MAGMA_NATIVE_READER_CONTRACT.eligible_scope_materialization,
    'not_materialized_predicate_pushdown',
  );
  assert.equal(
    MAGMA_NATIVE_READER_CONTRACT.topology_access_strategy,
    'bounded_indexed_lateral_expansion_before_join',
  );
  assert.equal(
    MAGMA_NATIVE_READER_CONTRACT.entity_neighbor_domain,
    'current_bounded_graph_workspace',
  );
  assert.equal(
    MAGMA_NATIVE_READER_CONTRACT.entity_candidate_materialization,
    'once_per_topology_read',
  );
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.maximum_entity_names_scanned_per_frontier, 16);
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.maximum_rows_per_frontier, 26);
  assert.equal(MAGMA_NATIVE_READER_CONTRACT.retained_quarantine_graph_admission, false);
  assert.ok(MAGMA_NATIVE_READER_CONTRACT.required_indexes.includes(
    'aimos_memories(company_id,source,memory_type,created_at,id)',
  ));
});

test('MAGMA native read session binds one verified snapshot across multiple bounded reads', async () => {
  const statements = [];
  let releases = 0;
  const client = {
    async query(text, params) {
      statements.push({ text, params });
      if (/FROM agent_identity/.test(text)) return { rows: [{ active: 1 }] };
      return { rows: [] };
    },
    release() { releases += 1; },
  };
  const session = await openMagmaNativeReadSession({
    recallAuthority: authority({
      actorAgentId: 'housekeeper',
      isHousekeeper: true,
    }),
    connectFn: async () => client,
  });

  await session.query('SELECT 1', []);
  await session.query('SELECT 2', []);
  await session.admit([]);
  await session.close({ commit: true });

  assert.equal(statements.filter((row) => row.text === 'BEGIN READ ONLY').length, 1);
  assert.equal(statements.filter((row) => /FROM agent_identity/.test(row.text)).length, 1);
  assert.equal(statements.filter((row) => row.text === 'COMMIT').length, 1);
  assert.equal(statements.filter((row) => /^SELECT set_config/.test(row.text)).length, 1);
  const principalBinding = statements.find((row) => /^SELECT set_config/.test(row.text));
  assert.deepEqual(principalBinding.params.slice(-2), ['plan_cache_mode', 'force_custom_plan']);
  assert.equal(releases, 1);
  await assert.rejects(session.query('SELECT 3', []), /magma_native_reader:read_session_closed/);
});

test('MAGMA native evidence query applies every principal and command predicate with parameters', () => {
  const statement = buildMagmaNativeEvidenceQuery({
    recallAuthority: authority({
      command: {
        source_filter: 'benchmark:scope',
        memory_type_filter: 'session',
        session_id: 'session-1',
      },
    }),
    candidateIds: IDS,
  });

  assert.match(statement.text, /m\.company_id = \$1/);
  assert.match(statement.text, /m\.clearance_level <= \$2/);
  assert.match(statement.text, /COALESCE\(m\.data_class, 'public'\) = ANY\(\$3::text\[\]\)/);
  assert.match(statement.text, /m\.agent_id = \$4/);
  assert.match(statement.text, /m\.scope = 'quarantine'/);
  assert.match(
    statement.text,
    /NOT \(m\.scope = 'quarantine' OR m\.memory_type = 'quarantine' OR COALESCE\(m\.retrieval_weight, 1\.0\) = 0\.1\)/,
  );
  assert.match(statement.text, /m\.id = ANY\(\$6::uuid\[\]\)/);
  assert.match(statement.text, /m\.source = \$7/);
  assert.match(statement.text, /m\.memory_type = \$8/);
  assert.match(statement.text, /m\.key LIKE \$9 ESCAPE/);
  assert.doesNotMatch(statement.text, /benchmark:scope|signed-agent|session-1/);
  assert.match(statement.preparedName, /^magma_native_evidence_v2_[0-9a-f]{24}$/);
  assert.deepEqual(statement.params.slice(0, 6), [
    'hom',
    7,
    ['public', 'internal', 'confidential'],
    'signed-agent',
    false,
    [...IDS],
  ]);
});

test('MAGMA native reader returns only provenance-admitted rows in candidate order', async () => {
  const rawRows = [
    { id: IDS[1], key: 'second', value: 'second evidence' },
    { id: IDS[0], key: 'first', value: 'first evidence' },
  ];
  let queryCalls = 0;
  let admissionCalls = 0;
  const result = await readMagmaNativeEvidence({
    recallAuthority: authority(),
    candidateIds: IDS,
    queryFn: async (text, params) => {
      queryCalls += 1;
      assert.match(text, /^SELECT m\.id::text/);
      assert.equal(params[0], 'hom');
      return { rows: rawRows };
    },
    admitFn: async (rows, resolvedAuthority) => {
      admissionCalls += 1;
      assert.equal(rows, rawRows);
      assert.equal(resolvedAuthority.actorAgentId, 'signed-agent');
      return {
        memories: [{ ...rawRows[1], provenance_proof: { version_status: 'current' } }],
        rejected: [{ memory_id: IDS[1], reason: 'proof_rejected' }],
      };
    },
  });

  assert.equal(queryCalls, 1);
  assert.equal(admissionCalls, 1);
  assert.deepEqual(result.memories.map((row) => row.id), [IDS[0]]);
  assert.equal(result.decision.requested_count, 2);
  assert.equal(result.decision.admitted_count, 1);
  assert.equal(result.decision.omitted_count, 1);
  assert.equal(result.decision.database_write_performed, false);
  assert.equal(result.decision.canary_or_epistemic_disclosure_authority, false);
});

test('MAGMA topology query applies one eligible scope to all three bounded views', () => {
  const statement = buildMagmaNativeTopologyQuery({
    recallAuthority: authority({ command: { source_filter: 'benchmark:scope' } }),
    frontierIds: [IDS[0]],
    queryEmbedding: [0.6, 0.8],
    entityCandidateIds: IDS,
  });

  assert.match(statement.text, /WITH eligible AS NOT MATERIALIZED/);
  assert.match(
    statement.text,
    /NOT \(m\.scope = 'quarantine' OR m\.memory_type = 'quarantine' OR COALESCE\(m\.retrieval_weight, 1\.0\) = 0\.1\)/,
  );
  assert.match(statement.text, /frontier AS MATERIALIZED/);
  assert.match(statement.text, /cr\.authority_event_id IS NOT NULL/);
  assert.match(statement.text, /CROSS JOIN LATERAL/);
  assert.match(statement.text, /LIMIT 8/);
  assert.match(statement.text, /LIMIT 16/);
  assert.match(statement.text, /LIMIT 4/);
  assert.match(statement.text, /entity_candidate_scope AS MATERIALIZED/);
  assert.match(statement.text, /AS query_similarity/);
  assert.match(statement.text, /candidate\.id = ANY\(\$9::uuid\[\]\)/);
  assert.match(statement.text, /candidate\.entity = entity_anchor\.entity/);
  assert.doesNotMatch(statement.text, /lower\(candidate\.entity\)|lower\(ae\.entity\)/);
  assert.match(statement.text, /signed_endpoint_origin_time/);
  assert.match(statement.text, /m\.source = \$8/);
  assert.doesNotMatch(statement.text, /benchmark:scope|signed-agent/);
  assert.match(statement.preparedName, /^magma_native_topology_v2_[0-9a-f]{24}$/);
  assert.deepEqual(statement.params[5], [IDS[0]]);
  assert.equal(statement.params[6], '[0.6,0.8]');
  assert.deepEqual(statement.params[8], [...IDS]);
  assert.deepEqual(statement.entityCandidateIds, [...IDS]);
});

test('MAGMA topology reader rejects unsigned semantic edges and accepts bounded evidence labels', async () => {
  const base = {
    relation: 'semantic',
    source_id: IDS[0],
    target_id: IDS[1],
    edge_weight: 0.91,
    qualifier: null,
    authority_event_id: null,
    evidence_kind: 'signed_memory_cross_ref',
  };
  await assert.rejects(
    readMagmaNativeTopology({
      recallAuthority: authority(),
      frontierIds: [IDS[0]],
      queryEmbedding: [1, 0],
      queryFn: async () => ({ rows: [base] }),
    }),
    /magma_native_reader:semantic_edge_unsigned/,
  );

  const topology = await readMagmaNativeTopology({
    recallAuthority: authority(),
    frontierIds: [IDS[0]],
    queryEmbedding: [1, 0],
    queryFn: async () => ({ rows: [
      { ...base, authority_event_id: 'event-1' },
      {
        ...base,
        relation: 'entity',
        authority_event_id: null,
        qualifier: 'walid',
        evidence_kind: 'derived_entity_membership',
      },
    ] }),
  });
  assert.equal(topology.edges.length, 2);
  assert.equal(topology.decision.semantic_edges, 1);
  assert.equal(topology.decision.entity_edges, 1);
  assert.equal(topology.decision.entity_candidate_pool_count, 1);
  assert.equal(topology.decision.entity_neighbor_domain, 'current_bounded_graph_workspace');
  assert.equal(topology.decision.entity_candidate_materialization, 'once_per_topology_read');
  assert.equal(topology.decision.entity_edge_receipt_required_at_recall_decision, true);
  assert.equal(topology.decision.content_read, false);
});

test('MAGMA native reader fails closed on malformed authority, identifiers, and cap overflow', () => {
  assert.throws(
    () => buildMagmaNativeEvidenceQuery({ recallAuthority: null, candidateIds: IDS }),
    /magma_native_reader:authority_required/,
  );
  assert.throws(
    () => buildMagmaNativeEvidenceQuery({ recallAuthority: authority(), candidateIds: ['not-a-uuid'] }),
    /magma_native_reader:candidate_id_invalid/,
  );
  const tooMany = Array.from({ length: 201 }, (_, index) =>
    `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
  );
  assert.throws(
    () => buildMagmaNativeEvidenceQuery({ recallAuthority: authority(), candidateIds: tooMany }),
    /magma_native_reader:candidate_limit_exceeded/,
  );
  assert.throws(
    () => buildMagmaNativeTopologyQuery({
      recallAuthority: authority(),
      frontierIds: [IDS[0]],
      queryEmbedding: [1, 0],
      entityCandidateIds: tooMany,
    }),
    /magma_native_reader:candidate_limit_exceeded/,
  );
});

test('MAGMA native reader source has no write statement or ENV authority and declares its sole caller', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/magma-native-reader.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /process\.env/);
  assert.doesNotMatch(source, /\b(?:INSERT|UPDATE|DELETE|TRUNCATE)\s+(?:INTO|FROM)?\s*aimos_/i);
  assert.match(source, /BEGIN READ ONLY/);
  assert.match(source, /SELECT set_config\(\$1,\$2,true\),\s+set_config\(\$3,\$4,true\),\s+set_config\(\$5,\$6,true\)/);
  assert.match(source, /'plan_cache_mode', 'force_custom_plan'/);
  assert.doesNotMatch(source, /\bFOR\s+(?:UPDATE|NO KEY UPDATE|SHARE|KEY SHARE)\b/i);
  assert.match(source, /admitNativeRecallCandidates/);
  assert.match(source, /canonical_caller:\s*'magma-native-candidate'/);
});

test('MAGMA filtered temporal-neighborhood migration is additive and matches the live query shape', async () => {
  const source = await readFile(
    new URL('../../migrations/096-native-retrieval-filtered-temporal-neighborhood-index.sql', import.meta.url),
    'utf8',
  );
  assert.match(source, /CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aimos_memories_company_source_type_created_id/);
  assert.match(source, /aimos_memories\s*\(company_id, source, memory_type, created_at, id\)/);
  assert.doesNotMatch(source, /\b(?:DROP|DELETE|UPDATE|TRUNCATE)\b/i);
  assert.match(source, /no authority/i);
  assert.match(source, /no memory/i);
});
