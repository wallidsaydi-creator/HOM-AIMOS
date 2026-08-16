import test from 'node:test';
import assert from 'node:assert/strict';

import {
  HAGE_NATIVE_CONTRACT,
  HAGE_NATIVE_RELATIONS,
  buildHageAdjacency,
  createHageGraphSnapshot,
  eligibleHageNeighbors,
  hageRelationIntent,
  hageSnapshotSha256,
  relationOneHot,
} from '../../services/retrieval/hage-native/graph-contract.js';

const hex = (value) => String(value).repeat(64).slice(0, 64);

function unitEmbedding(index = 0) {
  const vector = Array(HAGE_NATIVE_CONTRACT.embedding_dimensions).fill(0);
  vector[index] = 1;
  return vector;
}

function node(id, embeddingIndex, timestamp) {
  return {
    id,
    content_sha256: hex('c'),
    timestamp_unix_ms: timestamp,
    embedding: unitEmbedding(embeddingIndex),
    metadata_sha256: hex('d'),
  };
}

function fixture({ reverse = false } = {}) {
  const a = hex('a');
  const b = hex('b');
  const c = hex('c');
  const nodes = [
    node(a, 0, 1_700_000_000_000),
    node(b, 1, 1_700_000_001_000),
    node(c, 2, 1_700_000_002_000),
  ];
  const edges = [
    {
      id: hex('1'),
      from: a,
      to: b,
      relation: 'temporal',
      initial_feature: [1, 0, 0, 0],
      evidence_sha256: hex('e'),
    },
    {
      id: hex('2'),
      from: b,
      to: a,
      relation: 'semantic',
      initial_feature: [0, 1, 0, 0],
      evidence_sha256: hex('f'),
    },
    {
      id: hex('3'),
      from: b,
      to: c,
      relation: 'causal',
      initial_feature: [0, 0, 1, 0],
      evidence_sha256: hex('9'),
    },
  ];
  return {
    schema_version: 1,
    source_manifest_sha256: hex('4'),
    source_commit: hex('5'),
    embedding_model_id: 'Xenova/all-mpnet-base-v2',
    embedding_model_revision: 'e086c5e0b3a57b0ce46dd6d9c0662948860b35f3',
    nodes: reverse ? nodes.reverse() : nodes,
    edges: reverse ? edges.reverse() : edges,
  };
}

test('HAGE-N1 fixes paper relation order and dimensions', () => {
  assert.deepEqual(HAGE_NATIVE_RELATIONS, ['temporal', 'semantic', 'causal', 'entity']);
  assert.equal(HAGE_NATIVE_CONTRACT.embedding_dimensions, 768);
  assert.equal(HAGE_NATIVE_CONTRACT.enriched_edge_dimensions, 10);
  assert.equal(HAGE_NATIVE_CONTRACT.query_router_input_dimensions, 778);
  assert.deepEqual(relationOneHot('causal'), [0, 0, 1, 0]);
  assert.throws(() => relationOneHot('session'), /edge_relation/);
});

test('HAGE-N1 relation intent is deterministic, ordered, and unit normalized', () => {
  const intent = hageRelationIntent({
    intent: 'temporal_order',
    features: { asks_evidence: false, has_named_entities: true },
    named_entities: ['Alice'],
  });
  const expected = 1 / Math.sqrt(3);
  assert.deepEqual(intent, [expected, expected, 0, expected]);
  assert.equal(Math.abs(Math.hypot(...intent) - 1) < 1e-12, true);
  assert.equal(Object.isFrozen(intent), true);
  assert.deepEqual(hageRelationIntent({ intent: 'semantic_recall' }), [0, 1, 0, 0]);
});

test('HAGE-N1 snapshot normalization is immutable and insertion-order independent', () => {
  const source = fixture({ reverse: true });
  const before = structuredClone(source);
  const normalized = createHageGraphSnapshot(source);
  assert.deepEqual(source, before);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.nodes), true);
  assert.equal(Object.isFrozen(normalized.nodes[0].embedding), true);
  assert.deepEqual(normalized.nodes.map((entry) => entry.id), [hex('a'), hex('b'), hex('c')]);
  assert.equal(hageSnapshotSha256(source), hageSnapshotSha256(fixture()));
});

test('HAGE-N1 snapshot hash binds every material tensor and metadata field', () => {
  const baseline = fixture();
  const baselineHash = hageSnapshotSha256(baseline);
  const mutations = [
    (copy) => { copy.source_manifest_sha256 = hex('6'); },
    (copy) => { copy.nodes[0].timestamp_unix_ms += 1; },
    (copy) => { copy.nodes[0].embedding = unitEmbedding(7); },
    (copy) => { copy.edges[0].initial_feature = [0.9, 0.1, 0, 0]; },
    (copy) => { copy.edges[0].evidence_sha256 = hex('7'); },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(baseline);
    mutate(copy);
    assert.notEqual(hageSnapshotSha256(copy), baselineHash);
  }
});

test('HAGE-N1 preserves cycles but visited masking prevents immediate revisits', () => {
  const snapshot = createHageGraphSnapshot(fixture());
  const adjacency = buildHageAdjacency(snapshot);
  const a = hex('a');
  const b = hex('b');
  assert.equal(adjacency[a][0].to, b);
  assert.equal(adjacency[b].some((edge) => edge.to === a), true);
  assert.deepEqual(eligibleHageNeighbors({
    snapshot,
    current_node_id: b,
    visited_node_ids: [a, b],
  }).map((edge) => edge.to), [hex('c')]);
});

test('HAGE-N1 represents sinks explicitly without fabricating fallback edges', () => {
  const snapshot = createHageGraphSnapshot(fixture());
  assert.deepEqual(eligibleHageNeighbors({
    snapshot,
    current_node_id: hex('c'),
    visited_node_ids: [hex('c')],
  }), []);
});

test('HAGE-N1 rejects malformed, non-finite, unnormalized, and ambiguous records', () => {
  const cases = [
    (copy) => { copy.schema_version = 2; },
    (copy) => { copy.nodes[0].embedding[0] = Number.NaN; },
    (copy) => { copy.nodes[0].embedding = Array(768).fill(0); },
    (copy) => { copy.nodes.push(structuredClone(copy.nodes[0])); },
    (copy) => { copy.edges[0].to = hex('8'); },
    (copy) => { copy.edges[0].from = copy.edges[0].to; },
    (copy) => { copy.edges[0].initial_feature[0] = 1.1; },
    (copy) => { copy.edges.push({ ...structuredClone(copy.edges[0]), id: hex('8') }); },
    (copy) => { copy.nodes[0].content_sha256 = 'not-a-hash'; },
    (copy) => { copy.nodes[0].timestamp_unix_ms = '1700000000000'; },
    (copy) => { copy.edges[0].relation = 'TEMPORAL'; },
    (copy) => { copy.embedding_model_id = { name: 'model' }; },
  ];
  for (const mutate of cases) {
    const copy = structuredClone(fixture());
    mutate(copy);
    assert.throws(() => createHageGraphSnapshot(copy), /hage_native_contract:/);
  }
});

test('HAGE-N1 rejects invalid visited masks and absent current nodes', () => {
  const snapshot = fixture();
  assert.throws(() => eligibleHageNeighbors({
    snapshot,
    current_node_id: hex('8'),
  }), /current_node_missing/);
  assert.throws(() => eligibleHageNeighbors({
    snapshot,
    current_node_id: hex('a'),
    visited_node_ids: 'not-an-array',
  }), /visited_not_array/);
});
