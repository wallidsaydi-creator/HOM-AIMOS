/**
 * graph-contract.js — Pure HAGE-N graph and tensor boundary.
 *
 * Paper authority: HAGE.pdf, Equations (4)–(7).
 * Native AIMOS adaptation:
 * - 768-dimensional pinned AIMOS embeddings;
 * - canonical relation order [temporal, semantic, causal, entity];
 * - deterministic relation intent from existing query-understanding evidence;
 * - domain-separated, length-prefixed snapshot commitment.
 *
 * This module is intentionally dormant. It has no database, route, signer,
 * Keychain, HTTP, model-loader, configuration-ledger, or environment authority.
 */

import { createHash } from 'node:crypto';

export const HAGE_NATIVE_RELATIONS = Object.freeze([
  'temporal',
  'semantic',
  'causal',
  'entity',
]);

export const HAGE_NATIVE_CONTRACT = Object.freeze({
  schema_version: 1,
  snapshot_domain: 'aimos.hage-snapshot/v1\0',
  embedding_dimensions: 768,
  edge_feature_dimensions: 4,
  relation_intent_dimensions: 4,
  enriched_edge_dimensions: 10,
  query_router_input_dimensions: 778,
  unit_norm_tolerance: 1e-3,
  max_nodes: 100_000,
  max_edges: 1_000_000,
  max_out_degree: 10_000,
});

const SHA256_HEX = /^[0-9a-f]{64}$/;
const TEMPORAL_INTENTS = new Set([
  'current_truth',
  'knowledge_update',
  'session_recall',
  'temporal_delta',
  'temporal_order',
  'temporal_pattern',
  'timeline',
]);

function fail(code) {
  throw new Error(`hage_native_contract:${code}`);
}

function requirePlainObject(value, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  return value;
}

function requireSha256(value, code) {
  if (typeof value !== 'string') fail(code);
  const normalized = value.trim();
  if (!SHA256_HEX.test(normalized)) fail(code);
  return normalized;
}

function requireString(value, code, maxLength = 512) {
  if (typeof value !== 'string') fail(code);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength) fail(code);
  return normalized;
}

function requireSafeInteger(value, code) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) fail(code);
  return value;
}

function freezeNumbers(values) {
  return Object.freeze([...values]);
}

function requireFiniteVector(value, dimensions, code, { unit = false, bounded = false } = {}) {
  if (!Array.isArray(value) && !ArrayBuffer.isView(value)) fail(`${code}_not_vector`);
  if (value.length !== dimensions) fail(`${code}_dimension`);
  const result = new Array(dimensions);
  let squaredNorm = 0;
  for (let index = 0; index < dimensions; index += 1) {
    const number = Number(value[index]);
    if (!Number.isFinite(number)) fail(`${code}_non_finite`);
    if (bounded && (number < 0 || number > 1)) fail(`${code}_range`);
    const canonical = Object.is(number, -0) ? 0 : number;
    result[index] = canonical;
    squaredNorm += canonical * canonical;
  }
  if (unit && Math.abs(Math.sqrt(squaredNorm) - 1) > HAGE_NATIVE_CONTRACT.unit_norm_tolerance) {
    fail(`${code}_unit_norm`);
  }
  return freezeNumbers(result);
}

function relationIndex(relation) {
  const index = HAGE_NATIVE_RELATIONS.indexOf(relation);
  if (index < 0) fail('edge_relation');
  return index;
}

function normalizeNode(raw) {
  const node = requirePlainObject(raw, 'node_not_object');
  return Object.freeze({
    id: requireSha256(node.id, 'node_id'),
    content_sha256: requireSha256(node.content_sha256, 'node_content_sha256'),
    timestamp_unix_ms: requireSafeInteger(node.timestamp_unix_ms, 'node_timestamp'),
    embedding: requireFiniteVector(
      node.embedding,
      HAGE_NATIVE_CONTRACT.embedding_dimensions,
      'node_embedding',
      { unit: true },
    ),
    metadata_sha256: requireSha256(node.metadata_sha256, 'node_metadata_sha256'),
  });
}

function normalizeEdge(raw, nodeIds) {
  const edge = requirePlainObject(raw, 'edge_not_object');
  const relation = requireString(edge.relation, 'edge_relation', 32);
  relationIndex(relation);
  const from = requireSha256(edge.from, 'edge_from');
  const to = requireSha256(edge.to, 'edge_to');
  if (!nodeIds.has(from) || !nodeIds.has(to)) fail('edge_endpoint_missing');
  if (from === to) fail('edge_self_loop');
  return Object.freeze({
    id: requireSha256(edge.id, 'edge_id'),
    from,
    to,
    relation,
    initial_feature: requireFiniteVector(
      edge.initial_feature,
      HAGE_NATIVE_CONTRACT.edge_feature_dimensions,
      'edge_initial_feature',
      { bounded: true },
    ),
    evidence_sha256: requireSha256(edge.evidence_sha256, 'edge_evidence_sha256'),
  });
}

function compareNodes(left, right) {
  return left.id.localeCompare(right.id);
}

function compareEdges(left, right) {
  return left.from.localeCompare(right.from)
    || left.to.localeCompare(right.to)
    || relationIndex(left.relation) - relationIndex(right.relation)
    || left.id.localeCompare(right.id);
}

function encodeU32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail('u32_range');
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32BE(value, 0);
  return bytes;
}

function encodeI64(value) {
  if (!Number.isSafeInteger(value)) fail('i64_range');
  const bytes = Buffer.allocUnsafe(8);
  bytes.writeBigInt64BE(BigInt(value), 0);
  return bytes;
}

function encodeFloat32(value) {
  if (!Number.isFinite(value)) fail('float32_non_finite');
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeFloatBE(Object.is(value, -0) ? 0 : value, 0);
  if (!Number.isFinite(bytes.readFloatBE(0))) fail('float32_overflow');
  return bytes;
}

function updateField(hash, label, bytes) {
  const labelBytes = Buffer.from(label, 'utf8');
  const valueBytes = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  hash.update(encodeU32(labelBytes.length));
  hash.update(labelBytes);
  hash.update(encodeU32(valueBytes.length));
  hash.update(valueBytes);
}

function updateString(hash, label, value) {
  updateField(hash, label, Buffer.from(value, 'utf8'));
}

function updateVector(hash, label, vector) {
  updateField(hash, `${label}.length`, encodeU32(vector.length));
  for (let index = 0; index < vector.length; index += 1) {
    updateField(hash, `${label}.${index}`, encodeFloat32(vector[index]));
  }
}

export function relationOneHot(relation) {
  const index = relationIndex(requireString(relation, 'edge_relation', 32));
  return freezeNumbers(HAGE_NATIVE_RELATIONS.map((_, current) => (current === index ? 1 : 0)));
}

export function hageRelationIntent(queryUnderstanding = {}) {
  const understanding = requirePlainObject(queryUnderstanding, 'query_understanding_not_object');
  const features = understanding.features && typeof understanding.features === 'object'
    && !Array.isArray(understanding.features) ? understanding.features : {};
  const intent = String(understanding.intent || 'semantic_recall').trim().toLowerCase();
  const temporal = TEMPORAL_INTENTS.has(intent)
    || Boolean(features.has_temporal_scope)
    || Boolean(features.asks_timeline)
    || Boolean(features.asks_order_compare)
    || Boolean(features.asks_temporal_delta)
    || Boolean(features.asks_temporal_pattern);
  const causal = intent === 'reasoning_evidence' || Boolean(features.asks_evidence);
  const namedEntities = Array.isArray(understanding.named_entities) ? understanding.named_entities : [];
  const speakerBindings = Array.isArray(understanding.speaker_bindings) ? understanding.speaker_bindings : [];
  const targets = Array.isArray(understanding.targets) ? understanding.targets : [];
  const entity = intent === 'speaker_entity_lookup'
    || Boolean(features.has_named_entities)
    || Boolean(features.has_speaker_bindings)
    || Boolean(features.needs_speaker_binding)
    || namedEntities.length > 0
    || speakerBindings.length > 0
    || targets.includes('entity');
  const raw = [temporal ? 1 : 0, 1, causal ? 1 : 0, entity ? 1 : 0];
  const norm = Math.sqrt(raw.reduce((sum, value) => sum + (value * value), 0));
  return freezeNumbers(raw.map((value) => value / norm));
}

export function createHageGraphSnapshot(raw = {}) {
  const input = requirePlainObject(raw, 'snapshot_not_object');
  if (input.schema_version !== HAGE_NATIVE_CONTRACT.schema_version) fail('snapshot_schema_version');
  const rawNodes = Array.isArray(input.nodes) ? input.nodes : fail('snapshot_nodes_not_array');
  const rawEdges = Array.isArray(input.edges) ? input.edges : fail('snapshot_edges_not_array');
  if (rawNodes.length > HAGE_NATIVE_CONTRACT.max_nodes) fail('snapshot_node_cap');
  if (rawEdges.length > HAGE_NATIVE_CONTRACT.max_edges) fail('snapshot_edge_cap');

  const nodes = rawNodes.map(normalizeNode).sort(compareNodes);
  const nodeIds = new Set();
  for (const node of nodes) {
    if (nodeIds.has(node.id)) fail('node_duplicate');
    nodeIds.add(node.id);
  }

  const edges = rawEdges.map((edge) => normalizeEdge(edge, nodeIds)).sort(compareEdges);
  const edgeIds = new Set();
  const edgeKeys = new Set();
  const outDegree = new Map();
  for (const edge of edges) {
    if (edgeIds.has(edge.id)) fail('edge_id_duplicate');
    edgeIds.add(edge.id);
    const key = `${edge.from}\0${edge.to}\0${edge.relation}`;
    if (edgeKeys.has(key)) fail('edge_relation_duplicate');
    edgeKeys.add(key);
    const degree = (outDegree.get(edge.from) || 0) + 1;
    if (degree > HAGE_NATIVE_CONTRACT.max_out_degree) fail('edge_out_degree_cap');
    outDegree.set(edge.from, degree);
  }

  return Object.freeze({
    schema_version: HAGE_NATIVE_CONTRACT.schema_version,
    source_manifest_sha256: requireSha256(input.source_manifest_sha256, 'source_manifest_sha256'),
    source_commit: requireSha256(input.source_commit, 'source_commit'),
    embedding_model_id: requireString(input.embedding_model_id, 'embedding_model_id'),
    embedding_model_revision: requireString(input.embedding_model_revision, 'embedding_model_revision'),
    embedding_dimensions: HAGE_NATIVE_CONTRACT.embedding_dimensions,
    relation_order: HAGE_NATIVE_RELATIONS,
    nodes: Object.freeze(nodes),
    edges: Object.freeze(edges),
  });
}

export function hageSnapshotSha256(snapshot) {
  const normalized = createHageGraphSnapshot(snapshot);
  const hash = createHash('sha256');
  hash.update(Buffer.from(HAGE_NATIVE_CONTRACT.snapshot_domain, 'utf8'));
  updateField(hash, 'schema_version', encodeU32(normalized.schema_version));
  updateString(hash, 'source_manifest_sha256', normalized.source_manifest_sha256);
  updateString(hash, 'source_commit', normalized.source_commit);
  updateString(hash, 'embedding_model_id', normalized.embedding_model_id);
  updateString(hash, 'embedding_model_revision', normalized.embedding_model_revision);
  updateField(hash, 'embedding_dimensions', encodeU32(normalized.embedding_dimensions));
  updateField(hash, 'node_count', encodeU32(normalized.nodes.length));
  for (let index = 0; index < normalized.nodes.length; index += 1) {
    const node = normalized.nodes[index];
    updateString(hash, `node.${index}.id`, node.id);
    updateString(hash, `node.${index}.content_sha256`, node.content_sha256);
    updateField(hash, `node.${index}.timestamp_unix_ms`, encodeI64(node.timestamp_unix_ms));
    updateVector(hash, `node.${index}.embedding`, node.embedding);
    updateString(hash, `node.${index}.metadata_sha256`, node.metadata_sha256);
  }
  updateField(hash, 'edge_count', encodeU32(normalized.edges.length));
  for (let index = 0; index < normalized.edges.length; index += 1) {
    const edge = normalized.edges[index];
    updateString(hash, `edge.${index}.id`, edge.id);
    updateString(hash, `edge.${index}.from`, edge.from);
    updateString(hash, `edge.${index}.to`, edge.to);
    updateString(hash, `edge.${index}.relation`, edge.relation);
    updateVector(hash, `edge.${index}.initial_feature`, edge.initial_feature);
    updateString(hash, `edge.${index}.evidence_sha256`, edge.evidence_sha256);
  }
  return hash.digest('hex');
}

export function buildHageAdjacency(snapshot) {
  const normalized = createHageGraphSnapshot(snapshot);
  const rows = Object.fromEntries(normalized.nodes.map((node) => [node.id, []]));
  for (const edge of normalized.edges) rows[edge.from].push(edge);
  for (const node of normalized.nodes) Object.freeze(rows[node.id]);
  return Object.freeze(rows);
}

export function eligibleHageNeighbors({ snapshot, current_node_id: currentNodeId, visited_node_ids: visited = [] } = {}) {
  const normalized = createHageGraphSnapshot(snapshot);
  const current = requireSha256(currentNodeId, 'current_node_id');
  if (!normalized.nodes.some((node) => node.id === current)) fail('current_node_missing');
  if (!Array.isArray(visited)) fail('visited_not_array');
  const visitedIds = new Set(visited.map((value) => requireSha256(value, 'visited_node_id')));
  const adjacency = buildHageAdjacency(normalized);
  return Object.freeze(adjacency[current].filter((edge) => !visitedIds.has(edge.to)));
}
