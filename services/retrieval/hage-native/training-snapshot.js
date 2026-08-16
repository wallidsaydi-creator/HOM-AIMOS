/**
 * training-snapshot.js — Dormant HAGE-N4 snapshot contract and verifier.
 *
 * Paper authority: HAGE.pdf, Equations (4)–(15), for the graph/tensor meaning.
 * AIMOS authority: the native HAGE implementation plan for signed, read-only,
 * source-bound offline-training snapshots.
 *
 * This module does not export a live snapshot, read a database, access a key,
 * sign an artifact, write a file, call a route, or admit a checkpoint. It only
 * normalizes a prebuilt private bundle, computes commitments, and verifies a
 * detached Ed25519 receipt against an explicit trusted context.
 */

import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';

import { canonicalJson } from '../../security/agent-identity.js';
import {
  HAGE_NATIVE_CONTRACT,
  HAGE_NATIVE_RELATIONS,
  createHageGraphSnapshot,
  hageSnapshotSha256,
} from './graph-contract.js';

export const HAGE_TRAINING_SNAPSHOT_CONTRACT = Object.freeze({
  schema: 'hom.aimos.hage-training-snapshot/v1',
  group_schema: 'hom.aimos.hage-training-groups/v1',
  receipt_schema: 'hom.aimos.hage-training-snapshot-receipt/v1',
  purpose: 'hage-offline-training',
  signer_agent_id: 'housekeeper',
  grouping_unit: 'source_session',
  snapshot_domain: 'aimos.hage-training-snapshot/v1\0',
  group_domain: 'aimos.hage-training-groups/v1\0',
  receipt_domain: 'aimos.hage-training-snapshot-receipt/v1\0',
  paper_sha256: '867feac3e32d553c4f0815f9b760d5e7ede5515fcd4698e32003d597bc66b5f5',
  upstream_reference_commit: 'ddc159d7b16f362d31d0273d6990aa28f1e424e0',
  directory_mode: 0o700,
  file_mode: 0o600,
  required_files: Object.freeze([
    'graph.json',
    'groups.json',
    'manifest.json',
    'receipt.json',
  ]),
  max_manifest_bytes: 1 * 1024 * 1024,
  max_groups_bytes: 256 * 1024 * 1024,
  max_graph_bytes: 4 * 1024 * 1024 * 1024,
  max_receipt_bytes: 1 * 1024 * 1024,
  max_group_rows: HAGE_NATIVE_CONTRACT.max_nodes,
});

const SHA256_HEX = /^[0-9a-f]{64}$/;
const GIT_COMMIT_HEX = /^[0-9a-f]{40}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const COMPANY_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const EVENT_ID = /^[0-9a-f]{64}$/;

const SNAPSHOT_KEYS = Object.freeze([
  'schema_version',
  'source_manifest_sha256',
  'source_commit',
  'embedding_model_id',
  'embedding_model_revision',
  'embedding_dimensions',
  'relation_order',
  'nodes',
  'edges',
]);

const NODE_KEYS = Object.freeze([
  'id',
  'content_sha256',
  'timestamp_unix_ms',
  'embedding',
  'metadata_sha256',
]);

const EDGE_KEYS = Object.freeze([
  'id',
  'from',
  'to',
  'relation',
  'initial_feature',
  'evidence_sha256',
]);

const GROUP_MANIFEST_KEYS = Object.freeze([
  'schema',
  'company_id',
  'grouping_unit',
  'rows',
]);

const GROUP_ROW_KEYS = Object.freeze([
  'node_id',
  'corpus_sha256',
  'source_sha256',
  'session_sha256',
  'split_group_sha256',
  'authorization_receipt_sha256',
]);

const MANIFEST_KEYS = Object.freeze([
  'schema',
  'purpose',
  'company_id',
  'intent_sha256',
  'export_nonce',
  'created_at_unix',
  'source_commit_sha256',
  'source_manifest_sha256',
  'architecture_manifest_sha256',
  'paper_sha256',
  'upstream_reference_commit',
  'graph_snapshot_sha256',
  'group_manifest_sha256',
  'embedding',
  'relation_order',
  'counts',
  'authorization',
  'retention',
]);

const EMBEDDING_KEYS = Object.freeze([
  'model_id',
  'revision',
  'dimensions',
  'pooling',
  'normalized',
]);

const COUNT_KEYS = Object.freeze([
  'nodes',
  'edges',
  'corpora',
  'sources',
  'sessions',
  'split_groups',
]);

const AUTHORIZATION_KEYS = Object.freeze([
  'read_receipt_sha256',
  'scope_sha256',
  'clearance_ceiling',
]);

const RETENTION_KEYS = Object.freeze([
  'canonical_memory_mutation',
  'canonical_memory_deletion',
  'selective_suppression',
]);

const RECEIPT_KEYS = Object.freeze([
  'body',
  'signature_base64url',
]);

const RECEIPT_BODY_KEYS = Object.freeze([
  'schema',
  'company_id',
  'event_id',
  'operation',
  'snapshot_commitment_sha256',
  'graph_snapshot_sha256',
  'group_manifest_sha256',
  'intent_sha256',
  'export_nonce',
  'event_mutation_sha256',
  'signer_agent_id',
  'signer_epoch',
  'cert_fingerprint',
  'signed_at_unix',
]);

const BUNDLE_KEYS = Object.freeze([
  'graph_snapshot',
  'group_manifest',
  'manifest',
  'receipt',
  'trusted_context',
]);

const TRUST_KEYS = Object.freeze([
  'company_id',
  'intent_sha256',
  'read_receipt_sha256',
  'source_commit_sha256',
  'signer_agent_id',
  'signer_epoch',
  'cert_fingerprint',
  'signer_public_key',
  'consumed_export_nonces',
  'consumed_event_ids',
]);

const FILESYSTEM_KEYS = Object.freeze([
  'directory',
  'files',
  'process_uid',
]);

const DIRECTORY_KEYS = Object.freeze(['mode', 'uid', 'type', 'symlink']);
const FILE_KEYS = Object.freeze(['name', 'mode', 'uid', 'type', 'symlink', 'size_bytes']);

function fail(code) {
  throw new Error(`hage_training_snapshot:${code}`);
}

function requirePlainObject(value, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  return value;
}

function assertExactKeys(value, keys, code) {
  const object = requirePlainObject(value, `${code}_not_object`);
  const observed = Object.keys(object).sort();
  const expected = [...keys].sort();
  if (observed.length !== expected.length
      || observed.some((key, index) => key !== expected[index])) {
    fail(`${code}_keys`);
  }
  return object;
}

function requireString(value, code, maxLength = 512) {
  if (typeof value !== 'string') fail(code);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength) fail(code);
  return normalized;
}

function requireLiteral(value, expected, code) {
  if (value !== expected) fail(code);
  return value;
}

function requireSha256(value, code) {
  const normalized = requireString(value, code, 64);
  if (!SHA256_HEX.test(normalized)) fail(code);
  return normalized;
}

function requireGitCommit(value, code) {
  const normalized = requireString(value, code, 40);
  if (!GIT_COMMIT_HEX.test(normalized)) fail(code);
  return normalized;
}

function requireCompanyId(value, code) {
  const normalized = requireString(value, code, 64);
  if (!COMPANY_ID.test(normalized)) fail(code);
  return normalized;
}

function requireSafeInteger(value, code, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) fail(code);
  return value;
}

function requireBoolean(value, expected, code) {
  if (typeof value !== 'boolean' || (expected !== undefined && value !== expected)) fail(code);
  return value;
}

function requireIsoEpoch(value, code) {
  const normalized = requireString(value, code, 64);
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== normalized) fail(code);
  return normalized;
}

function requireBase64url(value, code, expectedBytes) {
  const normalized = requireString(value, code, 4096);
  if (!BASE64URL.test(normalized)) fail(code);
  let bytes;
  try {
    bytes = Buffer.from(normalized, 'base64url');
  } catch {
    fail(code);
  }
  if (!bytes.length || (expectedBytes !== undefined && bytes.length !== expectedBytes)) fail(code);
  if (bytes.toString('base64url') !== normalized) fail(code);
  return normalized;
}

function requireExactStringArray(value, expected, code) {
  if (!Array.isArray(value)
      || value.length !== expected.length
      || value.some((entry, index) => entry !== expected[index])) fail(code);
  return Object.freeze([...value]);
}

function commitment(domain, body) {
  const bodyBytes = Buffer.from(canonicalJson(body), 'utf8');
  if (bodyBytes.length > 0xffffffff) fail('commitment_body_too_large');
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bodyBytes.length, 0);
  return createHash('sha256')
    .update(Buffer.from(domain, 'utf8'))
    .update(length)
    .update(bodyBytes)
    .digest('hex');
}

function assertExactGraphArtifact(graphSnapshot) {
  const graph = assertExactKeys(graphSnapshot, SNAPSHOT_KEYS, 'graph');
  if (!Array.isArray(graph.nodes)) fail('graph_nodes');
  if (!Array.isArray(graph.edges)) fail('graph_edges');
  for (const node of graph.nodes) assertExactKeys(node, NODE_KEYS, 'graph_node');
  for (const edge of graph.edges) assertExactKeys(edge, EDGE_KEYS, 'graph_edge');
  if (graph.embedding_dimensions !== HAGE_NATIVE_CONTRACT.embedding_dimensions) fail('graph_embedding_dimensions');
  requireExactStringArray(graph.relation_order, HAGE_NATIVE_RELATIONS, 'graph_relation_order');
  return graph;
}

export function createHageTrainingGroupManifest(raw = {}, nodeIds = null) {
  const input = assertExactKeys(raw, GROUP_MANIFEST_KEYS, 'groups');
  requireLiteral(input.schema, HAGE_TRAINING_SNAPSHOT_CONTRACT.group_schema, 'groups_schema');
  const companyId = requireCompanyId(input.company_id, 'groups_company_id');
  requireLiteral(input.grouping_unit, HAGE_TRAINING_SNAPSHOT_CONTRACT.grouping_unit, 'groups_unit');
  if (!Array.isArray(input.rows) || input.rows.length > HAGE_TRAINING_SNAPSHOT_CONTRACT.max_group_rows) {
    fail('groups_rows');
  }
  const expectedNodeIds = nodeIds === null ? null : new Set(nodeIds);
  const observedNodeIds = new Set();
  const rows = input.rows.map((rawRow) => {
    const row = assertExactKeys(rawRow, GROUP_ROW_KEYS, 'group_row');
    const normalized = Object.freeze({
      node_id: requireSha256(row.node_id, 'group_node_id'),
      corpus_sha256: requireSha256(row.corpus_sha256, 'group_corpus_sha256'),
      source_sha256: requireSha256(row.source_sha256, 'group_source_sha256'),
      session_sha256: requireSha256(row.session_sha256, 'group_session_sha256'),
      split_group_sha256: requireSha256(row.split_group_sha256, 'group_split_sha256'),
      authorization_receipt_sha256: requireSha256(
        row.authorization_receipt_sha256,
        'group_authorization_receipt_sha256',
      ),
    });
    if (observedNodeIds.has(normalized.node_id)) fail('group_node_duplicate');
    if (expectedNodeIds && !expectedNodeIds.has(normalized.node_id)) fail('group_node_unknown');
    observedNodeIds.add(normalized.node_id);
    return normalized;
  }).sort((left, right) => left.node_id.localeCompare(right.node_id));
  if (expectedNodeIds
      && (observedNodeIds.size !== expectedNodeIds.size
        || [...expectedNodeIds].some((nodeId) => !observedNodeIds.has(nodeId)))) {
    fail('group_node_coverage');
  }
  return Object.freeze({
    schema: HAGE_TRAINING_SNAPSHOT_CONTRACT.group_schema,
    company_id: companyId,
    grouping_unit: HAGE_TRAINING_SNAPSHOT_CONTRACT.grouping_unit,
    rows: Object.freeze(rows),
  });
}

export function hageTrainingGroupManifestSha256(groupManifest, nodeIds = null) {
  const normalized = createHageTrainingGroupManifest(groupManifest, nodeIds);
  return commitment(HAGE_TRAINING_SNAPSHOT_CONTRACT.group_domain, normalized);
}

function normalizeEmbedding(raw) {
  const input = assertExactKeys(raw, EMBEDDING_KEYS, 'manifest_embedding');
  return Object.freeze({
    model_id: requireString(input.model_id, 'manifest_embedding_model_id', 256),
    revision: requireString(input.revision, 'manifest_embedding_revision', 128),
    dimensions: requireSafeInteger(input.dimensions, 'manifest_embedding_dimensions', {
      min: HAGE_NATIVE_CONTRACT.embedding_dimensions,
      max: HAGE_NATIVE_CONTRACT.embedding_dimensions,
    }),
    pooling: requireLiteral(input.pooling, 'mean', 'manifest_embedding_pooling'),
    normalized: requireBoolean(input.normalized, true, 'manifest_embedding_normalized'),
  });
}

function normalizeCounts(raw) {
  const input = assertExactKeys(raw, COUNT_KEYS, 'manifest_counts');
  return Object.freeze(Object.fromEntries(COUNT_KEYS.map((key) => [
    key,
    requireSafeInteger(input[key], `manifest_count_${key}`, {
      max: key === 'edges' ? HAGE_NATIVE_CONTRACT.max_edges : HAGE_NATIVE_CONTRACT.max_nodes,
    }),
  ])));
}

function normalizeAuthorization(raw) {
  const input = assertExactKeys(raw, AUTHORIZATION_KEYS, 'manifest_authorization');
  return Object.freeze({
    read_receipt_sha256: requireSha256(input.read_receipt_sha256, 'manifest_read_receipt_sha256'),
    scope_sha256: requireSha256(input.scope_sha256, 'manifest_scope_sha256'),
    clearance_ceiling: requireSafeInteger(input.clearance_ceiling, 'manifest_clearance_ceiling', {
      min: 1,
      max: 12,
    }),
  });
}

function normalizeRetention(raw) {
  const input = assertExactKeys(raw, RETENTION_KEYS, 'manifest_retention');
  return Object.freeze({
    canonical_memory_mutation: requireBoolean(
      input.canonical_memory_mutation,
      false,
      'manifest_canonical_memory_mutation',
    ),
    canonical_memory_deletion: requireBoolean(
      input.canonical_memory_deletion,
      false,
      'manifest_canonical_memory_deletion',
    ),
    selective_suppression: requireBoolean(
      input.selective_suppression,
      false,
      'manifest_selective_suppression',
    ),
  });
}

export function createHageTrainingSnapshotManifest(raw = {}) {
  const input = assertExactKeys(raw, MANIFEST_KEYS, 'manifest');
  return Object.freeze({
    schema: requireLiteral(input.schema, HAGE_TRAINING_SNAPSHOT_CONTRACT.schema, 'manifest_schema'),
    purpose: requireLiteral(input.purpose, HAGE_TRAINING_SNAPSHOT_CONTRACT.purpose, 'manifest_purpose'),
    company_id: requireCompanyId(input.company_id, 'manifest_company_id'),
    intent_sha256: requireSha256(input.intent_sha256, 'manifest_intent_sha256'),
    export_nonce: requireSha256(input.export_nonce, 'manifest_export_nonce'),
    created_at_unix: requireSafeInteger(input.created_at_unix, 'manifest_created_at_unix'),
    source_commit_sha256: requireSha256(input.source_commit_sha256, 'manifest_source_commit_sha256'),
    source_manifest_sha256: requireSha256(input.source_manifest_sha256, 'manifest_source_manifest_sha256'),
    architecture_manifest_sha256: requireSha256(
      input.architecture_manifest_sha256,
      'manifest_architecture_manifest_sha256',
    ),
    paper_sha256: requireLiteral(
      input.paper_sha256,
      HAGE_TRAINING_SNAPSHOT_CONTRACT.paper_sha256,
      'manifest_paper_sha256',
    ),
    upstream_reference_commit: requireGitCommit(
      input.upstream_reference_commit,
      'manifest_upstream_reference_commit',
    ),
    graph_snapshot_sha256: requireSha256(input.graph_snapshot_sha256, 'manifest_graph_snapshot_sha256'),
    group_manifest_sha256: requireSha256(input.group_manifest_sha256, 'manifest_group_manifest_sha256'),
    embedding: normalizeEmbedding(input.embedding),
    relation_order: requireExactStringArray(
      input.relation_order,
      HAGE_NATIVE_RELATIONS,
      'manifest_relation_order',
    ),
    counts: normalizeCounts(input.counts),
    authorization: normalizeAuthorization(input.authorization),
    retention: normalizeRetention(input.retention),
  });
}

export function hageTrainingSnapshotCommitment(manifest) {
  return commitment(
    HAGE_TRAINING_SNAPSHOT_CONTRACT.snapshot_domain,
    createHageTrainingSnapshotManifest(manifest),
  );
}

function normalizeReceiptBody(raw) {
  const input = assertExactKeys(raw, RECEIPT_BODY_KEYS, 'receipt_body');
  return Object.freeze({
    schema: requireLiteral(input.schema, HAGE_TRAINING_SNAPSHOT_CONTRACT.receipt_schema, 'receipt_schema'),
    company_id: requireCompanyId(input.company_id, 'receipt_company_id'),
    event_id: requireSha256(input.event_id, 'receipt_event_id'),
    operation: requireLiteral(input.operation, 'hage_training_snapshot_exported', 'receipt_operation'),
    snapshot_commitment_sha256: requireSha256(
      input.snapshot_commitment_sha256,
      'receipt_snapshot_commitment_sha256',
    ),
    graph_snapshot_sha256: requireSha256(input.graph_snapshot_sha256, 'receipt_graph_snapshot_sha256'),
    group_manifest_sha256: requireSha256(input.group_manifest_sha256, 'receipt_group_manifest_sha256'),
    intent_sha256: requireSha256(input.intent_sha256, 'receipt_intent_sha256'),
    export_nonce: requireSha256(input.export_nonce, 'receipt_export_nonce'),
    event_mutation_sha256: requireSha256(input.event_mutation_sha256, 'receipt_event_mutation_sha256'),
    signer_agent_id: requireLiteral(
      input.signer_agent_id,
      HAGE_TRAINING_SNAPSHOT_CONTRACT.signer_agent_id,
      'receipt_signer_agent_id',
    ),
    signer_epoch: requireIsoEpoch(input.signer_epoch, 'receipt_signer_epoch'),
    cert_fingerprint: requireSha256(input.cert_fingerprint, 'receipt_cert_fingerprint'),
    signed_at_unix: requireSafeInteger(input.signed_at_unix, 'receipt_signed_at_unix'),
  });
}

export function hageTrainingSnapshotReceiptCommitment(receiptBody) {
  return commitment(
    HAGE_TRAINING_SNAPSHOT_CONTRACT.receipt_domain,
    normalizeReceiptBody(receiptBody),
  );
}

function normalizeReceipt(raw) {
  const input = assertExactKeys(raw, RECEIPT_KEYS, 'receipt');
  return Object.freeze({
    body: normalizeReceiptBody(input.body),
    signature_base64url: requireBase64url(input.signature_base64url, 'receipt_signature', 64),
  });
}

function normalizeTrustContext(raw) {
  const input = assertExactKeys(raw, TRUST_KEYS, 'trust');
  if (!Array.isArray(input.consumed_export_nonces)) fail('trust_consumed_export_nonces');
  if (!Array.isArray(input.consumed_event_ids)) fail('trust_consumed_event_ids');
  return Object.freeze({
    company_id: requireCompanyId(input.company_id, 'trust_company_id'),
    intent_sha256: requireSha256(input.intent_sha256, 'trust_intent_sha256'),
    read_receipt_sha256: requireSha256(input.read_receipt_sha256, 'trust_read_receipt_sha256'),
    source_commit_sha256: requireSha256(input.source_commit_sha256, 'trust_source_commit_sha256'),
    signer_agent_id: requireLiteral(
      input.signer_agent_id,
      HAGE_TRAINING_SNAPSHOT_CONTRACT.signer_agent_id,
      'trust_signer_agent_id',
    ),
    signer_epoch: requireIsoEpoch(input.signer_epoch, 'trust_signer_epoch'),
    cert_fingerprint: requireSha256(input.cert_fingerprint, 'trust_cert_fingerprint'),
    signer_public_key: requireBase64url(input.signer_public_key, 'trust_signer_public_key'),
    consumed_export_nonces: Object.freeze(input.consumed_export_nonces.map((value) => (
      requireSha256(value, 'trust_consumed_export_nonce')
    ))),
    consumed_event_ids: Object.freeze(input.consumed_event_ids.map((value) => (
      requireSha256(value, 'trust_consumed_event_id')
    ))),
  });
}

function uniqueCount(rows, key) {
  return new Set(rows.map((row) => row[key])).size;
}

function rawVerifyEd25519(publicKeyBase64url, commitmentHex, signatureBase64url) {
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(requireBase64url(publicKeyBase64url, 'signer_public_key'), 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return verifySignature(
      null,
      Buffer.from(commitmentHex, 'hex'),
      publicKey,
      Buffer.from(signatureBase64url, 'base64url'),
    );
  } catch {
    return false;
  }
}

export function verifyPortableHageTrainingSnapshot(raw = {}) {
  try {
    const input = assertExactKeys(raw, BUNDLE_KEYS, 'bundle');
    const graphSnapshot = input.graph_snapshot;
    const groupManifest = input.group_manifest;
    const manifest = input.manifest;
    const receipt = input.receipt;
    const trustedContext = input.trusted_context;
    assertExactGraphArtifact(graphSnapshot);
    const graph = createHageGraphSnapshot(graphSnapshot);
    const nodeIds = graph.nodes.map((node) => node.id);
    const groups = createHageTrainingGroupManifest(groupManifest, nodeIds);
    const normalizedManifest = createHageTrainingSnapshotManifest(manifest);
    const normalizedReceipt = normalizeReceipt(receipt);
    const trust = normalizeTrustContext(trustedContext);
    const graphHash = hageSnapshotSha256(graph);
    const groupsHash = hageTrainingGroupManifestSha256(groups, nodeIds);
    const snapshotCommitment = hageTrainingSnapshotCommitment(normalizedManifest);
    const receiptCommitment = hageTrainingSnapshotReceiptCommitment(normalizedReceipt.body);

    if (normalizedManifest.company_id !== groups.company_id
        || normalizedManifest.company_id !== trust.company_id
        || normalizedReceipt.body.company_id !== trust.company_id) fail('company_mismatch');
    if (normalizedManifest.intent_sha256 !== trust.intent_sha256
        || normalizedReceipt.body.intent_sha256 !== trust.intent_sha256) fail('intent_unauthorized');
    if (normalizedManifest.authorization.read_receipt_sha256 !== trust.read_receipt_sha256
        || groups.rows.some((row) => row.authorization_receipt_sha256 !== trust.read_receipt_sha256)) {
      fail('read_receipt_unauthorized');
    }
    if (normalizedManifest.source_commit_sha256 !== trust.source_commit_sha256
        || graph.source_commit !== trust.source_commit_sha256) fail('source_commit_mismatch');
    if (normalizedManifest.source_manifest_sha256 !== graph.source_manifest_sha256) {
      fail('source_manifest_mismatch');
    }
    if (normalizedManifest.graph_snapshot_sha256 !== graphHash
        || normalizedReceipt.body.graph_snapshot_sha256 !== graphHash) fail('graph_hash_mismatch');
    if (normalizedManifest.group_manifest_sha256 !== groupsHash
        || normalizedReceipt.body.group_manifest_sha256 !== groupsHash) fail('groups_hash_mismatch');
    if (normalizedReceipt.body.snapshot_commitment_sha256 !== snapshotCommitment) {
      fail('snapshot_commitment_mismatch');
    }
    if (normalizedReceipt.body.export_nonce !== normalizedManifest.export_nonce) fail('nonce_mismatch');
    if (trust.consumed_export_nonces.includes(normalizedManifest.export_nonce)
        || trust.consumed_event_ids.includes(normalizedReceipt.body.event_id)) fail('replay_detected');
    if (normalizedReceipt.body.signer_agent_id !== trust.signer_agent_id
        || normalizedReceipt.body.signer_epoch !== trust.signer_epoch
        || normalizedReceipt.body.cert_fingerprint !== trust.cert_fingerprint) fail('signer_epoch_mismatch');
    if (normalizedReceipt.body.signed_at_unix < normalizedManifest.created_at_unix
        || normalizedReceipt.body.signed_at_unix - normalizedManifest.created_at_unix > 300) {
      fail('receipt_time_binding');
    }
    if (graph.embedding_model_id !== normalizedManifest.embedding.model_id
        || graph.embedding_model_revision !== normalizedManifest.embedding.revision
        || graph.embedding_dimensions !== normalizedManifest.embedding.dimensions) {
      fail('embedding_binding');
    }
    if (normalizedManifest.counts.nodes !== graph.nodes.length
        || normalizedManifest.counts.edges !== graph.edges.length
        || normalizedManifest.counts.corpora !== uniqueCount(groups.rows, 'corpus_sha256')
        || normalizedManifest.counts.sources !== uniqueCount(groups.rows, 'source_sha256')
        || normalizedManifest.counts.sessions !== uniqueCount(groups.rows, 'session_sha256')
        || normalizedManifest.counts.split_groups !== uniqueCount(groups.rows, 'split_group_sha256')) {
      fail('count_binding');
    }
    if (!rawVerifyEd25519(
      trust.signer_public_key,
      receiptCommitment,
      normalizedReceipt.signature_base64url,
    )) {
      fail('signature_invalid');
    }

    return Object.freeze({
      valid: true,
      reason: null,
      snapshot_commitment_sha256: snapshotCommitment,
      receipt_commitment_sha256: receiptCommitment,
      graph_snapshot_sha256: graphHash,
      group_manifest_sha256: groupsHash,
      event_id: normalizedReceipt.body.event_id,
      event_mutation_sha256: normalizedReceipt.body.event_mutation_sha256,
      signer_agent_id: normalizedReceipt.body.signer_agent_id,
      signer_epoch: normalizedReceipt.body.signer_epoch,
      live_admission_verified: false,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return Object.freeze({
      valid: false,
      reason: message.startsWith('hage_training_snapshot:')
        ? message.slice('hage_training_snapshot:'.length)
        : 'malformed_bundle',
      live_admission_verified: false,
    });
  }
}

export function verifyHageTrainingSnapshotFilesystemBoundary(raw = {}) {
  try {
    const input = assertExactKeys(raw, FILESYSTEM_KEYS, 'filesystem');
    const directory = assertExactKeys(input.directory, DIRECTORY_KEYS, 'filesystem_directory');
    const processUid = requireSafeInteger(input.process_uid, 'filesystem_process_uid');
    if (directory.type !== 'directory'
        || directory.symlink !== false
        || directory.uid !== processUid
        || directory.mode !== HAGE_TRAINING_SNAPSHOT_CONTRACT.directory_mode) {
      fail('filesystem_directory_boundary');
    }
    if (!Array.isArray(input.files)) fail('filesystem_files');
    const files = input.files.map((rawFile) => {
      const file = assertExactKeys(rawFile, FILE_KEYS, 'filesystem_file');
      return Object.freeze({
        name: requireString(file.name, 'filesystem_file_name', 64),
        mode: requireSafeInteger(file.mode, 'filesystem_file_mode', { max: 0o777 }),
        uid: requireSafeInteger(file.uid, 'filesystem_file_uid'),
        type: requireString(file.type, 'filesystem_file_type', 16),
        symlink: requireBoolean(file.symlink, undefined, 'filesystem_file_symlink'),
        size_bytes: requireSafeInteger(file.size_bytes, 'filesystem_file_size'),
      });
    }).sort((left, right) => left.name.localeCompare(right.name));
    const names = files.map((file) => file.name);
    const expectedNames = [...HAGE_TRAINING_SNAPSHOT_CONTRACT.required_files].sort();
    if (names.length !== expectedNames.length
        || names.some((name, index) => name !== expectedNames[index])) fail('filesystem_file_set');
    const maxByName = {
      'graph.json': HAGE_TRAINING_SNAPSHOT_CONTRACT.max_graph_bytes,
      'groups.json': HAGE_TRAINING_SNAPSHOT_CONTRACT.max_groups_bytes,
      'manifest.json': HAGE_TRAINING_SNAPSHOT_CONTRACT.max_manifest_bytes,
      'receipt.json': HAGE_TRAINING_SNAPSHOT_CONTRACT.max_receipt_bytes,
    };
    for (const file of files) {
      if (file.type !== 'file'
          || file.symlink !== false
          || file.uid !== processUid
          || file.mode !== HAGE_TRAINING_SNAPSHOT_CONTRACT.file_mode
          || file.size_bytes > maxByName[file.name]) fail('filesystem_file_boundary');
    }
    return Object.freeze({ valid: true, reason: null, files: Object.freeze(files) });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return Object.freeze({
      valid: false,
      reason: message.startsWith('hage_training_snapshot:')
        ? message.slice('hage_training_snapshot:'.length)
        : 'malformed_filesystem_metadata',
    });
  }
}
