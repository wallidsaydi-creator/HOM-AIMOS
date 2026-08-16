import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as signMessage,
} from 'node:crypto';

import {
  HAGE_TRAINING_SNAPSHOT_CONTRACT,
  createHageTrainingGroupManifest,
  createHageTrainingSnapshotManifest,
  hageTrainingGroupManifestSha256,
  hageTrainingSnapshotCommitment,
  hageTrainingSnapshotReceiptCommitment,
  verifyHageTrainingSnapshotFilesystemBoundary,
  verifyPortableHageTrainingSnapshot,
} from '../../services/retrieval/hage-native/training-snapshot.js';
import {
  HAGE_NATIVE_CONTRACT,
  HAGE_NATIVE_RELATIONS,
  createHageGraphSnapshot,
  hageSnapshotSha256,
} from '../../services/retrieval/hage-native/graph-contract.js';

function sha(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function unitEmbedding(index) {
  const embedding = Array(HAGE_NATIVE_CONTRACT.embedding_dimensions).fill(0);
  embedding[index] = 1;
  return embedding;
}

function graphFixture() {
  const left = sha('node:left');
  const right = sha('node:right');
  return createHageGraphSnapshot({
    schema_version: 1,
    source_manifest_sha256: sha('source-manifest'),
    source_commit: sha('source-commit'),
    embedding_model_id: 'Xenova/all-mpnet-base-v2',
    embedding_model_revision: 'e086c5e0b3a57b0ce46dd6d9c0662948860b35f3',
    nodes: [
      {
        id: left,
        content_sha256: sha('content:left'),
        timestamp_unix_ms: 1_780_000_000_000,
        embedding: unitEmbedding(0),
        metadata_sha256: sha('metadata:left'),
      },
      {
        id: right,
        content_sha256: sha('content:right'),
        timestamp_unix_ms: 1_780_000_001_000,
        embedding: unitEmbedding(1),
        metadata_sha256: sha('metadata:right'),
      },
    ],
    edges: [{
      id: sha('edge:left-right'),
      from: left,
      to: right,
      relation: 'causal',
      initial_feature: [0, 0, 1, 0],
      evidence_sha256: sha('edge-evidence'),
    }],
  });
}

function groupFixture(graph, readReceipt = sha('read-receipt'), companyId = 'hom') {
  return createHageTrainingGroupManifest({
    schema: HAGE_TRAINING_SNAPSHOT_CONTRACT.group_schema,
    company_id: companyId,
    grouping_unit: HAGE_TRAINING_SNAPSHOT_CONTRACT.grouping_unit,
    rows: graph.nodes.map((node, index) => ({
      node_id: node.id,
      corpus_sha256: sha('corpus:one'),
      source_sha256: sha(`source:${index}`),
      session_sha256: sha(`session:${index}`),
      split_group_sha256: sha(`split:${index}`),
      authorization_receipt_sha256: readReceipt,
    })),
  }, graph.nodes.map((node) => node.id));
}

function buildSignedBundle() {
  const graph = graphFixture();
  const groups = groupFixture(graph);
  const graphHash = hageSnapshotSha256(graph);
  const groupsHash = hageTrainingGroupManifestSha256(
    groups,
    graph.nodes.map((node) => node.id),
  );
  const intent = sha('intent:hage-training');
  const exportNonce = sha('export-nonce:one');
  const signerEpoch = '2026-08-05T12:00:00.000Z';
  const certFingerprint = sha('housekeeper-cert');
  const manifest = createHageTrainingSnapshotManifest({
    schema: HAGE_TRAINING_SNAPSHOT_CONTRACT.schema,
    purpose: HAGE_TRAINING_SNAPSHOT_CONTRACT.purpose,
    company_id: 'hom',
    intent_sha256: intent,
    export_nonce: exportNonce,
    created_at_unix: 1_785_930_000,
    source_commit_sha256: graph.source_commit,
    source_manifest_sha256: graph.source_manifest_sha256,
    architecture_manifest_sha256: sha('architecture-manifest'),
    paper_sha256: HAGE_TRAINING_SNAPSHOT_CONTRACT.paper_sha256,
    upstream_reference_commit: HAGE_TRAINING_SNAPSHOT_CONTRACT.upstream_reference_commit,
    graph_snapshot_sha256: graphHash,
    group_manifest_sha256: groupsHash,
    embedding: {
      model_id: graph.embedding_model_id,
      revision: graph.embedding_model_revision,
      dimensions: graph.embedding_dimensions,
      pooling: 'mean',
      normalized: true,
    },
    relation_order: HAGE_NATIVE_RELATIONS,
    counts: {
      nodes: 2,
      edges: 1,
      corpora: 1,
      sources: 2,
      sessions: 2,
      split_groups: 2,
    },
    authorization: {
      read_receipt_sha256: sha('read-receipt'),
      scope_sha256: sha('scope'),
      clearance_ceiling: 10,
    },
    retention: {
      canonical_memory_mutation: false,
      canonical_memory_deletion: false,
      selective_suppression: false,
    },
  });
  const snapshotCommitment = hageTrainingSnapshotCommitment(manifest);
  const receiptBody = {
    schema: HAGE_TRAINING_SNAPSHOT_CONTRACT.receipt_schema,
    company_id: 'hom',
    event_id: sha('event:one'),
    operation: 'hage_training_snapshot_exported',
    snapshot_commitment_sha256: snapshotCommitment,
    graph_snapshot_sha256: graphHash,
    group_manifest_sha256: groupsHash,
    intent_sha256: intent,
    export_nonce: exportNonce,
    event_mutation_sha256: sha('event-mutation'),
    signer_agent_id: 'housekeeper',
    signer_epoch: signerEpoch,
    cert_fingerprint: certFingerprint,
    signed_at_unix: 1_785_930_001,
  };
  const receiptCommitment = hageTrainingSnapshotReceiptCommitment(receiptBody);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const signature = signMessage(null, Buffer.from(receiptCommitment, 'hex'), privateKey);
  return {
    graph_snapshot: graph,
    group_manifest: groups,
    manifest,
    receipt: {
      body: receiptBody,
      signature_base64url: signature.toString('base64url'),
    },
    trusted_context: {
      company_id: 'hom',
      intent_sha256: intent,
      read_receipt_sha256: sha('read-receipt'),
      source_commit_sha256: graph.source_commit,
      signer_agent_id: 'housekeeper',
      signer_epoch: signerEpoch,
      cert_fingerprint: certFingerprint,
      signer_public_key: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
      consumed_export_nonces: [],
      consumed_event_ids: [],
    },
  };
}

function filesystemFixture() {
  return {
    directory: { mode: 0o700, uid: 501, type: 'directory', symlink: false },
    files: [
      { name: 'graph.json', mode: 0o600, uid: 501, type: 'file', symlink: false, size_bytes: 50_000 },
      { name: 'groups.json', mode: 0o600, uid: 501, type: 'file', symlink: false, size_bytes: 5_000 },
      { name: 'manifest.json', mode: 0o600, uid: 501, type: 'file', symlink: false, size_bytes: 2_000 },
      { name: 'receipt.json', mode: 0o600, uid: 501, type: 'file', symlink: false, size_bytes: 2_000 },
    ],
    process_uid: 501,
  };
}

test('HAGE-N4 dry-run bundle verifies without live admission authority', () => {
  const result = verifyPortableHageTrainingSnapshot(buildSignedBundle());
  assert.equal(result.valid, true);
  assert.equal(result.reason, null);
  assert.equal(result.signer_agent_id, 'housekeeper');
  assert.equal(result.live_admission_verified, false);
  assert.match(result.snapshot_commitment_sha256, /^[0-9a-f]{64}$/);
});

test('HAGE-N4 commitments are deterministic across object insertion order', () => {
  const { manifest } = buildSignedBundle();
  const reversed = Object.fromEntries(Object.entries(structuredClone(manifest)).reverse());
  assert.equal(hageTrainingSnapshotCommitment(manifest), hageTrainingSnapshotCommitment(reversed));
});

test('HAGE-N4 rejects graph, group, and manifest mutations', () => {
  const mutations = [
    (bundle) => { bundle.graph_snapshot.nodes[0].timestamp_unix_ms += 1; },
    (bundle) => { bundle.group_manifest.rows[0].session_sha256 = sha('tampered-session'); },
    (bundle) => { bundle.manifest.counts.nodes = 3; },
    (bundle) => { bundle.receipt.body.event_mutation_sha256 = sha('tampered-event'); },
  ];
  for (const mutate of mutations) {
    const bundle = structuredClone(buildSignedBundle());
    mutate(bundle);
    assert.equal(verifyPortableHageTrainingSnapshot(bundle).valid, false);
  }
});

test('HAGE-N4 rejects cross-company and unauthorized intent or read receipt', () => {
  const cases = [
    (bundle) => { bundle.trusted_context.company_id = 'other'; },
    (bundle) => { bundle.trusted_context.intent_sha256 = sha('other-intent'); },
    (bundle) => { bundle.trusted_context.read_receipt_sha256 = sha('other-receipt'); },
    (bundle) => { bundle.trusted_context.source_commit_sha256 = sha('other-source'); },
  ];
  for (const mutate of cases) {
    const bundle = buildSignedBundle();
    mutate(bundle);
    const result = verifyPortableHageTrainingSnapshot(bundle);
    assert.equal(result.valid, false);
  }
});

test('HAGE-N4 rejects unsigned and wrongly signed receipts', () => {
  const unsigned = buildSignedBundle();
  unsigned.receipt.signature_base64url = '';
  assert.equal(verifyPortableHageTrainingSnapshot(unsigned).valid, false);

  const wrongKey = buildSignedBundle();
  const { publicKey } = generateKeyPairSync('ed25519');
  wrongKey.trusted_context.signer_public_key = publicKey
    .export({ format: 'der', type: 'spki' })
    .toString('base64url');
  assert.equal(verifyPortableHageTrainingSnapshot(wrongKey).reason, 'signature_invalid');
});

test('HAGE-N4 binds the exact housekeeper signer epoch and certificate fingerprint', () => {
  const epoch = buildSignedBundle();
  epoch.trusted_context.signer_epoch = '2026-08-05T12:00:01.000Z';
  assert.equal(verifyPortableHageTrainingSnapshot(epoch).reason, 'signer_epoch_mismatch');

  const cert = buildSignedBundle();
  cert.trusted_context.cert_fingerprint = sha('other-cert');
  assert.equal(verifyPortableHageTrainingSnapshot(cert).reason, 'signer_epoch_mismatch');
});

test('HAGE-N4 rejects replayed export nonces and event IDs', () => {
  const nonceReplay = buildSignedBundle();
  nonceReplay.trusted_context.consumed_export_nonces = [nonceReplay.manifest.export_nonce];
  assert.equal(verifyPortableHageTrainingSnapshot(nonceReplay).reason, 'replay_detected');

  const eventReplay = buildSignedBundle();
  eventReplay.trusted_context.consumed_event_ids = [eventReplay.receipt.body.event_id];
  assert.equal(verifyPortableHageTrainingSnapshot(eventReplay).reason, 'replay_detected');
});

test('HAGE-N4 requires complete one-to-one source/session grouping', () => {
  const missing = structuredClone(buildSignedBundle());
  missing.group_manifest.rows.pop();
  assert.equal(verifyPortableHageTrainingSnapshot(missing).reason, 'group_node_coverage');

  const duplicate = structuredClone(buildSignedBundle());
  duplicate.group_manifest.rows[1].node_id = duplicate.group_manifest.rows[0].node_id;
  assert.equal(verifyPortableHageTrainingSnapshot(duplicate).reason, 'group_node_duplicate');
});

test('HAGE-N4 rejects unknown fields that could carry raw text or credentials', () => {
  const bundleLeak = structuredClone(buildSignedBundle());
  bundleLeak.private_key = 'not-authorized';
  assert.equal(verifyPortableHageTrainingSnapshot(bundleLeak).reason, 'bundle_keys');

  const graphLeak = structuredClone(buildSignedBundle());
  graphLeak.graph_snapshot.nodes[0].raw_text = 'private memory text';
  assert.equal(verifyPortableHageTrainingSnapshot(graphLeak).reason, 'graph_node_keys');

  const manifestLeak = structuredClone(buildSignedBundle());
  manifestLeak.manifest.api_token = 'not-authorized';
  assert.equal(verifyPortableHageTrainingSnapshot(manifestLeak).reason, 'manifest_keys');

  const groupLeak = structuredClone(buildSignedBundle());
  groupLeak.group_manifest.rows[0].session_text = 'private session';
  assert.equal(verifyPortableHageTrainingSnapshot(groupLeak).reason, 'group_row_keys');
});

test('HAGE-N4 validates owner-only, non-symlink filesystem metadata', () => {
  const result = verifyHageTrainingSnapshotFilesystemBoundary(filesystemFixture());
  assert.equal(result.valid, true);
  assert.deepEqual(result.files.map((file) => file.name), [
    'graph.json',
    'groups.json',
    'manifest.json',
    'receipt.json',
  ]);
});

test('HAGE-N4 fails closed on unsafe modes, owners, symlinks, file sets, and sizes', () => {
  const cases = [
    (fixture) => { fixture.directory.mode = 0o755; },
    (fixture) => { fixture.files[0].mode = 0o644; },
    (fixture) => { fixture.files[0].uid = 0; },
    (fixture) => { fixture.files[0].symlink = true; },
    (fixture) => { fixture.files.pop(); },
    (fixture) => { fixture.files[0].size_bytes = HAGE_TRAINING_SNAPSHOT_CONTRACT.max_graph_bytes + 1; },
  ];
  for (const mutate of cases) {
    const fixture = filesystemFixture();
    mutate(fixture);
    assert.equal(verifyHageTrainingSnapshotFilesystemBoundary(fixture).valid, false);
  }
});

test('HAGE-N4 does not mutate caller-owned bundle data', () => {
  const bundle = buildSignedBundle();
  const before = structuredClone(bundle);
  verifyPortableHageTrainingSnapshot(bundle);
  assert.deepEqual(bundle, before);
});
