import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  canonicalJson,
  generateKeypair,
  issueCert,
  signPayload,
} from '../../services/security/agent-identity.js';
import {
  eventGenesisHash,
  eventMutationHash,
} from '../../services/security/protocol/mutmem-protocol.js';
import {
  RECALL_GRAPH_LINK_BATCH_CONTRACT,
  readBatchedRecallGraphLinks,
} from '../../services/retrieval/native-recall-pipeline.js';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const EVENT = '44444444-4444-4444-8444-444444444444';

function signedGraphEvent() {
  const signer = generateKeypair();
  const signerValidFrom = '2026-08-31T12:00:00.000Z';
  const validFromUnix = Math.floor(new Date(signerValidFrom).getTime() / 1000);
  const cert = issueCert(signer.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: 'graph-link-batch-test',
    valid_from: validFromUnix,
    valid_until: 2_000_000_000,
    issuer: 'housekeeper',
    issued_at: validFromUnix,
  });
  const certFingerprint = createHash('sha256').update(Buffer.from(cert, 'utf8')).digest('hex');
  const prev = eventGenesisHash('hom', 'housekeeper', signerValidFrom);
  const ts = validFromUnix + 1;
  const nonce = 'graph-link-batch-nonce';
  const metadata = {
    edges: [
      { source_memory_id: A, target_memory_id: C, similarity: 0.9 },
      { source_memory_id: B, target_memory_id: C, similarity: 0.8 },
    ],
    reasoning: 'Fixture signs exact cross-reference relational state.',
  };
  const body = {
    ledger_version: 1,
    event_id: EVENT,
    company_id: 'hom',
    subject_agent_id: 'housekeeper',
    actor_agent_id: null,
    actor_valid_from: null,
    signer_agent_id: 'housekeeper',
    signer_valid_from: signerValidFrom,
    cert_fingerprint: certFingerprint,
    identity_tier: 'T1_SYSTEM_SELF',
    authority_kind: 'housekeeper_autonomous',
    request_envelope_digest: null,
    operation: 'memory_cross_refs_seeded',
    key: 'test:graph',
    metadata,
    parent_event_id: null,
    ledger_seq: 1,
    prev_mutation_hash: prev.toString('hex'),
    ts_signed: ts,
  };
  const contentHash = createHash('sha256').update(Buffer.from(canonicalJson(body), 'utf8')).digest();
  return {
    id: EVENT,
    ts: new Date(ts * 1000),
    company_id: 'hom',
    agent_id: 'housekeeper',
    operation: body.operation,
    key: body.key,
    metadata,
    parent_event_id: null,
    proof_required: true,
    ledger_version: 1,
    ledger_seq: 1,
    signer_agent_id: 'housekeeper',
    signer_valid_from: signerValidFrom,
    cert_fingerprint: certFingerprint,
    identity_tier: body.identity_tier,
    authority_kind: body.authority_kind,
    signed_body: body,
    content_hash: contentHash,
    mutation_hash: eventMutationHash(prev, contentHash, nonce, ts),
    prev_mutation_hash: prev,
    ts_signed: ts,
    nonce,
    sig: Buffer.from(signPayload(signer.privkey, body, nonce, ts), 'base64url'),
    cert,
    pubkey: signer.pubkey,
    revocation_ts_signed: null,
    stored_predecessor_hash: null,
    master_pubkey: signer.pubkey,
  };
}

test('R5H-S0 graph-link annotation uses one bounded multi-seed query', async () => {
  const calls = [];
  const event = signedGraphEvent();
  const result = await readBatchedRecallGraphLinks({
    companyId: 'hom',
    seedMemoryIds: [A, B],
    maxHops: 4,
    queryFn: async (text, params) => {
      calls.push({ text, params });
      if (text.includes('FROM aimos_events event')) return { rows: [event] };
      return { rows: [
        {
          root_memory_id: A,
          memory_id: C,
          similarity: 0.9,
          hop: 1,
          path_edges: [{
            source_memory_id: A,
            target_memory_id: C,
            similarity: 0.9,
            edge_type: 'similarity',
            authority_event_id: EVENT,
          }],
        },
        {
          root_memory_id: B,
          memory_id: C,
          similarity: 0.8,
          hop: 1,
          path_edges: [{
            source_memory_id: B,
            target_memory_id: C,
            similarity: 0.8,
            edge_type: 'similarity',
            authority_event_id: EVENT,
          }],
        },
      ] };
    },
  });
  assert.equal(calls.length, 2);
  assert.match(calls[0].text, /unnest\(\$2::uuid\[\]\)/);
  assert.match(calls[0].text, /CROSS JOIN LATERAL/);
  assert.match(calls[0].text, /NOT edge\.target_memory_id = ANY\(gw\.path_ids\)/);
  assert.match(calls[0].text, /root_rank <= \$5/);
  assert.equal(calls[0].params[2], 2);
  assert.equal(result.decision.database_round_trips, 2);
  assert.equal(result.decision.seed_count, 2);
  assert.equal(result.decision.row_count, 2);
  assert.equal(result.decision.applied_hops, 2);
  assert.equal(result.decision.verified_edge_count, 2);
  assert.equal(result.decision.verified_authority_event_count, 1);
  assert.equal(result.decision.unsigned_edge_admission_count, 0);
  assert.match(result.decision.edge_set_sha256, /^[0-9a-f]{64}$/);
  assert.match(result.decision.decision_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(result.linksBySeed.get(A), [{ id: C, similarity: 0.9, hop: 1, authority_event_ids: [EVENT] }]);
  assert.deepEqual(result.linksBySeed.get(B), [{ id: C, similarity: 0.8, hop: 1, authority_event_ids: [EVENT] }]);
});

test('graph-link authority rejects unsigned paths and signed-body relational mismatch', async () => {
  const event = signedGraphEvent();
  await assert.rejects(
    readBatchedRecallGraphLinks({
      companyId: 'hom',
      seedMemoryIds: [A],
      maxHops: 1,
      queryFn: async (text) => {
        if (text.includes('FROM aimos_events event')) return { rows: [event] };
        return { rows: [{
          root_memory_id: A,
          memory_id: C,
          similarity: 0.91,
          hop: 1,
          path_edges: [{
            source_memory_id: A,
            target_memory_id: C,
            similarity: 0.91,
            edge_type: 'similarity',
            authority_event_id: EVENT,
          }],
        }] };
      },
    }),
    /recall_graph_link_authority_relational_mismatch/,
  );

  await assert.rejects(
    readBatchedRecallGraphLinks({
      companyId: 'hom',
      seedMemoryIds: [A],
      maxHops: 1,
      queryFn: async () => ({ rows: [{
        root_memory_id: A,
        memory_id: C,
        similarity: 0.9,
        hop: 1,
        path_edges: [{
          source_memory_id: A,
          target_memory_id: C,
          similarity: 0.9,
          edge_type: 'similarity',
          authority_event_id: null,
        }],
      }] }),
    }),
    /recall_graph_link_path_invalid/,
  );
});

test('R5H-S0 graph-link batch fails closed on seed and row bound violations', async () => {
  await assert.rejects(
    readBatchedRecallGraphLinks({
      companyId: 'hom', seedMemoryIds: ['invalid'], maxHops: 1,
      queryFn: async () => ({ rows: [] }),
    }),
    /recall_graph_link_batch_seed_bound_invalid/,
  );
  const tooManyRows = Array.from(
    { length: RECALL_GRAPH_LINK_BATCH_CONTRACT.maximum_links_per_seed + 1 },
    () => ({
      root_memory_id: A,
      memory_id: C,
      similarity: 1,
      hop: 1,
      path_edges: [{
        source_memory_id: A,
        target_memory_id: C,
        similarity: 1,
        edge_type: 'similarity',
        authority_event_id: EVENT,
      }],
    }),
  );
  await assert.rejects(
    readBatchedRecallGraphLinks({
      companyId: 'hom', seedMemoryIds: [A], maxHops: 1,
      queryFn: async () => ({ rows: tooManyRows }),
    }),
    /recall_graph_link_batch_row_bound_exceeded/,
  );
});
