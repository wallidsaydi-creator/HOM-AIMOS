import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  cognitiveBaselineHash,
  cognitiveCorpusRoot,
  cognitiveProjectionHash,
  cognitiveTransitionHash,
  eventGenesisHash,
  eventMutationHash,
  memoryEpistemicClassificationHash,
  recallMerkleRoot,
  retainedProvenanceLeafHash,
  retainedProvenanceMerkleRoot,
} from '../../services/security/protocol/mutmem-protocol.js';

const baseline = {
  companyId: 'hom',
  memoryId: '11111111-1111-4111-8111-111111111111',
  eventId: '22222222-2222-4222-8222-222222222222',
  eventMutationHash: Buffer.alloc(32, 1),
  liveContentHash: Buffer.alloc(32, 2),
  observedWeight: Math.fround(1.2344),
  weightMilli: 1234,
  observedTs: 1_800_000_000,
  signerValidFromIso: '2026-07-11T19:13:08.000Z',
  certFingerprint: 'ab'.repeat(32),
};

const transition = {
  companyId: 'hom',
  memoryId: '00112233-4455-6677-8899-aabbccddeeff',
  oldWeight: 0.1,
  newWeight: 3,
  provenanceMutationHash: Buffer.alloc(32),
};

const retainedRow = {
  provenance_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  memory_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  provenance_agent_id: 'legacy-agent',
  agent_valid_from: '2026-07-11T09:13:20.000Z',
  cert_fingerprint: 'a'.repeat(64),
  prov_content_hash: createHash('sha256').update('retained-content').digest(),
  mutation_hash: createHash('sha256').update('retained-mutation').digest(),
  prev_mutation_hash: null,
  ts_signed: 1_783_764_000,
  nonce: 'retained-node-nonce',
  sig: Buffer.alloc(64, 7),
  identity_tier: 'T1',
  is_genesis: true,
  backfilled: false,
  memory_originated_at: null,
  legacy_envelope_sig: null,
  provenance_created_at: '2026-07-11T09:20:00.000Z',
  event_type: 'SAVE',
  body_json: null,
  sig_form_version: 1,
  snapshot_live_content_hash: Buffer.alloc(32, 3),
  request_sig_form: 1,
  signed_method: null,
  signed_path: null,
  signed_claims: null,
  binding_schema_version: 1,
};

test('pure protocol owner reproduces every frozen pre-extraction commitment', () => {
  assert.equal(canonicalJson({ z: 1, a: [true, 'x'] }), '{"a":[true,"x"],"z":1}');
  assert.equal(
    cognitiveBaselineHash(baseline).toString('hex'),
    '8339e5ab8ddfcb9fa2b33dd579473dafeb808559d838353d264a80d620e17c35',
  );
  assert.equal(
    cognitiveTransitionHash(transition).toString('hex'),
    '930a0a94bbb14afc2974aba6e4f0950ae2f50d746934ff1a6f4e749ca015c2b5',
  );
  assert.equal(
    cognitiveProjectionHash({
      memoryId: transition.memoryId,
      oldWeightMilli: 100,
      newWeightMilli: 3000,
      provenanceMutationHash: Buffer.alloc(32),
    }).toString('hex'),
    '5780918207215f284ee26878aea5d69da03555cfff4e3e4bc36b172dae57ad79',
  );

  const eventGenesis = eventGenesisHash('hom', 'housekeeper', '2026-07-11T09:30:00.000Z');
  assert.equal(eventGenesis.toString('hex'), 'bc637cd7e9ca552be14c04eb293ff271ce2c63badd9295bd0823027df4700291');
  assert.equal(
    eventMutationHash(
      eventGenesis,
      createHash('sha256').update('event-content').digest(),
      'event-proof-nonce',
      1_783_764_000,
    ).toString('hex'),
    'f0bdeb74b82d6585cb66eb235d337c60ba56973dc6ba99e5f95895cce2ca37a1',
  );

  const retainedLeaf = retainedProvenanceLeafHash(retainedRow);
  assert.equal(retainedLeaf.toString('hex'), 'd6824f6903f86966ef1ca3508c2c87f358e796be0d8ca46f897569144e74c1bf');
  assert(retainedProvenanceMerkleRoot([retainedRow]).equals(retainedLeaf));

  assert.equal(
    recallMerkleRoot([]).toString('hex'),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
  assert.equal(
    recallMerkleRoot([
      { ordinal: 0, memory_id: 'memory-a', calibrated_score: 0.8 },
      { ordinal: 1, memory_id: 'memory-b', calibrated_score: 0.7 },
    ]).toString('hex'),
    'e352e6aa18fad98652671fe995c7d05dcb4060c27bac8aae6f61939e9325dcb3',
  );
});

test('epistemic classification constructor matches the migration 092 SQL vector', () => {
  assert.equal(
    memoryEpistemicClassificationHash({
      memoryId: baseline.memoryId,
      label: 'poison_likely',
      confidenceMilli: 875,
      liveContentHash: Buffer.alloc(32, 2),
      eventMutationHash: Buffer.alloc(32, 3),
    }).toString('hex'),
    '1a9a95db727c2c829b712d8c98a5ff32b70bf6529ae07fe9ef2736a886d6746c',
  );
});

test('corpus root is deterministic and order-sensitive', () => {
  const records = [{ memory_id: 'a', ok: true }, { memory_id: 'b', ok: false }];
  const root = cognitiveCorpusRoot(records);
  assert(root.equals(cognitiveCorpusRoot(records.map((record) => ({ ...record })))));
  assert(!root.equals(cognitiveCorpusRoot([...records].reverse())));
});

test('pure protocol owner has no runtime, authority, persistence, or I/O dependency', async () => {
  const [protocol, canonical, signer, verifier, provenance, recall, eventLedger] = await Promise.all([
    readFile(new URL('../../services/security/protocol/mutmem-protocol.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/security/protocol/canonical-json.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/security/housekeeper-signer.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/security/cognitive-weight-verifier.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/security/memory-provenance.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/retrieval/native-recall.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/observe/event-ledger.js', import.meta.url), 'utf8'),
  ]);
  const protocolImports = [...protocol.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]);
  const canonicalImports = [...canonical.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]);
  assert.deepEqual(protocolImports, ['node:crypto', './canonical-json.js']);
  assert.deepEqual(canonicalImports, []);
  assert.doesNotMatch(protocol, /process\.env|fetch\(|readFile\(|writeFile\(|query\(/);
  assert.doesNotMatch(canonical, /process\.env|fetch\(|readFile\(|writeFile\(|query\(/);
  assert.doesNotMatch(signer, /function cognitive(?:Baseline|Transition)Hash/);
  assert.doesNotMatch(verifier, /function cognitiveProjectionHash/);
  assert.doesNotMatch(provenance, /function retainedProvenance(?:LeafHash|MerkleRoot)/);
  assert.doesNotMatch(recall, /function recallMerkleRoot/);
  assert.doesNotMatch(eventLedger, /function event(?:Genesis|Mutation)Hash/);
});

test('invalid fixed-width inputs retain stable fail-closed reasons', () => {
  assert.throws(
    () => cognitiveTransitionHash({ ...transition, provenanceMutationHash: Buffer.alloc(31) }),
    /cognitive_transition_identity_malformed/,
  );
  assert.throws(
    () => cognitiveBaselineHash({ ...baseline, observedTs: 0 }),
    /cognitive_baseline_input_malformed/,
  );
  assert.throws(
    () => cognitiveProjectionHash({
      memoryId: transition.memoryId,
      oldWeightMilli: 100,
      newWeightMilli: 3000,
      provenanceMutationHash: Buffer.alloc(31),
    }),
    /cognitive_projection_hash_input_invalid/,
  );
  assert.throws(
    () => eventMutationHash(Buffer.alloc(31), Buffer.alloc(32), 'n', 1),
    /event_prev_hash_invalid/,
  );
  assert.throws(
    () => memoryEpistemicClassificationHash({
      memoryId: baseline.memoryId,
      label: 'supported',
      confidenceMilli: 1001,
      liveContentHash: Buffer.alloc(32),
      eventMutationHash: Buffer.alloc(32),
    }),
    /epistemic_classification_confidence_invalid/,
  );
});
