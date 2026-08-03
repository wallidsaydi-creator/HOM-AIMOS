import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  canonicalJson,
  generateKeypair,
  issueCert,
  pubkeyFingerprint,
  signPayload,
} from '../../services/security/agent-identity.js';
import { contentHash } from '../../services/security/identity-chain.js';
import {
  retainedProvenanceMerkleRoot,
  verifyRetainedMutationNode,
} from '../../services/security/memory-provenance.js';
import {
  lineageMutationHash,
  verifyHousekeeperSupersessionLineage,
} from '../../services/security/memory-lineage.js';

const root = new URL('../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');

function provenanceRow(overrides = {}) {
  const nonce = 'retained-node-nonce';
  const ts = 1_783_764_000;
  const content = createHash('sha256').update('retained-content').digest();
  return {
    provenance_id: randomUUID(),
    memory_id: randomUUID(),
    provenance_agent_id: 'legacy-agent',
    agent_valid_from: new Date(1_783_763_000 * 1000).toISOString(),
    cert_fingerprint: 'a'.repeat(64),
    prov_content_hash: content,
    mutation_hash: createHash('sha256').update(Buffer.concat([
      content,
      Buffer.from(nonce),
      Buffer.from(String(ts)),
    ])).digest(),
    prev_mutation_hash: null,
    ts_signed: ts,
    nonce,
    sig: Buffer.alloc(64, 7),
    identity_tier: 'T1',
    is_genesis: true,
    backfilled: false,
    memory_originated_at: null,
    legacy_envelope_sig: null,
    provenance_created_at: new Date(ts * 1000).toISOString(),
    event_type: 'SAVE',
    body_json: null,
    sig_form_version: 1,
    snapshot_live_content_hash: Buffer.alloc(32, 3),
    request_sig_form: 1,
    signed_method: null,
    signed_path: null,
    signed_claims: null,
    binding_schema_version: 1,
    ...overrides,
  };
}

test('retained checkpoint commits signature and certificate metadata without promoting origin proof', () => {
  const row = provenanceRow();
  assert.equal(verifyRetainedMutationNode(row).valid, true);
  assert.equal(verifyRetainedMutationNode({ ...row, mutation_hash: Buffer.alloc(32) }).valid, false);

  const rootBefore = retainedProvenanceMerkleRoot([row]);
  const signatureTamper = retainedProvenanceMerkleRoot([{ ...row, sig: Buffer.alloc(64, 8) }]);
  const certificateTamper = retainedProvenanceMerkleRoot([{ ...row, cert_fingerprint: 'b'.repeat(64) }]);
  assert.notDeepEqual(signatureTamper, rootBefore);
  assert.notDeepEqual(certificateTamper, rootBefore);
});

test('D2 supersession lineage verifies exact signed edge and fails on tampering', () => {
  const master = generateKeypair();
  const signer = generateKeypair();
  const validFrom = 1_783_763_000;
  const validUntil = 1_783_773_000;
  const masterFingerprint = pubkeyFingerprint(master.pubkey);
  const cert = issueCert(master.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: 'device-lineage',
    valid_from: validFrom,
    valid_until: validUntil,
    issuer: masterFingerprint,
    issued_at: validFrom,
  });
  const childId = randomUUID();
  const parentId = randomUUID();
  const childHash = Buffer.alloc(32, 1);
  const parentHash = Buffer.alloc(32, 2);
  const metadata = { relation: 'supersedes' };
  const metadataHash = createHash('sha256').update(canonicalJson(metadata)).digest('hex');
  const body = {
    event_type: 'LINEAGE',
    binding_schema_version: 2,
    company_id: 'hom',
    key: 'signed:lineage',
    child_id: childId,
    parent_ids: [parentId],
    derivation_type: 'supersede',
    supersession_event_id: 7,
    trigger_type: 'update',
    supersession_metadata_sha256: metadataHash,
    child_live_content_hash: childHash.toString('hex'),
    parent_live_content_hash: parentHash.toString('hex'),
    attestation_reason: 'native_save_commit',
    historical_origin_authority_claimed: true,
  };
  const nonce = 'signed-lineage-nonce';
  const tsSigned = 1_783_764_000;
  const cHash = contentHash(body);
  const mutation = lineageMutationHash(cHash, null, nonce, tsSigned);
  const row = {
    body_json: body,
    attestation_tier: 'D2',
    binding_schema_version: 2,
    content_hash: cHash,
    mutation_hash: mutation,
    prev_mutation_hash: null,
    is_genesis: true,
    nonce,
    ts_signed: tsSigned,
    sig: Buffer.from(signPayload(signer.privkey, body, nonce, tsSigned), 'base64url'),
    attesting_agent_id: 'housekeeper',
    attesting_agent_valid_from: new Date(validFrom * 1000).toISOString(),
    attesting_cert_fingerprint: createHash('sha256').update(cert).digest('hex'),
    signer_pubkey: signer.pubkey,
    signer_cert: cert,
    master_pubkey: master.pubkey,
    master_fingerprint: masterFingerprint,
    company_id: 'hom',
    key: body.key,
    child_id: childId,
    parent_id: parentId,
    derivation_type: 'supersede',
    supersession_event_id: 7,
    trigger_type: 'update',
    supersession_metadata: metadata,
    child_live_content_hash: childHash,
    parent_live_content_hash: parentHash,
  };

  assert.equal(verifyHousekeeperSupersessionLineage(row).valid, true);
  assert.equal(
    verifyHousekeeperSupersessionLineage({ ...row, supersession_metadata: { relation: 'tampered' } }).valid,
    false,
  );
  assert.equal(
    verifyHousekeeperSupersessionLineage({ ...row, parent_live_content_hash: Buffer.alloc(32, 9) }).valid,
    false,
  );
});

test('retained ceremony is explicit, append-only, and uses native D2 lineage', () => {
  const ceremony = read('scripts/ceremony/attest-orphaned-memories.mjs');
  const persistence = read('services/write/persist-memory.js');
  const migration = read('migrations/090-signed-supersession-lineage.sql');

  assert.match(ceremony, /event_type: 'RETAINED_ATTEST'/);
  assert.match(ceremony, /historical_origin_signature_claimed: false/);
  assert.doesNotMatch(ceremony, /UPDATE\s+aimos_memories|DELETE\s+FROM\s+aimos_memories/i);
  assert.match(ceremony, /commitHousekeeperSupersession/);
  assert.match(persistence, /lineage_mutation_hash/);
  assert.match(migration, /ON DELETE RESTRICT/);
  assert.match(migration, /REVOKE UPDATE, DELETE, TRUNCATE/);
});
