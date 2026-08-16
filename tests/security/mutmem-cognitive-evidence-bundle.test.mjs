import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  COGNITIVE_EVIDENCE_SCHEMA,
  createCognitiveWeightEvidenceBundle,
  verifyCognitiveWeightEvidenceBundle,
} from '../../services/security/protocol/cognitive-weight-evidence.js';
import {
  canonicalJson,
  generateKeypair,
  issueCert,
  pubkeyFingerprint,
  signPayload,
} from '../../services/security/agent-identity.js';
import {
  eventGenesisHash,
  eventMutationHash,
} from '../../services/security/protocol/mutmem-protocol.js';

function masterIdentity() {
  const { publicKey } = generateKeyPairSync('ed25519');
  const masterPubkey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    master_pubkey: masterPubkey,
    master_fingerprint: createHash('sha256')
      .update(Buffer.from(masterPubkey, 'base64url'))
      .digest('hex'),
  };
}

function defaultBundle() {
  return createCognitiveWeightEvidenceBundle({
    companyId: 'hom',
    masterIdentity: masterIdentity(),
    memories: [{
      id: '11111111-1111-4111-8111-111111111111',
      company_id: 'hom',
      content_hash: Buffer.alloc(32, 7),
      retrieval_weight: 1,
    }],
    sqlRows: [{
      memory_id: '11111111-1111-4111-8111-111111111111',
      certification_status: 'default_empty_chain',
      ok: true,
      chain_length: 0,
      sigs_verified: 0,
      reason: null,
    }],
  });
}

function housekeeperEventBundle(issuer, { selfSigned = false } = {}) {
  const master = generateKeypair();
  const signer = generateKeypair();
  const masterFingerprint = pubkeyFingerprint(master.pubkey);
  const certificateIssuer = issuer === 'legacy-master-fingerprint'
    ? masterFingerprint
    : issuer;
  const validFrom = 1_786_447_260;
  const validUntil = 253_402_300_799;
  const signedAt = validFrom + 60;
  const cert = issueCert(selfSigned ? signer.privkey : master.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: 'housekeeper-device',
    valid_from: validFrom,
    valid_until: validUntil,
    issuer: certificateIssuer,
    issued_at: validFrom,
  });
  const validFromIso = new Date(validFrom * 1000).toISOString();
  const certFingerprint = createHash('sha256').update(cert, 'utf8').digest('hex');
  const previous = eventGenesisHash('hom', 'housekeeper', validFromIso);
  const eventId = randomUUID();
  const nonce = 'housekeeper-issuer-conformance';
  const body = {
    event_id: eventId,
    company_id: 'hom',
    subject_agent_id: 'housekeeper',
    signer_agent_id: 'housekeeper',
    signer_valid_from: validFromIso,
    cert_fingerprint: certFingerprint,
    identity_tier: selfSigned ? 'T1_SYSTEM_SELF' : 'T1',
    authority_kind: 'system',
    operation: 'housekeeper_issuer_conformance_test',
    key: 'housekeeper:issuer',
    metadata: {},
    parent_event_id: null,
    ledger_seq: 1,
    prev_mutation_hash: previous.toString('hex'),
    ts_signed: signedAt,
  };
  const contentHash = createHash('sha256').update(canonicalJson(body), 'utf8').digest();
  const mutationHash = eventMutationHash(previous, contentHash, nonce, signedAt);
  const signature = signPayload(signer.privkey, body, nonce, signedAt);
  return createCognitiveWeightEvidenceBundle({
    companyId: 'hom',
    masterIdentity: {
      master_pubkey: master.pubkey,
      master_fingerprint: masterFingerprint,
    },
    events: [{
      id: eventId,
      company_id: 'hom',
      agent_id: 'housekeeper',
      signer_agent_id: 'housekeeper',
      signer_valid_from: validFromIso,
      cert_fingerprint: certFingerprint,
      identity_tier: body.identity_tier,
      authority_kind: body.authority_kind,
      operation: body.operation,
      key: body.key,
      metadata: body.metadata,
      parent_event_id: null,
      ledger_seq: 1,
      prev_mutation_hash: previous,
      content_hash: contentHash,
      mutation_hash: mutationHash,
      ts_signed: signedAt,
      nonce,
      sig: Buffer.from(signature, 'base64url'),
      proof_required: true,
      ledger_version: 1,
      signed_body: body,
      pubkey: signer.pubkey,
      cert,
      device_fp: 'housekeeper-device',
      valid_until: new Date(validUntil * 1000).toISOString(),
    }],
  });
}

test('V2-S3 bundle survives a JSON round trip and verifies without runtime authority', () => {
  const bundle = JSON.parse(JSON.stringify(defaultBundle()));
  assert.equal(bundle.format.schema, COGNITIVE_EVIDENCE_SCHEMA);
  assert.equal(bundle.format.authority, 'descriptive_only');
  const proof = verifyCognitiveWeightEvidenceBundle(bundle);
  assert.equal(proof.records.length, 1);
  assert.equal(proof.records[0].certification_status, 'default_empty_chain');
  assert.equal(proof.records[0].ok, true);
  assert.equal(proof.parity, true);
  assert.equal(proof.proofRoot.length, 32);
  assert.equal(proof.bundleSha256.length, 32);
});

test('V2-S3 verifier fails closed when a memory weight is changed after export', () => {
  const bundle = defaultBundle();
  bundle.memories[0].retrieval_weight_float4 = '3f000000';
  assert.throws(
    () => verifyCognitiveWeightEvidenceBundle(bundle),
    /cognitive_evidence_memory_weight_invalid/,
  );
});

test('V2-S3A accepts the canonical symbolic master issuer and retained legacy fingerprint issuer', () => {
  for (const issuer of ['aimos-master', 'legacy-master-fingerprint']) {
    const proof = verifyCognitiveWeightEvidenceBundle(housekeeperEventBundle(issuer));
    assert.equal(proof.eventStreamResults[0].valid, true);
  }
});

test('V2-S3A accepts self-signed genesis but rejects an unknown master-signed issuer', () => {
  const selfSigned = verifyCognitiveWeightEvidenceBundle(
    housekeeperEventBundle('housekeeper', { selfSigned: true }),
  );
  assert.equal(selfSigned.eventStreamResults[0].valid, true);

  const unknown = verifyCognitiveWeightEvidenceBundle(housekeeperEventBundle('unexpected-root'));
  assert.equal(unknown.eventStreamResults[0].valid, false);
  assert.equal(unknown.eventStreamResults[0].reason, 'cognitive_evidence_event_identity_epoch_invalid');
});

test('V2-S3A binds the retained master fingerprint to the retained master public key', () => {
  const bundle = housekeeperEventBundle('aimos-master');
  bundle.master_identity.fingerprint = '0'.repeat(64);
  assert.throws(
    () => verifyCognitiveWeightEvidenceBundle(bundle),
    /cognitive_evidence_master_fingerprint_mismatch/,
  );
});

test('V2-S3 pure verifier dependency boundary excludes persistence and authority owners', async () => {
  const [pureVerifier, reader] = await Promise.all([
    readFile(new URL('../../services/security/protocol/cognitive-weight-evidence.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/security/cognitive-weight-verifier.js', import.meta.url), 'utf8'),
  ]);
  const imports = [...pureVerifier.matchAll(/from\s+['"]([^'"]+)['"]/g)]
    .map((match) => match[1]);
  assert.deepEqual(imports, [
    'node:crypto',
    './canonical-json.js',
    './mutmem-protocol.js',
  ]);
  assert.doesNotMatch(
    pureVerifier,
    /process\.env|\.\.\/\.\.\/db\/|fetch\(|readFile\(|writeFile\(|\.query\(|signPayload|load.*Privkey/,
  );
  assert.match(reader, /readCognitiveWeightEvidenceBundle/);
  assert.match(reader, /BEGIN READ ONLY/);
  assert.doesNotMatch(
    reader,
    /agent-identity|memory-provenance|event-ledger|housekeeper-signer|signPayload|load.*Privkey/,
  );
});
