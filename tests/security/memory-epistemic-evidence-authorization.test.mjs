import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  buildMemoryEpistemicEvidenceAssertion,
  buildMemoryPoisonHypothesis,
} from '../../services/security/memory-epistemic-evidence-assertion.js';
import {
  buildMemoryEpistemicEvidenceAuthorizationBody,
  createMemoryEpistemicEvidenceAuthorization,
  deterministicEvidenceAssertionId,
  verifyMemoryEpistemicEvidenceAuthorization,
} from '../../services/security/memory-epistemic-evidence-authorization.js';
import { generateKeypair, pubkeyFingerprint } from '../../services/security/agent-identity.js';
import { commitMemoryEpistemicEvidenceAssertion } from '../../services/security/memory-epistemic-classifier.js';

const sha = (value) => createHash('sha256').update(String(value), 'utf8').digest('hex');
const master = generateKeypair();
const signer = Object.freeze({
  agent_id: 'housekeeper',
  valid_from: '2026-08-11T11:21:00.000Z',
  cert_fingerprint: sha('housekeeper-certificate'),
  identity_tier: 'T1',
});
const source = Object.freeze({
  event_id: '00000000-0000-4000-8000-000000000901',
  event_content_sha256: sha('classification-event-content'),
  event_mutation_sha256: sha('classification-event-mutation'),
  signer_agent_id: 'housekeeper',
  signer_valid_from: '2026-07-10T16:42:21.000Z',
  signer_cert_fingerprint: sha('historical-housekeeper-certificate'),
  classifier_version: 'aimos-memory-epistemic-v1',
  label: 'poison_likely',
  confidence_milli: 800,
  save_mutation_sha256: sha('save-mutation'),
  binding_mutation_sha256: sha('binding-mutation'),
});
const hypothesis = buildMemoryPoisonHypothesis({
  memoryId: '00000000-0000-4000-8000-000000000902',
  liveContentHash: sha('retained-content'),
});
const assertion = buildMemoryEpistemicEvidenceAssertion({
  assertionId: deterministicEvidenceAssertionId({ hypothesis, source }),
  hypothesis,
  relation: 'supports',
  confidenceMilli: 800,
  rationaleSha256: sha('controlled fixture is deliberately false'),
  assessorIdentitySha256: sha('assessor-identity'),
  evidenceType: 'classification_history',
  evidenceArtifactSha256: source.event_content_sha256,
  evidenceProvenanceSha256: source.event_mutation_sha256,
  sourceIndependence: {
    status: 'dependent',
    basis: 'origin',
    source_identity_sha256: sha('source-identity'),
    independence_group_sha256: sha('source-group'),
    basis_evidence_sha256: sha('basis-evidence'),
  },
});

function approval() {
  const body = buildMemoryEpistemicEvidenceAuthorizationBody({
    companyId: 'hom',
    assertion,
    classificationSource: source,
    masterFingerprint: pubkeyFingerprint(master.pubkey),
    masterEpoch: '2026-07-10T16:42:21.000Z',
    housekeeperSigner: signer,
    reason: 'Authorize one exact append-only evidence assertion and no other state transition or policy effect.',
    signedTs: 1786450000,
  });
  return createMemoryEpistemicEvidenceAuthorization({
    body,
    masterPrivkeyB64u: master.privkey,
    masterPubkeyB64u: master.pubkey,
    nonce: '0123456789abcdef0123456789abcdef',
  });
}

function verification(envelope) {
  return verifyMemoryEpistemicEvidenceAuthorization(envelope, {
    assertion,
    classificationSource: source,
    expectedMasterPubkeyB64u: master.pubkey,
    expectedMasterFingerprint: pubkeyFingerprint(master.pubkey),
    expectedHousekeeperSigner: signer,
  });
}

test('master approval binds one exact dependent supporting assertion and forbids side effects', () => {
  const envelope = approval();
  const verified = verification(envelope);
  assert.equal(verified.valid, true);
  assert.equal(verified.assertion_sha256, assertion.assertion_sha256);
  assert.equal(envelope.body.independence_status, 'dependent');
  for (const field of [
    'classification_transition_authority',
    'save_authority',
    'recall_authority',
    'ranking_authority',
    'deletion_authority',
    'antigen_authority',
    'automatic_policy_activation',
    'housekeeper_discretion',
  ]) assert.equal(envelope.body[field], false);
});

test('approval fails closed under assertion, source, signer, scope, or signature tampering', () => {
  const mutations = [
    (copy) => { copy.body.assertion_sha256 = sha('different-assertion'); },
    (copy) => { copy.body.classification_source.event_mutation_sha256 = sha('different-source'); },
    (copy) => { copy.body.housekeeper_cert_fingerprint = sha('different-housekeeper'); },
    (copy) => { copy.body.ranking_authority = true; },
    (copy) => { copy.sig = Buffer.alloc(64).toString('base64url'); },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(approval());
    mutate(copy);
    assert.equal(verification(copy).valid, false);
  }
});

test('native assertion owner embeds only a verified custody authorization', async () => {
  const rows = [];
  const client = { query: async () => ({ rows: [] }) };
  const listEventsFn = async () => rows;
  const readEventFn = async (id) => rows.find((row) => row.id === id);
  const logEventFn = async (_company, _subject, operation, key, metadata) => {
    rows.push({
      id: '00000000-0000-4000-8000-000000000903',
      operation,
      key,
      metadata,
      parent_event_id: null,
      mutation_hash: Buffer.from(sha('assertion-mutation'), 'hex'),
      ledger_seq: 1,
    });
    return { event_id: rows[0].id, mutation_hash: sha('assertion-mutation') };
  };
  const envelope = approval();
  const result = await commitMemoryEpistemicEvidenceAssertion({
    client,
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    assertion,
    authorizationEvidence: {
      approval: envelope,
      classificationSource: source,
      masterPubkeyB64u: master.pubkey,
      masterFingerprint: pubkeyFingerprint(master.pubkey),
      housekeeperSigner: signer,
    },
  }, { listEventsFn, readEventFn, logEventFn });
  assert.equal(result.appended, true);
  assert.equal(rows[0].metadata.custody_approval.master_approval_sha256,
    envelope.approval_sha256);
  assert.deepEqual(rows[0].metadata.custody_approval.master_approval, envelope);
});
