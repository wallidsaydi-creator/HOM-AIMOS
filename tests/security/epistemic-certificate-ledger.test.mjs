import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { certifyEpistemicEditRobustness } from '../../services/security/epistemic-edit-certifier.js';
import {
  certifyEpistemicMulticlassEditRobustnessFromPlan,
  generateEpistemicMulticlassDeletionPlan,
} from '../../services/security/epistemic-edit-certificate-multiclass-certifier.js';
import {
  EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS,
  buildEpistemicCertificateCustodyPlan,
  persistEpistemicCertificateEvidence,
  verifyPersistedEpistemicCertificateEvidence,
} from '../../services/security/epistemic-certificate-ledger.js';

const classifierSourceSha256 = createHash('sha256')
  .update(readFileSync(new URL('../../services/security/memory-epistemic-classifier-kernel.js', import.meta.url)))
  .digest('hex');

const memory = Object.freeze({
  id: '00000000-0000-4000-8000-000000000101',
  key: 'ecr:custody:test',
  source: 'synthetic:test',
  memory_type: 'research',
  value: 'Retained evidence remains attributable while bounded edit stability is independently checked.',
  content_hash: 'b'.repeat(64),
});

function certificateFixture() {
  return certifyEpistemicEditRobustness({
    memory,
    peers: [],
    classifierSourceSha256,
    nSelect: 24,
    nCertify: 48,
    nMax: 1,
  });
}

function mockLedger() {
  const rows = [];
  let sequence = 0;
  const logEventFn = async (_company, _subject, operation, key, metadata, parentEventId) => {
    sequence += 1;
    const id = randomUUID();
    const mutationHash = createHash('sha256').update(`${sequence}:${id}`).digest();
    rows.push({
      id,
      operation,
      key,
      metadata: structuredClone(metadata),
      parent_event_id: parentEventId,
      mutation_hash: mutationHash,
      ledger_seq: sequence,
    });
    return { event_id: id, mutation_hash: mutationHash.toString('hex') };
  };
  return {
    rows,
    logEventFn,
    listEventsFn: async (_company, key) => rows.filter((row) => row.key === key),
    readEventFn: async (id) => {
      const row = rows.find((entry) => entry.id === id);
      if (!row) throw new Error('mock_event_not_found');
      return row;
    },
  };
}

test('custody plan chunks transcript evidence below the declared event ceiling', () => {
  const certificate = certificateFixture();
  const plan = buildEpistemicCertificateCustodyPlan({
    ceremonyId: '00000000-0000-4000-8000-000000000201',
    certificate,
    maxChunkBytes: 1_100,
  });
  assert.ok(plan.chunks.length > 2);
  assert.equal(plan.chunk_manifest.length, plan.chunks.length);
  assert.match(plan.evidence_root_sha256, /^[0-9a-f]{64}$/);
  assert.equal(plan.start_metadata.header_json_b64.includes('token_count'), false);
});

test('signed-writer custody is idempotent and portable transcript replay verifies', async () => {
  const certificate = certificateFixture();
  const ledger = mockLedger();
  const args = {
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    ceremonyId: '00000000-0000-4000-8000-000000000202',
    certificate,
    memory,
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
    maxChunkBytes: 1_100,
  };
  const first = await persistEpistemicCertificateEvidence(args, ledger);
  const count = ledger.rows.length;
  const second = await persistEpistemicCertificateEvidence(args, ledger);
  assert.equal(ledger.rows.length, count);
  assert.equal(second.reused, count);
  assert.equal(first.terminal_receipt.event_id, second.terminal_receipt.event_id);
  const verified = await verifyPersistedEpistemicCertificateEvidence({
    companyId: 'hom',
    terminalEventId: first.terminal_receipt.event_id,
    memory,
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
  }, ledger);
  assert.equal(verified.valid, true);
  assert.equal(verified.certificate.certificate_sha256, certificate.certificate_sha256);
});

test('resume appends only missing chunks and the terminal event', async () => {
  const certificate = certificateFixture();
  const ledger = mockLedger();
  let calls = 0;
  const interrupted = {
    ...ledger,
    logEventFn: async (...args) => {
      calls += 1;
      if (calls === 3) throw new Error('simulated_crash');
      return ledger.logEventFn(...args);
    },
  };
  const args = {
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    ceremonyId: '00000000-0000-4000-8000-000000000203',
    certificate,
    memory,
    expectedClassifierSourceSha256: classifierSourceSha256,
    maxChunkBytes: 1_100,
  };
  await assert.rejects(() => persistEpistemicCertificateEvidence(args, interrupted), /simulated_crash/);
  const retained = ledger.rows.length;
  const resumed = await persistEpistemicCertificateEvidence(args, ledger);
  assert.equal(resumed.reused, retained);
  assert.equal(ledger.rows.filter((row) => row.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.STARTED).length, 1);
  assert.equal(ledger.rows.filter((row) => row.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.COMPLETED).length, 1);
});

test('tampered transcript and duplicate chunk fail closed', async () => {
  const certificate = certificateFixture();
  const ledger = mockLedger();
  const args = {
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    ceremonyId: '00000000-0000-4000-8000-000000000204',
    certificate,
    memory,
    expectedClassifierSourceSha256: classifierSourceSha256,
    maxChunkBytes: 1_100,
  };
  const persisted = await persistEpistemicCertificateEvidence(args, ledger);
  const chunk = ledger.rows.find((row) => row.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.TRANSCRIPT_CHUNK);
  const original = chunk.metadata.rows_json_b64;
  chunk.metadata.rows_json_b64 = Buffer.from('[{"bitmap":"","output":"U"}]').toString('base64');
  await assert.rejects(() => verifyPersistedEpistemicCertificateEvidence({
    companyId: 'hom',
    terminalEventId: persisted.terminal_receipt.event_id,
    memory,
    expectedClassifierSourceSha256: classifierSourceSha256,
  }, ledger), /chunk_rows_hash_mismatch/);
  chunk.metadata.rows_json_b64 = original;
  ledger.rows.push({ ...structuredClone(chunk), id: randomUUID(), mutation_hash: Buffer.alloc(32, 7) });
  await assert.rejects(() => persistEpistemicCertificateEvidence(args, ledger), /chunk_fork_detected/);
});

test('signed custody preserves and replays the exact seven-state certificate schema', async () => {
  const ledger = mockLedger();
  const signedLabel = 'poison_likely';
  const baseDecisionSha256 = 'd'.repeat(64);
  const parameters = {
    memory,
    peers: [],
    classifierSourceSha256,
    signedLabel,
    baseDecisionSha256,
    pDel: { numerator: 3, denominator: 5 },
    nSelect: 20,
    nCertify: 40,
    nMax: 100,
  };
  const deletionPlan = generateEpistemicMulticlassDeletionPlan(parameters);
  const certificate = certifyEpistemicMulticlassEditRobustnessFromPlan({
    ...parameters,
    deletionPlan,
  });
  const persisted = await persistEpistemicCertificateEvidence({
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    ceremonyId: '00000000-0000-4000-8000-000000000205',
    certificate,
    memory,
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
    expectedSignedLabel: signedLabel,
    expectedBaseDecisionSha256: baseDecisionSha256,
    maxChunkBytes: 1_100,
  }, ledger);
  const verified = await verifyPersistedEpistemicCertificateEvidence({
    companyId: 'hom',
    terminalEventId: persisted.terminal_receipt.event_id,
    memory,
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
    expectedSignedLabel: signedLabel,
    expectedBaseDecisionSha256: baseDecisionSha256,
  }, ledger);
  assert.equal(verified.valid, true);
  assert.equal(verified.certificate.schema, 'aimos.epistemic-multiclass-edit-certificate/v1');
  assert.equal(verified.certificate.deletion_plan_sha256, deletionPlan.plan_sha256);
  assert.equal(verified.portable_verification.effective_label, signedLabel);
  assert.equal(verified.portable_verification.persistent_transition_authorized, false);
  assert.equal(verified.portable_verification.automatic_policy_activation, false);
});
