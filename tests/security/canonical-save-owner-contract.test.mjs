import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  CANONICAL_SAVE_STAGE_ORDER,
  appendCanonicalSaveStage,
  canonicalSaveActionCommitment,
  createCanonicalSaveTrace,
  finalizeCanonicalSaveTrace,
  verifyCanonicalSaveTrace,
} from '../../services/write/canonical-save-contract.js';
import { createCanonicalSaveOwner } from '../../services/write/canonical-save-owner.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const PRODUCTION_ROOTS = ['routes', 'services', 'jobs', 'middleware'];

function walk(relative) {
  const absolute = path.join(ROOT, relative);
  if (!statSync(absolute).isDirectory()) return [relative];
  return readdirSync(absolute, { withFileTypes: true })
    .flatMap((entry) => walk(path.join(relative, entry.name)));
}

function source(relative) {
  return readFileSync(path.join(ROOT, relative), 'utf8');
}

function completeSuccessTrace() {
  const action = canonicalSaveActionCommitment({ schema: 'fixture/v1', key: 'fixture' });
  const trace = createCanonicalSaveTrace(action);
  for (const stage of CANONICAL_SAVE_STAGE_ORDER.slice(0, -1)) {
    appendCanonicalSaveStage(trace, stage, 'PASS', { fixture: stage });
  }
  return finalizeCanonicalSaveTrace(trace, {
    outcome: 'SUCCESS',
    terminalEvidence: { domain_mutation_committed: true, memory_id: 'fixture-memory' },
  });
}

function traceEvidenceKeys(value, out = []) {
  if (Array.isArray(value)) {
    for (const entry of value) traceEvidenceKeys(entry, out);
  } else if (value && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      out.push(key);
      traceEvidenceKeys(entry, out);
    }
  }
  return out;
}

function ownerFixture({ validatorError = null, persistenceError = null, quarantine = false, reassert = false } = {}) {
  const events = [];
  const diagnosticCalls = { rpe: [], screening: 0, encoding: [], transformationRead: 0, transformationWrite: 0 };
  const persistInputs = [];
  const transaction = { commits: 0, rollbacks: 0, client: null, attackerClient: { attacker: true } };
  const client = {
    async query(sql) {
      if (String(sql).includes('clearance_level>=12')) return { rows: [] };
      return { rows: [], rowCount: 0 };
    },
  };
  transaction.client = client;
  const hash = Buffer.alloc(32, 7);
  const persisted = {
    id: '11111111-1111-4111-8111-111111111111',
    memory_tier: 'long-term',
    live_content_hash: hash,
    ledger_commit: { mutationHash: hash, contentHash: hash, isGenesis: true, prevMutationHash: null },
    binding_commit: { mutationHash: Buffer.alloc(32, 8) },
    envelope_commit: null,
    embedding_disposition: { degraded: false, dimension: 768 },
    lineage_disposition: { status: 'NO_OP', reason: 'fixture' },
    graph_disposition: { status: quarantine ? 'QUARANTINE_SKIPPED' : 'NO_OP', reason: 'fixture' },
    epistemic_classification_event_id: '22222222-2222-4222-8222-222222222222',
    epistemic_classification_hash: 'a'.repeat(64),
    epistemic_transition_appended: !reassert,
    epistemic_label: quarantine ? 'poison_suspected' : 'unverified',
    quarantined: quarantine,
    occurrence_reasserted: reassert,
    save_feedback: {},
  };
  const owner = createCanonicalSaveOwner({
    withTransaction: async (fn) => {
      try {
        const result = await fn(client);
        transaction.commits += 1;
        return result;
      } catch (error) {
        transaction.rollbacks += 1;
        throw error;
      }
    },
    logEvent: async (_company, _agent, operation, _key, metadata, parent, options) => {
      const receipt = {
        event_id: `${String(events.length + 1).padStart(8, '0')}-0000-4000-8000-000000000000`,
        mutation_hash: String(events.length + 1).padStart(64, '0'),
      };
      events.push({ operation, metadata, parent, client: options?.client || null, receipt });
      return receipt;
    },
    evaluateCanaryWrite: async () => ({
      detected: quarantine,
      tokens: quarantine ? ['SECRET-DEADBEEF'] : [],
      quarantine,
      reason: quarantine ? 'fixture_canary' : null,
      event_receipt: { event_id: '33333333-3333-4333-8333-333333333333', mutation_hash: 'b'.repeat(64) },
    }),
    evaluateSecurityContent: () => ({
      operation: 'memory_save',
      action: quarantine ? 'retain_quarantine' : 'allow',
      reason: quarantine ? 'fixture_canary' : 'clean',
      severity: quarantine ? 'critical' : 'low',
      quarantine,
      contentHash: 'c'.repeat(64),
      liveSignals: [],
      analysis: { totalWeight: 0, hits: [] },
    }),
    appendSecurityDecision: async () => ({
      event_id: '44444444-4444-4444-8444-444444444444',
      mutation_hash: 'd'.repeat(64),
      signed_body: { operation: 'security_content_decision', metadata: { content_sha256: 'c'.repeat(64), action: quarantine ? 'retain_quarantine' : 'allow' } },
    }),
    enforceVersionOnlyMemoryPolicy: () => ({ status: 'pass' }),
    validateWrite: async () => {
      if (validatorError) throw validatorError;
      return { valid: true, retryable: false, diagnostics: { fixture: true } };
    },
    assessQuality: () => ({ pass: true, score: 1, walls: { form: true, filter: true, substance: true } }),
    computeRPE: async (text) => { diagnosticCalls.rpe.push(text); return { rpe: 0.5, route: 'STANDARD' }; },
    monitorRPEGateQuality: async () => { diagnosticCalls.screening += 1; return { status: 'ok' }; },
    detectEncodingStyle: (value) => { diagnosticCalls.encoding.push(value); return { style: 'narrative_hook', confidence: 1 }; },
    computeSchemaHash: () => 'schema-hash',
    getCachedTransformation: async () => { diagnosticCalls.transformationRead += 1; return { cached: true }; },
    cacheTransformation: async () => { diagnosticCalls.transformationWrite += 1; },
    semanticCache: { invalidate() {} },
    persistMemory: async (input) => {
      persistInputs.push(input);
      assert.equal(input.client, client);
      assert.notEqual(input.client, transaction.attackerClient);
      if (persistenceError) throw persistenceError;
      return persisted;
    },
    recallAuthorizationService: {
      getEffective: async () => ({
        allowed: true,
        writeAllowed: true,
        clearanceCeiling: 10,
        dataClassCeiling: 'confidential',
        mutationHash: Buffer.alloc(32, 9),
      }),
    },
  });
  return { owner, events, transaction, persisted, diagnosticCalls, persistInputs };
}

function internalSpec(overrides = {}) {
  const body = { operation: 'cr5-fixture-save' };
  return {
    company_id: 'hom',
    agent_id: 'fixture-agent',
    key: 'cr4:fixture:save',
    value: 'A substantive canonical SAVE fixture with exact stage ownership and evidence.',
    scope: 'system',
    clearance_level: 5,
    memory_type: 'declarative',
    source: 'cr4-fixture',
    mutation_authority: {
      kind: 'verified_request',
      body,
      agentId: 'fixture-agent',
      validFromIso: '2026-08-27T00:00:00.000Z',
      certString: 'fixture-certificate',
      signedTs: 1787788800,
      nonce: 'fixture-nonce',
      sigBytes: Buffer.alloc(64, 1),
      identityTier: 'T1',
      requestSigForm: 1,
      signedMethod: 'POST',
      signedPath: '/aimos/save',
      signedClaims: null,
      requestReceiptId: '11111111-1111-4111-8111-111111111111',
      requestReceiptMutationHash: '1'.repeat(64),
      requestAdmissionEventId: '22222222-2222-4222-8222-222222222222',
      requestAdmissionMutationHash: '2'.repeat(64),
      companyId: 'hom',
    },
    ...overrides,
  };
}

test('bare or forged Housekeeper authority is rejected before persistence', async () => {
  const fixture = ownerFixture();
  const bare = await fixture.owner(internalSpec({ mutation_authority: 'housekeeper' }));
  assert.equal(bare.rejected, true);
  assert.equal(bare.canonical_save_trace.stages[0].stage, 'AUTH');
  assert.equal(bare.canonical_save_trace.stages[0].status, 'REJECTED');

  const forged = await fixture.owner(internalSpec({
    mutation_authority: {
      kind: 'verified_housekeeper_action',
      actorAgentId: 'housekeeper',
      actorValidFromIso: '2026-08-27T00:00:00.000Z',
      actorIdentityTier: 'T1',
      companyId: 'hom',
      actionEventId: '33333333-3333-4333-8333-333333333333',
      actionMutationHash: '3'.repeat(64),
      actionSha256: '4'.repeat(64),
      actionContextSha256: '5'.repeat(64),
    },
  }));
  assert.equal(forged.rejected, true);
  assert.equal(forged.canonical_save_trace.stages[0].status, 'REJECTED');
  assert.equal(fixture.transaction.commits, 0);
});

test('data class above the exact master-signed grant is rejected before a transaction', async () => {
  const fixture = ownerFixture();
  const result = await fixture.owner(internalSpec({ data_class: 'restricted' }));
  assert.equal(result.rejected, true);
  assert.equal(result.http_status, 403);
  assert.match(result.reason, /data_class_exceeds_verified_authority/);
  assert.equal(result.canonical_save_trace.stages[0].stage, 'AUTH');
  assert.equal(result.canonical_save_trace.stages[0].status, 'REJECTED');
  assert.equal(fixture.transaction.commits, 0);
  assert.equal(fixture.persistInputs.length, 0);
});

test('wrong actor and clearance above the exact grant fail at canonical SAVE authorization', async () => {
  for (const overrides of [
    { agent_id: 'other-agent' },
    { clearance_level: 11 },
  ]) {
    const fixture = ownerFixture();
    const result = await fixture.owner(internalSpec(overrides));
    assert.equal(result.rejected, true);
    assert.equal(result.http_status, 403);
    assert.equal(result.canonical_save_trace.stages[0].stage, 'AUTH');
    assert.equal(result.canonical_save_trace.stages[0].status, 'REJECTED');
    assert.equal(fixture.transaction.commits, 0);
    assert.equal(fixture.persistInputs.length, 0);
  }
});

test('credential-lane plaintext reaches custody persistence but no memory diagnostic consumer', async () => {
  const fixture = ownerFixture();
  const secret = 'sk-live-cr10-credential-boundary-value';
  const result = await fixture.owner(internalSpec({
    key: 'openai_api_key',
    value: secret,
    data_class: 'confidential',
  }));
  assert.equal(result.rejected, undefined);
  assert.equal(result.canonical_save_trace.stages[7].stage, 'SECRET_BOUNDARY');
  assert.equal(result.canonical_save_trace.stages[7].status, 'CREDENTIAL_ISOLATED');
  assert.deepEqual(result.save_diagnostics, {
    rpe: { status: 'SKIPPED_CREDENTIAL_LANE' },
    encoding: { style: null, status: 'SKIPPED_CREDENTIAL_LANE' },
    transformation_cache: { status: 'SKIPPED_CREDENTIAL_LANE' },
    sensible_screening: { status: 'SKIPPED_CREDENTIAL_LANE' },
  });
  assert.deepEqual(fixture.diagnosticCalls, {
    rpe: [], screening: 0, encoding: [], transformationRead: 0, transformationWrite: 0,
  });
  assert.equal(fixture.persistInputs.length, 1);
  assert.equal(fixture.persistInputs[0].value, secret, 'only native custody persistence receives plaintext');
});

test('canonical SAVE trace is fixed-cardinality, ordered, hash-bound, and self-verifying', () => {
  const result = completeSuccessTrace();
  assert.equal(result.stage_count, 15);
  assert.deepEqual(result.stage_order, CANONICAL_SAVE_STAGE_ORDER);
  assert.equal(verifyCanonicalSaveTrace(result).valid, true);

  const tampered = structuredClone(result);
  tampered.stages[7].evidence.redaction_applied = true;
  assert.equal(verifyCanonicalSaveTrace(tampered).valid, false);
});

test('canonical SAVE retains the SE position as an explicit non-authoritative disabled stage', async () => {
  const fixture = ownerFixture();
  const result = await fixture.owner(internalSpec());
  assert.equal(result.canonical_save_trace.stages[3].stage, 'SE');
  assert.equal(result.canonical_save_trace.stages[3].status, 'DISABLED');
  assert.deepEqual(result.canonical_save_trace.stages[3].evidence, {
    runtime_authority: false,
    reason: 'operator_disabled',
  });
  assert.equal(fixture.persistInputs[0].security_disposition, undefined);
  assert.equal(fixture.persistInputs[0].canary_disposition.decision.detected, false);
});

test('stage omission, reordering, and post-rejection relaxation fail closed', () => {
  const action = canonicalSaveActionCommitment({ schema: 'fixture/v1', key: 'negative' });
  const reordered = createCanonicalSaveTrace(action);
  assert.throws(() => appendCanonicalSaveStage(reordered, 'RECEIPT', 'PASS'), /stage_order_invalid/);

  const restricted = createCanonicalSaveTrace(action);
  appendCanonicalSaveStage(restricted, 'AUTH', 'REJECTED', { reason: 'denied' });
  assert.throws(() => appendCanonicalSaveStage(restricted, 'RECEIPT', 'PASS'), /monotonic_restriction/);

  const omitted = createCanonicalSaveTrace(action);
  appendCanonicalSaveStage(omitted, 'AUTH', 'PASS');
  assert.throws(() => finalizeCanonicalSaveTrace(omitted, {
    outcome: 'SUCCESS',
    terminalEvidence: { domain_mutation_committed: true },
  }), /success_stage_incomplete/);
});

test('only the canonical SAVE owner imports persistMemory and only persistence owns direct INSERT', () => {
  const files = PRODUCTION_ROOTS.flatMap(walk)
    .filter((file) => /\.(?:js|mjs|cjs)$/.test(file))
    .sort();
  const importers = files.filter((file) => /(?:from\s*['"][^'"]*persist-memory|import\s*\(\s*['"][^'"]*persist-memory)/.test(source(file)));
  assert.deepEqual(importers, ['services/write/canonical-save-owner.js']);

  const insertOwners = files.filter((file) => /INSERT\s+INTO\s+(?:public\.)?aimos_memories/i.test(source(file)));
  assert.deepEqual(insertOwners, ['services/write/persist-memory.js']);
});

test('REST and both MCP transports delegate without composing their own SAVE security prelude', () => {
  const rest = source('routes/aimos.js');
  const streamable = source('routes/aimos-mcp-streamable.js');
  assert.match(rest, /executeCanonicalSave\(/);
  assert.match(streamable, /executeCanonicalSave\(/);
  const restSave = rest.slice(rest.indexOf("router.post('/save'"), rest.indexOf('// ─── Phase 4: POST /aimos/lineage'));
  assert.doesNotMatch(restSave, /evaluateCanaryWrite|evaluateSecurityContent|appendSecurityDecision|validateWrite|persistMemory/);
  const streamSave = streamable.slice(streamable.indexOf("case 'aimos_save':"), streamable.indexOf('default:', streamable.indexOf("case 'aimos_save':")));
  assert.doesNotMatch(streamSave, /evaluateCanaryWrite|appendSecurityDecision|persistMemory/);
});

test('canonical owner commits success terminal in the same transaction and ignores caller client injection', async () => {
  const fixture = ownerFixture();
  const result = await fixture.owner(internalSpec({ client: fixture.transaction.attackerClient }));
  assert.equal(result.rejected, undefined);
  assert.equal(result.canonical_save_trace.outcome, 'SUCCESS');
  assert.equal(result.canonical_save_trace.stage_count, 15);
  const sanitizerSensitive = /(?:password|passphrase|secret|token|authorization|api[_-]?key|private[_-]?key|credential)/i;
  assert.deepEqual(
    traceEvidenceKeys(result.canonical_save_trace.stages.map((stage) => stage.evidence))
      .filter((key) => sanitizerSensitive.test(key)),
    [],
  );
  assert.equal(fixture.transaction.commits, 1);
  assert.equal(fixture.transaction.rollbacks, 0);
  const terminal = fixture.events.find((event) => event.operation === 'canonical_save_terminal');
  assert.equal(terminal.client, fixture.transaction.client);
  assert.equal(terminal.metadata.outcome, 'SUCCESS');
  assert.equal(terminal.metadata.stages[9].stage, 'PERSISTENCE');
});

test('validator exception fails closed with retained failure terminal and no transaction', async () => {
  const fixture = ownerFixture({ validatorError: new Error('validator offline') });
  const result = await fixture.owner(internalSpec());
  assert.equal(result.rejected, true);
  assert.equal(result.http_status, 503);
  assert.equal(result.canonical_save_trace.outcome, 'FAILED');
  assert.equal(result.canonical_save_trace.stages[5].stage, 'VALIDATOR');
  assert.equal(result.canonical_save_trace.stages[5].status, 'FAILED');
  assert.equal(fixture.transaction.commits, 0);
  assert.equal(fixture.transaction.rollbacks, 0);
});

test('persistence failure rolls back and cannot retain a success terminal', async () => {
  const failure = Object.assign(new Error('database fault'), { code: 'fixture_database_fault' });
  const fixture = ownerFixture({ persistenceError: failure });
  await assert.rejects(fixture.owner(internalSpec()), (error) => {
    assert.equal(error.code, 'fixture_database_fault');
    assert.equal(error.canonicalSaveTrace.outcome, 'FAILED');
    return true;
  });
  assert.equal(fixture.transaction.commits, 0);
  assert.equal(fixture.transaction.rollbacks, 1);
  const terminals = fixture.events.filter((event) => event.operation === 'canonical_save_terminal');
  assert.equal(terminals.length, 1);
  assert.equal(terminals[0].metadata.outcome, 'FAILED');
  assert.equal(terminals[0].client, null);
});

test('quarantine and exact-state reassertion retain complete successful traces', async () => {
  const quarantined = ownerFixture({ quarantine: true });
  const quarantineResult = await quarantined.owner(internalSpec());
  assert.equal(quarantineResult.canonical_save_trace.stages[2].status, 'RETAIN_QUARANTINE');
  assert.equal(quarantineResult.canonical_save_trace.stages[12].status, 'QUARANTINE_SKIPPED');
  assert.equal(quarantineResult.canonical_save_trace.outcome, 'SUCCESS');

  const reasserted = ownerFixture({ reassert: true });
  const reassertResult = await reasserted.owner(internalSpec());
  assert.equal(reassertResult.canonical_save_trace.stages[9].status, 'NO_OP_REASSERT');
  assert.equal(reassertResult.canonical_save_trace.stages[13].status, 'RETAINED_EXISTING');
  assert.equal(reassertResult.canonical_save_trace.stages[13].evidence.classification_hash, 'a'.repeat(64));
  assert.equal(reassertResult.canonical_save_trace.outcome, 'SUCCESS');
});
