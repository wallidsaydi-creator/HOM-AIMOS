import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createMaterialEffectOwner,
  reconstructMaterialEffectTraces,
} from '../../services/security/material-effect-owner.js';
import { proveCr7R5MaterialEffectAudit } from '../../scripts/verification/prove-cr7-r5-material-effect-audit.mjs';

function harness({ failTerminal = false } = {}) {
  const rows = [];
  let sequence = 0;
  const logEventFn = async (_company, subject, operation, key, metadata, parent) => {
    sequence += 1;
    if (failTerminal && operation === 'material_effect_terminal') throw new Error('terminal_append_failed');
    const eventId = `event-${sequence}`;
    const mutationHash = String(sequence).padStart(64, '0');
    rows.push({ id: eventId, event_id: eventId, agent_id: subject, operation, key, metadata, parent_event_id: parent, mutation_hash: mutationHash });
    return { event_id: eventId, mutation_hash: mutationHash };
  };
  return {
    rows,
    owner: createMaterialEffectOwner({
      logEventFn,
      readEventHistoryFn: async () => rows,
      uuidFn: () => 'action-1',
    }),
  };
}

test('material effect owner commits only hashes and reconstructs one terminal', async () => {
  const { rows, owner } = harness();
  const action = await owner.begin({
    kind: 'external', operation: 'provider_call', targetIdentifier: 'https://example.invalid/path',
    inputProjection: { authorization: 'SECRET', body: 'sensitive input' },
  });
  await owner.finish({ action, disposition: 'SUCCEEDED', resultProjection: { body: 'sensitive output' } });
  const encoded = JSON.stringify(rows);
  assert.doesNotMatch(encoded, /SECRET|sensitive input|sensitive output|example\.invalid/);
  const proof = reconstructMaterialEffectTraces(rows);
  assert.equal(proof.complete.length, 1);
  assert.equal(proof.open.length, 0);
  assert.equal(proof.timeComplexity, 'O(n)');
});

test('terminal append failure leaves one detectable open action without replay', async () => {
  const { rows, owner } = harness({ failTerminal: true });
  const action = await owner.begin({
    kind: 'filesystem', operation: 'artifact_write', targetIdentifier: '/private/path', inputProjection: { bytes: 'x' },
  });
  await assert.rejects(owner.finish({ action, disposition: 'SUCCEEDED', resultProjection: { ok: true } }), /terminal_append_failed/);
  const proof = reconstructMaterialEffectTraces(rows);
  assert.equal(proof.complete.length, 0);
  assert.equal(proof.open.length, 1);
});

test('canonical verified-request authority binds the enrolled actor rather than autonomous Housekeeper', async () => {
  const { rows, owner } = harness();
  await owner.begin({
    kind: 'external',
    operation: 'mcp_call',
    targetIdentifier: 'opaque-mcp-route',
    inputProjection: { method: 'GET' },
    subjectAgentId: 'housekeeper',
    authority: {
      agentId: 'codex-auditor',
      validFromIso: '2026-08-10T18:49:54.000Z',
      requestReceiptId: 'receipt-1',
      requestReceiptMutationHash: 'a'.repeat(64),
    },
  });
  assert.equal(rows[0].agent_id, 'codex-auditor');
});

test('reconstruction rejects terminal substitution and forks', async () => {
  const { rows, owner } = harness();
  const action = await owner.begin({
    kind: 'external', operation: 'network', targetIdentifier: 'opaque', inputProjection: { a: 1 },
  });
  await owner.finish({ action, disposition: 'FAILED', resultProjection: { status: 500 } });
  const substituted = structuredClone(rows);
  substituted[1].metadata.target_sha256 = 'f'.repeat(64);
  assert.throws(() => reconstructMaterialEffectTraces(substituted), /terminal_start_binding_invalid/);
  assert.throws(() => reconstructMaterialEffectTraces([...rows, structuredClone(rows[1])]), /terminal_fork/);
});

test('CR7-R5 audit proves the corrected 68-site partition with zero current open effects', () => {
  const proof = proveCr7R5MaterialEffectAudit();
  assert.equal(proof.frozen_corrected_a0_effect_count, 68);
  assert.equal(proof.current_effect_count, 63);
  assert.equal(proof.retired_effect_count, 5);
  assert.equal(proof.current_open_effect_count, 0);
  assert.equal(proof.reconstruction.time_complexity, 'O(n)');
  assert.equal(proof.reconstruction.terminal_bijection_enforced, true);
  assert.equal(proof.paper_authority.formulas_changed, false);
  assert.equal(proof.purge_executed, false);
  assert.equal(proof.fresh_disposable_installation_deferred, true);
  assert.match(proof.audit_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.proof_root_sha256, /^[0-9a-f]{64}$/);
});
