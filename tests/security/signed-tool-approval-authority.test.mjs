import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  projectToolApprovalHistory,
  toolArgumentsHash,
} from '../../services/orchestration/tool-approval-store.js';

const ROOT = new URL('../../', import.meta.url);

function row({ id, operation, seq, parent = null, metadata = {} }) {
  return {
    id,
    operation,
    key: metadata.tool || 'web_search',
    agent_id: metadata.agent_id || 'auditor',
    ledger_seq: seq,
    parent_event_id: parent,
    metadata: { schema: 'aimos.tool-approval/v1', ...metadata },
    mutation_hash: Buffer.alloc(32, seq),
    ts: new Date(1_783_780_000_000 + seq * 1000),
  };
}

test('tool approval projection is append-only and requires one reserved execution', () => {
  const args = { query: 'signed approval evidence' };
  const rows = [
    row({
      id: 'request', operation: 'tool_approval_requested', seq: 1,
      metadata: { tool: 'web_search', args, args_sha256: toolArgumentsHash(args), agent_id: 'auditor' },
    }),
    row({
      id: 'approve', operation: 'tool_approval_approved', seq: 2, parent: 'request',
      metadata: { approval_request_id: 'request', tool: 'web_search', args_sha256: toolArgumentsHash(args), agent_id: 'auditor' },
    }),
    row({
      id: 'reserve', operation: 'tool_approval_execution_reserved', seq: 3, parent: 'approve',
      metadata: { approval_request_id: 'request', tool: 'web_search', args_sha256: toolArgumentsHash(args), agent_id: 'auditor' },
    }),
  ];

  const projected = projectToolApprovalHistory(rows);
  assert.equal(projected.length, 1);
  assert.equal(projected[0].status, 'executing');
  assert.equal(projected[0].argsHash, toolArgumentsHash(args));
  assert.equal(projected[0].decisionEventId, 'approve');
  assert.equal(projected[0].reservationEventId, 'reserve');

  const completed = projectToolApprovalHistory([
    ...rows,
    row({
      id: 'claim', operation: 'tool_approval_execution_claimed', seq: 4, parent: 'reserve',
      metadata: { approval_request_id: 'request', tool: 'web_search', args_sha256: toolArgumentsHash(args), agent_id: 'auditor' },
    }),
    row({
      id: 'executed', operation: 'tool_approval_executed', seq: 5, parent: 'claim',
      metadata: { approval_request_id: 'request', tool: 'web_search', args_sha256: toolArgumentsHash(args), agent_id: 'auditor', result: { ok: true } },
    }),
  ])[0];
  assert.equal(completed.status, 'executed');
  assert.deepEqual(completed.result, { ok: true });
});

test('tool approval source has no mutable map, TTL deletion, or bare boolean authority', async () => {
  const [store, registry, routes] = await Promise.all([
    readFile(new URL('services/orchestration/tool-approval-store.js', ROOT), 'utf8'),
    readFile(new URL('services/orchestration/tool-registry.js', ROOT), 'utf8'),
    readFile(new URL('routes/tools.js', ROOT), 'utf8'),
  ]);

  assert.doesNotMatch(store, /const\s+approvals\s*=\s*new Map\(|approvals\.(?:set|delete)\(|purgeExpired|DEFAULT_TTL_MS|Math\.random/);
  assert.match(store, /readVerifiedEventHistory/);
  assert.match(store, /tool_approval_execution_reserved/);
  assert.match(store, /tool_approval_execution_claimed/);
  assert.match(registry, /claimToolApprovalExecution/);
  assert.match(registry, /signed_tool_approval_execution_evidence_required/);
  assert.doesNotMatch(registry, /const approved = options\.approved === true/);
  assert.match(routes, /\/approvals', requireCapability\('admin_override'\)/);
  assert.match(routes, /reserveToolApprovalExecution/);
});
