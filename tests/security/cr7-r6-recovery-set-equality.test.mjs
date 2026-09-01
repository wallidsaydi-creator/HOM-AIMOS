import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { createMaterialEffectOwner, reconstructMaterialEffectTraces } from '../../services/security/material-effect-owner.js';
import { reconcileOpenToolActions, reconstructToolActionTraces } from '../../services/orchestration/tool-action-ledger.js';
import { reconcileCredentialUseReservations } from '../../services/security/credential-ledger.js';
import { reconcileOpenCanonicalSaveActionsWithDeps, reconstructCanonicalSaveActionTraces } from '../../services/write/canonical-save-contract.js';
import { reconcileOpenRuns, reconstructRunTraces } from '../../services/orchestration/run-metadata.js';
import { proveCr7R6RecoverySetEquality, verifyCommittedTerminalBijection } from '../../scripts/verification/prove-cr7-r6-recovery-set-equality.mjs';
import { agentPool, pool } from '../../db/connection.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
test.after(async () => {
  await agentPool.end();
  await pool.end();
});
function event({ id, operation, key, metadata, parent = null, mutation = HASH_A, agent = 'housekeeper' }) {
  return { id, event_id: id, company_id: 'hom', agent_id: agent, operation, key, metadata, parent_event_id: parent, mutation_hash: mutation };
}

test('material effects reconcile once after restart without replay and remain permutation-stable', async () => {
  const rows = [event({
    id: 'material-start', operation: 'material_effect_started', key: 'material-action',
    metadata: { schema: 'hom.aimos.material-effect/v1', action_id: 'material-action', effect_kind: 'external', effect_operation: 'provider_call', target_sha256: HASH_A, input_sha256: HASH_B },
  })];
  const logEventFn = async (_company, agent, operation, key, metadata, parent) => {
    if (rows.some((row) => row.operation === operation && row.key === key)) throw new Error('event_operation_key_exists');
    const row = event({ id: 'material-terminal', operation, key, metadata, parent, mutation: 'c'.repeat(64), agent });
    rows.push(row);
    return { event_id: row.id, mutation_hash: row.mutation_hash };
  };
  const owner = createMaterialEffectOwner({ logEventFn, readEventHistoryFn: async () => rows });
  const first = await owner.reconcileOpen();
  const second = await owner.reconcileOpen();
  assert.equal(first.reconciled.length, 1);
  assert.equal(first.remainingOpen, 0);
  assert.equal(first.externalEffectsReplayed, 0);
  assert.equal(second.reconciled.length, 0);
  assert.equal(reconstructMaterialEffectTraces([...rows].reverse()).complete.length, 1);
  assert.throws(() => reconstructMaterialEffectTraces([...rows, structuredClone(rows[1])]), /terminal_fork/);
  const substituted = structuredClone(rows);
  substituted[1].metadata.start_mutation_hash = '0'.repeat(64);
  assert.throws(() => reconstructMaterialEffectTraces(substituted), /start_binding_invalid/);
});

test('tool actions reconcile once without invoking the tool', async () => {
  const rows = [event({
    id: 'tool-start', operation: 'tool_execution_started', key: 'web_search', agent: 'codex-auditor',
    metadata: { schema: 'aimos.tool-action/v1', tool: 'web_search', args_sha256: HASH_A, runtime_agent_id: 'codex-auditor', actor_agent_id: 'codex-auditor', actor_valid_from: '2026-08-10T18:49:54.000Z', actor_identity_tier: 'T1' },
  })];
  let invocations = 0;
  const finishFn = async ({ action, disposition }) => {
    assert.equal(disposition, 'INDETERMINATE');
    rows.push(event({
      id: 'tool-terminal', operation: 'tool_execution_indeterminate', key: action.receipt.event_id,
      parent: action.receipt.event_id, agent: 'codex-auditor', mutation: HASH_B,
      metadata: { schema: 'aimos.tool-action/v1', tool_action_event_id: action.receipt.event_id, tool: action.authority.tool, args_sha256: action.authority.argsHash, disposition },
    }));
    return { event_id: 'tool-terminal', mutation_hash: HASH_B };
  };
  const first = await reconcileOpenToolActions({ rows, finishFn });
  const second = await reconcileOpenToolActions({ rows, finishFn });
  assert.equal(first.reconciled.length, 1);
  assert.equal(first.toolInvocationsReplayed, invocations);
  assert.equal(second.reconciled.length, 0);
  assert.equal(reconstructToolActionTraces([...rows].reverse()).complete.length, 1);
  assert.throws(() => reconstructToolActionTraces([...rows, structuredClone(rows[1])]), /terminal_fork/);
  const substituted = structuredClone(rows);
  substituted[1].parent_event_id = 'wrong-start';
  assert.throws(() => reconstructToolActionTraces(substituted), /start_binding_invalid/);
});

test('credential-use recovery appends indeterminate only and is an exact second-pass no-op', async () => {
  let open = [{
    useId: 'credential-use-1', useGroupId: null, serviceName: 'example', slotId: 'slot',
    credentialHash: HASH_A, subjectAgentId: 'housekeeper', reservationProvenanceId: 'reservation-1',
    reservationMutationHash: HASH_B,
  }];
  const calls = [];
  const finalizeFn = async (input) => {
    calls.push(input);
    open = [];
    return { disposition: 'INDETERMINATE' };
  };
  const first = await reconcileCredentialUseReservations(open, { finalizeFn, reloadFn: async () => open });
  const second = await reconcileCredentialUseReservations(open, { finalizeFn, reloadFn: async () => open });
  assert.equal(calls[0].outcome, 'indeterminate');
  assert.equal(first.externalEffectsReplayed, 0);
  assert.equal(first.remainingOpen, 0);
  assert.equal(second.reconciled.length, 0);
});

test('autonomous SAVE orphan recovery closes the action without repeating SAVE or fabricating memory', async () => {
  const rows = [event({
    id: 'save-start', operation: 'canonical_save_action_started', key: 'session:key',
    metadata: { schema: 'hom.aimos.canonical-save-action-start/v2', action_sha256: HASH_A, action_context_sha256: HASH_B, source: 'test', memory_type: 'event_log' },
  })];
  const logEventFn = async (_company, agent, operation, key, metadata, parent) => {
    if (rows.some((row) => row.operation === operation && row.key === key)) throw new Error('event_operation_key_exists');
    const row = event({ id: 'save-recovery-terminal', operation, key, metadata, parent, mutation: 'c'.repeat(64), agent });
    rows.push(row);
    return { event_id: row.id, mutation_hash: row.mutation_hash };
  };
  const first = await reconcileOpenCanonicalSaveActionsWithDeps({
    companyId: 'hom', events: rows, logEventFn, readHistoryFn: async () => rows,
  });
  const second = await reconcileOpenCanonicalSaveActionsWithDeps({
    companyId: 'hom', events: rows, logEventFn, readHistoryFn: async () => rows,
  });
  assert.equal(first.savesReplayed, 0);
  assert.equal(first.memoriesFabricated, 0);
  assert.equal(first.remainingOpen, 0);
  assert.equal(second.reconciled.length, 0);
  assert.equal(reconstructCanonicalSaveActionTraces([...rows].reverse()).complete.length, 1);
  assert.throws(() => reconstructCanonicalSaveActionTraces([...rows, structuredClone(rows[1])]), /terminal_fork/);
  const substituted = structuredClone(rows);
  substituted[1].metadata.action_sha256 = '0'.repeat(64);
  assert.throws(() => reconstructCanonicalSaveActionTraces(substituted), /recovery_binding_invalid/);
});

test('agent-run recovery retains an indeterminate terminal without publishing a response', async () => {
  const rows = [event({
    id: 'run-start', operation: 'agent_run_started', key: 'run-1', agent: 'codex-auditor',
    metadata: { schema: 'hom.aimos.agent-run-state/v1', run_id: 'run-1', company_id: 'hom', source_agent_id: 'codex-auditor', resolved_agent_id: 'codex-auditor', status: 'running' },
  })];
  const appendFn = async ({ operation, runId, projection, agentId }) => {
    const start = rows[0];
    rows.push(event({
      id: 'run-terminal', operation, key: runId, parent: start.id, agent: agentId, mutation: HASH_B,
      metadata: { schema: 'hom.aimos.agent-run-state/v1', ...projection, start_event_id: start.id, start_mutation_hash: start.mutation_hash },
    }));
    return { event_id: 'run-terminal', mutation_hash: HASH_B };
  };
  const first = await reconcileOpenRuns({ events: rows, appendFn });
  const second = await reconcileOpenRuns({ events: rows, appendFn });
  assert.equal(first.runsReplayed, 0);
  assert.equal(first.responsesPublished, 0);
  assert.equal(first.remainingOpen, 0);
  assert.equal(second.reconciled.length, 0);
  assert.equal(reconstructRunTraces([...rows].reverse()).complete.length, 1);
  assert.throws(() => reconstructRunTraces([...rows, structuredClone(rows[1])]), /terminal_fork/);
  const substituted = structuredClone(rows);
  substituted[1].parent_event_id = 'wrong-start';
  assert.throws(() => reconstructRunTraces(substituted), /start_binding_invalid/);
});

test('session-lane recovery closes the dead process mutex without replaying its callback', async () => {
  const moduleUrl = pathToFileURL(path.join(ROOT, 'services/orchestration/session-runner.js')).href;
  const script = `
    const { reconcileOpenSessionLanes, reconstructSessionLaneTraces } = await import(${JSON.stringify(moduleUrl)});
    const H='b'.repeat(64); const rows=[{id:'lane-start',event_id:'lane-start',company_id:'hom',agent_id:'codex-auditor',operation:'session_lane_started',key:'session-1:run-1',parent_event_id:null,mutation_hash:'a'.repeat(64),metadata:{schema:'hom.aimos.session-lane-transition/v1',company_id:'hom',session_key:'session-1',run_id:'run-1',agent_id:'codex-auditor',model:'codex',status:'running'}}];
    const terminalFn=async(input)=>{rows.push({id:'lane-terminal',event_id:'lane-terminal',company_id:'hom',agent_id:input.agentId,operation:'session_lane_terminal',key:input.sessionKey+':'+input.runId,parent_event_id:input.startEventId,mutation_hash:H,metadata:{schema:'hom.aimos.session-lane-transition/v1',company_id:'hom',session_key:input.sessionKey,run_id:input.runId,start_event_id:input.startEventId,start_mutation_hash:input.startMutationHash,disposition:input.disposition}});return {event_id:'lane-terminal',mutation_hash:H};};
    const first=await reconcileOpenSessionLanes({events:rows,terminalFn}); const second=await reconcileOpenSessionLanes({events:rows,terminalFn}); const permutation=reconstructSessionLaneTraces([...rows].reverse()); let forkDenied=false;try{reconstructSessionLaneTraces([...rows,structuredClone(rows[1])]);}catch(e){forkDenied=/terminal_fork/.test(e.message);}let bindingDenied=false;const substituted=structuredClone(rows);substituted[1].parent_event_id='wrong-start';try{reconstructSessionLaneTraces(substituted);}catch(e){bindingDenied=/start_binding_invalid/.test(e.message);}
    process.stdout.write(JSON.stringify({first,second,complete:permutation.complete.length,forkDenied,bindingDenied})); process.exit(0);
  `;
  const result = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', script], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 10_000,
  }));
  assert.equal(result.first.sessionCallbacksReplayed, 0);
  assert.equal(result.first.remainingOpen, 0);
  assert.equal(result.second.reconciled.length, 0);
  assert.equal(result.complete, 1);
  assert.equal(result.forkDenied, true);
  assert.equal(result.bindingDenied, true);
});

test('committed material effects and success terminals have exact linear-time set equality', () => {
  const bindings = [HASH_A, HASH_B];
  const proof = verifyCommittedTerminalBijection({
    committedEffects: bindings.map((binding) => ({ binding })),
    successTerminals: [...bindings].reverse().map((binding) => ({ binding })),
  });
  assert.equal(proof.exactSetEquality, true);
  assert.equal(proof.uniqueBinding, true);
  assert.equal(proof.timeComplexity, 'O(n)');
  assert.throws(() => verifyCommittedTerminalBijection({ committedEffects: [{ binding: HASH_A }], successTerminals: [] }), /set_equality/);
  assert.throws(() => verifyCommittedTerminalBijection({ committedEffects: [{ binding: HASH_A }], successTerminals: [{ binding: HASH_A }, { binding: HASH_A }] }), /duplicate/);
});

test('independent R6 audit freezes six recovery owners and eight failure modes', () => {
  const proof = proveCr7R6RecoverySetEquality();
  assert.equal(proof.recovery_family_count, 6);
  assert.equal(proof.failure_matrix.length, 8);
  assert.equal(proof.reconstruction.exactSetEquality, true);
  assert.equal(proof.second_pass_exact_noop_required, true);
  assert.equal(proof.boot_recovery_precedes_listen, true);
  assert.equal(proof.recovery_event_limit, 100_000);
  assert.equal(proof.credential_slot_limit, 10_000);
  assert.equal(proof.provider_calls_executed, 0);
  assert.equal(proof.live_database_mutations_executed, 0);
  assert.equal(proof.paper_authority.formulas_changed, false);
  const timeout = proof.failure_matrix.find((entry) => entry.case === 'timeout');
  assert.deepEqual(timeout, {
    case: 'timeout',
    terminal: 'INDETERMINATE',
    success_allowed: false,
  }, 'timeout is fault-contained by an explicit non-success terminal');
  assert.match(proof.source_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.audit_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.proof_root_sha256, /^[0-9a-f]{64}$/);
});

test('server boot verifies one shared event snapshot before conditional family recovery', () => {
  const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  const start = server.indexOf('async function reconcileCr7OpenActionsAtBoot()');
  const end = server.indexOf('\nasync function startServer()', start);
  const owner = server.slice(start, end);
  assert.equal((owner.match(/readVerifiedEventHistory\(/g) || []).length, 1);
  for (const reducer of [
    'reconstructMaterialEffectTraces(events)',
    'reconstructToolActionTraces(events)',
    'reconstructCanonicalSaveActionTraces(events)',
    'reconstructRunTraces(events)',
    'reconstructSessionLaneTraces(events)',
  ]) assert.match(owner, new RegExp(reducer.replace(/[()]/g, '\\$&')));
  assert.match(owner, /openCredentialUses\.length/);
});
