import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  createMaterialEffectOwner,
  reconstructMaterialEffectTraces,
} from '../../services/security/material-effect-owner.js';
import {
  createLocalFileWriteOrphanReconciler,
  localFileWriteInputProjection,
  writeAllowedLocalFile,
} from '../../services/security/purpose-authorization.js';
import { proveCr7R8FileWriteSuccessor } from '../../scripts/verification/prove-cr7-r8-file-write-successor.mjs';

const ACTION_IDS = [
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333',
];

function harness({ failCleanupTerminalOnce = false } = {}) {
  const rows = [];
  let sequence = 0;
  let actionIndex = 0;
  let failTerminal = failCleanupTerminalOnce;
  const owner = createMaterialEffectOwner({
    uuidFn: () => ACTION_IDS[actionIndex++],
    logEventFn: async (companyId, agentId, operation, key, metadata, parentEventId) => {
      if (failTerminal && operation === 'material_effect_terminal'
          && metadata.effect_operation === 'local_file_orphan_cleanup') {
        failTerminal = false;
        throw new Error('injected_terminal_append_failure');
      }
      sequence += 1;
      const eventId = `event-${sequence}`;
      const mutationHash = String(sequence).padStart(64, '0');
      rows.push({
        id: eventId, event_id: eventId, company_id: companyId, agent_id: agentId,
        signer_agent_id: 'housekeeper',
        operation, key, metadata, parent_event_id: parentEventId,
        mutation_hash: mutationHash,
      });
      return { event_id: eventId, mutation_hash: mutationHash };
    },
    readEventHistoryFn: async () => rows,
  });
  return { rows, owner };
}

function scratchReconciler(root, owner, rows) {
  return createLocalFileWriteOrphanReconciler({
    roots: [root],
    effectOwner: owner,
    verifyStartFn: async (eventId, companyId) => {
      const row = rows.find((entry) => entry.id === eventId && entry.company_id === companyId);
      if (!row) throw new Error('verified_start_not_found_in_fixture_store');
      return row;
    },
  });
}

function scratch(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-cr7-r8-')));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

async function beginWrite(owner, target, content = 'retained draft') {
  const toolActionEventId = 'verified-tool-action-fixture';
  const action = await owner.begin({
    kind: 'filesystem', operation: 'local_file_write', targetIdentifier: target,
    inputProjection: localFileWriteInputProjection({ content, toolActionEventId }),
    subjectAgentId: 'housekeeper',
  });
  return { action, toolActionEventId };
}

test('R8 forward census retains all 101 surviving historical sites and owns four new effects', () => {
  const proof = proveCr7R8FileWriteSuccessor();
  assert.equal(proof.historical_effect_count, 103);
  assert.equal(proof.retired_effect_ids.length, 2);
  assert.equal(proof.new_effect_ids.length, 4);
  assert.equal(proof.current_effect_count, 105);
  assert.equal(proof.successor_static_owner_pattern_count, 4);
  assert.equal(proof.signed_native_write_qualification_executed, false);
  assert.equal(proof.live_restart_qualification_executed, false);
  assert.equal(proof.release_closed, false);
});

test('native write cannot be invoked with a fabricated start object or without signed tool authority', async (t) => {
  const root = scratch(t);
  const { owner } = harness();
  const target = path.join(root, 'nested', 'report.txt');
  const { action } = await beginWrite(owner, target);
  const actorValidFromIso = new Date().toISOString();
  await assert.rejects(writeAllowedLocalFile({
    filepath: target, content: 'substituted', materialEffectStart: action,
    toolActionAuthority: { actorAgentId: 'fixture', actorValidFromIso },
    executionContext: { actorAgentId: 'fixture', actorValidFromIso, companyId: 'hom' },
    agentId: 'fixture',
  }), /verified_tool_action_required/);
  assert.equal(fs.existsSync(path.join(root, 'nested')), false);
  await owner.finish({ action, disposition: 'INDETERMINATE', resultProjection: { denied: true } });
});

test('restart removes only an orphan bound to a verified open start, then closes it without replay', async (t) => {
  const root = scratch(t);
  const { rows, owner } = harness();
  const target = path.join(root, 'report.txt');
  const { action } = await beginWrite(owner, target);
  const orphan = path.join(root, `.report.txt.aimos-${action.actionId}`);
  fs.writeFileSync(orphan, 'draft after process death', { mode: 0o600 });
  const unrelated = path.join(root, '.report.txt.aimos-99999999-9999-4999-8999-999999999999');
  fs.writeFileSync(unrelated, 'not an AIMOS start', { mode: 0o600 });
  const open = reconstructMaterialEffectTraces(rows).open;
  const reconcileFiles = scratchReconciler(root, owner, rows);
  const cleanup = await reconcileFiles(open);
  assert.equal(cleanup.removed, 1);
  assert.equal(fs.existsSync(orphan), false);
  assert.equal(fs.readFileSync(unrelated, 'utf8'), 'not an AIMOS start');
  const afterFiles = reconstructMaterialEffectTraces(rows);
  assert.equal(afterFiles.complete.length, 1); // signed cleanup start/terminal
  assert.equal(afterFiles.open.length, 1); // original write remains open
  const recovery = await owner.reconcileOpen({ historyFn: async () => rows });
  assert.equal(recovery.remainingOpen, 0);
  assert.equal(recovery.externalEffectsReplayed, 0);
  assert.equal(reconstructMaterialEffectTraces(rows).complete.length, 2);
});

test('a matching action ID with a different target hash cannot authorize deletion', async (t) => {
  const root = scratch(t);
  const { rows, owner } = harness();
  const { action } = await beginWrite(owner, path.join(root, 'intended.txt'));
  const other = path.join(root, `.other.txt.aimos-${action.actionId}`);
  fs.writeFileSync(other, 'unrelated', { mode: 0o600 });
  const reconcileFiles = scratchReconciler(root, owner, rows);
  const result = await reconcileFiles(reconstructMaterialEffectTraces(rows).open);
  assert.equal(result.removed, 0);
  assert.equal(result.unmatched, 1);
  assert.equal(fs.readFileSync(other, 'utf8'), 'unrelated');
  await owner.reconcileOpen({ historyFn: async () => rows });
});

test('fabricated matching open trace absent from verified history cannot unlink a file', async (t) => {
  const root = scratch(t);
  const { rows, owner } = harness();
  const target = path.join(root, 'report.txt');
  const { action } = await beginWrite(owner, target);
  const fabricatedId = ACTION_IDS[1];
  const forged = structuredClone(reconstructMaterialEffectTraces(rows).open[0]);
  forged.actionId = fabricatedId;
  forged.start.key = fabricatedId;
  forged.start.id = 'forged-event';
  forged.start.event_id = 'forged-event';
  forged.start.metadata.action_id = fabricatedId;
  const orphan = path.join(root, `.report.txt.aimos-${fabricatedId}`);
  fs.writeFileSync(orphan, 'not ledger backed', { mode: 0o600 });
  const reconcileFiles = scratchReconciler(root, owner, rows);
  await assert.rejects(reconcileFiles([forged]), /verified_start_not_found_in_fixture_store/);
  assert.equal(fs.readFileSync(orphan, 'utf8'), 'not ledger backed');
  await owner.finish({ action, disposition: 'INDETERMINATE', resultProjection: { denied: true } });
});

test('recovery fixture for a crash after rename keeps the file and marks the open start indeterminate', async (t) => {
  const root = scratch(t);
  const { rows, owner } = harness();
  const target = path.join(root, 'report.txt');
  const { action } = await beginWrite(owner, target);
  const temporary = path.join(root, `.report.txt.aimos-${action.actionId}`);
  fs.writeFileSync(temporary, 'retained draft', { mode: 0o600 });
  fs.renameSync(temporary, target);
  const reconcileFiles = scratchReconciler(root, owner, rows);
  const result = await reconcileFiles(reconstructMaterialEffectTraces(rows).open);
  assert.equal(result.removed, 0);
  assert.equal(result.unmatched, 1);
  assert.equal(fs.readFileSync(target, 'utf8'), 'retained draft');
  await owner.reconcileOpen({ historyFn: async () => rows });
  assert.equal(reconstructMaterialEffectTraces(rows).complete[0].terminal.metadata.disposition, 'INDETERMINATE');
});

test('cleanup terminal failure remains an open signed action for later recovery', async (t) => {
  const root = scratch(t);
  const { rows, owner } = harness({ failCleanupTerminalOnce: true });
  const target = path.join(root, 'report.txt');
  const { action } = await beginWrite(owner, target);
  const orphan = path.join(root, `.report.txt.aimos-${action.actionId}`);
  fs.writeFileSync(orphan, 'draft', { mode: 0o600 });
  const reconcileFiles = scratchReconciler(root, owner, rows);
  await assert.rejects(reconcileFiles(reconstructMaterialEffectTraces(rows).open),
    /injected_terminal_append_failure/);
  assert.equal(fs.existsSync(orphan), false);
  assert.equal(reconstructMaterialEffectTraces(rows).open.length, 2);
  const recovery = await owner.reconcileOpen({ historyFn: async () => rows });
  assert.equal(recovery.remainingOpen, 0);
  assert.equal(recovery.externalEffectsReplayed, 0);
});
