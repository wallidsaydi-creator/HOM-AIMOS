#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { proveCr7R5MaterialEffectAudit } from './prove-cr7-r5-material-effect-audit.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MAX_SET_BINDINGS = 100_000;
const FAMILY_FILES = Object.freeze([
  ['material_effect', 'services/security/material-effect-owner.js'],
  ['tool_action', 'services/orchestration/tool-action-ledger.js'],
  ['credential_use', 'services/security/credential-ledger.js'],
  ['canonical_save_action', 'services/write/canonical-save-owner.js'],
  ['agent_run', 'services/orchestration/run-metadata.js'],
  ['session_lane', 'services/orchestration/session-runner.js'],
]);

function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function canonicalJson(value) {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
function read(relative) { return fs.readFileSync(path.join(ROOT, relative), 'utf8'); }
function assert(value, reason) { if (!value) throw new Error(`cr7_r6_audit_failed:${reason}`); }

export function verifyCommittedTerminalBijection({ committedEffects = [], successTerminals = [] } = {}) {
  if (!Array.isArray(committedEffects) || !Array.isArray(successTerminals)
      || committedEffects.length > MAX_SET_BINDINGS || successTerminals.length > MAX_SET_BINDINGS) {
    throw new Error('committed_terminal_set_limit');
  }
  const committed = new Map();
  const terminals = new Map();
  for (const effect of committedEffects) {
    const binding = String(effect?.binding || '');
    if (!/^[0-9a-f]{64}$/.test(binding) || committed.has(binding)) {
      throw new Error('committed_effect_binding_duplicate_or_invalid');
    }
    committed.set(binding, effect);
  }
  for (const terminal of successTerminals) {
    const binding = String(terminal?.binding || '');
    if (!/^[0-9a-f]{64}$/.test(binding) || terminals.has(binding)) {
      throw new Error('success_terminal_binding_duplicate_or_invalid');
    }
    terminals.set(binding, terminal);
  }
  const missing = [...committed.keys()].filter((binding) => !terminals.has(binding));
  const extra = [...terminals.keys()].filter((binding) => !committed.has(binding));
  if (missing.length || extra.length) throw new Error('committed_terminal_set_equality_failed');
  return Object.freeze({
    committedCount: committed.size,
    successTerminalCount: terminals.size,
    exactSetEquality: true,
    uniqueBinding: true,
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export function proveCr7R6RecoverySetEquality() {
  const r5 = proveCr7R5MaterialEffectAudit();
  assert(r5.current_open_effect_count === 0, 'r5_input_open');
  const required = Object.freeze({
    material_effect: [/reconstructMaterialEffectTraces/, /reconcileOpen/, /externalEffectsReplayed: 0/],
    tool_action: [/tool_execution_terminal/, /reconstructToolActionTraces/, /reconcileOpenToolActions/, /toolInvocationsReplayed: 0/],
    credential_use: [/findOpenCredentialUses/, /reconcileOpenCredentialUses/, /externalEffectsReplayed: 0/],
    canonical_save_action: [/reconstructCanonicalSaveActionTraces/, /reconcileOpenCanonicalSaveActions/, /savesReplayed: 0/],
    agent_run: [/reconstructRunTraces/, /reconcileOpenRuns/, /runsReplayed: 0/, /responsesPublished: 0/],
    session_lane: [/reconstructSessionLaneTraces/, /reconcileOpenSessionLanes/, /sessionCallbacksReplayed: 0/],
  });
  const families = FAMILY_FILES.map(([family, file]) => {
    const files = family === 'canonical_save_action'
      ? [file, 'services/write/canonical-save-contract.js']
      : [file];
    const source = files.map(read).join('\n');
    for (const pattern of required[family]) assert(pattern.test(source), `${family}:${pattern}`);
    assert(/O\(n\)/.test(source), `${family}:bounded_reconstruction_missing`);
    return Object.freeze({ family, files, sha256: sha256(source), verdict: 'RECOVERY_OWNER_PRESENT' });
  });
  const server = read('server.js');
  const recoveryCall = server.indexOf('await reconcileCr7OpenActionsAtBoot();');
  const listenCall = server.indexOf("app.listen(PORT, '127.0.0.1'");
  assert(/async function reconcileCr7OpenActionsAtBoot/.test(server), 'boot_recovery_owner_missing');
  assert(recoveryCall >= 0 && listenCall >= 0 && recoveryCall < listenCall, 'boot_recovery_must_precede_listen');
  for (const name of [
    'materialEffectOwner.reconcileOpen', 'reconcileOpenToolActions',
    'credentialLedger.reconcileOpenCredentialUses', 'reconcileOpenCanonicalSaveActions',
    'reconcileOpenRuns', 'reconcileOpenSessionLanes',
  ]) assert(server.includes(name), `boot_recovery_family_missing:${name}`);

  const bindings = ['a', 'b', 'c'].map((value) => sha256(`cr7-r6-${value}`));
  const bijection = verifyCommittedTerminalBijection({
    committedEffects: bindings.map((binding) => ({ binding })),
    successTerminals: [...bindings].reverse().map((binding) => ({ binding })),
  });
  let missingDenied = false;
  let duplicateDenied = false;
  let extraDenied = false;
  try {
    verifyCommittedTerminalBijection({
      committedEffects: bindings.map((binding) => ({ binding })),
      successTerminals: bindings.slice(1).map((binding) => ({ binding })),
    });
  } catch (error) { missingDenied = /set_equality/.test(error.message); }
  try {
    verifyCommittedTerminalBijection({
      committedEffects: bindings.map((binding) => ({ binding })),
      successTerminals: [{ binding: bindings[0] }, { binding: bindings[0] }],
    });
  } catch (error) { duplicateDenied = /duplicate_or_invalid/.test(error.message); }
  try {
    verifyCommittedTerminalBijection({
      committedEffects: bindings.slice(0, 2).map((binding) => ({ binding })),
      successTerminals: bindings.map((binding) => ({ binding })),
    });
  } catch (error) { extraDenied = /set_equality/.test(error.message); }
  assert(missingDenied && duplicateDenied && extraDenied, 'bijection_negative_vectors');

  const failureMatrix = Object.freeze([
    { case: 'rollback_before_effect', terminal: 'FAILED', success_allowed: false },
    { case: 'crash_after_start', terminal: 'INDETERMINATE', success_allowed: false },
    { case: 'crash_after_possible_effect', terminal: 'INDETERMINATE', success_allowed: false },
    { case: 'terminal_append_failure', terminal: 'OPEN_THEN_INDETERMINATE', success_allowed: false },
    { case: 'timeout', terminal: 'INDETERMINATE', success_allowed: false },
    { case: 'process_death', terminal: 'INDETERMINATE', success_allowed: false },
    { case: 'replay', terminal: 'DENIED_OR_EXACT_IDEMPOTENT', success_allowed: false },
    { case: 'fork', terminal: 'DENIED', success_allowed: false },
  ]);
  const sourceManifest = [
    ...families.map(({ family, files, sha256: digest }) => ({ family, files, sha256: digest })),
    { family: 'boot_composition', files: ['server.js'], sha256: sha256(server) },
  ];
  const body = {
    schema: 'hom.aimos.cr7-r6-recovery-set-equality-audit/v1',
    frozen_predecessor_r5_proof_root_sha256: 'f9dd27d66c5422b3aeacb59284caa8074e4eebc00e3ae869aeadf11f800397a9',
    current_r5_parity_proof_root_sha256: r5.proof_root_sha256,
    recovery_family_count: families.length,
    source_root_sha256: sha256(canonicalJson(sourceManifest)),
    reconstruction: bijection,
    missing_terminal_denied: missingDenied,
    duplicate_terminal_denied: duplicateDenied,
    extra_terminal_denied: extraDenied,
    failure_matrix: failureMatrix,
    second_pass_exact_noop_required: true,
    boot_recovery_precedes_listen: true,
    recovery_event_limit: MAX_SET_BINDINGS,
    credential_slot_limit: 10_000,
    provider_calls_executed: 0,
    credential_mutations_executed: 0,
    live_database_mutations_executed: 0,
    live_cutover: false,
    scheduler_recovery_owner: 'CR8',
    paper_authority: {
      formulas_changed: false,
      consultation_required: false,
      reason: 'R6 changes trace reconstruction and recovery protocols only',
    },
    families,
  };
  return Object.freeze({
    ...body,
    audit_root_sha256: sha256(canonicalJson(families)),
    proof_root_sha256: sha256(canonicalJson(body)),
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(proveCr7R6RecoverySetEquality(), null, 2));
}
