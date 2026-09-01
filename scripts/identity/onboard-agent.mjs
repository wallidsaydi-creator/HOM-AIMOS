#!/usr/bin/env node

// Generic first-launch AIMOS onboarding. Genesis has already created the
// autonomous Housekeeper and Guide corpus. This owner creates the operator
// certificate root, enrolls one user-selected ordinary agent, grants its exact
// epoch canonical memory access, and optionally appends a signed model policy.
// It contains no benchmark, provider default, or hidden identity.

import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { pool } from '../../db/connection.js';
import { AIMOS_AGENT_KEY_ROOT, AIMOS_INSTALLATION_CONTEXT } from '../../services/core/runtime-config.js';
import { logEvent, readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { recallAuthorizationService } from '../../services/security/recall-authorization.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { systemConfigLedger } from '../../services/security/system-config-ledger.js';
import {
  decryptMasterPrivkey,
  enrollAgentWithDeps,
  enrollMasterWithDeps,
  KC_SERVICE,
} from './lib.js';
import * as identityDb from './db.js';
import { keychainGet, keychainSet } from './keychain.js';
import {
  defaultOnboardingKeychainAccount,
  normalizeOnboardingAgentId,
  normalizeOnboardingModelPreference,
  onboardingModelConfigEntries,
  PUBLIC_AGENT_CLEARANCE_DEFAULT,
  PUBLIC_AGENT_CLEARANCE_MAXIMUM,
} from './onboarding-contract.mjs';
import { readLine, readPassphrase } from './passphrase.js';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const args = process.argv.slice(2);

function cli(name) {
  const inline = args.find((arg) => arg.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
}

function integerOption(name, fallback, minimum, maximum) {
  const raw = cli(name);
  const value = raw == null ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`onboarding_option_invalid:${name}`);
  }
  return value;
}

function normalizeDataClass(value) {
  const normalized = String(value || 'confidential').trim().toLowerCase();
  if (!new Set(['public', 'internal', 'confidential', 'restricted']).has(normalized)) {
    throw new Error('onboarding_data_class_invalid');
  }
  return normalized;
}

async function selectInputs() {
  const agentInput = cli('--agent-id') || await readLine('Choose an AIMOS agent identity');
  const agentId = normalizeOnboardingAgentId(agentInput);
  const providerArgument = cli('--model-provider');
  const modelArgument = cli('--model');
  let provider = providerArgument;
  let model = modelArgument;
  if (provider == null && model == null) {
    provider = await readLine('Model provider (optional; press Enter to configure later)');
    if (provider) model = await readLine('Model identifier');
  }
  return {
    agentId,
    modelPreference: normalizeOnboardingModelPreference(provider, model),
    validityDays: integerOption('--validity-days', 30, 1, 365),
    clearance: integerOption(
      '--clearance',
      PUBLIC_AGENT_CLEARANCE_DEFAULT,
      0,
      PUBLIC_AGENT_CLEARANCE_MAXIMUM,
    ),
    dataClass: normalizeDataClass(cli('--data-class')),
    writeAllowed: !args.includes('--read-only'),
    keychainAccount: cli('--keychain-account')
      || defaultOnboardingKeychainAccount(AIMOS_INSTALLATION_CONTEXT),
  };
}

async function genesisState() {
  return (await pool.query(`SELECT
    (SELECT count(*)::int FROM agent_identity WHERE agent_id='housekeeper') AS housekeepers,
    (SELECT count(*)::int FROM aimos_memories WHERE source='guide:genesis-install') AS guide_memories,
    (SELECT count(*)::int FROM aimos_memories) AS memories,
    (SELECT count(*)::int FROM aimos_master_identity) AS masters`)).rows[0];
}

async function enrollMaster(passphrase, account) {
  const existing = await identityDb.getMaster();
  if (existing) {
    const service = existing.keychain_service || KC_SERVICE;
    const selectedAccount = existing.keychain_account || account;
    const blob = await keychainGet(service, selectedAccount);
    const privateKey = blob ? decryptMasterPrivkey(passphrase, blob) : null;
    if (!privateKey) throw new Error('onboarding_existing_master_unlock_failed');
    return {
      created: false,
      fingerprint: existing.fingerprint,
      privateKey,
      keychainService: service,
      keychainAccount: selectedAccount,
    };
  }

  if (await keychainGet(KC_SERVICE, account)) {
    throw new Error('onboarding_master_slot_not_clean_use_explicit_keychain_account');
  }

  const prepared = await enrollMasterWithDeps(passphrase, {
    keychain: { get: keychainGet, set: keychainSet },
    db: identityDb,
    kcService: KC_SERVICE,
    kcAccount: account,
    brainRoot: process.cwd(),
  }, { prepareOnly: true });
  if (!prepared.ok) throw new Error(`onboarding_master_prepare_failed:${prepared.reason}`);
  const encryptedBlobSha256 = sha256(Buffer.from(prepared.encryptedBlob, 'utf8'));
  const start = await identityDb.beginMasterEnrollment(prepared.masterRow, encryptedBlobSha256);
  try {
    if (prepared.needsKeychainWrite) await keychainSet(KC_SERVICE, account, prepared.encryptedBlob);
    const observed = await keychainGet(KC_SERVICE, account);
    if (!observed || sha256(Buffer.from(observed, 'utf8')) !== encryptedBlobSha256) {
      throw new Error('onboarding_master_keychain_readback_failed');
    }
    await identityDb.commitMasterEnrollment(prepared.masterRow, start, encryptedBlobSha256);
  } catch (error) {
    await identityDb.markMasterEnrollmentIndeterminate(start, error).catch(() => null);
    throw error;
  }
  const privateKey = decryptMasterPrivkey(passphrase, prepared.encryptedBlob);
  if (!privateKey) throw new Error('onboarding_master_decryption_failed');
  return {
    created: true,
    fingerprint: prepared.fingerprint,
    privateKey,
    keychainService: KC_SERVICE,
    keychainAccount: account,
  };
}

async function enrollOrdinaryAgent(inputs, passphrase, master) {
  if (await identityDb.getAgent(inputs.agentId)) throw new Error('onboarding_agent_already_active');
  const prepared = await enrollAgentWithDeps(inputs.agentId, passphrase, {
    keychain: { get: keychainGet, set: keychainSet },
    db: identityDb,
    kcService: master.keychainService,
    kcAccount: master.keychainAccount,
    brainRoot: process.cwd(),
  }, { validityDays: inputs.validityDays, deferCommit: true });
  if (!prepared.ok) throw new Error(`onboarding_agent_prepare_failed:${prepared.reason}`);
  const start = await identityDb.beginAgentEnrollment(prepared.agentRow);
  const keyPath = path.join(AIMOS_AGENT_KEY_ROOT, `${inputs.agentId}.key`);
  const cachePath = path.join(AIMOS_AGENT_KEY_ROOT, `${inputs.agentId}.cert-cache.json`);
  try {
    await mkdir(AIMOS_AGENT_KEY_ROOT, { recursive: true, mode: 0o700 });
    if (existsSync(keyPath) || existsSync(cachePath)) throw new Error('onboarding_agent_material_already_exists');
    await writeFile(keyPath, `${prepared.agentPrivkey}\n`, { mode: 0o600, flag: 'wx' });
    await chmod(keyPath, 0o600);
    await writeFile(cachePath, `${JSON.stringify({
      agent_id: inputs.agentId,
      cert: prepared.cert,
      expires_at_ms: prepared.validUntil * 1_000,
    })}\n`, { mode: 0o600, flag: 'wx' });
    await chmod(cachePath, 0o600);
    await identityDb.commitAgentEnrollment(prepared.agentRow, start, {
      signing_material_sha256: sha256(await readFile(keyPath)),
      cert_cache_sha256: sha256(await readFile(cachePath)),
    });
  } catch (error) {
    await identityDb.markAgentEnrollmentIndeterminate(start, error).catch(() => null);
    throw error;
  }
  return prepared;
}

async function appendConfiguration(inputs, master) {
  const committed = [];
  const values = [{
    configKey: 'OPERATOR_AGENT_ID',
    value: inputs.agentId,
    reason: 'First-launch operator selected this ordinary AIMOS agent identity',
  }, ...onboardingModelConfigEntries(inputs.modelPreference).map((entry) => ({
    ...entry,
    reason: 'First-launch user selected this provider/model preference',
  }))];
  for (const entry of values) {
    const result = await systemConfigLedger.commitConfigValue({
      ...entry,
      operator: inputs.agentId,
      masterPrivkeyB64u: master.privateKey,
      masterFingerprint: master.fingerprint,
    });
    if (!result.ok) throw new Error(`onboarding_config_commit_failed:${entry.configKey}:${result.reason}`);
    committed.push({
      config_key: entry.configKey,
      mutation_hash: Buffer.from(result.mutationHash).toString('hex'),
    });
  }
  return committed;
}

async function main() {
  const inputs = await selectInputs();
  const before = await genesisState();
  if (before.housekeepers !== 1 || before.guide_memories !== 8 || before.memories !== 8
      || ![0, 1].includes(before.masters)) {
    throw new Error('onboarding_genesis_state_invalid');
  }
  const plan = {
    schema: 'hom.aimos.first-launch-onboarding-plan/v1',
    installation_context_sha256: AIMOS_INSTALLATION_CONTEXT.context_sha256,
    instance: AIMOS_INSTALLATION_CONTEXT.instance,
    agent_id: inputs.agentId,
    validity_days: inputs.validityDays,
    clearance_ceiling: inputs.clearance,
    data_class_ceiling: inputs.dataClass,
    write_allowed: inputs.writeAllowed,
    model_preference: inputs.modelPreference,
    master_after_housekeeper: true,
    public_agent_clearance_maximum: PUBLIC_AGENT_CLEARANCE_MAXIMUM,
    benchmark_specific: false,
  };
  const planSha256 = sha256(Buffer.from(canonicalJson(plan)));
  console.log(JSON.stringify({
    status: 'AIMOS_FIRST_LAUNCH_ONBOARDING_PREFLIGHT',
    plan_sha256: planSha256,
    ...plan,
    one_passphrase: true,
  }, null, 2));
  let passphrase = await readPassphrase('Choose the AIMOS operator passphrase (entered once; not retained): ');
  if (passphrase.length < 8) throw new Error('onboarding_passphrase_too_short');

  let processStart = null;
  try {
    processStart = await logEvent(
      'hom', 'housekeeper', 'first_launch_onboarding_started', inputs.agentId,
      {
        schema: 'hom.aimos.first-launch-onboarding-start/v1',
        plan_sha256: planSha256,
        installation_context_sha256: AIMOS_INSTALLATION_CONTEXT.context_sha256,
        selected_agent_id: inputs.agentId,
        master_present_before: before.masters === 1,
        model_preference_selected: Boolean(inputs.modelPreference),
        reasoning: 'Genesis created the Housekeeper and complete Guide corpus before this user-selected ordinary agent onboarding began.',
      },
      null,
      { returnReceipt: true, exclusiveOperationKey: true },
    );
    const master = await enrollMaster(passphrase, inputs.keychainAccount);
    const agent = await enrollOrdinaryAgent(inputs, passphrase, master);
    const grant = await recallAuthorizationService.commit({
      companyId: 'hom',
      subjectAgentId: inputs.agentId,
      subjectValidFrom: agent.agentRow.valid_from,
      allowed: true,
      writeAllowed: inputs.writeAllowed,
      clearanceCeiling: inputs.clearance,
      dataClassCeiling: inputs.dataClass,
      masterPrivkeyB64u: master.privateKey,
      masterFingerprint: master.fingerprint,
      reason: 'First-launch ordinary AIMOS memory authority',
    });
    const configuration = await appendConfiguration(inputs, master);
    const terminal = await logEvent(
      'hom', 'housekeeper', 'first_launch_onboarding_terminal', inputs.agentId,
      {
        schema: 'hom.aimos.first-launch-onboarding-terminal/v1',
        plan_sha256: planSha256,
        start_event_id: processStart.event_id,
        start_mutation_hash: processStart.mutation_hash,
        installation_context_sha256: AIMOS_INSTALLATION_CONTEXT.context_sha256,
        master_fingerprint: master.fingerprint,
        master_created: master.created,
        selected_agent_id: inputs.agentId,
        selected_agent_valid_from: new Date(agent.agentRow.valid_from).toISOString(),
        selected_agent_fingerprint: agent.fingerprint,
        grant_mutation_hash: Buffer.from(grant.mutationHash).toString('hex'),
        configuration,
        disposition: 'SUCCESS',
        reasoning: 'The exact user-selected identity, certificate epoch, memory grant and optional model preference were independently committed before onboarding success.',
      },
      processStart.event_id,
      { returnReceipt: true, exclusiveOperationKey: true },
    );
    await readVerifiedEventById(terminal.event_id, 'hom');
    const receipt = {
      schema: 'hom.aimos.first-launch-onboarding-receipt/v1',
      plan_sha256: planSha256,
      installation_context_sha256: AIMOS_INSTALLATION_CONTEXT.context_sha256,
      agent_id: inputs.agentId,
      agent_valid_from: new Date(agent.agentRow.valid_from).toISOString(),
      agent_fingerprint: agent.fingerprint,
      master_fingerprint: master.fingerprint,
      grant_mutation_hash: Buffer.from(grant.mutationHash).toString('hex'),
      configuration,
      model_preference: inputs.modelPreference,
      start_event_id: processStart.event_id,
      terminal_event_id: terminal.event_id,
      terminal_mutation_hash: terminal.mutation_hash,
      one_passphrase: true,
      benchmark_specific: false,
      ready_for_service_start: true,
    };
    const unsigned = { ...receipt };
    receipt.receipt_sha256 = sha256(Buffer.from(canonicalJson(unsigned)));
    const receiptRoot = path.join(AIMOS_INSTALLATION_CONTEXT.state_root, 'onboarding');
    await mkdir(receiptRoot, { recursive: true, mode: 0o700 });
    const receiptPath = path.join(receiptRoot, 'first-launch-receipt.json');
    await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    console.log(JSON.stringify({
      success: true,
      status: 'AIMOS_FIRST_LAUNCH_ONBOARDING_COMPLETE',
      agent_id: receipt.agent_id,
      agent_valid_from: receipt.agent_valid_from,
      agent_fingerprint: receipt.agent_fingerprint,
      write_allowed: inputs.writeAllowed,
      clearance_ceiling: inputs.clearance,
      data_class_ceiling: inputs.dataClass,
      model_preference: inputs.modelPreference,
      receipt: receiptPath,
      receipt_sha256: receipt.receipt_sha256,
      next: 'START_PERSISTENT_AIMOS_SERVICE',
    }, null, 2));
  } catch (error) {
    if (processStart?.event_id) {
      await logEvent(
        'hom', 'housekeeper', 'first_launch_onboarding_terminal', inputs.agentId,
        {
          schema: 'hom.aimos.first-launch-onboarding-terminal/v1',
          plan_sha256: planSha256,
          start_event_id: processStart.event_id,
          start_mutation_hash: processStart.mutation_hash,
          installation_context_sha256: AIMOS_INSTALLATION_CONTEXT.context_sha256,
          disposition: 'INDETERMINATE',
          error_class: error?.name || 'onboarding_failure',
          reasoning: 'First-launch onboarding did not reach a complete verified identity, grant and configuration terminal; reconciliation is required.',
        },
        processStart.event_id,
        { returnReceipt: true, exclusiveOperationKey: true },
      ).catch(() => null);
    }
    throw error;
  } finally {
    passphrase = null;
  }
}

main().catch(async (error) => {
  console.error(`[onboard-agent] ${error?.message || error}`);
  try { await pool.end(); } catch { /* ignore */ }
  process.exitCode = 1;
}).then(async () => {
  try { await pool.end(); } catch { /* ignore */ }
});
