#!/usr/bin/env node

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

import { pool } from '../../db/connection.js';
import { runMigrations } from '../../migrations/run.js';
import { canonicalJson } from '../../services/security/agent-identity.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import {
  createOriginTrustRegistryV1,
  ORIGIN_SOURCE_CLAIM_SCHEMA_V1,
  ORIGIN_TRUST_REGISTRY_SCHEMA_V1,
} from '../../services/security/protocol/origin-corroboration-v1.js';
import { systemConfigLedger } from '../../services/security/system-config-ledger.js';
import { systemConfigStore } from '../../services/security/system-config-store.js';
import { manageInstalledUserService } from '../service/manage-user-service.mjs';
import { decryptMasterPrivkey, KC_ACCOUNT_DEFAULT, KC_SERVICE } from '../identity/lib.js';
import { keychainGet } from '../identity/keychain.js';
import * as identityDb from '../identity/db.js';
import { readLine, readPassphrase } from '../identity/passphrase.js';
import { auditCurrentOriginLedger } from '../verification/audit-origin-ledger-current.mjs';

const NODE_MAJOR = 26;
const BASE = 'http://127.0.0.1:9100';
const AGENT = 'codex-auditor';
const CLAIM_TEXT = 'SHA-256 is a specified Secure Hash Algorithm.\n';
const ACTION_ID = 'ob5-nist-ietf-sha256-write';
const CONFIG_KEY = 'ORIGIN_TRUST_REGISTRY';

function arg(name) {
  const inline = process.argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function assert(value, code) {
  if (!value) throw new Error(code);
}

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function registryInput() {
  return {
    schema: ORIGIN_TRUST_REGISTRY_SCHEMA_V1,
    version: 1,
    threshold: 2,
    valid_from: '2026-09-19T00:00:00.000Z',
    valid_until: '2027-09-19T00:00:00.000Z',
    claim: {
      schema: ORIGIN_SOURCE_CLAIM_SCHEMA_V1,
      claim_id: 'sha256-secure-hash-member',
      subject: 'SHA-256',
      predicate: 'is_specified_secure_hash_algorithm',
      object: true,
      rendered_value: CLAIM_TEXT,
    },
    action: {
      action_id: ACTION_ID,
      tool: 'write_file',
      arguments: {
        content: CLAIM_TEXT,
        filepath: path.join(
          os.homedir(), 'Documents', 'ob5-proof', 'ob5-corroborated-sha256-20260919.sentinel',
        ),
      },
      source_bound_fields: ['content'],
      operator_bound_fields: ['filepath'],
    },
    authorities: [
      {
        authority_id: 'ietf-rfc-6234',
        principal_id: 'trusted-source:ietf:rfc-6234',
        administrative_domain: 'www.rfc-editor.org',
        upstream_source: 'ietf:rfc:6234',
        url: 'https://www.rfc-editor.org/rfc/rfc6234.txt',
        media_type: 'text/plain',
        evidence_marker_utf8: 'SHA-256         32 byte / 256 bit',
        max_bytes: 1048576,
      },
      {
        authority_id: 'nist-hash-functions',
        principal_id: 'trusted-source:nist:hash-functions',
        administrative_domain: 'csrc.nist.gov',
        upstream_source: 'nist:hash-functions',
        url: 'https://csrc.nist.gov/projects/hash-functions',
        media_type: 'text/html',
        evidence_marker_utf8: 'SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224',
        max_bytes: 1048576,
      },
    ],
  };
}

async function postSigned(route, body, timeoutMs = 180000) {
  const headers = await buildEnvelopeHeaders(AGENT, 'POST', route, body);
  const response = await fetch(`${BASE}${route}`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const raw = await response.text();
  let parsed;
  try { parsed = JSON.parse(raw); } catch { parsed = { raw }; }
  return { status: response.status, body: parsed };
}

async function waitReady(timeoutMs = 60000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try {
      const response = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(2000) });
      const body = await response.json();
      if (response.ok && body.ready === true && body.boot_error == null) return body;
    } catch { /* managed restart is still converging */ }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('ob5_corroboration_health_timeout');
}

async function currentMemory(registry) {
  const key = `ob5:corroboration:${registry.claim.claim_sha256}`;
  const result = await pool.query(
    `SELECT id::text,value FROM aimos_memories WHERE company_id='hom' AND key=$1 ORDER BY created_at`,
    [key],
  );
  assert(result.rows.length <= 1, 'ob5_corroboration_memory_not_unique');
  if (result.rows[0]) {
    assert(result.rows[0].value === CLAIM_TEXT, 'ob5_corroboration_memory_value_mismatch');
    return { key, memoryId: result.rows[0].id, reused: true };
  }
  const saved = await postSigned('/aimos/save', {
    key,
    value: CLAIM_TEXT,
    memory_type: 'declarative',
    save_operation_id: randomUUID(),
  });
  assert(saved.status === 200 && saved.body?.success === true && saved.body?.memory_id,
    `ob5_corroboration_claim_save_failed:${saved.status}:${JSON.stringify(saved.body)}`);
  return { key, memoryId: saved.body.memory_id, reused: false, response: saved.body };
}

async function main() {
  const nodeMajor = Number.parseInt(process.versions.node.split('.')[0], 10);
  assert(nodeMajor === NODE_MAJOR, `ob5_node_runtime_mismatch:${process.versions.node}`);
  const live = process.argv.includes('--live');
  const resumeAuthorization = arg('--resume-authorization');
  const continueReadyRuntime = process.argv.includes('--continue-ready-runtime');
  const keychainAccount = arg('--keychain-account') || arg('--kc-account') || KC_ACCOUNT_DEFAULT;
  const rawRegistry = registryInput();
  const registry = createOriginTrustRegistryV1(rawRegistry);
  const plan = {
    schema: 'hom.aimos.ob5-independent-corroboration-ceremony/v1',
    source_root: process.cwd(),
    database: 'aimos',
    port: 9100,
    agent_id: AGENT,
    registry_sha256: registry.registry_sha256,
    claim_sha256: registry.claim.claim_sha256,
    action_id: registry.action.action_id,
    action_scope: registry.action.action_scope,
    action_value_sha256: registry.action.value_sha256,
    exact_filepath: registry.action.arguments.filepath,
    source_authorities: registry.authorities.map((authority) => ({
      authority_id: authority.authority_id,
      principal_id: authority.principal_id,
      administrative_domain_sha256: authority.administrative_domain_sha256,
      upstream_source_sha256: authority.upstream_source_sha256,
      url: authority.url,
      evidence_marker_sha256: authority.evidence_marker_sha256,
      max_bytes: authority.max_bytes,
    })),
    threshold: 2,
    one_passphrase: true,
    one_confirmation: true,
    new_identity: false,
    new_provider: false,
    new_listener: false,
    pre_authorization_network_effects: false,
    live_mutation: live,
  };
  const authorizationSha256 = sha(Buffer.from(canonicalJson(plan), 'utf8'));
  const configValue = canonicalJson(rawRegistry);
  const retainedRegistryValue = live
    ? await systemConfigLedger.readConfigString(CONFIG_KEY)
    : null;
  const resuming = Boolean(resumeAuthorization);
  assert(!continueReadyRuntime || resuming, 'ob5_ready_runtime_requires_resume');
  if (resuming) {
    assert(resumeAuthorization === authorizationSha256, 'ob5_resume_authorization_mismatch');
    assert(retainedRegistryValue === configValue, 'ob5_resume_registry_mismatch');
  }
  console.log(JSON.stringify({
    mode: live ? 'LIVE' : 'DRY_RUN',
    status: 'OB5_INDEPENDENT_CORROBORATION_PREFLIGHT',
    authorization_sha256: authorizationSha256,
    resume_existing_authorization: resuming,
    ...plan,
  }, null, 2));
  if (!live) return;

  let master = null;
  let privateKey = null;
  if (!resuming) {
    master = await identityDb.getMaster();
    assert(master?.fingerprint, 'ob5_master_missing');
    const encrypted = await keychainGet(KC_SERVICE, keychainAccount);
    assert(encrypted, 'ob5_master_keychain_blob_missing');
    const passphrase = await readPassphrase('Master passphrase (once; registry and complete OB-5 proof): ');
    privateKey = decryptMasterPrivkey(passphrase, encrypted);
    assert(privateKey, 'ob5_master_passphrase_invalid');
    const expected = `AUTHORIZE OB5 NIST IETF ${authorizationSha256}`;
    const confirmation = await readLine(`Type exactly "${expected}"`);
    assert(confirmation === expected, 'ob5_confirmation_invalid');
  }

  const migration = await runMigrations(pool);
  assert(migration.errors.length === 0, 'ob5_migration_failed');
  const auditClient = await pool.connect();
  try {
    await auditClient.query('BEGIN READ ONLY');
    await auditCurrentOriginLedger(auditClient);
    await auditClient.query('COMMIT');
  } catch (error) {
    await auditClient.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    auditClient.release();
  }
  const existing = await systemConfigLedger.readConfigString(CONFIG_KEY);
  if (existing !== configValue) {
    assert(!resuming, 'ob5_resume_registry_changed');
    const committed = await systemConfigLedger.commitConfigValue({
      configKey: CONFIG_KEY,
      value: configValue,
      reason: 'operator_selected_provider_agnostic_nist_ietf_origin_trust_registry',
      operator: os.userInfo().username,
      masterPrivkeyB64u: privateKey,
      masterFingerprint: master.fingerprint,
    });
    assert(committed.ok, `ob5_registry_commit_failed:${committed.reason}`);
  }
  const localLoad = await systemConfigStore.loadAll();
  assert(localLoad.ok, `ob5_registry_local_verify_failed:${localLoad.reason}`);
  const verifiedRegistry = systemConfigStore.readVerifiedConfig(CONFIG_KEY);
  assert(verifiedRegistry?.value === configValue, 'ob5_registry_readback_mismatch');

  const firstService = await manageInstalledUserService(
    continueReadyRuntime ? 'status' : 'restart',
  );
  assert(firstService.success && firstService.definition.port === 9100
    && firstService.definition.database === 'aimos'
    && firstService.definition.source_root === process.cwd(),
  continueReadyRuntime ? 'ob5_resume_runtime_target_invalid' : 'ob5_first_restart_target_invalid');
  const firstHealth = continueReadyRuntime ? firstService.health : await waitReady();
  assert(firstHealth?.ready === true && firstHealth?.bootError == null,
    'ob5_first_runtime_not_ready');
  const retained = await currentMemory(registry);
  const requestBody = { action_id: ACTION_ID, memory_id: retained.memoryId };
  const executed = await postSigned('/tools/corroboration/execute', requestBody);
  assert(executed.status === 200 && executed.body?.success === true,
    `ob5_corroboration_execute_failed:${executed.status}:${JSON.stringify(executed.body)}`);
  const fileBytes = fs.readFileSync(registry.action.arguments.filepath);
  assert(fileBytes.equals(Buffer.from(CLAIM_TEXT, 'utf8')), 'ob5_corroborated_file_bytes_invalid');

  const elevationSha256 = executed.body.elevation_sha256;
  const database = await pool.query(
    `SELECT encode(e.elevation_sha256,'hex') AS elevation_sha256,e.elevation_schema,
            e.actor_agent_id,e.action_id,encode(e.arguments_sha256,'hex') AS arguments_sha256,
            encode(e.value_sha256,'hex') AS value_sha256,
            count(v.verdict_sha256)::integer AS consumption_count,
            min(v.decision) AS decision
       FROM aimos_origin_elevations e
       LEFT JOIN aimos_action_origin_verdicts v ON v.elevation_sha256=e.elevation_sha256
      WHERE e.elevation_sha256=decode($1,'hex')
      GROUP BY e.elevation_sha256,e.elevation_schema,e.actor_agent_id,e.action_id,
               e.arguments_sha256,e.value_sha256`,
    [elevationSha256],
  );
  const row = database.rows[0];
  assert(row?.elevation_schema === 'hom.aimos.origin-elevation/v2'
    && row.actor_agent_id === AGENT && row.action_id === ACTION_ID
    && row.arguments_sha256 === registry.action.arguments_sha256
    && row.value_sha256 === registry.action.value_sha256
    && Number(row.consumption_count) === 1 && row.decision === 'ALLOW',
  'ob5_corroboration_database_readback_invalid');
  for (const source of executed.body.source_observations) {
    await readVerifiedEventById(source.event_id, 'hom');
    await readVerifiedEventById(source.license_event_id, 'hom');
  }

  const replay = await postSigned('/tools/corroboration/execute', requestBody);
  assert(replay.status === 409, `ob5_corroboration_replay_not_denied:${replay.status}`);
  const counts = await pool.query(
    `SELECT (SELECT count(*)::integer FROM aimos_origin_elevations
              WHERE elevation_sha256=decode($1,'hex')) AS elevation_count,
            (SELECT count(*)::integer FROM aimos_action_origin_verdicts
              WHERE elevation_sha256=decode($1,'hex')) AS consumption_count`,
    [elevationSha256],
  );
  assert(Number(counts.rows[0].elevation_count) === 1
    && Number(counts.rows[0].consumption_count) === 1,
  'ob5_corroboration_replay_effect_detected');

  const secondRestart = await manageInstalledUserService('restart');
  assert(secondRestart.success, 'ob5_second_restart_failed');
  const secondHealth = await waitReady();
  const afterBytes = fs.readFileSync(registry.action.arguments.filepath);
  assert(sha(afterBytes) === sha(fileBytes), 'ob5_corroborated_file_restart_mismatch');
  const after = await pool.query(
    `SELECT count(*)::integer AS n FROM aimos_action_origin_verdicts
      WHERE elevation_sha256=decode($1,'hex') AND decision='ALLOW'`,
    [elevationSha256],
  );
  assert(Number(after.rows[0].n) === 1, 'ob5_corroboration_restart_consumption_invalid');

  console.log(JSON.stringify({
    success: true,
    status: 'OB5_INDEPENDENT_CORROBORATION_LIVE_PROVED',
    authorization_sha256: authorizationSha256,
    resumed_existing_authorization: resuming,
    continued_ready_runtime: continueReadyRuntime,
    registry_sha256: registry.registry_sha256,
    registry_mutation_sha256: verifiedRegistry.mutation_hash,
    claim_sha256: registry.claim.claim_sha256,
    memory_id: retained.memoryId,
    memory_reused: retained.reused,
    elevation_sha256: elevationSha256,
    sources: executed.body.source_observations,
    result: executed.body.result,
    file_sha256: sha(fileBytes),
    replay_status: replay.status,
    restart_verified: true,
    first_ready: firstHealth.ready,
    second_ready: secondHealth.ready,
    next: 'OB5_AGGREGATE_INDEPENDENT_AUDIT',
  }, null, 2));
}

main().catch(async (error) => {
  console.error(error?.stack || error);
  try { await pool.end(); } catch { /* no-op */ }
  process.exitCode = 1;
}).finally(async () => {
  try { await pool.end(); } catch { /* no-op */ }
});
