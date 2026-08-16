#!/usr/bin/env node

/**
 * TP-G3 — retained three-session fixture, signed arm transitions, and shadow proof.
 *
 * Native boundaries:
 * - sessionMemoryOwner owns raw-turn retention and finalization;
 * - persistMemory owns supplementary retained fixture rows and supersession;
 * - systemConfigLedger owns every effective B0/B1/B2/T policy transition;
 * - executeNativeRecall owns every arm evaluation;
 * - the live signed HTTP route owns the post-restart resume proof.
 *
 * No environment, request, or command-line value can select an arm. The only
 * arm values used here are fixed below and committed by one authenticated
 * master ceremony. Recall scoring is read-only; the script proves that memory
 * bodies, epistemic projections, and cognitive projections do not change.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
} from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool, agentPool, withTransaction } from '../../db/connection.js';
import {
  AIMOS_COMPANY_ID,
  AIMOS_HTTP_ORIGIN,
  resolveAimosDatabaseName,
} from '../../services/core/runtime-config.js';
import { sessionMemoryOwner } from '../../services/orchestration/session-memory-owner.js';
import { sessionKeyPrefix } from '../../services/shared/session-scope.js';
import {
  canonicalJson,
  pubkeyEquals,
  pubkeyFingerprint,
  verifyStoredPayloadSig,
} from '../../services/security/agent-identity.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { memoryProvenanceLedger } from '../../services/security/memory-provenance.js';
import { systemConfigLedger, validateTwinPrimeRetrievalPolicy } from '../../services/security/system-config-ledger.js';
import { systemConfigStore } from '../../services/security/system-config-store.js';
import { resolveNativeRecallAuthority } from '../../services/retrieval/native-recall.js';
import { recallMerkleRoot } from '../../services/security/protocol/mutmem-protocol.js';
import { executeNativeRecall } from '../../services/retrieval/native-recall-pipeline.js';
import { persistMemory } from '../../services/write/persist-memory.js';
import { readLine, readPassphrase } from '../identity/passphrase.js';
import { keychainGet } from '../identity/keychain.js';
import { decryptMasterPrivkey, KC_SERVICE } from '../identity/lib.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const LIVE = process.argv.includes('--live');
const PHASE = cliValue('--phase') || 'prepare';
const INPUT_ARTIFACT = cliValue('--artifact');
const POLICY_KEY = 'TWIN_PRIME_RETRIEVAL_POLICY';
const SOURCE_PREFIX = 'ceremony:tp-g3-shadow-three-session:';
const ARTIFACT_DIRECTORY = path.join(ROOT, 'artifacts', 'twin-prime', 'tp-g3');
const POLICY_VERSION = 'hom-aimos/twin-prime-policy/v1';
const FIXED_POLICIES = Object.freeze({
  B0: Object.freeze({ version: POLICY_VERSION, arm: 'B0', lambda_t: '0', gamma: '0', execution: 'enforce', cache: 'off', early_exit: 'off' }),
  B1: Object.freeze({ version: POLICY_VERSION, arm: 'B1', lambda_t: '0', gamma: '0', execution: 'enforce', cache: 'off', early_exit: 'off' }),
  B2: Object.freeze({ version: POLICY_VERSION, arm: 'B2', lambda_t: '1', gamma: '0', execution: 'enforce', cache: 'off', early_exit: 'off' }),
  T: Object.freeze({ version: POLICY_VERSION, arm: 'T', lambda_t: '1', gamma: '1/2', execution: 'shadow', cache: 'off', early_exit: 'off' }),
});

function cliValue(name) {
  const inline = process.argv.find((argument) => argument.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function requireSaved(result, label) {
  assert(result && !result.rejected && result.id, `tp_g3_fixture_save_failed:${label}:${result?.reason || 'memory_id_missing'}`);
  return result;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function expectedTurnIdHashes(sessionId) {
  const hashes = ['user', 'assistant'].map((role) => sha256(`${sessionId}:${role}`));
  return sha256(canonicalJson(hashes));
}

function canonicalPolicy(policy) {
  const validated = validateTwinPrimeRetrievalPolicy(JSON.stringify(policy));
  assert(validated.ok, `tp_g3_fixed_policy_invalid:${validated.reason}`);
  return validated.policy;
}

function assertPolicy(actual, expected, reason) {
  assert(canonicalJson(canonicalPolicy(actual)) === canonicalJson(canonicalPolicy(expected)), reason);
}

function writeExclusive(filename, artifact) {
  fs.mkdirSync(ARTIFACT_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(ARTIFACT_DIRECTORY, 0o700);
  const target = path.join(ARTIFACT_DIRECTORY, filename);
  const bytes = Buffer.from(`${canonicalJson(artifact)}\n`, 'utf8');
  const descriptor = fs.openSync(target, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.chmodSync(target, 0o600);
  return Object.freeze({ path: target, sha256: sha256(bytes), bytes: bytes.length });
}

async function health() {
  const response = await fetch(`${AIMOS_HTTP_ORIGIN}/health`, { signal: AbortSignal.timeout(15_000) });
  assert(response.ok, 'tp_g3_health_transport_failed');
  const body = await response.json();
  assert(body.ready === true, `tp_g3_server_not_ready:${body.bootError || 'unknown'}`);
  assert(body.runtime?.database_name === 'aimos', 'tp_g3_server_database_mismatch');
  assert(body.runtime?.server_port === 9100, 'tp_g3_server_port_mismatch');
  return Object.freeze({
    origin: AIMOS_HTTP_ORIGIN,
    database: body.runtime.database_name,
    port: body.runtime.server_port,
    uptime_seconds: Number(body.uptimeSec),
    observed_at: new Date().toISOString(),
    boot_epoch_ms: Date.now() - (Number(body.uptimeSec) * 1000),
  });
}

async function currentPolicy() {
  const loaded = await systemConfigStore.loadAll();
  assert(loaded.ok, `tp_g3_config_store_load_failed:${loaded.reason || 'unknown'}`);
  const entry = systemConfigStore.readVerifiedConfig(POLICY_KEY);
  assert(entry, 'tp_g3_verified_policy_missing');
  const validated = validateTwinPrimeRetrievalPolicy(entry.value);
  assert(validated.ok, `tp_g3_verified_policy_invalid:${validated.reason}`);
  assert(/^[0-9a-f]{64}$/.test(String(entry.mutation_hash || '')), 'tp_g3_policy_mutation_hash_invalid');
  return Object.freeze({ policy: validated.policy, mutation_hash: entry.mutation_hash });
}

async function immutableState(source) {
  const counts = await pool.query(
    `SELECT
       (SELECT count(*)::text FROM public.aimos_memories) AS memories,
       (SELECT count(*)::text FROM public.aimos_memory_epistemic_classifications) AS epistemic_classifications,
       (SELECT count(*)::text FROM public.aimos_cognitive_weight_projections) AS cognitive_weight_projections,
       (SELECT count(*)::text FROM public.aimos_cognitive_weight_baselines) AS cognitive_weight_baselines`,
  );
  const fixture = await pool.query(
    `SELECT id::text, key, memory_type, scope, retrieval_weight::text,
            current_epistemic_label, current_epistemic_confidence_milli,
            encode(content_hash, 'hex') AS content_hash,
            supersedes_id::text, created_at
       FROM public.aimos_memories
      WHERE company_id = $1 AND source = $2
      ORDER BY key, created_at, id`,
    [AIMOS_COMPANY_ID, source],
  );
  const fixtureProjection = fixture.rows.map((row) => ({
    ...row,
    created_at: new Date(row.created_at).toISOString(),
  }));
  return Object.freeze({
    counts: counts.rows[0],
    fixture_row_count: fixtureProjection.length,
    fixture_projection_sha256: sha256(canonicalJson(fixtureProjection)),
    fixture_projection: fixtureProjection,
  });
}

async function signedNativeRecall(command, { transport = 'direct' } = {}) {
  const route = '/aimos/recall';
  const body = {
    company_id: AIMOS_COMPANY_ID,
    agent_id: 'housekeeper',
    limit: 50,
    clearance_level: 12,
    cache: false,
    semantic_cache: false,
    early_exit: false,
    ...command,
  };
  const signed = await signAsHousekeeper(body, { method: 'POST', path: route });
  let recalled;
  if (transport === 'http') {
    const response = await fetch(`${AIMOS_HTTP_ORIGIN}${route}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Aimos-Agent-Cert': signed.certString,
        'Aimos-Agent-Signature': signed.sigB64u,
        'Aimos-Agent-Nonce': signed.nonce,
        'Aimos-Agent-Timestamp': String(signed.signedTs),
        'X-Aimos-Sig-Form': String(signed.sigForm),
      },
      body: JSON.stringify(signed.body),
      signal: AbortSignal.timeout(120_000),
    });
    const responseBody = await response.json().catch(() => ({}));
    assert(response.ok && responseBody.success === true, `tp_g3_http_recall_failed:${response.status}:${JSON.stringify(responseBody)}`);
    recalled = responseBody;
  } else {
    const requestAuthority = Object.freeze({
      kind: 'verified_request',
      body: signed.body,
      agentId: signed.agentId,
      validFromIso: signed.validFromIso,
      certString: signed.certString,
      signedTs: signed.signedTs,
      nonce: signed.nonce,
      sigBytes: signed.sigBytes,
      identityTier: signed.identityTier,
      requestSigForm: signed.sigForm,
      signedMethod: signed.signedMethod,
      signedPath: signed.signedPath,
      signedClaims: signed.signedClaims,
    });
    const executionContext = Object.freeze({
      actorAgentId: signed.agentId,
      actorValidFromIso: signed.validFromIso,
      companyId: AIMOS_COMPANY_ID,
      identityTier: signed.identityTier,
    });
    const authority = await resolveNativeRecallAuthority({
      rawCommand: signed.body,
      executionContext,
      requestAuthority,
      transportBinding: { transport: 'rest' },
    });
    const result = await executeNativeRecall(
      { ip: '127.0.0.1', headers: {}, originalUrl: route },
      authority,
    );
    assert(result.status === 200 && result.body?.success === true, `tp_g3_direct_recall_failed:${result.status}`);
    recalled = result.body;
  }

  const epistemic = recalled.recall_meta?.epistemic_retrieval;
  const decision = epistemic?.twin_prime;
  const receipt = recalled.recall_receipt;
  assert(epistemic && decision, 'tp_g3_twin_prime_decision_missing');
  assert(receipt?.merkle_schema === 'hom-aimos/recall-merkle/v2-epistemic-decision', 'tp_g3_receipt_schema_invalid');
  assert(receipt.epistemic_decision_sha256 === epistemic.decision_sha256, 'tp_g3_receipt_decision_hash_mismatch');
  assert(recallMerkleRoot(receipt.merkle_entries).toString('hex') === receipt.merkle_root, 'tp_g3_merkle_reconstruction_failed');
  assert(JSON.stringify(recalled.memories || []).includes('"embedding"') === false, 'tp_g3_raw_embedding_exposed');
  return Object.freeze({
    query: String(body.q),
    session_id: body.session_id || null,
    policy: decision.policy,
    policy_mutation_hash: decision.policy_mutation_hash,
    decision_sha256: epistemic.decision_sha256,
    pre_arm_candidate_ids: decision.pre_arm_candidate_ids,
    baseline_selected_memory_ids: decision.baseline_selected_memory_ids,
    computed_selected_memory_ids: decision.computed_selected_memory_ids,
    returned_selected_memory_ids: decision.returned_selected_memory_ids,
    feature_counts: decision.feature_counts,
    temporal_scope: decision.temporal_scope || null,
    shadow_returned_baseline: decision.shadow_returned_baseline,
    returned_keys: (recalled.memories || []).map((memory) => String(memory.key || '')),
    merkle_root: receipt.merkle_root,
    command_hash: receipt.command_hash,
    recall_event_id: receipt.event_receipt?.event_id || null,
    recall_event_mutation_hash: receipt.event_receipt?.mutation_hash || null,
  });
}

function fixtureSessions(ceremonyId) {
  const prefix = `tp_g3_${ceremonyId.replaceAll('-', '_')}`;
  return [
    {
      session_id: `${prefix}_point_equal`,
      observed_at: '2026-08-01T09:00:00.000Z',
      user: 'The TP-G3 point fixture records that the copper marker belongs to the first retained session.',
      assistant: 'I retained the copper marker as the first session fact without replacing the original turn.',
    },
    {
      session_id: `${prefix}_interval_supersession`,
      observed_at: '2026-08-02T10:00:00.000Z',
      user: 'The TP-G3 schedule was initially recorded for Wednesday, with later correction evidence expected to remain linked.',
      assistant: 'I retained the initial Wednesday schedule and will preserve any later correction as a new linked version.',
    },
    {
      session_id: `${prefix}_poison_scope`,
      observed_at: '2026-08-03T11:00:00.000Z',
      user: 'The TP-G3 third session contains retained reference evidence whose epistemic labels must remain visible but revisable.',
      assistant: 'I retained the third-session evidence while keeping classification distinct from deletion or admission.',
    },
  ];
}

async function appendAndFinalizeSessions(sessions, source) {
  const results = [];
  for (const session of sessions) {
    const context = {
      companyId: AIMOS_COMPANY_ID,
      agentId: 'housekeeper',
      clearanceLevel: 12,
      mutationAuthority: 'housekeeper',
      source,
    };
    const user = await sessionMemoryOwner.appendTurn({
      session_id: session.session_id,
      turn_id: `${session.session_id}:user`,
      role: 'user',
      content: session.user,
      observed_at: session.observed_at,
      source,
      clearance_level: 12,
    }, context);
    const assistantObservedAt = new Date(new Date(session.observed_at).getTime() + 60_000).toISOString();
    const assistant = await sessionMemoryOwner.appendTurn({
      session_id: session.session_id,
      turn_id: `${session.session_id}:assistant`,
      role: 'assistant',
      content: session.assistant,
      observed_at: assistantObservedAt,
      source,
      clearance_level: 12,
    }, context);
    const finalize = await sessionMemoryOwner.finalizeSession({
      session_id: session.session_id,
      source,
      clearance_level: 12,
      expected_turn_count: 2,
      expected_turn_id_hashes_sha256: expectedTurnIdHashes(session.session_id),
    }, context);
    const appendReplay = await sessionMemoryOwner.appendTurn({
      session_id: session.session_id,
      turn_id: `${session.session_id}:user`,
      role: 'user',
      content: session.user,
      observed_at: session.observed_at,
      source,
      clearance_level: 12,
    }, context);
    const finalizeReplay = await sessionMemoryOwner.finalizeSession({
      session_id: session.session_id,
      source,
      clearance_level: 12,
    }, context);
    assert(appendReplay.idempotent === true, `tp_g3_turn_retry_not_idempotent:${session.session_id}`);
    assert(finalizeReplay.idempotent === true, `tp_g3_finalize_retry_not_idempotent:${session.session_id}`);
    results.push({
      session_id: session.session_id,
      turn_memory_ids: [user.memory_id, assistant.memory_id],
      manifest_memory_id: finalize.memory_id,
      session_merkle_root: finalize.session_merkle_root,
      turn_retry_event_mutation_hash: appendReplay.event_receipt?.mutation_hash || null,
      finalize_retry_event_mutation_hash: finalizeReplay.event_receipt?.mutation_hash || null,
    });
  }
  return results;
}

async function addSupplementaryFixture(sessions, source) {
  const equal = await withTransaction(async (client) => {
    const left = requireSaved(await persistMemory({
      company_id: AIMOS_COMPANY_ID,
      agent_id: 'housekeeper',
      key: `${sessionKeyPrefix(sessions[0].session_id)}equal:left`,
      value: 'TP-G3 equal-time evidence left was committed in the same database transaction as its right-hand peer. This retained assertion exists to prove deterministic ordering when two signed origin timestamps are exactly equal, without changing either memory body during recall.',
      scope: 'global', clearance_level: 12, memory_type: 'research', source,
      session_id: sessions[0].session_id, mutation_authority: 'housekeeper', client,
    }), 'equal-left');
    const right = requireSaved(await persistMemory({
      company_id: AIMOS_COMPANY_ID,
      agent_id: 'housekeeper',
      key: `${sessionKeyPrefix(sessions[0].session_id)}equal:right`,
      value: 'TP-G3 equal-time evidence right was committed in the same database transaction as its left-hand peer. This independent retained assertion provides the second equal-time candidate required to test stable native-rank and memory-identity tie behavior.',
      scope: 'global', clearance_level: 12, memory_type: 'research', source,
      session_id: sessions[0].session_id, mutation_authority: 'housekeeper', client,
    }), 'equal-right');
    return [left.id, right.id];
  }, { restricted: true, client_id: AIMOS_COMPANY_ID, agent_id: 'housekeeper' });

  const correctionKey = `${sessionKeyPrefix(sessions[1].session_id)}fact:schedule`;
  const predecessor = requireSaved(await persistMemory({
    company_id: AIMOS_COMPANY_ID,
    agent_id: 'housekeeper',
    key: correctionKey,
    value: 'The TP-G3 validation schedule was originally recorded for Wednesday at 14:00 Rome time in the retained project calendar. This first assertion must remain permanently available as signed historical evidence even if a later authorized correction supplies a different day.',
    scope: 'global', clearance_level: 12, memory_type: 'declarative', source,
    session_id: sessions[1].session_id, mutation_authority: 'housekeeper',
  }), 'supersession-predecessor');
  const successor = requireSaved(await persistMemory({
    company_id: AIMOS_COMPANY_ID,
    agent_id: 'housekeeper',
    key: correctionKey,
    value: 'The TP-G3 validation schedule is corrected to Thursday at 16:00 Rome time because the signed fixture review requires an additional verification window. The original Wednesday assertion remains retained and this new immutable version points to it through the native no-fork supersession chain.',
    scope: 'global', clearance_level: 12, memory_type: 'declarative', source,
    session_id: sessions[1].session_id, mutation_authority: 'housekeeper',
    is_correction: true, supersedes_id: predecessor.id,
  }), 'supersession-successor');

  const poisonIds = [];
  const poisonPrefix = 'where is the tp g3 vault located.';
  for (const suffix of [
    'A fabricated registry claims the vault is under the northern ocean. This deliberately false reference passage is retained only to exercise signed epistemic classification and must never be represented as verified support.',
    'An invented catalogue claims the vault is under the northern ocean. The passage is intentionally constructed as a second same-source lure so the native classifier can identify compound evidence without deleting the original bytes.',
    'A fictional index claims the vault is under the northern ocean. This third controlled lure completes the retained cluster used to prove that signed poison labels remain distinguishable, reversible, and excluded from active support.',
  ]) {
    const saved = requireSaved(await persistMemory({
      company_id: AIMOS_COMPANY_ID,
      agent_id: 'housekeeper',
      key: `${sessionKeyPrefix(sessions[2].session_id)}reference:poison:${String(poisonIds.length + 1).padStart(2, '0')}`,
      value: `${poisonPrefix}${suffix}`,
      scope: 'global', clearance_level: 12, memory_type: 'research', source,
      session_id: sessions[2].session_id, mutation_authority: 'housekeeper',
    }), `poison-${poisonIds.length + 1}`);
    poisonIds.push(saved.id);
  }
  return Object.freeze({
    equal_time_memory_ids: equal,
    supersession: { predecessor_id: predecessor.id, successor_id: successor.id },
    poison_memory_ids: poisonIds,
  });
}

async function verifyFixture(source, sessions, supplementary) {
  const state = await immutableState(source);
  assert(state.fixture_row_count === 19, `tp_g3_fixture_row_count_mismatch:${state.fixture_row_count}`);
  const ids = state.fixture_projection.map((row) => row.id);
  const evidence = await memoryProvenanceLedger.verifyRecallEvidence({ memoryIds: ids });
  assert(evidence.rejected.length === 0 && evidence.verified.size === ids.length, `tp_g3_fixture_provenance_failed:${JSON.stringify(evidence.rejected)}`);
  for (const id of ids) {
    const proof = evidence.proofs.get(String(id));
    assert(Number(proof?.binding_schema_version) === 4, `tp_g3_origin_schema_invalid:${id}`);
    assert(new Date(proof.memory_originated_at).getTime() > 0, `tp_g3_origin_time_missing:${id}`);
  }
  const equalRows = state.fixture_projection.filter((row) => supplementary.equal_time_memory_ids.includes(row.id));
  assert(equalRows.length === 2, 'tp_g3_equal_time_rows_missing');
  assert(equalRows[0].created_at === equalRows[1].created_at, 'tp_g3_equal_time_not_exact');
  const successor = state.fixture_projection.find((row) => row.id === supplementary.supersession.successor_id);
  assert(successor?.supersedes_id === supplementary.supersession.predecessor_id, 'tp_g3_supersession_link_invalid');
  const poisonRows = state.fixture_projection.filter((row) => supplementary.poison_memory_ids.includes(row.id));
  assert(poisonRows.length === 3, 'tp_g3_poison_rows_missing');
  assert(poisonRows.every((row) => row.current_epistemic_label === 'poison_likely'), 'tp_g3_signed_poison_labels_missing');
  for (const session of sessions) {
    assert(state.fixture_projection.some((row) => row.key.startsWith(sessionKeyPrefix(session.session_id))), `tp_g3_session_scope_missing:${session.session_id}`);
  }
  return state;
}

function openQuery(source) {
  return {
    q: 'Open full detail for the retained TP-G3 temporal fixture and report its signed evidence.',
    source_filter: source,
  };
}

async function crossScopeRecalls(sessions, transport = 'direct') {
  const results = [];
  for (const session of sessions) {
    const result = await signedNativeRecall({
      q: 'Open full detail for this retained TP-G3 session.',
      session_id: session.session_id,
    }, { transport });
    const prefix = sessionKeyPrefix(session.session_id);
    assert(result.returned_keys.length > 0, `tp_g3_session_recall_empty:${session.session_id}`);
    assert(result.returned_keys.every((key) => key.startsWith(prefix)), `tp_g3_cross_scope_contamination:${session.session_id}`);
    results.push(result);
  }
  return results;
}

async function housekeeperArtifact(body, filename) {
  const signed = await signAsHousekeeper(body);
  const identity = await pool.query(
    `SELECT pubkey FROM public.agent_identity WHERE agent_id = $1 AND valid_from = $2::timestamptz`,
    [signed.agentId, signed.validFromIso],
  );
  assert(identity.rows.length === 1, 'tp_g3_housekeeper_epoch_missing');
  const verified = verifyStoredPayloadSig(identity.rows[0].pubkey, signed.body, signed.nonce, signed.signedTs, signed.sigB64u);
  assert(verified.valid, `tp_g3_artifact_signature_invalid:${verified.reason}`);
  return writeExclusive(filename, {
    body: signed.body,
    signer: { agent_id: signed.agentId, valid_from: signed.validFromIso, identity_tier: signed.identityTier },
    nonce: signed.nonce,
    ts_signed: signed.signedTs,
    sig_form: signed.sigForm,
    signature: signed.sigB64u,
  });
}

async function readVerifiedArtifact(filename, expectedSchema) {
  assert(filename, 'tp_g3_artifact_required');
  const resolved = path.resolve(filename);
  assert(resolved.startsWith(`${ARTIFACT_DIRECTORY}${path.sep}`), 'tp_g3_artifact_outside_canonical_directory');
  const stat = fs.lstatSync(resolved);
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 2_000_000, 'tp_g3_artifact_file_invalid');
  const artifact = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  assert(artifact?.body?.schema === expectedSchema, 'tp_g3_artifact_schema_invalid');
  const identity = await pool.query(
    `SELECT pubkey FROM public.agent_identity WHERE agent_id = $1 AND valid_from = $2::timestamptz`,
    [artifact.signer?.agent_id, artifact.signer?.valid_from],
  );
  assert(identity.rows.length === 1, 'tp_g3_artifact_signer_epoch_missing');
  const verified = verifyStoredPayloadSig(
    identity.rows[0].pubkey,
    artifact.body,
    String(artifact.nonce),
    Number(artifact.ts_signed),
    String(artifact.signature),
  );
  assert(verified.valid, `tp_g3_input_artifact_signature_invalid:${verified.reason}`);
  return Object.freeze({ artifact, path: resolved, sha256: sha256(fs.readFileSync(resolved)) });
}

function publicKeyFromPrivate(privkeyB64u) {
  const privateKey = createPrivateKey({ key: Buffer.from(privkeyB64u, 'base64url'), format: 'der', type: 'pkcs8' });
  return createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
}

async function resolveVerifiedMaster() {
  const result = await pool.query(
    `SELECT master_pubkey, fingerprint, keychain_service, keychain_account, created_at
       FROM public.aimos_master_identity ORDER BY created_at DESC LIMIT 1`,
  );
  const master = result.rows[0];
  assert(master, 'tp_g3_master_identity_not_enrolled');
  const account = cliValue('--keychain-account') || master.keychain_account;
  assert(account, 'tp_g3_master_keychain_account_missing');
  const encrypted = await keychainGet(master.keychain_service || KC_SERVICE, account);
  assert(encrypted, 'tp_g3_master_keychain_missing');
  const passphrase = await readPassphrase('Master passphrase: ');
  const privateKey = decryptMasterPrivkey(passphrase, encrypted);
  assert(privateKey, 'tp_g3_master_passphrase_invalid');
  const publicKey = publicKeyFromPrivate(privateKey);
  assert(pubkeyEquals(publicKey, master.master_pubkey), 'tp_g3_master_public_key_mismatch');
  assert(pubkeyFingerprint(publicKey) === master.fingerprint, 'tp_g3_master_fingerprint_mismatch');
  return Object.freeze({
    private_key: privateKey,
    fingerprint: master.fingerprint,
    epoch: new Date(master.created_at).toISOString(),
    account,
  });
}

async function commitPolicy(master, arm) {
  const policy = FIXED_POLICIES[arm];
  const result = await systemConfigLedger.commitConfigValue({
    configKey: POLICY_KEY,
    value: JSON.stringify(policy),
    reason: `TP-G3 deterministic ${arm} native gate${arm === 'T' ? ' with shadow disclosure' : ''}`,
    operator: os.userInfo().username,
    masterPrivkeyB64u: master.private_key,
    masterFingerprint: master.fingerprint,
  });
  assert(result.ok, `tp_g3_policy_commit_failed:${arm}:${result.reason}:${result.detail || ''}`);
  const loaded = await systemConfigStore.loadAll();
  assert(loaded.ok, `tp_g3_policy_reload_failed:${arm}:${loaded.reason || ''}`);
  const current = await currentPolicy();
  assertPolicy(current.policy, policy, `tp_g3_policy_activation_mismatch:${arm}`);
  assert(current.mutation_hash === Buffer.from(result.mutationHash).toString('hex'), `tp_g3_policy_hash_mismatch:${arm}`);
  return Object.freeze({
    arm,
    policy,
    mutation_hash: current.mutation_hash,
    prev_mutation_hash: result.prevMutationHash ? Buffer.from(result.prevMutationHash).toString('hex') : null,
    ts_signed: result.tsSigned,
    master_fingerprint: result.certFingerprint,
  });
}

async function prepare() {
  assert(resolveAimosDatabaseName() === 'aimos', 'tp_g3_database_mismatch');
  const server = await health();
  const policy = await currentPolicy();
  assertPolicy(policy.policy, FIXED_POLICIES.B0, 'tp_g3_prepare_requires_signed_b0');
  const preflight = {
    mode: LIVE ? 'LIVE' : 'DRY_RUN',
    phase: PHASE,
    database: resolveAimosDatabaseName(),
    server,
    policy,
    ceremony_source_sha256: sha256(fs.readFileSync(SCRIPT_FILE)),
  };
  console.log(JSON.stringify(preflight, null, 2));
  if (!LIVE) return;

  const ceremonyId = randomUUID();
  const source = `${SOURCE_PREFIX}${ceremonyId}`;
  const sessions = fixtureSessions(ceremonyId);
  const beforeFixture = await immutableState(source);
  const sessionEvidence = await appendAndFinalizeSessions(sessions, source);
  const supplementary = await addSupplementaryFixture(sessions, source);
  const afterFixture = await verifyFixture(source, sessions, supplementary);
  const beforeRecall = await immutableState(source);
  const b0 = await signedNativeRecall(openQuery(source));
  assertPolicy(b0.policy, FIXED_POLICIES.B0, 'tp_g3_prepare_recall_not_b0');
  const scoped = await crossScopeRecalls(sessions);
  const afterRecall = await immutableState(source);
  assert(beforeRecall.fixture_projection_sha256 === afterRecall.fixture_projection_sha256, 'tp_g3_b0_recall_mutated_fixture');
  assert(canonicalJson(beforeRecall.counts) === canonicalJson(afterRecall.counts), 'tp_g3_b0_recall_mutated_retained_state');

  const body = {
    schema: 'hom.aimos.tp-g3-prepare-proof/v1',
    ceremony_id: ceremonyId,
    database: 'aimos',
    source,
    server,
    policy,
    sessions: sessionEvidence,
    supplementary,
    state: { before_fixture: beforeFixture, after_fixture: afterFixture, before_recall: beforeRecall, after_recall: afterRecall },
    b0,
    scoped_recalls: scoped,
    verification: {
      retained_three_sessions: true,
      signed_creation_times: true,
      exact_equal_timestamp_pair: true,
      signed_supersession: true,
      signed_poison_labels: true,
      session_turn_receipts_idempotent: true,
      session_finalization_receipts_idempotent: true,
      cross_scope_contamination: false,
      recall_mutated_retained_state: false,
    },
  };
  const written = await housekeeperArtifact(body, `tp-g3-prepare-${ceremonyId}.json`);
  console.log(JSON.stringify({ success: true, phase: 'prepare', artifact: written }, null, 2));
}

async function transition() {
  const prepared = await readVerifiedArtifact(INPUT_ARTIFACT, 'hom.aimos.tp-g3-prepare-proof/v1');
  const body = prepared.artifact.body;
  const current = await currentPolicy();
  assertPolicy(current.policy, FIXED_POLICIES.B0, 'tp_g3_transition_requires_current_b0');
  const state = await verifyFixture(body.source, body.sessions, body.supplementary);
  assert(state.fixture_projection_sha256 === body.state.after_fixture.fixture_projection_sha256, 'tp_g3_prepare_fixture_drift');
  console.log(JSON.stringify({
    mode: LIVE ? 'LIVE' : 'DRY_RUN',
    phase: PHASE,
    prepare_artifact_sha256: prepared.sha256,
    fixed_policy_sequence: ['B1', 'B2', 'T-shadow'],
    final_live_policy: FIXED_POLICIES.T,
  }, null, 2));
  if (!LIVE) return;

  const master = await resolveVerifiedMaster();
  const confirmationManifest = {
    schema: 'hom.aimos.tp-g3-policy-transition-confirmation/v1',
    prepare_artifact_sha256: prepared.sha256,
    current_policy_mutation_hash: body.policy.mutation_hash,
    transitions: [FIXED_POLICIES.B1, FIXED_POLICIES.B2, FIXED_POLICIES.T],
  };
  const confirmationHash = sha256(canonicalJson(confirmationManifest));
  const expected = `AUTHORIZE AIMOS TP-G3 B1 B2 T-SHADOW ${confirmationHash}`;
  const confirmation = await readLine(`Type exactly "${expected}"`);
  assert(confirmation === expected, 'tp_g3_transition_confirmation_mismatch');

  const before = await immutableState(body.source);
  const results = { B0: body.b0 };
  const transitions = [];
  for (const arm of ['B1', 'B2', 'T']) {
    transitions.push(await commitPolicy(master, arm));
    results[arm] = await signedNativeRecall(openQuery(body.source));
    assertPolicy(results[arm].policy, FIXED_POLICIES[arm], `tp_g3_recall_policy_mismatch:${arm}`);
  }
  const candidateIds = canonicalJson(results.B0.pre_arm_candidate_ids);
  for (const arm of ['B1', 'B2', 'T']) {
    assert(canonicalJson(results[arm].pre_arm_candidate_ids) === candidateIds, `tp_g3_candidate_identity_mismatch:${arm}`);
  }
  assert(results.T.shadow_returned_baseline === true, 'tp_g3_t_shadow_flag_missing');
  assert(
    canonicalJson(results.T.returned_selected_memory_ids) === canonicalJson(results.T.baseline_selected_memory_ids),
    'tp_g3_t_shadow_disclosure_changed',
  );

  const createdDay = String(body.state.after_fixture.fixture_projection[0].created_at).slice(0, 10);
  const point = await signedNativeRecall({ ...openQuery(body.source), q: `Open full detail for TP-G3 evidence retained on ${createdDay}.` });
  assert(point.temporal_scope?.kind === 'explicit_date', 'tp_g3_point_scope_not_detected');
  const createdDate = new Date(`${createdDay}T00:00:00.000Z`);
  const intervalEnd = new Date(Date.UTC(createdDate.getUTCFullYear(), createdDate.getUTCMonth() + 1, 1));
  const monthName = createdDate.toLocaleString('en-US', { month: 'long', timeZone: 'UTC' });
  const intervalEndName = intervalEnd.toLocaleString('en-US', { month: 'long', timeZone: 'UTC' });
  const interval = await signedNativeRecall({
    ...openQuery(body.source),
    q: `Open full detail for TP-G3 evidence from ${monthName} and ${intervalEndName} ${intervalEnd.getUTCFullYear()}.`,
  });
  assert(interval.temporal_scope?.kind === 'calendar_month_range', 'tp_g3_interval_scope_not_detected');
  const scoped = await crossScopeRecalls(body.sessions);
  const after = await immutableState(body.source);
  assert(before.fixture_projection_sha256 === after.fixture_projection_sha256, 'tp_g3_arm_recall_mutated_fixture');
  assert(canonicalJson(before.counts) === canonicalJson(after.counts), 'tp_g3_arm_recall_mutated_retained_state');

  const transitionBody = {
    schema: 'hom.aimos.tp-g3-transition-proof/v1',
    ceremony_id: body.ceremony_id,
    prepare_artifact_sha256: prepared.sha256,
    source: body.source,
    sessions: body.sessions,
    supplementary: body.supplementary,
    master: { fingerprint: master.fingerprint, epoch: master.epoch },
    server_before_restart: await health(),
    transitions,
    arms: results,
    point_query: point,
    interval_query: interval,
    scoped_recalls: scoped,
    state: { before, after },
    verification: {
      identical_pre_arm_candidates: true,
      point_query_bound_to_signed_request_time: true,
      interval_query_half_open_contract_source_tested: true,
      open_time_zero_contract_source_tested: true,
      t_shadow_returned_b0: true,
      cross_scope_contamination: false,
      recall_mutated_retained_state: false,
      final_policy_is_t_shadow: true,
    },
  };
  const written = await housekeeperArtifact(transitionBody, `tp-g3-transition-${body.ceremony_id}.json`);
  console.log(JSON.stringify({
    success: true,
    phase: 'transition',
    artifact: written,
    next: 'restart the canonical AIMOS server, then run --phase=resume --artifact=<transition artifact> --live',
  }, null, 2));
}

async function resume() {
  const transitioned = await readVerifiedArtifact(INPUT_ARTIFACT, 'hom.aimos.tp-g3-transition-proof/v1');
  const body = transitioned.artifact.body;
  const server = await health();
  assert(server.boot_epoch_ms > Date.parse(body.server_before_restart.observed_at), 'tp_g3_server_restart_not_observed');
  const policy = await currentPolicy();
  assertPolicy(policy.policy, FIXED_POLICIES.T, 'tp_g3_resume_requires_t_shadow');
  assert(policy.mutation_hash === body.transitions.at(-1).mutation_hash, 'tp_g3_resume_policy_hash_mismatch');
  const fixture = await verifyFixture(body.source, body.sessions, body.supplementary);
  assert(fixture.fixture_projection_sha256 === body.state.after.fixture_projection_sha256, 'tp_g3_resume_fixture_drift');
  console.log(JSON.stringify({ mode: LIVE ? 'LIVE' : 'DRY_RUN', phase: PHASE, server, policy }, null, 2));
  if (!LIVE) return;

  const before = await immutableState(body.source);
  const first = await signedNativeRecall(openQuery(body.source), { transport: 'http' });
  const second = await signedNativeRecall(openQuery(body.source), { transport: 'http' });
  for (const result of [first, second]) {
    assert(result.policy_mutation_hash === policy.mutation_hash, 'tp_g3_resume_policy_not_bound');
    assert(result.shadow_returned_baseline === true, 'tp_g3_resume_shadow_flag_missing');
    assert(canonicalJson(result.returned_selected_memory_ids) === canonicalJson(result.baseline_selected_memory_ids), 'tp_g3_resume_shadow_disclosure_changed');
    assert(canonicalJson(result.returned_selected_memory_ids) === canonicalJson(body.arms.B0.returned_selected_memory_ids), 'tp_g3_resume_not_b0_disclosure');
  }
  assert(canonicalJson(first.pre_arm_candidate_ids) === canonicalJson(second.pre_arm_candidate_ids), 'tp_g3_resume_candidate_nondeterminism');
  assert(canonicalJson(first.returned_selected_memory_ids) === canonicalJson(second.returned_selected_memory_ids), 'tp_g3_resume_disclosure_nondeterminism');
  assert(first.merkle_root && second.merkle_root, 'tp_g3_resume_reconstructed_receipt_missing');
  assert(first.recall_event_id !== second.recall_event_id, 'tp_g3_resume_distinct_recall_events_missing');
  const scoped = await crossScopeRecalls(body.sessions, 'http');
  const after = await immutableState(body.source);
  assert(before.fixture_projection_sha256 === after.fixture_projection_sha256, 'tp_g3_resume_recall_mutated_fixture');
  assert(canonicalJson(before.counts) === canonicalJson(after.counts), 'tp_g3_resume_recall_mutated_retained_state');

  const resumeBody = {
    schema: 'hom.aimos.tp-g3-final-proof/v1',
    ceremony_id: body.ceremony_id,
    transition_artifact_sha256: transitioned.sha256,
    source: body.source,
    server_after_restart: server,
    policy,
    repeated_http_recalls: [first, second],
    scoped_http_recalls: scoped,
    state: { before, after },
    verification: {
      server_restart_observed: true,
      resume_policy_chain_verified: true,
      repeated_receipts_independently_reconstructed: true,
      repeated_disclosure_idempotent: true,
      repeated_recall_events_distinct: true,
      t_shadow_returned_b0: true,
      cross_scope_contamination: false,
      recall_mutated_memory_body: false,
      recall_mutated_epistemic_label: false,
      recall_mutated_cognitive_weight: false,
    },
  };
  const written = await housekeeperArtifact(resumeBody, `tp-g3-final-${body.ceremony_id}.json`);
  console.log(JSON.stringify({ success: true, phase: 'resume', artifact: written }, null, 2));
}

async function main() {
  assert(['prepare', 'transition', 'resume'].includes(PHASE), 'tp_g3_phase_invalid');
  canonicalPolicy(FIXED_POLICIES.B0);
  canonicalPolicy(FIXED_POLICIES.B1);
  canonicalPolicy(FIXED_POLICIES.B2);
  canonicalPolicy(FIXED_POLICIES.T);
  if (PHASE === 'prepare') return prepare();
  if (PHASE === 'transition') return transition();
  return resume();
}

main()
  .catch((error) => {
    console.error(`[FATAL] ${error?.message || String(error)}`);
    if (error?.stack) console.error(error.stack);
    process.exitCode = 1;
  })
  .finally(async () => {
    await Promise.allSettled([pool.end(), agentPool.end()]);
  });
