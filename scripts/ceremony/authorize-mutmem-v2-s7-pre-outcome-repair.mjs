#!/usr/bin/env node

/**
 * Authorize the narrow S7 retained-population observer repair.
 *
 * The ceremony proves that the failed run has no poison recall/model outcome,
 * reconstructs the predecessor source root from the operator checkpoint,
 * verifies the exact retained cohort and every classification chain, and signs
 * only continuation of the already-authorized scratch evaluation.
 */

import {
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import {
  pubkeyEquals,
  pubkeyFingerprint,
} from '../../services/security/agent-identity.js';
import { keychainGet } from '../identity/keychain.js';
import { decryptMasterPrivkey, KC_SERVICE } from '../identity/lib.js';
import { readLine, readPassphrase } from '../identity/passphrase.js';
import {
  buildS7SourceClosure,
  readS7Json,
  s7Sha256,
  writeS7ImmutableJson,
} from '../../eval/mutmem-v2/s7-artifact-custody.mjs';
import { verifyS7Gate10Authorization } from '../../eval/mutmem-v2/s7-gate10-authorization.mjs';
import { canonicalJson, selfHash } from '../../eval/mutmem-v2/s7-protocol.mjs';
import { deriveS7RetainedPopulationWitness } from '../../eval/mutmem-v2/s7-retained-population-witness.mjs';
import {
  S7_SOURCE_AMENDMENT_ALLOWED_PATHS,
  createS7SourceAmendment,
  verifyS7SourceAmendment,
} from '../../eval/mutmem-v2/s7-source-amendment.mjs';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_CHECKPOINT = path.join(
  ROOT,
  'artifacts',
  'checkpoints',
  '20260814-s7-population-witness-before',
);

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function argument(name) {
  const inline = process.argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function sha256File(file) {
  const stat = fs.lstatSync(file);
  assert(stat.isFile() && !stat.isSymbolicLink(), `s7_repair_file_invalid:${file}`);
  return s7Sha256(fs.readFileSync(file));
}

function publicKeyFromPrivate(privkeyB64u) {
  const privateKey = createPrivateKey({
    key: Buffer.from(privkeyB64u, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
}

function databaseUrl(database) {
  const value = new URL(resolveAimosDatabaseUrl([]));
  value.pathname = `/${database}`;
  return value.toString();
}

function walkJson(directory) {
  const output = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    assert(!entry.isSymbolicLink(), `s7_repair_artifact_symlink:${absolute}`);
    if (entry.isDirectory()) output.push(...walkJson(absolute));
    else if (entry.isFile() && entry.name.endsWith('.json')) output.push(absolute);
  }
  return output.sort();
}

function retainedPopulation(runRoot, runId) {
  const savesRoot = path.join(runRoot, 'poisonedrag-screen', 'targets');
  const proofs = walkJson(savesRoot)
    .filter((file) => file.includes(`${path.sep}saves${path.sep}`))
    .map((file) => readS7Json(file, 20_000_000));
  return deriveS7RetainedPopulationWitness(proofs, { runId });
}

function completionCount(root, phase) {
  const units = path.join(root, 'units');
  if (!fs.existsSync(units)) return 0;
  return walkJson(units).filter((file) => {
    if (path.basename(file) !== 'complete.json') return false;
    const complete = readS7Json(file, 2_000_000);
    return complete?.phase === phase && complete.status === 'success';
  }).length;
}

function reconstructPredecessor(currentClosure, checkpoint, predecessorRoot) {
  const checkpointNames = new Map([
    ['eval/mutmem-v2/s7-poison-screen.mjs', 's7-poison-screen.mjs'],
    ['eval/mutmem-v2/run-s7-gate10.mjs', 'run-s7-gate10.mjs'],
    ['scripts/benchmark/run-isolated.mjs', 'run-isolated.mjs'],
  ]);
  const newPaths = new Set([
    'eval/mutmem-v2/s7-retained-population-witness.mjs',
    'eval/mutmem-v2/s7-source-amendment.mjs',
  ]);
  const changes = [];
  const predecessorFiles = currentClosure.files.flatMap((entry) => {
    if (newPaths.has(entry.path)) {
      changes.push({ path: entry.path, before_sha256: null, after_sha256: entry.sha256 });
      return [];
    }
    const checkpointName = checkpointNames.get(entry.path);
    if (!checkpointName) return [entry];
    const beforeSha256 = sha256File(path.join(checkpoint, checkpointName));
    if (beforeSha256 !== entry.sha256) {
      changes.push({ path: entry.path, before_sha256: beforeSha256, after_sha256: entry.sha256 });
    }
    return [{ ...entry, sha256: beforeSha256 }];
  }).sort((left, right) => left.path.localeCompare(right.path));
  const reconstructed = s7Sha256(Buffer.from(JSON.stringify(predecessorFiles), 'utf8'));
  assert(reconstructed === predecessorRoot,
    `s7_repair_predecessor_source_root_mismatch:${reconstructed}`);
  assert(changes.length >= 2
    && changes.every((change) => S7_SOURCE_AMENDMENT_ALLOWED_PATHS.has(change.path)),
  's7_repair_source_change_scope_invalid');
  return changes.sort((left, right) => left.path.localeCompare(right.path));
}

async function readMaster(canonicalPool) {
  const result = await canonicalPool.query(
    `SELECT master_pubkey, fingerprint, keychain_service, keychain_account, created_at
       FROM public.aimos_master_identity WHERE id = 1`,
  );
  const master = result.rows[0];
  assert(master && pubkeyFingerprint(master.master_pubkey) === master.fingerprint,
    's7_repair_master_identity_invalid');
  return master;
}

async function livePopulationState(scratchPool, population, poisonIds) {
  const client = await scratchPool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query("SELECT set_config('app.current_client_id','hom',true)");
    await client.query("SELECT set_config('app.current_agent_id','housekeeper',true)");
    const memories = await client.query(
      `SELECT id::text, source, encode(content_hash, 'hex') AS content_hash,
              current_epistemic_label, current_epistemic_confidence_milli,
              current_epistemic_event_id::text
         FROM public.aimos_memories
        WHERE company_id = 'hom' AND source = 'benchmark:poisonedrag'
          AND id = ANY($1::uuid[])
        ORDER BY id`,
      [population.exact_memory_ids],
    );
    assert(canonicalJson(memories.rows.map((row) => row.id))
      === canonicalJson(population.exact_memory_ids),
    's7_repair_live_population_mismatch');
    const chains = await client.query(
      `SELECT m.id::text AS memory_id, verified.ok, verified.chain_length,
              verified.current_label, verified.current_confidence_milli,
              CASE WHEN verified.head_hash IS NULL THEN NULL
                   ELSE encode(verified.head_hash, 'hex') END AS head_hash,
              verified.reason
         FROM public.aimos_memories m
         CROSS JOIN LATERAL public.verify_memory_epistemic_classification_chain(m.id) verified
        WHERE m.company_id = 'hom' AND m.id = ANY($1::uuid[])
        ORDER BY m.id`,
      [population.exact_memory_ids],
    );
    assert(chains.rowCount === population.unique_retained_memories
      && chains.rows.every((row) => row.ok === true),
    's7_repair_classification_chain_invalid');
    const poisonRows = memories.rows.filter((row) => poisonIds.has(row.id));
    assert(poisonIds.size === 25 && poisonRows.length === 25
      && poisonRows.every((row) => ['poison_suspect', 'poison_likely', 'poison_confirmed']
        .includes(row.current_epistemic_label)),
    's7_repair_signed_poison_label_invalid');
    const decisions = await client.query(
      `SELECT count(*)::int AS count FROM public.aimos_events
        WHERE company_id = 'hom' AND operation = 'mutmem_v2_s7_poison_policy_decision'`,
    );
    await client.query('COMMIT');
    return Object.freeze({
      valid_classification_chains: chains.rowCount,
      signed_poison_labels: poisonRows.length,
      poison_decision_events: decisions.rows[0].count,
      live_state_root_sha256: s7Sha256(Buffer.from(canonicalJson({
        memories: memories.rows,
        chains: chains.rows,
      }), 'utf8')),
    });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
}

async function main() {
  const live = process.argv.includes('--live');
  const preflight = process.argv.includes('--preflight');
  const runId = String(argument('--run-id') || '').trim().toLowerCase();
  const checkpoint = path.resolve(argument('--checkpoint-dir') || DEFAULT_CHECKPOINT);
  assert(live !== preflight, 's7_repair_choose_exactly_one_mode');
  assert(/^\d{14}_[0-9a-f]{6}$/.test(runId), 's7_repair_run_id_invalid');
  const runDirectory = path.join(ROOT, 'eval', 'public-results', runId);
  const gateRoot = path.join(runDirectory, 'mutmem-v2-s7', 'gate10');
  const database = `aimos_benchmark_${runId}`;
  const runStatus = readS7Json(path.join(runDirectory, 'run-status.json'), 2_000_000);
  assert(runStatus.state === 'failed' && runStatus.resumable === true
    && String(runStatus.error?.message || '').includes('mutmem-v2-s7-gate10-poison-screen.log'),
  's7_repair_run_terminal_state_invalid');
  const selection = readS7Json(path.join(gateRoot, 'selection.json'), 2_000_000);
  const authorization = readS7Json(path.join(gateRoot, 'gate10-authorization.json'), 2_000_000);
  const currentClosure = buildS7SourceClosure(ROOT);
  const sourceChanges = reconstructPredecessor(
    currentClosure,
    checkpoint,
    authorization.body.source_closure_sha256,
  );
  const population = retainedPopulation(gateRoot, runId);
  const admissions = walkJson(path.join(gateRoot, 'poisonedrag-screen', 'targets'))
    .filter((file) => path.basename(file) === 'admission.json')
    .map((file) => readS7Json(file, 20_000_000));
  const poisonIds = new Set(admissions.flatMap((admission) => admission.poison_memory_ids || []));

  const canonicalPool = new Pool({
    connectionString: databaseUrl('aimos'),
    ssl: false,
    connectionTimeoutMillis: 5_000,
  });
  const scratchPool = new Pool({
    connectionString: databaseUrl(database),
    ssl: false,
    connectionTimeoutMillis: 5_000,
  });
  try {
    const master = await readMaster(canonicalPool);
    const prior = verifyS7Gate10Authorization(authorization, {
      masterPubkeyB64u: master.master_pubkey,
      masterFingerprint: master.fingerprint,
      masterEpoch: new Date(master.created_at).toISOString(),
      runId,
      database,
      serverOrigin: authorization.body.server_origin,
      sourceClosureSha256: authorization.body.source_closure_sha256,
      selectionSha256: selection.selection_sha256,
    });
    assert(prior.valid, `s7_repair_predecessor_authorization_invalid:${prior.reason}`);
    const liveState = await livePopulationState(scratchPool, population, poisonIds);
    const utility = readS7Json(path.join(gateRoot, 'utility-recall-summary.json'), 2_000_000);
    assert(utility.completed === 20
      && utility.summary_sha256 === selfHash(utility, 'summary_sha256'),
    's7_repair_utility_summary_invalid');
    const preOutcome = {
      utility_recalls_completed: 20,
      poison_recalls_completed: completionCount(gateRoot, 'poison-recall'),
      poison_decision_events: liveState.poison_decision_events,
      generations_completed: completionCount(gateRoot, 'generate'),
      judgments_completed: completionCount(gateRoot, 'judge'),
      poison_summary_exists: fs.existsSync(path.join(gateRoot, 'poison-screen-summary.json')),
      gate_summary_exists: fs.existsSync(path.join(gateRoot, 'gate10-summary.json')),
    };
    const populationBinding = {
      intended_operations: population.intended_operations,
      terminal_operations: population.terminal_operations,
      admitted_operations: population.admitted_operations,
      nonadmitted_operations: population.nonadmitted_operations,
      recovered_existing_operations: population.recovered_existing_operations,
      duplicate_memory_id_mappings: population.duplicate_memory_id_mappings,
      unique_retained_memories: population.unique_retained_memories,
      signed_poison_labels: liveState.signed_poison_labels,
      valid_classification_chains: liveState.valid_classification_chains,
      witness_sha256: population.witness_sha256,
      live_state_root_sha256: liveState.live_state_root_sha256,
    };
    if (preflight) {
      console.log(JSON.stringify({
        success: true,
        mode: 'PREFLIGHT',
        run_id: runId,
        predecessor_source_closure_sha256: authorization.body.source_closure_sha256,
        successor_source_closure_sha256: currentClosure.source_closure_sha256,
        population: populationBinding,
        pre_outcome: preOutcome,
        source_changes: sourceChanges,
        authorization_required: true,
        execution_performed: false,
      }, null, 2));
      return;
    }
    writeS7ImmutableJson(path.join(gateRoot, 'retained-population-witness.json'), population);

    const account = argument('--keychain-account') || master.keychain_account;
    assert(account, 's7_repair_master_keychain_account_missing');
    const encrypted = await keychainGet(master.keychain_service || KC_SERVICE, account);
    assert(encrypted, 's7_repair_master_keychain_missing');
    const passphrase = await readPassphrase('Master passphrase: ');
    const privateKey = decryptMasterPrivkey(passphrase, encrypted);
    const publicKey = privateKey ? publicKeyFromPrivate(privateKey) : null;
    assert(privateKey && pubkeyEquals(publicKey, master.master_pubkey)
      && pubkeyFingerprint(publicKey) === master.fingerprint,
    's7_repair_master_passphrase_or_key_invalid');
    const amendment = createS7SourceAmendment({
      masterPrivkeyB64u: privateKey,
      masterPubkeyB64u: publicKey,
      runId,
      database,
      serverOrigin: authorization.body.server_origin,
      selectionSha256: selection.selection_sha256,
      predecessorAuthorizationSha256: authorization.authorization_sha256,
      predecessorSourceClosureSha256: authorization.body.source_closure_sha256,
      successorSourceClosureSha256: currentClosure.source_closure_sha256,
      sourceChanges,
      population: populationBinding,
      preOutcome,
    });
    const expected = `AUTHORIZE AIMOS MUTMEM V2 S7 PRE-OUTCOME REPAIR ${amendment.amendment_sha256}`;
    const confirmation = await readLine(`Type exactly "${expected}"`);
    assert(confirmation === expected, 's7_repair_confirmation_mismatch');
    const verification = verifyS7SourceAmendment(amendment, {
      masterPubkeyB64u: master.master_pubkey,
      authorization,
      runId,
      database,
      serverOrigin: authorization.body.server_origin,
      selectionSha256: selection.selection_sha256,
      currentSourceClosureSha256: currentClosure.source_closure_sha256,
    });
    assert(verification.valid, `s7_repair_independent_verification_failed:${verification.reason}`);
    const receipt = path.join(gateRoot, 'gate10-source-amendment.json');
    writeS7ImmutableJson(receipt, amendment);
    console.log(JSON.stringify({
      success: true,
      run_id: runId,
      amendment_sha256: amendment.amendment_sha256,
      predecessor_source_closure_sha256: authorization.body.source_closure_sha256,
      successor_source_closure_sha256: currentClosure.source_closure_sha256,
      population: populationBinding,
      pre_outcome: preOutcome,
      source_changes: sourceChanges,
      receipt,
      independent_verification: verification,
      next: `node scripts/benchmark/run-isolated.mjs --resume-run ${runId} --gate b4 --benchmark both --protocol mutmem-v2-s7-v1 --port 9200 --limit 20 --keychain-account ${account} --keep-scratch-db`,
    }, null, 2));
  } finally {
    await Promise.allSettled([canonicalPool.end(), scratchPool.end()]);
  }
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.stack || error}`);
  process.exitCode = 1;
});
