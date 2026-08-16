#!/usr/bin/env node

/**
 * Read-only TP-G5 Gate-10 verifier.
 *
 * Verifies the frozen contract, completed attempt topology, artifact hashes,
 * paired candidate identity, aggregate reconstruction, inherited master trust
 * receipt, and the signed scratch-only policy chain. The emitted receipt
 * authorizes only the preregistered Gate-50 evaluation; it does not promote T.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { pool, agentPool } from '../../db/connection.js';
import { scoreRetrievalEvidence } from '../../eval/aggregate-canonical-results.mjs';
import {
  TP_G5_GATE_CONTRACT,
  TP_G5_MODELS,
  buildG5ArmPolicy,
  selfHash,
  verifyG5PilotContract,
} from '../../eval/twin-prime/g5-protocol.mjs';
import { verifyBenchmarkMasterTrustReceipt } from '../../eval/twin-prime/g5-scratch-trust-root.mjs';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import { canonicalJson } from '../../services/security/agent-identity.js';
import { systemConfigStore } from '../../services/security/system-config-store.js';

const ROOT = path.resolve(import.meta.dirname, '..', '..');
const GATE = 'gate10';
const ARMS = TP_G5_GATE_CONTRACT[GATE].arms;
const PHASES = Object.freeze(['recall', 'generate', 'judge']);

function cliValue(name) {
  const inline = process.argv.find((argument) => argument.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function readJson(file) {
  const stat = fs.lstatSync(file);
  assert(stat.isFile() && !stat.isSymbolicLink(), `tp_g5_verify_file_invalid:${file}`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256File(file) {
  return sha256(fs.readFileSync(file));
}

function canonicalHashFile(file) {
  return sha256(Buffer.from(canonicalJson(readJson(file)), 'utf8'));
}

function exact(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function isHash(value) {
  return /^[0-9a-f]{64}$/.test(String(value || ''));
}

function mean(values) {
  return values.length ? values.reduce((sum, value) => sum + Number(value), 0) / values.length : null;
}

function percentile95(values) {
  const sorted = [...values].map(Number).sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)] ?? null;
}

function sessionMap(sessions, scopeId) {
  const scope = sessions.scopes.find((entry) => entry.scope_id === scopeId);
  assert(scope, `tp_g5_verify_session_scope_missing:${scopeId}`);
  return new Map(scope.sessions.map((session) => [session.source_session_id, session.session_id]));
}

function verifyRunEnvelope({ runId, runDir, contractDir }) {
  const status = readJson(path.join(runDir, 'run-status.json'));
  assert(status.run_id === runId
    && status.state === 'complete'
    && status.phase === 'complete'
    && status.resumable === false
    && !status.error,
  'tp_g5_verify_run_status_invalid');

  const manifest = readJson(path.join(runDir, 'run-manifest.json'));
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.manifest_sha256;
  assert(manifest.manifest_sha256 === sha256(JSON.stringify(unsignedManifest)),
    'tp_g5_verify_run_manifest_hash_invalid');
  assert(manifest.run_id === runId
    && manifest.database_name === `aimos_benchmark_${runId}`
    && manifest.configuration?.protocol === 'twin-prime-g5-v1'
    && manifest.configuration?.benchmark === 'both'
    && manifest.configuration?.gate === 'b4'
    && manifest.configuration?.gate_name === GATE
    && manifest.configuration?.question_count === 10
    && exact(manifest.configuration?.arms, ARMS)
    && manifest.configuration?.recall_depth_k === 20
    && manifest.configuration?.phase_retries === 6
    && manifest.configuration?.effective_policy_authority === 'signed_system_config_ledger'
    && manifest.configuration?.t_enforcement_scope === 'exact_scratch_database_only'
    && manifest.configuration?.canonical_policy_unchanged === true,
  'tp_g5_verify_run_manifest_binding_invalid');

  const contractFile = path.join(contractDir, 'pilot-contract.json');
  const contract = readJson(contractFile);
  assert(verifyG5PilotContract(contract), 'tp_g5_verify_contract_invalid');
  assert(contract.pilot_contract_sha256 === manifest.configuration.pilot_contract_sha256,
    'tp_g5_verify_contract_run_mismatch');
  assert(sha256File(contractFile) === manifest.datasets?.twin_prime_g5_pilot_contract?.sha256,
    'tp_g5_verify_contract_bytes_drift');

  const artifactManifest = readJson(path.join(contractDir, 'artifact-manifest.json'));
  assert(artifactManifest.artifact_manifest_sha256
    === selfHash(artifactManifest, 'artifact_manifest_sha256'),
  'tp_g5_verify_artifact_manifest_hash_invalid');
  assert(artifactManifest.artifact_manifest_sha256 === manifest.configuration.artifact_manifest_sha256,
    'tp_g5_verify_artifact_manifest_run_mismatch');
  for (const entry of artifactManifest.files) {
    const file = path.join(contractDir, entry.file);
    const value = readJson(file);
    const hashKey = entry.file === 'pilot-contract.json'
      ? 'pilot_contract_sha256'
      : 'private_map_sha256';
    assert(sha256File(file) === entry.bytes_sha256
      && value[hashKey] === entry.canonical_sha256
      && selfHash(value, hashKey) === entry.canonical_sha256,
    `tp_g5_verify_contract_artifact_invalid:${entry.file}`);
  }

  const artifactHashes = readJson(path.join(runDir, 'artifact-hashes.json'));
  let artifactFilesVerified = 0;
  for (const [relative, expected] of Object.entries(artifactHashes)) {
    const file = path.join(runDir, relative);
    assert(isHash(expected)
      && fs.existsSync(file)
      && fs.lstatSync(file).isFile()
      && !fs.lstatSync(file).isSymbolicLink()
      && sha256File(file) === expected,
    `tp_g5_verify_artifact_invalid:${relative}`);
    artifactFilesVerified += 1;
  }

  const isolation = readJson(path.join(runDir, 'isolation-proof.json'));
  assert(isolation.run_id === runId
    && isolation.protocol === 'twin-prime-g5-v1'
    && isolation.scope === 'gate10:10-questions:four-arms'
    && isolation.scratch?.database_name === `aimos_benchmark_${runId}`
    && isolation.scratch?.retained === true
    && isolation.scratch?.pre_purge_artifacts?.verified === true
    && isolation.canonical?.untouched === true
    && exact(isolation.canonical.before, isolation.canonical.after),
  'tp_g5_verify_isolation_invalid');

  return { manifest, contract, artifactManifest, artifactFilesVerified };
}

function verifyAttempts({ runId, gateDir, contract }) {
  const selection = readJson(path.join(gateDir, 'selection.json'));
  assert(selection.selection_sha256 === selfHash(selection, 'selection_sha256')
    && selection.run_id === runId
    && selection.gate === GATE
    && selection.pilot_contract_sha256 === contract.pilot_contract_sha256
    && selection.question_count === 10
    && exact(selection.arms, ARMS),
  'tp_g5_verify_selection_invalid');
  const publicSelection = selection.entries.map(({
    unit_sha256: unitSha256,
    question_id_sha256: questionIdSha256,
    dataset,
    category,
    fold,
  }) => ({
    unit_sha256: unitSha256,
    question_id_sha256: questionIdSha256,
    dataset,
    category,
    fold,
  }));
  assert(exact(publicSelection, contract.selections.gate10.entries),
    'tp_g5_verify_selection_contract_mismatch');

  const phaseSummaries = {};
  for (const phase of PHASES) {
    const summary = readJson(path.join(gateDir, `${phase}-summary.json`));
    assert(summary.summary_sha256 === selfHash(summary, 'summary_sha256')
      && summary.run_id === runId
      && summary.gate === GATE
      && summary.completed === 40
      && summary.reused === 0,
    `tp_g5_verify_phase_summary_invalid:${phase}`);
    if (phase !== 'recall') {
      assert(summary.phase === phase, `tp_g5_verify_phase_name_invalid:${phase}`);
    }
    phaseSummaries[phase] = summary.summary_sha256;
  }

  const sessionsByDataset = Object.fromEntries(['locomo', 'longmemeval'].map((dataset) => [
    dataset,
    readJson(path.join(ROOT, 'eval', 'data', 'twin-prime-g1p-canonical-v2', `${dataset}-sessions.json`)),
  ]));
  const observations = new Map();
  const attemptArtifacts = new Map();
  let completedAttempts = 0;
  let listedFilesVerified = 0;
  let failedAttempts = 0;
  let recallReceiptsVerified = 0;
  let pairedUnitsVerified = 0;

  for (const entry of selection.entries) {
    const unitDir = path.join(gateDir, 'questions', entry.unit_sha256);
    const inputFile = path.join(unitDir, 'input.json');
    const goldFile = path.join(unitDir, 'gold.json');
    assert(canonicalHashFile(inputFile) === entry.input_sha256
      && canonicalHashFile(goldFile) === entry.gold_sha256,
    `tp_g5_verify_question_hash_invalid:${entry.unit_sha256}`);
    const input = readJson(inputFile);
    const gold = readJson(goldFile);
    const unitObservations = [];

    for (const arm of ARMS) {
      for (const phase of PHASES) {
        const phaseDir = path.join(unitDir, arm, phase);
        const attempts = fs.readdirSync(phaseDir)
          .filter((name) => name.startsWith('attempt-'))
          .sort();
        assert(exact(attempts, ['attempt-0001']),
          `tp_g5_verify_attempt_topology_invalid:${entry.unit_sha256}:${arm}:${phase}`);
        const attemptDir = path.join(phaseDir, 'attempt-0001');
        const names = fs.readdirSync(attemptDir);
        failedAttempts += names.filter((name) => name === 'failure.json').length;
        const complete = readJson(path.join(attemptDir, 'complete.json'));
        assert(complete.schema === 'hom.aimos.twin-prime-pilot-attempt-complete/v1'
          && complete.phase === phase
          && complete.status === 'success'
          && complete.complete_sha256 === selfHash(complete, 'complete_sha256'),
        `tp_g5_verify_attempt_complete_invalid:${entry.unit_sha256}:${arm}:${phase}`);
        for (const [name, expected] of Object.entries(complete.files)) {
          const file = path.join(attemptDir, name);
          assert(sha256File(file) === expected,
            `tp_g5_verify_attempt_artifact_invalid:${entry.unit_sha256}:${arm}:${phase}:${name}`);
          listedFilesVerified += 1;
        }
        completedAttempts += 1;

        if (phase === 'recall') {
          const observation = readJson(path.join(attemptDir, 'arm-observation.json'));
          const policy = buildG5ArmPolicy(arm);
          assert(observation.observation_sha256 === selfHash(observation, 'observation_sha256')
            && observation.unit_sha256 === entry.unit_sha256
            && observation.dataset === entry.dataset
            && observation.category === entry.category
            && observation.fold === entry.fold
            && observation.arm === arm
            && observation.lambda_t === policy.lambda_t
            && observation.gamma === policy.gamma,
          `tp_g5_verify_observation_invalid:${entry.unit_sha256}:${arm}`);
          const verification = readJson(path.join(attemptDir, 'verification.json'));
          const response = readJson(path.join(attemptDir, 'recall-response.json'));
          assert(verification.verified === true
            && verification.result_count === response.memories.length
            && isHash(verification.command_hash)
            && isHash(verification.outer_request_hash)
            && isHash(verification.merkle_root),
          `tp_g5_verify_recall_receipt_invalid:${entry.unit_sha256}:${arm}`);
          const expected = entry.dataset === 'locomo'
            ? (gold.expected_evidence || [])
            : (gold.answer_session_ids || []);
          const retrieval = scoreRetrievalEvidence({
            benchmark: entry.dataset,
            memories: response.memories || [],
            expectedEvidence: expected,
            sourceToCanonical: sessionMap(sessionsByDataset[entry.dataset], input.scope_id),
          });
          attemptArtifacts.set(`${entry.unit_sha256}:${arm}:recall`, {
            observation,
            retrieval,
            latency: readJson(path.join(attemptDir, 'timings.json')).latency_ms,
          });
          unitObservations.push(observation);
          observations.set(`${entry.unit_sha256}:${arm}`, observation);
          recallReceiptsVerified += 1;
        } else {
          const provider = readJson(path.join(attemptDir, 'provider-evidence.json'));
          const expectedModel = phase === 'generate'
            ? TP_G5_MODELS.generator_model
            : TP_G5_MODELS.judge_model;
          const expectedReasoning = phase === 'generate'
            ? TP_G5_MODELS.generator_reasoning
            : TP_G5_MODELS.judge_reasoning;
          assert(provider.provider === 'codex'
            && provider.requested_model === expectedModel
            && provider.actual_model === expectedModel
            && provider.reasoning_effort === expectedReasoning
            && provider.status === 'completed'
            && provider.credential_use?.outcome === 'completed',
          `tp_g5_verify_provider_invalid:${entry.unit_sha256}:${arm}:${phase}`);
          attemptArtifacts.set(`${entry.unit_sha256}:${arm}:${phase}`, {
            verdict: phase === 'judge' ? readJson(path.join(attemptDir, 'verdict.json')) : null,
            usage: provider.usage,
            latency: readJson(path.join(attemptDir, 'timings.json')).latency_ms,
          });
        }
      }
    }
    assert(unitObservations.every((value) => value.paired_identity_sha256
      === unitObservations[0].paired_identity_sha256),
    `tp_g5_verify_paired_identity_invalid:${entry.unit_sha256}`);
    assert(unitObservations.every((value) => exact(
      value.admitted_candidate_id_hashes,
      unitObservations[0].admitted_candidate_id_hashes,
    )), `tp_g5_verify_pre_arm_candidates_invalid:${entry.unit_sha256}`);
    pairedUnitsVerified += 1;
  }
  assert(completedAttempts === 120
    && failedAttempts === 0
    && recallReceiptsVerified === 40
    && pairedUnitsVerified === 10,
  'tp_g5_verify_attempt_denominator_invalid');

  return {
    selection,
    phaseSummaries,
    observations,
    attemptArtifacts,
    counts: {
      completed_attempts: completedAttempts,
      listed_attempt_files_verified: listedFilesVerified,
      failed_attempts: failedAttempts,
      recall_receipts_verified: recallReceiptsVerified,
      paired_units_verified: pairedUnitsVerified,
    },
  };
}

function verifyTransitions({ runId, gateDir, selection, observations }) {
  const transitions = ARMS.map((arm) => readJson(path.join(gateDir, 'transitions', `${arm}.json`)));
  for (let index = 0; index < transitions.length; index += 1) {
    const transition = transitions[index];
    const arm = ARMS[index];
    const expectedPrevious = index === 0 ? null : transitions[index - 1].mutation_hash;
    assert(transition.schema === 'hom.aimos.twin-prime-signed-pilot-transition/v1'
      && transition.run_id === runId
      && transition.database === `aimos_benchmark_${runId}`
      && transition.gate === GATE
      && transition.arm === arm
      && exact(transition.policy, buildG5ArmPolicy(arm))
      && isHash(transition.mutation_hash)
      && transition.prev_mutation_hash === expectedPrevious
      && transition.reused === false,
    `tp_g5_verify_transition_invalid:${arm}`);
    for (const entry of selection.entries) {
      assert(observations.get(`${entry.unit_sha256}:${arm}`).policy_mutation_hash
        === transition.mutation_hash,
      `tp_g5_verify_observation_transition_invalid:${entry.unit_sha256}:${arm}`);
    }
  }
  const recallSummary = readJson(path.join(gateDir, 'recall-summary.json'));
  const trustReceipt = readJson(path.join(gateDir, 'scratch-master-trust-root-receipt.json'));
  assert(recallSummary.summary_sha256 === selfHash(recallSummary, 'summary_sha256')
    && recallSummary.transition_count === 4
    && recallSummary.identical_pre_arm_candidates === true
    && exact(recallSummary.transitions, transitions)
    && recallSummary.scratch_master_trust_receipt_sha256 === trustReceipt.receipt_sha256,
  'tp_g5_verify_recall_summary_invalid');
  return { transitions, trustReceipt, recallSummary };
}

function verifyPilotSummary({ runId, gateDir, contract, attempts }) {
  const pilot = readJson(path.join(gateDir, 'pilot-summary.json'));
  assert(pilot.summary_sha256 === selfHash(pilot, 'summary_sha256')
    && pilot.run_id === runId
    && pilot.gate === GATE
    && pilot.pilot_contract_sha256 === contract.pilot_contract_sha256
    && pilot.question_count === 10
    && pilot.arm_question_outputs === 40
    && pilot.rows.length === 40
    && exact(pilot.models, TP_G5_MODELS)
    && pilot.failure_resume_idempotency?.immutable_attempts === true
    && pilot.failure_resume_idempotency?.successful_attempts_per_unit_phase === 1
    && Object.values(pilot.failure_resume_idempotency?.reused_counts || {})
      .every((value) => value === 0),
  'tp_g5_verify_pilot_summary_invalid');

  for (const row of pilot.rows) {
    const recall = attempts.get(`${row.unit_sha256}:${row.arm}:recall`);
    const generated = attempts.get(`${row.unit_sha256}:${row.arm}:generate`);
    const judged = attempts.get(`${row.unit_sha256}:${row.arm}:judge`);
    assert(row.observation_sha256 === recall.observation.observation_sha256
      && exact(row.retrieval, recall.retrieval)
      && exact(row.verdict, judged.verdict)
      && row.latency_ms.recall === recall.latency
      && row.latency_ms.generate === generated.latency
      && row.latency_ms.judge === judged.latency
      && exact(row.usage.generator, generated.usage)
      && exact(row.usage.judge, judged.usage),
    `tp_g5_verify_pilot_row_invalid:${row.unit_sha256}:${row.arm}`);
  }

  for (const [arm, aggregate] of Object.entries(pilot.by_arm)) {
    const rows = pilot.rows.filter((row) => row.arm === arm);
    const eligible = rows.filter((row) => row.retrieval.eligible);
    assert(aggregate.questions === 10
      && aggregate.judged_correct === rows.filter((row) => row.verdict.correct === true).length
      && aggregate.judged_accuracy === mean(rows.map((row) => Number(row.verdict.correct === true)))
      && aggregate.mean_evidence_recall_at_20
        === mean(eligible.map((row) => row.retrieval.evidence_recall_at_k))
      && aggregate.mean_hit_at_1 === mean(eligible.map((row) => Number(row.retrieval.hit_at_1)))
      && aggregate.mean_ndcg_at_20 === mean(eligible.map((row) => row.retrieval.ndcg_at_k)),
    `tp_g5_verify_pilot_aggregate_invalid:${arm}`);
  }
  return pilot;
}

function verifyReplays({ runId, runDir }) {
  const expectedCounts = { locomo: 111, longmemeval: 247 };
  const replays = {};
  for (const [benchmark, expected] of Object.entries(expectedCounts)) {
    const matches = fs.readdirSync(runDir)
      .filter((name) => name.startsWith(`replay-summary-${benchmark}-`) && name.endsWith('.json'));
    assert(matches.length === 1, `tp_g5_verify_replay_summary_count_invalid:${benchmark}`);
    const summary = readJson(path.join(runDir, matches[0]));
    const unsignedSummary = { ...summary };
    delete unsignedSummary.summary_sha256;
    assert(summary.summary_sha256 === sha256(JSON.stringify(unsignedSummary))
      && summary.run_id === runId
      && summary.database_name === `aimos_benchmark_${runId}`
      && summary.completed_sessions === expected
      && summary.failed_sessions === 0
      && summary.reused_session_proofs === 0,
    `tp_g5_verify_replay_invalid:${benchmark}`);
    replays[benchmark] = {
      completed_sessions: summary.completed_sessions,
      failed_sessions: 0,
      reused_session_proofs: 0,
      summary_sha256: summary.summary_sha256,
    };
  }
  return replays;
}

async function verifyLiveScratchTrust({ runId, database, gateDir, transitions, trustReceipt }) {
  const loaded = await systemConfigStore.loadAll();
  assert(loaded.ok, `tp_g5_verify_signed_config_invalid:${loaded.reason || ''}`);
  const active = systemConfigStore.readVerifiedConfig('TWIN_PRIME_RETRIEVAL_POLICY');
  assert(active?.mutation_hash === transitions.at(-1).mutation_hash
    && exact(JSON.parse(active.value), transitions.at(-1).policy),
  'tp_g5_verify_active_policy_invalid');

  const masterResult = await pool.query(
    `SELECT id, master_pubkey, fingerprint, created_at, revocation_cert_hash,
            keychain_service, keychain_account
       FROM aimos_master_identity WHERE id = 1`,
  );
  assert(masterResult.rows.length === 1, 'tp_g5_verify_master_missing');
  const trust = verifyBenchmarkMasterTrustReceipt(trustReceipt, {
    runId,
    targetDatabase: database,
    canonicalMaster: masterResult.rows[0],
  });
  assert(trust.valid, `tp_g5_verify_trust_receipt_invalid:${trust.reason}`);

  const rows = await pool.query(
    `SELECT value_text, cert_fingerprint,
            encode(mutation_hash, 'hex') AS mutation_hash,
            CASE WHEN prev_mutation_hash IS NULL THEN NULL
                 ELSE encode(prev_mutation_hash, 'hex') END AS prev_mutation_hash,
            ts_signed, is_genesis
       FROM aimos_system_config
      WHERE config_key = 'TWIN_PRIME_RETRIEVAL_POLICY'
      ORDER BY created_at ASC, config_id ASC`,
  );
  assert(rows.rows.length === transitions.length, 'tp_g5_verify_live_transition_count_invalid');
  for (let index = 0; index < rows.rows.length; index += 1) {
    const row = rows.rows[index];
    const transition = transitions[index];
    assert(exact(JSON.parse(row.value_text), transition.policy)
      && row.cert_fingerprint === transition.master_fingerprint
      && row.mutation_hash === transition.mutation_hash
      && row.prev_mutation_hash === transition.prev_mutation_hash
      && Number(row.ts_signed) === Number(transition.ts_signed)
      && Boolean(row.is_genesis) === (index === 0),
    `tp_g5_verify_live_transition_invalid:${transition.arm}`);
  }
  return {
    signed_config_store_verified: true,
    trust_receipt_verified: true,
    master_fingerprint: trust.master_fingerprint,
    transition_count: rows.rows.length,
    active_policy_mutation_hash: active.mutation_hash,
  };
}

async function main() {
  const runId = String(cliValue('--run-id') || '').trim();
  assert(/^\d{14}_[0-9a-f]{6}$/.test(runId), 'tp_g5_verify_run_id_invalid');
  const database = resolveAimosDatabaseName();
  assert(database === `aimos_benchmark_${runId}`, 'tp_g5_verify_database_mismatch');
  const runDir = path.resolve(cliValue('--run-dir') || path.join(ROOT, 'eval', 'public-results', runId));
  const gateDir = path.join(runDir, 'twin-prime-g5', GATE);
  const contractDir = path.join(ROOT, 'eval', 'twin-prime', 'tp-g5-contract-v6');
  const receiptFile = path.resolve(cliValue('--receipt-file') || path.join(
    ROOT,
    'artifacts',
    'twin-prime',
    'tp-g5',
    `gate10-verification-${runId}.json`,
  ));

  const envelope = verifyRunEnvelope({ runId, runDir, contractDir });
  const attemptEvidence = verifyAttempts({ runId, gateDir, contract: envelope.contract });
  const transitionEvidence = verifyTransitions({
    runId,
    gateDir,
    selection: attemptEvidence.selection,
    observations: attemptEvidence.observations,
  });
  const pilot = verifyPilotSummary({
    runId,
    gateDir,
    contract: envelope.contract,
    attempts: attemptEvidence.attemptArtifacts,
  });
  const replays = verifyReplays({ runId, runDir });
  const liveTrust = await verifyLiveScratchTrust({
    runId,
    database,
    gateDir,
    transitions: transitionEvidence.transitions,
    trustReceipt: transitionEvidence.trustReceipt,
  });

  const b2Rows = pilot.rows.filter((row) => row.arm === 'B2');
  const tRows = pilot.rows.filter((row) => row.arm === 'T');
  const changedSelections = attemptEvidence.selection.entries.filter((entry) => !exact(
    attemptEvidence.observations.get(`${entry.unit_sha256}:B2`).computed_selected_id_hashes,
    attemptEvidence.observations.get(`${entry.unit_sha256}:T`).computed_selected_id_hashes,
  )).length;
  const receipt = {
    schema: 'hom.aimos.twin-prime-gate-verification/v1',
    protocol: 'hom-aimos/twin-prime-pilots/v1',
    run_id: runId,
    database,
    gate: GATE,
    verdict: 'verified_end_to_end_correctness',
    authorizes_next_preregistered_gate: 'gate50',
    does_not_authorize: ['canonical_T_enforcement', 'feature_promotion', 'efficacy_claim'],
    scope_note: 'Gate-10 verifies integrity and end-to-end completeness. Gate-50 remains required under the no-early-stopping rule.',
    bindings: {
      run_manifest_sha256: envelope.manifest.manifest_sha256,
      pilot_contract_sha256: envelope.contract.pilot_contract_sha256,
      contract_artifact_manifest_sha256: envelope.artifactManifest.artifact_manifest_sha256,
      selection_sha256: attemptEvidence.selection.selection_sha256,
      pilot_summary_sha256: pilot.summary_sha256,
      phase_summary_sha256: attemptEvidence.phaseSummaries,
      replay_summary: replays,
    },
    integrity: {
      artifact_files_verified: envelope.artifactFilesVerified,
      ...attemptEvidence.counts,
      signed_transition_artifacts_verified: transitionEvidence.transitions.length,
      identical_pre_arm_candidate_sets: true,
      canonical_database_untouched: true,
      ...liveTrust,
    },
    observed_results: pilot.by_arm,
    diagnostics: {
      T_vs_B2: {
        computed_selection_changes: changedSelections,
        question_count: 10,
        evidence_recall_at_20_delta: pilot.by_arm.T.mean_evidence_recall_at_20
          - pilot.by_arm.B2.mean_evidence_recall_at_20,
        hit_at_1_delta: pilot.by_arm.T.mean_hit_at_1 - pilot.by_arm.B2.mean_hit_at_1,
        ndcg_at_20_delta: pilot.by_arm.T.mean_ndcg_at_20 - pilot.by_arm.B2.mean_ndcg_at_20,
        judged_accuracy_delta: pilot.by_arm.T.judged_accuracy - pilot.by_arm.B2.judged_accuracy,
        B2_recall_p95_ms: percentile95(b2Rows.map((row) => row.latency_ms.recall)),
        T_recall_p95_ms: percentile95(tRows.map((row) => row.latency_ms.recall)),
      },
    },
  };
  receipt.receipt_sha256 = selfHash(receipt, 'receipt_sha256');
  fs.mkdirSync(path.dirname(receiptFile), { recursive: true, mode: 0o700 });
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ success: true, receipt: receiptFile, ...receipt }, null, 2));
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
