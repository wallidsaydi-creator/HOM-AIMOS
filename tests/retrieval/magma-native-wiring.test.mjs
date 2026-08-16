import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { calibrateNativeRecallResponse } from '../../services/retrieval/recall-output-calibrator.js';

test('MAGMA is an admission-first native gear fused before early exit and security-closed before disclosure', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const calibrationConfig = source.indexOf("readVerifiedConfig('MAGMA_RETRIEVAL_CALIBRATION')");
  const admission = source.indexOf('const mainAdmission = await admitNativeRecallCandidates');
  const candidate = source.indexOf('magmaCandidate = await composeMagmaNativeCandidate', admission);
  const fusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', candidate);
  const earlyExit = source.indexOf("markStage('early_exit_decision')", fusion);
  const postGraphAdmission = source.indexOf('const postGraphAdmission = await admitNativeRecallCandidates', earlyExit);
  const refusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', postGraphAdmission);
  const epistemic = source.indexOf("markStage('epistemic_trust_selection')", refusion);
  const canary = source.indexOf("graphId: 'magma'", epistemic);
  const reconstructedGraphClosure = source.indexOf("graphId: 'reconstructed_graph'", canary);
  const disclosure = source.indexOf(
    'const disclosureMemories = reconstructedGraphSecurity.memories',
    reconstructedGraphClosure,
  );
  const finalReceipt = source.indexOf('calibratedRecallResponse.recall_receipt = await finalizeNativeRecall', disclosure);

  assert.ok(calibrationConfig >= 0);
  assert.ok(admission >= 0);
  assert.ok(candidate > admission);
  assert.ok(fusion > candidate);
  assert.ok(earlyExit > fusion);
  assert.ok(postGraphAdmission > earlyExit);
  assert.ok(refusion > postGraphAdmission);
  assert.ok(epistemic > refusion);
  assert.ok(canary > epistemic);
  assert.ok(reconstructedGraphClosure > canary);
  assert.ok(disclosure > reconstructedGraphClosure);
  assert.ok(finalReceipt > disclosure);
  assert.doesNotMatch(source, /readVerifiedConfig\('MAGMA_RETRIEVAL_POLICY'\)/);
  assert.doesNotMatch(source, /magmaConfig|magmaShadowSecurity/);
  assert.match(source, /architecture_role: 'permanent_native_retrieval_gear'/);
  assert.match(source, /runtime_mode: null/);
  assert.match(source, /candidate_set_authority: false/);
  assert.match(source, /runtimeMs: magmaCandidateRuntimeMs/);
  assert.match(source, /baseline_candidate_memory_ids: magmaBaselineCandidateIds/);
});

test('MAGMA calibration is not activation, request, or ENV authority and retains bounded mathematics', async () => {
  const ledger = await readFile(
    new URL('../../services/security/system-config-ledger.js', import.meta.url),
    'utf8',
  );
  const candidate = await readFile(
    new URL('../../services/retrieval/magma-native-candidate.js', import.meta.url),
    'utf8',
  );
  const reader = await readFile(
    new URL('../../services/retrieval/magma-native-reader.js', import.meta.url),
    'utf8',
  );

  assert.match(ledger, /MAGMA_RETRIEVAL_CALIBRATION/);
  assert.match(ledger, /cannot enable, disable, shadow, enforce/);
  assert.match(ledger, /candidate_p95_ceiling_ms !== 250/);
  assert.match(ledger, /parsed\.max_depth < 1 \|\| parsed\.max_depth > 3/);
  assert.match(ledger, /parsed\.max_nodes < 50 \|\| parsed\.max_nodes > 200/);
  assert.doesNotMatch(candidate, /process\.env/);
  assert.doesNotMatch(reader, /process\.env/);
  assert.match(candidate, /execution_authority: 'verified_agent_or_role_identity_envelope'/);
  assert.match(reader, /governance_owner: 'housekeeper'/);
});

test('output calibration preserves native MAGMA gear evidence without changing memory data', () => {
  const magmaRetrieval = {
    architecture_role: 'permanent_native_retrieval_gear',
    runtime_mode: null,
    activation_authority: false,
    calibration_mutation_hash: 'a'.repeat(64),
    proof_sha256: 'b'.repeat(64),
    runner_sha256: 'c'.repeat(64),
    candidate_set_authority: false,
    decision: {
      decision_sha256: 'd'.repeat(64),
      edge_commitment_sha256: 'e'.repeat(64),
    },
  };
  const magmaSecurityClosure = {
    graph_id: 'magma',
    graph_decision_sha256: 'd'.repeat(64),
    canonical_memory_changed: false,
    retention_changed: false,
    saber_runtime_authority: false,
    receipt: { mutation_hash: 'f'.repeat(64) },
  };
  const calibrated = calibrateNativeRecallResponse({
    query: 'open full detail',
    runtimeBudget: { answer_shape: 'full_detail' },
    recallResponse: {
      success: true,
      memories: [{
        id: '11111111-1111-4111-8111-111111111111',
        key: 'retained-memory',
        value: 'Retained evidence remains unchanged.',
      }],
      recall_meta: {
        magma_retrieval: magmaRetrieval,
        magma_security_closure: magmaSecurityClosure,
      },
    },
  });

  assert.deepEqual(calibrated.recall_meta.magma_retrieval, magmaRetrieval);
  assert.deepEqual(calibrated.recall_meta.magma_security_closure, magmaSecurityClosure);
  assert.equal(calibrated.memories[0].value, 'Retained evidence remains unchanged.');
  assert.equal(calibrated.memories[0].magma_score, undefined);
});
