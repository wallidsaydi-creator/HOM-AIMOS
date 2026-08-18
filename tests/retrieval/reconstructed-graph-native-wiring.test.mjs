import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { calibrateNativeRecallResponse } from '../../services/retrieval/recall-output-calibrator.js';

test('G2 is a permanent bounded subgear inside one graph-family channel before disclosure', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const session = source.indexOf('verifiedAdmissionSession = await openNativeRecallAdmissionSession');
  const admission = source.indexOf('const mainAdmission = await contentStateOccurrenceAdmission.admit');
  const dormant = source.indexOf("skipStage('magma_native_gear', 'dormant_research_not_in_live_recall')", admission);
  const baselineFusion = source.indexOf('const graphFamilyBaselineFusion = fuseNativeRetrievalGears', dormant);
  const canary = source.indexOf('const reconstructedGraphCanaryPartition = partitionGraphCanaryDisclosure', baselineFusion);
  const stateSelection = source.indexOf('const reconstructedGraphStateSelection =', canary);
  const g2 = source.indexOf('reconstructedGraphCandidate = composeReconstructedGraphNativeCandidate', stateSelection);
  const candidateFamily = source.indexOf('graphFamilyCandidate = composeNativeGraphFamilyChannel', g2);
  const centralFusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', candidateFamily);
  const earlyExit = source.indexOf("markStage('early_exit_decision')", centralFusion);
  const postGraphAdmission = source.indexOf('const postGraphAdmission = await contentStateOccurrenceAdmission.admit', earlyExit);
  const refusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', postGraphAdmission);
  const epistemic = source.indexOf("markStage('epistemic_trust_selection')", refusion);
  const finalClosure = source.indexOf('const finalSecurityClosure = await governCanaryRecallFinalClosure({', epistemic);
  const disclosure = source.indexOf('const disclosureMemories = finalSecurityClosure.memories', finalClosure);
  const receipt = source.indexOf('calibratedRecallResponse = await calibrateAndFinalizeNativeRecallReturn', disclosure);

  assert.ok(session >= 0);
  assert.ok(admission > session);
  assert.ok(dormant > admission);
  assert.ok(baselineFusion > dormant);
  assert.ok(canary > baselineFusion);
  assert.ok(stateSelection > canary);
  assert.ok(g2 > stateSelection);
  assert.ok(candidateFamily > g2);
  assert.ok(centralFusion > candidateFamily);
  assert.ok(earlyExit > centralFusion);
  assert.ok(postGraphAdmission > earlyExit);
  assert.ok(refusion > postGraphAdmission);
  assert.ok(epistemic > refusion);
  assert.ok(finalClosure > epistemic);
  assert.ok(disclosure > finalClosure);
  assert.ok(receipt > disclosure);
  assert.match(source.slice(candidateFamily, centralFusion), /reconstructedGraphGear: reconstructedGraphCandidate/);
  assert.match(source.slice(stateSelection, g2 + 500), /contentStateSelectionDecision: reconstructedGraphStateSelection\.decision/);
  assert.match(source.slice(stateSelection, g2 + 500), /requireContentStateSelection: true/);
  assert.match(source.slice(refusion - 300, refusion + 300), /graphFamilyGear: graphFamilyCandidate/);
  assert.match(source.slice(finalClosure, disclosure), /reconstructed_graph_native_candidate: reconstructedGraphCandidate\?\.decision/);
  assert.match(source.slice(finalClosure, disclosure), /graph_family_channel: graphFamilyCandidate\?\.decision/);
  assert.match(source.slice(finalClosure, disclosure), /magma_dormancy: MAGMA_DORMANT_RUNTIME_DECISION/);
  assert.doesNotMatch(source, /magmaCandidate\s*=\s*await composeMagmaNativeCandidate/);
  assert.doesNotMatch(source, /graph-family-bounded-fusion\.js/);
  assert.doesNotMatch(source, /RECONSTRUCTED_GRAPH_RETRIEVAL_POLICY|process\.env\.RECONSTRUCTED/);
});

test('output calibration preserves G2 and graph-family evidence without changing memory data', () => {
  const graphFamily = {
    architecture_role: 'single_permanent_native_graph_family_channel',
    outer_channel_count: 1,
    subgear_count: 2,
    decision: { decision_sha256: 'a'.repeat(64) },
  };
  const reconstructed = {
    architecture_role: 'permanent_native_graph_family_subgear',
    runtime_mode: null,
    fixed_corpus_proof_file_sha256: 'b'.repeat(64),
    decision: { decision_sha256: 'c'.repeat(64) },
  };
  const closure = {
    schema: 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope',
    decision_sha256: 'c'.repeat(64),
    classification_map_root_sha256: 'd'.repeat(64),
    one_request_local_classification_map: true,
    canonical_memory_mutated: false,
    retention_changed: false,
    saber_runtime_authority: false,
  };
  const calibrated = calibrateNativeRecallResponse({
    query: 'open full detail',
    runtimeBudget: { answer_shape: 'full_detail' },
    recallResponse: {
      success: true,
      memories: [{ id: 'm1', key: 'retained', value: 'Evidence remains unchanged.' }],
      recall_meta: {
        graph_family_retrieval: graphFamily,
        reconstructed_graph_retrieval: reconstructed,
        recall_security_closure: closure,
      },
    },
  });

  assert.deepEqual(calibrated.recall_meta.graph_family_retrieval, graphFamily);
  assert.deepEqual(calibrated.recall_meta.reconstructed_graph_retrieval, reconstructed);
  assert.deepEqual(calibrated.recall_meta.recall_security_closure, closure);
  assert.equal(calibrated.memories[0].value, 'Evidence remains unchanged.');
});
