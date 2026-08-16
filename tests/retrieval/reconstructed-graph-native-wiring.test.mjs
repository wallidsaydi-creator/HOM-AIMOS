import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { calibrateNativeRecallResponse } from '../../services/retrieval/recall-output-calibrator.js';

test('G2 is a permanent bounded subgear inside one graph-family channel before disclosure', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const admission = source.indexOf('const mainAdmission = await admitNativeRecallCandidates');
  const magma = source.indexOf('magmaCandidate = await composeMagmaNativeCandidate', admission);
  const baselineFamily = source.indexOf('graphFamilyCandidate = composeNativeGraphFamilyChannel', magma);
  const baselineFusion = source.indexOf('const graphFamilyBaselineFusion = fuseNativeRetrievalGears', baselineFamily);
  const canary = source.indexOf('const reconstructedGraphCanaryPartition = partitionGraphCanaryDisclosure', baselineFusion);
  const g2 = source.indexOf('reconstructedGraphCandidate = composeReconstructedGraphNativeCandidate', canary);
  const candidateFamily = source.indexOf('graphFamilyCandidate = composeNativeGraphFamilyChannel', g2);
  const centralFusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', candidateFamily);
  const earlyExit = source.indexOf("markStage('early_exit_decision')", centralFusion);
  const postGraphAdmission = source.indexOf('const postGraphAdmission = await admitNativeRecallCandidates', earlyExit);
  const refusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', postGraphAdmission);
  const epistemic = source.indexOf("markStage('epistemic_trust_selection')", refusion);
  const magmaClosure = source.indexOf("graphId: 'magma'", epistemic);
  const g2Closure = source.indexOf("graphId: 'reconstructed_graph'", magmaClosure);
  const disclosure = source.indexOf('const disclosureMemories = reconstructedGraphSecurity.memories', g2Closure);
  const receipt = source.indexOf('calibratedRecallResponse.recall_receipt = await finalizeNativeRecall', disclosure);

  assert.ok(admission >= 0);
  assert.ok(magma > admission);
  assert.ok(baselineFamily > magma);
  assert.ok(baselineFusion > baselineFamily);
  assert.ok(canary > baselineFusion);
  assert.ok(g2 > canary);
  assert.ok(candidateFamily > g2);
  assert.ok(centralFusion > candidateFamily);
  assert.ok(earlyExit > centralFusion);
  assert.ok(postGraphAdmission > earlyExit);
  assert.ok(refusion > postGraphAdmission);
  assert.ok(epistemic > refusion);
  assert.ok(magmaClosure > epistemic);
  assert.ok(g2Closure > magmaClosure);
  assert.ok(disclosure > g2Closure);
  assert.ok(receipt > disclosure);
  assert.match(source.slice(candidateFamily, centralFusion), /reconstructedGraphGear: reconstructedGraphCandidate/);
  assert.match(source.slice(refusion - 300, refusion + 300), /magmaGear: graphFamilyCandidate/);
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
    graph_id: 'reconstructed_graph',
    graph_decision_sha256: 'c'.repeat(64),
    canonical_memory_changed: false,
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
        reconstructed_graph_security_closure: closure,
      },
    },
  });

  assert.deepEqual(calibrated.recall_meta.graph_family_retrieval, graphFamily);
  assert.deepEqual(calibrated.recall_meta.reconstructed_graph_retrieval, reconstructed);
  assert.deepEqual(calibrated.recall_meta.reconstructed_graph_security_closure, closure);
  assert.equal(calibrated.memories[0].value, 'Evidence remains unchanged.');
});
