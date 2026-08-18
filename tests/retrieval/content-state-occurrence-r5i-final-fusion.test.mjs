import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { NATIVE_RETRIEVAL_FUSION_CONTRACT } from '../../services/retrieval/native-retrieval-fusion.js';
import { GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT } from '../../services/retrieval/reconstructed-graph-additive/graph-family-bounded-fusion.js';

test('R5I production binds exactly three named recompositions and one final fusion', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const runtime = source.slice(source.indexOf('export async function executeNativeRecall'));
  assert.equal((runtime.match(/fuseNativeRetrievalGears\(\{/g) || []).length, 3);
  assert.equal((runtime.match(/requireGraphFamilyContract: true/g) || []).length, 2);
  assert.equal((runtime.match(/requireGraphFamilyContract: false/g) || []).length, 1);
  for (const phase of NATIVE_RETRIEVAL_FUSION_CONTRACT.production_phases) {
    assert.equal((runtime.match(new RegExp(`fusionPhase: '${phase}'`, 'g')) || []).length, 1);
  }
  const concept = runtime.indexOf("markStage('concept_graph_ppr')");
  const finalFusion = runtime.indexOf("fusionPhase: 'final_post_concept_ppr'", concept);
  const finalEvidence = runtime.indexOf("evidence_stage: 'final_post_concept_ppr'", finalFusion);
  const calibration = runtime.indexOf("markStage('recall_calibration')", finalEvidence);
  const epistemic = runtime.indexOf("markStage('epistemic_trust_selection')", calibration);
  assert.ok(concept >= 0);
  assert.ok(finalFusion > concept);
  assert.ok(finalEvidence > finalFusion);
  assert.ok(calibration > finalEvidence);
  assert.ok(epistemic > calibration);
  assert.match(runtime.slice(finalFusion, calibration), /baseline_fusion: nativeRetrievalFusion/);
  assert.match(runtime.slice(finalFusion, calibration), /final_fusion: nativeRetrievalFusion/);
  assert.match(runtime.slice(finalFusion, calibration), /final_production_fusion: true/);
});

test('R5I central contract exposes one graph-family outer channel and no subgear vote', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.graph_family_channel_key, 'graph_family');
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.graph_family_outer_channel_count, 1);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('magma'), false);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('reconstructed_graph'), false);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('graph_family'), true);
  assert.equal(GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT.runtime_wired, true);
  assert.equal(GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT.maximum_outer_channels, 1);
  assert.equal(GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT.duplicate_signal_idempotent, true);
});

test('R5I mathematical contract keeps the paper k and equal peer weights', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.rrf_k, 60);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.equation,
    'weighted_reciprocal_rank_fusion');
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.paper_authority,
    'Cormack_et_al_2009_and_MAGMA_equation_4');
  assert.deepEqual(
    [...NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set].sort(),
    [...NATIVE_RETRIEVAL_FUSION_CONTRACT.gears].sort(),
  );
});

test('R5I baseline preservation is linear membership, not quadratic scanning', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-retrieval-fusion.js', import.meta.url),
    'utf8',
  );
  assert.match(source, /const selectedIdSet = new Set\(selectedIds\)/);
  assert.match(source, /baselineIds\.some\(\(id\) => !selectedIdSet\.has\(id\)\)/);
  assert.doesNotMatch(source, /baselineIds\.(?:some|every)\(\(id\) => [^\n]*selectedIds\.includes\(id\)/);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.time_complexity,
    'O(sum_channel_lengths + candidate_count_log_candidate_count)');
});
