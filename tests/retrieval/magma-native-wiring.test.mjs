import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { calibrateNativeRecallResponse } from '../../services/retrieval/recall-output-calibrator.js';

test('MAGMA is retained as dormant research and has no canonical recall execution or vote', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const session = source.indexOf('verifiedAdmissionSession = await openNativeRecallAdmissionSession');
  const admission = source.indexOf('const mainAdmission = await contentStateOccurrenceAdmission.admit');
  const canaryGraphAdmission = source.indexOf(
    'const canaryMagmaComposition = await governCanaryMagmaGraphAdmission',
    admission,
  );
  const dormant = source.indexOf("skipStage('magma_native_gear', 'dormant_research_not_in_live_recall')", canaryGraphAdmission);
  const g2 = source.indexOf('reconstructedGraphCandidate = composeReconstructedGraphNativeCandidate', dormant);
  const fusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', g2);
  const earlyExit = source.indexOf("markStage('early_exit_decision')", fusion);
  const postGraphAdmission = source.indexOf('const postGraphAdmission = await contentStateOccurrenceAdmission.admit', earlyExit);
  const refusion = source.indexOf('nativeRetrievalFusion = fuseNativeRetrievalGears', postGraphAdmission);
  const epistemic = source.indexOf("markStage('epistemic_trust_selection')", refusion);
  const finalClosure = source.indexOf('const finalSecurityClosure = await governCanaryRecallFinalClosure({', epistemic);
  const disclosure = source.indexOf(
    'const disclosureMemories = finalSecurityClosure.memories',
    finalClosure,
  );
  const finalReceipt = source.indexOf('calibratedRecallResponse = await calibrateAndFinalizeNativeRecallReturn', disclosure);

  assert.ok(session >= 0);
  assert.ok(admission > session);
  assert.ok(canaryGraphAdmission > admission);
  assert.ok(dormant > canaryGraphAdmission);
  assert.ok(g2 > dormant);
  assert.ok(fusion > g2);
  assert.ok(earlyExit > fusion);
  assert.ok(postGraphAdmission > earlyExit);
  assert.ok(refusion > postGraphAdmission);
  assert.ok(epistemic > refusion);
  assert.ok(finalClosure > epistemic);
  assert.ok(disclosure > finalClosure);
  assert.ok(finalReceipt > disclosure);
  assert.match(source.slice(finalReceipt), /verifiedAdmissionSession\.close\(\{ commit: false \}\)/);
  assert.doesNotMatch(source, /readVerifiedConfig\('MAGMA_RETRIEVAL_(?:POLICY|CALIBRATION)'\)/);
  assert.doesNotMatch(source, /magmaCandidate\s*=\s*await composeMagmaNativeCandidate/);
  assert.doesNotMatch(source, /magmaGear:\s*graphFamilyCandidate/);
  assert.match(source, /architecture_role: 'dormant_research_only'/);
  assert.match(source, /runtime_wired: false/);
  assert.match(source, /rank_contribution_count: 0/);
  assert.match(source.slice(finalClosure, disclosure), /magma_dormancy: MAGMA_DORMANT_RUNTIME_DECISION/);
  assert.doesNotMatch(source, /magma_security_closure|reconstructed_graph_security_closure/);
  assert.doesNotMatch(source, /for \(const memory of memories\) \{\s*const graphRes = await query/);
  assert.match(source, /readBatchedRecallGraphLinks/);
});

test('clean-only top-k is finalized at each actual return path after its complete candidate population', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const earlyExit = source.indexOf("markStage('early_exit_decision')");
  const earlyBoundary = source.indexOf(
    'const earlyCanaryCleanSelectionBoundary = buildCanaryCleanSelectionBoundary',
    earlyExit,
  );
  const earlySelection = source.indexOf(
    'canaryCleanSelectionBoundary: earlyCanaryCleanSelectionBoundary',
    earlyBoundary,
  );
  const conceptPpr = source.indexOf("markStage('concept_graph_ppr')", earlySelection);
  const postGraphAdmission = source.indexOf(
    'const postGraphAdmission = await contentStateOccurrenceAdmission.admit',
    conceptPpr,
  );
  const refusion = source.indexOf(
    'nativeRetrievalFusion = fuseNativeRetrievalGears',
    postGraphAdmission,
  );
  const confidenceDone = source.indexOf("debugRecallPoint('confidence_scoring_done'", refusion);
  const normalBoundary = source.indexOf(
    "markStage('canary_clean_top_k_boundary')",
    confidenceDone,
  );
  const epistemic = source.indexOf("markStage('epistemic_trust_selection')", normalBoundary);
  const normalSelection = source.indexOf(
    "returnPath: 'normal_recall'",
    epistemic,
  );

  assert.ok(earlyExit >= 0);
  assert.ok(earlyBoundary > earlyExit);
  assert.ok(earlySelection > earlyBoundary);
  assert.ok(conceptPpr > earlySelection);
  assert.ok(postGraphAdmission > conceptPpr);
  assert.ok(refusion > postGraphAdmission);
  assert.ok(confidenceDone > refusion);
  assert.ok(normalBoundary > confidenceDone);
  assert.ok(epistemic > normalBoundary);
  assert.ok(normalSelection > epistemic);

  const normalCall = source.slice(
    source.lastIndexOf('selectAndLedgerEpistemicRecall({', normalSelection),
    normalSelection + 80,
  );
  assert.doesNotMatch(normalCall, /canaryCleanSelectionBoundary:/);

  const selectorStart = source.indexOf('async function selectAndLedgerEpistemicRecall');
  const selectorEnd = source.indexOf('\nfunction verifiedTwinPrimePolicy', selectorStart);
  const selector = source.slice(selectorStart, selectorEnd);
  const sharedBoundary = selector.indexOf('buildCanaryCleanSelectionBoundary(');
  const governedSelection = selector.indexOf('await governCanaryCleanTopKSelection');
  const epistemicReceipt = selector.indexOf("'epistemic_recall_decision'", governedSelection);
  assert.ok(sharedBoundary >= 0);
  assert.ok(governedSelection >= 0);
  assert.ok(epistemicReceipt > governedSelection);
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
  const canaryMagmaComposition = {
    schema: 'hom-aimos/canary-magma-composition/v1',
    decision_sha256: '0'.repeat(64),
    input_count: 3,
    graph_admitted_count: 2,
    retained_evidence_count: 1,
    canary_marked_memory_count: 0,
    quarantine_evidence_count: 1,
    retained_baseline_preserved: true,
    canonical_memory_mutated: false,
    retention_changed: false,
    disclosure_authority: false,
    receipt: { mutation_hash: '9'.repeat(64) },
  };
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
  const recallSecurityClosure = {
    schema: 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope',
    decision_sha256: 'd'.repeat(64),
    classification_map_root_sha256: 'e'.repeat(64),
    one_request_local_classification_map: true,
    canonical_memory_mutated: false,
    retention_changed: false,
    saber_runtime_authority: false,
    receipt: { mutation_hash: 'f'.repeat(64) },
  };
  const nativeRetrievalFusion = {
    schema: 'hom-aimos/native-retrieval-fusion/v1',
    decision_sha256: '1'.repeat(64),
    baseline_candidate_set_preserved: true,
    magma: {
      contribution_count: 2,
      edge_commitment_sha256: '2'.repeat(64),
    },
  };
  const canaryCleanSelection = {
    schema: 'hom-aimos/canary-clean-selection/v2-epistemic-withholding',
    return_path: 'semantic_cache',
    decision_sha256: '3'.repeat(64),
    boundary_sha256: '4'.repeat(64),
    requested_top_k: 1,
    clean_eligible_count: 1,
    retained_evidence_count: 0,
    selected_clean_count: 1,
    clean_backfill_count: 0,
    retained_decision_set_sha256: '5'.repeat(64),
    receipt: { mutation_hash: '6'.repeat(64) },
  };
  const cacheRevalidation = {
    source_memory_count: 4,
    admitted_memory_count: 4,
    selected_clean_count: 3,
    stale_selection_derived_content_reused: false,
    canonical_memory_mutated: false,
    retention_changed: false,
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
        canary_magma_composition: canaryMagmaComposition,
        canary_clean_selection: canaryCleanSelection,
        cache_revalidation: cacheRevalidation,
        native_retrieval_fusion: nativeRetrievalFusion,
        magma_retrieval: magmaRetrieval,
        recall_security_closure: recallSecurityClosure,
      },
    },
  });

  assert.deepEqual(calibrated.recall_meta.canary_magma_composition, canaryMagmaComposition);
  assert.deepEqual(calibrated.recall_meta.canary_clean_selection, canaryCleanSelection);
  assert.deepEqual(calibrated.recall_meta.cache_revalidation, cacheRevalidation);
  assert.deepEqual(calibrated.recall_meta.native_retrieval_fusion, nativeRetrievalFusion);
  assert.deepEqual(calibrated.recall_meta.magma_retrieval, magmaRetrieval);
  assert.deepEqual(calibrated.recall_meta.recall_security_closure, recallSecurityClosure);
  assert.equal(calibrated.memories[0].value, 'Retained evidence remains unchanged.');
  assert.equal(calibrated.memories[0].magma_score, undefined);
});
