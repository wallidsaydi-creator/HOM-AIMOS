import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const recallOwner = readFileSync(new URL('../../services/retrieval/native-recall.js', import.meta.url), 'utf8');
const recallPipeline = readFileSync(new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url), 'utf8');
const outputCalibrator = readFileSync(new URL('../../services/retrieval/recall-output-calibrator.js', import.meta.url), 'utf8');

test('verified graph decision is signed in the native receipt on normal and early return paths', () => {
  assert.match(recallPipeline, /graphEvidenceDecision: recallBreadthPolicy\.graph_link_batch \|\| null/g);
  assert.match(recallOwner, /recall_graph_evidence_decision_invalid/);
  assert.match(recallOwner, /verified_graph_decision: normalizedGraphEvidence/);
  assert.match(recallOwner, /verified_graph_event_body_bound: true/);
  assert.match(recallOwner, /unsigned_edge_admission_count\) !== 0/);
});

test('graph receipt binding does not silently change the portable v3 Merkle entry family', () => {
  assert.doesNotMatch(recallOwner, /entry_type: 'verified_recall_graph'/);
  assert.match(recallOwner, /hom-aimos\/recall-merkle\/v3-epistemic-and-security-closure/);
});

test('native structural projection is signed without obtaining rank or Merkle-family authority', () => {
  assert.match(recallPipeline, /structuralEvidenceDecision: nativeStructuralProjection/g);
  assert.match(recallOwner, /recall_structural_evidence_decision_invalid/);
  assert.match(recallOwner, /native_structural_projection: normalizedStructuralEvidence/);
  assert.match(recallOwner, /native_structural_projection_event_body_bound: true/);
  assert.doesNotMatch(recallOwner, /entry_type: 'native_structural_projection'/);
});

test('retired zero-rank calibration shadow has no native recall, receipt, or output path', () => {
  const source = `${recallPipeline}\n${recallOwner}\n${outputCalibrator}`;
  assert.doesNotMatch(source, /native_calibration_shadow|calibrationShadowDecision|nativeCalibrationShadow|NATIVE_CALIBRATION_SHADOW/);
});

test('native embedding continuity is event-body bound without adding a portable Merkle entry family', () => {
  assert.match(recallOwner, /recall_embedding_continuity_decision_invalid/);
  assert.match(recallOwner, /native_embedding_continuity: normalizedEmbeddingContinuity/);
  assert.match(recallOwner, /native_embedding_continuity_event_body_bound: true/);
  assert.doesNotMatch(recallOwner, /entry_type: 'native_embedding_continuity'/);
});
