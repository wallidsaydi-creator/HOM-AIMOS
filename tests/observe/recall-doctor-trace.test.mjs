import test from 'node:test';
import assert from 'node:assert/strict';

import { buildRecallDoctorCandidateTrace } from '../../services/observe/recall-doctor-trace.js';

test('doctor trace preserves exact epistemic relevance inputs while omitting memory bodies', () => {
  const trace = buildRecallDoctorCandidateTrace({
    queryText: 'Which value is supported?',
    memories: [{
      id: 'memory-1',
      key: 'memory:key:1',
      value: 'This body must not enter the diagnostic sidecar.',
      memory_type: 'research',
      similarity: 0.91,
      calibrated_recall_score: 0.81234567,
      _raw_rerank: 0.79876543,
      rerank_score: 0.78,
      recall_confidence: 0.76,
      score: 0.74567891,
      raw_distance: 0.09,
      confidence: {
        percent: 76,
        components: { semantic: 0.91 },
      },
      deep_recall_override: {
        applied: true,
        reason: 'high_specificity_semantic_match',
      },
      created_at: new Date('2026-07-30T10:00:00.000Z'),
      provenance_proof: {
        live_content_hash: 'a'.repeat(64),
        save_mutation_hash: 'b'.repeat(64),
        binding_mutation_hash: 'c'.repeat(64),
      },
    }],
  });

  assert.equal(trace.candidate_set[0].calibrated_recall_score, 0.812346);
  assert.equal(trace.candidate_set[0].raw_rerank_score, 0.798765);
  assert.deepEqual(trace.candidate_set[0].epistemic_relevance_inputs, {
    calibrated_recall_score: 0.81234567,
    raw_rerank: 0.79876543,
    rerank_score: 0.78,
    recall_confidence: 0.76,
    score: 0.74567891,
  });
  assert.deepEqual(trace.candidate_set[0].output_calibration_projection.confidence, {
    percent: 76,
    components: { semantic: 0.91 },
  });
  assert.deepEqual(trace.candidate_set[0].output_calibration_projection.deep_recall_override, {
    applied: true,
    reason: 'high_specificity_semantic_match',
  });
  assert.equal(trace.candidate_set[0].output_calibration_projection.raw_distance, 0.09);
  assert.equal(Object.hasOwn(
    trace.candidate_set[0].output_calibration_projection,
    'created_at',
  ), false);
  assert.deepEqual(trace.candidate_set[0].provenance_proof_projection, {
    live_content_hash: 'a'.repeat(64),
    save_mutation_hash: 'b'.repeat(64),
    binding_mutation_hash: 'c'.repeat(64),
  });
  assert.equal(trace.candidate_set[0].body_omitted, true);
  assert.equal(Object.hasOwn(trace.candidate_set[0], 'value'), false);
  assert.equal(Object.hasOwn(trace.candidate_set[0].output_calibration_projection, 'value'), false);
  assert.equal(trace.guardrails.mutates_rank, false);
  assert.equal(trace.guardrails.writes_aimos_db, false);
});
