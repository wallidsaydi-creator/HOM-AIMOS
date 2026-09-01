import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  MUTMEM_REPRODUCIBILITY_REQUIREMENTS,
  evaluateMutMemReproducibilityAssessment,
} from '../../services/security/protocol/mutmem-reproducibility-contract.js';

const assessment = JSON.parse(readFileSync(
  new URL('../../eval/publication/mutmem-v1-reproducibility-assessment.json', import.meta.url),
  'utf8',
));

test('V1 scorecard preserves the recovered Opus/Fable scores without promotion', () => {
  const result = evaluateMutMemReproducibilityAssessment(assessment);
  assert.deepEqual(result.historical_scores, {
    artifact_integrity_and_claim_verifiability: 4.5,
    independent_end_to_end_reproducibility: 3.5,
  });
  assert.deepEqual(result.score_gaps, {
    artifact_integrity_and_claim_verifiability: 0.5,
    independent_end_to_end_reproducibility: 0.5,
  });
  assert.equal(result.highest_supported_level, 'verified');
  assert.equal(result.independently_replicated, false);
  assert.equal(result.v2_release_ready, false);
});

test('V1 scorecard exposes the complete ten-item improvement set', () => {
  const result = evaluateMutMemReproducibilityAssessment(assessment);
  assert.equal(MUTMEM_REPRODUCIBILITY_REQUIREMENTS.length, 10);
  assert.deepEqual(result.requirement_counts, { present: 3, partial: 5, missing: 2 });
  assert.deepEqual(
    result.open_requirements.map((entry) => entry.id),
    MUTMEM_REPRODUCIBILITY_REQUIREMENTS.filter((id) => ![
      'dataset_manifests',
      'generated_tables_and_figures',
      'claim_to_evidence_map',
    ].includes(id)),
  );
});

test('scorecard fails closed on duplicate, unknown or promoted evidence', () => {
  const duplicate = structuredClone(assessment);
  duplicate.requirements[1] = structuredClone(duplicate.requirements[0]);
  assert.throws(() => evaluateMutMemReproducibilityAssessment(duplicate), /requirement_invalid/);

  const promoted = structuredClone(assessment);
  promoted.highest_supported_level = 'independently_replicated';
  assert.throws(() => evaluateMutMemReproducibilityAssessment(promoted), /replication_claim_invalid/);
});
