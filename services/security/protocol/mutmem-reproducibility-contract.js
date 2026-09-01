// Authority-free MutMem publication reproducibility scorecard.
//
// This module encodes the Opus/Fable reproducibility standard as data and pure
// validation. It has no runtime, database, signer, network, filesystem, model,
// policy, or publication authority. A score describes evidence; it cannot
// manufacture a missing artifact or promote a paper claim.

export const MUTMEM_REPRODUCIBILITY_SCHEMA =
  'hom.aimos.mutmem-reproducibility-assessment/v1';

export const MUTMEM_REPRODUCIBILITY_REQUIREMENTS = Object.freeze([
  'verify_and_reproduce_entrypoints',
  'environment_manifest',
  'dataset_manifests',
  'generated_tables_and_figures',
  'claim_to_evidence_map',
  'attempt_failure_ledger',
  'public_private_boundary_manifest',
  'fresh_machine_proof',
  'archival_release_binding',
  'v1_to_v2_change_ledger',
]);

const STATUS = new Set(['present', 'partial', 'missing']);
const LEVEL = new Set(['verified', 'regenerable', 'reproducible', 'independently_replicated']);
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

function fail(code) {
  throw new Error(`mutmem_reproducibility:${code}`);
}

function finiteScore(value, code) {
  const score = Number(value);
  if (!Number.isFinite(score) || score < 0 || score > 5) fail(code);
  return score;
}

function exactRequirementSet(requirements) {
  if (!Array.isArray(requirements)
      || requirements.length !== MUTMEM_REPRODUCIBILITY_REQUIREMENTS.length) {
    fail('requirement_set_invalid');
  }
  const byId = new Map();
  for (const entry of requirements) {
    const id = String(entry?.id || '');
    if (!MUTMEM_REPRODUCIBILITY_REQUIREMENTS.includes(id) || byId.has(id)
        || !STATUS.has(entry?.status)
        || typeof entry?.evidence !== 'string' || !entry.evidence.trim()
        || typeof entry?.improvement !== 'string' || !entry.improvement.trim()) {
      fail('requirement_invalid');
    }
    byId.set(id, Object.freeze({
      id,
      status: entry.status,
      evidence: entry.evidence.trim(),
      improvement: entry.improvement.trim(),
    }));
  }
  return MUTMEM_REPRODUCIBILITY_REQUIREMENTS.map((id) => byId.get(id));
}

export function evaluateMutMemReproducibilityAssessment(assessment = {}) {
  if (assessment?.schema !== MUTMEM_REPRODUCIBILITY_SCHEMA
      || Number(assessment?.version) !== 1
      || !SHA256.test(String(assessment?.paper?.pdf_sha256 || ''))
      || !SHA256.test(String(assessment?.paper?.tex_sha256 || ''))
      || !GIT_COMMIT.test(String(assessment?.authority?.commit || ''))
      || typeof assessment?.authority?.source !== 'string'
      || !assessment.authority.source.trim()) {
    fail('assessment_identity_invalid');
  }
  const artifactScore = finiteScore(
    assessment.scores?.artifact_integrity_and_claim_verifiability,
    'artifact_score_invalid',
  );
  const reproductionScore = finiteScore(
    assessment.scores?.independent_end_to_end_reproducibility,
    'reproduction_score_invalid',
  );
  const artifactTarget = finiteScore(
    assessment.targets?.artifact_integrity_and_claim_verifiability,
    'artifact_target_invalid',
  );
  const reproductionTarget = finiteScore(
    assessment.targets?.independent_end_to_end_reproducibility,
    'reproduction_target_invalid',
  );
  if (!LEVEL.has(assessment.highest_supported_level)
      || typeof assessment.independently_replicated !== 'boolean') {
    fail('support_level_invalid');
  }
  if (assessment.highest_supported_level === 'independently_replicated'
      && assessment.independently_replicated !== true) {
    fail('replication_claim_invalid');
  }

  const requirements = exactRequirementSet(assessment.requirements);
  const counts = Object.freeze({
    present: requirements.filter((entry) => entry.status === 'present').length,
    partial: requirements.filter((entry) => entry.status === 'partial').length,
    missing: requirements.filter((entry) => entry.status === 'missing').length,
  });
  const open = requirements
    .filter((entry) => entry.status !== 'present')
    .map((entry) => Object.freeze({ ...entry }));
  return Object.freeze({
    schema: MUTMEM_REPRODUCIBILITY_SCHEMA,
    paper: Object.freeze({ ...assessment.paper }),
    historical_scores: Object.freeze({
      artifact_integrity_and_claim_verifiability: artifactScore,
      independent_end_to_end_reproducibility: reproductionScore,
    }),
    targets: Object.freeze({
      artifact_integrity_and_claim_verifiability: artifactTarget,
      independent_end_to_end_reproducibility: reproductionTarget,
    }),
    score_gaps: Object.freeze({
      artifact_integrity_and_claim_verifiability: Math.max(0, artifactTarget - artifactScore),
      independent_end_to_end_reproducibility: Math.max(0, reproductionTarget - reproductionScore),
    }),
    highest_supported_level: assessment.highest_supported_level,
    independently_replicated: assessment.independently_replicated,
    requirement_counts: counts,
    open_requirements: Object.freeze(open),
    release_package_complete: counts.partial === 0 && counts.missing === 0,
    v2_release_ready: artifactScore >= artifactTarget
      && reproductionScore >= reproductionTarget
      && counts.partial === 0
      && counts.missing === 0,
    scoring_authority: 'descriptive_assessment_only',
  });
}

export default {
  MUTMEM_REPRODUCIBILITY_SCHEMA,
  MUTMEM_REPRODUCIBILITY_REQUIREMENTS,
  evaluateMutMemReproducibilityAssessment,
};
