/** Authority-free R9 scale and Hebbian decision verifier. */

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { latencySummary } from './content-state-occurrence-r9-scale.mjs';

function fail(code) { throw new Error(`r9_verifier:${code}`); }
function root(document) {
  const { report_root_sha256: expected, ...body } = document || {};
  const observed = createHash('sha256').update(Buffer.from(canonicalJson(body), 'utf8')).digest('hex');
  if (expected !== observed) fail('artifact_root_invalid');
  return observed;
}
function distribution(rows = []) {
  const counts = { elevate: 0, neutral: 0, attenuate: 0, unavailable: 0 };
  for (const row of rows) {
    if (row.direction > 0) counts.elevate += 1;
    else if (row.direction < 0) counts.attenuate += 1;
    else if (row.consensus) counts.neutral += 1;
    else counts.unavailable += 1;
  }
  const decided = counts.elevate + counts.neutral + counts.attenuate;
  return {
    ...counts,
    decided,
    maximum_direction_share: decided
      ? Math.max(counts.elevate, counts.neutral, counts.attenuate) / decided
      : 1,
  };
}

export function verifyR9ScaleArtifact(document) {
  const artifactRoot = root(document);
  const million = document.million || {};
  const expected = {
    maximum_duplicate: { states: 1, blocked: 0, collapsed: 999_999 },
    all_unique: { states: 1_000_000, blocked: 0, collapsed: 0 },
    mixed_poison: { states: 250_000, blocked: 25_000, collapsed: 750_000 },
  };
  for (const [scenario, contract] of Object.entries(expected)) {
    const row = million[scenario];
    if (!row || row.result?.input_occurrence_count !== 1_000_000
        || row.result?.unique_state_count !== contract.states
        || row.result?.blocked_state_count !== contract.blocked
        || row.result?.collapsed_occurrence_count !== contract.collapsed
        || row.result?.membership_operations !== 1_000_000) {
      fail(`million_scenario_invalid:${scenario}`);
    }
  }
  const computedGates = {
    request_projection_p95: Math.max(...Object.values(document.bounded).map((row) => row.latency.p95_ms)) <= 25,
    mutation_projection_p95: document.mutation.latency.p95_ms <= 50,
    graph_workspace_p95: document.graph.latency.p95_ms <= 100,
    offline_100k_p95: Math.max(...Object.values(document.offline_100k).map((row) => row.latency.p95_ms)) <= 5_000,
    million_elapsed: Object.values(million).every((row) => row.elapsed_ms <= 45_000),
    million_heap: Object.values(million).every((row) => row.result.peak_heap_bytes < 2 * 1024 ** 3),
    cap_semantics: document.exhaustion?.bounded?.status === 'bounded_window_exhausted'
      && document.exhaustion?.exhausted?.status === 'exhausted_unique',
    stale_projection_fallback: document.projection_fallback?.stale?.mode === 'bounded_canonical_fallback',
  };
  if (canonicalJson(computedGates) !== canonicalJson(document.gates)
      || !Object.values(computedGates).every(Boolean)
      || document.projection_decision?.selected !== 'bounded_canonical_request_local'
      || document.projection_decision?.persistent_projection_selected !== false
      || document.projection_decision?.projection_migration_required !== false
      || document.canonical_mutation_performed !== false
      || document.policy_activation_performed !== false) {
    fail('scale_decision_invalid');
  }
  return Object.freeze({ valid: true, artifact_root_sha256: artifactRoot, gates: computedGates });
}

export function verifyR9HebbianArtifact(document) {
  const artifactRoot = root(document);
  const calibration = distribution(document.calibration);
  const heldout = distribution(document.heldout);
  const latency = latencySummary(document.heldout.map((row) => Number(row.latency_ms)));
  const projectedBatch = latency.p95_ms * 500;
  const computedGates = {
    state_bounded_targets_and_neighbors: document.heldout.every((row) => row.consensus == null
      || (row.consensus.uniquePrincipalStateNeighbors <= row.consensus.retainedNeighborRows
        && row.consensus.neighborCount <= 24)),
    blocked_evidence_zero_influence: document.blocked_results.every((row) => row.consensus == null),
    heldout_decision_distribution: heldout.maximum_direction_share <= 0.80,
    heldout_warm_p95_latency: latency.p95_ms <= 250,
    projected_batch_latency: projectedBatch <= 180_000,
    bounded_log_step: document.heldout.every((row) => Math.abs(row.predicted_delta_log) <= 0.262 + Number.EPSILON),
    paired_retrieval_utility_benefit: false,
    canonical_noninterference: canonicalJson(document.before) === canonicalJson(document.after),
  };
  if (canonicalJson(calibration) !== canonicalJson(document.calibration_distribution)
      || canonicalJson(heldout) !== canonicalJson(document.heldout_distribution)
      || canonicalJson(latency) !== canonicalJson(document.heldout_latency)
      || projectedBatch !== document.projected_500_target_batch_ms
      || canonicalJson(computedGates) !== canonicalJson(document.gates)
      || document.activation_decision?.enabled !== false
      || document.activation_decision?.eligible !== false
      || document.activation_decision?.signed_configuration_changed !== false
      || document.canonical_mutation_performed !== false
      || document.weight_mutation_performed !== false) {
    fail('hebbian_decision_invalid');
  }
  return Object.freeze({
    valid: true,
    artifact_root_sha256: artifactRoot,
    calibration_distribution: calibration,
    heldout_distribution: heldout,
    heldout_latency: latency,
    gates: computedGates,
  });
}
