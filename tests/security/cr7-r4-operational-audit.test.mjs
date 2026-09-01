import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { proveCr7R4OperationalAudit } from '../../scripts/verification/prove-cr7-r4-operational-audit.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (relative) => readFileSync(path.join(ROOT, relative), 'utf8');

test('CR7-R4 freezes every open database effect and promotes only proved atomic owners', () => {
  const proof = proveCr7R4OperationalAudit();
  assert.equal(proof.frozen_a0_open_database_effect_count, 62);
  assert.equal(proof.frozen_a0_open_database_file_count, 27);
  assert.equal(proof.frozen_a1_existing_atomic_count, 10);
  assert.equal(proof.frozen_a1_remediation_required_count, 52);
  assert.equal(proof.current_open_database_effect_count, 0);
  assert.deepEqual(proof.verdict_counts, { R4_OPERATIONAL_ATOMIC: 10, OPEN_DATABASE: 0 });
  assert.equal(proof.results.length, 10);
  assert.equal(new Set(proof.results.map((entry) => entry.effect_id)).size, 10);
  assert.equal(proof.fresh_disposable_installation_deferred, true);
  assert.equal(proof.reconstruction.time_complexity, 'O(n)');
  assert.equal(proof.reconstruction.committed_transition_to_terminal_bijection, true);
  assert.equal(proof.paper_authority.formulas_changed, false);
  assert.match(proof.r4_source_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.audit_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.proof_root_sha256, /^[0-9a-f]{64}$/);
});

test('run, session, checkpoint and BDI state converge on signed events', () => {
  const run = read('services/orchestration/run-metadata.js');
  const session = read('services/orchestration/session-runner.js');
  const bdi = read('services/orchestration/agent-bdi-state.js');
  const route = read('routes/aimos.js');
  for (const body of [run, session, bdi, route]) {
    assert.doesNotMatch(body, /INSERT INTO agent_runs|UPDATE agent_runs|INSERT INTO run_idempotency|INSERT INTO session_lanes|UPDATE session_lanes|INSERT INTO agent_state|UPDATE agent_state/);
  }
  assert.match(run, /agent_run_started/);
  assert.match(run, /agent_run_terminal/);
  assert.match(session, /session_lane_started/);
  assert.match(session, /session_lane_terminal/);
  assert.match(bdi, /agent_bdi_state_committed/);
  assert.match(route, /task_checkpoint_committed/);
});

test('skill and learning writes use canonical SAVE or signed outcomes', () => {
  const route = read('routes/aimos.js');
  const runner = read('services/orchestration/agent-runner.js');
  const learning = read('services/learning/agent-learning.js');
  const dual = read('services/learning/dual-skill-bank.js');
  for (const body of [route, runner, learning, dual]) {
    assert.doesNotMatch(body, /INSERT INTO procedural_skills|UPDATE procedural_skills|INSERT INTO recommendation_log|UPDATE recommendation_log|INSERT INTO skill_bank|UPDATE skill_bank/);
  }
  assert.match(route, /memory_type: 'procedural'/);
  assert.match(runner, /saveLearnedProceduralSkill/);
  assert.match(learning, /recommendation_committed/);
  assert.match(dual, /dual_skill_deposit_retired_use_canonical_procedural_save/);
});

test('derived projections have no unowned database writer', () => {
  const census = proveCr7R4OperationalAudit();
  assert.equal(census.current_open_database_effect_count, 0);
  const mcp = read('routes/mcp.js');
  const graph = read('services/orchestration/interaction-graph-healer.js');
  const similarity = read('services/retrieval/similarity-stats.js');
  const cache = read('services/write/transformation-cache.js');
  assert.doesNotMatch(mcp, /INSERT INTO mcp_connections|UPDATE mcp_connections/);
  assert.doesNotMatch(graph, /INSERT INTO interaction_graph|UPDATE interaction_graph/);
  assert.doesNotMatch(similarity, /INSERT INTO similarity_statistics/);
  assert.doesNotMatch(cache, /INSERT INTO transformation_cache|UPDATE transformation_cache/);
});

test('paper-backed learning storage changes preserve formulas and cite physical authority', () => {
  const normalizer = read('services/learning/error-normalizer.js');
  const prospect = read('services/learning/prospect-theory.js');
  assert.match(normalizer, /5df20d03d73678f51456442b83eb37b94dd59f77a17afd164bb02b158e32c9a7/);
  assert.match(normalizer, /welfordUpdate/);
  assert.match(prospect, /33f52599bff4484c55986a697739b5d51223f33d4a5f6567798e93defa39e30d/);
  assert.match(prospect, /DEFAULT_ALPHA = 0\.88/);
  assert.match(prospect, /DEFAULT_LAMBDA = 2\.25/);
});
