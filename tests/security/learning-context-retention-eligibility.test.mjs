import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

const OWNED_PATHS = [
  'services/dream/dream-feedback.js',
  'services/learning/plasticity-controller.js',
  'services/learning/agent-learning.js',
  'services/learning/reflection-finetuner.js',
  'services/learning/batch-reflector.js',
  'services/learning/epistemic-vigilance.js',
  'services/orchestration/agent-confidence-calibration.js',
  'services/orchestration/graph-designer.js',
  'services/orchestration/meta-controller.js',
  'services/orchestration/agent-prompts.js',
  'services/context/context-renewal.js',
  'services/context/persistent-identity-bootstrap.js',
  'services/write/sensible-screening.js',
];

async function source(relativePath) {
  return readFile(new URL(relativePath, ROOT), 'utf8');
}

function memoryQueries(body) {
  return [...body.matchAll(/`([^`]*\bFROM\s+aimos_memories\b[^`]*)`/gi)]
    .map((match) => match[1]);
}

test('learning and context memory reads retain every canonical lifecycle state', async () => {
  for (const relativePath of OWNED_PATHS) {
    const body = await source(relativePath);
    const queries = memoryQueries(body);
    assert.ok(queries.length > 0, `${relativePath} must contain an inspected memory query`);

    for (const sql of queries) {
      assert.doesNotMatch(sql, /\b(?:[a-z]+\.)?is_active\s*=\s*(?:true|false)\b/i, relativePath);
      assert.doesNotMatch(sql, /\b(?:valid_until|expires?_at)\s*(?:<|<=|>|>=|=|IS\s+NOT\s+NULL)/i, relativePath);
      assert.doesNotMatch(sql, /\b(?:superseded_by|supersedes_id)\s+IS\s+NULL\b/i, relativePath);
      assert.doesNotMatch(sql, /\bcreated_at\s*>\s*NOW\(\)\s*-\s*INTERVAL/i, relativePath);
      assert.match(sql, /\bcompany_id\s*=\s*\$\d+\b/i, `${relativePath} must remain tenant-bound`);
    }
  }
});

test('retention expansion preserves ownership and relevance boundaries', async () => {
  const reflections = await source('services/learning/reflection-finetuner.js');
  assert.match(reflections, /company_id = \$1 AND agent_id = \$2/);
  assert.match(reflections, /memory_type = 'reflection_transaction'/);

  const prompts = await source('services/orchestration/agent-prompts.js');
  assert.match(prompts, /agent_id = ANY\(\$2::text\[\]\)\s+OR scope = 'global'/);
  assert.match(prompts, /m\.agent_id = ANY\(\$2::text\[\]\) OR m\.scope = 'global'/);
  assert.match(prompts, /m\.embedding IS NOT NULL/);

  const identity = await source('services/context/persistent-identity-bootstrap.js');
  assert.match(identity, /agent_id = \$2\s+OR agent_id IS NULL/);

  const topology = await source('services/orchestration/graph-designer.js');
  assert.match(topology, /memory_type = 'procedural'/);
  assert.match(topology, /key LIKE 'topology_cache:%'/);
  assert.match(topology, /similarity < 0\.85/);
});

test('append-only singleton reads resolve the latest retained projection', async () => {
  for (const relativePath of [
    'services/dream/dream-feedback.js',
    'services/learning/agent-learning.js',
    'services/orchestration/agent-confidence-calibration.js',
    'services/context/context-renewal.js',
  ]) {
    const body = await source(relativePath);
    assert.match(body, /ORDER BY (?:updated_at|created_at) DESC/i, relativePath);
  }
});

test('dream feedback changes replay frequency without suppression authority', async () => {
  const feedback = await source('services/dream/dream-feedback.js');
  const nightly = await source('jobs/nightly-dream.js');

  for (const body of [feedback, nightly]) {
    assert.doesNotMatch(body, /suppressed_patterns|suppressedPatterns/);
  }
  assert.match(feedback, /low_frequency_patterns/);
  assert.match(feedback, /no memory or evidence becomes ineligible for recall/);
  assert.match(nightly, /explicit predecessor\/successor relation atomically/);
});

test('retention changes leave learning and calibration formulas intact', async () => {
  const plasticity = await source('services/learning/plasticity-controller.js');
  assert.match(plasticity, /const LOW_PLASTICITY_THRESHOLD = 50/);
  assert.match(plasticity, /const MEDIUM_PLASTICITY_THRESHOLD = 10/);
  assert.match(plasticity, /write_strength = plasticity_level \* gate_confidence/);

  const meta = await source('services/orchestration/meta-controller.js');
  assert.match(meta, /const mastery = successRate \* 0\.7 \+ volumeFactor \* 0\.3/);
  assert.match(meta, /const novelty = 1 \/ \(1 \+ Math\.exp\(-5 \* \(distance - 0\.4\)\)\)/);

  const calibration = await source('services/orchestration/agent-confidence-calibration.js');
  assert.match(calibration, /f7Score \* 0\.6 \+ heuristicConfidence \* 0\.4/);
});
