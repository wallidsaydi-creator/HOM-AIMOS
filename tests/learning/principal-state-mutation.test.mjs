import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  projectPrincipalStateMutationTargets,
  validateOutcomeMutationEvidence,
} from '../../services/learning/mutation-composition/principal-state.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const UUIDS = [
  '10000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000002',
  '10000000-0000-4000-8000-000000000003',
];

function occurrence(index, overrides = {}) {
  return {
    company_id: 'hom',
    memory_id: UUIDS[index],
    live_content_hash: 'a'.repeat(64),
    principal_agent_id: 'agent-a',
    occurrence_ref: (index + 1).toString(16).repeat(64).slice(0, 64),
    signed_time_ms: 1_786_200_000_000 + index,
    security_eligible: true,
    ...overrides,
  };
}

test('one principal state emits one latest-occurrence representative without consulting weight', () => {
  const projected = projectPrincipalStateMutationTargets([
    { ...occurrence(0), retrieval_weight: 3 },
    { ...occurrence(1), retrieval_weight: 0.1 },
  ]);
  assert.equal(projected.length, 1);
  assert.equal(projected[0].representative_memory_id, UUIDS[1]);
  assert.equal(projected[0].retained_occurrence_count, 2);
  assert.equal(Object.hasOwn(projected[0], 'retrieval_weight'), false);
});

test('equal content under different principals remains two mutation states', () => {
  const projected = projectPrincipalStateMutationTargets([
    occurrence(0),
    occurrence(1, { principal_agent_id: 'agent-b' }),
  ]);
  assert.equal(projected.length, 2);
  assert.deepEqual(projected.map((row) => row.principal_agent_id), ['agent-a', 'agent-b']);
});

test('malformed, blocked, and duplicate occurrence references fail closed', () => {
  assert.throws(
    () => projectPrincipalStateMutationTargets([occurrence(0, { security_eligible: false })]),
    /verified_eligible_occurrence_required/,
  );
  assert.throws(
    () => projectPrincipalStateMutationTargets([occurrence(0), occurrence(1, {
      occurrence_ref: occurrence(0).occurrence_ref,
    })]),
    /duplicate_occurrence_reference/,
  );
});

test('outcome contract admits only complete occurrence/principal-state evidence', () => {
  const evidence = {
    schema: 'hom.aimos.mutation-outcome-evidence/v2',
    company_id: 'hom',
    memory_id: UUIDS[0],
    live_content_hash: 'a'.repeat(64),
    occurrence_ref: 'b'.repeat(64),
    target_scope: 'principal_state',
    recall_event_id: UUIDS[1],
    recall_event_mutation_hash: 'c'.repeat(64),
    recall_merkle_root: 'd'.repeat(64),
    security_closure_sha256: 'e'.repeat(64),
    outcome_id: UUIDS[2],
  };
  assert.deepEqual(validateOutcomeMutationEvidence(evidence), evidence);
  assert.throws(
    () => validateOutcomeMutationEvidence({ ...evidence, target_scope: 'content_state' }),
    /content_state_mutation_not_authorized/,
  );
  assert.throws(
    () => validateOutcomeMutationEvidence({ ...evidence, occurrence_ref: '' }),
    /outcome_evidence_invalid/,
  );
});

test('maximum duplicate class remains linear and emits one target', () => {
  const input = Array.from({ length: 20_000 }, (_, index) => ({
    company_id: 'hom',
    memory_id: `20000000-0000-4000-8000-${index.toString().padStart(12, '0')}`,
    live_content_hash: 'f'.repeat(64),
    principal_agent_id: 'agent-scale',
    occurrence_ref: index.toString(16).padStart(64, '0'),
    signed_time_ms: 1_786_200_000_000 + index,
    security_eligible: true,
  }));
  const started = performance.now();
  const projected = projectPrincipalStateMutationTargets(input);
  const elapsed = performance.now() - started;
  assert.equal(projected.length, 1);
  assert.equal(projected[0].retained_occurrence_count, 20_000);
  assert.ok(elapsed < 1_500, `20K projection took ${elapsed.toFixed(3)}ms`);
});

test('pure mutation kernel has no database, signing, environment, or mutation authority', () => {
  const source = fs.readFileSync(path.join(
    ROOT,
    'services/learning/mutation-composition/principal-state.js',
  ), 'utf8');
  assert.doesNotMatch(source, /db\/connection|process\.env|UPDATE\s+aimos|INSERT\s+INTO|privateKey|signAs/);
});
