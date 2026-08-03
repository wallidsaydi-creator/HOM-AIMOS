import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

const SCOPED_CALLS = new Map([
  ['services/context/context-renewal.js', ["'context-renewal'", "'context-renewal'"]],
  ['services/core/concept-graph.js', ["'concept-graph'"]],
  ['services/core/constitution-enforcer.js', ["'system'"]],
  ['services/core/scheming-monitor.js', ['agentId']],
  ['services/dream/delta-writer.js', ["'delta-writer'"]],
  ['services/dream/dream-feedback.js', ["'dream-feedback'"]],
  ['services/learning/agent-learning.js', ['agentId', 'agentId', 'agentId']],
  ['services/learning/batch-reflector.js', ["'batch-reflector'", "'batch-reflector'", "'batch-reflector'"]],
  ['services/learning/epistemic-vigilance.js', ["'epistemic'", "'epistemic'", "'epistemic'"]],
  ['services/learning/failure-replay.js', ["'failure-replay'"]],
  ['services/learning/reflection-finetuner.js', ['agentId']],
  ['services/learning/skill-consolidation.js', ["'skill-consolidation'", "'skill-consolidation'"]],
]);

function persistCalls(source) {
  const calls = [];
  let cursor = 0;

  while (true) {
    const start = source.indexOf('persistMemory({', cursor);
    if (start === -1) return calls;
    const suffix = source.slice(start);
    const end = suffix.match(/^\s*\}\);/m);
    assert.ok(end, 'persistMemory call must have a closing object boundary');
    calls.push(suffix.slice(0, end.index + end[0].length));
    cursor = start + end.index + end[0].length;
  }
}

test('scoped autonomous persistence calls declare the native housekeeper authority', async () => {
  let total = 0;

  for (const [relativePath, expectedSubjects] of SCOPED_CALLS) {
    const source = await readFile(new URL(relativePath, ROOT), 'utf8');
    const calls = persistCalls(source);
    assert.equal(calls.length, expectedSubjects.length, `${relativePath} call count drifted`);
    total += calls.length;

    calls.forEach((call, index) => {
      assert.match(call, /mutation_authority:\s*'housekeeper'/, relativePath);
      assert.equal((call.match(/mutation_authority:/g) || []).length, 1, relativePath);
      assert.match(
        call,
        new RegExp(`agent_id:\\s*${expectedSubjects[index]}`),
        `${relativePath} changed the memory subject at call ${index + 1}`,
      );
    });

    assert.doesNotMatch(source, /agent_id:\s*'housekeeper'/, `${relativePath} rewrote a subject as signer`);
    assert.doesNotMatch(source, /commitProvenance|signAsHousekeeper|memoryProvenanceLedger/);
  }

  assert.equal(total, 20);
});
