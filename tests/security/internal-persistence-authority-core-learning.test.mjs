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
  ['services/learning/agent-learning.js', ['agentId', 'agentId', 'agentId', 'group.agentId']],
  ['services/learning/batch-reflector.js', ["'batch-reflector'", 'subjectAgentId', "'batch-reflector'"]],
  ['services/learning/epistemic-vigilance.js', ["'epistemic'", "'epistemic'", "'epistemic'"]],
  ['services/learning/failure-replay.js', ["'failure-replay'"]],
  ['services/learning/reflection-finetuner.js', ['agentId']],
  ['services/learning/skill-consolidation.js', ["'skill-consolidation'", 'row.agent_id']],
]);

function persistCalls(source) {
  const calls = [];
  let cursor = 0;

  while (true) {
    const start = source.indexOf('executeHousekeeperCanonicalSave({', cursor);
    if (start === -1) return calls;
    const suffix = source.slice(start);
    const end = suffix.match(/^\s*\}\);/m);
    assert.ok(end, 'canonical SAVE call must have a closing object boundary');
    calls.push(suffix.slice(0, end.index + end[0].length));
    cursor = start + end.index + end[0].length;
  }
}

test('scoped autonomous persistence calls use the typed Housekeeper SAVE owner', async () => {
  let total = 0;

  for (const [relativePath, expectedSubjects] of SCOPED_CALLS) {
    const source = await readFile(new URL(relativePath, ROOT), 'utf8');
    const calls = persistCalls(source);
    assert.equal(calls.length, expectedSubjects.length, `${relativePath} call count drifted`);
    total += calls.length;

    calls.forEach((call, index) => {
      assert.doesNotMatch(call, /mutation_authority:/, relativePath);
      assert.match(
        call,
        new RegExp(`agent_id:\\s*${expectedSubjects[index]}`),
        `${relativePath} changed the memory subject at call ${index + 1}`,
      );
    });

    assert.doesNotMatch(source, /agent_id:\s*'housekeeper'/, `${relativePath} rewrote a subject as signer`);
    assert.doesNotMatch(source, /mutation_authority:\s*'housekeeper'/);
    assert.doesNotMatch(source, /commitProvenance|signAsHousekeeper|memoryProvenanceLedger/);
  }

  assert.equal(total, 21);
});

test('live post-run audit and quality producers retain the runtime-owned input state', async () => {
  const runner = await readFile(new URL('services/orchestration/agent-runner.js', ROOT), 'utf8');
  const scheming = await readFile(new URL('services/core/scheming-monitor.js', ROOT), 'utf8');
  const reflector = await readFile(new URL('services/learning/batch-reflector.js', ROOT), 'utf8');

  assert.match(runner, /auditTrajectory\(runtimeAgent\.id, trajectoryEvents, \{[\s\S]*?nativeToolInputs,[\s\S]*?provider: modelPreference\.provider,[\s\S]*?model: modelPreference\.model/);
  assert.match(runner, /runQualityLoop\([^\n]+\{ nativeToolInputs, subjectAgentId: runtimeAgent\.id \}\)/);
  const route = await readFile(new URL('routes/agent-execution.js', ROOT), 'utf8');
  assert.match(route, /sameResolvedModel\(modelResolved, executionResolution\.primaryModel\)/);
  assert.doesNotMatch(route, /modelResolved !== executionResolution\.primaryModel/);
  assert.match(scheming, /\}, \{ nativeToolInputs: options\.nativeToolInputs \|\| null \}\);/);
  assert.match(scheming, /return runProvider\(\{/);
  assert.match(scheming, /scheming_monitor_model_selection_required/);
  assert.doesNotMatch(scheming, /OLLAMA_BASE_URL|OLLAMA_MODEL|llama3\.2/);
  assert.match(reflector, /runQualityLoop\(hypothesis,[^\n]+options = \{\}\)/);
  assert.match(reflector, /\}, \{ nativeToolInputs: options\.nativeToolInputs \|\| null \}\);/);
});
