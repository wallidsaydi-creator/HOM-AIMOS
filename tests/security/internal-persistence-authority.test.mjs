import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

const EXPECTED_CALLS = new Map([
  ['services/observe/architecture-registry.js', 2],
  ['services/orchestration/agent-runner.js', 9],
  ['services/orchestration/agent-xai-explanation.js', 2],
  ['services/orchestration/capability-probe.js', 1],
  ['services/orchestration/explore-exploit-loop.js', 1],
  ['services/orchestration/graph-designer.js', 1],
  ['services/orchestration/hypothesis-verifier.js', 1],
  ['services/orchestration/scheduler.js', 2],
]);

function persistCallWindows(source) {
  const lines = source.split('\n');
  const starts = [];
  for (let index = 0; index < lines.length; index++) {
    if (lines[index].includes('persistMemory({')) starts.push(index);
  }
  return starts.map((start, index) => {
    const nextStart = starts[index + 1] ?? lines.length;
    return lines.slice(start, Math.min(nextStart, start + 60)).join('\n');
  });
}

test('every scoped internal persistence call declares housekeeper mutation authority', async () => {
  let totalCalls = 0;
  for (const [relativePath, expectedCount] of EXPECTED_CALLS) {
    const source = await readFile(new URL(relativePath, ROOT), 'utf8');
    const calls = persistCallWindows(source);
    assert.equal(calls.length, expectedCount, `${relativePath} persistence call count drifted`);
    totalCalls += calls.length;

    for (const call of calls) {
      assert.match(call, /mutation_authority: 'housekeeper'/, relativePath);
      assert.equal((call.match(/mutation_authority:/g) || []).length, 1, relativePath);
    }

    assert.doesNotMatch(source, /agent_id: 'housekeeper'/, `${relativePath} rewrote the memory subject`);
    assert.doesNotMatch(source, /commitProvenance|signAsHousekeeper|memoryProvenanceLedger/);
  }

  assert.equal(totalCalls, 19);
});

test('subject identities remain distinct from the autonomous signer', async () => {
  const [architecture, capability, runner, xai] = await Promise.all([
    readFile(new URL('services/observe/architecture-registry.js', ROOT), 'utf8'),
    readFile(new URL('services/orchestration/capability-probe.js', ROOT), 'utf8'),
    readFile(new URL('services/orchestration/agent-runner.js', ROOT), 'utf8'),
    readFile(new URL('services/orchestration/agent-xai-explanation.js', ROOT), 'utf8'),
  ]);

  assert.equal((architecture.match(/agent_id: 'architecture-registry'/g) || []).length, 2);
  assert.match(capability, /agent_id: 'capability-probe'[\s\S]*key: `capability_profile:\$\{agentId\}`/);
  assert.match(runner, /agent_id: toAgentId/);
  assert.match(runner, /agent_id: runtimeAgent\.id/);
  for (const call of persistCallWindows(xai)) {
    assert.match(call, /agent_id: runtimeAgent\.id/);
  }
});
