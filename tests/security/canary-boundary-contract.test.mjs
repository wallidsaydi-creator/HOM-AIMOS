import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  buildCanaryKillChainDiagnostics,
  detectCanaries,
  generateCanary,
  logCanaryEvent,
  scanRelayedMemory,
  scanToolExecution,
  scanToolResult,
} from '../../services/security/canary-tracker.js';

test('canaries use cryptographic bytes and preserve the published token format', () => {
  const tokens = new Set(Array.from({ length: 64 }, () => generateCanary()));
  assert.equal(tokens.size, 64);
  for (const token of tokens) assert.match(token, /^SECRET-[A-F0-9]{8}$/);
});

test('nested tool arguments and results are scanned without lossy object coercion', () => {
  assert.deepEqual(
    detectCanaries({ request: { authorization: 'SECRET-DEADBEEF' } }),
    ['SECRET-DEADBEEF'],
  );
  assert.deepEqual(
    detectCanaries({ repeated: ['SECRET-CAFEBABE', 'SECRET-CAFEBABE'] }),
    ['SECRET-CAFEBABE'],
  );
});

test('clean boundary scans are side-effect free', async () => {
  const execution = await scanToolExecution('web_search', { query: 'weather' }, 'clean-run');
  const exposure = await scanToolResult('web_search', { answer: 'sunny' }, 'clean-run');
  const relay = await scanRelayedMemory('A clean retained memory.', 'clean-run');

  assert.equal(execution.blocked, false);
  assert.deepEqual(execution.events, []);
  assert.deepEqual(exposure.events, []);
  assert.deepEqual(relay.events, []);
});

test('EXECUTED diagnostics distinguish blocked dispatch from an invoked tool', () => {
  const diagnostics = buildCanaryKillChainDiagnostics([
    { stage: 'EXECUTED', dispatchBlocked: true, toolInvoked: false },
    { stage: 'EXECUTED', dispatchBlocked: false, toolInvoked: true },
  ]);

  assert.equal(diagnostics.stage_counts.EXECUTED, 2);
  assert.equal(diagnostics.blocked_tool_dispatches, 1);
  assert.equal(diagnostics.executed_tool_invocations, 1);
});

test('invalid kill-chain stages are rejected before ledger access', async () => {
  await assert.rejects(
    logCanaryEvent('SECRET-DEADBEEF', 'OUTPUT', 'model_response', 'run'),
    /invalid_canary_stage:OUTPUT/,
  );
});

test('tool execution and result scans occupy the native signed action boundary', async () => {
  const source = await readFile(
    new URL('../../services/orchestration/tool-registry.js', import.meta.url),
    'utf8',
  );
  const begin = source.indexOf('signedToolAction = await beginToolAction(');
  const outboundScan = source.indexOf('await scanToolExecution(', begin);
  const invoke = source.indexOf('await runWithTimeout(', begin);
  const resultScan = source.indexOf('await scanToolResult(', invoke);
  const terminal = source.indexOf('await finishToolAction({', resultScan);

  assert.ok(begin >= 0);
  assert.ok(outboundScan > begin, 'arguments must be scanned after a signed action exists');
  assert.ok(invoke > outboundScan, 'arguments must be scanned before tool dispatch');
  assert.ok(resultScan > invoke, 'tool results can only be scanned after invocation');
  assert.ok(terminal > resultScan, 'terminal action proof follows result-boundary evidence');
});

test('RELAYED is owned by recalled memory before prompt construction', async () => {
  const source = await readFile(
    new URL('../../services/orchestration/agent-runner.js', import.meta.url),
    'utf8',
  );
  const load = source.indexOf('const aimosContextPack =');
  const relay = source.indexOf('await scanRelayedMemory(', load);
  const prompt = source.indexOf('buildSystemPrompt(', relay);

  assert.ok(load >= 0);
  assert.ok(relay > load, 'relay scan must follow native memory retrieval');
  assert.ok(prompt > relay, 'relay scan must precede model prompt construction');
  assert.doesNotMatch(source, /scanAssembledPrompt/);
});
