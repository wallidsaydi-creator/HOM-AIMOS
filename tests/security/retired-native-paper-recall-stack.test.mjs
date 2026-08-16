import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const routeSource = await readFile(
  new URL('../../routes/aimos.js', import.meta.url),
  'utf8',
);

const functionStart = routeSource.indexOf(
  'export function applyNativePaperRecallOperators(',
);
const functionEnd = routeSource.indexOf(
  '\n\n\nconst SERVER_BOOT_TIME',
  functionStart,
);
const retiredFunction = routeSource.slice(functionStart, functionEnd);

test('the positive-only native paper scorer remains retired and unreachable', () => {
  assert.ok(functionStart >= 0, 'retirement boundary export is missing');
  assert.ok(functionEnd > functionStart, 'retirement boundary end is missing');

  const retirementReturn = retiredFunction.indexOf(
    "reason: 'retired_monotone_positive_only_stack'",
  );
  const legacyBody = retiredFunction.indexOf(
    'if (!Array.isArray(memories) || memories.length === 0)',
  );

  assert.ok(retirementReturn >= 0, 'retirement reason is missing');
  assert.ok(
    legacyBody > retirementReturn,
    'legacy scorer body precedes the fail-closed retirement return',
  );
  assert.match(retiredFunction, /replacement:\s*'services\/observe\/calibrated-rank-composition\.js'/);

  const references = routeSource.match(/applyNativePaperRecallOperators\s*\(/g) ?? [];
  assert.equal(references.length, 1, 'retired scorer acquired a route caller');
});

test('the canonical route does not import dormant graph scorers', () => {
  const dormantGraphModules = [
    'hmem-hierarchical-reasoning.js',
    'hage-hybrid-agent-graph.js',
    'hindsight-memory-graph.js',
    'hingemem-boundary-hypergraph.js',
    'reconstructed-graph-memory.js',
    'mnemis-dual-route-graph.js',
  ];

  for (const moduleName of dormantGraphModules) {
    assert.doesNotMatch(
      routeSource,
      new RegExp(`import[^;]+${moduleName.replaceAll('.', '\\\\.')}[^;]*;`),
      `${moduleName} is still loaded by the canonical route`,
    );
  }
});
