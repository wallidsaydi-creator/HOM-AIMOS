import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const routeSource = await readFile(
  new URL('../../routes/aimos.js', import.meta.url),
  'utf8',
);

test('the retired positive-only paper wrapper is absent, not stubbed', () => {
  assert.doesNotMatch(routeSource, /applyNativePaperRecallOperators/);
  assert.doesNotMatch(routeSource, /retired_monotone_positive_only_stack/);
  assert.doesNotMatch(routeSource, /NATIVE_RECALL_PAPER_ACTIVATION/);
});

test('destructive and unpromoted paper primitives are not loaded by the canonical route', () => {
  const disabledModules = [
    'hebbian-orthogonal-projection.js',
    'neurogenesis-catastrophic-forgetting.js',
    'serena-self-regulated-neurogenesis.js',
    'tacos-neuromodulated-consolidation.js',
    'synaptic-consolidation-plasticity.js',
    'hmem-hierarchical-reasoning.js',
    'hage-hybrid-agent-graph.js',
    'hindsight-memory-graph.js',
    'hingemem-boundary-hypergraph.js',
    'reconstructed-graph-memory.js',
    'mnemis-dual-route-graph.js',
  ];
  for (const moduleName of disabledModules) {
    assert.doesNotMatch(
      routeSource,
      new RegExp(`import[^;]+${moduleName.replaceAll('.', '\\\\.')}[^;]*;`),
      `${moduleName} is loaded by the canonical route`,
    );
  }
});
