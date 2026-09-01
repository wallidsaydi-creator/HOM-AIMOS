import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildEntityEdgeProjection } from '../../services/write/persist-memory.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (relativePath) => readFileSync(path.join(ROOT, relativePath), 'utf8');

function walk(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(absolute) : [absolute];
  });
}

test('entity-edge projection root is order-invariant and binds every relational field', () => {
  const rows = [
    { id: 2, company_id: 'hom', memory_id: '20000000-0000-4000-8000-000000000002', entity: 'rome platform', entity_type: 'proper_noun' },
    { id: 1, company_id: 'hom', memory_id: '20000000-0000-4000-8000-000000000002', entity: 'codex memory', entity_type: 'proper_noun' },
  ];
  const first = buildEntityEdgeProjection(rows);
  const reordered = buildEntityEdgeProjection([...rows].reverse());
  const changed = buildEntityEdgeProjection([{ ...rows[0], entity: 'milan platform' }, rows[1]]);
  assert.deepEqual(first, reordered);
  assert.notEqual(first.projection_root_sha256, changed.projection_root_sha256);
  assert.deepEqual(first.records.map((record) => record.row_id), [1, 2]);
  assert.match(first.projection_root_sha256, /^[0-9a-f]{64}$/);
});

test('R2 removes the unreachable broad Concept-edge writer and preserves only its portable verifier', () => {
  const owner = read('services/security/concept-edge-provenance.js');
  const graph = read('services/core/concept-graph.js');
  assert.doesNotMatch(owner, /withTransaction|logEvent\(|INSERT\s+INTO\s+concept_edges|appendSignedConceptEdge/);
  assert.doesNotMatch(graph, /appendSignedConceptEdge|linkToConcepts|linkDerived/);
  assert.match(owner, /portable historical receipt contract and verifier/);
  assert.match(owner, /verifyConceptEdgeReceipt/);
});

test('standalone provenance, lineage and SAVE envelope default to the restricted runtime pool', () => {
  for (const relativePath of [
    'services/security/memory-provenance.js',
    'services/security/memory-lineage.js',
    'services/security/save-envelope.js',
  ]) {
    const source = read(relativePath);
    assert.match(source, /agentPool as defaultPool/);
    assert.doesNotMatch(source, /pool as defaultPool/);
  }
});

test('broad-pool administrative mutations are explicit offline maintenance with zero runtime caller', () => {
  const contracts = [
    ['services/governance/governor-config-ledger.js', 'GOVERNOR_CONFIG_MUTATION_SCOPE', /\.commitConfigFlag\(/],
    ['services/security/system-config-ledger.js', 'SYSTEM_CONFIG_MUTATION_SCOPE', /\.commitConfigValue\(/],
    ['services/security/recall-authorization.js', 'RECALL_AUTHORIZATION_MUTATION_SCOPE', /recallAuthorizationService\.commit\(/],
  ];
  const productionFiles = [path.join(ROOT, 'server.js'), ...['routes', 'services', 'jobs']
    .flatMap((directory) => walk(path.join(ROOT, directory)))].filter((file) => file.endsWith('.js'));
  for (const [ownerPath, constant, callPattern] of contracts) {
    assert.match(read(ownerPath), new RegExp(`${constant} = 'offline_maintenance_only'`));
    const callers = productionFiles
      .filter((file) => path.relative(ROOT, file) !== ownerPath)
      .filter((file) => callPattern.test(readFileSync(file, 'utf8')))
      .map((file) => path.relative(ROOT, file));
    assert.deepEqual(callers, [], ownerPath);
  }
});

test('canonical SAVE binds exact entity rows to a same-transaction signed event and terminal trace', () => {
  const source = read('services/write/persist-memory.js');
  assert.match(source, /memory_entity_edges_committed/);
  assert.match(source, /entity_edge_projection_root_sha256/);
  assert.match(source, /entity_edge_authority_event_id/);
  assert.match(source, /RETURNING id, company_id, entity, entity_type, memory_id/);
  assert.match(source, /client: txClient/);
});
