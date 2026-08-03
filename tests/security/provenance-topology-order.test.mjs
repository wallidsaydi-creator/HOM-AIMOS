import test from 'node:test';
import assert from 'node:assert/strict';

import { orderProvenanceRowsByTopology } from '../../services/security/memory-provenance.js';

function hash(byte) {
  return Buffer.alloc(32, byte);
}

test('provenance order follows signed links despite timestamp and UUID inversion', () => {
  const genesis = {
    provenance_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
    mutation_hash: hash(1),
    prev_mutation_hash: null,
    created_at: '2026-07-11T12:00:02.000Z',
  };
  const save = {
    provenance_id: '00000000-0000-4000-8000-000000000000',
    mutation_hash: hash(2),
    prev_mutation_hash: hash(1),
    created_at: '2026-07-11T12:00:03.000Z',
  };
  const bindingFromOlderTransaction = {
    provenance_id: '11111111-1111-4111-8111-111111111111',
    mutation_hash: hash(3),
    prev_mutation_hash: hash(2),
    created_at: '2026-07-11T12:00:01.000Z',
  };

  assert.deepEqual(
    orderProvenanceRowsByTopology([save, bindingFromOlderTransaction, genesis]),
    [genesis, save, bindingFromOlderTransaction],
  );
});

test('provenance topology fails closed on forks, missing links, and multiple roots', () => {
  const root = { mutation_hash: hash(1), prev_mutation_hash: null };
  const successor = { mutation_hash: hash(2), prev_mutation_hash: hash(1) };

  assert.throws(
    () => orderProvenanceRowsByTopology([
      root,
      successor,
      { mutation_hash: hash(3), prev_mutation_hash: hash(1) },
    ]),
    /provenance_topology_fork/,
  );
  assert.throws(
    () => orderProvenanceRowsByTopology([
      root,
      successor,
      { mutation_hash: hash(3), prev_mutation_hash: hash(9) },
    ]),
    /provenance_topology_disconnected/,
  );
  assert.throws(
    () => orderProvenanceRowsByTopology([
      root,
      { mutation_hash: hash(3), prev_mutation_hash: null },
    ]),
    /provenance_topology_genesis_invalid/,
  );
});
