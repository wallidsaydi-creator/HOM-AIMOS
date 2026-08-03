import test from 'node:test';
import assert from 'node:assert/strict';

import { orderMemoryVersionsByTopology } from '../../services/temporal/temporal-resolver.js';

test('memory versions follow supersession links rather than transaction timestamps', () => {
  const root = { id: 'root', supersedes_id: null, created_at: '2026-07-11T12:00:02Z' };
  const successor = { id: 'successor', supersedes_id: 'root', created_at: '2026-07-11T12:00:01Z' };
  const head = { id: 'head', supersedes_id: 'successor', created_at: '2026-07-11T12:00:03Z' };
  assert.deepEqual(orderMemoryVersionsByTopology([head, root, successor]), [root, successor, head]);
});

test('memory version topology fails closed on roots, forks, and missing links', () => {
  const root = { id: 'root', supersedes_id: null };
  assert.throws(
    () => orderMemoryVersionsByTopology([root, { id: 'other-root', supersedes_id: null }]),
    /memory_topology_root_invalid/,
  );
  assert.throws(
    () => orderMemoryVersionsByTopology([
      root,
      { id: 'child-a', supersedes_id: 'root' },
      { id: 'child-b', supersedes_id: 'root' },
    ]),
    /memory_topology_fork/,
  );
  assert.throws(
    () => orderMemoryVersionsByTopology([root, { id: 'orphan', supersedes_id: 'missing' }]),
    /memory_topology_disconnected/,
  );
});
