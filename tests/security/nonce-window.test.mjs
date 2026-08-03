import test from 'node:test';
import assert from 'node:assert/strict';

import { createNonceWindow } from '../../services/security/nonce-window.js';

test('nonce replay protection expires exactly at the configured window', () => {
  let now = 1_000_000;
  const window = createNonceWindow({
    capacity: 10,
    windowTtlSecs: 10,
    nowFn: () => now,
  });

  assert.equal(window.seenAndRecord('agent-a', 'nonce-1'), false);
  assert.equal(window.seenAndRecord('agent-a', 'nonce-1'), true);

  now += 9_999;
  assert.equal(window.has('agent-a', 'nonce-1'), true);
  assert.equal(window.seenAndRecord('agent-a', 'nonce-1'), true);

  now += 1;
  assert.equal(window.has('agent-a', 'nonce-1'), false);
  assert.equal(window.seenAndRecord('agent-a', 'nonce-1'), false);
});

test('expiry pruning preserves live entries and the capacity bound', () => {
  let now = 50_000;
  const window = createNonceWindow({
    capacity: 2,
    windowTtlSecs: 5,
    nowFn: () => now,
  });

  window.seenAndRecord('agent-a', 'old');
  now += 4_000;
  window.seenAndRecord('agent-a', 'live');
  now += 1_000;
  window.seenAndRecord('agent-a', 'new');

  assert.equal(window.has('agent-a', 'old'), false);
  assert.equal(window.has('agent-a', 'live'), true);
  assert.equal(window.has('agent-a', 'new'), true);
  assert.equal(window.size(), 2);
});
