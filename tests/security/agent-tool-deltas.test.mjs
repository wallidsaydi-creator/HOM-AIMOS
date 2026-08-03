import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { mergeToolDeltas } from '../../routes/agent-shared.js';

test('tool delta merge normalizes deterministic unions with deny winning', () => {
  assert.deepEqual(
    mergeToolDeltas(
      { allow: [' x_search ', 'delegate_task', 'x_search'], deny: ['gmail-send'] },
      { allow: ['gmail-send', ' web-search '], deny: [' delegate_task ', 'gmail-send'] }
    ),
    {
      allow: ['web-search', 'x_search'],
      deny: ['delegate_task', 'gmail-send']
    }
  );
  assert.deepEqual(mergeToolDeltas({ allow: 'delegate_task' }, null), { allow: [], deny: [] });
});

test('intelligence specialist and checker resolutions deny delegate_task', () => {
  const executionSource = fs.readFileSync(
    new URL('../../routes/agent-execution.js', import.meta.url),
    'utf8'
  );

  assert.match(
    executionSource,
    /mergeToolDeltas\(specialistResolution\.toolDeltas, \{ deny: \['delegate_task'\] \}\)/
  );
  assert.match(
    executionSource,
    /mergeToolDeltas\(checkerResolution\.toolDeltas, \{ deny: \['delegate_task'\] \}\)/
  );

  for (const role of ['specialist', 'checker']) {
    const merged = mergeToolDeltas(
      { allow: ['delegate_task', `${role}_tool`], deny: [] },
      { deny: ['delegate_task'] }
    );
    assert.equal(merged.allow.includes('delegate_task'), false, `${role} allow must not retain delegation`);
    assert.equal(merged.deny.includes('delegate_task'), true, `${role} deny must lock delegation`);
  }
});
