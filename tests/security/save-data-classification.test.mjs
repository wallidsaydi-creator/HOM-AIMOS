import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyDataSensitivity } from '../../services/write/persist-memory.js';

test('descriptive credential vocabulary remains confidential without an SE gate', () => {
  const value = 'The documentation explains why a password and API token must never be pasted into chat.';
  assert.equal(classifyDataSensitivity(value, 10), 'confidential');
});

test('actual credential prefixes and assignments remain restricted', () => {
  const stripeCredentialFixture = ['sk', 'live', '1234567890'].join('_');
  assert.equal(classifyDataSensitivity(`Example ${stripeCredentialFixture} secret`, 10), 'restricted');
  assert.equal(classifyDataSensitivity('password: correct-horse-battery-staple', 10), 'restricted');
  assert.equal(classifyDataSensitivity('password: sunshine', 10), 'restricted');
  assert.equal(classifyDataSensitivity('token: AbC123!xyz99', 10), 'restricted');
  assert.equal(classifyDataSensitivity(JSON.stringify({ password: 'correct-horse-battery-staple' }), 10), 'restricted');
});

test('classification is server-derived and independent of caller-shaped security objects', () => {
  assert.equal(classifyDataSensitivity('password token credential', 10), 'confidential');
});

test('code placeholders, type annotations, and ordinary prose are not credential material', () => {
  for (const value of [
    'password: str',
    'this.password = password;',
    'api_key=YOUR_API_KEY',
    'The cooking secret: dry brining works well.',
    'A small token: appreciation is enough.',
    JSON.stringify({ turns: [{ role: 'assistant', content: 'password: str' }] }),
  ]) {
    assert.equal(classifyDataSensitivity(value, 10), 'confidential', value);
  }
});
