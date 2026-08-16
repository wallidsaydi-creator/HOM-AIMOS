import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

test('fixed-point certificate math matches the independent high-precision reference', () => {
  const output = execFileSync('python3', [
    path.join(root, 'scripts', 'verification', 'verify-epistemic-certificate-math.py'),
    '--vectors',
    path.join(root, 'tests', 'fixtures', 'epistemic-edit-certificate-math-v1.json'),
  ], { cwd: root, encoding: 'utf8' });
  const result = JSON.parse(output);
  assert.equal(result.success, true);
  assert.deepEqual(result.failures, []);
  assert.equal(result.results.length, 5);
});
