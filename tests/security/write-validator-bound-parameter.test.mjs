import assert from 'node:assert/strict';
import test from 'node:test';

import { buildWriteValidationDiagnostics } from '../../services/write/write-validator.js';

const KEY = 'mutmem:v2:campaign:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

test('quoted SQL is inert bound-parameter vocabulary and requires no SE gate', () => {
  const value = 'Documentation example: sql = "INSERT INTO audit_log (message) VALUES (?)"; this is quoted source evidence.';
  const bound = buildWriteValidationDiagnostics({ agentId: 'codex-auditor', targetKey: KEY, newValue: value });
  assert.equal(bound.checks.injection.pass, true);
  assert.equal(bound.checks.injection.reason, undefined);
});

test('byte-level unsafe input remains blocked while SE is disabled', () => {
  const result = buildWriteValidationDiagnostics({ agentId: 'codex-auditor', targetKey: KEY, newValue: 'unsafe\0value' });
  assert.equal(result.checks.injection.pass, false);
});
