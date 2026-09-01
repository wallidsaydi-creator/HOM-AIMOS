import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const SOURCE = new URL(
  '../../scripts/verification/prove-mutmem-p1-live-projection.mjs',
  import.meta.url,
);

test('P1 live projector crosses only canonical signed recall and retained read evidence', async () => {
  const source = await readFile(SOURCE, 'utf8');
  assert.match(source, /buildEnvelopeHeaders\('codex-auditor', 'POST', '\/aimos\/recall', requestBody\)/);
  assert.match(source, /fetch\('http:\/\/127\.0\.0\.1:9100\/aimos\/recall'/);
  assert.match(source, /provenance\.sig_form_version=3/);
  assert.match(source, /createMutMemPortableEvidenceEnvelopeV2/);
  assert.match(source, /evaluateMutMemPortablePredicatesV2/);
  assert.doesNotMatch(source, /\/aimos\/save|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM|TRUNCATE|CREATE\s+(?:TABLE|DATABASE)|DROP\s+(?:TABLE|DATABASE)/i);
  assert.doesNotMatch(source, /requestBody\s*=\s*\{[^}]*agent_id|requestBody\s*=\s*\{[^}]*company_id|source_filter/s);
});

test('P1 live projector retains identity-bearing evidence privately and reports no memory write', async () => {
  const source = await readFile(SOURCE, 'utf8');
  assert.match(source, /private_identity_bearing_artifact: true/);
  assert.match(source, /writeFile\(artifact, bytes, \{ mode: 0o600, flag: 'wx' \}\)/);
  assert.match(source, /memory_write: false/);
  assert.match(source, /domain_database_mutation: false/);
});
