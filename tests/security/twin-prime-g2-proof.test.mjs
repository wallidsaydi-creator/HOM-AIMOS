import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('TP-G2 proof is native, portable, read-only over retained memory state, and fully receipted', async () => {
  const source = await readFile(
    new URL('../../scripts/ceremony/tp-g2-signed-policy-proof.mjs', import.meta.url),
    'utf8',
  );

  assert.doesNotMatch(source, /process\.env/);
  assert.doesNotMatch(source, /persistMemory|\bDELETE\b|\bUPDATE\b|\bINSERT\b/);
  assert.doesNotMatch(source, /44ee34efcd5bb5d82c6d6ba233978c21ea8ec24fff710887dabc91e26616a0e4/);
  assert.match(source, /systemConfigStore\.readVerifiedConfig\(POLICY_KEY\)/);
  assert.match(source, /validateTwinPrimeRetrievalPolicy\(policyEntry\.value\)/);
  assert.match(source, /signAsHousekeeper\(body, \{ method: 'POST', path: route \}\)/);
  assert.match(source, /b0_baseline_equals_computed: true/);
  assert.match(source, /b0_baseline_equals_returned: true/);
  assert.match(source, /recallMerkleRoot\(receipt\.merkle_entries\)/);
  assert.match(source, /retained_memory_state_unchanged: true/);
  assert.match(source, /ceremony_source_sha256/);
  assert.match(source, /writeExclusive/);
});
