import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const sourceUrl = new URL('../../scripts/ceremony/tp-g3-shadow-three-session-proof.mjs', import.meta.url);

test('TP-G3 ceremony keeps authority native, signed, and phase bounded', async () => {
  const source = await readFile(sourceUrl, 'utf8');

  assert.match(source, /sessionMemoryOwner\.appendTurn/);
  assert.match(source, /sessionMemoryOwner\.finalizeSession/);
  assert.match(source, /persistMemory\(/);
  assert.match(source, /systemConfigLedger\.commitConfigValue/);
  assert.match(source, /systemConfigStore\.readVerifiedConfig\(POLICY_KEY\)/);
  assert.match(source, /resolveNativeRecallAuthority/);
  assert.match(source, /executeNativeRecall/);
  assert.match(source, /signAsHousekeeper/);
  assert.match(source, /readPassphrase\('Master passphrase: '\)/);
  assert.match(source, /Type exactly/);
  assert.doesNotMatch(source, /process\.env/);
  assert.doesNotMatch(source, /DELETE\s+FROM|UPDATE\s+aimos_memories|is_active\s*=\s*false/i);
  assert.doesNotMatch(source, /(?:arm|lambda_t|gamma)\s*:\s*cliValue/);
  assert.match(source, /execution: 'shadow'/);
  assert.match(source, /cache: 'off'/);
  assert.match(source, /early_exit: 'off'/);
});

test('TP-G3 ceremony proves restart, scope, idempotency, and immutable recall state', async () => {
  const source = await readFile(sourceUrl, 'utf8');

  assert.match(source, /tp_g3_server_restart_not_observed/);
  assert.match(source, /tp_g3_cross_scope_contamination/);
  assert.match(source, /tp_g3_resume_reconstructed_receipt_missing/);
  assert.match(source, /repeated_receipts_independently_reconstructed: true/);
  assert.match(source, /repeated_disclosure_idempotent: true/);
  assert.match(source, /tp_g3_resume_distinct_recall_events_missing/);
  assert.match(source, /fixture_projection_sha256/);
  assert.match(source, /aimos_memory_epistemic_classifications/);
  assert.match(source, /aimos_cognitive_weight_projections/);
  assert.match(source, /aimos_cognitive_weight_baselines/);
  assert.match(source, /current_epistemic_label === 'poison_likely'/);
  assert.match(source, /supersedes_id: predecessor\.id/);
  assert.match(source, /equalRows\[0\]\.created_at === equalRows\[1\]\.created_at/);
});
