import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function census() {
  return JSON.parse(execFileSync(process.execPath, [
    path.join(ROOT, 'scripts/verification/prove-cr7-durable-action-census.mjs'),
    '--json',
  ], { cwd: ROOT, encoding: 'utf8' }));
}

test('CR7-R0 freezes a total executable effect census without claiming open sites closed', () => {
  const result = census();
  assert.equal(result.schema, 'hom.aimos.cr7-executable-effect-census/v1');
  assert.equal(result.source_file_count, 365);
  assert.equal(result.effect_site_count, 103);
  assert.equal(result.unclassified_effect_site_count, 0);
  // The Codex OAuth freshness repair shifts existing provider-call line numbers;
  // the effect-site count, classes, ownership, and source anchors are unchanged.
  assert.equal(result.effect_root_sha256, '305c0048188c8f944080abd8454bbcfc1e82ea3a3b3902cbf1156e4259758859');
  assert.deepEqual(result.by_class, {
    durable_database: 37,
    durable_file: 15,
    external_effect: 39,
    credential_effect: 4,
    destructive_offline_effect: 8,
  });
  assert.equal(result.by_ownership_status.OPEN_UNRECONCILED || 0, 0);
  assert.equal(result.by_ownership_status.R5_EXTERNAL_START_TERMINAL, 23);
  assert.equal(result.by_ownership_status.R5_FILE_START_TERMINAL, 13);
  assert.equal(result.by_ownership_status.R5_CREDENTIAL_USE_START_TERMINAL, 14);
  assert.equal(result.by_ownership_status.R5_SUBORDINATE_TRANSPORT, 2);
  assert.equal(result.by_ownership_status.R4_OPERATIONAL_ATOMIC, 10);
  assert.equal(result.by_ownership_status.CANDIDATE_ATOMIC_EXISTING_LEDGER, 23);
  assert.equal(result.by_ownership_status.OFFLINE_SIGNED_MAINTENANCE, 3);
  assert.equal(result.by_ownership_status.R3_CREDENTIAL_CUSTODY_START_TERMINAL, 4);
  assert.equal(result.by_ownership_status.RETAINED_OFFLINE_SIGNED_CEREMONY, 8);
  assert.equal(result.by_ownership_status.DORMANT_UNREACHABLE, 3);
  assert.equal(result.effects.every((effect) => effect.effect_id && effect.required_binding), true);
});
