import assert from 'node:assert/strict';
import test from 'node:test';

import { proveCr7R2DatabaseLocalClosure } from '../../scripts/verification/prove-cr7-r2-database-local-closure.mjs';

test('CR7-R2 verifier proves relational and privilege progression without absorbing later gates', () => {
  const proof = proveCr7R2DatabaseLocalClosure();
  assert.equal(proof.valid, true);
  assert.equal(proof.frozen_r2_census_root_sha256, '648ce46c02ca493b4a2e6620c42656f646cd017fd5a91ba32dbf08d4185be1c4');
  assert.equal(proof.current_census_root_sha256, '0b6b2828d79138dc74929c99057e0e94b62f4b96ea4f964e7952a7895bcd2ac3');
  assert.equal(proof.frozen_r2_owner_audit_root_sha256, 'a3715ebc1213c239863859f8a141264ec41ae1f4e9c47bb1292a6f705f5f57b3');
  assert.equal(proof.current_owner_audit_root_sha256, '15b94dcb8492676bad02cd2c5f6d1af7cbb277de4503896aeb25493d9eaae9af');
  assert.equal(proof.checks.historical_r0_effect_count, 160);
  assert.equal(proof.checks.current_effect_count, 104);
  assert.equal(proof.checks.broad_concept_edge_writer_removed, true);
  assert.equal(proof.checks.entity_edge_exact_projection, true);
  assert.equal(proof.checks.restricted_standalone_defaults, true);
  assert.equal(proof.checks.offline_maintenance_scopes, true);
  assert.equal(proof.checks.runtime_open_sites_preserved_for_later_gates, 0);
  assert.equal(proof.checks.external_partial_sites_preserved_for_r5, 0);
  assert.equal(proof.checks.external_complete_sites_closed_by_r5, 14);
  assert.equal(proof.migration_added, false);
  assert.equal(proof.frozen_r2_proof_root_sha256, '84dcd1bc3331d10bc67c48d696852d78c90f1d6057acfd732f139376f840861f');
  assert.match(proof.proof_root_sha256, /^[0-9a-f]{64}$/);
});
