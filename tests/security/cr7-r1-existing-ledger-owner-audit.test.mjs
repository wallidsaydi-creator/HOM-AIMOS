import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { proveCr7R1ExistingLedgerOwners } from '../../scripts/verification/prove-cr7-r1-existing-ledger-owners.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (relativePath) => readFileSync(path.join(ROOT, relativePath), 'utf8');

test('CR7-R1 independently accounts every existing-owner candidate without promotion by proximity', () => {
  const audit = proveCr7R1ExistingLedgerOwners();
  assert.equal(audit.frozen_r1_input_census_root_sha256, '648ce46c02ca493b4a2e6620c42656f646cd017fd5a91ba32dbf08d4185be1c4');
  assert.equal(audit.input_census_root_sha256, '0b6b2828d79138dc74929c99057e0e94b62f4b96ea4f964e7952a7895bcd2ac3');
  assert.equal(audit.candidate_count, 37);
  assert.equal(audit.audited_count, 37);
  assert.equal(audit.missing_candidate_count, 0);
  assert.deepEqual(audit.verdict_counts, {
    ATOMIC: 23,
    COMPLETE_START_TERMINAL: 14,
    PARTIAL: 0,
    OPEN: 0,
  });
  assert.equal(audit.frozen_r1_audit_root_sha256, 'a3715ebc1213c239863859f8a141264ec41ae1f4e9c47bb1292a6f705f5f57b3');
  assert.equal(audit.audit_root_sha256, '15b94dcb8492676bad02cd2c5f6d1af7cbb277de4503896aeb25493d9eaae9af');
  assert.equal(new Set(audit.results.map((result) => result.effect_id)).size, 37);
  assert.equal(new Set(audit.results.map((result) => result.owner_family)).size, 17);
});

test('R5 promotes credential use only after indeterminate and orphan recovery exist', () => {
  const audit = proveCr7R1ExistingLedgerOwners();
  const external = audit.results.filter((result) => result.owner_family.endsWith('credential_use'));
  assert.equal(external.length, 14);
  assert.equal(external.every((result) => result.verdict === 'COMPLETE_START_TERMINAL'), true);
  assert.equal(external.every((result) => result.limitations.length === 0), true);

  const ledger = read('services/security/credential-ledger.js');
  assert.match(ledger, /\['completed', 'failed', 'indeterminate'\]\.includes\(outcome\)/);
  assert.match(ledger, /findOpenCredentialUses/);
  assert.match(ledger, /INDETERMINATE/);
  assert.doesNotMatch(ledger, /USE_INDETERMINATE/);
});

test('R2 removes or closes the two R1 relational gaps without weakening historical verifiers', () => {
  const audit = proveCr7R1ExistingLedgerOwners();
  const conceptEdge = audit.results.find((result) => result.owner_family === 'concept_edge_projection');
  const persistenceResults = audit.results.filter((result) => result.file === 'services/write/persist-memory.js');
  assert.equal(conceptEdge, undefined);
  assert.equal(persistenceResults.length, 4);
  assert.equal(persistenceResults.every((result) => result.verdict === 'ATOMIC'), true);
  assert.equal(persistenceResults.every((result) => result.limitations.length === 0), true);

  const persistence = read('services/write/persist-memory.js');
  assert.match(persistence, /entity_edges_committed: graphEntityEdges/);
  assert.match(persistence, /entity_edge_projection_root_sha256/);
  assert.match(persistence, /memory_entity_edges_committed/);
});
