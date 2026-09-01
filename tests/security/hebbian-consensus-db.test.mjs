import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

test('Hebbian has one public mutation owner and no fabricated direct-hub authority', () => {
  const source = fs.readFileSync(path.join(ROOT, 'services/dream/hebbian-consensus.js'), 'utf8');
  assert.match(source, /export async function runHebbianConsensusBatch/);
  assert.doesNotMatch(source, /export async function applyConsensusReweight/);
  assert.doesNotMatch(source, /applyConsensusReweight,\s*\n\s*runHebbianConsensusBatch/);
  assert.match(source, /readFlag\(HEBBIAN_CONSTANTS\.flag_key, \{ strict: true \}\)/);
  assert.match(source, /buildVerifiedHebbianAssociationSnapshot/);
  assert.match(source, /controlCertifiedMutationProposal/);
  assert.match(source, /apply_signed_cognitive_reweight/);
  assert.doesNotMatch(source, /association_snapshot_sha256:\s*['\"](?:11)+['\"]/);
  assert.doesNotMatch(source, /verified_receipt_root_sha256:\s*['\"](?:22)+['\"]/);
});
