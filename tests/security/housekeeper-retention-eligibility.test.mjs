import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

async function source(relativePath) {
  return readFile(new URL(relativePath, ROOT), 'utf8');
}

const lifecycleExclusions = [
  /\bis_active\s*=\s*(?:true|false)\b/i,
  /\bvalid_until\s*(?:<|<=|>|>=|=)\s*/i,
  /\bexpires?_at\s*(?:<|<=|>|>=|=)\s*/i,
  /\bsuperseded_by\s+is\s+null\b/i,
  /\bsupersedes_id\s+is\s+null\b/i,
];

test('housekeeper dream reads do not exclude retained memory lifecycle states', async () => {
  for (const relativePath of [
    'jobs/nightly-dream.js',
    'services/dream/spiced-consolidator.js',
  ]) {
    const text = await source(relativePath);
    for (const forbidden of lifecycleExclusions) {
      assert.doesNotMatch(text, forbidden, `${relativePath} must not hide retained memories with ${forbidden}`);
    }
  }
});

test('SPICED retained-memory reads remain company-bound inside their native transaction', async () => {
  const text = await source('services/dream/spiced-consolidator.js');
  const governor = await source('services/governance/cohen-grossberg-energy-governor.js');
  assert.match(
    governor,
    /FROM aimos_memories\s+WHERE company_id=\$2 AND id = ANY\(\$1::uuid\[\]\)/,
  );
  assert.match(text, /readEnergyWindowSnapshot\(orderedMemoryIds, \{ client \}\)/);
  assert.match(text, /enforceEnergyBound\(orderedMemoryIds, \{ client, before: energyBefore \}\)/);
  assert.match(
    text,
    /FROM aimos_memories\s+WHERE company_id=\$1 AND id=ANY\(\$2::uuid\[\]\)\s+AND retrieval_weight >= \$3 AND retrieval_weight < \$4/,
  );
  assert.match(text, /buildVerifiedHebbianAssociationSnapshot/);
  assert.match(text, /verified_receipt_root_sha256/);
  assert.match(text, /spiced_verified_recall_activation_required/);
  assert.doesNotMatch(text, /export async function amplifyConsolidated/);
  assert.doesNotMatch(text, /export async function formEdges(?:Batch)?/);
  assert.match(text, /spiced_consolidation_started/);
  assert.match(text, /spiced_consolidation_terminal/);
  assert.doesNotMatch(text, /FROM aimos_memories[\s\S]{0,160}FOR SHARE/);
  assert.match(
    text,
    /FROM aimos_memories\s+WHERE company_id = \$1\s+AND id = ANY\(\$4::uuid\[\]\)/,
  );
  assert.doesNotMatch(
    text,
    /selectConsolidationCandidates[\s\S]*?created_at\s*>=/,
    'SPICED candidate selection must not use age as a lifecycle exclusion',
  );
});

test('SPICED Eq. 5 amplification constants and signed transaction path are unchanged', async () => {
  const text = await source('services/dream/spiced-consolidator.js');

  assert.match(text, /const CONSOLIDATION_GAMMA = 1\.3;/);
  assert.match(text, /const CONSOLIDATION_CAP = 3\.0;/);
  assert.match(text, /Math\.max\(oldWeight, Math\.min\(CONSOLIDATION_CAP, oldWeight \* effectiveGamma\)\)/);
  assert.match(text, /controlCertifiedMutationProposal/);
  assert.match(text, /apply_signed_cognitive_reweight/);
  assert.doesNotMatch(text, /async function computeCycleDelta/);
  assert.match(text, /logEvent\(COMPANY, 'housekeeper', 'spiced_consolidation_amplified'/);
  assert.match(text, /\{ restricted: true, client_id: COMPANY, agent_id: 'housekeeper' \}/);
});
