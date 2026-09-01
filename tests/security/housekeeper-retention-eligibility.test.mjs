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

test('SPICED retained-memory reads remain tenant-bound', async () => {
  const text = await source('services/dream/spiced-consolidator.js');

  assert.match(
    text,
    /SELECT id,retrieval_weight FROM aimos_memories WHERE company_id=\$1 AND id=ANY\(\$2::uuid\[\]\)/,
  );
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
    /FROM aimos_memories\s+WHERE company_id = \$1 AND id = ANY\(\$4\)/,
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
  assert.match(text, /retrieval_weight \* \$2/);
  assert.match(text, /logEvent\(COMPANY, 'housekeeper', 'spiced_consolidation_amplified'/);
  assert.match(text, /\{ restricted: true, client_id: COMPANY, agent_id: 'housekeeper' \}/);
});
