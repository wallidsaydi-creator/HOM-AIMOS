import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveFreshnessWriteFields } from '../../services/temporal/freshness-metadata.js';

test('research benchmark imports are not stamped as freshly fact-verified', () => {
  const fields = resolveFreshnessWriteFields({
    key: 'sess:benchmark:reference:1',
    memoryType: 'research',
    source: 'benchmark:poisonedrag',
  });
  assert.equal(fields.freshness_state, 'historical');
  assert.equal(fields.last_verified_at, null);
  assert.equal(fields.verified_by, null);
  assert.equal(fields.verification_basis, 'reference_import');
});

test('an explicit independent verifier remains preserved', () => {
  const fields = resolveFreshnessWriteFields({
    key: 'paper:verified-result',
    memoryType: 'research',
    source: 'import:paper',
    lastVerifiedAt: '2026-07-21T00:00:00.000Z',
    verifiedBy: 'paper-auditor',
    verificationBasis: 'independent_evidence',
  });
  assert.equal(fields.last_verified_at, '2026-07-21T00:00:00.000Z');
  assert.equal(fields.verified_by, 'paper-auditor');
  assert.equal(fields.verification_basis, 'independent_evidence');
});
