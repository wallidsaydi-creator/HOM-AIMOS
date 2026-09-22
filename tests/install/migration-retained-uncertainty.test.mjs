import assert from 'node:assert/strict';
import test from 'node:test';

import { retainedHistoricalChecksumUncertainty } from '../../migrations/run.js';

test('migration runner accepts only the two exact CR9 retained uncertainties', () => {
  assert.equal(retainedHistoricalChecksumUncertainty(
    '098-request-receipt-occurrence-lookup.sql',
    '1d9288168577df1f3eba64c33932e7ed3d44548d0ece27126a474e466a21fc4a',
    'fed5e24f61751e6fea7efc01178f8cfd28ff2a3494abec9c971fdade7479925e',
  ), true);
  assert.equal(retainedHistoricalChecksumUncertainty(
    '099-occurrence-attributed-mutation-evidence.sql',
    '5fd0ce46a65cef460feb7769789d4cdc54770d838a12f2bddae7091edb4df01a',
    'b4fd7e3b9360843c3538d1c052cfbccf77bcef25f9f4c7e88bcf98320f0224f8',
  ), true);
  assert.equal(retainedHistoricalChecksumUncertainty(
    '098-request-receipt-occurrence-lookup.sql',
    '00'.repeat(32),
    'fed5e24f61751e6fea7efc01178f8cfd28ff2a3494abec9c971fdade7479925e',
  ), false);
  assert.equal(retainedHistoricalChecksumUncertainty(
    '100-origin-family-ledger-and-writers.sql',
    '00'.repeat(32),
    '11'.repeat(32),
  ), false);
});
