import assert from 'node:assert/strict';
import test from 'node:test';

import {
  getAuthorizedRecallDataClasses,
} from '../../services/retrieval/native-recall-pipeline.js';

test('signed data-class ceiling still bounds a high-clearance recall', () => {
  assert.deepEqual(
    getAuthorizedRecallDataClasses(10, 'confidential'),
    ['public', 'internal', 'confidential'],
  );
});

test('numeric clearance and signed data-class authority intersect', () => {
  assert.deepEqual(
    getAuthorizedRecallDataClasses(4, 'restricted'),
    ['public', 'internal'],
  );
  assert.deepEqual(
    getAuthorizedRecallDataClasses(12, 'restricted'),
    ['public', 'internal', 'confidential', 'restricted'],
  );
});

test('unknown signed data-class authority fails closed', () => {
  assert.throws(
    () => getAuthorizedRecallDataClasses(10, 'unknown'),
    /recall_rescue_data_class_ceiling_invalid/,
  );
});
