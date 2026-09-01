import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { validateOutcomeMutationEvidence } from '../../services/learning/mutation-composition/principal-state.js';
import {
  MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2,
  evaluateMutMemPortableMutationBundleV2,
} from '../../services/security/protocol/mutmem-portable-mutation-v2.js';
import {
  createMutMemPortableMutationVectorsV2,
} from '../../scripts/verification/mutmem-portable-mutation-fixture-factory.mjs';

const vectors = createMutMemPortableMutationVectorsV2();

test('P1 mutation vectors cover all terminal classes and every failure code', () => {
  assert.equal(vectors.filter((vector) => vector.expected === 'valid').length, 3);
  assert.deepEqual(
    vectors.filter((vector) => vector.expected === 'valid')
      .map((vector) => vector.bundle.terminal.kind).sort(),
    ['authorized_transition', 'occurrence_observation', 'signed_noop'],
  );
  assert.deepEqual(
    vectors.filter((vector) => vector.expected === 'invalid')
      .map((vector) => vector.reason).sort(),
    [...MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2].sort(),
  );
});

for (const vector of vectors) {
  test(`P1 mutation vector ${vector.id} has exact terminal ${vector.expected}`, () => {
    if (vector.expected === 'valid') {
      const result = evaluateMutMemPortableMutationBundleV2(vector.bundle);
      assert.equal(result.valid, true);
      assert.equal(result.terminal_kind, vector.bundle.terminal.kind);
      assert.equal(result.native_outcome_schema_preserved, true);
      assert.equal(result.cryptographic_signatures_verified, false);
      assert.deepEqual(
        validateOutcomeMutationEvidence(vector.bundle.outcome_evidence),
        vector.bundle.outcome_evidence,
      );
      return;
    }
    assert.throws(
      () => evaluateMutMemPortableMutationBundleV2(vector.bundle),
      new RegExp(`mutmem_portable_mutation_v2:${vector.reason}$`),
    );
  });
}

test('P1 mutation protocol and fixture owners are authority-free', async () => {
  const [owner, fixture] = await Promise.all([
    readFile(new URL(
      '../../services/security/protocol/mutmem-portable-mutation-v2.js',
      import.meta.url,
    ), 'utf8'),
    readFile(new URL(
      '../../scripts/verification/mutmem-portable-mutation-fixture-factory.mjs',
      import.meta.url,
    ), 'utf8'),
  ]);
  assert.doesNotMatch(`${owner}\n${fixture}`,
    /process\.env|fetch\(|writeFile\(|query\(|pool\.|\bsign\(|createPrivateKey|routes\/|jobs\//);
});
