import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  applyCalibrationSnapshot,
  calibrateBelief,
  reconstructCalibrationSnapshot,
} from '../../services/retrieval/recall-calibrator.js';

function hash(label) {
  return createHash('sha256').update(label).digest();
}

function fixture() {
  const genesis = {
    id: '11111111-1111-4111-8111-111111111111',
    operation: 'recall_calibration_genesis',
    ledger_seq: 1,
    mutation_hash: hash('calibration-genesis'),
    metadata: {
      schema: 'hom.aimos.recall-calibration/v1',
      formula_version: 'sortify-belief-lms/eta-0.2/aimos-guardrails-v1',
      alpha: 1,
      beta: 0,
      learning_rate: 0.2,
      last_observation_seq: 0,
    },
  };
  const observation = {
    id: '22222222-2222-4222-8222-222222222222',
    operation: 'recall_calibration_observation_batch',
    ledger_seq: 2,
    mutation_hash: hash('calibration-observation'),
    metadata: {
      schema: genesis.metadata.schema,
      formula_version: genesis.metadata.formula_version,
      observations: [{
        memory_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        recall_event_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        recall_mutation_hash: 'c'.repeat(64),
        calibration_mutation_hash: genesis.mutation_hash.toString('hex'),
        raw_score: 0.8,
        calibrated_score: 0.8,
        observed_usefulness: 0,
        label_source: 'held_out_relevance',
      }],
    },
  };
  const update = {
    id: '33333333-3333-4333-8333-333333333333',
    operation: 'recall_calibration_update',
    ledger_seq: 3,
    mutation_hash: hash('calibration-update'),
    metadata: {
      schema: genesis.metadata.schema,
      formula_version: genesis.metadata.formula_version,
      previous_calibration_event_id: genesis.id,
      previous_calibration_mutation_hash: genesis.mutation_hash.toString('hex'),
      old_alpha: 1,
      old_beta: 0,
      new_alpha: 0.872,
      new_beta: -0.16,
      learning_rate: 0.2,
      corrections: 1,
      observation_count: 1,
      observation_event_sequences: [2],
      last_observation_seq: 2,
    },
  };
  return { genesis, observation, update };
}

test('signed calibration reconstruction applies each observation exactly once', () => {
  const { genesis, observation, update } = fixture();
  const snapshot = reconstructCalibrationSnapshot([genesis, observation, update]);
  assert.equal(snapshot.alpha, 0.872);
  assert.ok(Math.abs(snapshot.beta - (-0.16)) < 1e-12);
  assert.equal(snapshot.verifiedObservationCount, 1);
  assert.equal(snapshot.pendingObservationCount, 0);
  assert.equal(snapshot.calibrationEventId, update.id);
  assert.ok(Math.abs(calibrateBelief(0.5, snapshot) - 0.276) < 1e-12);

  assert.throws(
    () => reconstructCalibrationSnapshot([
      genesis,
      observation,
      { ...update, metadata: { ...update.metadata, new_beta: -0.15 } },
    ]),
    /transition_invalid/,
  );
});

test('housekeeper custody rotation preserves one logical calibration stream across signer epochs', () => {
  const { genesis, observation, update } = fixture();
  const oldEpoch = '2026-07-10T16:42:21.000Z';
  const newEpoch = '2026-08-11T11:21:00.000Z';
  const snapshot = reconstructCalibrationSnapshot([
    { ...genesis, ledger_seq: 49, signer_valid_from: oldEpoch },
    {
      id: '44444444-4444-4444-8444-444444444444',
      operation: 'unrelated_signed_event',
      ledger_seq: 20_340,
      signer_valid_from: oldEpoch,
      mutation_hash: hash('unrelated-old-epoch-event'),
      metadata: {},
    },
    { ...observation, ledger_seq: 1, signer_valid_from: newEpoch },
    { ...update, ledger_seq: 2, signer_valid_from: newEpoch },
  ]);
  assert.equal(snapshot.alpha, 0.872);
  assert.ok(Math.abs(snapshot.beta - (-0.16)) < 1e-12);
  assert.equal(snapshot.lastObservationSequence, 2);
  assert.equal(snapshot.pendingObservationCount, 0);
});

test('one immutable calibration snapshot annotates every returned memory', () => {
  const { genesis, observation, update } = fixture();
  const snapshot = reconstructCalibrationSnapshot([genesis, observation, update]);
  const memories = [{ id: 'a', rerank_score: 0.5 }, { id: 'b', recall_confidence: 0.9 }];
  applyCalibrationSnapshot(memories, snapshot);
  assert.ok(Math.abs(memories[0].calibrated_recall_score - 0.276) < 1e-12);
  assert.ok(Math.abs(memories[1].calibrated_recall_score - 0.6248) < 1e-12);
  assert(memories.every((memory) => memory.calibration_mutation_hash === snapshot.calibrationMutationHash));
  assert.throws(
    () => applyCalibrationSnapshot(memories, { ...snapshot, calibrationMutationHash: 'f'.repeat(64) }),
    /mixed_calibration_snapshot/,
  );
});

test('runtime contains no unsigned calibration projection or fake ORCA implementation', async () => {
  const [calibrator, pipeline, receipt, cache, migration] = await Promise.all([
    readFile(new URL('../../services/retrieval/recall-calibrator.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/retrieval/native-recall.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/caching/semantic-cache.js', import.meta.url), 'utf8'),
    readFile(new URL('../../migrations/063-retire-unsigned-recall-calibration.sql', import.meta.url), 'utf8'),
  ]);
  assert.doesNotMatch(calibrator, /\b(?:INSERT INTO recall_observations|UPDATE recall_calibration|ON CONFLICT \(company_id, channel\)|selectLTTThreshold|computeConformalInterval|computeTTTFastWeights|calibratePreference)\b/);
  assert.match(pipeline, /const calibrationSnapshot = await getVerifiedCalibrationSnapshot\(company, \{[\s\S]*?verifiedAdmissionSession\.read/);
  assert.match(pipeline, /applyCalibrationSnapshot\(memories, calibrationSnapshot\)/);
  assert.doesNotMatch(pipeline, /recall-calibrator error \(non-fatal\)/);
  assert.match(receipt, /raw_calibration_score/);
  assert.match(receipt, /calibration_mutation_hash/);
  assert.match(cache, /calibrationMutationHash/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public\.recall_calibration FROM agent_runtime/);
});
