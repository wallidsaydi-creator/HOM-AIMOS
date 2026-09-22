import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1,
  ORIGIN_LEDGER_AUTHORITY_PROFILE_V1,
  originLedgerEnvelopeHashV1,
} from '../../services/security/origin-ledger.js';

const schema = readFileSync(
  new URL('../../migrations/100-origin-family-ledger-and-writers.sql', import.meta.url),
  'utf8',
);
const writers = readFileSync(
  new URL('../../migrations/101-origin-family-typed-writers.sql', import.meta.url),
  'utf8',
);
const independentParity = readFileSync(
  new URL('../../migrations/103-origin-writer-independent-crypto-parity.sql', import.meta.url),
  'utf8',
);
const byteOrder = readFileSync(
  new URL('../../migrations/105-origin-security-family-byte-order.sql', import.meta.url),
  'utf8',
);

test('OB-2 authority profile and ledger envelope have frozen byte vectors', () => {
  assert.equal(ORIGIN_LEDGER_AUTHORITY_PROFILE_V1.signer, 'housekeeper');
  assert.equal(ORIGIN_LEDGER_AUTHORITY_PROFILE_V1.signature, 'ed25519');
  assert.equal(
    ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1,
    '14001dd244e7e3276eb27c145f00abe41ec121908c65a2cf1eef571b922037b3',
  );
  assert.equal(originLedgerEnvelopeHashV1({
    objectSchema: 'hom.aimos.memory-origin-binding/v1',
    objectSha256: '11'.repeat(32),
    previousLedgerHash: '22'.repeat(32),
    databaseContextSha256: '33'.repeat(32),
    signerValidFrom: '2026-08-11T11:21:00.000Z',
    signedAt: '2026-09-01T18:00:00.000Z',
  }).toString('hex'), 'f8414d9bb80cac344bb5551eb629b9cb480cf361d891fc9a00a2ce21cf5653c7');
});

test('OB-5 v2 elevation occupies the same native no-fork ledger envelope domain', () => {
  assert.equal(originLedgerEnvelopeHashV1({
    objectSchema: 'hom.aimos.origin-elevation/v2',
    objectSha256: '44'.repeat(32),
    previousLedgerHash: '55'.repeat(32),
    databaseContextSha256: '66'.repeat(32),
    signerValidFrom: '2026-08-11T11:21:00.000Z',
    signedAt: '2026-09-19T17:10:00.000Z',
  }).toString('hex'), '2b1c59ce16dceb66f9ab7f5c6480787e74fee143c00ffdccb2012e278e66558d');
});

test('OB-2 schema has three typed append-only families and one no-fork envelope', () => {
  for (const table of [
    'aimos_memory_origin_bindings',
    'aimos_origin_elevations',
    'aimos_action_origin_verdicts',
    'aimos_origin_ledger_entries',
  ]) {
    assert.match(schema, new RegExp(`CREATE TABLE public\\.${table}`));
    assert.match(schema, new RegExp(`REVOKE ALL ON[\\s\\S]*${table}`));
  }
  assert.match(schema, /aimos_origin_ledger_one_genesis/);
  assert.match(schema, /aimos_origin_ledger_one_successor/);
  assert.doesNotMatch(schema, /GRANT\s+(?:INSERT|UPDATE|DELETE|TRUNCATE)/i);
  assert.doesNotMatch(schema, /CREATE\s+(?:TRIGGER|RULE)/i);
});

test('OB-2 exposes only the state read and three exact writers to agent_runtime', () => {
  for (const writer of [
    'commit_memory_origin_binding_v1',
    'commit_origin_elevation_v1',
    'commit_action_origin_verdict_v1',
  ]) {
    assert.match(writers, new RegExp(`CREATE FUNCTION public\\.${writer}`));
    assert.match(writers, new RegExp(`GRANT EXECUTE ON FUNCTION[\\s\\S]*${writer}`));
  }
  assert.match(schema, /GRANT EXECUTE ON FUNCTION public\.ob2_read_origin_ledger_state\(text\) TO agent_runtime/);
  assert.match(schema, /pgsodium\.crypto_sign_verify_detached/);
  assert.match(writers, /origin_memory_relational_mismatch/);
  assert.match(writers, /origin_parent_lattice_invalid/);
  assert.match(writers, /origin_elevation_authority_invalid/);
  assert.match(writers, /origin_verdict_semantics_invalid/);
  assert.match(independentParity, /ob2_verify_request_occurrence_authority/);
  assert.match(independentParity, /pgsodium\.crypto_sign_verify_detached/);
  assert.match(independentParity, /ob2_validate_corroborators/);
  assert.match(independentParity, /ob2_validate_security_values/);
  assert.match(byteOrder, /ORDER BY convert_to\(distinct_family\.family,'UTF8'\)/);
});

test('OB-2 envelope rejects wrong domain and malformed commitments before signing', () => {
  assert.throws(() => originLedgerEnvelopeHashV1({
    objectSchema: 'hom.aimos.wrong/v1',
    objectSha256: '11'.repeat(32),
    databaseContextSha256: '33'.repeat(32),
    signerValidFrom: '2026-08-11T11:21:00.000Z',
    signedAt: '2026-09-01T18:00:00.000Z',
  }), /origin_ledger_envelope_scope_invalid/);
  assert.throws(() => originLedgerEnvelopeHashV1({
    objectSchema: 'hom.aimos.memory-origin-binding/v1',
    objectSha256: '11',
    databaseContextSha256: '33'.repeat(32),
    signerValidFrom: '2026-08-11T11:21:00.000Z',
    signedAt: '2026-09-01T18:00:00.000Z',
  }), /origin_ledger_hash_invalid/);
});
