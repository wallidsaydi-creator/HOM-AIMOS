import test from 'node:test';
import assert from 'node:assert/strict';
import { createP2MutationCryptographicVectors } from '../../scripts/verification/mutmem-p2-crypto-vector-factory.mjs';
import { spawnSync } from 'node:child_process';
import { canonicalBytes, sha256Hex } from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';
import { mutationBundleHash, verifyMutationBundle } from '../../verifiers/mutmem-v2/node/mutation-verifier.mjs';

const vectors = { mutation: { vectors: createP2MutationCryptographicVectors() } };
const pythonCli = new URL('../../verifiers/mutmem-v2/python/verifier_cli.py', import.meta.url).pathname;
function rehash(value) {
  const { bundle_sha256, ...bundleBody } = value.bundle;
  value.bundle.bundle_sha256 = mutationBundleHash(bundleBody);
  value.witness.mutation_bundle_sha256 = value.bundle.bundle_sha256;
  const { witness_sha256, ...witnessBody } = value.witness;
  value.witness.witness_sha256 = sha256Hex(Buffer.concat([
    Buffer.from('hom.aimos.mutmem-portable-mutation-witness/v1\0'), canonicalBytes(witnessBody),
  ]));
  return value;
}
function nodeResult(value, verifyCryptography = true) {
  try {
    verifyMutationBundle(value.bundle, {
      witness: value.witness, trustContext: value.trust_context,
      expectedMasterFingerprint: value.expected_master_fingerprint, verifyCryptography,
    });
    return { valid: true, reason: null };
  } catch (error) { return { valid: false, reason: error.reason || error.message }; }
}
function pythonResults(items, verifyCryptography = true) {
  const result = spawnSync('python3', ['-B', pythonCli], {
    input: JSON.stringify({ operation: 'batch', profile: 'mutation', items: items.map((value, id) => ({
      ...value, id, verify_cryptography: verifyCryptography,
    })) }), encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout).terminals;
}

test('AUD-001 independent verifiers reject duplicated authority substitutions without changing signatures', () => {
  const cases = [];
  const add = (base, name, mutate, reason) => {
    const value = structuredClone(base);
    mutate(value);
    cases.push({ name: `${base.bundle.terminal.kind}:${name}`, value: rehash(value), reason });
  };
  for (const base of vectors.mutation.vectors.filter((value) => value.expected === 'valid')) {
    add(base, 'positive', () => {}, null);
    add(base, 'reward-summary-and-witness', (v) => {
      v.bundle.valence_evidence.reward_sign *= -1;
      v.witness.valence_evidence.reward_sign *= -1;
    }, 'MUTATION_VALENCE_BINDING_INVALID');
    add(base, 'reward-summary-only', (v) => { v.bundle.valence_evidence.reward_sign *= -1; }, 'MUTATION_VALENCE_BINDING_INVALID');
    add(base, 'reward-witness-only', (v) => { v.witness.valence_evidence.reward_sign *= -1; }, 'MUTATION_VALENCE_SIGNATURE_INVALID');
    for (const reward of [true, '1', 0, 1.5, null]) {
      add(base, `reward-domain-${JSON.stringify(reward)}`, (v) => {
        v.bundle.valence_evidence.reward_sign = reward;
        v.witness.valence_evidence.reward_sign = reward;
      }, 'MUTATION_VALENCE_BINDING_INVALID');
    }
    for (const [field, replacement] of Object.entries({
      company_id: 'other', memory_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      context_hash: 'a'.repeat(64), identity_tier: 'T3', ts_signed: 1788109999,
      signer_agent_id: 'other', signer_valid_from: '2026-08-11T00:00:00.000Z',
      cert_fingerprint: 'a'.repeat(64), signature_b64u: 'A'.repeat(86),
    })) {
      add(base, `summary-${field}`, (v) => { v.bundle.valence_evidence[field] = replacement; }, 'MUTATION_VALENCE_SIGNATURE_INVALID');
      if (field !== 'signature_b64u') add(base, `witness-${field}`, (v) => {
        v.witness.valence_evidence[field] = replacement;
      }, 'MUTATION_VALENCE_SIGNATURE_INVALID');
    }
    add(base, 'outcome-company', (v) => { v.bundle.outcome_event.company_id = 'other'; }, 'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
    add(base, 'outcome-timestamp', (v) => { v.bundle.outcome_event.timestamp = '2026-08-11T00:00:00.000Z'; }, 'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
    add(base, 'outcome-witness-valid-until', v => { v.witness.outcome_event.signer_valid_until = '2099-01-01T00:00:00.000Z'; }, 'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
    add(base, 'valence-witness-valid-until', v => { v.witness.valence_evidence.signer_valid_until = '2099-01-01T00:00:00.000Z'; }, 'MUTATION_VALENCE_SIGNATURE_INVALID');
    add(base, 'outcome-numeric-epoch', v => { v.witness.outcome_event.signer_valid_from = Date.parse(v.witness.outcome_event.signer_valid_from); }, 'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
    add(base, 'outcome-numeric-timestamp', v => { v.witness.outcome_event.timestamp = Date.parse(v.witness.outcome_event.timestamp); }, 'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
    add(base, 'outcome-malformed-timestamp', v => { v.witness.outcome_event.timestamp = 'not-an-iso-timestamp'; }, 'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
    for (const field of ['recall_event_id','recall_event_mutation_hash','recall_merkle_root','security_closure_sha256']) {
      add(base, `outcome-duplicate-${field}`, v => { v.bundle.outcome_event.metadata[field] = field === 'recall_event_id'
        ? 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' : 'a'.repeat(64); }, 'MUTATION_OUTCOME_EVENT_INVALID');
    }
    for (const field of ['ledger_seq', 'ts_signed']) {
      add(base, `outcome-${field}-string`, v => { v.witness.outcome_event[field] = String(v.witness.outcome_event[field]); }, 'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
    }
    if (base.bundle.terminal.kind === 'authorized_transition') {
      add(base, 'provenance-valid-until', v => { v.witness.terminal_proof.provenance.agent_valid_until = '2099-01-01T00:00:00.000Z'; }, 'MUTATION_PROVENANCE_SIGNATURE_INVALID');
      add(base, 'provenance-identity-tier', v => { v.witness.terminal_proof.provenance.identity_tier = 'T3'; }, 'MUTATION_PROVENANCE_SIGNATURE_INVALID');
    } else {
      add(base, 'terminal-valid-until', v => { v.witness.terminal_proof.event.signer_valid_until = '2099-01-01T00:00:00.000Z'; }, 'MUTATION_TERMINAL_SIGNATURE_INVALID');
      add(base, 'terminal-id-alias-conflict', v => {
        v.bundle.terminal.event.event_id = v.witness.terminal_proof.event.event_id;
        v.bundle.terminal.event.id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
      }, 'MUTATION_TERMINAL_SIGNATURE_INVALID');
      if (base.bundle.terminal.kind === 'signed_noop') add(base, 'terminal-context-substitution', v => {
        v.bundle.terminal.event.metadata.context_hash = 'a'.repeat(64);
      }, 'MUTATION_VALENCE_BINDING_INVALID');
    }
  }
  const python = pythonResults(cases.map(({ value }) => value));
  const failures = [];
  cases.forEach(({ name, value, reason }, index) => {
    for (const [language, observed] of [['node', nodeResult(value)], ['python', python[index]]]) {
      if (observed.valid !== (reason === null) || (observed.reason ?? null) !== reason) {
        failures.push(`${name}/${language}: expected=${reason}, observed=${observed.reason ?? 'ACCEPTED'}`);
      }
    }
  });
  assert.deepEqual(failures, []);
});

test('AUD-001 optional terminal reward cannot contradict valence even in structural verification', () => {
  const cases = vectors.mutation.vectors.filter(v => v.expected === 'valid'
    && v.bundle.terminal.kind !== 'authorized_transition').map(base => {
    const value = structuredClone(base);
    value.bundle.terminal.event.metadata.reward_sign = -value.bundle.valence_evidence.reward_sign;
    return rehash(value);
  });
  assert.equal(cases.length, 2);
  const python = pythonResults(cases, false);
  for (const [i, value] of cases.entries()) {
    assert.deepEqual(nodeResult(value, false), { valid: false, reason: 'MUTATION_VALENCE_BINDING_INVALID' });
    assert.equal(python[i].valid, false);
    assert.equal(python[i].reason, 'MUTATION_VALENCE_BINDING_INVALID');
  }
});
