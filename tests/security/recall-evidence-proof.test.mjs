import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';

import {
  canonicalJson,
  generateKeypair,
  issueCert,
  pubkeyFingerprint,
  signPayload,
  signPayloadWithContext,
  signPayloadWithEnvelopeClaims,
} from '../../services/security/agent-identity.js';
import { contentHash } from '../../services/security/identity-chain.js';
import {
  computeLiveRowContentHash,
  verifyRecallEvidenceRow,
} from '../../services/security/memory-provenance.js';

function mutationHash(content, prev, nonce, ts) {
  return createHash('sha256').update(Buffer.concat([
    content,
    ...(prev ? [prev] : []),
    Buffer.from(nonce, 'utf8'),
    Buffer.from(String(ts), 'utf8'),
  ])).digest();
}

function fixture(requestSigForm, options = {}) {
  const keys = generateKeypair();
  const master = generateKeypair();
  const memoryId = randomUUID();
  const validFromUnix = 1_783_763_000;
  const validUntilUnix = 1_783_773_000;
  const masterFingerprint = pubkeyFingerprint(master.pubkey);
  const certIssuer = options.certIssuer === 'aimos-master'
    ? 'aimos-master'
    : options.certIssuer || masterFingerprint;
  const signerCert = issueCert(master.privkey, {
    v: 1,
    agent_id: 'proof-agent',
    pubkey: keys.pubkey,
    device_fp: 'device-proof',
    valid_from: validFromUnix,
    valid_until: validUntilUnix,
    issuer: certIssuer,
    issued_at: validFromUnix,
  });
  const intentBody = {
    company_id: 'hom',
    agent_id: 'proof-agent',
    key: 'proof:recall:evidence',
    value: options.intentValue
      ?? 'This retained memory has exact cryptographic evidence for native recall admission.',
    scope: 'global',
    clearance_level: 1,
    memory_type: 'declarative',
    source: 'test',
  };
  const liveFields = {
    key: intentBody.key,
    value: typeof intentBody.value === 'string'
      ? intentBody.value
      : JSON.stringify(intentBody.value),
    scope: intentBody.scope,
    memory_type: intentBody.memory_type,
    clearance_level: intentBody.clearance_level,
    data_class: 'public',
    source: intentBody.source,
  };
  const body = options.outerBody || intentBody;
  const cHash = contentHash(body);
  const liveHash = computeLiveRowContentHash(liveFields);
  const nonce = `recall-evidence-form-${requestSigForm}`;
  const ts = 1_783_764_000;
  const claims = requestSigForm === 4
    ? { prev_chain_hash: Buffer.alloc(32, 0xaa).toString('base64url'), device_fp: 'device-proof' }
    : null;
  const signedPath = options.signedPath || '/aimos/save';
  const signature = requestSigForm === 4
    ? signPayloadWithEnvelopeClaims(keys.privkey, body, 'POST', signedPath, claims, nonce, ts)
    : requestSigForm === 3
      ? signPayloadWithContext(keys.privkey, body, 'POST', signedPath, nonce, ts)
      : signPayload(keys.privkey, body, nonce, ts);

  return {
    keys,
    row: {
      memory_id: memoryId,
      live_company_id: 'hom',
      live_agent_id: 'proof-agent',
      ...Object.fromEntries(Object.entries(liveFields).map(([key, value]) => [`live_${key}`, value])),
      live_content_hash: liveHash,
      snapshot_live_content_hash: liveHash,
      supersedes_id: null,
      has_successor: false,
      provenance_id: randomUUID(),
      provenance_agent_id: 'proof-agent',
      agent_valid_from: new Date(validFromUnix * 1000).toISOString(),
      cert_fingerprint: createHash('sha256').update(signerCert).digest('hex'),
      prov_content_hash: cHash,
      mutation_hash: mutationHash(cHash, null, nonce, ts),
      prev_mutation_hash: null,
      ts_signed: ts,
      nonce,
      sig: Buffer.from(signature, 'base64url'),
      event_type: 'SAVE',
      identity_tier: requestSigForm === 4 ? 'T2' : 'T1',
      is_genesis: true,
      sig_form_version: 1,
      request_sig_form: requestSigForm,
      signed_method: requestSigForm === 1 ? null : 'POST',
      signed_path: requestSigForm === 1 ? null : signedPath,
      signed_claims: claims,
      body_json: body,
      memory_originated_at: null,
      signer_pubkey: keys.pubkey,
      signer_cert: signerCert,
      signer_device_fp: 'device-proof',
      signer_valid_until: new Date(validUntilUnix * 1000).toISOString(),
      master_pubkey: master.pubkey,
      master_fingerprint: masterFingerprint,
      revocation_sig: null,
    },
  };
}

for (const form of [1, 3, 4]) {
  test(`recall evidence verifies stored request signature form ${form}`, () => {
    const { row } = fixture(form);
    const result = verifyRecallEvidenceRow(row);
    assert.equal(result.valid, true);
    assert.equal(result.proof.memory_id, row.memory_id);
    assert.equal(result.proof.request_sig_form, form);
    assert.equal(result.proof.version_status, 'current');
  });
}

test('recall evidence fails closed on signature, body, snapshot, and identity tampering', () => {
  const { row } = fixture(4);
  assert.equal(verifyRecallEvidenceRow({ ...row, sig: Buffer.alloc(64) }).valid, false);
  assert.equal(verifyRecallEvidenceRow({ ...row, live_value: `${row.live_value} tampered` }).valid, false);
  assert.equal(verifyRecallEvidenceRow({ ...row, snapshot_live_content_hash: Buffer.alloc(32) }).valid, false);
  assert.equal(verifyRecallEvidenceRow({ ...row, signer_pubkey: generateKeypair().pubkey }).valid, false);
  assert.equal(verifyRecallEvidenceRow({ ...row, body_json: null }).valid, false);
});

test('recall evidence accepts canonical and legacy master issuer forms but rejects unknown issuers', () => {
  assert.equal(verifyRecallEvidenceRow(fixture(3, { certIssuer: 'aimos-master' }).row).valid, true);
  assert.equal(verifyRecallEvidenceRow(fixture(3).row).valid, true);
  assert.equal(verifyRecallEvidenceRow(fixture(3, { certIssuer: 'unexpected-root' }).row).valid, false);
});

test('SAVE intent remains valid when the native writer reclassifies canonical fields', () => {
  const { row } = fixture(3);
  const normalizedFields = {
    key: row.live_key,
    value: row.live_value,
    scope: 'quarantine',
    memory_type: 'quarantine',
    clearance_level: row.live_clearance_level,
    data_class: row.live_data_class,
    source: `${row.live_source}:degraded_embedding`,
  };
  const normalizedHash = computeLiveRowContentHash(normalizedFields);
  const normalizedRow = {
    ...row,
    live_scope: normalizedFields.scope,
    live_memory_type: normalizedFields.memory_type,
    live_source: normalizedFields.source,
    live_content_hash: normalizedHash,
    snapshot_live_content_hash: normalizedHash,
  };

  assert.equal(verifyRecallEvidenceRow(normalizedRow).valid, true);
  assert.equal(
    verifyRecallEvidenceRow({ ...normalizedRow, live_key: 'tampered:key' }).reason,
    'live_row_content_hash_mismatch',
  );
  assert.equal(
    verifyRecallEvidenceRow({ ...normalizedRow, body_json: { ...row.body_json, key: 'wrong:intent:key' } }).valid,
    false,
  );
});

test('streamable MCP SAVE verifies the exact signed nested intent', () => {
  const intent = {
    key: 'proof:recall:evidence',
    value: 'This retained memory has exact cryptographic evidence for native recall admission.',
    scope: 'global',
    memory_type: 'declarative',
    clearance_level: 1,
    source: 'test',
  };
  const outerBody = {
    jsonrpc: '2.0',
    id: 'save-1',
    method: 'tools/call',
    params: { name: 'aimos_save', arguments: intent },
  };
  const { row } = fixture(3, { outerBody, signedPath: '/mcp' });
  assert.equal(verifyRecallEvidenceRow(row).valid, true);

  const ambiguousOuter = [outerBody, { ...outerBody, id: 'save-2' }];
  const ambiguous = fixture(3, { outerBody: ambiguousOuter, signedPath: '/mcp' }).row;
  assert.equal(verifyRecallEvidenceRow(ambiguous).reason, 'signed_save_intent_missing_or_ambiguous');
});

test('REST SAVE reconstructs structured object and array values without weakening exact strings', () => {
  for (const intentValue of [
    { summary: 'signed structured evidence', evidence: { marker: 'SECRET-3810AEFF' } },
    ['signed structured evidence', { marker: 'SECRET-8597B901' }],
  ]) {
    const { row } = fixture(3, { intentValue });
    assert.equal(verifyRecallEvidenceRow(row).valid, true);
    assert.equal(
      verifyRecallEvidenceRow({
        ...row,
        live_value: JSON.stringify({ tampered: true }),
      }).valid,
      false,
    );
  }
});

test('streamable MCP SAVE reconstructs structured values after JSONB member reordering', () => {
  const intent = {
    key: 'proof:recall:evidence',
    value: { z: 'last in canonical order', a: { marker: 'SECRET-3810AEFF' } },
    scope: 'global',
    memory_type: 'declarative',
    clearance_level: 1,
    source: 'test',
  };
  const outerBody = {
    jsonrpc: '2.0',
    id: 'save-structured-1',
    method: 'tools/call',
    params: { name: 'aimos_save', arguments: intent },
  };
  const { row } = fixture(3, {
    outerBody,
    signedPath: '/mcp',
    intentValue: intent.value,
  });
  row.live_value = JSON.stringify({ a: { marker: 'SECRET-3810AEFF' }, z: 'last in canonical order' });
  const liveFields = {
    key: row.live_key,
    value: row.live_value,
    scope: row.live_scope,
    memory_type: row.live_memory_type,
    clearance_level: row.live_clearance_level,
    data_class: row.live_data_class,
    source: row.live_source,
  };
  row.live_content_hash = computeLiveRowContentHash(liveFields);
  row.snapshot_live_content_hash = row.live_content_hash;
  assert.equal(verifyRecallEvidenceRow(row).valid, true);
});

function sessionTurnEvidenceFixture(overrides = {}) {
  const turnBody = {
    company_id: 'hom',
    agent_id: 'proof-agent',
    session_id: 'proof_session_01',
    turn_id: 'proof-turn-1',
    role: 'user',
    content: 'The signed session request retains indigo as the preferred primary-control color.',
    observed_at: '2026-07-13T12:00:00.000Z',
    source_ref: 'proof-source:1',
    speaker: 'test-user',
    image_context: [{ caption: 'indigo primary control' }],
    source: 'benchmark:session-proof',
    clearance_level: 10,
    ...overrides,
  };
  const sequence = 1;
  const turnIdHash = createHash('sha256').update(Buffer.from(String(turnBody.turn_id), 'utf8')).digest('hex');
  const key = `sess:${String(turnBody.session_id).trim()}:turn:${String(sequence).padStart(12, '0')}:${turnIdHash}`;
  const record = {
    schema: 'aimos.session-turn/v1',
    session_id: String(turnBody.session_id).trim(),
    sequence,
    turn_id_sha256: turnIdHash,
    role: String(turnBody.role).trim().toLowerCase(),
    observed_at: new Date(turnBody.observed_at).toISOString(),
    source_ref: turnBody.source_ref == null ? null : String(turnBody.source_ref).trim() || null,
    content: String(turnBody.content),
    ...(String(turnBody.speaker || '').trim() ? { speaker: String(turnBody.speaker).trim() } : {}),
    ...(turnBody.image_context?.length ? { image_context: turnBody.image_context } : {}),
  };
  const value = canonicalJson(record);
  const liveFields = {
    key,
    value,
    scope: 'global',
    memory_type: 'conversation_feed',
    clearance_level: turnBody.clearance_level,
    data_class: 'confidential',
    source: turnBody.source,
  };
  const { row } = fixture(3, { outerBody: turnBody, signedPath: '/aimos/session/turn' });
  Object.assign(row, Object.fromEntries(
    Object.entries(liveFields).map(([field, value]) => [`live_${field}`, value]),
  ));
  row.live_agent_id = 'proof-agent';
  row.live_company_id = 'hom';
  row.live_content_hash = computeLiveRowContentHash(liveFields);
  row.snapshot_live_content_hash = row.live_content_hash;
  return row;
}

test('native session-turn SAVE verifies the exact signed derived memory intent', () => {
  const row = sessionTurnEvidenceFixture();
  assert.equal(verifyRecallEvidenceRow(row).valid, true);

  const quarantinedFields = {
    key: row.live_key,
    value: row.live_value,
    scope: 'quarantine',
    memory_type: 'quarantine',
    clearance_level: row.live_clearance_level,
    data_class: row.live_data_class,
    source: row.live_source,
  };
  const quarantinedRow = {
    ...row,
    live_scope: 'quarantine',
    live_memory_type: 'quarantine',
    live_content_hash: computeLiveRowContentHash(quarantinedFields),
    snapshot_live_content_hash: computeLiveRowContentHash(quarantinedFields),
  };
  assert.equal(
    verifyRecallEvidenceRow(quarantinedRow).valid,
    true,
    'the signed turn intent and housekeeper BIND remain valid after native quarantine classification',
  );

  const degradedSourceFields = {
    ...quarantinedFields,
    source: `${row.live_source}:degraded_embedding`,
  };
  const degradedSourceRow = {
    ...quarantinedRow,
    live_source: degradedSourceFields.source,
    live_content_hash: computeLiveRowContentHash(degradedSourceFields),
    snapshot_live_content_hash: computeLiveRowContentHash(degradedSourceFields),
  };
  assert.equal(
    verifyRecallEvidenceRow(degradedSourceRow).valid,
    true,
    'the signed turn intent and housekeeper BIND remain valid after native source normalization',
  );

  const tamperedValue = canonicalJson({ ...JSON.parse(row.live_value), content: 'tampered derived turn' });
  const tamperedFields = {
    key: row.live_key,
    value: tamperedValue,
    scope: row.live_scope,
    memory_type: row.live_memory_type,
    clearance_level: row.live_clearance_level,
    data_class: row.live_data_class,
    source: row.live_source,
  };
  const tamperedRow = {
    ...row,
    live_value: tamperedValue,
    live_content_hash: computeLiveRowContentHash(tamperedFields),
    snapshot_live_content_hash: computeLiveRowContentHash(tamperedFields),
  };
  assert.equal(
    verifyRecallEvidenceRow(tamperedRow).reason,
    'signed_save_intent_missing_or_ambiguous',
  );

  const wrongTurnHash = '0'.repeat(64);
  const wrongKey = row.live_key.replace(/[0-9a-f]{64}$/, wrongTurnHash);
  const wrongKeyFields = {
    key: wrongKey,
    value: row.live_value,
    scope: row.live_scope,
    memory_type: row.live_memory_type,
    clearance_level: row.live_clearance_level,
    data_class: row.live_data_class,
    source: row.live_source,
  };
  const wrongKeyRow = {
    ...row,
    live_key: wrongKey,
    live_content_hash: computeLiveRowContentHash(wrongKeyFields),
    snapshot_live_content_hash: computeLiveRowContentHash(wrongKeyFields),
  };
  assert.equal(
    verifyRecallEvidenceRow(wrongKeyRow).reason,
    'signed_save_intent_missing_or_ambiguous',
  );
});
