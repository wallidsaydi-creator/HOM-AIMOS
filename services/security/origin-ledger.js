// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← OB-3 native SAVE producers and OB-5 consequential-action owner
// → Frozen OB-1 protocol + the three OB-2 database-local typed writers
// Pipeline: portable object → database-bound no-fork envelope → Ed25519 → SQL
// Sources: RFC 8032; Crosby & Wallach tamper-evident logs; Cecchetti–Myers–
//          Arden NMIFC; Louck origin-bound authority.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

import { canonicalJson, signRaw } from './agent-identity.js';
import { readVerifiedEventsByIds } from '../observe/event-ledger.js';
import {
  extractValidFromIso,
  getHousekeeperCert,
  loadHousekeeperPrivkey,
} from './housekeeper-signer.js';
import {
  ORIGIN_BINDING_SCHEMAS_V1,
  originProtocolHashV1,
} from './protocol/origin-binding-v1.js';
import { ORIGIN_ELEVATION_SCHEMA_V2 } from './protocol/origin-corroboration-v1.js';

const HASH_BYTES = 32;
const SIGNATURE_BYTES = 64;
const ZERO_HASH = Buffer.alloc(HASH_BYTES);
export const MEMORY_ORIGIN_SCHEMA_V2 = 'hom.aimos.memory-origin-binding/v2';
export const MEMORY_ORIGIN_SCHEMA_V3 = 'hom.aimos.memory-origin-binding/v3';
const nativeMemorySchema = schema => [MEMORY_ORIGIN_SCHEMA_V2,MEMORY_ORIGIN_SCHEMA_V3].includes(schema);
const extendedFramedSchema = schema => nativeMemorySchema(schema)
  || schema === ORIGIN_ELEVATION_SCHEMA_V2;
const LEDGER_DOMAIN = Buffer.from('hom.aimos.origin-ledger-envelope/v1\0', 'utf8');

// Selected native memory inputs only. Missing historical bindings stay missing;
// this reader neither fabricates origin nor reclassifies a retained memory.
export async function readVerifiedMemoryOriginTips({ client, companyId, memoryIds }) {
  if (!client || !companyId || !Array.isArray(memoryIds)) throw new Error('origin_input_read_scope_required');
  const tips = new Map(memoryIds.map(id => [id, []]));
  if (!memoryIds.length) return tips;
  const result = await client.query(`WITH relevant AS MATERIALIZED (
      SELECT * FROM aimos_memory_origin_bindings WHERE company_id=$1 AND memory_id=ANY($2::uuid[])
    ), consumed AS (SELECT memory_id,unnest(parent_origin_sha256s) AS hash FROM relevant)
    SELECT b.*,l.object_schema,l.object_sha256,l.prev_ledger_hash,l.database_context_sha256,
      l.authority_profile_sha256,l.signer_agent_id,l.signer_valid_from,l.signer_cert_fingerprint,
      l.signed_at,l.ledger_signature,m.content_hash AS current_content_hash
    FROM relevant b JOIN aimos_origin_ledger_entries l ON l.ledger_hash=b.ledger_hash AND l.company_id=b.company_id
      JOIN aimos_memories m ON m.id=b.memory_id AND m.company_id=b.company_id
      LEFT JOIN consumed c ON c.memory_id=b.memory_id AND c.hash=b.binding_sha256
    WHERE c.hash IS NULL ORDER BY b.memory_id,b.binding_sha256`, [companyId, memoryIds]);
  const evidenceEvents = new Map();
  const eventIds = [...new Set(result.rows.map(row => row.classification_event_id))];
  // Reuse the native bounded event verifier, without an N+1 query per input.
  for (let index = 0; index < eventIds.length; index += 4000) {
    for (const [id, event] of await readVerifiedEventsByIds(eventIds.slice(index,index + 4000),companyId,{client})) {
      evidenceEvents.set(id,event);
    }
  }
  for (const row of result.rows) {
    const body = typeof row.body_json === 'string' ? JSON.parse(row.body_json) : row.body_json;
    const portable = portableObject({ ...body, binding_sha256: row.binding_sha256.toString('hex') },
      'binding_sha256', row.object_schema);
    const event = evidenceEvents.get(row.classification_event_id);
    const certificate = JSON.parse(Buffer.from(event.cert,'base64url').toString('utf8')).body;
    const signedSeconds = new Date(row.signed_at).getTime() / 1000;
    const evidence = typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata;
    const ledgerHash = originLedgerEnvelopeHashV1({
      objectSchema: row.object_schema, objectSha256: row.object_sha256,
      previousLedgerHash: row.prev_ledger_hash, databaseContextSha256: row.database_context_sha256,
      authorityProfileSha256: row.authority_profile_sha256, signerAgentId: row.signer_agent_id,
      signerValidFrom: row.signer_valid_from, signedAt: row.signed_at,
    });
    const key = createPublicKey({ format: 'der', type: 'spki', key: Buffer.from(event.pubkey, 'base64url') });
    const signedBody = evidence?.binding;
    const { created_at: _created, ...withoutCreated } = body;
    const comparable = { ...withoutCreated, classification: { ...body.classification } };
    delete comparable.classification.evidence_sha256;
    if (body.company_id !== companyId || body.memory_id !== row.memory_id
      || !portable.objectHash.equals(row.object_sha256) || !portable.bodyBytes.equals(row.body_bytes)
      || !ledgerHash.equals(row.ledger_hash) || !verifySignature(null, ledgerHash, key, row.ledger_signature)
      || row.signer_agent_id !== event.signer_agent_id
      || new Date(row.signer_valid_from).getTime() !== new Date(event.signer_valid_from).getTime()
      || row.signer_cert_fingerprint !== event.cert_fingerprint
      || row.authority_profile_sha256.toString('hex') !== ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1
      || !Number.isSafeInteger(signedSeconds) || signedSeconds < Number(event.ts_signed)
      || signedSeconds < Number(certificate.valid_from) || signedSeconds >= Number(certificate.valid_until)
      || (event.revocation_ts_signed != null && signedSeconds >= Number(event.revocation_ts_signed))
      || new Date(body.created_at).getTime() !== Number(event.ts_signed) * 1000
      || event.operation !== 'origin_family_classified'
      || body.classification.evidence_sha256 !== Buffer.from(event.mutation_hash).toString('hex')
      || canonicalJson(comparable) !== canonicalJson(signedBody)
      || body.content_sha256 !== row.current_content_hash.toString('hex')
      || canonicalJson(body.classification.family_ids) !== canonicalJson(row.family_ids)
      || body.confidentiality !== row.confidentiality || body.integrity !== row.integrity
      || body.action_class !== row.action_class) throw new Error('origin_input_binding_verification_failed');
    tips.get(row.memory_id).push(Object.freeze({
      binding_sha256: row.binding_sha256.toString('hex'), ledger_hash: row.ledger_hash.toString('hex'),
      classification_event_id: row.classification_event_id,
      classification_event_mutation_sha256: Buffer.from(event.mutation_hash).toString('hex'),
      family_ids: Object.freeze([...row.family_ids]), confidentiality: row.confidentiality,
      integrity: row.integrity, action_class: row.action_class,
      channel_identity_sha256: body.origin.channel_identity_sha256,
    }));
  }
  return tips;
}

export async function readVerifiedActionOriginVerdict({
  client,
  companyId,
  verdictSha256,
  expectedTool,
  expectedArgumentsSha256,
  expectedInputEventId,
} = {}) {
  if (!client || !companyId || !/^[0-9a-f]{64}$/.test(String(verdictSha256 || ''))) {
    throw new Error('action_origin_verdict_read_scope_required');
  }
  const result = await client.query(
    `SELECT verdict.*, ledger.object_schema,ledger.object_sha256,
            ledger.prev_ledger_hash,ledger.database_context_sha256,
            ledger.authority_profile_sha256,ledger.signer_agent_id,
            ledger.signer_valid_from,ledger.signer_cert_fingerprint,
            ledger.signed_at,ledger.ledger_signature,
            identity.pubkey,identity.cert,
            revocation.ts_signed AS revocation_ts_signed
       FROM aimos_action_origin_verdicts verdict
       JOIN aimos_origin_ledger_entries ledger
         ON ledger.ledger_hash=verdict.ledger_hash
        AND ledger.company_id=verdict.company_id
       JOIN agent_identity identity
         ON identity.agent_id=ledger.signer_agent_id
        AND identity.valid_from=ledger.signer_valid_from
       LEFT JOIN aimos_agent_revocation_events revocation
         ON revocation.agent_id=identity.agent_id
        AND revocation.agent_valid_from=identity.valid_from
      WHERE verdict.company_id=$1 AND verdict.verdict_sha256=decode($2,'hex')`,
    [companyId, verdictSha256],
  );
  if (result.rowCount !== 1) throw new Error('action_origin_verdict_not_found');
  const row = result.rows[0];
  const body = typeof row.body_json === 'string' ? JSON.parse(row.body_json) : row.body_json;
  const portable = portableObject(
    { ...body, verdict_sha256: verdictSha256 },
    'verdict_sha256',
    ORIGIN_BINDING_SCHEMAS_V1.action_verdict,
  );
  const ledgerHash = originLedgerEnvelopeHashV1({
    objectSchema: row.object_schema,
    objectSha256: row.object_sha256,
    previousLedgerHash: row.prev_ledger_hash,
    databaseContextSha256: row.database_context_sha256,
    authorityProfileSha256: row.authority_profile_sha256,
    signerAgentId: row.signer_agent_id,
    signerValidFrom: row.signer_valid_from,
    signedAt: row.signed_at,
  });
  const key = createPublicKey({
    format: 'der',
    type: 'spki',
    key: Buffer.from(row.pubkey, 'base64url'),
  });
  const inputEvent = await readVerifiedEventsByIds(
    [expectedInputEventId],
    companyId,
    { client },
  );
  const observed = inputEvent.get(String(expectedInputEventId));
  const observedMutation = observed
    ? Buffer.from(observed.mutation_hash).toString('hex')
    : null;
  if (body.company_id !== companyId
      || body.tool_name !== expectedTool
      || body.arguments_sha256 !== expectedArgumentsSha256
      || body.decision !== 'ALLOW'
      || body.failure_code !== null
      || body.input_origin_sha256s.length !== 1
      || body.input_origin_sha256s[0] !== observedMutation
      || observed.operation !== 'origin_action_input_observed'
      || row.object_schema !== ORIGIN_BINDING_SCHEMAS_V1.action_verdict
      || !portable.objectHash.equals(row.object_sha256)
      || !portable.bodyBytes.equals(row.body_bytes)
      || !ledgerHash.equals(row.ledger_hash)
      || !verifySignature(null, ledgerHash, key, row.ledger_signature)
      || row.signer_agent_id !== 'housekeeper'
      || row.authority_profile_sha256.toString('hex')
        !== ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1
      || (row.revocation_ts_signed != null
        && Number(row.revocation_ts_signed) <= new Date(row.signed_at).getTime() / 1000)) {
    throw new Error('action_origin_verdict_binding_invalid');
  }
  return Object.freeze({
    verdictSha256,
    ledgerHash: row.ledger_hash.toString('hex'),
    body: Object.freeze(body),
    inputEvent: observed,
  });
}

export const ORIGIN_LEDGER_AUTHORITY_PROFILE_V1 = Object.freeze({
  canonicalization: 'hom-aimos/canonical-json/v1-safe-integers',
  custody: 'application_local_encrypted_file',
  database_verification: 'pgsodium.crypto_sign_verify_detached',
  hash: 'sha256',
  schema: 'hom.aimos.origin-ledger-authority-profile/v1',
  signature: 'ed25519',
  signer: 'housekeeper',
  signing_input: 'hom.aimos.origin-ledger-envelope/v1',
  version: 1,
});

function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('origin_ledger_length_invalid');
  }
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}

function i64(value) {
  if (!Number.isSafeInteger(value)) throw new Error('origin_ledger_timestamp_invalid');
  const result = Buffer.alloc(8);
  result.writeBigInt64BE(BigInt(value));
  return result;
}

function frame(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  return Buffer.concat([u32(bytes.length), bytes]);
}

function exactHash(value, code = 'origin_ledger_hash_invalid') {
  const bytes = Buffer.isBuffer(value)
    ? Buffer.from(value)
    : Buffer.from(String(value || ''), 'hex');
  if (bytes.length !== HASH_BYTES) throw new Error(code);
  return bytes;
}

function profileHash() {
  const bytes = Buffer.from(canonicalJson(ORIGIN_LEDGER_AUTHORITY_PROFILE_V1), 'utf8');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(`${ORIGIN_LEDGER_AUTHORITY_PROFILE_V1.schema}\0`, 'utf8'),
    u32(bytes.length),
    bytes,
  ])).digest();
}

export const ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1 = profileHash().toString('hex');

export function originLedgerEnvelopeHashV1({
  objectSchema,
  objectSha256,
  previousLedgerHash = null,
  databaseContextSha256,
  authorityProfileSha256 = ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1,
  signerAgentId = 'housekeeper',
  signerValidFrom,
  signedAt,
} = {}) {
  if (!([...Object.values(ORIGIN_BINDING_SCHEMAS_V1)].includes(objectSchema)
        || extendedFramedSchema(objectSchema))
      || signerAgentId !== 'housekeeper') {
    throw new Error('origin_ledger_envelope_scope_invalid');
  }
  const signerEpochMs = new Date(signerValidFrom).getTime();
  const signedAtMs = new Date(signedAt).getTime();
  if (!Number.isSafeInteger(signerEpochMs) || !Number.isSafeInteger(signedAtMs)) {
    throw new Error('origin_ledger_timestamp_invalid');
  }
  return createHash('sha256').update(Buffer.concat([
    LEDGER_DOMAIN,
    frame(objectSchema),
    exactHash(objectSha256),
    previousLedgerHash == null ? ZERO_HASH : exactHash(previousLedgerHash),
    exactHash(databaseContextSha256),
    exactHash(authorityProfileSha256),
    frame(signerAgentId),
    i64(signerEpochMs),
    i64(signedAtMs),
  ])).digest();
}

function portableObject(value, hashField, schema) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value.schema !== schema || typeof value[hashField] !== 'string') {
    throw new Error('origin_ledger_portable_object_invalid');
  }
  const { [hashField]: suppliedHash, ...body } = value;
  const bodyBytes = Buffer.from(canonicalJson(body), 'utf8');
  const objectHash = extendedFramedSchema(schema)
    ? createHash('sha256').update(Buffer.concat([
        Buffer.from(`${schema}\0`, 'utf8'), u32(bodyBytes.length), bodyBytes,
      ])).digest()
    : originProtocolHashV1(body);
  if (objectHash.toString('hex') !== suppliedHash) {
    throw new Error('origin_ledger_portable_hash_invalid');
  }
  return Object.freeze({ body, bodyBytes, objectHash });
}

async function exactLedgerAuthority(client, companyId, objectSchema, objectHash) {
  if (!client || typeof client.query !== 'function') {
    throw new Error('origin_ledger_transaction_client_required');
  }
  // Serialize before reading/signing the head, not only inside the SQL writer.
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('origin-ledger:' || $1,0))", [companyId]);
  const stateResult = await client.query(
    'SELECT * FROM public.ob2_read_origin_ledger_state($1)',
    [companyId],
  );
  if (stateResult.rowCount !== 1) throw new Error('origin_ledger_state_invalid');
  const state = stateResult.rows[0];
  const cert = await getHousekeeperCert({ queryFn: (sql, params) => client.query(sql, params) });
  const validFrom = extractValidFromIso(cert);
  const fingerprint = createHash('sha256').update(Buffer.from(cert, 'utf8')).digest('hex');
  if (state.signer_agent_id !== 'housekeeper'
      || new Date(state.signer_valid_from).toISOString() !== validFrom
      || state.signer_cert_fingerprint !== fingerprint
      || Buffer.from(state.authority_profile_sha256).toString('hex')
        !== ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1) {
    throw new Error('origin_ledger_signer_state_mismatch');
  }
  const signedAt = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString();
  const ledgerHash = originLedgerEnvelopeHashV1({
    objectSchema,
    objectSha256: objectHash,
    previousLedgerHash: state.prev_ledger_hash,
    databaseContextSha256: state.database_context_sha256,
    signerValidFrom: validFrom,
    signedAt,
  });
  const signature = signRaw(loadHousekeeperPrivkey(), ledgerHash);
  if (!Buffer.isBuffer(signature) || signature.length !== SIGNATURE_BYTES) {
    throw new Error('origin_ledger_signature_invalid');
  }
  return Object.freeze({
    previousLedgerHash: state.prev_ledger_hash ? Buffer.from(state.prev_ledger_hash) : null,
    signerValidFrom: validFrom,
    signerCertFingerprint: fingerprint,
    authorityProfileSha256: Buffer.from(state.authority_profile_sha256),
    signedAt,
    ledgerHash,
    signature,
  });
}

async function commitTyped({
  client,
  companyId,
  object,
  hashField,
  schema,
  functionName,
  evidenceEventId = null,
  requestBody = null,
}) {
  const portable = portableObject(object, hashField, schema);
  if (portable.body.company_id !== companyId) throw new Error('origin_ledger_company_mismatch');
  const authority = await exactLedgerAuthority(client, companyId, schema, portable.objectHash);
  const result = await client.query(
    `SELECT public.${functionName}($1::jsonb,$2::bytea,$3::bytea,$4::uuid,$5::bytea,$6::timestamptz,$7::text,$8::bytea,$9::timestamptz,$10::bytea${nativeMemorySchema(schema) ? ',$11::json' : ''}) AS ledger_hash`,
    [
      JSON.stringify(portable.body), portable.bodyBytes, portable.objectHash,
      evidenceEventId, authority.previousLedgerHash, authority.signerValidFrom,
      authority.signerCertFingerprint, authority.authorityProfileSha256,
      authority.signedAt, authority.signature,
      ...(nativeMemorySchema(schema) ? [requestBody == null ? null : canonicalJson(requestBody)] : []),
    ],
  );
  const committedHash = Buffer.from(result.rows[0]?.ledger_hash || []);
  if (!committedHash.equals(authority.ledgerHash)) {
    throw new Error('origin_ledger_database_hash_mismatch');
  }
  return Object.freeze({
    objectSha256: portable.objectHash.toString('hex'),
    ledgerHash: committedHash.toString('hex'),
    previousLedgerHash: authority.previousLedgerHash?.toString('hex') || null,
    signerValidFrom: authority.signerValidFrom,
    signerCertFingerprint: authority.signerCertFingerprint,
    authorityProfileSha256: authority.authorityProfileSha256.toString('hex'),
    signedAt: authority.signedAt,
  });
}

export function commitMemoryOriginBindingV2({ client, companyId, body, classificationEventId, requestBody = null }) {
  // The existing typed writer accepts explicitly versioned native bodies;
  // v1/v2 bytes are not reinterpreted or rewritten as a v3 derivation.
  if (!nativeMemorySchema(body?.schema)) throw new Error('origin_ledger_portable_object_invalid');
  const bytes = Buffer.from(canonicalJson(body), 'utf8');
  const binding_sha256 = createHash('sha256').update(Buffer.concat([
    Buffer.from(`${body.schema}\0`, 'utf8'), u32(bytes.length), bytes,
  ])).digest('hex');
  return commitTyped({ client, companyId, object: { ...body, binding_sha256 },
    hashField: 'binding_sha256', schema: body.schema,
    functionName: 'commit_memory_origin_binding_v2', evidenceEventId: classificationEventId, requestBody });
}

export function commitMemoryOriginBindingV1({
  client,
  companyId,
  binding,
  classificationEventId,
}) {
  if (!classificationEventId) throw new Error('origin_classification_event_required');
  return commitTyped({
    client, companyId, object: binding, hashField: 'binding_sha256',
    schema: ORIGIN_BINDING_SCHEMAS_V1.memory_binding,
    functionName: 'commit_memory_origin_binding_v1',
    evidenceEventId: classificationEventId,
  });
}

export function commitOriginElevationV1({
  client,
  companyId,
  elevation,
  authorizationEventId = null,
}) {
  return commitTyped({
    client, companyId, object: elevation, hashField: 'elevation_sha256',
    schema: ORIGIN_BINDING_SCHEMAS_V1.elevation,
    functionName: 'commit_origin_elevation_v1',
    evidenceEventId: authorizationEventId,
  });
}

export function commitOriginElevationV2({ client, companyId, elevation }) {
  return commitTyped({
    client, companyId, object: elevation, hashField: 'elevation_sha256',
    schema: ORIGIN_ELEVATION_SCHEMA_V2,
    functionName: 'commit_origin_elevation_v2',
  });
}

export function commitActionOriginVerdictV1({
  client,
  companyId,
  verdict,
  authorizationEventId = null,
}) {
  return commitTyped({
    client, companyId, object: verdict, hashField: 'verdict_sha256',
    schema: ORIGIN_BINDING_SCHEMAS_V1.action_verdict,
    functionName: 'commit_action_origin_verdict_v1',
    evidenceEventId: authorizationEventId,
  });
}
