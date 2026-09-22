#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';

import { agentPool } from '../../db/connection.js';
import { canonicalJson, signRaw } from '../../services/security/agent-identity.js';
import { loadHousekeeperPrivkey } from '../../services/security/housekeeper-signer.js';
import {
  ORIGIN_BINDING_SCHEMAS_V1,
  ORIGIN_FAMILY_PROFILE_SHA256_V1,
  createActionOriginVerdictV1,
  createMemoryOriginBindingV1,
  createOriginElevationV1,
  originFamilyClosureV1,
} from '../../services/security/protocol/origin-binding-v1.js';
import {
  ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1,
  commitActionOriginVerdictV1,
  commitMemoryOriginBindingV1,
  commitOriginElevationV1,
  originLedgerEnvelopeHashV1,
} from '../../services/security/origin-ledger.js';
import { logEvent } from '../../services/observe/event-ledger.js';

const COMPANY_ID = 'hom';
const HASH_BYTES = 32;

function u32(value) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}

function uncheckedObjectHash(schema, body) {
  const bytes = Buffer.from(canonicalJson(body), 'utf8');
  return {
    bytes,
    hash: createHash('sha256').update(Buffer.concat([
      Buffer.from(`${schema}\0`, 'utf8'), u32(bytes.length), bytes,
    ])).digest(),
  };
}

async function expectDenied(client, code, action) {
  const savepoint = `ob2_${code.replace(/[^a-z0-9_]/gi, '_')}`;
  await client.query(`SAVEPOINT ${savepoint}`);
  try {
    await action();
    throw new Error(`ob2_negative_not_rejected:${code}`);
  } catch (error) {
    await client.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
    await client.query(`RELEASE SAVEPOINT ${savepoint}`);
    const message = String(error?.message || error);
    if (message === `ob2_negative_not_rejected:${code}`) throw error;
    return { code, observed: message.split('\n')[0] };
  }
}

async function rawMemoryCommit(client, body, classificationEventId, overrides = {}) {
  const state = (await client.query(
    'SELECT * FROM public.ob2_read_origin_ledger_state($1)', [body.company_id],
  )).rows[0];
  const portable = uncheckedObjectHash(
    overrides.objectSchema || ORIGIN_BINDING_SCHEMAS_V1.memory_binding,
    body,
  );
  const previous = Object.hasOwn(overrides, 'previousLedgerHash')
    ? overrides.previousLedgerHash : state.prev_ledger_hash;
  const signedAt = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString();
  const ledgerHash = originLedgerEnvelopeHashV1({
    objectSchema: ORIGIN_BINDING_SCHEMAS_V1.memory_binding,
    objectSha256: portable.hash,
    previousLedgerHash: previous,
    databaseContextSha256: state.database_context_sha256,
    authorityProfileSha256: state.authority_profile_sha256,
    signerValidFrom: state.signer_valid_from,
    signedAt,
  });
  const signature = overrides.signature || signRaw(loadHousekeeperPrivkey(), ledgerHash);
  return client.query(
    `SELECT public.commit_memory_origin_binding_v1(
       $1::jsonb,$2::bytea,$3::bytea,$4::uuid,$5::bytea,$6::timestamptz,
       $7::text,$8::bytea,$9::timestamptz,$10::bytea)`,
    [
      JSON.stringify(body), portable.bytes, portable.hash, classificationEventId,
      previous, state.signer_valid_from, state.signer_cert_fingerprint,
      state.authority_profile_sha256, signedAt, signature,
    ],
  );
}

const client = await agentPool.connect();
try {
  await client.query('BEGIN');
  await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', COMPANY_ID]);
  await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);

  const selected = (await client.query(`
    SELECT memory.id AS memory_id, memory.key, memory.company_id, memory.scope,
           memory.data_class, encode(memory.content_hash,'hex') AS content_sha256,
           provenance.provenance_id AS occurrence_id, provenance.agent_id,
           provenance.agent_valid_from, provenance.cert_fingerprint,
           receipt.request_receipt_id,
           encode(receipt.mutation_hash,'hex') AS request_mutation_sha256
      FROM public.aimos_memories memory
      JOIN public.aimos_memory_provenance provenance
        ON provenance.memory_id = memory.id
       AND provenance.event_type = 'SAVE'
       AND provenance.live_content_hash = memory.content_hash
      JOIN public.aimos_request_receipts receipt
        ON receipt.company_id = memory.company_id
       AND receipt.actor_agent_id = provenance.agent_id
       AND receipt.actor_valid_from = provenance.agent_valid_from
       AND receipt.sig = provenance.sig
       AND receipt.request_hash = provenance.content_hash
     WHERE memory.company_id = $1 AND memory.content_hash IS NOT NULL
       AND memory.data_class IS NOT NULL
       AND NOT EXISTS (
         SELECT 1 FROM public.aimos_memory_origin_bindings binding
          WHERE binding.occurrence_id = provenance.provenance_id
       )
     ORDER BY memory.created_at DESC
     LIMIT 1`, [COMPANY_ID])).rows[0];
  if (!selected) throw new Error('ob2_live_authority_fixture_unavailable');

  const familyIds = originFamilyClosureV1(['information.event']);
  const classification = await logEvent(
    COMPANY_ID,
    selected.agent_id,
    'origin_family_classified',
    selected.key,
    {
      schema: 'hom.aimos.origin-classification-evidence/v1',
      memory_id: selected.memory_id,
      content_sha256: selected.content_sha256,
      actor_agent_id: selected.agent_id,
      family_profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
      family_ids: familyIds,
      classification_authority: 'deterministic_route_schema',
      ingress_channel: 'authenticated_agent',
      channel_identity_sha256: selected.cert_fingerprint,
      confidentiality: selected.data_class,
      integrity: 'agent',
      action_class: 'inform',
      action_scope: selected.scope,
      session_id: null,
      tool_action_event_id: null,
      reasoning: 'OB-2 live proof applies the frozen deterministic route taxonomy to one already authenticated retained occurrence inside a transaction that is rolled back.',
      source_knowledge: 'Phase 1 OB-1 frozen protocol and OB-2 database writer proof',
    },
    null,
    { client, returnReceipt: true },
  );
  const binding = createMemoryOriginBindingV1({
    schema: ORIGIN_BINDING_SCHEMAS_V1.memory_binding,
    company_id: COMPANY_ID,
    memory_id: selected.memory_id,
    occurrence_id: selected.occurrence_id,
    content_sha256: selected.content_sha256,
    actor: {
      agent_id: selected.agent_id,
      valid_from: new Date(selected.agent_valid_from).toISOString(),
      cert_fingerprint_sha256: selected.cert_fingerprint,
    },
    request: {
      receipt_id: selected.request_receipt_id,
      mutation_sha256: selected.request_mutation_sha256,
    },
    origin: {
      ingress_channel: 'authenticated_agent',
      channel_identity_sha256: selected.cert_fingerprint,
    },
    parents: { origin_sha256s: [] },
    classification: {
      profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
      family_ids: familyIds,
      authority: 'deterministic_route_schema',
      evidence_sha256: classification.mutation_hash,
    },
    confidentiality: selected.data_class,
    integrity: 'agent',
    action_class: 'inform',
    scope: selected.scope,
    session_id: null,
    tool_action_event_id: null,
    created_at: new Date(classification.ts_signed * 1000).toISOString(),
  });
  const memoryCommit = await commitMemoryOriginBindingV1({
    client, companyId: COMPANY_ID, binding,
    classificationEventId: classification.event_id,
  });

  const elevationAuthority = await logEvent(
    COMPANY_ID, selected.agent_id, 'origin_elevation_authorized', selected.key,
    {
      schema: 'hom.aimos.origin-elevation-authorization/v1',
      value_sha256: selected.content_sha256,
      family_id: 'information.event',
      action_scope: selected.scope,
      reasoning: 'OB-2 live proof binds a one-use elevation to the exact retained value and scope; the transaction is rolled back.',
      source_knowledge: 'Phase 1 OB-2 elevation writer proof',
    }, classification.event_id, { client, returnReceipt: true },
  );
  const now = new Date(Math.floor(Date.now() / 1000) * 1000);
  const elevation = createOriginElevationV1({
    schema: ORIGIN_BINDING_SCHEMAS_V1.elevation,
    company_id: COMPANY_ID,
    elevation_id: randomUUID(),
    value_sha256: selected.content_sha256,
    family_id: 'information.event',
    action_scope: selected.scope,
    risk_class: 'non_consequential',
    base_origin_sha256s: [binding.binding_sha256],
    corroborators: [],
    threshold: 2,
    user_authorization_sha256: elevationAuthority.mutation_hash,
    maximum_uses: 1,
    valid_from: new Date(now.getTime() - 1_000).toISOString(),
    valid_until: new Date(now.getTime() + 3_600_000).toISOString(),
    created_at: now.toISOString(),
  });
  const elevationCommit = await commitOriginElevationV1({
    client, companyId: COMPANY_ID, elevation,
    authorizationEventId: elevationAuthority.event_id,
  });

  const verdict = createActionOriginVerdictV1({
    schema: ORIGIN_BINDING_SCHEMAS_V1.action_verdict,
    company_id: COMPANY_ID,
    verdict_id: randomUUID(),
    actor: binding.actor,
    tool_name: 'origin-audit',
    action_scope: selected.scope,
    risk_class: 'non_consequential',
    arguments_sha256: createHash('sha256').update('ob2-live-proof').digest('hex'),
    security_values: [{
      value_sha256: selected.content_sha256,
      family_ids: familyIds,
    }],
    family_ids: familyIds,
    input_origin_sha256s: [binding.binding_sha256],
    untrusted_influence: false,
    elevation_sha256: elevation.elevation_sha256,
    user_authorization_sha256: null,
    decision: 'ALLOW',
    failure_code: null,
    previous_verdict_sha256: null,
    created_at: now.toISOString(),
  });
  const verdictCommit = await commitActionOriginVerdictV1({
    client, companyId: COMPANY_ID, verdict,
  });

  const negative = [];
  const body = structuredClone(binding);
  delete body.binding_sha256;
  negative.push(await expectDenied(client, 'wrong_memory', () => rawMemoryCommit(
    client, { ...body, memory_id: randomUUID() }, classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_content', () => rawMemoryCommit(
    client, { ...body, content_sha256: 'aa'.repeat(HASH_BYTES) }, classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_actor_epoch', () => rawMemoryCommit(
    client, { ...body, actor: { ...body.actor, valid_from: '2026-01-01T00:00:00.000Z' } },
    classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_request', () => rawMemoryCommit(
    client, { ...body, request: { ...body.request, receipt_id: randomUUID() } },
    classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_parent', () => rawMemoryCommit(
    client, { ...body, parents: { origin_sha256s: ['bb'.repeat(HASH_BYTES)] } },
    classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_family_order', () => rawMemoryCommit(
    client, {
      ...body,
      classification: { ...body.classification, family_ids: [...familyIds].reverse() },
    }, classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_family_profile', () => rawMemoryCommit(
    client, {
      ...body,
      classification: { ...body.classification, profile_sha256: 'cc'.repeat(HASH_BYTES) },
    }, classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_confidentiality', () => rawMemoryCommit(
    client, { ...body, confidentiality: 'public' }, classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_integrity', () => rawMemoryCommit(
    client, { ...body, integrity: 'trusted' }, classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_scope', () => rawMemoryCommit(
    client, { ...body, scope: 'wrong.scope' }, classification.event_id,
  )));
  negative.push(await expectDenied(client, 'wrong_signature', () => rawMemoryCommit(
    client, body, classification.event_id, { signature: Buffer.alloc(64) },
  )));
  negative.push(await expectDenied(client, 'wrong_predecessor', () => rawMemoryCommit(
    client, body, classification.event_id, { previousLedgerHash: Buffer.alloc(32, 9) },
  )));
  negative.push(await expectDenied(client, 'wrong_domain', () => rawMemoryCommit(
    client, { ...body, schema: 'hom.aimos.wrong/v1' }, classification.event_id,
    { objectSchema: 'hom.aimos.wrong/v1' },
  )));
  negative.push(await expectDenied(client, 'wrong_database_scope', async () => {
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', 'wrong-company']);
    return rawMemoryCommit(client, body, classification.event_id);
  }));
  await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', COMPANY_ID]);
  negative.push(await expectDenied(client, 'direct_insert_privilege', () => client.query(
    `INSERT INTO public.aimos_memory_origin_bindings(binding_sha256)
     VALUES (decode($1,'hex'))`, ['dd'.repeat(HASH_BYTES)],
  )));
  negative.push(await expectDenied(client, 'direct_update_privilege', () => client.query(
    `UPDATE public.aimos_memory_origin_bindings SET action_scope='wrong'
      WHERE binding_sha256=decode($1,'hex')`, [binding.binding_sha256],
  )));
  negative.push(await expectDenied(client, 'direct_delete_privilege', () => client.query(
    `DELETE FROM public.aimos_memory_origin_bindings
      WHERE binding_sha256=decode($1,'hex')`, [binding.binding_sha256],
  )));

  const counts = (await client.query(`
    SELECT
      (SELECT count(*) FROM public.aimos_origin_ledger_entries) AS ledger_entries,
      (SELECT count(*) FROM public.aimos_memory_origin_bindings) AS memory_bindings,
      (SELECT count(*) FROM public.aimos_origin_elevations) AS elevations,
      (SELECT count(*) FROM public.aimos_action_origin_verdicts) AS verdicts
  `)).rows[0];
  if (Number(counts.ledger_entries) !== 3 || Number(counts.memory_bindings) !== 1
      || Number(counts.elevations) !== 1 || Number(counts.verdicts) !== 1) {
    throw new Error('ob2_live_positive_cardinality_invalid');
  }

  await client.query('ROLLBACK');
  const residueClient = await agentPool.connect();
  let residue;
  try {
    await residueClient.query('BEGIN');
    await residueClient.query('SELECT set_config($1,$2,true)', ['app.current_client_id', COMPANY_ID]);
    residue = (await residueClient.query(`
      SELECT
        (SELECT count(*) FROM public.aimos_origin_ledger_entries) AS ledger_entries,
        (SELECT count(*) FROM public.aimos_memory_origin_bindings) AS memory_bindings,
        (SELECT count(*) FROM public.aimos_origin_elevations) AS elevations,
        (SELECT count(*) FROM public.aimos_action_origin_verdicts) AS verdicts
    `)).rows[0];
    await residueClient.query('ROLLBACK');
  } finally {
    residueClient.release();
  }
  if (Object.values(residue).some((value) => Number(value) !== 0)) {
    throw new Error('ob2_live_proof_residue_detected');
  }
  console.log(JSON.stringify({
    success: true,
    status: 'OB2_LIVE_DATABASE_WRITERS_PROVED',
    database: 'aimos',
    selected_live_memory_id: selected.memory_id,
    selected_live_occurrence_id: selected.occurrence_id,
    positive_objects: {
      memory_binding: memoryCommit,
      elevation: elevationCommit,
      action_verdict: verdictCommit,
    },
    denials: negative,
    denial_count: negative.length,
    rollback_zero_residue: true,
    authority_profile_sha256: ORIGIN_LEDGER_AUTHORITY_PROFILE_SHA256_V1,
  }, null, 2));
} catch (error) {
  try { await client.query('ROLLBACK'); } catch { /* connection may be unusable */ }
  console.error(error.stack || error.message);
  process.exitCode = 1;
} finally {
  client.release();
  await agentPool.end();
}
