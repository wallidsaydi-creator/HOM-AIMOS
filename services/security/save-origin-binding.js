// Native SAVE origin owner: consumes existing operation authority and commits
// classification + origin inside the caller's memory/occurrence transaction.
// Sources: Louck 2606.24322 §§II–IV; Cecchetti–Myers–Arden 1708.08596 §§2–3.
// ← OB-2 audit and subsequent atomic origin writer integration
// → native request/event/certificate verification + origin authority v2 bytes
import { createHash } from 'node:crypto';
import { resolveCertificateAuthorityPubkey, verifyCertChain } from './agent-identity.js';
import { readVerifiedEventById, logEvent } from '../observe/event-ledger.js';
import { MEMORY_ORIGIN_SCHEMA_V2, MEMORY_ORIGIN_SCHEMA_V3, commitMemoryOriginBindingV2, readVerifiedMemoryOriginTips } from './origin-ledger.js';
import { ORIGIN_FAMILY_PROFILE_BODY_V1, ORIGIN_FAMILY_PROFILE_SHA256_V1, originFamilyClosureV1 } from './protocol/origin-binding-v1.js';
import { canonicalJson } from './protocol/canonical-json.js';
import { memoryProvenanceLedger } from './memory-provenance.js';
import { normalizeSourceMemoryIds } from '../write/canonical-save-contract.js';
import { readVerifiedRequestReceiptByMutationHash, verifyRequestReceiptProof } from './request-receipt-ledger.js';
import {
  createOriginOperationAuthorityV2,
  ORIGIN_OPERATION_AUTHORITY_SCHEMA_V2,
  ORIGIN_OPERATION_AUTHORITY_KINDS_V2,
} from './protocol/origin-authority-v2.js';

function requireValue(condition, reason) {
  if (!condition) throw new Error('origin_authority_' + reason);
}
const hex = (value) => Buffer.from(value).toString('hex');
const fingerprint = (cert) => createHash('sha256').update(cert, 'utf8').digest('hex');
const iso = (value) => new Date(value).toISOString();
const signedAt = (seconds) => iso(Number(seconds) * 1000);
const confidentialityOrder = ['public','internal','confidential','restricted'];
const familyPolicies = new Map(ORIGIN_FAMILY_PROFILE_BODY_V1.families.map(f => [f.id,f.action_policy]));

// Complete membership comes from native record/row parity. This manifest is
// an input proof inside the same origin binding, not another SAVE pipeline.
// Its length-framed root binds the full sorted set, including legacy unknowns.
async function readDeclaredSaveInputs({client,companyId,authority,key}) {
  if (authority?.kind === 'verified_request') {
    let intent=authority.body;
    const pathname=String(authority.signedPath || '').split('?')[0];
    if (pathname === '/aimos/mcp/tools/call') {
      intent=intent?.name==='aimos_save'?intent.arguments:null;
    }
    else if (pathname === '/mcp') {
      const calls=(Array.isArray(intent)?intent:[intent]).filter(r=>r?.method==='tools/call' && r.params?.name==='aimos_save');
      const matches=calls.map(r=>typeof r.params.arguments==='string'?JSON.parse(r.params.arguments):r.params.arguments)
        .filter(r=>r?.key===key);
      requireValue(matches.length===1,'declared_input_intent_ambiguous'); intent=matches[0];
    }
    if (typeof intent==='string') intent=JSON.parse(intent);
    return normalizeSourceMemoryIds(intent?.source_memory_ids);
  }
  const id=authority?.kind==='verified_tool_action'?authority.eventId:authority?.actionEventId;
  requireValue(id,'declared_input_authority_missing');
  const event=await readVerifiedEventById(id,companyId,{client});
  return normalizeSourceMemoryIds(event.metadata?.source_memory_ids);
}

export async function readCanonicalSaveInputs({client,companyId,subjectAgentId,value,sessionId,
  authority,key,sourceMemoryIds}) {
  const declared=await readDeclaredSaveInputs({client,companyId,authority,key});
  requireValue(canonicalJson(declared)===canonicalJson(normalizeSourceMemoryIds(sourceMemoryIds)),
    'declared_input_handoff_mismatch');
  const projection = (await client.query('SELECT ob3_native_save_input_ids($1,$2,$3,$4,$5::jsonb) AS inputs',
    [companyId,subjectAgentId,value,sessionId || null,declared===null?null:JSON.stringify(declared)])).rows[0].inputs;
  let resultInputs = null;
  if (authority.kind !== 'verified_request') {
    const event = await readVerifiedEventById(authority.kind === 'verified_tool_action'
      ? authority.eventId : authority.actionEventId,companyId,{client});
    if (event.metadata?.native_input_snapshot) {
      requireValue(projection && declared !== null,'native_input_declaration_missing');
      const { readNativeInputClassification } = await import('../orchestration/tool-action-ledger.js');
      resultInputs = await readNativeInputClassification({ snapshot:event.metadata.native_input_snapshot,companyId,client });
      requireValue(event.metadata.native_input_snapshot.memory_ids.every(id=>projection.memory_ids.includes(id)),
        'native_input_membership_missing');
      requireValue(resultInputs.private_subject_ids.every(id=>id===subjectAgentId),'input_private_subject_mismatch');
    }
  }
  if (!projection) return null;
  const ids = projection.memory_ids;
  const memories = (await client.query(`SELECT id,content_hash,data_class,clearance_level,scope,cube_scope,agent_id FROM aimos_memories
    WHERE company_id=$1 AND id=ANY($2::uuid[]) ORDER BY id`,[companyId,ids])).rows;
  requireValue(memories.length===ids.length,'input_memory_missing');
  requireValue(!memories.some(m=>(m.cube_scope==='private'
    || ['agent','private',m.agent_id].includes(m.scope))
    && m.agent_id!==subjectAgentId),'input_private_subject_mismatch');
  const verified = await memoryProvenanceLedger.verifyRecallEvidence({memoryIds:ids,client});
  requireValue(!verified.rejected.length && verified.verified.size===ids.length,'input_provenance_invalid');
  const byMemory = await readVerifiedMemoryOriginTips({client,companyId,memoryIds:ids});
  const tips = [...byMemory.values()].flat();
  const inputs = memories.map(m=>({memory_id:m.id,content_sha256:hex(m.content_hash),
    origin_sha256s:byMemory.get(m.id).map(b=>b.binding_sha256),legacy_unbound:byMemory.get(m.id).length===0}));
  const bytes=Buffer.from(canonicalJson(inputs),'utf8'),length=Buffer.alloc(4);length.writeUInt32BE(bytes.length);
  const inputsSha=createHash('sha256').update(Buffer.concat([
    Buffer.from('hom.aimos.origin-input-manifest/v1\0'),length,bytes])).digest('hex');
  const legacy=inputs.some(i=>i.legacy_unbound);
  const family=projection.producer==='compaction_handoff'?'derived.summary':'derived';
  const families=originFamilyClosureV1([...new Set([family,...tips.flatMap(t=>t.family_ids),
    ...(resultInputs?.family_ids || []),
    ...(legacy?['unknown_protected']:[])])]);
  let confRank=legacy?3:1;
  for (const m of memories) confRank=Math.max(confRank,confidentialityOrder.indexOf(m.data_class));
  for (const t of tips) confRank=Math.max(confRank,confidentialityOrder.indexOf(t.confidentiality));
  if (resultInputs) confRank=Math.max(confRank,confidentialityOrder.indexOf(resultInputs.confidentiality));
  return {derivation:{schema:'hom.aimos.origin-input-manifest/v1',producer:projection.producer,
    input_count:inputs.length,inputs_sha256:inputsSha,inputs},family_ids:families,
    confidentiality:confidentialityOrder[confRank],
    clearance_floor:memories.reduce((n,m)=>Math.max(n,Number(m.clearance_level)),resultInputs?.clearance_floor || 1),
    private_input:Boolean(resultInputs?.private_subject_ids.length) || memories.some(m=>m.cube_scope==='private' || ['agent','private',m.agent_id].includes(m.scope)
      || Number(m.clearance_level)<=2),
    integrity:legacy || resultInputs?.integrity==='untrusted' || tips.some(t=>t.integrity==='untrusted')?'untrusted':'agent',
    action_class:legacy || resultInputs?.action_class==='none' || tips.some(t=>t.action_class==='none')?'none':'inform'};
}

// Historical verification at the operation time is not fresh authorization.
// The mutation owner must lock/recheck current actor/grant state and cross-bind
// the exact resulting memory before consuming this authority commitment.
async function readActor(client, agentId, validFrom, at) {
  const result = await client.query(
    `SELECT identity.*, master.master_pubkey, master.fingerprint AS master_fingerprint,
            revocation.ts_signed AS revocation_ts_signed
       FROM agent_identity identity
       LEFT JOIN aimos_master_identity master ON master.id=1
       LEFT JOIN aimos_agent_revocation_events revocation
         ON revocation.agent_id=identity.agent_id
        AND revocation.agent_valid_from=identity.valid_from
      WHERE identity.agent_id=$1 AND identity.valid_from=$2`,
    [agentId, validFrom],
  );
  requireValue(result.rows.length === 1, 'actor_epoch_missing');
  const row = result.rows[0];
  let body;
  try { body = JSON.parse(Buffer.from(row.cert, 'base64url').toString('utf8')).body; }
  catch { throw new Error('origin_authority_actor_certificate_invalid'); }
  const pubkey = resolveCertificateAuthorityPubkey({
    certificateBody: body, subjectPubkey: row.pubkey,
    masterPubkey: row.master_pubkey, masterFingerprint: row.master_fingerprint,
  });
  const proof = pubkey ? verifyCertChain(row.cert, pubkey, { nowFn: () => Number(at) }) : null;
  requireValue(proof?.valid && body.agent_id === agentId && body.pubkey === row.pubkey
    && Number(body.valid_from) === Math.floor(new Date(row.valid_from).getTime() / 1000)
    && Number(body.valid_until) === Math.floor(new Date(row.valid_until).getTime() / 1000)
    && (row.revocation_ts_signed == null || Number(row.revocation_ts_signed) > Number(at)),
  'actor_certificate_invalid');
  return Object.freeze({ agent_id: agentId, valid_from: iso(row.valid_from),
    cert_fingerprint_sha256: fingerprint(row.cert) });
}

export async function readOriginOperationAuthorityV2({
  client, companyId, kind, referenceId, expectedMutationSha256, requestBody = null,
} = {}) {
  requireValue(client && typeof client.query === 'function', 'transaction_required');
  requireValue(ORIGIN_OPERATION_AUTHORITY_KINDS_V2.includes(kind), 'kind_invalid');
  requireValue(typeof expectedMutationSha256 === 'string'
    && /^[0-9a-f]{64}$/.test(expectedMutationSha256), 'hash_invalid');
  requireValue(typeof referenceId === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(referenceId),
  'reference_invalid');
  const context = (await client.query(
    "SELECT current_setting('app.current_client_id',true) AS company",
  )).rows[0];
  requireValue(typeof companyId === 'string' && companyId.length > 0
    && context?.company === companyId, 'transaction_scope_mismatch');
  const common = { schema: ORIGIN_OPERATION_AUTHORITY_SCHEMA_V2, kind, company_id: companyId };

  if (kind === 'verified_request') {
    requireValue(requestBody && typeof requestBody === 'object' && !Array.isArray(requestBody),
      'request_body_required');
    const verified = await readVerifiedRequestReceiptByMutationHash({
      companyId, requestReceiptMutationHash: expectedMutationSha256, client,
    });
    requireValue(verified.requestReceiptId === referenceId, 'receipt_reference_mismatch');
    const rows = await client.query(
      `SELECT receipt.*, identity.pubkey
         FROM aimos_request_receipts receipt
         JOIN agent_identity identity ON identity.agent_id=receipt.actor_agent_id
          AND identity.valid_from=receipt.actor_valid_from
        WHERE receipt.company_id=$1 AND receipt.request_receipt_id=$2`,
      [companyId, referenceId],
    );
    requireValue(rows.rows.length === 1, 'receipt_reference_mismatch');
    const row = rows.rows[0];
    requireValue([3, 4, 5].includes(Number(row.request_sig_form)), 'request_signature_form_invalid');
    requireValue(verifyRequestReceiptProof(row, { body: requestBody, pubkey: row.pubkey }).valid,
      'request_signature_invalid');
    const actor = { agent_id: verified.actorAgentId, valid_from: verified.actorValidFromIso,
      cert_fingerprint_sha256: verified.actorCertFingerprint };
    return createOriginOperationAuthorityV2({ ...common, actor, signer: actor,
      subject_agent_id: actor.agent_id, evidence: {
        receipt_id: referenceId, mutation_sha256: verified.requestReceiptMutationHash,
        request_sha256: verified.requestHash, signature_form: Number(row.request_sig_form),
        signed_method: verified.signedMethod, signed_path: verified.signedPath,
        signed_at: signedAt(verified.signedTs),
      } });
  }

  requireValue(requestBody === null, 'action_request_body_forbidden');
  const event = await readVerifiedEventById(referenceId, companyId, { client });
  requireValue(event.company_id === companyId && hex(event.mutation_hash) === expectedMutationSha256
    && event.signer_agent_id === 'housekeeper', 'event_reference_mismatch');
  const metadata = typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata;
  const signer = { agent_id: event.signer_agent_id, valid_from: iso(event.signer_valid_from),
    cert_fingerprint_sha256: event.cert_fingerprint };
  if (kind === 'verified_housekeeper_action') {
    requireValue(event.operation === 'canonical_save_action_started'
      && metadata?.schema === 'hom.aimos.canonical-save-action-start/v2', 'housekeeper_event_invalid');
    return createOriginOperationAuthorityV2({ ...common, actor: signer, signer,
      subject_agent_id: event.agent_id, evidence: { event_id: referenceId,
        mutation_sha256: expectedMutationSha256, action_sha256: metadata.action_sha256,
        action_context_sha256: metadata.action_context_sha256, signed_at: signedAt(event.ts_signed) } });
  }

  requireValue(event.operation === 'tool_execution_started'
    && metadata?.schema === 'aimos.tool-action/v1'
    && event.key === metadata.tool && event.agent_id === metadata.runtime_agent_id, 'tool_event_invalid');
  const actor = await readActor(client, metadata.actor_agent_id, metadata.actor_valid_from, event.ts_signed);
  return createOriginOperationAuthorityV2({ ...common, actor, signer,
    subject_agent_id: actor.agent_id, evidence: { event_id: referenceId,
      mutation_sha256: expectedMutationSha256, tool: metadata.tool, args_sha256: metadata.args_sha256,
      runtime_agent_id: metadata.runtime_agent_id,
      purpose_authorization_sha256: metadata.purpose_authorization_sha256 ?? null,
      signed_at: signedAt(event.ts_signed) } });
}

export async function commitCanonicalSaveOrigin({ client, companyId, memoryId, occurrenceId,
  authority, sessionId = null, sourceMemoryIds }) {
  requireValue(authority && occurrenceId, 'save_occurrence_required');
  const request = authority.kind === 'verified_request';
  const tool = authority.kind === 'verified_tool_action';
  const operation = await readOriginOperationAuthorityV2({ client, companyId, kind: authority.kind,
    referenceId: request ? authority.requestReceiptId : tool ? authority.eventId : authority.actionEventId,
    expectedMutationSha256: request ? authority.requestReceiptMutationHash
      : tool ? authority.eventMutationHash : authority.actionMutationHash,
    requestBody: request ? authority.body : null });
  const row = (await client.query(
    `SELECT id, key, company_id, agent_id, content_hash, memory_type, data_class, scope, supersedes_id, value
       FROM aimos_memories WHERE id=$1 AND company_id=$2`, [memoryId, companyId])).rows[0];
  requireValue(row && row.agent_id === operation.subject_agent_id, 'save_subject_mismatch');
  // Match the ledger owner's lock before resolving parents. Clock timestamps
  // are not a no-fork ordering authority, including across concurrent reasserts.
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
    [`origin-ledger:${companyId}`]);
  const parents = (await client.query(
    `WITH relevant AS MATERIALIZED (
       SELECT memory_id, binding_sha256, family_ids, confidentiality, integrity,
              action_class, parent_origin_sha256s
         FROM aimos_memory_origin_bindings
        WHERE company_id=$1 AND memory_id=ANY($2::uuid[])
     ), consumed AS (
       SELECT memory_id, unnest(parent_origin_sha256s) AS binding_sha256 FROM relevant
     )
     SELECT parent.binding_sha256, parent.family_ids, parent.confidentiality,
            parent.integrity, parent.action_class
       FROM relevant parent
       LEFT JOIN consumed USING (memory_id, binding_sha256)
      WHERE consumed.binding_sha256 IS NULL
      ORDER BY parent.binding_sha256 LIMIT 65`,
    [companyId, [memoryId, row.supersedes_id].filter(Boolean)])).rows;
  requireValue(parents.length <= 64, 'parent_count_invalid');
  const inputs = await readCanonicalSaveInputs({client,companyId,subjectAgentId:row.agent_id,
    value:row.value,sessionId,authority,key:row.key,sourceMemoryIds});
  // Classification records the existing native storage type, never an action
  // grant inferred from prose. Version and reassertion parents come from the
  // retained topology, not caller metadata. Other producer inputs are separate.
  const family = ['credential_reference', 'credential_provider'].includes(row.memory_type)
    ? 'secret.credential' : row.memory_type === 'preference' && row.data_class !== 'public'
      ? 'information.preference' : ['episodic', 'conversation_feed', 'session_exchange', 'session_manifest', 'session_debrief'].includes(row.memory_type)
        ? 'information.event' : 'information.fact';
  const families = originFamilyClosureV1([...new Set([family,...parents.flatMap(parent=>parent.family_ids),
    ...(inputs?.family_ids || [])])]);
  const protectedFamily = families.some(id => !['inform_only','inherit_parents'].includes(familyPolicies.get(id)));
  const integrity = inputs?.integrity==='untrusted' || parents.some(parent => parent.integrity === 'untrusted') ? 'untrusted' : 'agent';
  const actionClass = protectedFamily || integrity === 'untrusted'
    || inputs?.action_class==='none' || parents.some(parent => parent.action_class === 'none') ? 'none' : 'inform';
  const ingress = tool ? 'authenticated_tool' : request && operation.actor.agent_id !== 'housekeeper'
    ? 'authenticated_agent' : 'housekeeper_system';
  const body = { schema: inputs?MEMORY_ORIGIN_SCHEMA_V3:MEMORY_ORIGIN_SCHEMA_V2, company_id: companyId,
    ...(inputs?{derivation:inputs.derivation}:{}),
    memory_id: memoryId, occurrence_id: occurrenceId, content_sha256: hex(row.content_hash),
    actor: operation.actor, operation_authority: operation,
    request: request ? { receipt_id: operation.evidence.receipt_id,
      mutation_sha256: operation.evidence.mutation_sha256 } : null,
    origin: { ingress_channel: ingress,
      channel_identity_sha256: operation.actor.cert_fingerprint_sha256 },
    parents: { origin_sha256s: parents.map(parent => hex(parent.binding_sha256)) },
    classification: { profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1, family_ids: families,
      authority: 'deterministic_field_schema' },
    confidentiality: row.data_class, integrity, action_class: actionClass,
    scope: row.scope, session_id: sessionId || null,
    tool_action_event_id: tool ? operation.evidence.event_id : null };
  const evidence = await logEvent(companyId, operation.subject_agent_id, 'origin_family_classified', memoryId, {
    schema: 'hom.aimos.origin-classification-evidence/v2', binding: body,
    reasoning: 'Bind the retained native memory occurrence to its verified operation origin and storage family without granting action authority.',
  }, request ? authority.requestAdmissionEventId : operation.evidence.event_id,
  { client, returnReceipt: true });
  const event = await readVerifiedEventById(evidence.event_id, companyId, { client });
  const committed = await commitMemoryOriginBindingV2({ client, companyId,
    body: { ...body, classification: { ...body.classification, evidence_sha256: hex(event.mutation_hash) },
      created_at: signedAt(event.ts_signed) },
    classificationEventId: evidence.event_id, requestBody: request ? authority.body : null });
  return Object.freeze({ memory_id: memoryId, occurrence_id: occurrenceId,
    binding_sha256: committed.objectSha256, ledger_hash: committed.ledgerHash,
    classification_event_id: evidence.event_id, authority_sha256: operation.authority_sha256 });
}
