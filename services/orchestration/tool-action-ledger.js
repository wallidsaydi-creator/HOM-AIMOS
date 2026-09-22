// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js and canonical mutations caused by tools
// → Calls: observe/event-ledger.js
// Pipeline: TOOL EXECUTION | Position: signed derived-action authority
// Sources: RFC 6962 tamper-evident logging; RFC 8032 Ed25519; confused-deputy
// authority discipline. This service changes no retrieval/ranking mathematics.
// ─────────────────────────────────────────────────────────────────────────────

import https from 'node:https';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';

import { canonicalJson } from '../security/agent-identity.js';
import { logEvent, readVerifiedEventById, readVerifiedEventHistory } from '../observe/event-ledger.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { normalizeSourceMemoryIds } from '../write/canonical-save-contract.js';
import { agentPool, withTransaction } from '../../db/connection.js';
import {
  commitActionOriginVerdictV1,
  commitOriginElevationV2,
  readVerifiedActionOriginVerdict,
  readVerifiedMemoryOriginTips,
} from '../security/origin-ledger.js';
import { ORIGIN_FAMILY_PROFILE_BODY_V1, ORIGIN_FAMILY_PROFILE_SHA256_V1,
  originFamilyClosureV1 } from '../security/protocol/origin-binding-v1.js';
import {
  CONSEQUENTIAL_ACTION_AUTHORIZATION_SCHEMA_V1,
  CONSEQUENTIAL_ACTION_INPUT_SCHEMA_V1,
  buildActionOriginVerdictV1,
  buildConsequentialActionProjectionV1,
} from '../security/protocol/consequential-action-v1.js';
import { readVerifiedRequestReceiptByMutationHash } from '../security/request-receipt-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';
import { materialEffectOwner } from '../security/material-effect-owner.js';
import {
  ORIGIN_CORROBORATION_LICENSE_SCHEMA_V2,
  ORIGIN_ELEVATION_SCHEMA_V2,
  ORIGIN_SOURCE_OBSERVATION_SCHEMA_V1,
  ORIGIN_TRUST_REGISTRY_ACTIVATION_SCHEMA_V1,
  createOriginElevationV2,
  createOriginTrustRegistryV1,
} from '../security/protocol/origin-corroboration-v1.js';

const RESULT_ORIGIN_SCHEMA = 'hom.aimos.native-result-origin/v1';
const MODEL_CONTEXT_STARTED = 'tool_context_prepared';
const MODEL_CONTEXT_COMPLETED = 'model_context_completed';
const MODEL_CONTEXT_TERMINAL = 'model_context_terminal';
const CONFIDENTIALITY = ['public', 'internal', 'confidential', 'restricted'];
const INTEGRITY = ['untrusted', 'agent', 'trusted'];
const ACTION = ['none', 'inform', 'act'];
const FAMILY_POLICIES = new Map(ORIGIN_FAMILY_PROFILE_BODY_V1.families.map(f => [f.id, f]));

function resultOriginHash(body) {
  const bytes = Buffer.from(canonicalJson(body), 'utf8'), length = Buffer.alloc(4);
  if (bytes.length > 1_048_576) throw new Error('native_result_origin_size_invalid');
  length.writeUInt32BE(bytes.length);
  return createHash('sha256').update(Buffer.concat([Buffer.from(RESULT_ORIGIN_SCHEMA + '\0'), length, bytes])).digest('hex');
}

// A result receipt is monitor evidence, never a new grant or independent vote.
export async function verifyNativeResultOrigin(reference, { companyId, client = null } = {}) {
  const row = await readVerifiedEventById(reference.terminal_event_id, companyId, { client });
  const metadata = rowMetadata(row), classified = metadata.result_origin;
  if (!classified || classified.schema !== RESULT_ORIGIN_SCHEMA) throw new Error('native_result_origin_missing');
  const { classification_sha256, ...body } = classified;
  if (classification_sha256 !== resultOriginHash(body)
    || classification_sha256 !== reference.classification_sha256
    || body.company_id !== companyId || body.independent_authority !== false
    || body.family_profile_sha256 !== ORIGIN_FAMILY_PROFILE_SHA256_V1
    || Buffer.from(row.mutation_hash).toString('hex') !== reference.terminal_mutation_sha256
    || body.result_sha256 !== reference.result_sha256
    || body.disclosed_result_sha256 !== reference.disclosed_result_sha256
    || row.signer_agent_id !== 'housekeeper'
    || !Number.isInteger(body.clearance_floor) || body.clearance_floor < 1 || body.clearance_floor > 12
    || !Array.isArray(body.private_subject_ids) || !body.private_subject_ids.every(id => typeof id === 'string' && id)
    || !Array.isArray(body.authenticated_ingress_domains)
    || !body.authenticated_ingress_domains.every(hash => /^[0-9a-f]{64}$/.test(hash))
    || (reference.action_event_id && body.action_event_id !== reference.action_event_id)
    || ![TERMINAL, 'model_context_completed'].includes(row.operation)
    || !CONFIDENTIALITY.includes(body.confidentiality) || !INTEGRITY.includes(body.integrity)
    || !['none','inform'].includes(body.action_class)
    || canonicalJson(originFamilyClosureV1(body.family_ids)) !== canonicalJson(body.family_ids)) {
    throw new Error('native_result_origin_binding_invalid');
  }
  verifyToolInputSnapshot(body.input_snapshot);
  if (body.input_snapshot.input_sha256 !== body.input_snapshot_sha256
      || String(row.parent_event_id) !== body.action_event_id) throw new Error('native_result_input_root_invalid');
  const start = await readVerifiedEventById(body.action_event_id, companyId, { client });
  const profile = rowMetadata(start).native_tool_profile;
  if (row.operation === TERMINAL && Object.hasOwn(rowMetadata(start), 'dispatch_allowed')) {
    const execution = body.execution;
    if (!execution || canonicalJson(Object.keys(execution).sort()) !== canonicalJson(['disposition','tool_invoked'])
      || !['SUCCEEDED','DENIED','FAILED','INDETERMINATE'].includes(execution.disposition)
      || typeof execution.tool_invoked !== 'boolean'
      || execution.disposition !== metadata.disposition || metadata.outcome_sha256 !== body.result_sha256
      || (rowMetadata(start).dispatch_allowed === false && (execution.tool_invoked || execution.disposition !== 'DENIED'))
      || (execution.disposition === 'SUCCEEDED' && !execution.tool_invoked)) {
      throw new Error('native_result_execution_binding_invalid');
    }
  }
  if (body.native_profile_sha256 !== (rowMetadata(start).native_tool_profile_sha256 || null)
    || Buffer.from(start.mutation_hash).toString('hex') !== reference.action_mutation_sha256
    || start.signer_agent_id !== 'housekeeper' || start.agent_id !== row.agent_id
    || (row.operation === TERMINAL && (start.operation !== STARTED
      || metadata.tool_action_event_id !== start.id || !profile
      || sha256Canonical(profile) !== body.native_profile_sha256
      || (body.execution?.tool_invoked === false
        ? (body.source.owner !== 'services/orchestration/tool-registry.js#executeTool'
          || body.source.kind !== 'native_derivation' || body.source.namespace !== 'hom.aimos.tool_decision')
        : (body.source.owner !== profile.owner || body.source.kind !== profile.source_kind
          || body.source.namespace !== profile.source_namespace)) || reference.tool !== profile.tool
      || (metadata.disposition === 'SUCCEEDED' && metadata.outcome_sha256 !== body.result_sha256)))
    || (row.operation === 'model_context_completed' && (start.operation !== 'tool_context_prepared'
      || reference.result_kind !== 'model' || reference.tool !== null
      || body.source.owner !== 'services/orchestration/agent-tools.js#runByModel'
      || metadata.outcome_sha256 !== body.result_sha256))) {
    throw new Error('native_result_source_owner_invalid');
  }
  return classified;
}

// Resolve only this operation's real inputs. This does not backfill the brain.
export async function readNativeInputClassification({ snapshot, companyId, client, extraMemoryIds = [] }) {
  verifyToolInputSnapshot(snapshot);
  const memoryIds = normalizeSourceMemoryIds([...new Set([...snapshot.memory_ids, ...extraMemoryIds])]);
  const { memoryProvenanceLedger } = await import('../security/memory-provenance.js');
  const proof = await memoryProvenanceLedger.verifyRecallEvidence({ memoryIds, client });
  if (proof.rejected.length || proof.verified.size !== memoryIds.length) throw new Error('native_result_input_provenance_invalid');
  const origins = await readVerifiedMemoryOriginTips({ client, companyId, memoryIds });
  const rows = memoryIds.length ? (await client.query(`SELECT id::text,content_hash,data_class,clearance_level,scope,cube_scope,agent_id
    FROM aimos_memories WHERE company_id=$1 AND id=ANY($2::uuid[]) ORDER BY id`, [companyId, memoryIds])).rows : [];
  if (rows.length !== memoryIds.length) throw new Error('native_result_input_memory_missing');
  const labels = [], inputs = [], eventInputs = [];
  for (const row of rows) {
    const tips = origins.get(row.id);
    labels.push({ family_ids: tips.length ? tips.flatMap(t => t.family_ids) : ['unknown_protected'],
      confidentiality: tips.length ? row.data_class : 'restricted', integrity: tips.length ? 'agent' : 'untrusted',
      action_class: tips.length ? 'inform' : 'none' }, ...tips);
    inputs.push({ memory_id: row.id, content_sha256: row.content_hash.toString('hex'),
      provenance_binding_sha256: proof.proofs.get(row.id).binding_mutation_hash,
      origin_sha256s: tips.map(t => t.binding_sha256), legacy_unbound: tips.length === 0 });
  }
  // These kinds identify observed native producers, not trusted content. Raw
  // files and legacy records lack authenticated content-origin evidence.
  const unknownContext = snapshot.context_inputs.some(i => ['file','record','event'].includes(i.kind));
  if (unknownContext) labels.push({ family_ids: ['unknown_protected'], confidentiality: 'restricted', integrity: 'untrusted', action_class: 'none' });
  if (snapshot.context_inputs.some(i => ['request','messages'].includes(i.kind))) {
    labels.push({ family_ids: ['action_input'], confidentiality: 'restricted', integrity: 'agent', action_class: 'inform' });
  }
  for (const input of snapshot.context_inputs.filter((entry) => entry.kind === 'signed_event')) {
    const eventId = String(input.ref || '').replace(/^aimos_events:/, '');
    const event = await readVerifiedEventById(eventId, companyId, { client });
    const mutationSha256 = Buffer.from(event.mutation_hash).toString('hex');
    const projection = { event_id: eventId, mutation_sha256: mutationSha256 };
    const bytes = canonicalJson(projection);
    if (input.observed_sha256 !== createHash('sha256').update(bytes, 'utf8').digest('hex')
        || input.observed_bytes !== Buffer.byteLength(bytes, 'utf8')) {
      throw new Error('native_signed_event_input_binding_invalid');
    }
    eventInputs.push(projection);
    labels.push({ family_ids: ['information.event'], confidentiality: 'restricted', integrity: 'agent', action_class: 'none' });
  }
  for (const reference of snapshot.context_receipts) await verifyToolContextReceipt(reference, { companyId, client });
  const resultRefs = [], priorResults = [];
  for (const reference of snapshot.tool_results) {
    const classified = await verifyNativeResultOrigin(reference, { companyId, client });
    labels.push(classified);
    priorResults.push(classified);
    resultRefs.push({ terminal_event_id: reference.terminal_event_id,
      terminal_mutation_sha256: reference.terminal_mutation_sha256,
      classification_sha256: classified.classification_sha256 });
  }
  if (labels.some(l => !CONFIDENTIALITY.includes(l.confidentiality)
    || !INTEGRITY.includes(l.integrity) || !ACTION.includes(l.action_class))) throw new Error('native_result_input_label_invalid');
  const families = originFamilyClosureV1([...new Set(['derived', ...labels.flatMap(l => l.family_ids)])]);
  const confidentialityRank = Math.max(1, ...labels.map(l => CONFIDENTIALITY.indexOf(l.confidentiality)),
    ...families.map(f => CONFIDENTIALITY.indexOf(FAMILY_POLICIES.get(f).confidentiality_floor)));
  const integrityRank = Math.min(1, ...labels.map(l => INTEGRITY.indexOf(l.integrity)));
  const actionRank = Math.min(1, ...labels.map(l => ACTION.indexOf(l.action_class)));
  if (confidentialityRank < 0 || integrityRank < 0 || actionRank < 0) throw new Error('native_result_input_label_invalid');
  return { family_ids: families, confidentiality: CONFIDENTIALITY[confidentialityRank],
    integrity: INTEGRITY[integrityRank], action_class: integrityRank === 0
      || families.some(f => !['inform_only','inherit_parents'].includes(FAMILY_POLICIES.get(f).action_policy))
      ? 'none' : ACTION[actionRank],
    memory_inputs: inputs, event_inputs: eventInputs, result_inputs: resultRefs,
    unknown_context: unknownContext,
    authenticated_ingress_domains: [...new Set([...origins.values()].flat().map(t => t.channel_identity_sha256)
      .concat(priorResults.flatMap(r => r.authenticated_ingress_domains)))].sort(),
    clearance_floor: Math.max(1, ...rows.map(r => Number(r.clearance_level)), ...priorResults.map(r => r.clearance_floor)),
    private_subject_ids: [...new Set(rows.filter(r => r.cube_scope === 'private'
      || ['private','agent',r.agent_id].includes(r.scope)).map(r => r.agent_id)
      .concat(priorResults.flatMap(r => r.private_subject_ids)))].sort(),
  };
}

export async function classifyNativeResult({ state, companyId, actionEventId, profile, result, disclosedResult = result, execution = null }) {
  const snapshot = readToolInputState(state), client = await agentPool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query("SELECT set_config('app.current_client_id',$1,true),set_config('app.current_agent_id','housekeeper',true)", [companyId]);
    const tool = profile?.tool || null;
    const outputIds = tool === 'aimos_recall' ? (result?.memories || []).map(m => m.id)
      : ['aimos_save','delegate_task'].includes(tool) && result?.memory_id ? [result.memory_id] : [];
    const inherited = await readNativeInputClassification({ snapshot, companyId, client, extraMemoryIds: outputIds });
    const notInvoked = execution?.tool_invoked === false;
    const unknownSource = profile && (notInvoked
      || !['native_memory','native_record','native_derivation'].includes(profile.source_kind));
    const families = originFamilyClosureV1([...new Set([...inherited.family_ids,
      ...(tool ? ['derived.tool_result'] : []), ...(unknownSource ? ['unknown_protected'] : [])])]);
    const integrity = unknownSource || profile?.result_integrity_ceiling === 'untrusted' ? 'untrusted' : inherited.integrity;
    const body = { schema: RESULT_ORIGIN_SCHEMA, company_id: companyId, action_event_id: actionEventId,
      family_profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
      source: { owner: notInvoked ? 'services/orchestration/tool-registry.js#executeTool'
          : profile?.owner || 'services/orchestration/agent-tools.js#runByModel',
        kind: notInvoked ? 'native_derivation' : profile?.source_kind || 'native_derivation',
        namespace: notInvoked ? 'hom.aimos.tool_decision' : profile?.source_namespace || 'aimos.model',
        authenticated_content_origin: false },
      input_snapshot_sha256: snapshot.input_sha256, input_snapshot: snapshot,
      native_profile_sha256: profile ? sha256Canonical(profile) : null,
      ...(execution ? { execution } : {}),
      memory_inputs: inherited.memory_inputs, event_inputs: inherited.event_inputs,
      result_inputs: inherited.result_inputs,
      unknown_context: inherited.unknown_context, unknown_source: Boolean(unknownSource),
      authenticated_ingress_domains: inherited.authenticated_ingress_domains,
      result_sha256: sha256Canonical(result), disclosed_result_sha256: sha256Canonical(disclosedResult),
      family_ids: families, confidentiality: unknownSource ? 'restricted'
        : CONFIDENTIALITY[Math.max(CONFIDENTIALITY.indexOf(inherited.confidentiality),
          CONFIDENTIALITY.indexOf(profile?.confidentiality_floor || 'internal'))],
      integrity, action_class: integrity === 'untrusted' ? 'none' : inherited.action_class,
      clearance_floor: inherited.clearance_floor, private_subject_ids: inherited.private_subject_ids,
      independent_authority: false };
    return Object.freeze({ ...body, classification_sha256: resultOriginHash(body) });
  } finally { try { await client.query('ROLLBACK'); } finally { client.release(); } }
}

const SCHEMA = 'aimos.tool-action/v1';
const STARTED = 'tool_execution_started';
const SUCCEEDED = 'tool_execution_succeeded';
const FAILED = 'tool_execution_failed';
const INDETERMINATE = 'tool_execution_indeterminate';
const TERMINAL = 'tool_execution_terminal';
const toolInputStates = new WeakMap();

// Runtime-owned input collection, never reconstructed from model arguments.
// The signed action records each snapshot; this transient object grants no
// operation authority and is not a persistence or replay store.
export function createToolInputState(memoryIds = [], parentState = null) {
  const state = Object.freeze({ schema: 'hom.aimos.tool-input-state/v2' });
  toolInputStates.set(state, {
    memoryIds: new Set(normalizeSourceMemoryIds(memoryIds)),
    results: new Map(),
    contextInputs: new Map(),
    contextReceipts: new Map(),
  });
  if (parentState) mergeToolInputState(state, parentState);
  return state;
}

// These are observed source/byte bindings, NOT trust labels or permissions.
// Preserve every version observed, including inputs to transformations whose
// text is later compacted. No raw prompt/credential is copied into event metadata.
export function recordToolContextInput(state, { kind, owner, ref, value, memoryIds = [] }) {
  const current = toolInputStates.get(state);
  if (!current) throw new Error('native_tool_input_state_required');
  if (!['memory', 'event', 'signed_event', 'record', 'file', 'request', 'derived', 'messages'].includes(kind)
      || typeof owner !== 'string' || !owner || typeof ref !== 'string' || !ref
      || value === undefined) throw new Error('native_context_input_invalid');
  // Match the JSON-visible projection (including Date.toJSON), rather than
  // accidentally hashing Date objects as empty objects.
  const bytes = canonicalJson(JSON.parse(JSON.stringify(value, (_key, entry) => {
    if (typeof entry === 'number' && !Number.isFinite(entry)) throw new Error('native_context_non_finite_input');
    return entry;
  })));
  const body = {
    kind, owner, ref,
    observed_sha256: createHash('sha256').update(bytes, 'utf8').digest('hex'),
    observed_bytes: Buffer.byteLength(bytes, 'utf8'),
    memory_ids: Object.freeze(normalizeSourceMemoryIds(memoryIds)),
  };
  const input = Object.freeze({ ...body, input_sha256: sha256Canonical(body) });
  current.contextInputs.set(input.input_sha256, input);
  for (const id of input.memory_ids) current.memoryIds.add(id);
  return input;
}

export function recordVerifiedEventContextInput(state, { owner, eventId, mutationSha256 }) {
  const id = String(eventId || '').replace(/^aimos_events:/, '');
  const mutation = String(mutationSha256 || '').toLowerCase();
  if (!id || !/^[0-9a-f]{64}$/.test(mutation)) {
    throw new Error('native_signed_event_input_invalid');
  }
  return recordToolContextInput(state, {
    kind: 'signed_event',
    owner,
    ref: `aimos_events:${id}`,
    value: { event_id: id, mutation_sha256: mutation },
  });
}

export function mergeToolInputState(state, sourceState) {
  const current = toolInputStates.get(state);
  const source = toolInputStates.get(sourceState);
  if (!current || !source) throw new Error('native_tool_input_state_required');
  if (current.failure || source.failure) throw new Error('native_tool_result_evidence_incomplete');
  for (const id of source.memoryIds) current.memoryIds.add(id);
  for (const [id, entry] of source.results) current.results.set(id, entry);
  for (const [id, entry] of source.contextInputs) current.contextInputs.set(id, entry);
  for (const [id, entry] of source.contextReceipts) current.contextReceipts.set(id, entry);
}

export function readToolInputState(state) {
  const current = toolInputStates.get(state);
  if (!current) throw new Error('native_tool_input_state_required');
  if (current.failure) throw new Error('native_tool_result_evidence_incomplete');
  const body = {
    schema: 'hom.aimos.tool-input-snapshot/v2',
    memory_ids: Object.freeze(normalizeSourceMemoryIds([...current.memoryIds])),
    tool_results: Object.freeze([...current.results.values()].sort((a, b) => a.action_event_id.localeCompare(b.action_event_id))),
    context_inputs: Object.freeze([...current.contextInputs.values()].sort((a, b) => a.input_sha256.localeCompare(b.input_sha256))),
    context_receipts: Object.freeze([...current.contextReceipts.values()].sort((a, b) => a.event_id.localeCompare(b.event_id))),
  };
  return Object.freeze({ ...body, input_sha256: sha256Canonical(body) });
}

export function invalidateToolInputState(state) {
  const current = toolInputStates.get(state);
  if (!current) throw new Error('native_tool_input_state_required');
  current.failure = true;
}

export async function retainToolContext(state, { agentId, runId, model, messages, systemPrompt, userPrompt, toolSchemas, executionContext }) {
  if (!executionContext?.actorAgentId || !executionContext?.companyId) {
    throw new Error('verified_context_execution_authority_required');
  }
  const invocation = recordToolContextInput(state, {
    kind: 'messages', owner: 'services/orchestration/agent-tools.js#runByModel',
    ref: String(runId || executionContext.requestAdmissionEventId || agentId),
    value: { model, messages, system_prompt: systemPrompt, user_prompt: userPrompt, tool_schemas: toolSchemas },
  });
  const snapshot = readToolInputState(state);
  const receipt = await logEvent(executionContext.companyId, agentId, 'tool_context_prepared', invocation.input_sha256, {
    schema: 'hom.aimos.tool-context/v1',
    run_id: runId || null, model,
    actor_agent_id: executionContext.actorAgentId,
    actor_valid_from: executionContext.actorValidFromIso || null,
    request_admission_event_id: executionContext.requestAdmissionEventId || null,
    invocation_input_sha256: invocation.input_sha256,
    native_input_snapshot: snapshot,
    trust_established: false,
    reasoning: 'Retain native producer references and exact assembled-input commitments before inference. This observation grants no source trust, new permission or disclosure authority.',
  }, executionContext.requestAdmissionEventId || executionContext.autonomousActionEventId || null,
  { authority: executionContext, returnReceipt: true });
  toolInputStates.get(state).contextReceipts.set(receipt.event_id, Object.freeze({
    event_id: receipt.event_id, mutation_sha256: receipt.mutation_hash,
    input_sha256: snapshot.input_sha256,
  }));
  return receipt;
}

// The existing inference owner closes its prepared context with the exact
// returned bytes. Model output remains derived data, not a registered tool or
// a source of action authority. Subsequent native SAVE consumes this reference.
export async function completeToolContext(state, { receipt, agentId, result, executionContext }) {
  const current = toolInputStates.get(state);
  const reference = current?.contextReceipts.get(receipt?.event_id);
  if (!reference) throw new Error('native_model_context_start_required');
  await verifyToolContextReceipt(reference, { companyId: executionContext.companyId });
  const classification = await classifyNativeResult({ state, companyId: executionContext.companyId,
    actionEventId: receipt.event_id, profile: null, result });
  const terminal = await logEvent(executionContext.companyId, agentId, MODEL_CONTEXT_COMPLETED, receipt.event_id, {
    schema: 'hom.aimos.model-context-result/v1', context_event_id: receipt.event_id,
    outcome_sha256: classification.result_sha256, result_origin: classification,
    reasoning: 'Bind the exact native model result to all observed arguments, context and prior results; inherited labels confer no new action authority.',
  }, receipt.event_id, { authority: executionContext, returnReceipt: true, exclusiveOperationKey: true });
  current.results.set(receipt.event_id, Object.freeze({
    action_event_id: receipt.event_id, action_mutation_sha256: receipt.mutation_hash,
    terminal_event_id: terminal.event_id, terminal_mutation_sha256: terminal.mutation_hash,
    result_kind: 'model', tool: null, result_sha256: classification.result_sha256,
    disclosed_result_sha256: classification.disclosed_result_sha256,
    classification_sha256: classification.classification_sha256,
  }));
  return terminal;
}

export async function failToolContext(state, { receipt, agentId, error, executionContext }) {
  const current = toolInputStates.get(state);
  const reference = current?.contextReceipts.get(receipt?.event_id);
  if (!reference) throw new Error('native_model_context_start_required');
  await verifyToolContextReceipt(reference, { companyId: executionContext.companyId });
  return logEvent(executionContext.companyId, agentId, MODEL_CONTEXT_TERMINAL, receipt.event_id, {
    schema: 'hom.aimos.model-context-terminal/v1',
    context_event_id: receipt.event_id,
    context_mutation_sha256: receipt.mutation_hash,
    disposition: 'INDETERMINATE',
    error_class: String(error?.name || 'model_context_failure').slice(0, 128),
    reasoning: 'The model context did not produce a consumable result; Housekeeper retained an indeterminate terminal without replaying inference or manufacturing result evidence.',
  }, receipt.event_id, {
    authority: executionContext,
    returnReceipt: true,
    exclusiveOperationKey: true,
  });
}

export function reconstructModelContextTraces(rows = []) {
  if (!Array.isArray(rows)) throw new Error('model_context_recovery_input_invalid');
  const traces = new Map();
  for (const row of rows) {
    if (![MODEL_CONTEXT_STARTED, MODEL_CONTEXT_COMPLETED, MODEL_CONTEXT_TERMINAL].includes(row?.operation)) continue;
    const metadata = rowMetadata(row);
    if (row.operation === MODEL_CONTEXT_STARTED) {
      if (metadata.schema !== 'hom.aimos.tool-context/v1') continue;
      const startId = String(row.id || row.event_id || '');
      const trace = traces.get(startId) || { contextId: startId, start: null, terminal: null };
      if (!startId || trace.start) throw new Error('model_context_start_fork');
      trace.start = row;
      traces.set(startId, trace);
      continue;
    }
    if (!['hom.aimos.model-context-result/v1', 'hom.aimos.model-context-terminal/v1'].includes(metadata.schema)) continue;
    const startId = String(metadata.context_event_id || row.parent_event_id || '');
    const trace = traces.get(startId) || { contextId: startId, start: null, terminal: null };
    if (!startId || trace.terminal) throw new Error('model_context_terminal_fork');
    trace.terminal = row;
    traces.set(startId, trace);
  }
  const ordered = [...traces.values()].sort((left, right) => left.contextId.localeCompare(right.contextId));
  for (const trace of ordered) {
    if (!trace.start) throw new Error('model_context_terminal_without_start');
    if (!trace.terminal) continue;
    const terminalMetadata = rowMetadata(trace.terminal);
    const startMutationSha256 = typeof trace.start.mutation_hash === 'string'
      ? trace.start.mutation_hash : Buffer.from(trace.start.mutation_hash || []).toString('hex');
    if (String(trace.terminal.key || '') !== trace.contextId
        || String(trace.terminal.parent_event_id || '') !== trace.contextId
        || terminalMetadata.context_event_id !== trace.contextId
        || (trace.terminal.operation === MODEL_CONTEXT_TERMINAL
          && (terminalMetadata.disposition !== 'INDETERMINATE'
            || terminalMetadata.context_mutation_sha256 !== startMutationSha256))) {
      throw new Error('model_context_terminal_start_binding_invalid');
    }
  }
  return Object.freeze({
    complete: Object.freeze(ordered.filter((trace) => trace.terminal)),
    open: Object.freeze(ordered.filter((trace) => !trace.terminal)),
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function reconcileOpenModelContexts({
  companyId = AIMOS_COMPANY_ID,
  rows = null,
  readHistoryFn = readVerifiedEventHistory,
  logEventFn = logEvent,
} = {}) {
  const load = async () => rows || readHistoryFn(companyId, { signerAgentId: 'housekeeper' });
  const before = reconstructModelContextTraces(await load());
  const reconciled = [];
  for (const trace of before.open) {
    const startId = String(trace.start.id || trace.start.event_id || '');
    const mutationSha256 = typeof trace.start.mutation_hash === 'string'
      ? trace.start.mutation_hash : Buffer.from(trace.start.mutation_hash || []).toString('hex');
    try {
      const receipt = await logEventFn(companyId, String(trace.start.agent_id || 'housekeeper'),
        MODEL_CONTEXT_TERMINAL, startId, {
          schema: 'hom.aimos.model-context-terminal/v1',
          context_event_id: startId,
          context_mutation_sha256: mutationSha256,
          disposition: 'INDETERMINATE',
          error_class: 'process_restart_orphan',
          reasoning: 'Housekeeper closed an orphaned model-context start after restart without replaying inference or fabricating a model result.',
        }, startId, { returnReceipt: true, exclusiveOperationKey: true });
      reconciled.push(Object.freeze({ contextId: startId, receipt }));
    } catch (error) {
      if (error?.message !== 'event_operation_key_exists') throw error;
      const raced = reconstructModelContextTraces(await load()).complete
        .find((candidate) => candidate.contextId === startId);
      if (!raced) throw new Error('model_context_recovery_race_unverified');
      reconciled.push(Object.freeze({ contextId: startId, existing: true }));
    }
  }
  const after = reconstructModelContextTraces(await load());
  return Object.freeze({
    scanned: before.complete.length + before.open.length,
    reconciled: Object.freeze(reconciled),
    remainingOpen: after.open.length,
    modelInvocationsReplayed: 0,
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export function verifyToolInputSnapshot(snapshot) {
  if (snapshot?.schema !== 'hom.aimos.tool-input-snapshot/v2') throw new Error('native_context_snapshot_version_invalid');
  const { input_sha256: root, ...body } = snapshot;
  if (root !== sha256Canonical(body)
      || canonicalJson(Object.keys(body).sort()) !== canonicalJson(['context_inputs', 'context_receipts', 'memory_ids', 'schema', 'tool_results'])
      || !Array.isArray(body.context_inputs) || !Array.isArray(body.context_receipts)
      || !Array.isArray(body.tool_results)
      || canonicalJson(normalizeSourceMemoryIds(body.memory_ids)) !== canonicalJson(body.memory_ids)) {
    throw new Error('native_context_snapshot_binding_invalid');
  }
  const memoryIds = new Set(body.memory_ids);
  const hashes = new Set();
  for (const input of body.context_inputs) {
    const { input_sha256: digest, ...fields } = input;
    if (digest !== sha256Canonical(fields) || hashes.has(digest)
        || !fields.memory_ids.every(id => memoryIds.has(id))) throw new Error('native_context_source_binding_invalid');
    hashes.add(digest);
  }
  return true;
}

export async function verifyToolContextReceipt(receipt, { companyId = AIMOS_COMPANY_ID, client = null } = {}) {
  const row = await readVerifiedEventById(receipt.event_id, companyId, { client });
  const metadata = rowMetadata(row);
  verifyToolInputSnapshot(metadata.native_input_snapshot);
  if (row.operation !== 'tool_context_prepared' || metadata.schema !== 'hom.aimos.tool-context/v1'
      || Buffer.from(row.mutation_hash).toString('hex') !== receipt.mutation_sha256
      || metadata.native_input_snapshot.input_sha256 !== receipt.input_sha256
      || !metadata.native_input_snapshot.context_inputs.some(input => input.kind === 'messages'
        && input.input_sha256 === metadata.invocation_input_sha256)) throw new Error('native_context_receipt_binding_invalid');
  return metadata;
}

export function recordToolInputResult(state, { action, terminal, result, disclosedResult = result, classification = null }) {
  const current = toolInputStates.get(state);
  if (!current || !action?.receipt?.event_id || !terminal?.event_id) {
    throw new Error('native_tool_input_result_required');
  }
  const tool = action.authority.tool;
  const memoryIds = new Set(current.memoryIds);
  for (const id of action.sourceMemoryIds || []) memoryIds.add(id);
  if (!disclosedResult?.blocked) {
    if (tool === 'aimos_recall') {
      for (const memory of disclosedResult?.memories || []) memoryIds.add(memory.id);
    } else if (tool === 'aimos_save' && disclosedResult?.memory_id) {
      memoryIds.add(disclosedResult.memory_id);
    } else if (tool === 'delegate_task' && disclosedResult?.origin_inputs) {
      for (const id of normalizeSourceMemoryIds(disclosedResult.origin_inputs.memory_ids)) memoryIds.add(id);
      if (disclosedResult.memory_id) memoryIds.add(disclosedResult.memory_id);
    }
  }
  const normalized = normalizeSourceMemoryIds([...memoryIds]);
  if (!classification || classification.action_event_id !== action.receipt.event_id
    || classification.result_sha256 !== sha256Canonical(result)
    || classification.disclosed_result_sha256 !== sha256Canonical(disclosedResult)) {
    throw new Error('native_tool_result_classification_required');
  }
  current.memoryIds = new Set(normalized);
  current.results.set(action.receipt.event_id, Object.freeze({
    action_event_id: action.receipt.event_id,
    action_mutation_sha256: action.receipt.mutation_hash,
    terminal_event_id: terminal.event_id,
    terminal_mutation_sha256: terminal.mutation_hash,
    tool,
    result_sha256: sha256Canonical(result),
    disclosed_result_sha256: sha256Canonical(disclosedResult),
    classification_sha256: classification.classification_sha256,
  }));
}

function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value ?? null), 'utf8').digest('hex');
}

function rowMetadata(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  try { return JSON.parse(row?.metadata || '{}'); } catch { return {}; }
}

export function toolActionArgumentsHash(args = {}) {
  return sha256Canonical(args || {});
}

const ORIGIN_TRUST_CONFIG_KEY = 'ORIGIN_TRUST_REGISTRY';
const ORIGIN_FETCH_TIMEOUT_MS = 20_000;

function corroborationSha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function authorityKey(registryMutation, actionId, authorityId) {
  return `${registryMutation}:${actionId}:${authorityId}`;
}

function authorityAttemptKey(registryMutation, actionId, authorityId,
  requestReceiptMutationSha256) {
  const requestHash = String(requestReceiptMutationSha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(requestHash)) {
    throw new Error('origin_corroboration_attempt_key_invalid');
  }
  return `${authorityKey(registryMutation, actionId, authorityId)}:${requestHash}`;
}

function exactContentType(value) {
  return String(value || '').split(';', 1)[0].trim().toLowerCase();
}

export function fetchOriginAuthorityDocument(authority, {
  requestFn = https.request,
  timeoutMs = ORIGIN_FETCH_TIMEOUT_MS,
} = {}) {
  return new Promise((resolve, reject) => {
    const expectedUrl = new URL(authority.url);
    // Source evidence requires the peer certificate and SPKI, not merely an
    // authorized resumed session. A dedicated zero-cache agent forces a full
    // certificate-bearing handshake for every independent observation.
    const evidenceAgent = requestFn === https.request
      ? new https.Agent({ keepAlive: false, maxCachedSessions: 0 })
      : undefined;
    const request = requestFn(expectedUrl, {
      method: 'GET',
      headers: {
        accept: authority.media_type,
        'user-agent': 'HOM-AIMOS-Origin-Corroboration/1',
      },
      rejectUnauthorized: true,
      servername: expectedUrl.hostname,
      ...(evidenceAgent ? { agent: evidenceAgent } : {}),
    }, (response) => {
      const fail = (code) => {
        response.resume();
        reject(new Error(code));
      };
      if (response.statusCode !== 200) return fail('origin_source_http_status_invalid');
      if (response.headers.location) return fail('origin_source_redirect_forbidden');
      if (exactContentType(response.headers['content-type']) !== authority.media_type) {
        return fail('origin_source_media_type_invalid');
      }
      const declared = Number(response.headers['content-length'] || 0);
      if (declared > authority.max_bytes) return fail('origin_source_document_too_large');
      const socket = response.socket;
      if (!socket?.authorized || socket.authorizationError) {
        return fail('origin_source_tls_not_authorized');
      }
      let certificate;
      try {
        certificate = socket.getPeerX509Certificate?.() || null;
        if (!certificate) {
          const peer = socket.getPeerCertificate(true);
          if (peer?.raw) certificate = new X509Certificate(peer.raw);
        }
      } catch {
        return fail('origin_source_tls_certificate_invalid');
      }
      if (!certificate?.raw) return fail('origin_source_tls_certificate_missing');
      const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
      const chunks = [];
      let length = 0;
      response.on('data', (chunk) => {
        length += chunk.length;
        if (length > authority.max_bytes) {
          request.destroy(new Error('origin_source_document_too_large'));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      response.once('end', () => {
        const bytes = Buffer.concat(chunks);
        const marker = Buffer.from(authority.evidence_marker_utf8, 'utf8');
        if (!bytes.includes(marker)) {
          reject(new Error('origin_source_evidence_marker_missing'));
          return;
        }
        resolve(Object.freeze({
          authority_id: authority.authority_id,
          url: authority.url,
          media_type: authority.media_type,
          document_sha256: corroborationSha256(bytes),
          document_bytes: bytes.length,
          evidence_marker_sha256: corroborationSha256(marker),
          tls_peer_certificate_sha256: corroborationSha256(certificate.raw),
          tls_peer_spki_sha256: corroborationSha256(spki),
          tls_protocol: String(socket.getProtocol() || ''),
          fetched_at: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
        }));
      });
      response.once('error', reject);
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error('origin_source_fetch_timeout')));
    request.once('error', reject);
    request.end();
  });
}

function activeRegistry() {
  const entry = systemConfigStore.readVerifiedConfig(ORIGIN_TRUST_CONFIG_KEY);
  if (!entry?.value || !/^[0-9a-f]{64}$/.test(String(entry.mutation_hash || ''))) {
    throw new Error('origin_trust_registry_not_active');
  }
  let parsed;
  try { parsed = JSON.parse(entry.value); } catch {
    throw new Error('origin_trust_registry_value_invalid');
  }
  const registry = createOriginTrustRegistryV1(parsed);
  const now = new Date().toISOString();
  if (now < registry.valid_from || now >= registry.valid_until) {
    throw new Error('origin_trust_registry_expired');
  }
  return Object.freeze({
    registry,
    registryMutationSha256: entry.mutation_hash,
  });
}

async function assertCorroborationActionUnused(registry) {
  return withTransaction(async (client) => {
    const existing = await client.query(
      `SELECT e.elevation_sha256,e.valid_until,
              EXISTS (SELECT 1 FROM aimos_action_origin_verdicts v
                       WHERE v.elevation_sha256=e.elevation_sha256) AS consumed
         FROM aimos_origin_elevations e
        WHERE e.company_id=$1
          AND e.elevation_schema='hom.aimos.origin-elevation/v2'
          AND e.registry_sha256=decode($2,'hex')
          AND e.action_id=$3
        ORDER BY e.valid_until DESC,e.elevation_sha256`,
      [AIMOS_COMPANY_ID, registry.registry_sha256, registry.action.action_id],
    );
    if (existing.rows.some((row) => row.consumed)) {
      throw new Error('origin_corroboration_action_already_consumed');
    }
    if (existing.rows.some((row) => new Date(row.valid_until).getTime() > Date.now())) {
      throw new Error('origin_corroboration_action_pending_recovery');
    }
    return true;
  }, {
    restricted: true,
    readOnly: true,
    clientId: AIMOS_COMPANY_ID,
    agentId: 'housekeeper',
  });
}

async function appendRegistryActivation({ client, registry, registryMutationSha256 }) {
  const expectedMetadata = {
      schema: ORIGIN_TRUST_REGISTRY_ACTIVATION_SCHEMA_V1,
      config_key: ORIGIN_TRUST_CONFIG_KEY,
      config_mutation_sha256: registryMutationSha256,
      registry_sha256: registry.registry_sha256,
      registry,
      provider_agnostic: true,
      action_authority: false,
      reasoning: 'Housekeeper activated the exact master-signed trusted-source registry after verified system-config loading; activation grants no action by itself.',
      source_knowledge: 'Louck TMA-NM M3; HOM-AIMOS signed system configuration',
  };
  const existing = await client.query(
    `SELECT id
       FROM aimos_events
      WHERE company_id=$1 AND operation='origin_trust_registry_activated'
        AND key=$2 AND ledger_version=1
      ORDER BY ledger_seq`,
    [AIMOS_COMPANY_ID, registryMutationSha256],
  );
  if (existing.rowCount > 1) throw new Error('origin_registry_activation_fork');
  if (existing.rowCount === 1) {
    const row = await readVerifiedEventById(existing.rows[0].id, AIMOS_COMPANY_ID, { client });
    const metadata = rowMetadata(row);
    if (row.signer_agent_id !== 'housekeeper'
        || row.authority_kind !== 'housekeeper_autonomous'
        || row.parent_event_id !== null
        || canonicalJson(metadata) !== canonicalJson(expectedMetadata)) {
      throw new Error('origin_registry_activation_existing_invalid');
    }
    return Object.freeze({
      event_id: String(row.id),
      mutation_hash: Buffer.from(row.mutation_hash).toString('hex'),
      existing: true,
    });
  }
  return logEvent(AIMOS_COMPANY_ID, 'housekeeper', 'origin_trust_registry_activated',
    registryMutationSha256, expectedMetadata,
    null, { client, returnReceipt: true, exclusiveOperationKey: true });
}

async function appendSourceObservation({
  client,
  activation,
  registry,
  registryMutationSha256,
  authority,
  fetched,
  requestReceiptMutationSha256,
}) {
  return logEvent(AIMOS_COMPANY_ID, authority.principal_id, 'origin_source_observed',
    authorityAttemptKey(registryMutationSha256, registry.action.action_id,
      authority.authority_id, requestReceiptMutationSha256), {
      schema: ORIGIN_SOURCE_OBSERVATION_SCHEMA_V1,
      registry_activation_event_id: activation.event_id,
      registry_activation_mutation_sha256: activation.mutation_hash,
      config_mutation_sha256: registryMutationSha256,
      registry_sha256: registry.registry_sha256,
      action_id: registry.action.action_id,
      claim_sha256: registry.claim.claim_sha256,
      authority_id: authority.authority_id,
      principal_id: authority.principal_id,
      principal_valid_from: authority.valid_from,
      administrative_domain_sha256: authority.administrative_domain_sha256,
      upstream_source_sha256: authority.upstream_source_sha256,
      source_url_sha256: corroborationSha256(Buffer.from(authority.url, 'utf8')),
      media_type: authority.media_type,
      evidence_marker_sha256: authority.evidence_marker_sha256,
      document_sha256: fetched.document_sha256,
      document_bytes: fetched.document_bytes,
      tls_peer_certificate_sha256: fetched.tls_peer_certificate_sha256,
      tls_peer_spki_sha256: fetched.tls_peer_spki_sha256,
      tls_protocol: fetched.tls_protocol,
      fetched_at: fetched.fetched_at,
      material_effect_start_event_id: fetched.material_effect_start_event_id,
      material_effect_start_mutation_sha256: fetched.material_effect_start_mutation_sha256,
      material_effect_terminal_event_id: fetched.material_effect_terminal_event_id,
      material_effect_terminal_mutation_sha256: fetched.material_effect_terminal_mutation_sha256,
      trust_established_for_exact_claim_only: true,
      action_authority: false,
      reasoning: 'Housekeeper fetched one exact master-registered HTTPS authority, verified hostname/TLS, bounded bytes and the configured claim marker, then retained the observation without executing an action.',
      source_knowledge: 'Louck TMA-NM M1/M3; Node TLS hostname verification',
    }, activation.event_id, { client, returnReceipt: true, exclusiveOperationKey: true });
}

async function appendCorroborationLicense({
  client,
  observation,
  registry,
  registryMutationSha256,
  authority,
  baseOriginSha256s,
  actor,
  requestReceiptMutationSha256,
  validUntil,
}) {
  return logEvent(AIMOS_COMPANY_ID, authority.principal_id, 'origin_corroboration_licensed',
    authorityAttemptKey(registryMutationSha256, registry.action.action_id,
      authority.authority_id, requestReceiptMutationSha256), {
      schema: ORIGIN_CORROBORATION_LICENSE_SCHEMA_V2,
      config_mutation_sha256: registryMutationSha256,
      registry_sha256: registry.registry_sha256,
      action_id: registry.action.action_id,
      actor,
      request_receipt_mutation_sha256: requestReceiptMutationSha256,
      source_observation_event_id: observation.event_id,
      source_observation_mutation_sha256: observation.mutation_hash,
      claim_sha256: registry.claim.claim_sha256,
      principal_id: authority.principal_id,
      principal_valid_from: authority.valid_from,
      administrative_domain_sha256: authority.administrative_domain_sha256,
      upstream_source_sha256: authority.upstream_source_sha256,
      arguments_sha256: registry.action.arguments_sha256,
      value_sha256: registry.action.value_sha256,
      family_id: registry.action.primary_family_id,
      action_scope: registry.action.action_scope,
      risk_class: registry.action.risk_class,
      base_origin_sha256s: baseOriginSha256s,
      maximum_uses: 1,
      valid_until: validUntil,
      action_authority: 'exact_single_use_elevation_input_only',
      reasoning: 'Housekeeper licensed one exact source-supported value and master-bound action tuple; the license is one input to a threshold elevation and cannot authorize execution alone.',
      source_knowledge: 'Louck TMA-NM M3; HOM-AIMOS OB-5',
    }, observation.event_id, { client, returnReceipt: true, exclusiveOperationKey: true });
}

async function readCorroborationRequestInputs({
  client,
  memory,
  registry,
  executionContext,
}) {
  const request = await readVerifiedRequestReceiptByMutationHash({
    companyId: AIMOS_COMPANY_ID,
    requestReceiptMutationHash: executionContext.requestReceiptMutationHash,
    client,
  });
  if (request.actorAgentId !== executionContext.actorAgentId
      || request.actorValidFromIso !== new Date(executionContext.actorValidFromIso).toISOString()) {
    throw new Error('origin_corroboration_request_actor_mismatch');
  }
  const identity = await client.query(
    `SELECT cert FROM agent_identity
      WHERE agent_id=$1 AND valid_from=$2 AND revoked_at IS NULL
        AND valid_from<=clock_timestamp() AND valid_until>clock_timestamp()`,
    [request.actorAgentId, request.actorValidFromIso],
  );
  if (identity.rowCount !== 1) throw new Error('origin_corroboration_actor_epoch_invalid');
  const actor = Object.freeze({
    agent_id: request.actorAgentId,
    valid_from: request.actorValidFromIso,
    cert_fingerprint_sha256: corroborationSha256(Buffer.from(String(identity.rows[0].cert), 'utf8')),
  });
  const memoryResult = await client.query(
    `SELECT id::text,value,encode(content_hash,'hex') AS content_sha256
       FROM aimos_memories WHERE company_id=$1 AND id=$2::uuid`,
    [AIMOS_COMPANY_ID, memory],
  );
  if (memoryResult.rowCount !== 1
      || memoryResult.rows[0].value !== registry.claim.rendered_value) {
    throw new Error('origin_corroboration_memory_claim_mismatch');
  }
  const tips = await readVerifiedMemoryOriginTips({
    client,
    companyId: AIMOS_COMPANY_ID,
    memoryIds: [memory],
  });
  const baseOriginSha256s = [...new Set(
    (tips.get(memory) || []).map((entry) => entry.binding_sha256),
  )].sort();
  if (baseOriginSha256s.length === 0 || baseOriginSha256s.length > 64) {
    throw new Error('origin_corroboration_base_origin_missing');
  }
  return Object.freeze({
    request,
    actor,
    memoryRow: Object.freeze(memoryResult.rows[0]),
    baseOriginSha256s: Object.freeze(baseOriginSha256s),
  });
}

export async function produceIndependentOriginElevation({
  memoryId,
  actionId,
  executionContext,
} = {}) {
  const memory = String(memoryId || '').toLowerCase();
  const requestedAction = String(actionId || '').toLowerCase();
  if (!/^[0-9a-f-]{36}$/.test(memory) || !executionContext?.actorAgentId
      || !executionContext?.actorValidFromIso
      || !/^[0-9a-f]{64}$/.test(String(executionContext?.requestReceiptMutationHash || ''))) {
    throw new Error('origin_corroboration_request_invalid');
  }
  const { registry, registryMutationSha256 } = activeRegistry();
  if (requestedAction !== registry.action.action_id) {
    throw new Error('origin_corroboration_action_not_registered');
  }
  // Deny completed replays—and expose an interrupted elevation as a recovery
  // obligation—before opening either registered HTTPS source. PostgreSQL is
  // still the final concurrency authority; this ordering prevents ordinary
  // retries from causing fresh network effects.
  await assertCorroborationActionUnused(registry);
  // All local authority and claim bindings must be valid before any external
  // source is contacted. Repeat the same checks in the committing transaction
  // below so a preflight result cannot be substituted across the network wait.
  await withTransaction((client) => readCorroborationRequestInputs({
    client,
    memory,
    registry,
    executionContext,
  }), {
    restricted: true,
    readOnly: true,
    clientId: AIMOS_COMPANY_ID,
    agentId: executionContext.actorAgentId,
  });
  const fetched = await Promise.all(registry.authorities.map(async (authority) => {
    const effect = await materialEffectOwner.begin({
      kind: 'external',
      operation: 'origin_source_fetch',
      targetIdentifier: authority.url,
      inputProjection: {
        registry_sha256: registry.registry_sha256,
        action_id: registry.action.action_id,
        authority_id: authority.authority_id,
        claim_sha256: registry.claim.claim_sha256,
        evidence_marker_sha256: authority.evidence_marker_sha256,
        max_bytes: authority.max_bytes,
      },
      subjectAgentId: executionContext.actorAgentId,
      authority: executionContext,
      parentEventId: executionContext.requestAdmissionEventId || null,
      companyId: AIMOS_COMPANY_ID,
    });
    try {
      const document = await fetchOriginAuthorityDocument(authority);
      const terminal = await materialEffectOwner.finish({
        action: effect,
        disposition: 'SUCCEEDED',
        resultProjection: {
          document_sha256: document.document_sha256,
          document_bytes: document.document_bytes,
          tls_peer_certificate_sha256: document.tls_peer_certificate_sha256,
          tls_peer_spki_sha256: document.tls_peer_spki_sha256,
          evidence_marker_sha256: document.evidence_marker_sha256,
        },
        resultClass: 'origin_source_verified',
      });
      return Object.freeze({
        ...document,
        material_effect_start_event_id: effect.receipt.event_id,
        material_effect_start_mutation_sha256: effect.receipt.mutation_hash,
        material_effect_terminal_event_id: terminal.event_id,
        material_effect_terminal_mutation_sha256: terminal.mutation_hash,
      });
    } catch (error) {
      try {
        await materialEffectOwner.finish({
          action: effect,
          disposition: 'FAILED',
          resultProjection: { error_code: String(error?.message || 'origin_source_fetch_failed') },
          resultClass: 'origin_source_fetch_failed',
        });
      } catch (terminalError) {
        error.materialEffectTerminalError = terminalError?.message || String(terminalError);
      }
      throw error;
    }
  }));

  return withTransaction(async (client) => {
    const {
      request,
      actor,
      memoryRow,
      baseOriginSha256s,
    } = await readCorroborationRequestInputs({
      client,
      memory,
      registry,
      executionContext,
    });
    const nowSeconds = Math.floor(Date.now() / 1000);
    const createdAt = new Date(nowSeconds * 1000).toISOString();
    const validUntil = new Date(Math.min(
      new Date(registry.valid_until).getTime(),
      (nowSeconds + 300) * 1000,
    )).toISOString();
    const activation = await appendRegistryActivation({
      client, registry, registryMutationSha256,
    });
    const licenses = [];
    for (let index = 0; index < registry.authorities.length; index += 1) {
      const authority = registry.authorities[index];
      const observation = await appendSourceObservation({
        client,
        activation,
        registry,
        registryMutationSha256,
        authority,
        fetched: fetched[index],
        requestReceiptMutationSha256: request.requestReceiptMutationHash,
      });
      const license = await appendCorroborationLicense({
        client,
        observation,
        registry,
        registryMutationSha256,
        authority,
        baseOriginSha256s,
        actor,
        requestReceiptMutationSha256: request.requestReceiptMutationHash,
        validUntil,
      });
      licenses.push({ authority, observation, license });
    }
    const corroborators = licenses.map(({ authority, license }) => ({
      principal_id: authority.principal_id,
      valid_from: authority.valid_from,
      administrative_domain_sha256: authority.administrative_domain_sha256,
      upstream_source_sha256: authority.upstream_source_sha256,
      license_sha256: license.mutation_hash,
    })).sort((left, right) => [
      left.administrative_domain_sha256,
      left.upstream_source_sha256,
      left.principal_id,
      left.valid_from,
    ].join(':').localeCompare([
      right.administrative_domain_sha256,
      right.upstream_source_sha256,
      right.principal_id,
      right.valid_from,
    ].join(':')));
    const elevation = createOriginElevationV2({
      schema: ORIGIN_ELEVATION_SCHEMA_V2,
      company_id: AIMOS_COMPANY_ID,
      elevation_id: randomUUID(),
      actor,
      request_receipt_mutation_sha256: request.requestReceiptMutationHash,
      action_id: registry.action.action_id,
      arguments_sha256: registry.action.arguments_sha256,
      value_sha256: registry.action.value_sha256,
      family_id: registry.action.primary_family_id,
      action_scope: registry.action.action_scope,
      risk_class: registry.action.risk_class,
      base_origin_sha256s: baseOriginSha256s,
      corroborators,
      threshold: registry.threshold,
      maximum_uses: 1,
      valid_from: createdAt,
      valid_until: validUntil,
      created_at: createdAt,
    });
    const committed = await commitOriginElevationV2({
      client,
      companyId: AIMOS_COMPANY_ID,
      elevation,
    });
    return Object.freeze({
      registry,
      registryMutationSha256,
      actor,
      memoryId: memory,
      baseOriginSha256s: Object.freeze(baseOriginSha256s),
      fetched: Object.freeze(fetched),
      activation,
      licenses: Object.freeze(licenses),
      elevation,
      committed,
    });
  }, { restricted: true, clientId: AIMOS_COMPANY_ID, agentId: 'housekeeper' });
}

export async function verifyOriginCorroborationReceipt(result) {
  if (!result?.activation?.event_id || !result?.elevation?.elevation_sha256) {
    throw new Error('origin_corroboration_receipt_invalid');
  }
  const activation = await readVerifiedEventById(result.activation.event_id, AIMOS_COMPANY_ID);
  if (activation.operation !== 'origin_trust_registry_activated') {
    throw new Error('origin_corroboration_activation_invalid');
  }
  for (const entry of result.licenses) {
    const observation = await readVerifiedEventById(entry.observation.event_id, AIMOS_COMPANY_ID);
    const license = await readVerifiedEventById(entry.license.event_id, AIMOS_COMPANY_ID);
    if (observation.operation !== 'origin_source_observed'
        || license.operation !== 'origin_corroboration_licensed'
        || String(license.parent_event_id) !== String(observation.id)) {
      throw new Error('origin_corroboration_event_chain_invalid');
    }
  }
  return Object.freeze({ valid: true, elevation_sha256: result.elevation.elevation_sha256 });
}

export async function beginToolAction({
  tool,
  args = {},
  runtimeAgentId,
  executionContext,
  parentEventId = null,
  purposeAuthorizationReceipt = null,
  inputState = null,
  nativeProfile = null,
  memoryGrant = null,
  actionAuthorization = null,
  dispatchAllowed = true,
} = {}) {
  const name = String(tool || '').trim();
  const runtimeAgent = String(runtimeAgentId || '').trim();
  const actorAgentId = String(executionContext?.actorAgentId || '').trim();
  const actorValidFromIso = executionContext?.actorValidFromIso
    ? new Date(executionContext.actorValidFromIso).toISOString()
    : null;
  const actorIdentityTier = String(executionContext?.identityTier || '').trim().toUpperCase();
  const companyId = String(executionContext?.companyId || '').trim();
  if (!name || !runtimeAgent || !actorAgentId || !actorValidFromIso || !companyId) {
    throw new Error('verified_tool_execution_context_required');
  }
  if (memoryGrant && (memoryGrant.schema !== 'hom.aimos.native-memory-tool-grant-reference/v1'
    || !['aimos_recall','aimos_save'].includes(name)
    || memoryGrant.company_id !== companyId || memoryGrant.actor_agent_id !== actorAgentId
    || memoryGrant.actor_valid_from !== actorValidFromIso || memoryGrant.allowed !== true
    || (name === 'aimos_save' && memoryGrant.write_allowed !== true)
    || !/^[0-9a-f]{64}$/.test(memoryGrant.grant_mutation_sha256))) {
    throw new Error('native_memory_tool_grant_binding_invalid');
  }
  const argsHash = toolActionArgumentsHash(args);
  if (nativeProfile && (nativeProfile.profile?.schema !== 'hom.aimos.native-tool-profile/v1'
    || nativeProfile.profile.tool !== name
    || sha256Canonical(nativeProfile.profile) !== nativeProfile.sha256)) {
    throw new Error('native_tool_profile_binding_invalid');
  }
  // Rejected arguments are observed bytes, not evidence that their claimed
  // memories were read. Only admitted calls may resolve that declaration.
  const declaredIds = dispatchAllowed ? normalizeSourceMemoryIds(args.source_memory_ids) : [];
  if (inputState) recordToolContextInput(inputState, {
    kind: 'derived', owner: 'services/orchestration/tool-registry.js#executeTool',
    ref: `${name}:${argsHash}`, value: args, memoryIds: declaredIds || [],
  });
  const inputs = inputState ? readToolInputState(inputState) : null;
  const sourceMemoryIds = inputs
    ? normalizeSourceMemoryIds([...new Set([...inputs.memory_ids, ...(declaredIds || [])])])
    : declaredIds;
  if (inputState) toolInputStates.get(inputState).memoryIds = new Set(sourceMemoryIds);
  const actionPolicy = nativeProfile?.profile?.action_authority || null;
  if (actionPolicy && !inputs) throw new Error('consequential_action_input_snapshot_required');

  const appendStart = async ({ client = null, actionOrigin = null,
    effectiveDispatchAllowed = dispatchAllowed } = {}) => logEvent(companyId, runtimeAgent, STARTED, name, {
    schema: SCHEMA,
    dispatch_allowed: effectiveDispatchAllowed,
    tool: name,
    args_sha256: argsHash,
    ...(nativeProfile ? {
      native_tool_profile: nativeProfile.profile,
      native_tool_profile_sha256: nativeProfile.sha256,
    } : {}),
    ...(memoryGrant ? { native_memory_grant: memoryGrant } : {}),
    ...(sourceMemoryIds === null ? {} : { source_memory_ids: sourceMemoryIds }),
    ...(inputs ? { native_input_snapshot: inputs } : {}),
    runtime_agent_id: runtimeAgent,
    actor_agent_id: actorAgentId,
    actor_valid_from: actorValidFromIso,
    actor_identity_tier: actorIdentityTier,
    request_receipt_id: executionContext.requestReceiptId || null,
    request_receipt_mutation_hash: executionContext.requestReceiptMutationHash || null,
    request_admission_event_id: executionContext.requestAdmissionEventId || null,
    request_admission_mutation_hash: executionContext.requestAdmissionMutationHash || null,
    request_admission_authority_kind: executionContext.requestAdmissionAuthorityKind || null,
    purpose_authorization_sha256: purposeAuthorizationReceipt?.artifactSha256 || null,
    purpose_authorization_content_sha256: purposeAuthorizationReceipt?.contentSha256 || null,
    purpose_authorization_operation: purposeAuthorizationReceipt?.operation || null,
    purpose_authorization_read_root_sha256: purposeAuthorizationReceipt?.readRootSha256 || null,
    ...(actionOrigin ? { action_origin: actionOrigin } : {}),
    reasoning: `Housekeeper signed the exact derived ${name} action before execution; arguments are hash-bound and not copied into the event ledger.`,
    source_knowledge: 'tool-action-ledger.js — RFC 6962 / RFC 8032 derived-action authority',
  }, parentEventId, {
    authority: executionContext,
    returnReceipt: true,
    ...(client ? { client, identityQueryFn: (sql, params) => client.query(sql, params) } : {}),
  });

  let actionOrigin = null;
  let receipt;
  if (actionPolicy && dispatchAllowed) {
    const result = await withTransaction(async (client) => {
      const projection = buildConsequentialActionProjectionV1({
        tool: name,
        args: args || {},
        profile: nativeProfile.profile,
      });
      const inputClassification = await readNativeInputClassification({
        snapshot: inputs,
        companyId,
        client,
      });
      let actorCertFingerprint;
      if (executionContext.requestReceiptMutationHash) {
        const request = await readVerifiedRequestReceiptByMutationHash({
          companyId,
          requestReceiptMutationHash: executionContext.requestReceiptMutationHash,
          client,
        });
        if (request.actorAgentId !== actorAgentId
            || request.actorValidFromIso !== actorValidFromIso) {
          throw new Error('consequential_action_request_actor_mismatch');
        }
        actorCertFingerprint = request.actorCertFingerprint;
      } else {
        const identity = await client.query(
          `SELECT cert FROM agent_identity
            WHERE agent_id=$1 AND valid_from=$2 AND revoked_at IS NULL
              AND valid_from<=clock_timestamp() AND valid_until>clock_timestamp()`,
          [actorAgentId, actorValidFromIso],
        );
        if (identity.rowCount !== 1 || actorAgentId !== 'housekeeper') {
          throw new Error('consequential_action_actor_epoch_invalid');
        }
        actorCertFingerprint = createHash('sha256')
          .update(String(identity.rows[0].cert), 'utf8').digest('hex');
      }
      const untrustedInfluence = inputClassification.integrity !== 'trusted'
        || inputClassification.action_class !== 'act'
        || inputClassification.unknown_context === true
        || !executionContext.requestReceiptMutationHash;
      const observation = await logEvent(companyId, runtimeAgent,
        'origin_action_input_observed', name, {
          schema: CONSEQUENTIAL_ACTION_INPUT_SCHEMA_V1,
          tool: name,
          action_scope: projection.action_scope,
          risk_class: projection.risk_class,
          arguments_sha256: argsHash,
          request_receipt_mutation_sha256: executionContext.requestReceiptMutationHash || null,
          native_tool_profile_sha256: nativeProfile.sha256,
          security_value_sha256: projection.value_sha256,
          security_value_primary_family_id: projection.primary_family_id,
          security_value_family_ids: projection.family_ids,
          native_input_snapshot: inputs,
          native_input_snapshot_sha256: inputs.input_sha256,
          input_memory_origins: inputClassification.memory_inputs,
          input_event_origins: inputClassification.event_inputs,
          input_result_origins: inputClassification.result_inputs,
          untrusted_influence: untrustedInfluence,
          attribution_indeterminate: inputClassification.unknown_context === true,
          actor_agent_id: actorAgentId,
          actor_valid_from: actorValidFromIso,
          reasoning: 'The native monitor bound the exact consequential value projection to every runtime-consumed input before an action verdict.',
          source_knowledge: 'Louck TMA-NM M2/M3 and Algorithm 1; HOM-AIMOS OB-5',
        }, parentEventId, {
          authority: executionContext,
          client,
          identityQueryFn: (sql, params) => client.query(sql, params),
          returnReceipt: true,
        });
      const previous = await client.query(
        `SELECT encode(verdict_sha256,'hex') AS verdict_sha256
           FROM aimos_action_origin_verdicts prior
          WHERE company_id=$1 AND actor_agent_id=$2 AND actor_valid_from=$3
            AND tool_name=$4 AND action_scope=$5
            AND NOT EXISTS (
              SELECT 1 FROM aimos_action_origin_verdicts successor
               WHERE successor.previous_verdict_sha256=prior.verdict_sha256)
          ORDER BY committed_at DESC LIMIT 1`,
        [companyId, actorAgentId, actorValidFromIso, name, projection.action_scope],
      );
      const suppliedAuthorization = actionAuthorization?.eventId
        && actionAuthorization?.mutationSha256
        && actionAuthorization?.operatorProof?.proof_sha256 ? actionAuthorization : null;
      let exactAuthorization = null;
      if (suppliedAuthorization) {
        const claim = await readVerifiedEventById(
          suppliedAuthorization.eventId,
          companyId,
          { client },
        );
        const claimMetadata = rowMetadata(claim);
        const claimMutation = Buffer.from(claim.mutation_hash).toString('hex');
        if (claim.operation !== 'tool_approval_execution_claimed'
            || claimMutation !== suppliedAuthorization.mutationSha256
            || claimMetadata.tool !== name
            || claimMetadata.args_sha256 !== argsHash
            || claimMetadata.agent_id !== runtimeAgent) {
          throw new Error('consequential_action_authorization_claim_invalid');
        }
        exactAuthorization = await logEvent(companyId, runtimeAgent,
          'origin_action_authorized', suppliedAuthorization.eventId, {
            schema: CONSEQUENTIAL_ACTION_AUTHORIZATION_SCHEMA_V1,
            approval_claim_event_id: suppliedAuthorization.eventId,
            approval_claim_mutation_sha256: suppliedAuthorization.mutationSha256,
            actor_agent_id: actorAgentId,
            actor_valid_from: actorValidFromIso,
            tool: name,
            action_scope: projection.action_scope,
            risk_class: projection.risk_class,
            arguments_sha256: argsHash,
            security_value_sha256: projection.value_sha256,
            input_origin_sha256: observation.mutation_hash,
            prior_action_commitment_sha256: observation.mutation_hash,
            operator_proof: suppliedAuthorization.operatorProof,
            operator_proof_sha256: suppliedAuthorization.operatorProof.proof_sha256,
            maximum_uses: 1,
            valid_until: new Date((Math.floor(Date.now() / 1000) + 300) * 1000).toISOString(),
            reasoning: 'The fresh operator approval was narrowed to this exact action tuple and one use before verdict consumption.',
            source_knowledge: 'Louck TMA-NM M3 exact action-bound single-use authorization',
          }, suppliedAuthorization.eventId, {
            authority: executionContext,
            client,
            identityQueryFn: (sql, params) => client.query(sql, params),
            returnReceipt: true,
            exclusiveOperationKey: true,
          });
      }
      const baseOriginSha256s = [...new Set(
        inputClassification.memory_inputs.flatMap((entry) => entry.origin_sha256s || []),
      )].sort();
      let selectedElevationSha256 = null;
      if (untrustedInfluence && !exactAuthorization && baseOriginSha256s.length > 0) {
        const eligible = await client.query(
          `SELECT encode(public.select_origin_elevation_v2_for_action(
             $1,$2::bytea,$3,$4,$5,$6::bytea[],$7,$8,$9,$10::bytea,$11::bytea),'hex')
             AS elevation_sha256`,
          [companyId, Buffer.from(projection.value_sha256, 'hex'),
            projection.primary_family_id, projection.action_scope, projection.risk_class,
            baseOriginSha256s.map(value => Buffer.from(value, 'hex')),
            actorAgentId, actorValidFromIso, actorCertFingerprint,
            Buffer.from(executionContext.requestReceiptMutationHash, 'hex'),
            Buffer.from(argsHash, 'hex')],
        );
        selectedElevationSha256 = eligible.rows[0]?.elevation_sha256 || null;
      }
      const verdict = buildActionOriginVerdictV1({
        companyId,
        actor: {
          agent_id: actorAgentId,
          valid_from: actorValidFromIso,
          cert_fingerprint_sha256: actorCertFingerprint,
        },
        projection,
        inputOriginSha256: observation.mutation_hash,
        untrustedInfluence,
        attributionIndeterminate: inputClassification.unknown_context === true,
        elevationSha256: selectedElevationSha256,
        userAuthorizationSha256: exactAuthorization?.mutation_hash || null,
        previousVerdictSha256: previous.rows[0]?.verdict_sha256 || null,
        createdAt: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
      });
      const committed = await commitActionOriginVerdictV1({
        client,
        companyId,
        verdict,
        authorizationEventId: exactAuthorization?.event_id || null,
      });
      const binding = Object.freeze({
        schema: 'hom.aimos.tool-action-origin-binding/v1',
        input_event_id: observation.event_id,
        input_mutation_sha256: observation.mutation_hash,
        projection_sha256: projection.value_sha256,
        verdict_sha256: verdict.verdict_sha256,
        verdict_ledger_sha256: committed.ledgerHash,
        decision: verdict.decision,
        failure_code: verdict.failure_code,
      });
      const started = await appendStart({
        client,
        actionOrigin: binding,
        effectiveDispatchAllowed: verdict.decision === 'ALLOW',
      });
      return { receipt: started, actionOrigin: binding };
    }, { restricted: true, clientId: companyId, agentId: 'housekeeper' });
    receipt = result.receipt;
    actionOrigin = result.actionOrigin;
  } else {
    receipt = await appendStart();
  }
  return Object.freeze({
    receipt,
    sourceMemoryIds,
    authority: Object.freeze({
      kind: 'verified_tool_action',
      eventId: receipt.event_id,
      eventMutationHash: receipt.mutation_hash,
      tool: name,
      argsHash,
      nativeToolProfileSha256: nativeProfile?.sha256 || null,
      nativeInputSha256: inputs?.input_sha256 || null,
      runtimeAgentId: runtimeAgent,
      actorAgentId,
      actorValidFromIso,
      actorIdentityTier,
      companyId,
      requestReceiptId: executionContext.requestReceiptId || null,
      requestReceiptMutationHash: executionContext.requestReceiptMutationHash || null,
      requestAdmissionEventId: executionContext.requestAdmissionEventId || null,
      requestAdmissionMutationHash: executionContext.requestAdmissionMutationHash || null,
      requestAdmissionAuthorityKind: executionContext.requestAdmissionAuthorityKind || null,
      purposeAuthorizationSha256: purposeAuthorizationReceipt?.artifactSha256 || null,
      actionOriginVerdictSha256: actionOrigin?.verdict_sha256 || null,
      actionOriginDecision: actionOrigin?.decision || null,
    }),
  });
}

export async function finishToolAction({ action, executionContext, succeeded, disposition = null, result = null, error = null, classification = null } = {}) {
  if (!action?.receipt?.event_id || !action?.authority) throw new Error('tool_action_start_receipt_required');
  const normalizedDisposition = String(disposition || (succeeded ? 'SUCCEEDED' : 'FAILED')).toUpperCase();
  if (!['SUCCEEDED', 'DENIED', 'FAILED', 'INDETERMINATE'].includes(normalizedDisposition)) {
    throw new Error('tool_action_terminal_disposition_invalid');
  }
  const operation = TERMINAL;
  if (classification) {
    const { classification_sha256, ...body } = classification;
    if (classification_sha256 !== resultOriginHash(body)
      || body.action_event_id !== action.receipt.event_id || body.result_sha256 !== sha256Canonical(result)
      || body.native_profile_sha256 !== action.authority.nativeToolProfileSha256
      || (body.execution && body.execution.disposition !== normalizedDisposition)) throw new Error('native_result_terminal_binding_invalid');
  }
  return logEvent(action.authority.companyId, action.authority.runtimeAgentId, operation, action.receipt.event_id, {
    schema: SCHEMA,
    tool_action_event_id: action.receipt.event_id,
    tool: action.authority.tool,
    native_tool_profile_sha256: action.authority.nativeToolProfileSha256 || null,
    native_input_sha256: action.authority.nativeInputSha256 || null,
    args_sha256: action.authority.argsHash,
    runtime_agent_id: action.authority.runtimeAgentId,
    actor_agent_id: action.authority.actorAgentId,
    actor_valid_from: action.authority.actorValidFromIso,
    actor_identity_tier: action.authority.actorIdentityTier,
    outcome_sha256: classification?.result_sha256
      || sha256Canonical(normalizedDisposition === 'SUCCEEDED' ? result : String(error || 'unknown_error')),
    outcome: normalizedDisposition.toLowerCase(),
    disposition: normalizedDisposition,
    ...(classification ? { result_origin: classification } : {}),
    reasoning: `Housekeeper signed the terminal ${operation} outcome for the exact derived tool action.`,
    source_knowledge: 'tool-action-ledger.js — append-only signed tool outcome',
  }, action.receipt.event_id, {
    authority: executionContext,
    returnReceipt: true,
    exclusiveOperationKey: true,
  });
}

export function reconstructToolActionTraces(rows = []) {
  if (!Array.isArray(rows)) throw new Error('tool_action_recovery_input_invalid');
  const actions = new Map();
  for (const row of rows) {
    if (![STARTED, TERMINAL, SUCCEEDED, FAILED, INDETERMINATE].includes(row?.operation)) continue;
    const metadata = rowMetadata(row);
    if (metadata.schema !== SCHEMA) continue;
    if (row.operation === STARTED) {
      const startId = String(row.id || row.event_id || '');
      const action = actions.get(startId) || { actionId: startId, start: null, terminal: null };
      if (!startId || action.start) throw new Error('tool_action_start_fork');
      action.start = row;
      actions.set(startId, action);
      continue;
    }
    const startId = String(metadata.tool_action_event_id || '');
    const action = actions.get(startId) || { actionId: startId, start: null, terminal: null };
    if (action.terminal) throw new Error('tool_action_terminal_fork');
    action.terminal = row;
    actions.set(startId, action);
  }
  const values = [...actions.values()].sort((left, right) => left.actionId.localeCompare(right.actionId));
  for (const action of values) {
    if (!action.start) throw new Error('tool_action_terminal_without_start');
    if (!action.terminal) continue;
    const metadata = rowMetadata(action.terminal);
    if (String(action.terminal.key || '') !== action.actionId
        || String(action.terminal.parent_event_id || '') !== action.actionId
        || metadata.args_sha256 !== rowMetadata(action.start).args_sha256
        || metadata.tool !== rowMetadata(action.start).tool) {
      throw new Error('tool_action_terminal_start_binding_invalid');
    }
  }
  return Object.freeze({
    complete: Object.freeze(values.filter((action) => action.terminal)),
    open: Object.freeze(values.filter((action) => !action.terminal)),
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function reconcileOpenToolActions({
  companyId = AIMOS_COMPANY_ID,
  rows = null,
  readHistoryFn = readVerifiedEventHistory,
  finishFn = finishToolAction,
} = {}) {
  const load = async () => rows || readHistoryFn(companyId, { signerAgentId: 'housekeeper' });
  const before = reconstructToolActionTraces(await load());
  const reconciled = [];
  for (const trace of before.open) {
    const metadata = rowMetadata(trace.start);
    const startId = String(trace.start.id || trace.start.event_id || '');
    const mutationHash = typeof trace.start.mutation_hash === 'string'
      ? trace.start.mutation_hash
      : Buffer.from(trace.start.mutation_hash || []).toString('hex');
    const action = Object.freeze({
      receipt: Object.freeze({ event_id: startId, mutation_hash: mutationHash }),
      authority: Object.freeze({
        kind: 'verified_tool_action',
        eventId: startId,
        eventMutationHash: mutationHash,
        tool: metadata.tool,
        argsHash: metadata.args_sha256,
        runtimeAgentId: metadata.runtime_agent_id,
        actorAgentId: metadata.actor_agent_id,
        actorValidFromIso: metadata.actor_valid_from,
        actorIdentityTier: metadata.actor_identity_tier,
        companyId: String(trace.start.company_id || companyId),
        purposeAuthorizationSha256: metadata.purpose_authorization_sha256 || null,
      }),
    });
    try {
      const receipt = await finishFn({
        action,
        executionContext: null,
        disposition: 'INDETERMINATE',
        error: 'process_restart_orphan_reconciled_without_tool_replay',
      });
      reconciled.push(Object.freeze({ actionId: trace.actionId, receipt }));
    } catch (error) {
      if (error?.message !== 'event_operation_key_exists') throw error;
      const raced = reconstructToolActionTraces(await load()).complete
        .find((entry) => entry.actionId === trace.actionId);
      if (!raced) throw new Error('tool_action_recovery_race_unverified');
      reconciled.push(Object.freeze({ actionId: trace.actionId, existing: true }));
    }
  }
  const after = reconstructToolActionTraces(await load());
  return Object.freeze({
    scanned: before.complete.length + before.open.length,
    reconciled: Object.freeze(reconciled),
    remainingOpen: after.open.length,
    toolInvocationsReplayed: 0,
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function verifyToolActionAuthority(authority, {
  client = null,
  expectedCompanyId,
  expectedTool,
  expectedActorAgentId,
  expectedArguments = null,
} = {}) {
  if (authority?.kind !== 'verified_tool_action') throw new Error('verified_tool_action_required');
  const companyId = String(expectedCompanyId || authority.companyId || '').trim();
  const row = await readVerifiedEventById(authority.eventId, companyId, { client });
  const body = typeof row.signed_body === 'string' ? JSON.parse(row.signed_body) : row.signed_body;
  const metadata = rowMetadata(row);
  if (metadata.native_input_snapshot?.schema === 'hom.aimos.tool-input-snapshot/v2') {
    verifyToolInputSnapshot(metadata.native_input_snapshot);
    if (authority.nativeInputSha256 !== metadata.native_input_snapshot.input_sha256) {
      throw new Error('verified_tool_context_binding_invalid');
    }
  }
  const profile = metadata.native_tool_profile ?? null;
  const profileHash = metadata.native_tool_profile_sha256 ?? null;
  const profileMatches = profile === null
    ? profileHash === null && (authority.nativeToolProfileSha256 ?? null) === null
    : profile.schema === 'hom.aimos.native-tool-profile/v1'
      && profile.tool === authority.tool
      && sha256Canonical(profile) === profileHash
      && profileHash === authority.nativeToolProfileSha256;
  if (profile?.action_authority) {
    const binding = metadata.action_origin;
    if (!binding || binding.schema !== 'hom.aimos.tool-action-origin-binding/v1'
        || binding.decision !== 'ALLOW'
        || binding.verdict_sha256 !== authority.actionOriginVerdictSha256) {
      throw new Error('verified_tool_action_origin_binding_invalid');
    }
    const verify = (verificationClient) => readVerifiedActionOriginVerdict({
      client: verificationClient, companyId, verdictSha256: binding.verdict_sha256,
      expectedTool: authority.tool, expectedArgumentsSha256: authority.argsHash,
      expectedInputEventId: binding.input_event_id,
    });
    const verified = client ? await verify(client) : await withTransaction(verify, {
      restricted: true,
      clientId: companyId,
      agentId: 'housekeeper',
    });
    if (binding.projection_sha256 !== verified.body.security_values[0]?.value_sha256
        || verified.body.action_scope !== profile.action_authority.action_scope
        || verified.body.risk_class !== profile.action_authority.risk_class) {
      throw new Error('verified_tool_action_origin_binding_invalid');
    }
  }
  const exact = row.operation === STARTED
    && metadata.dispatch_allowed !== false
    && profileMatches
    && row.key === authority.tool
    && metadata.schema === SCHEMA
    && metadata.tool === authority.tool
    && metadata.args_sha256 === authority.argsHash
    && metadata.runtime_agent_id === authority.runtimeAgentId
    && metadata.actor_agent_id === authority.actorAgentId
    && new Date(metadata.actor_valid_from).toISOString() === new Date(authority.actorValidFromIso).toISOString()
    && String(metadata.actor_identity_tier || '').toUpperCase() === String(authority.actorIdentityTier || '').toUpperCase()
    && body?.event_id === authority.eventId
    && Buffer.from(row.mutation_hash).toString('hex') === authority.eventMutationHash
    && (metadata.purpose_authorization_sha256 || null)
      === (authority.purposeAuthorizationSha256 || null)
    && companyId === authority.companyId
    && (metadata.request_receipt_id ?? null) === (authority.requestReceiptId ?? null)
    && (metadata.request_receipt_mutation_hash ?? null) === (authority.requestReceiptMutationHash ?? null)
    && (metadata.request_admission_event_id ?? null) === (authority.requestAdmissionEventId ?? null)
    && (metadata.request_admission_mutation_hash ?? null) === (authority.requestAdmissionMutationHash ?? null)
    && (metadata.request_admission_authority_kind ?? null) === (authority.requestAdmissionAuthorityKind ?? null)
    && (!expectedTool || expectedTool === authority.tool)
    && (!expectedActorAgentId || expectedActorAgentId === authority.actorAgentId)
    && (expectedArguments === null || toolActionArgumentsHash(expectedArguments) === metadata.args_sha256);
  if (!exact) throw new Error('verified_tool_action_binding_invalid');
  return Object.freeze({
    body,
    agentId: row.signer_agent_id,
    validFromIso: new Date(row.signer_valid_from).toISOString(),
    certString: row.cert,
    signedTs: Number(row.ts_signed),
    nonce: String(row.nonce),
    sigBytes: Buffer.from(row.sig),
    identityTier: row.identity_tier,
    requestSigForm: 1,
    signedMethod: null,
    signedPath: null,
    signedClaims: null,
    actionEventId: authority.eventId,
    actionMutationHash: authority.eventMutationHash,
    actionArgsHash: metadata.args_sha256,
  });
}

export const TOOL_ACTION_OPERATIONS = Object.freeze({ STARTED, SUCCEEDED, FAILED });
