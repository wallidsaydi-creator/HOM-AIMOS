import { createHash } from 'node:crypto';

import { canonicalJson } from '../security/protocol/canonical-json.js';

// A log-event request is signed before its display memory exists. Producer and
// historical verifier share this exact projection; no wall clock or model is
// allowed to change the signed request's derived bytes.
export function projectSignedEventLogMemory(body, { companyId, agentId, signedTs } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || typeof body.action !== 'string' || !body.action.trim()
    || typeof body.summary !== 'string' || !body.summary.trim()
    || !companyId || !agentId || !Number.isSafeInteger(Number(signedTs))
    || Number(signedTs) <= 0
    || (body.company_id != null && body.company_id !== companyId)
    || (body.agent_id != null && body.agent_id !== agentId)
    || (body.files != null && (!Array.isArray(body.files) || body.files.some(f => typeof f !== 'string')))) {
    throw new Error('signed_event_log_input_invalid');
  }
  const timestamp = new Date(Number(signedTs) * 1000).toISOString();
  const next = body.next_action || body.next;
  const files = body.files || [];
  const value = [
    `• ${timestamp.slice(11, 16)} — [${body.action}] ${body.summary}`,
    body.result ? `  result: ${typeof body.result === 'string' ? body.result : canonicalJson(body.result)}` : null,
    body.reasoning ? `  reasoning: ${body.reasoning}` : null,
    body.source_knowledge ? `  source: ${body.source_knowledge}` : null,
    files.length ? `  files: ${files.join(', ')}` : null,
    next ? `  next: ${next}` : null,
  ].filter(Boolean).join('\n');
  return {
    company_id: companyId,
    agent_id: agentId,
    key: `event_${body.action.toLowerCase()}_${timestamp.slice(0, 16).replace('T', '_').replace(':', '')}`,
    value,
    scope: 'system',
    clearance_level: 5,
    memory_type: 'event_log',
    ...(body.source_memory_ids === undefined ? {} : { source_memory_ids: normalizeSourceMemoryIds(body.source_memory_ids) }),
  };
}

// Native producer input set. Order is canonical, repetition is not independent
// evidence, and an absent declaration is distinct from an explicit empty set.
export function normalizeSourceMemoryIds(value) {
  if (value === undefined) return null;
  if (!Array.isArray(value) || value.length > 16384
    || value.some(id => typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id))
    || new Set(value).size !== value.length) throw new Error('origin_declared_input_set_invalid');
  return [...value].sort();
}

export const CANONICAL_SAVE_SCHEMA = 'hom.aimos.canonical-save-terminal/v1';
export const CANONICAL_SAVE_STAGE_ORDER = Object.freeze([
  'AUTH',
  'RECEIPT',
  'CANARY',
  'SE',
  'ALADDIN',
  'VALIDATOR',
  'QUALITY',
  'SECRET_BOUNDARY',
  'EMBEDDING',
  'PERSISTENCE',
  'PROVENANCE',
  'LINEAGE',
  'GRAPH',
  'EPISTEMIC',
  'TERMINAL',
]);

const ACTION_DOMAIN = Buffer.from('hom-aimos-canonical-save-action-v1\0', 'utf8');
const DECISION_DOMAIN = Buffer.from('hom-aimos-canonical-save-stage-v1\0', 'utf8');
const TRACE_DOMAIN = Buffer.from('hom-aimos-canonical-save-trace-v1\0', 'utf8');
const FAILURE_STATUSES = new Set(['FAILED', 'REJECTED', 'NOT_RUN']);

// Read-only compatibility for the retained OB-2 candidate receipts. The
// candidate changed the stage list without changing the v1 schema identifier.
// New traces use the canonical order above; historical signatures/hashes and
// failed outcomes remain independently verifiable, never rewritten.
const RETAINED_OB2_STAGE_ORDER = Object.freeze([
  ...CANONICAL_SAVE_STAGE_ORDER.slice(0, -1), 'ORIGIN', 'TERMINAL',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function uint32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function normalizedEvidence(evidence) {
  if (evidence == null) return {};
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    throw new Error('canonical_save_stage_evidence_invalid');
  }
  return JSON.parse(canonicalJson(evidence));
}

export function canonicalSaveActionCommitment(projection) {
  if (!projection || typeof projection !== 'object' || Array.isArray(projection)) {
    throw new Error('canonical_save_action_projection_invalid');
  }
  return sha256(Buffer.concat([
    ACTION_DOMAIN,
    Buffer.from(canonicalJson(projection), 'utf8'),
  ])).toString('hex');
}

export function canonicalSaveStageDecision(index, stage, status, evidence = {}) {
  return stageDecisionForOrder(CANONICAL_SAVE_STAGE_ORDER, index, stage, status, evidence);
}

function stageDecisionForOrder(order, index, stage, status, evidence = {}) {
  if (order[index] !== stage) {
    throw new Error('canonical_save_stage_order_invalid');
  }
  const normalizedStatus = String(status || '').trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9_]{1,63}$/.test(normalizedStatus)) {
    throw new Error('canonical_save_stage_status_invalid');
  }
  const normalized = normalizedEvidence(evidence);
  const body = { stage, status: normalizedStatus, evidence: normalized };
  const decisionSha256 = sha256(Buffer.concat([
    DECISION_DOMAIN,
    uint32(index),
    Buffer.from(canonicalJson(body), 'utf8'),
  ])).toString('hex');
  return Object.freeze({ ...body, decision_sha256: decisionSha256 });
}

export function canonicalSaveTraceRoot(stages) {
  return traceRootForOrder(CANONICAL_SAVE_STAGE_ORDER, stages);
}

function traceRootForOrder(order, stages) {
  if (!Array.isArray(stages) || stages.length !== order.length) {
    throw new Error('canonical_save_stage_cardinality_invalid');
  }
  const decisions = stages.map((entry, index) => {
    const expected = stageDecisionForOrder(order, index, entry.stage, entry.status, entry.evidence);
    if (expected.decision_sha256 !== entry.decision_sha256) {
      throw new Error('canonical_save_stage_decision_hash_invalid');
    }
    return Buffer.from(entry.decision_sha256, 'hex');
  });
  return sha256(Buffer.concat([TRACE_DOMAIN, ...decisions])).toString('hex');
}

export function createCanonicalSaveTrace(actionSha256) {
  if (!/^[0-9a-f]{64}$/.test(String(actionSha256 || ''))) {
    throw new Error('canonical_save_action_commitment_invalid');
  }
  return { action_sha256: String(actionSha256), stages: [], restricted: false };
}

export function appendCanonicalSaveStage(trace, stage, status, evidence = {}) {
  if (!trace || !Array.isArray(trace.stages)) throw new Error('canonical_save_trace_invalid');
  const index = trace.stages.length;
  if (index >= CANONICAL_SAVE_STAGE_ORDER.length) throw new Error('canonical_save_trace_complete');
  if (trace.restricted && stage !== 'TERMINAL' && status !== 'NOT_RUN') {
    throw new Error('canonical_save_monotonic_restriction_violated');
  }
  const entry = canonicalSaveStageDecision(index, stage, status, evidence);
  trace.stages.push(entry);
  if (['FAILED', 'REJECTED'].includes(entry.status)) trace.restricted = true;
  return entry;
}

export function finalizeCanonicalSaveTrace(trace, {
  outcome,
  failedStage = null,
  failureCode = null,
  terminalEvidence = {},
} = {}) {
  const normalizedOutcome = String(outcome || '').toUpperCase();
  if (!['SUCCESS', 'FAILED', 'REJECTED'].includes(normalizedOutcome)) {
    throw new Error('canonical_save_outcome_invalid');
  }
  while (trace.stages.length < CANONICAL_SAVE_STAGE_ORDER.length - 1) {
    const stage = CANONICAL_SAVE_STAGE_ORDER[trace.stages.length];
    appendCanonicalSaveStage(trace, stage, 'NOT_RUN', {
      failed_stage: failedStage,
      failure_code: failureCode,
    });
  }
  appendCanonicalSaveStage(trace, 'TERMINAL', normalizedOutcome, terminalEvidence);
  const stages = Object.freeze([...trace.stages]);
  if (normalizedOutcome === 'SUCCESS') {
    const incomplete = stages.slice(0, -1).filter((entry) => FAILURE_STATUSES.has(entry.status));
    if (incomplete.length) throw new Error('canonical_save_success_stage_incomplete');
  }
  const stageRootSha256 = canonicalSaveTraceRoot(stages);
  return Object.freeze({
    schema: CANONICAL_SAVE_SCHEMA,
    action_sha256: trace.action_sha256,
    outcome: normalizedOutcome,
    stage_count: stages.length,
    stage_order: CANONICAL_SAVE_STAGE_ORDER,
    stages,
    stage_root_sha256: stageRootSha256,
  });
}

export function verifyCanonicalSaveTrace(value) {
  try {
    const order = Number(value?.stage_count) === RETAINED_OB2_STAGE_ORDER.length
      ? RETAINED_OB2_STAGE_ORDER : CANONICAL_SAVE_STAGE_ORDER;
    if (value?.schema !== CANONICAL_SAVE_SCHEMA
        || value.action_sha256 == null
        || Number(value.stage_count) !== order.length
        || canonicalJson(value.stage_order) !== canonicalJson(order)
        || !Array.isArray(value.stages)
        || value.stages.length !== order.length) {
      return { valid: false, reason: 'canonical_save_trace_shape_invalid' };
    }
    const root = traceRootForOrder(order, value.stages);
    if (root !== value.stage_root_sha256) {
      return { valid: false, reason: 'canonical_save_trace_root_invalid' };
    }
    const terminal = value.stages[value.stages.length - 1];
    if (terminal.stage !== 'TERMINAL' || terminal.status !== value.outcome) {
      return { valid: false, reason: 'canonical_save_terminal_mismatch' };
    }
    if (value.outcome === 'SUCCESS'
        && value.stages.slice(0, -1).some((entry) => FAILURE_STATUSES.has(entry.status))) {
      return { valid: false, reason: 'canonical_save_success_stage_incomplete' };
    }
    return { valid: true, reason: null, stageRootSha256: root };
  } catch (error) {
    return { valid: false, reason: error?.message || 'canonical_save_trace_invalid' };
  }
}

function saveActionEventMetadata(event) {
  if (event?.metadata && typeof event.metadata === 'object') return event.metadata;
  try { return JSON.parse(event?.metadata || '{}'); } catch { return {}; }
}

function saveActionMutationHash(event) {
  return typeof event?.mutation_hash === 'string'
    ? event.mutation_hash
    : Buffer.from(event?.mutation_hash || []).toString('hex');
}

export function reconstructCanonicalSaveActionTraces(events = []) {
  if (!Array.isArray(events)) throw new Error('canonical_save_action_recovery_input_invalid');
  const actions = new Map();
  const eventsById = new Map();
  const terminals = [];
  for (const event of events) {
    const eventId = String(event.id || event.event_id || '');
    if (eventsById.has(eventId)) throw new Error('canonical_save_action_duplicate_event');
    eventsById.set(eventId, event);
    if (event?.operation === 'canonical_save_action_started') {
      const metadata = saveActionEventMetadata(event);
      if (metadata.schema !== 'hom.aimos.canonical-save-action-start/v2') continue;
      const actionId = String(event.id || event.event_id || '');
      if (!actionId || actions.has(actionId)
          || !/^[0-9a-f]{64}$/.test(String(metadata.action_sha256 || ''))
          || !/^[0-9a-f]{64}$/.test(String(metadata.action_context_sha256 || ''))) {
        throw new Error('canonical_save_action_start_invalid');
      }
      actions.set(actionId, { actionId, start: event, terminal: null, recovery: null });
    } else if (event?.operation === 'canonical_save_terminal'
        || event?.operation === 'canonical_save_action_recovery_terminal') {
      terminals.push(event);
    }
  }
  for (const terminal of terminals) {
    const metadata = saveActionEventMetadata(terminal);
    const isRecovery = terminal.operation === 'canonical_save_action_recovery_terminal';
    const receipt = metadata.stages?.[1]?.evidence;
    const actionId = isRecovery
      ? String(metadata.start_event_id || terminal.parent_event_id || '')
      : String(receipt?.kind === 'verified_housekeeper_action'
        ? receipt.event_id || '' : terminal.parent_event_id || '');
    const trace = actions.get(actionId);
    if (!trace) continue;
    if (isRecovery) {
      if (trace.recovery) throw new Error('canonical_save_action_terminal_fork');
      trace.recovery = terminal;
    } else {
      if (trace.terminal) throw new Error('canonical_save_action_terminal_fork');
      trace.terminal = terminal;
    }
  }
  const ordered = [...actions.values()].sort((left, right) => left.actionId.localeCompare(right.actionId));
  for (const trace of ordered) {
    const start = saveActionEventMetadata(trace.start);
    if (trace.recovery) {
      const recovery = saveActionEventMetadata(trace.recovery);
      if (String(trace.recovery.parent_event_id || '') !== trace.actionId
          || String(trace.recovery.key || '') !== trace.actionId
          || recovery.start_event_id !== trace.actionId
          || recovery.start_mutation_hash !== saveActionMutationHash(trace.start)
          || recovery.action_sha256 !== start.action_sha256
          || recovery.action_context_sha256 !== start.action_context_sha256
          || recovery.disposition !== 'INDETERMINATE_PROCESS_RESTART'
          || recovery.save_replayed !== false) {
        throw new Error('canonical_save_action_recovery_binding_invalid');
      }
    }
    if (!trace.terminal) {
      trace.terminal = trace.recovery;
      continue;
    }
    const terminal = saveActionEventMetadata(trace.terminal);
    const verified = verifyCanonicalSaveTrace(terminal);
    const receiptEvidence = terminal.stages?.[1]?.evidence || {};
    if (!verified.valid
        || terminal.action_sha256 !== start.action_sha256
        || receiptEvidence.event_id !== trace.actionId
        || receiptEvidence.mutation_hash !== saveActionMutationHash(trace.start)) {
      throw new Error('canonical_save_action_terminal_binding_invalid');
    }
    // The terminal's causal parent is the last signed security decision, not
    // necessarily the action start. Follow only the exact CANARY/SE receipts
    // committed in this trace, checking hashes and ancestry in verified history.
    const gates = new Map(terminal.stages.slice(2, 4)
      .filter((stage) => stage.evidence?.event_id)
      .map((stage) => [String(stage.evidence.event_id), stage]));
    const visited = new Set();
    let parentId = String(trace.terminal.parent_event_id || '');
    while (parentId !== trace.actionId) {
      const gate = gates.get(parentId);
      const event = eventsById.get(parentId);
      const allowed = gate?.stage === 'CANARY'
        ? ['canary_write_scan_passed', 'canary_write_retained_quarantine']
        : gate?.stage === 'SE' ? ['security_content_decision'] : [];
      if (visited.has(parentId) || visited.size >= 2 || !gate || !event
          || !allowed.includes(event.operation)
          || saveActionMutationHash(event) !== gate.evidence.mutation_hash) {
        throw new Error('canonical_save_action_terminal_parent_invalid');
      }
      visited.add(parentId);
      parentId = String(event.parent_event_id || '');
    }
  }
  return Object.freeze({
    complete: Object.freeze(ordered.filter((trace) => trace.terminal)),
    open: Object.freeze(ordered.filter((trace) => !trace.terminal)),
    successful: Object.freeze(ordered.filter((trace) => (
      trace.terminal?.operation === 'canonical_save_terminal'
      && saveActionEventMetadata(trace.terminal).outcome === 'SUCCESS'
    ))),
    timeComplexity: 'O(n log n)',
    spaceComplexity: 'O(n)',
  });
}

export async function reconcileOpenCanonicalSaveActionsWithDeps({
  companyId,
  events = null,
  readHistoryFn,
  logEventFn,
} = {}) {
  if (!companyId || typeof readHistoryFn !== 'function' || typeof logEventFn !== 'function') {
    throw new Error('canonical_save_action_recovery_dependencies_required');
  }
  const load = async () => events || readHistoryFn(companyId, { signerAgentId: 'housekeeper' });
  const before = reconstructCanonicalSaveActionTraces(await load());
  const reconciled = [];
  for (const trace of before.open) {
    const start = saveActionEventMetadata(trace.start);
    try {
      const receipt = await logEventFn(
        companyId,
        String(trace.start.agent_id || 'housekeeper'),
        'canonical_save_action_recovery_terminal',
        trace.actionId,
        {
          schema: 'hom.aimos.canonical-save-action-recovery/v1',
          start_event_id: trace.actionId,
          start_mutation_hash: saveActionMutationHash(trace.start),
          action_sha256: start.action_sha256,
          action_context_sha256: start.action_context_sha256,
          disposition: 'INDETERMINATE_PROCESS_RESTART',
          save_replayed: false,
          reasoning: 'Housekeeper closed an orphaned autonomous SAVE start after restart without repeating the SAVE or fabricating a memory terminal.',
        },
        trace.actionId,
        { returnReceipt: true, exclusiveOperationKey: true },
      );
      reconciled.push(Object.freeze({ actionId: trace.actionId, receipt }));
    } catch (error) {
      if (error?.message !== 'event_operation_key_exists') throw error;
      const raced = reconstructCanonicalSaveActionTraces(await load()).complete
        .find((entry) => entry.actionId === trace.actionId);
      if (!raced) throw new Error('canonical_save_action_recovery_race_unverified');
      reconciled.push(Object.freeze({ actionId: trace.actionId, existing: true }));
    }
  }
  const after = reconstructCanonicalSaveActionTraces(await load());
  return Object.freeze({
    scanned: before.complete.length + before.open.length,
    reconciled: Object.freeze(reconciled),
    remainingOpen: after.open.length,
    savesReplayed: 0,
    memoriesFabricated: 0,
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}
