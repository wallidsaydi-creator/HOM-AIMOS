// Pure additive handoff projection over a retained full compaction record.
// MemGPT/CoALA continuity metadata; original session detail is never replaced.
import { createHash } from 'node:crypto';
import { canonicalJson as stableJson } from './canonical-json.js';

export function postCompactionInputFromMemory(input, memory, agentId) {
  const record = parseRecordFromValue(memory?.value);
  if (!memory?.memory_id || record?.kind !== 'compaction_save'
    || (input.compaction_memory_id && input.compaction_memory_id !== memory.memory_id)
    || (input.compaction_key && input.compaction_key !== memory.key)
    || (!input.compaction_memory_id && !input.compaction_key)
    || ['compaction_payload','compaction_memory','compaction','payload','delivery','post_compaction_delivery']
      .some(field => Object.hasOwn(input,field))
    || (input.session_id && input.session_id !== record.session_id)
    || (input.project_id && input.project_id !== record.project_id)) {
    throw new Error('post_compaction_retained_source_mismatch');
  }
  return { ...input, agent_id: agentId, compaction_memory: memory };
}

const SESSION_DEBRIEF_COMPRESSION_RATIO = 1;
const TIMEM_SESSION_LEVEL = 'L2';
const TIMEM_LAMBDA = 0.90;
const PERSISTENT_UTILITY = 0.90;
const RPE_TAU = 0.20;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function firstText(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function sha256Hex(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function safeKeyPart(value) {
  return String(value || 'unknown')
    .replace(/[^a-zA-Z0-9_:-]/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 80);
}

function compactIso(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'invalid_time';
  return parsed.toISOString().replace(/[-:.]/g, '').replace('T', '_').replace('Z', 'Z');
}

function summarizeItem(item) {
  if (typeof item === 'string') return item.slice(0, 240);
  if (!isPlainObject(item)) return JSON.stringify(item).slice(0, 240);
  return String(
    item.summary ||
    item.title ||
    item.command ||
    item.path ||
    item.service ||
    item.name ||
    item.content ||
    JSON.stringify(item)
  ).slice(0, 240);
}

function parseRecordFromValue(value) {
  if (isPlainObject(value)) return value;
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const parsed = JSON.parse(value);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function normalizeCompaction(input) {
  const payload = input.compaction_payload || input.payload || input.compaction || input.compaction_memory || input;
  const record =
    payload?.metadata?.compaction_record ||
    payload?.compaction_record ||
    parseRecordFromValue(payload?.value) ||
    parseRecordFromValue(payload?.memory_value) ||
    parseRecordFromValue(payload?.memory?.value) ||
    null;

  return { payload, record };
}

function confidenceBand(payload, record) {
  const raw =
    payload?.metadata?.compaction_record?.confidence?.band ||
    record?.confidence?.band ||
    payload?.confidence?.band ||
    payload?.confidence;
  if (typeof raw === 'string') {
    const lowered = raw.toLowerCase();
    if (['high', 'medium', 'low'].includes(lowered)) return lowered;
  }
  const evidenceCount = asArray(record?.evidence_refs).length;
  if (evidenceCount >= 8) return 'high';
  if (evidenceCount >= 3) return 'medium';
  return 'low';
}

function selectCompleted(record) {
  const decisions = asArray(record?.decisions)
    .filter((item) => isPlainObject(item) ? ['done', 'complete', 'completed', 'accepted'].includes(String(item.status || '').toLowerCase()) : true)
    .map(summarizeItem);
  const passedTests = asArray(record?.evidence?.tests)
    .filter((item) => !isPlainObject(item) || ['pass', 'passed', 'ok'].includes(String(item.status || '').toLowerCase()))
    .map((item) => `test: ${summarizeItem(item)}`);
  return [...decisions, ...passedTests].slice(0, 12);
}

function selectInProgress(record) {
  const state = firstText(record?.continuity?.current_state);
  const phase = firstText(record?.continuity?.current_phase);
  const activeDecisions = asArray(record?.decisions)
    .filter((item) => isPlainObject(item) && ['active', 'in_progress', 'pending'].includes(String(item.status || '').toLowerCase()))
    .map(summarizeItem);
  return [phase, state, ...activeDecisions].filter(Boolean).slice(0, 8);
}

function selectRisks(record) {
  const failedTests = asArray(record?.evidence?.tests)
    .filter((item) => isPlainObject(item) && ['fail', 'failed', 'error'].includes(String(item.status || '').toLowerCase()))
    .map((item) => `test: ${summarizeItem(item)}`);
  const toolErrors = asArray(record?.evidence?.tool_events)
    .filter((item) => isPlainObject(item) && ['fail', 'failed', 'error'].includes(String(item.status || item.outcome || '').toLowerCase()))
    .map((item) => `tool: ${summarizeItem(item)}`);
  return [...failedTests, ...toolErrors].slice(0, 8);
}

function selectBlocked(record) {
  return asArray(record?.open_questions)
    .filter((item) => isPlainObject(item) ? item.blocked === true || /block/i.test(String(item.status || item.summary || item.title || '')) : /block/i.test(String(item)))
    .map(summarizeItem)
    .slice(0, 8);
}

function enforceApproxBudget(delivery, tokenBudget) {
  const maxChars = Math.max(800, Number(tokenBudget || 900) * 4);
  let current = JSON.stringify(delivery).length;
  if (current <= maxChars) {
    return {
      ...delivery,
      budget: { requested_tokens: tokenBudget || 900, estimated_chars: current, trimmed: false },
    };
  }

  const trimmed = structuredClone(delivery);
  const listFields = [
    trimmed.handoff.completed,
    trimmed.handoff.in_progress,
    trimmed.handoff.next_actions,
    trimmed.handoff.risks,
    trimmed.handoff.blocked_on,
    trimmed.evidence_refs,
  ];
  for (const list of listFields) {
    while (Array.isArray(list) && list.length > 3 && current > maxChars) {
      list.pop();
      current = JSON.stringify(trimmed).length;
    }
  }
  return {
    ...trimmed,
    budget: { requested_tokens: tokenBudget || 900, estimated_chars: current, trimmed: true },
  };
}

function validateTimeWindow(validFrom, validUntil) {
  const fromMs = Date.parse(validFrom);
  const untilMs = Date.parse(validUntil);
  const valid = Number.isFinite(fromMs) && Number.isFinite(untilMs) && untilMs >= fromMs;
  return {
    valid,
    duration_ms: valid ? untilMs - fromMs : null,
  };
}

function buildTiMemMetadata(record) {
  return {
    tmt_level: TIMEM_SESSION_LEVEL,
    level_name: 'session',
    tmt_lambda: TIMEM_LAMBDA,
    temporal_memory_tree: {
      T: ['M', 'E', 'tau', 'sigma'],
      tau: {
        valid_from: record?.time_window?.valid_from || null,
        valid_until: record?.time_window?.valid_until || null,
      },
      sigma: 'post_compaction_delivery',
    },
  };
}

function computeRpe({ surpriseAtSave = null, utility = PERSISTENT_UTILITY, tau = RPE_TAU }) {
  const surprise = Number(surpriseAtSave);
  if (surpriseAtSave == null || !Number.isFinite(surprise)) {
    return {
      rpe_score: null,
      surprise_at_save: null,
      formula_status: 'input_unavailable: requires surprise_at_save',
    };
  }
  return {
    rpe_score: Number(Math.min(1, utility >= tau ? utility * (surprise + 0.4) : 0).toFixed(6)),
    surprise_at_save: Number(surprise.toFixed(6)),
    formula_status: 'computed',
  };
}

export function buildPostCompactionDelivery(input = {}) {
  const { payload, record } = normalizeCompaction(input);
  const required = ['agent_id', 'project_id', 'session_id'];
  const missing = required.filter((field) => {
    const value = input[field] || record?.[field];
    return value === null || value === undefined || String(value).trim() === '';
  });
  const activeObjective = firstText(record?.continuity?.current_objective);
  const currentPhase = firstText(record?.continuity?.current_phase, record?.continuity?.current_state);
  if (!activeObjective) missing.push('active_objective');
  if (!currentPhase) missing.push('current_phase');

  const source = {
    memory_id: payload?.memory_id || payload?.metadata?.memory_id || payload?.memory?.id || null,
    key: payload?.key || payload?.memory?.key || null,
    chain_hash: payload?.chain_hash || payload?.metadata?.chain_hash || null,
    content_hash: payload?.metadata?.content_hash || null,
    agent_id: input.agent_id || record?.agent_id || null,
    session_id: input.session_id || record?.session_id || null,
    project_id: input.project_id || record?.project_id || null,
    workspace_path: record?.workspace_path || input.workspace_path || null,
    valid_from: record?.time_window?.valid_from || input.valid_from || null,
    valid_until: record?.time_window?.valid_until || input.valid_until || null,
  };

  const handoff = {
    active_objective: activeObjective,
    current_phase: currentPhase,
    completed: selectCompleted(record),
    in_progress: selectInProgress(record),
    next_actions: asArray(record?.continuity?.next_actions).map(summarizeItem).slice(0, 12),
    risks: selectRisks(record),
    blocked_on: selectBlocked(record),
  };

  const delivery = {
    kind: 'post_compaction_delivery',
    lane: 'post_compaction_delivery',
    source,
    handoff,
    evidence_refs: asArray(record?.evidence_refs).slice(0, 24),
    confidence: {
      band: confidenceBand(payload, record),
      reasons: [
        `${asArray(record?.evidence_refs).length} evidence refs available`,
        `${asArray(record?.decisions).length} decisions preserved`,
        `${asArray(record?.evidence?.tool_events).length} tool events preserved`,
      ],
    },
    validation: {
      ok: Boolean(record) && missing.length === 0,
      missing_fields: record ? missing : ['compaction_record'],
      native_service_claim: true,
      corpus_authority: 'docs/compaction-post-compaction-corpus.md',
    },
  };

  return enforceApproxBudget(delivery, input.token_budget);
}

export function buildPostCompactionSummaryPayload(input = {}) {
  const delivery = buildPostCompactionDelivery(input);
  const sourceRecord = normalizeCompaction(input).record;
  const validFrom = input.valid_from || delivery?.source?.valid_from || sourceRecord?.time_window?.valid_from;
  const validUntil = input.valid_until || delivery?.source?.valid_until || sourceRecord?.time_window?.valid_until;
  const timeWindow = validateTimeWindow(validFrom, validUntil);
  const evidenceRefs = asArray(delivery?.evidence_refs);
  const record = {
    schema: 'hom.aimos.post-compaction-record/v1',
    kind: 'post_compaction_summary_save',
    lane: 'post_compaction_delivery',
    agent_id: input.agent_id || delivery?.source?.agent_id || sourceRecord?.agent_id || null,
    project_id: input.project_id || delivery?.source?.project_id || sourceRecord?.project_id || null,
    session_id: input.session_id || delivery?.source?.session_id || sourceRecord?.session_id || null,
    workspace_path: input.workspace_path || delivery?.source?.workspace_path || sourceRecord?.workspace_path || null,
    time_window: {
      valid_from: validFrom || null,
      valid_until: validUntil || null,
      duration_ms: timeWindow.duration_ms,
    },
    source: {
      full_compaction_key: delivery?.source?.key || input.compaction_key || null,
      full_compaction_content_hash: delivery?.source?.content_hash || null,
      memory_id: delivery?.source?.memory_id || input.compaction_memory_id || null,
      chain_hash: delivery?.source?.chain_hash || null,
    },
    continuity: {
      current_objective: delivery?.handoff?.active_objective || null,
      current_state: delivery?.handoff?.current_phase || null,
      current_phase: delivery?.handoff?.current_phase || null,
      next_actions: asArray(delivery?.handoff?.next_actions),
    },
    handoff: {
      completed: asArray(delivery?.handoff?.completed),
      in_progress: asArray(delivery?.handoff?.in_progress),
      risks: asArray(delivery?.handoff?.risks),
      blocked_on: asArray(delivery?.handoff?.blocked_on),
    },
    evidence_refs: evidenceRefs.map((ref, index) => ({
      ref_id: ref.ref_id || `summary_ref:${index}:${sha256Hex(stableJson(ref)).slice(0, 12)}`,
      kind: ref.kind || 'delivery_evidence',
      index: Number.isFinite(ref.index) ? ref.index : index,
      summary: ref.summary || summarizeItem(ref),
    })),
    confidence: {
      band: delivery?.confidence?.band || 'medium',
      raw: delivery?.confidence || null,
    },
    dream_readability: {
      markers: [
        'POST_COMPACTION_SUMMARY',
        'SESSION_DEBRIEF',
        'HANDOFF',
        'NEXT_ACTIONS',
        'EVIDENCE_REFS',
      ],
      structured_reasoning_preserved: asArray(delivery?.handoff?.completed).length > 0 || asArray(delivery?.handoff?.in_progress).length > 0,
      tool_evidence_preserved: evidenceRefs.some((ref) => ref.kind === 'tool_event'),
    },
  };
  const contentHash = sha256Hex(stableJson(record));
  const key = [
    'post-compaction-summary',
    safeKeyPart(record.project_id),
    safeKeyPart(record.session_id),
    compactIso(validFrom),
  ].join(':').slice(0, 255);

  return {
    key,
    value: stableJson(record),
    memory_type: 'session_debrief',
    metadata: {
      native_service: 'services/context/post-compaction-delivery.js',
      lane: 'post_compaction_delivery',
      compaction_record: record,
      content_hash: contentHash,
      timem: buildTiMemMetadata(record),
      chronos: {
        calendar_model: 'chronos_event_and_raw_turn',
        time_window: record.time_window,
        raw_turn_refs: evidenceRefs.filter((ref) => ref.kind === 'turn').map((ref) => ref.ref_id),
        structured_event_candidates: [],
      },
      rpe: computeRpe({ surpriseAtSave: input.surprise_at_save }),
      freshness: {
        role: 'operational_state_metadata',
        initial_state: 'fresh',
        score: 1.0,
      },
      compression_policy: {
        intent_class: 'session_debrief',
        ratio: SESSION_DEBRIEF_COMPRESSION_RATIO,
        preserve_equations: true,
      },
    },
    validation: {
      ok: delivery?.validation?.ok === true && timeWindow.valid,
      delivery_validation: delivery?.validation || null,
      time_window: timeWindow,
      corpus_authority: 'docs/compaction-post-compaction-corpus.md',
      native_service_claim: true,
    },
    delivery,
  };
}
