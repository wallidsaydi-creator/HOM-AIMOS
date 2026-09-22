// Pure native compaction record projection. No database, signing or runtime imports.
// Chronos raw-turn/event split; TiMem session coordinates; Aladdin full retention.
import { createHash } from 'node:crypto';
import { canonicalJson as stableJson } from './canonical-json.js';

const REQUIRED_FIELDS = [
  'agent_id',
  'project_id',
  'session_id',
  'workspace_path',
  'valid_from',
  'valid_until',
  'turns',
  'tool_events',
  'files',
  'services',
  'tests',
  'decisions',
  'open_questions',
  'confidence',
];

const QUALITY_SUBSTANCE_MIN = 0.30;
const SESSION_DEBRIEF_COMPRESSION_RATIO = 1;
const PERSISTENT_UTILITY = 0.90;
const RPE_TAU = 0.20;
const TIMEM_SESSION_LEVEL = 'L2';
const TIMEM_LAMBDA = 0.90;
const BASELINE_MEMORY_COUNT = 14000;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sha256Hex(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
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

function missingRequiredFields(input) {
  return REQUIRED_FIELDS.filter((field) => {
    if (!Object.prototype.hasOwnProperty.call(input, field)) return true;
    const value = input[field];
    if (value === null || value === undefined) return true;
    if (typeof value === 'string' && value.trim() === '') return true;
    return false;
  });
}

function validateTimeWindow(validFrom, validUntil) {
  const fromMs = Date.parse(validFrom);
  const untilMs = Date.parse(validUntil);
  const valid = Number.isFinite(fromMs) && Number.isFinite(untilMs) && untilMs >= fromMs;
  return {
    valid,
    valid_from_ms: Number.isFinite(fromMs) ? fromMs : null,
    valid_until_ms: Number.isFinite(untilMs) ? untilMs : null,
    duration_ms: valid ? untilMs - fromMs : null,
  };
}

function estimateSubstanceScore(record) {
  const text = stableJson(record);
  let score = 0.25;
  if (asArray(record.evidence?.files).length > 0) score += 0.10;
  if (asArray(record.decisions).length > 0) score += 0.20;
  if (asArray(record.continuity?.next_actions).length > 0) score += 0.10;
  if (asArray(record.evidence?.tool_events).length > 0) score += 0.10;
  if (text.length > 500) score += 0.20;
  else if (text.length > 200) score += 0.15;
  else if (text.length > 100) score += 0.10;
  return Number(Math.min(1, score).toFixed(4));
}

function looksRepetitive(text) {
  const tokens = String(text || '').toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length < 8) return false;
  return new Set(tokens).size / tokens.length < 0.15;
}

function euclideanDistance(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length === 0 || a.length !== b.length) {
    return null;
  }
  const sum = a.reduce((acc, value, index) => {
    const delta = Number(value) - Number(b[index]);
    return Number.isFinite(delta) ? acc + delta * delta : Number.NaN;
  }, 0);
  return Number.isFinite(sum) ? Number(Math.sqrt(sum).toFixed(6)) : null;
}

function computeRpe({ surpriseAtSave, utility = PERSISTENT_UTILITY, tau = RPE_TAU }) {
  if (!Number.isFinite(surpriseAtSave)) {
    return {
      rpe_score: null,
      surprise_at_save: null,
      formula_status: 'input_unavailable: requires embedding_predicted and embedding_actual arrays, or explicit surprise_at_save',
    };
  }
  const gated = utility >= tau ? utility * (surpriseAtSave + 0.4) : 0;
  return {
    rpe_score: Number(Math.min(1, gated).toFixed(6)),
    surprise_at_save: Number(surpriseAtSave.toFixed(6)),
    formula_status: 'computed',
  };
}

function confidenceBand(confidence) {
  if (typeof confidence === 'string') {
    const lowered = confidence.toLowerCase();
    if (['high', 'medium', 'low'].includes(lowered)) return lowered;
  }
  if (isPlainObject(confidence) && typeof confidence.level === 'string') {
    const lowered = confidence.level.toLowerCase();
    if (['high', 'medium', 'low'].includes(lowered)) return lowered;
  }
  if (isPlainObject(confidence) && Number.isFinite(confidence.score)) {
    if (confidence.score >= 0.75) return 'high';
    if (confidence.score >= 0.50) return 'medium';
    return 'low';
  }
  return 'medium';
}

function summarizeItem(item) {
  if (typeof item === 'string') return item.slice(0, 240);
  if (!isPlainObject(item)) return stableJson(item).slice(0, 240);
  return String(
    item.summary ||
    item.title ||
    item.command ||
    item.path ||
    item.service ||
    item.name ||
    item.content ||
    stableJson(item)
  ).slice(0, 240);
}

function makeEvidenceRefs(input) {
  const groups = [
    ['turn', asArray(input.turns)],
    ['tool_event', asArray(input.tool_events)],
    ['file', asArray(input.files)],
    ['service', asArray(input.services)],
    ['test', asArray(input.tests)],
    ['decision', asArray(input.decisions)],
    ['open_question', asArray(input.open_questions)],
  ];
  return groups.flatMap(([kind, items]) => items.map((item, index) => {
    const material = stableJson({ kind, index, item });
    return {
      ref_id: `${kind}:${index}:${sha256Hex(material).slice(0, 12)}`,
      kind,
      index,
      summary: summarizeItem(item),
    };
  }));
}

function buildChronosMetadata(input, evidenceRefs) {
  const eventCandidates = [
    ...asArray(input.decisions).map((decision, index) => ({
      subject: input.agent_id,
      verb: 'decided',
      object: summarizeItem(decision),
      source_ref: evidenceRefs.find((ref) => ref.kind === 'decision' && ref.index === index)?.ref_id || null,
    })),
    ...asArray(input.tool_events).map((event, index) => ({
      subject: input.agent_id,
      verb: 'used_tool',
      object: summarizeItem(event),
      source_ref: evidenceRefs.find((ref) => ref.kind === 'tool_event' && ref.index === index)?.ref_id || null,
    })),
    ...asArray(input.tests).map((test, index) => ({
      subject: input.agent_id,
      verb: 'validated',
      object: summarizeItem(test),
      source_ref: evidenceRefs.find((ref) => ref.kind === 'test' && ref.index === index)?.ref_id || null,
    })),
  ];

  return {
    calendar_model: 'chronos_event_and_raw_turn',
    time_window: {
      valid_from: input.valid_from,
      valid_until: input.valid_until,
    },
    raw_turn_refs: evidenceRefs.filter((ref) => ref.kind === 'turn').map((ref) => ref.ref_id),
    structured_event_candidates: eventCandidates,
  };
}

function buildTiMemMetadata(input) {
  return {
    tmt_level: TIMEM_SESSION_LEVEL,
    level_name: 'session',
    tmt_lambda: TIMEM_LAMBDA,
    temporal_memory_tree: {
      T: ['M', 'E', 'tau', 'sigma'],
      tau: {
        valid_from: input.valid_from,
        valid_until: input.valid_until,
      },
      sigma: 'structured_session_debrief',
    },
  };
}

function buildScaleMetadata(memoryCount = BASELINE_MEMORY_COUNT) {
  const scaleRatio = Math.max(1, Number(memoryCount) / BASELINE_MEMORY_COUNT || 1);
  return {
    baseline_memory_count: BASELINE_MEMORY_COUNT,
    scale_ratio: Number(scaleRatio.toFixed(6)),
    memtable_batch_size: Math.max(100, Math.floor(100 * Math.pow(scaleRatio, 0.5))),
    bloom_target_fpr: Number(Math.max(0.005, Math.min(0.02, 0.01 * Math.pow(scaleRatio, 0.3))).toFixed(6)),
  };
}

function buildQualityValidation(record, value) {
  const substanceScore = estimateSubstanceScore(record);
  const formValid = typeof value === 'string' && value.trim().length >= 20;
  const filterValid = !looksRepetitive(value);
  return {
    ok: formValid && filterValid,
    walls: {
      form: { pass: formValid, min_chars: 20, actual_chars: value.length },
      filter: { pass: filterValid, repetitive: !filterValid },
      substance: {
        pass: true,
        exempt: true,
        score: substanceScore,
        min_score: QUALITY_SUBSTANCE_MIN,
        exempt_memory_type: 'session_debrief',
      },
    },
  };
}

function buildIdentityMetadata(input, recordHash) {
  return {
    required_for_route: true,
    save_envelope_sidecar_required: false,
    content_hash_formula: 'SHA-256(JCS(compaction_record))',
    candidate_content_hash: recordHash,
    agent_id: input.agent_id,
  };
}

function buildTriggerMetadata(input) {
  return {
    owner: 'hom_app_runtime',
    model: input.model || null,
    context_window: Number.isFinite(Number(input.context_window)) ? Number(input.context_window) : null,
    tokens_used: Number.isFinite(Number(input.tokens_used)) ? Number(input.tokens_used) : null,
    threshold: Number.isFinite(Number(input.threshold)) ? Number(input.threshold) : null,
    reason: input.reason || input.compaction_reason || null,
    origin: input.origin || 'app_context_window',
  };
}

export function buildCompactionSavePayload(input = {}) {
  const missing = missingRequiredFields(input);
  const invalidArrays = ['turns','tool_events','files','services','tests','decisions','open_questions']
    .filter(field => !Array.isArray(input[field]));
  if (!Array.isArray(input.turns) || input.turns.length === 0) invalidArrays.push('nonempty_turns');
  const timeWindow = validateTimeWindow(input.valid_from, input.valid_until);
  const evidenceRefs = makeEvidenceRefs(input);
  const surpriseInput = Number.isFinite(input.surprise_at_save)
    ? Number(input.surprise_at_save)
    : euclideanDistance(input.embedding_predicted, input.embedding_actual);
  const rpe = computeRpe({
    surpriseAtSave: surpriseInput,
    utility: Number.isFinite(input.utility) ? Number(input.utility) : PERSISTENT_UTILITY,
    tau: Number.isFinite(input.rpe_tau) ? Number(input.rpe_tau) : RPE_TAU,
  });

  const record = {
    schema: 'hom.aimos.compaction-record/v1',
    kind: 'compaction_save',
    lane: 'compaction_full',
    agent_id: input.agent_id || null,
    project_id: input.project_id || null,
    session_id: input.session_id || null,
    workspace_path: input.workspace_path || null,
    trigger: buildTriggerMetadata(input),
    time_window: {
      valid_from: input.valid_from || null,
      valid_until: input.valid_until || null,
      duration_ms: timeWindow.duration_ms,
    },
    continuity: {
      current_objective: input.current_objective || null,
      current_state: input.current_state || null,
      current_phase: input.current_phase || null,
      next_actions: asArray(input.next_actions),
    },
    evidence: {
      turns: asArray(input.turns),
      tool_events: asArray(input.tool_events),
      files: asArray(input.files),
      services: asArray(input.services),
      tests: asArray(input.tests),
    },
    source_memory_ids: input.source_memory_ids ?? [],
    decisions: asArray(input.decisions),
    open_questions: asArray(input.open_questions),
    confidence: {
      band: confidenceBand(input.confidence),
      raw: input.confidence,
    },
    evidence_refs: evidenceRefs,
    dream_readability: {
      markers: [
        'SESSION_DEBRIEF',
        'COMPACTION_FULL',
        'DECISIONS',
        'TOOL_EVENTS',
        'TESTS',
        'OPEN_QUESTIONS',
        'NEXT_ACTIONS',
      ],
      structured_reasoning_preserved: asArray(input.decisions).length > 0,
      tool_evidence_preserved: asArray(input.tool_events).length > 0,
    },
  };

  const recordHash = sha256Hex(stableJson(record));
  const key = [
    'compaction',
    safeKeyPart(input.project_id),
    safeKeyPart(input.session_id),
    compactIso(input.valid_from),
  ].join(':').slice(0, 255);
  const value = stableJson(record);
  const quality = buildQualityValidation(record, value);

  return {
    key,
    value,
    memory_type: 'session_debrief',
    metadata: {
      native_service: 'services/write/compaction-save.js',
      lane: 'compaction_full',
      compaction_record: record,
      content_hash: recordHash,
      timem: buildTiMemMetadata(input),
      chronos: buildChronosMetadata(input, evidenceRefs),
      rpe,
      freshness: {
        role: 'operational_state_metadata',
        initial_state: 'fresh',
        score: 1.0,
      },
      scale: buildScaleMetadata(input.memory_count),
      compression_policy: {
        intent_class: 'session_debrief',
        ratio: SESSION_DEBRIEF_COMPRESSION_RATIO,
        preserve_equations: true,
      },
      identity: buildIdentityMetadata(input, recordHash),
      app_trigger: record.trigger,
    },
    validation: {
      ok: missing.length === 0 && invalidArrays.length === 0 && timeWindow.valid && quality.ok,
      missing_fields: missing,
      invalid_array_fields: invalidArrays,
      time_window: timeWindow,
      quality_gate_compatibility: quality,
      corpus_authority: 'docs/compaction-post-compaction-corpus.md',
      native_service_claim: true,
    },
  };
}

export const __private__ = {
  stableJson,
  sha256Hex,
  euclideanDistance,
  computeRpe,
  estimateSubstanceScore,
};
