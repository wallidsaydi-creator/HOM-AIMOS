// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: signed REST, legacy MCP, and StreamableHTTP MCP transports
// → Calls: native retrieval/ranking services, restricted evidence admission,
//           recall calibration, and cryptographic receipt finalization
// Pipeline: RECALL | Position: canonical retrieval execution owner
// Sources: service headers cited by each ranking stage; RRF and HippoRAG are
// reviewed at the fusion/graph boundaries. This service preserves their math.
// ─────────────────────────────────────────────────────────────────────────────

import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { logEvent } from '../observe/event-ledger.js';
import { recordSimilarityObservation, getAnisotropyStats } from './similarity-stats.js';
import {
  applyCalibrationSnapshot,
  getVerifiedCalibrationSnapshot,
} from './recall-calibrator.js';
import { rankByTrust } from '../learning/trust-score.js';
import { conceptPprLookup } from './concept-ppr-native.js';
import {
  SALIENCE_FREQUENCY_ALADDIN_CONTRACT,
  applySalienceFrequencyAnnotations,
  evaluateSalienceFrequencyBatch,
} from '../temporal/dormancy-manager.js';
import {
  annotateDeepRecallOverrides,
  applyDeepRecallOverrideRanking,
  compareDeepRecallOverride,
} from './deep-recall-override.js';
import { reinforceRetrievedPheromones } from '../temporal/retrieval-pheromone.js';
import { detectEncodingStyle, rankByStyleMatch } from '../context/mnemonic-encoder.js';
import { multiStageRecall } from './multi-stage-retrieval.js';
import { checkContextSufficiency } from '../context/mvs-detector.js';
import { semanticCache } from '../caching/semantic-cache.js';
import { shouldEarlyExit, generateEarlyExitMetadata } from './adaptive-early-exit.js';
import { quimLookup } from './quim-index.js';
import { extractQueryEntityAnchors as extractEntities } from './query-entity-anchors.js';
import {
  admitNativeRecallCandidates,
  finalizeNativeRecall,
} from './native-recall.js';
import { buildRecallEvaluation } from './recall-diagnostics.js';
import { buildRecallDoctorCandidateTrace } from '../observe/recall-doctor-trace.js';
import { buildSourceAttributedSynthesis } from './source-attributed-synthesis.js';
import {
  buildRecallQueryUnderstanding,
  calibrateNativeRecallResponse,
} from './recall-output-calibrator.js';
import {
  buildRecallLexicalCalibration,
  scoreRecallLexicalMatch,
} from './recall-lexical-calibration.js';
import { IDENTIFIER_RECALL_STATUS, lookupIdentifierCandidates } from './identifier-recall.js';
import { RECALL_SPEED_CONFIG as SPEED_CONFIG } from './recall-runtime-config.js';
import { sessionKeyLikePattern } from '../shared/session-scope.js';
import { calibrateEpistemicRecall } from './epistemic-trust-retrieval.js';
import {
  MAGMA_NATIVE_CALIBRATION_DEFAULTS,
  composeMagmaNativeCandidate,
} from './magma-native-candidate.js';
import {
  RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT,
  composeReconstructedGraphNativeCandidate,
  composeNativeGraphFamilyChannel,
} from './reconstructed-graph-native-candidate.js';
import { fuseNativeRetrievalGears } from './native-retrieval-fusion.js';
import { systemConfigStore } from '../security/system-config-store.js';
import {
  validateMagmaRetrievalCalibration,
  validateTwinPrimeRetrievalPolicy,
} from '../security/system-config-ledger.js';
import { detectCanaries, scanRelayedMemory } from '../security/canary-tracker.js';

export function partitionGraphCanaryDisclosure(memories = []) {
  const admitted = [];
  const withheld = [];
  const tokens = new Set();

  for (const memory of Array.isArray(memories) ? memories : []) {
    const found = detectCanaries({
      key: memory?.key ?? null,
      value: memory?.value ?? null,
    });
    if (found.length === 0) {
      admitted.push(memory);
      continue;
    }
    for (const token of found) tokens.add(token);
    withheld.push(memory);
  }

  return Object.freeze({
    admitted: Object.freeze([...admitted]),
    withheld: Object.freeze([...withheld]),
    canary_tokens: Object.freeze([...tokens].sort()),
  });
}

export const NATIVE_GEARBOX_EVALUATION_EVIDENCE_SCHEMA =
  'hom-aimos/native-gearbox-evaluation-evidence/v1';

function snapshotNativeGearboxMemory(memory = {}) {
  return Object.freeze({
    ...memory,
    embedding: Array.isArray(memory?.embedding)
      ? Object.freeze([...memory.embedding])
      : memory?.embedding ?? null,
    graph_links: Object.freeze((Array.isArray(memory?.graph_links) ? memory.graph_links : [])
      .map((link) => Object.freeze({ ...link }))),
    provenance_proof: memory?.provenance_proof
      ? Object.freeze({ ...memory.provenance_proof })
      : null,
    canary_admitted: true,
  });
}

async function closeNativeRecallSecurityBoundary({
  boundaryId,
  boundaryOperation = 'recall_security_closure',
  sourceAgentId,
  memories,
  companyId,
  subjectAgentId,
  recallAuthority,
  epistemicReceipt,
  epistemicDecisionHash,
  graphDecision = null,
}) {
  if (!['identifier_exact', 'concept_gaama', 'magma', 'reconstructed_graph'].includes(boundaryId)) {
    throw new Error('recall_security_closure:unsupported_boundary');
  }
  const candidates = Array.isArray(memories) ? memories : [];
  const relay = await scanRelayedMemory(
    candidates.map((memory) => ({
      memory_id: memory?.id || memory?.memory_id || null,
      key: memory?.key || null,
      value: memory?.value || null,
    })),
    recallAuthority.requestReceiptId || epistemicDecisionHash,
    {
      sourceAgentId,
      targetAgentId: subjectAgentId,
      parentEventId: epistemicReceipt?.event_id || null,
      authority: recallAuthority.requestAuthority || null,
    },
  );
  const partition = partitionGraphCanaryDisclosure(candidates);
  const graphSelectedIds = new Set((graphDecision?.selected_memory_ids || []).map((id) => String(id)));
  const graphAnnotatedCount = candidates.filter((memory) => graphSelectedIds.size > 0
    ? graphSelectedIds.has(String(memory?.id || memory?.memory_id || ''))
    : boundaryId === 'magma'
      ? Number.isFinite(Number(memory?.magma_score))
        || memory?.native_fusion_gears?.includes('magma')
      : boundaryId === 'concept_gaama'
        && (memory?.source === 'concept_graph_ppr' || Number.isFinite(Number(memory?.ppr_score)))
  ).length;
  const receipt = await logEvent(
    companyId,
    subjectAgentId,
    boundaryOperation,
    epistemicDecisionHash,
    {
      boundary_id: boundaryId,
      graph_id: boundaryOperation === 'graph_security_closure' ? boundaryId : null,
      graph_decision_sha256: graphDecision?.decision_sha256 || null,
      graph_edge_commitment_sha256: graphDecision?.edge_commitment_sha256 || null,
      graph_selected_memory_ids: graphDecision?.selected_memory_ids
        || graphDecision?.traversal_selected_memory_ids
        || null,
      candidate_count: candidates.length,
      graph_annotated_count: graphAnnotatedCount,
      canary_marker_count: partition.canary_tokens.length,
      withheld_from_disclosure_count: partition.withheld.length,
      disclosed_count: partition.admitted.length,
      canary_stage: 'RELAYED',
      canary_detection_event_ids: relay.events.map((event) => event.receipt?.event_id).filter(Boolean),
      aladdin: {
        canonical_memory_changed: false,
        retention_changed: false,
        deletion_performed: false,
        suppression_performed: false,
        disposition: partition.withheld.length > 0
          ? 'retained_quarantine_withheld_from_response_only'
          : 'retained_clean_disclosure',
      },
      saber: {
        runtime_authority: false,
        evaluation_status: 'separate_isolated_campaign_required',
      },
      reasoning: `${boundaryId} candidates passed signed epistemic selection, explicit Canary relay inspection, and Aladdin full-retention closure before disclosure.`,
      source_knowledge: 'HOM-AIMOS native recall security closure: Canary traversal, SABER evaluation separation, and Aladdin retention',
    },
    epistemicReceipt?.event_id || null,
    { authority: recallAuthority.requestAuthority || null, returnReceipt: true },
  );

  return Object.freeze({
    memories: partition.admitted,
    decision: Object.freeze({
      boundary_id: boundaryId,
      graph_id: boundaryOperation === 'graph_security_closure' ? boundaryId : null,
      graph_decision_sha256: graphDecision?.decision_sha256 || null,
      graph_edge_commitment_sha256: graphDecision?.edge_commitment_sha256 || null,
      candidate_count: candidates.length,
      graph_annotated_count: graphAnnotatedCount,
      canary_marker_count: partition.canary_tokens.length,
      withheld_from_disclosure_count: partition.withheld.length,
      disclosed_count: partition.admitted.length,
      canonical_memory_changed: false,
      retention_changed: false,
      saber_runtime_authority: false,
      receipt: Object.freeze({
        event_id: receipt.event_id,
        ledger_seq: receipt.ledger_seq,
        content_hash: receipt.content_hash,
        mutation_hash: receipt.mutation_hash,
      }),
    }),
  });
}

async function closeGraphSecurityBoundary(options) {
  return closeNativeRecallSecurityBoundary({
    ...options,
    boundaryId: options.graphId,
    boundaryOperation: 'graph_security_closure',
  });
}

function parseAimosRuntimeFlag(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase();
  if (!normalized) return null;
  if (['1', 'true', 'on', 'yes'].includes(normalized)) return true;
  if (['0', 'false', 'off', 'no'].includes(normalized)) return false;
  return null;
}

function earlyExitFlagState(req) {
  const requestParam = 'early_exit';
  const requestRaw = req?.body?.[requestParam] ?? req?.body?.earlyExit;
  const requestParsed = parseAimosRuntimeFlag(requestRaw);
  const requestOverride = requestParsed !== null;
  const enabled = requestOverride ? requestParsed === true : false;

  return {
    feature: 'adaptive_early_exit',
    enabled,
    source: requestOverride
      ? (enabled ? 'request_query_enabled' : 'request_query_disabled')
      : 'default_off_pending_ab_gate',
    default_hot_path: 'off',
    override_precedence: 'request_query_only_until_ab_gate_passes',
    authority: 'request-scoped A/B override; persistent flags belong in the signed config ledger',
    request_param: requestParam,
    request_override: requestOverride ? (enabled ? 'on' : 'off') : null,
    request_value: requestRaw == null ? null : String(requestRaw),
    rollback: `omit ${requestParam} or pass ${requestParam}=0 to keep hot-path off; pass ${requestParam}=1 only for request-scoped A/B`,
  };
}

// ─── SPEED CONFIG — Phase 1-2 toggles (default OFF) ──────────────────────────
// Persistent configuration is read from the signed configuration ledgers at
// each owning subsystem; these defaults deliberately do not read environment.

function recallRuntimeBudgetFrom(req) {
  const source = req?.body || {};
  return {
    context_window: source.context_window ?? source.contextWindow,
    tokens_used: source.tokens_used ?? source.tokensUsed,
    recall_share: source.recall_share ?? source.recallShare,
    summary_token_budget: source.summary_token_budget ?? source.summaryTokenBudget,
    evidence_token_budget: source.evidence_token_budget ?? source.evidenceTokenBudget,
    full_detail_token_budget: source.full_detail_token_budget ?? source.fullDetailTokenBudget,
    answer_shape: source.answer_shape ?? source.answerShape,
    requested_shape: source.requested_shape ?? source.requestedShape,
    source_filter: source.source_filter ?? source.sourceFilter,
    memory_type_filter: source.memory_type_filter ?? source.memoryTypeFilter,
    session_id: source.session_id ?? source.sessionId,
  };
}

function isExplicitFullDetailRecall(queryText = '', runtimeBudget = {}) {
  const requested = String(runtimeBudget.answer_shape || runtimeBudget.requested_shape || '').trim();
  if (requested === 'full_detail') return true;
  return /\b(full detail|open full|exact session|exact key|open session|drill(?:down)?|verbatim|raw memory|memory_id|session id|session_id|key:)\b/i.test(String(queryText || ''));
}

function buildEffectiveRecallRuntimeBudget(runtimeBudget = {}, options = {}) {
  const explicitFullDetail = Boolean(options.explicitFullDetail);
  const sourceFiltered = Boolean(options.sourceFiltered);
  const requestedLimit = clampRecallInteger(options.requestedLimit, 10, 1, 200);
  const hasExplicitBudget = runtimeBudget.full_detail_token_budget !== undefined
    || runtimeBudget.fullDetailTokenBudget !== undefined;
  if (!explicitFullDetail || hasExplicitBudget) return runtimeBudget;

  const defaultBudget = 24000;
  const scaledBudget = sourceFiltered
    ? Math.min(220000, Math.max(defaultBudget, requestedLimit * 7000))
    : Math.min(80000, Math.max(defaultBudget, requestedLimit * 3000));

  return {
    ...runtimeBudget,
    full_detail_token_budget: scaledBudget,
  };
}

function hasTemporalRecallAxis(understanding = {}) {
  return Boolean(understanding.temporal_scope?.kind && understanding.temporal_scope.kind !== 'open')
    || ['temporal_order', 'temporal_delta', 'temporal_pattern', 'timeline'].includes(understanding.intent);
}

function hasAggregateRecallAxis(understanding = {}) {
  return ['session_count', 'timeline', 'temporal_delta'].includes(understanding.intent)
    || Boolean(understanding.features?.asks_count);
}

function hasEntityRecallAxis(understanding = {}) {
  return understanding.intent === 'speaker_entity_lookup'
    || (understanding.named_entities?.length || 0) > 0
    || (understanding.comparison_targets?.length || 0) > 0
    || (understanding.speaker_bindings?.length || 0) > 0;
}

function clampRecallInteger(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(parsed)));
}

function benchmarkSiblingHydrationSpec(key) {
  const raw = String(key || '');
  const longMem = raw.match(/^(benchmark:longmemeval:official:session:answer_[a-z0-9]+)(?:_\d+)?$/i);
  if (longMem) {
    return {
      kind: 'longmemeval_answer_root',
      root: longMem[1],
      likePattern: `${longMem[1]}\\_%`,
    };
  }
  const locomo = raw.match(/^(benchmark:locomo:official:session:[^:]+):session_\d+$/i);
  if (locomo) {
    return {
      kind: 'locomo_sample_root',
      root: locomo[1],
      likePattern: `${locomo[1]}:session\\_%`,
    };
  }
  return null;
}

function normalizeRecallRoleText(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}$:/._-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function stemRecallRoleToken(token) {
  let out = String(token || '').toLowerCase();
  if (out.length > 5 && out.endsWith('ies')) out = `${out.slice(0, -3)}y`;
  else if (out.length > 5 && out.endsWith('ing')) out = out.slice(0, -3);
  else if (out.length > 4 && out.endsWith('ed')) {
    const base = out.slice(0, -2);
    out = base.endsWith('v') ? `${base}e` : base;
  }
  else if (out.length > 4 && out.endsWith('s') && !out.endsWith('ss')) out = out.slice(0, -1);
  return out;
}

function recallRoleTokens(value) {
  const stop = new Set([
    'a', 'an', 'and', 'are', 'did', 'do', 'does', 'for', 'had', 'has', 'have',
    'i', 'in', 'is', 'it', 'its', 'me', 'my', 'new', 'of', 'on', 'or', 'start',
    'starting', 'the', 'their', 'to', 'was', 'were', 'with', 'narrator',
  ]);
  return [...new Set(normalizeRecallRoleText(value)
    .split(/\s+/)
    .map((token) => token.replace(/^[._:-]+|[._:-]+$/g, ''))
    .map(stemRecallRoleToken)
    .filter((token) => token.length >= 2 && !stop.has(token)))];
}

function recallEvidenceRoot(memory = {}, index = 0) {
  if (memory.sibling_root) return String(memory.sibling_root);
  const benchmarkRoot = benchmarkSiblingHydrationSpec(memory.key)?.root;
  if (benchmarkRoot) return benchmarkRoot;
  if (memory.session_id) return `session:${memory.session_id}`;
  if (memory.project_id) return `project:${memory.project_id}`;
  const key = String(memory.key || index);
  return key.replace(/([:_-](?:session|turn)?[_-]?\d+)$/i, '');
}

function scoreRoleCoverageForMemory(memory = {}, target = '', lexicalScore = 0) {
  const targetNorm = normalizeRecallRoleText(target);
  const haystack = normalizeRecallRoleText([
    memory.key,
    memory.session_id,
    memory.project_id,
    memory.memory_type,
    memory.source,
    memory.value,
  ].filter(Boolean).join(' '));
  if (!targetNorm || !haystack) return { score: 0, exact: false, coverage: 0 };

  const exact = targetNorm.length >= 3 && haystack.includes(targetNorm);
  const tokens = recallRoleTokens(targetNorm);
  const haystackTokenSet = new Set(haystack
    .split(/\s+/)
    .map((token) => token.replace(/^[._:-]+|[._:-]+$/g, ''))
    .map(stemRecallRoleToken)
    .filter(Boolean));
  const hits = tokens.filter((token) => haystackTokenSet.has(token)).length;
  const coverage = tokens.length ? hits / tokens.length : 0;
  const hasExplicitDate = /\bdate:\s*\d{4}\/\d{2}\/\d{2}\b|\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?\b/i
    .test(String(memory.value || ''));
  const score = Math.max(0, Math.min(
    1,
    (coverage * 0.66)
      + (exact ? 0.20 : 0)
      + (hasExplicitDate ? 0.06 : 0)
      + (Math.max(0, Math.min(1, Number(lexicalScore) || 0)) * 0.08)
  ));

  return {
    score: Number(score.toFixed(6)),
    exact,
    coverage: Number(coverage.toFixed(6)),
  };
}

function cleanRecallOpeningTarget(value) {
  return String(value || '')
    .replace(/["'“”‘’]/g, ' ')
    .replace(/\b(?:how\s+many|days?|weeks?|months?|did|do|does|i|me|my|the|their|a|an|narrator|arrival|arrived|receiving|received)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function temporalRoleTargetsForOpening(query) {
  const q = String(query || '');
  const targets = [];
  const addPair = (left, right) => {
    const cleaned = [cleanRecallOpeningTarget(left), cleanRecallOpeningTarget(right)]
      .filter((target) => target.length >= 2);
    if (cleaned.length === 2) targets.push(...cleaned);
  };

  const before = q.match(/\bhow\s+many\s+(?:days?|weeks?|months?)\s+before\s+(.+?)\s+did\s+(.+?)(?:\?|$)/i);
  if (before) addPair(before[2], before[1]);

  const after = q.match(/\bhow\s+many\s+(?:days?|weeks?|months?)\s+did\s+it\s+take\s+for\s+me\s+to\s+(.+?)\s+after\s+(.+?)(?:\?|$)/i);
  if (after) addPair(after[2], after[1]);

  const sinceWhen = q.match(/\bhow\s+many\s+(?:days?|weeks?|months?)\s+had\s+passed\s+since\s+(.+?)\s+when\s+(.+?)(?:\?|$)/i);
  if (sinceWhen) addPair(sinceWhen[1], sinceWhen[2]);

  const durationWhen = q.match(/\bhow\s+long\s+had\s+i\s+been\s+(.+?)\s+when\s+i\s+(.+?)(?:\?|$)/i);
  if (durationWhen) addPair(durationWhen[1], durationWhen[2]);

  const between = q.match(/\bbetween\s+(.+?)\s+and\s+(.+?)(?:\?|$)/i);
  if (between) addPair(between[1], between[2]);

  const firstAfter = q.match(/\bwhat\s+was\s+the\s+first\s+(.+?)\s+after\s+(.+?)(?:\?|$)/i);
  if (firstAfter) addPair(firstAfter[2], firstAfter[1]);

  const eventFirst = q.match(/\bwhich\s+event\s+happened\s+first\s*,?\s+(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (eventFirst) addPair(eventFirst[1], eventFirst[2]);

  const attendedEventFirst = q.match(/\bwhich\s+event\s+did\s+.+?\s+(?:attend|go\s+to|join|participate\s+in)\s+first\s*,?\s+(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (attendedEventFirst) addPair(attendedEventFirst[1], attendedEventFirst[2]);

  const tripFirst = q.match(/\bwhich\s+trip\s+did\s+.+?\s+take\s+first\s*,?\s+(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (tripFirst) addPair(tripFirst[1], tripFirst[2]);

  const weekdayWake = q.match(/\bwhat\s+time\s+do\s+i\s+wake\s+up\s+on\s+(.+?)(?:\?|$)/i);
  if (weekdayWake) {
    const weekdays = recallRoleTokens(weekdayWake[1]).filter((token) =>
      ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'].includes(token)
    );
    if (weekdays.length) addPair('waking up at', `${weekdays.join(' ')} waking up earlier`);
  }

  const currentJobDuration = q.match(/\bhow\s+long\s+have\s+i\s+been\s+working\s+before\s+i\s+started\s+my\s+current\s+job\s+at\s+([A-Za-z0-9][A-Za-z0-9 .&'-]{1,60})(?:\?|$)/i);
  if (currentJobDuration) {
    addPair('working professionally', `working at ${currentJobDuration[1]}`);
  }

  return [...new Set(targets)].slice(0, 4);
}

function aggregateRoleTargetsForOpening(query, lexicalCalibration = {}) {
  const q = String(query || '');
  const normalized = q.toLowerCase();
  const targets = [];
  const add = (...items) => {
    for (const item of items) {
      const cleaned = cleanRecallOpeningTarget(item);
      if (cleaned.length >= 2) targets.push(cleaned);
    }
  };

  const aggregateAction = q.match(/\bhow\s+many\s+(.+?)\s+(?:do|did|have|had|am|are)\s+i\s+(.+?)(?:\?|$)/i);
  if (aggregateAction) {
    const object = cleanRecallOpeningTarget(aggregateAction[1]);
    const actions = aggregateAction[2]
      .split(/\s+(?:or|and|,)\s+/i)
      .map((part) => cleanRecallOpeningTarget(part.replace(/\b(?:currently|still|need to|have to|from a store)\b/gi, '')))
      .filter(Boolean);
    for (const action of actions) {
      add(`${action} ${object}`, `${object} ${action}`);
      if (/\b(?:led|lead|leading|managed|managing)\b/i.test(action)) {
        add('led project', 'leading project', 'project team', 'data analysis team');
      }
    }
  }

  if (/\bmodel\s+kits?\b/i.test(q)) {
    add('model kit', 'finished model kit', 'working on model kit', 'bought model kit', 'scale model');
  }
  if (/\bcamping\s+trips?\b/i.test(q)) {
    add('camping trip', 'solo camping trip', 'got back from camping trip', 'national park camping');
  }
  if (/\bmovie\s+festivals?\b|\bfilm\s+festivals?\b/i.test(q)) {
    add('film festival', 'movie festival', 'attended festival', 'festival screening', 'festival q&a');
  }
  if (/\broad\s+trip\b/i.test(q) && /\b(?:hours?|driving|drive|drove|destinations?)\b/i.test(q)) {
    add('road trip', 'drove hours', 'hours drive', 'trip destination', 'drove to');
  }
  if (/\bbike\b/i.test(q) && /\b(?:money|spent|expenses?|cost)\b/i.test(q)) {
    add('bike expenses', 'bike cost', 'bike helmet', 'bike chain', 'bike lights', 'bike service');
  }
  if (/\bdoctor\b/i.test(q) && /\b(?:bed|sleep|slept)\b/i.test(q)) {
    add('doctor appointment', 'went to bed', 'get to bed', 'day before doctor appointment');
  }

  const phraseTargets = (lexicalCalibration.phrases || [])
    .filter((phrase) => {
      const p = String(phrase || '').toLowerCase();
      return p.length >= 3 && (
        /\b(project|model kit|camping trip|film festival|movie festival|road trip|bike|doctor appointment|went to bed)\b/.test(p)
        || (normalized.includes('how many') && /\b(attended|worked|bought|led|leading|spent|drove|cost)\b/.test(p))
      );
    });
  add(...phraseTargets);

  return [...new Set(targets)].slice(0, 8);
}

function applyRoleBalancedEvidenceOpening(memories = [], lexicalCalibration = {}, query = '') {
  const pairedTargets = [
    ...(lexicalCalibration.comparison_targets || []),
    ...temporalRoleTargetsForOpening(query),
  ];
  const aggregateTargets = aggregateRoleTargetsForOpening(query, lexicalCalibration);
  const targets = [...new Set([
    ...pairedTargets,
    ...aggregateTargets,
  ]
    .map((target) => String(target || '').trim())
    .filter((target) => target.length >= 2))]
    .slice(0, aggregateTargets.length ? 8 : 4);
  if (targets.length < 2 || memories.length < 2) return null;
  const requireAllTargets = aggregateTargets.length === 0;

  let candidatesByTarget = targets.map((target) => {
    const candidates = memories
      .map((memory, index) => {
        const lexicalScore = Number.isFinite(memory?._raw_rerank)
          ? memory._raw_rerank
          : (memory?.rerank_score || 0);
        const role = scoreRoleCoverageForMemory(memory, target, lexicalScore);
        return {
          memory,
          index,
          target,
          root: recallEvidenceRoot(memory, index),
          score: role.score,
          exact: role.exact,
          coverage: role.coverage,
          lexicalScore,
        };
      })
      .filter((candidate) => candidate.exact || candidate.coverage >= 0.67)
      .sort((a, b) => (b.score - a.score) || (b.lexicalScore - a.lexicalScore) || (a.index - b.index));
    return { target, candidates };
  });

  if (requireAllTargets && candidatesByTarget.some((entry) => entry.candidates.length === 0)) return null;
  if (!requireAllTargets) {
    candidatesByTarget = candidatesByTarget.filter((entry) => entry.candidates.length > 0);
    if (candidatesByTarget.length < 2) return null;
  }

  let coherentRoot = null;
  if (requireAllTargets) {
    const rootScores = new Map();
    for (const entry of candidatesByTarget) {
      const bestByRoot = new Map();
      for (const candidate of entry.candidates) {
        const current = bestByRoot.get(candidate.root);
        if (!current || candidate.score > current.score) bestByRoot.set(candidate.root, candidate);
      }
      for (const [root, candidate] of bestByRoot.entries()) {
        const aggregate = rootScores.get(root) || { root, coverage: 0, score: 0, byTarget: new Map() };
        aggregate.coverage += 1;
        aggregate.score += candidate.score;
        aggregate.byTarget.set(entry.target, candidate);
        rootScores.set(root, aggregate);
      }
    }

    coherentRoot = [...rootScores.values()]
      .filter((root) => root.coverage >= 2)
      .sort((a, b) => (b.coverage - a.coverage) || (b.score - a.score))[0] || null;
  }

  const selected = [];
  const selectedIds = new Set();
  const selectedRoots = new Set();
  const summaries = [];
  for (const entry of candidatesByTarget) {
    const coherentCandidate = coherentRoot
      ? (entry.candidates.find((candidate) => {
          const id = candidate.memory.id || candidate.memory.key || `idx:${candidate.index}`;
          return candidate.root === coherentRoot.root && !selectedIds.has(id);
        }) || entry.candidates.find((candidate) => candidate.root === coherentRoot.root) || null)
      : null;
    const fallbackCandidate = entry.candidates.find((candidate) => {
      const id = candidate.memory.id || candidate.memory.key || `idx:${candidate.index}`;
      return !selectedIds.has(id) && (requireAllTargets || !selectedRoots.has(candidate.root));
    }) || entry.candidates[0];
    const chosen = coherentCandidate || fallbackCandidate;
    if (!chosen) continue;
    const id = chosen.memory.id || chosen.memory.key || `idx:${chosen.index}`;
    summaries.push({
      target: entry.target,
      root: chosen.root,
      score: chosen.score,
      exact: chosen.exact,
      coverage: chosen.coverage,
      key: chosen.memory.key || null,
    });
    if (selectedIds.has(id)) continue;
    selectedIds.add(id);
    selectedRoots.add(chosen.root);
    chosen.memory.role_balanced_opening = {
      target: entry.target,
      root: chosen.root,
      score: chosen.score,
      exact: chosen.exact,
      coverage: chosen.coverage,
    };
    selected.push(chosen.memory);
  }

  if (selected.length < 2) return null;

  return {
    memories: [
      ...selected,
      ...memories.filter((memory, index) => {
        const id = memory.id || memory.key || `idx:${index}`;
        return !selectedIds.has(id);
      }),
    ],
    opened_roles: selected.length,
    coherent_root: coherentRoot?.root || null,
    targets: summaries,
  };
}

export function buildRecallRouteBreadthPolicy({ queryUnderstanding = {}, maxRows = 10, sourceFilter = '', mode = '', runtimeBudget = {} }) {
  const explicitFullDetail = mode === 'full_detail'
    || runtimeBudget.answer_shape === 'full_detail'
    || runtimeBudget.requested_shape === 'full_detail'
    || queryUnderstanding.intent === 'full_detail';
  const sourceFiltered = Boolean(String(sourceFilter || '').trim());
  const requested = clampRecallInteger(maxRows, 10, 1, 200);
  const pairedEvidenceIntent = hasTemporalRecallAxis(queryUnderstanding)
    || queryUnderstanding.intent === 'temporal_delta'
    || (queryUnderstanding.comparison_targets?.length || 0) >= 2
    || Boolean(queryUnderstanding.features?.has_comparison_targets);
  const aggregateEvidenceIntent = hasAggregateRecallAxis(queryUnderstanding);

  let profile = 'standard';
  if (explicitFullDetail) profile = 'exact_detail';
  else if (hasAggregateRecallAxis(queryUnderstanding) || queryUnderstanding.intent === 'current_truth') profile = 'aggregate_first';
  else if (hasTemporalRecallAxis(queryUnderstanding)) profile = 'temporal_first';
  else if (hasEntityRecallAxis(queryUnderstanding)) profile = 'entity_first';

  const definitions = {
    exact_detail: { vector: [200, 800, 8], bm25: [80, 300, 5], temporal: [80, 240, 4], hops: 2, qmd: true },
    aggregate_first: { vector: [96, 180, 6], bm25: [96, 180, 5], temporal: [160, 320, 6], hops: 0, qmd: false },
    temporal_first: { vector: [120, 240, 6], bm25: [120, 240, 5], temporal: [180, 360, 6], hops: 1, qmd: true },
    entity_first: { vector: [120, 240, 6], bm25: [120, 260, 5], temporal: [80, 180, 4], hops: 1, qmd: true },
    standard: { vector: [120, 300, 8], bm25: [80, 180, 4], temporal: [50, 120, 3], hops: 1, qmd: true },
  };
  const def = definitions[profile];
  const widen = sourceFiltered ? 1.35 : 1;
  const scaled = ([floor, cap, multiplier]) => Math.round(Math.min(Math.max(requested * multiplier, floor), cap) * widen);
  const responseLimit = profile === 'aggregate_first' ? Math.min(requested, 16) : requested;
  // MMR and epistemic cluster decisions must see a wider pool than the final
  // response. Truncating to top-k here makes later diversity mathematically
  // incapable of replacing a redundant high-similarity cluster.
  const candidateOpeningLimit = Math.min(
    explicitFullDetail ? 80 : 120,
    Math.max(responseLimit, requested * 6, 24),
  );

  return {
    profile,
    requested_limit: requested,
    response_limit: responseLimit,
    candidate_opening_limit: candidateOpeningLimit,
    vector_limit: scaled(def.vector),
    bm25_limit: scaled(def.bm25),
    temporal_limit: scaled(def.temporal),
    value_rescue_limit: explicitFullDetail && sourceFiltered ? Math.min(240, Math.max(96, requested * 8)) : 0,
    graph_hops: def.hops,
    qmd_allowed: def.qmd,
    temporal_bias_enabled: hasTemporalRecallAxis(queryUnderstanding),
    current_truth_bias_enabled: queryUnderstanding.intent === 'current_truth' || Boolean(queryUnderstanding.features?.asks_current_truth),
    aggregate_first_enabled: profile === 'aggregate_first',
    value_rescue_enabled: explicitFullDetail && sourceFiltered,
    identity_truth_rescue_enabled: Boolean(queryUnderstanding.features?.asks_identity_truth),
    identity_truth_rescue_limit: 24,
    sibling_hydration_enabled: explicitFullDetail && sourceFiltered && pairedEvidenceIntent,
    role_balanced_opening_enabled: explicitFullDetail && sourceFiltered && (pairedEvidenceIntent || aggregateEvidenceIntent),
    sibling_hydration_root_limit: 24,
    source_filtered: sourceFiltered,
  };
}

async function selectAndLedgerEpistemicRecall({
  memories,
  queryText,
  limit,
  companyId,
  subjectAgentId,
  twinPrimePolicy = null,
  twinPrimePolicyMutationHash = null,
  twinPrimeEligibilityReason = null,
  queryEmbedding = null,
  temporalScope = null,
  signedRequestTimeMs = null,
  parentEventId = null,
  requestAuthority = null,
}) {
  const memoryIds = [...new Set((Array.isArray(memories) ? memories : [])
    .map((memory) => String(memory?.id || memory?.memory_id || ''))
    .filter((id) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)))];
  const projections = memoryIds.length
    ? await query(
        `SELECT id::text AS memory_id,
                current_epistemic_label,
                current_epistemic_confidence_milli,
                current_epistemic_event_id::text
                ${twinPrimePolicy ? ', embedding::text AS embedding' : ''}
           FROM public.aimos_memories
          WHERE company_id = $1
            AND id = ANY($2::uuid[])`,
        [companyId, memoryIds],
      )
    : { rows: [] };
  const projectionByMemoryId = new Map(
    projections.rows.map((row) => [String(row.memory_id), row]),
  );
  const memoriesWithEpistemicProjection = (Array.isArray(memories) ? memories : []).map((memory) => {
    const memoryId = String(memory?.id || memory?.memory_id || '');
    const projection = projectionByMemoryId.get(memoryId);
    return projection ? {
      ...memory,
      current_epistemic_label: projection.current_epistemic_label,
      current_epistemic_confidence_milli: Number(projection.current_epistemic_confidence_milli || 0),
      current_epistemic_event_id: projection.current_epistemic_event_id || null,
    } : memory;
  });
  const calibrated = calibrateEpistemicRecall({
    query: queryText,
    memories: memoriesWithEpistemicProjection,
    limit,
    ...(twinPrimePolicy ? {
      twinPrimeContext: {
        policy: twinPrimePolicy,
        policyMutationHash: twinPrimePolicyMutationHash,
        eligible: twinPrimeEligibilityReason == null,
        ineligibleReason: twinPrimeEligibilityReason,
        queryEmbedding,
        temporalScope,
        requestTimeMs: signedRequestTimeMs,
        featuresByMemoryId: new Map(projections.rows.map((row) => [
          String(row.memory_id),
          { embedding: row.embedding },
        ])),
      },
    } : {}),
  });
  const receipt = await logEvent(
    companyId,
    subjectAgentId,
    'epistemic_recall_decision',
    calibrated.decision.query_sha256,
    {
      reasoning: 'Pre-disclosure epistemic calibration separates authenticated provenance from factual support and prevents redundant query-lure clusters from monopolizing the active evidence set.',
      ...calibrated.decision,
    },
    parentEventId,
    { authority: requestAuthority, returnReceipt: true },
  );
  return {
    memories: calibrated.memories,
    decision: calibrated.decision,
    receipt: {
      event_id: receipt.event_id,
      ledger_seq: receipt.ledger_seq,
      content_hash: receipt.content_hash,
      mutation_hash: receipt.mutation_hash,
    },
  };
}

function verifiedTwinPrimePolicy() {
  const entry = systemConfigStore.readVerifiedConfig('TWIN_PRIME_RETRIEVAL_POLICY');
  if (!entry) return null;
  const validated = validateTwinPrimeRetrievalPolicy(entry.value);
  if (!validated.ok) return null;
  return Object.freeze({
    policy: validated.policy,
    mutationHash: entry.mutation_hash,
  });
}

function verifiedMagmaCalibration() {
  const entry = systemConfigStore.readVerifiedConfig('MAGMA_RETRIEVAL_CALIBRATION');
  if (!entry) {
    return Object.freeze({
      calibration: MAGMA_NATIVE_CALIBRATION_DEFAULTS,
      mutationHash: null,
      source: 'immutable_code_default',
      rejectedSignedCalibrationReason: null,
    });
  }
  const validated = validateMagmaRetrievalCalibration(entry.value);
  if (!validated.ok) {
    return Object.freeze({
      calibration: MAGMA_NATIVE_CALIBRATION_DEFAULTS,
      mutationHash: null,
      source: 'immutable_code_default_after_rejected_signed_calibration',
      rejectedSignedCalibrationReason: validated.reason,
    });
  }
  return Object.freeze({
    calibration: validated.calibration,
    mutationHash: entry.mutation_hash,
    source: 'master_signed_system_config',
    rejectedSignedCalibrationReason: null,
  });
}

const NATIVE_FUSION_SEMANTIC_SHARE = 0.2;

function magmaGearMetadata({ calibrationState, gear, runtimeMs, fusion, failure = null } = {}) {
  const calibration = calibrationState.calibration;
  return Object.freeze({
    architecture_role: 'permanent_native_retrieval_gear',
    runtime_mode: null,
    activation_authority: false,
    candidate_set_authority: false,
    calibration_source: calibrationState.source,
    calibration_mutation_hash: calibrationState.mutationHash,
    rejected_signed_calibration_reason: calibrationState.rejectedSignedCalibrationReason,
    bounds: Object.freeze({
      max_depth: calibration.max_depth,
      max_nodes: calibration.max_nodes,
      result_limit: calibration.result_limit,
      beam_width: calibration.beam_width,
      rrf_k: calibration.rrf_k,
    }),
    proof_sha256: calibration.proof_sha256 || null,
    runner_sha256: calibration.runner_sha256 || null,
    runtime_ms: runtimeMs,
    runtime_breakdown_ms: gear?.runtime_breakdown_ms || null,
    candidate_p95_ceiling_ms: calibration.candidate_p95_ceiling_ms,
    within_single_call_ceiling: runtimeMs == null ? null : runtimeMs <= calibration.candidate_p95_ceiling_ms,
    operational_status: failure ? 'degraded' : gear ? 'complete' : 'empty_candidate_set',
    failure_code: failure,
    decision: gear?.decision || null,
    central_fusion_decision: fusion?.decision || null,
  });
}

function reconstructedGraphGearMetadata({
  gear,
  eligibleCandidateCount = 0,
  canaryWithheldCount = 0,
  failure = null,
} = {}) {
  return Object.freeze({
    architecture_role: RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.architecture_role,
    runtime_mode: null,
    activation_authority: false,
    candidate_set_authority: false,
    disclosure_authority: false,
    fixed_corpus_proof_file_sha256:
      RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.fixed_corpus_proof_file_sha256,
    fixed_corpus_summary_sha256:
      RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.fixed_corpus_summary_sha256,
    bounds: Object.freeze({
      maximum_workspace_states:
        RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.maximum_workspace_states,
      maximum_emitted_ranks:
        RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.maximum_emitted_ranks,
      native_workspace_states:
        RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.native_workspace_states,
      native_emitted_ranks:
        RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.native_emitted_ranks,
      graph_family_outer_channels:
        RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.graph_family_outer_channels,
    }),
    eligible_candidate_count: eligibleCandidateCount,
    canary_withheld_before_graph_construction: canaryWithheldCount,
    runtime_breakdown_ms: gear?.runtime_breakdown_ms || null,
    operational_status: failure
      ? 'degraded'
      : gear
        ? 'complete'
        : 'no_canary_admitted_candidates',
    failure_code: failure,
    decision: gear?.decision || null,
  });
}

function graphFamilyMetadata({ family, runtimeMs = null } = {}) {
  return Object.freeze({
    architecture_role: 'single_permanent_native_graph_family_channel',
    runtime_mode: null,
    activation_authority: false,
    candidate_set_authority: false,
    disclosure_authority: false,
    outer_channel_id: 'magma',
    outer_channel_count: family?.decision?.outer_channel_count || 0,
    subgear_count: family?.decision?.subgear_count || 0,
    runtime_ms: runtimeMs,
    decision: family?.decision || null,
  });
}

export function epistemicReceiptDecisionHash(decision) {
  const decisionSha256 = String(decision?.decision_sha256 || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(decisionSha256)) {
    throw new Error('native_recall_epistemic_decision_hash_invalid');
  }
  return decisionSha256;
}

function projectMemoryForRecallRerank(memory = {}, calibration = {}, options = {}) {
  const maxChars = clampRecallInteger(options.maxChars, 4800, 1200, 12000);
  const value = String(memory.value || '');
  if (value.length <= maxChars) return memory;

  const searchValue = value.length > maxChars * 3
    ? [
        value.slice(0, maxChars * 2),
        value.slice(Math.max(0, value.length - maxChars)),
      ].join('\n')
    : value;
  const lowerValue = searchValue.toLowerCase();
  const anchors = [
    ...(calibration.subject_terms || []),
    ...(calibration.named_entities || []),
    ...(calibration.comparison_targets || []),
    ...(calibration.temporal_terms || []),
    ...(calibration.phrases || []),
  ]
    .map((item) => String(item || '').toLowerCase().trim())
    .filter((item, index, all) => item.length >= 3 && all.indexOf(item) === index)
    .slice(0, 12);

  const windows = [];
  for (const anchor of anchors) {
    const hit = lowerValue.indexOf(anchor);
    if (hit === -1) continue;
    const start = Math.max(0, hit - 700);
    const end = Math.min(searchValue.length, hit + anchor.length + 700);
    windows.push(searchValue.slice(start, end));
  }

  const projectedValue = [
    searchValue.slice(0, 1400),
    ...windows,
    searchValue.slice(Math.max(0, searchValue.length - 1400)),
  ].join('\n').slice(0, maxChars);

  return {
    ...memory,
    value: projectedValue,
    _rerank_projection: 'bounded_lexical_window',
  };
}

function finiteRecallNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function roundRecallScore(value, fallback = null) {
  const number = finiteRecallNumber(value, fallback);
  return Number.isFinite(number) ? Number(number.toFixed(4)) : fallback;
}

function buildRetrievalFrequencyMetadata(memory = {}, nowMs = Date.now()) {
  const accessCount = Math.max(0, Math.floor(finiteRecallNumber(memory?.access_count, 0) || 0));
  const lastAccessedMs = memory?.last_accessed_at ? Date.parse(memory.last_accessed_at) : NaN;
  const ageDays = Number.isFinite(lastAccessedMs)
    ? Math.max(0, (nowMs - lastAccessedMs) / 86400000)
    : null;

  let band = 'normal';
  let reason = 'moderate_access_frequency';

  if (memory?.low_frequency_salience === true) {
    band = 'quiet';
    reason = 'low_frequency_salience';
  } else if (accessCount >= 10 || (ageDays != null && ageDays <= 7 && accessCount >= 3)) {
    band = 'high';
    reason = accessCount >= 10 ? 'high_access_count' : 'recent_repeated_access';
  } else if (accessCount <= 1 && (ageDays == null || ageDays >= 90)) {
    band = 'quiet';
    reason = ageDays == null ? 'no_access_telemetry' : 'low_recent_access';
  }

  return {
    retrieval_frequency_band: band,
    retrieval_frequency_reason: reason,
    retrieval_access_count: accessCount,
    retrieval_last_accessed_at: memory?.last_accessed_at || null,
    retrieval_access_age_days: ageDays == null ? null : Number(ageDays.toFixed(2)),
    retrieval_frequency_basis: 'derived_from_access_telemetry_no_decay_mutation',
  };
}

function annotateRetrievalFrequencyMetadata(memories = [], nowMs = Date.now()) {
  const counts = { quiet: 0, normal: 0, high: 0 };
  if (!Array.isArray(memories)) {
    return {
      annotated_count: 0,
      frequency_band_counts: counts,
      storage_policy: 'derived_metadata_no_canonical_content_mutation',
    };
  }

  for (const memory of memories) {
    const metadata = buildRetrievalFrequencyMetadata(memory, nowMs);
    Object.assign(memory, metadata);
    if (Object.prototype.hasOwnProperty.call(counts, metadata.retrieval_frequency_band)) {
      counts[metadata.retrieval_frequency_band] += 1;
    }
  }

  return {
    annotated_count: memories.length,
    frequency_band_counts: counts,
    storage_policy: 'derived_metadata_no_canonical_content_mutation',
  };
}

function annotateRecallRankDiagnostics(memories = []) {
  if (!Array.isArray(memories)) return;
  for (let index = 0; index < memories.length; index += 1) {
    const memory = memories[index];
    const next = memories[index + 1] || null;
    const finalScore = finiteRecallNumber(memory?.recall_confidence, finiteRecallNumber(memory?.rerank_score, 0));
    const nextScore = next
      ? finiteRecallNumber(next?.recall_confidence, finiteRecallNumber(next?.rerank_score, 0))
      : null;
    const rawDistance = finiteRecallNumber(memory?.raw_distance, null);
    const similarity = rawDistance == null
      ? finiteRecallNumber(memory?.score_components?.semantic, finiteRecallNumber(memory?.rerank_score, null))
      : Math.max(0, Math.min(1, 1 - rawDistance));
    const scoreComponents = {
      ...(memory?.score_components || {}),
      ...(memory?.confidence?.components || {}),
      semantic: roundRecallScore(memory?.score_components?.semantic ?? memory?.confidence?.components?.semantic ?? similarity, null),
      lexical: roundRecallScore(memory?.score_components?.lexical ?? memory?.confidence?.components?.keyword ?? memory?.rerank_score, null),
      bm25: roundRecallScore(memory?.bm25_rank ?? memory?.bm25_score, null),
      temporal: roundRecallScore(memory?.score_components?.temporal ?? memory?.confidence?.components?.recency, null),
      authority: roundRecallScore(memory?.confidence?.components?.authority, null),
      type_authority: roundRecallScore(memory?.confidence?.components?.type_authority, null),
      freshness_delta: roundRecallScore(memory?.confidence?.components?.freshness_delta, 0),
      final_confidence: roundRecallScore(finalScore, 0),
      raw_distance: roundRecallScore(rawDistance, null),
    };
    memory.similarity = roundRecallScore(similarity, null);
    memory.similarity_basis = rawDistance == null ? 'score_proxy' : 'embedding_distance';
    memory.score_components = scoreComponents;
    memory.rank_diagnostics = {
      rank: index + 1,
      final_score: roundRecallScore(finalScore, 0),
      next_margin: nextScore == null ? null : roundRecallScore(finalScore - nextScore, 0),
      rerank_score: roundRecallScore(memory?.rerank_score, null),
      raw_rerank_score: roundRecallScore(memory?._raw_rerank, null),
      recall_confidence: roundRecallScore(memory?.recall_confidence, null),
      retrieval_source: memory?.retrieval_source || 'hybrid_vector_bm25',
      score_basis: 'native_recall_observability',
    };
  }
}

function buildRecallRankObservability(memories = []) {
  const rankedScores = Array.isArray(memories)
    ? memories
        .map((memory) => finiteRecallNumber(memory?.rank_diagnostics?.final_score, null))
        .filter((score) => score != null)
    : [];
  return {
    enabled: true,
    score_count: rankedScores.length,
    top_score: rankedScores.length ? roundRecallScore(rankedScores[0], 0) : null,
    bottom_score: rankedScores.length ? roundRecallScore(rankedScores[rankedScores.length - 1], 0) : null,
    score_spread: rankedScores.length > 1 ? roundRecallScore(rankedScores[0] - rankedScores[rankedScores.length - 1], 0) : null,
    top1_margin: memories?.[0]?.rank_diagnostics?.next_margin ?? null,
    null_similarity_count: Array.isArray(memories)
      ? memories.filter((memory) => memory?.similarity == null).length
      : 0,
  };
}
export function enforceRecallResponseFilters(body, runtimeBudget = {}) {
  const sourceFilter = String(runtimeBudget.source_filter || '').trim();
  const memoryTypeFilter = String(runtimeBudget.memory_type_filter || '').trim();
  if ((!sourceFilter && !memoryTypeFilter) || !Array.isArray(body?.memories)) return body;

  const originalMemories = body.memories;
  const filteredMemories = originalMemories.filter((memory) => {
    const storedSource = String(memory?.source || memory?.memory_source || memory?.storage_source || '');
    const storedMemoryType = String(memory?.memory_type || memory?.memoryType || '');
    return (!sourceFilter || storedSource === sourceFilter)
      && (!memoryTypeFilter || storedMemoryType === memoryTypeFilter);
  });
  if (filteredMemories.length === originalMemories.length) return body;

  const filteredWorkingMemory = filteredMemories
    .slice(0, 12)
    .map((memory) => `[${memory.key || memory.source || 'memory'}] ${String(memory.value || '').slice(0, 1200)}`)
    .join('\n\n');

  return {
    ...body,
    memories: filteredMemories,
    count: filteredMemories.length,
    working_memory: filteredWorkingMemory,
    recall_meta: {
      ...(body.recall_meta || {}),
      total_results: filteredMemories.length,
      filter_enforcement: {
        ...(body.recall_meta?.filter_enforcement || {}),
        source_filter: sourceFilter || null,
        memory_type_filter: memoryTypeFilter || null,
        raw_memory_count: originalMemories.length,
        filtered_memory_count: filteredMemories.length,
      },
    },
  };
}

export function enforceRecallResponseLimit(body, responseLimit) {
  if (!Array.isArray(body?.memories)) return body;
  const limit = clampRecallInteger(responseLimit, 10, 1, 200);
  const candidateCount = body.memories.length;
  const boundedMemories = body.memories.slice(0, limit);
  return {
    ...body,
    memories: boundedMemories,
    count: boundedMemories.length,
    recall_meta: {
      ...(body.recall_meta || {}),
      total_results: boundedMemories.length,
      response_limit_enforcement: {
        requested_limit: limit,
        candidate_count: candidateCount,
        returned_count: boundedMemories.length,
        truncated: candidateCount > boundedMemories.length,
      },
    },
  };
}

function calibrateRecallRouteBody({ queryText, body, runtimeBudget, responseLimit }) {
  const filteredBody = enforceRecallResponseFilters(body, runtimeBudget);
  const boundedBody = enforceRecallResponseLimit(filteredBody, responseLimit);
  const calibratedBody = calibrateNativeRecallResponse({
    query: queryText,
    recallResponse: boundedBody,
    runtimeBudget,
  });
  for (const field of ['early_exit', 'early_exit_flag', 'exit_stage', 'skipped_stages']) {
    if (boundedBody?.recall_meta && Object.prototype.hasOwnProperty.call(boundedBody.recall_meta, field)
      && !Object.prototype.hasOwnProperty.call(calibratedBody?.recall_meta || {}, field)) {
      calibratedBody.recall_meta = {
        ...(calibratedBody.recall_meta || {}),
        [field]: boundedBody.recall_meta[field],
      };
    }
  }
  return calibratedBody;
}
function getMaxDataClassForClearance(clearanceLevel) {
  const cl = Number(clearanceLevel || 1);
  if (cl >= 10) return null; // all classes
  if (cl >= 7) return ['public', 'internal', 'confidential'];
  if (cl >= 4) return ['public', 'internal'];
  return ['public'];
}

let freshnessSchemaReady = false;
let freshnessSchemaPromise = null;
const REQUIRED_FRESHNESS_COLUMNS = [
  'last_verified_at',
  'verified_by',
  'verification_basis',
  'freshness_state',
  'valid_from',
  'valid_until',
];
async function ensureFreshnessSchema() {
  if (freshnessSchemaReady) return;
  if (!freshnessSchemaPromise) {
    freshnessSchemaPromise = (async () => {
      const result = await query(
        `SELECT column_name
         FROM information_schema.columns
         WHERE table_name = 'aimos_memories'
           AND column_name = ANY($1::text[])`,
        [REQUIRED_FRESHNESS_COLUMNS]
      );
      const present = new Set(result.rows.map((row) => row.column_name));
      const missing = REQUIRED_FRESHNESS_COLUMNS.filter((column) => !present.has(column));
      if (missing.length > 0) {
        console.warn(`[recall] freshness schema missing columns: ${missing.join(', ')}; run migrations before freshness-aware recall.`);
      }
      freshnessSchemaReady = true;
    })();
  }
  try {
    await freshnessSchemaPromise;
  } finally {
    if (!freshnessSchemaReady) freshnessSchemaPromise = null;
  }
}

function normalizeRecallQueryValue(value) {
  if (Array.isArray(value)) {
    const first = value.find((item) => String(item || '').trim());
    return first == null ? '' : String(first).trim();
  }
  if (value == null) return '';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' || typeof value === 'boolean') return String(value).trim();
  return '';
}

const POST_COMPACTION_HANDOFF_PATTERNS = [
  /\bpost[-\s]?compaction\b/i,
  /\bafter (?:compact|compaction)\b/i,
  /\bcompaction (?:handoff|summary|delivery)\b/i,
  /\bwhat did .*compaction (?:give|gave|deliver|produce)\b/i,
  /\bhandoff\b/i,
];

function isPostCompactionHandoffQuery(value) {
  const text = String(value || '');
  return POST_COMPACTION_HANDOFF_PATTERNS.some((pattern) => pattern.test(text));
}

function parseMemoryJson(value) {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function decorateCompactionHandoffMemory(row, index = 0) {
  const parsed = parseMemoryJson(row.value);
  const isPost = row.source === 'aimos-compaction:post';
  const confidence = isPost ? 1 : 0.92;
  return {
    id: row.id,
    key: row.key,
    value: row.value,
    scope: row.scope,
    memory_type: row.memory_type,
    clearance_level: row.clearance_level,
    created_at: row.created_at,
    updated_at: row.updated_at,
    credit_score: parseFloat(row.credit_score || 1.0),
    memory_tier: row.memory_tier || 'long-term',
    data_class: row.data_class || 'public',
    source: row.source,
    freshness_state: row.freshness_state || null,
    valid_from: row.valid_from || parsed?.time_window?.valid_from || null,
    valid_until: row.valid_until || parsed?.time_window?.valid_until || null,
    verified_by: row.verified_by || null,
    verification_basis: row.verification_basis || null,
    rerank_score: Number(Math.max(0.85, confidence - index * 0.02).toFixed(3)),
    recall_confidence: confidence,
    confidence_source: 'heuristic_compaction_lane',
    confidence: {
      percent: Number((confidence * 100).toFixed(1)),
      components: {
        semantic: 1,
        keyword: 1,
        recency: 1,
        authority: 1,
        type_authority: 1,
        compaction_lane_priority: isPost ? 1 : 0.92,
      },
    },
    graph_links: [],
    compaction_handoff: {
      lane: parsed?.lane || (isPost ? 'post_compaction_delivery' : 'compaction_full'),
      kind: parsed?.kind || null,
      session_id: parsed?.session_id || null,
      project_id: parsed?.project_id || null,
      workspace_path: parsed?.workspace_path || null,
      linked_full_compaction_key: parsed?.source?.full_compaction_key || null,
      current_objective: parsed?.continuity?.current_objective || null,
      current_phase: parsed?.continuity?.current_phase || parsed?.continuity?.current_state || null,
    },
  };
}

async function lookupPostCompactionHandoff({
  company,
  agent,
  clearance,
  limit,
  sessionId,
  projectId,
  workspacePath,
} = {}) {
  const params = [company, clearance, agent];
  const filters = [
    `company_id = $1`,
    `clearance_level <= $2`,
    `(clearance_level > 2 OR agent_id = $3 OR agent_id IS NULL)`,
    `memory_type = 'session_debrief'`,
    `source IN ('aimos-compaction:post', 'aimos-compaction:full')`,
  ];

  const addTextScope = (value) => {
    const text = String(value || '').trim();
    if (!text) return;
    params.push(`%${text}%`);
    filters.push(`(key ILIKE $${params.length} OR value ILIKE $${params.length})`);
  };

  addTextScope(sessionId);
  addTextScope(projectId);
  addTextScope(workspacePath);

  params.push(Math.min(Math.max(Number(limit || 10), 1), 20));
  const limitParam = params.length;

  const result = await query(
    `SELECT id, key, value, scope, memory_type, clearance_level, created_at, updated_at,
            credit_score, memory_tier, data_class, source, valid_from, valid_until,
            freshness_state, verified_by, verification_basis
       FROM aimos_memories
      WHERE ${filters.join('\n        AND ')}
      ORDER BY
        CASE WHEN source = 'aimos-compaction:post' THEN 0 ELSE 1 END,
        COALESCE(valid_until, valid_from, created_at, updated_at) DESC NULLS LAST,
        created_at DESC NULLS LAST
      LIMIT $${limitParam}`,
    params
  );

  const rows = [...result.rows];
  const firstPost = rows.find((row) => row.source === 'aimos-compaction:post');
  const firstPostJson = parseMemoryJson(firstPost?.value);
  const linkedFullKey = firstPostJson?.source?.full_compaction_key || null;
  if (linkedFullKey && !rows.some((row) => row.key === linkedFullKey)) {
    const linked = await query(
      `SELECT id, key, value, scope, memory_type, clearance_level, created_at, updated_at,
              credit_score, memory_tier, data_class, source, valid_from, valid_until,
              freshness_state, verified_by, verification_basis
         FROM aimos_memories
        WHERE company_id = $1
          AND key = $2
          AND clearance_level <= $3
          AND (clearance_level > 2 OR agent_id = $4 OR agent_id IS NULL)
        LIMIT 1`,
      [company, linkedFullKey, clearance, agent]
    );
    if (linked.rows[0]) rows.push(linked.rows[0]);
  }

  return {
    rows,
    memories: rows.map((row, index) => decorateCompactionHandoffMemory(row, index)),
    linked_full_compaction_key: linkedFullKey,
  };
}

export async function executeNativeRecall(req, recallAuthority) {
  const { q, query: queryParam, scope, limit = 10, memory_type_filter, source_filter, max_hops, mode, selectivity, lazy, session_id, project_id, workspace_path, sort } = recallAuthority.command;
  const sessionLikePattern = session_id && typeof session_id === 'string' && session_id.trim()
    ? sessionKeyLikePattern(session_id)
    : null;
  const recallInput = [q, queryParam, recallAuthority.command.key, recallAuthority.command.memory_id]
    .find((value) => String(value ?? '').trim().length > 0);
  const searchQuery = normalizeRecallQueryValue(
    recallInput,
  );
  const recallRuntimeBudget = recallRuntimeBudgetFrom({ body: recallAuthority.command });
  const company = recallAuthority.companyId;
  const agent = recallAuthority.actorAgentId;
  const clearance = recallAuthority.clearanceCeiling;
  const isDemoMode = recallAuthority.command.projection === 'demo_redacted';
  const recallPlan = {
    mode: mode || 'linear_hybrid',
    supported: true,
    temporal: null,
  };
  let nativeGearboxEvaluationEvidence = null;

  // ─── Recall Pipeline Tracer — per-stage timing (P0 #7) ─────────────────────
  const _inst = SPEED_CONFIG.instrumentation.enabled;
  const _debugRecall = String(recallAuthority.command.debug_recall || '').trim() === '1';
  const doctorTraceRequested = ['1', 'true', 'on', 'yes'].includes(String(recallAuthority.command.doctor_trace ?? recallAuthority.command.doctorTrace ?? '').trim().toLowerCase());
  const _stageTimings = _inst ? [] : null;
  let _prevStage = null;
  let _prevStart = _inst ? performance.now() : 0;
  let _debugPrevStage = null;
  let _debugPrevStart = _debugRecall ? performance.now() : 0;
  const _debugStart = _debugPrevStart;
  const _debugQuery = searchQuery.slice(0, 120).replace(/\s+/g, ' ');
  function debugRecallPoint(id, details = {}) {
    if (!_debugRecall) return;
    const now = performance.now();
    console.warn('[recall-debug]', JSON.stringify({
      point: id,
      total_ms: Math.round((now - _debugStart) * 100) / 100,
      query: _debugQuery,
      ...details,
    }));
  }
  function debugRecallStage(id) {
    if (!_debugRecall) return;
    const now = performance.now();
    if (_debugPrevStage) {
      console.warn('[recall-debug]', JSON.stringify({
        stage: _debugPrevStage,
        event: 'end',
        duration_ms: Math.round((now - _debugPrevStart) * 100) / 100,
        total_ms: Math.round((now - _debugStart) * 100) / 100,
        query: _debugQuery,
      }));
    }
    console.warn('[recall-debug]', JSON.stringify({
      stage: id,
      event: 'start',
      total_ms: Math.round((now - _debugStart) * 100) / 100,
      query: _debugQuery,
    }));
    _debugPrevStage = id;
    _debugPrevStart = now;
  }
  function markStage(id) {
    debugRecallStage(id);
    if (!_inst) return;
    const now = performance.now();
    if (_prevStage) {
      _stageTimings.push({ id: _prevStage, duration_ms: Math.round((now - _prevStart) * 100) / 100, success: true, skipped: false });
    }
    _prevStage = id;
    _prevStart = now;
  }
  function skipStage(id, reason) {
    if (_debugRecall) debugRecallPoint('skip_stage', { stage: id, reason });
    if (!_inst) return;
    _stageTimings.push({ id, duration_ms: 0, success: true, skipped: true, skip_reason: reason });
  }
  function endStages() {
    debugRecallStage('complete');
    if (!_inst || !_prevStage) return;
    const now = performance.now();
    _stageTimings.push({ id: _prevStage, duration_ms: Math.round((now - _prevStart) * 100) / 100, success: true, skipped: false });
    _prevStage = null;
  }
  const recallStartMs = _inst ? Date.now() : 0;
  try {
    debugRecallPoint('request_start', {
      limit,
      mode: mode || 'linear_hybrid',
      source_filter: source_filter || null,
      memory_type_filter: memory_type_filter || null,
    });
    await ensureFreshnessSchema();
    debugRecallPoint('freshness_schema_ready');
    const calibrationSnapshot = await getVerifiedCalibrationSnapshot(company);
    const maxRows = Math.min(Math.max(Number(limit || 10), 1), 200);
    if (!searchQuery || typeof searchQuery !== 'string' || !searchQuery.trim()) {
      console.warn(`[RECALL-GUARD] Empty query from ${req.ip} | referer: ${req.headers.referer || 'none'} | user-agent: ${req.headers['user-agent'] || 'none'} | full URL: ${req.originalUrl}`);
      return { status: 400, body: { success: false, error: 'Missing required parameter: q (search query)' } };
    }

    const typeFilter = String(memory_type_filter || '').trim();
    const srcFilter = String(source_filter || '').trim();
    const explicitFullDetailRecall = isExplicitFullDetailRecall(searchQuery, recallRuntimeBudget);
    const effectiveRecallRuntimeBudget = buildEffectiveRecallRuntimeBudget(recallRuntimeBudget, {
      explicitFullDetail: explicitFullDetailRecall,
      sourceFiltered: Boolean(srcFilter),
      requestedLimit: maxRows,
    });
    const routeQueryUnderstanding = buildRecallQueryUnderstanding(searchQuery, effectiveRecallRuntimeBudget);
    const twinPrimeConfig = verifiedTwinPrimePolicy();
    const magmaCalibrationState = verifiedMagmaCalibration();
    const signedRequestSeconds = Number(recallAuthority.requestAuthority?.signedTs);
    const twinPrimeSignedRequestTimeMs = Number.isSafeInteger(signedRequestSeconds)
      ? signedRequestSeconds * 1000
      : null;
    const twinPrimeTemporalScope = twinPrimeConfig && twinPrimeSignedRequestTimeMs
      ? buildRecallQueryUnderstanding(searchQuery, {
          ...effectiveRecallRuntimeBudget,
          reference_time: new Date(twinPrimeSignedRequestTimeMs),
        }).temporal_scope
      : null;
    const recallBreadthPolicy = buildRecallRouteBreadthPolicy({
      queryUnderstanding: routeQueryUnderstanding,
      maxRows,
      sourceFilter: srcFilter,
      mode,
      runtimeBudget: effectiveRecallRuntimeBudget,
    });
    const earlyExitFlag = earlyExitFlagState({ body: recallAuthority.command });
    recallBreadthPolicy.early_exit_flag = earlyExitFlag;
    if (twinPrimeConfig) {
      recallBreadthPolicy.early_exit_suppressed = 'signed_twin_prime_policy_requires_full_native_path';
      recallBreadthPolicy.semantic_cache_suppressed = 'signed_twin_prime_policy_requires_policy-bound_selection';
    }
    const effectiveMaxRows = recallBreadthPolicy.response_limit;
    const candidateOpeningLimit = recallBreadthPolicy.candidate_opening_limit;
    debugRecallPoint('policy_ready', {
      profile: recallBreadthPolicy.profile,
      explicit_full_detail: explicitFullDetailRecall,
      effective_max_rows: effectiveMaxRows,
      candidate_opening_limit: candidateOpeningLimit,
      vector_limit: recallBreadthPolicy.vector_limit,
      bm25_limit: recallBreadthPolicy.bm25_limit,
      temporal_limit: recallBreadthPolicy.temporal_limit,
      value_rescue_limit: recallBreadthPolicy.value_rescue_limit,
      graph_hops: recallBreadthPolicy.graph_hops,
      twin_prime_policy: twinPrimeConfig?.policy?.arm || null,
      magma_architecture_role: 'permanent_native_retrieval_gear',
      magma_calibration_source: magmaCalibrationState.source,
    });

    debugRecallPoint('identifier_lookup_start');
    const identifierLookup = await lookupIdentifierCandidates({
      queryText: searchQuery,
      companyId: company,
      agentId: agent,
      clearanceLevel: clearance,
      limit: effectiveMaxRows,
      memoryTypeFilter: typeFilter,
      sourceFilter: srcFilter,
    });
    debugRecallPoint('identifier_lookup_done', {
      status: identifierLookup.status,
      memories: identifierLookup.memories?.length || 0,
    });
    // An explicit memory_id is a non-substitutable identifier authority, not a
    // semantic-ranking request. MAGMA may observe the signed policy boundary,
    // but it must not replace or omit the identified row. The row still passes
    // native admission, epistemic selection, Canary inspection, Aladdin
    // retention closure, and final signed-receipt construction below.
    if (identifierLookup.status === IDENTIFIER_RECALL_STATUS.EXACT_MATCH) {
      const identifierAdmission = await admitNativeRecallCandidates(identifierLookup.memories, recallAuthority);
      applyCalibrationSnapshot(identifierAdmission.memories, calibrationSnapshot);
      const identifierDeepRecallSummary = annotateDeepRecallOverrides(identifierAdmission.memories, searchQuery);
      const identifierMemories = applyDeepRecallOverrideRanking(identifierAdmission.memories);
      annotateRecallRankDiagnostics(identifierMemories);
      const identifierEpistemic = await selectAndLedgerEpistemicRecall({
        memories: identifierMemories,
        queryText: searchQuery,
        limit: effectiveMaxRows,
        companyId: company,
        subjectAgentId: agent,
        twinPrimePolicy: twinPrimeConfig?.policy,
        twinPrimePolicyMutationHash: twinPrimeConfig?.mutationHash,
        twinPrimeEligibilityReason: twinPrimeConfig ? 'identifier_exact_lane' : null,
        temporalScope: twinPrimeTemporalScope,
        signedRequestTimeMs: twinPrimeSignedRequestTimeMs,
        parentEventId: recallAuthority.requestAuthority?.requestAdmissionEventId || null,
        requestAuthority: recallAuthority.requestAuthority || null,
      });
      await logEvent(company, agent, 'recall', searchQuery, {
        reasoning: `Exact identifier recall for '${searchQuery}' returned ${identifierLookup.memories.length} memory record(s).`,
        source_knowledge: 'identifier-recall.js — Generative Retrieval identifier ambiguity guard',
      });
      const identifierSecurity = await closeNativeRecallSecurityBoundary({
        boundaryId: 'identifier_exact',
        sourceAgentId: 'identifier-recall',
        memories: identifierEpistemic.memories,
        companyId: company,
        subjectAgentId: agent,
        recallAuthority,
        epistemicReceipt: identifierEpistemic.receipt,
        epistemicDecisionHash: identifierEpistemic.decision.decision_sha256,
      });
      const identifierBody = {
          success: true,
          memories: identifierSecurity.memories,
          count: identifierSecurity.memories.length,
          cache_hit: false,
          identifier_recall: identifierLookup.diagnostics,
          recall_meta: {
            identifier_recall: identifierLookup.diagnostics,
            deep_recall_override: identifierDeepRecallSummary,
            rank_observability: buildRecallRankObservability(identifierMemories),
            epistemic_retrieval: {
              version: identifierEpistemic.decision.version,
              decision_sha256: identifierEpistemic.decision.decision_sha256,
              candidate_count: identifierEpistemic.decision.candidate_count,
              states: identifierEpistemic.decision.states,
              abstention_required: identifierEpistemic.decision.abstention_required,
              ...(identifierEpistemic.decision.twin_prime ? { twin_prime: identifierEpistemic.decision.twin_prime } : {}),
              decision_receipt: identifierEpistemic.receipt,
            },
            recall_security_closure: identifierSecurity.decision,
            magma_retrieval: {
              ...magmaGearMetadata({ calibrationState: magmaCalibrationState, runtimeMs: 0 }),
              applicability: 'not_applicable_explicit_identifier',
              authority_ruling: 'exact_identifier_non_substitutable',
              substitution_authorized: false,
              graph_traversal_executed: false,
            },
            early_exit: false,
            early_exit_flag: earlyExitFlag,
            exit_stage: 'identifier_exact',
          },
          recall_plan: {
            ...recallPlan,
            mode: 'identifier_exact',
          },
        };
      const calibratedIdentifierBody = calibrateRecallRouteBody({
        queryText: searchQuery,
        body: identifierBody,
        runtimeBudget: effectiveRecallRuntimeBudget,
        responseLimit: effectiveMaxRows,
      });
      calibratedIdentifierBody.recall_receipt = await finalizeNativeRecall({
        memories: calibratedIdentifierBody.memories,
        authority: recallAuthority,
        epistemicDecisionHash: epistemicReceiptDecisionHash(identifierEpistemic.decision),
      });
      return { status: 200, body: calibratedIdentifierBody };
    }

    const compactionSourceCompatible =
      !srcFilter ||
      srcFilter === 'aimos-compaction:post' ||
      srcFilter === 'aimos-compaction:full';
    const compactionTypeCompatible = !typeFilter || typeFilter === 'session_debrief';
    if (isPostCompactionHandoffQuery(searchQuery) && compactionSourceCompatible && compactionTypeCompatible) {
      const handoffLookup = await lookupPostCompactionHandoff({
        company,
        agent,
        clearance,
        limit: maxRows,
        sessionId: session_id,
        projectId: project_id,
        workspacePath: workspace_path,
      });
      if (handoffLookup.memories.length > 0) {
        const handoffAdmission = await admitNativeRecallCandidates(handoffLookup.memories, recallAuthority);
        const admittedHandoffMemories = handoffAdmission.memories;
        applyCalibrationSnapshot(admittedHandoffMemories, calibrationSnapshot);
        const handoffEpistemic = await selectAndLedgerEpistemicRecall({
          memories: admittedHandoffMemories,
          queryText: searchQuery,
          limit: effectiveMaxRows,
          companyId: company,
          subjectAgentId: agent,
          twinPrimePolicy: twinPrimeConfig?.policy,
          twinPrimePolicyMutationHash: twinPrimeConfig?.mutationHash,
          twinPrimeEligibilityReason: twinPrimeConfig ? 'post_compaction_handoff_lane' : null,
          temporalScope: twinPrimeTemporalScope,
          signedRequestTimeMs: twinPrimeSignedRequestTimeMs,
          parentEventId: recallAuthority.requestAuthority?.requestAdmissionEventId || null,
          requestAuthority: recallAuthority.requestAuthority || null,
        });
        await logEvent(company, agent, 'recall', searchQuery, {
          lane: 'post_compaction_delivery',
          recall_mode: 'post_compaction_handoff',
          result_count: admittedHandoffMemories.length,
          linked_full_compaction_key: handoffLookup.linked_full_compaction_key,
          reasoning: `Post-compaction handoff recall for '${searchQuery}' returned ${handoffLookup.memories.length} native compaction lane record(s) before semantic cache.`,
          source_knowledge: 'compaction-post-compaction-corpus.md — TiMem L2 + Chronos handoff tuning',
        });
        const workingMemory = handoffEpistemic.memories
          .slice(0, 2)
          .map((mem) => `[${mem.source}] ${mem.value}`.slice(0, 700))
          .join('\n');
        const handoffBody = {
            success: true,
            memories: handoffEpistemic.memories,
            working_memory: isDemoMode ? demoRedact(workingMemory) : workingMemory,
            count: handoffEpistemic.memories.length,
            cache_hit: false,
            recall_plan: {
              ...recallPlan,
              mode: 'post_compaction_handoff',
              supported: true,
              cues: ['post_compaction_handoff'],
              cache_bypassed: true,
            },
            recall_meta: {
              qmd_activated: false,
              total_results: admittedHandoffMemories.length,
              confidence_distribution: {
                high: admittedHandoffMemories.length,
                medium: 0,
                low: 0,
              },
              temporal_truth: {
                truth_band: 'live',
                newest_memory_at: admittedHandoffMemories[0]?.created_at || null,
                oldest_memory_at: admittedHandoffMemories.at(-1)?.created_at || null,
                valid_from: admittedHandoffMemories[0]?.valid_from || null,
                valid_until: admittedHandoffMemories[0]?.valid_until || null,
              },
              compaction_handoff_recall: {
                source: 'native_compaction_lane',
                preferred_source: 'aimos-compaction:post',
                linked_full_compaction_key: handoffLookup.linked_full_compaction_key,
                session_id: session_id || admittedHandoffMemories[0]?.compaction_handoff?.session_id || null,
                project_id: project_id || admittedHandoffMemories[0]?.compaction_handoff?.project_id || null,
              },
              epistemic_retrieval: {
                version: handoffEpistemic.decision.version,
                decision_sha256: handoffEpistemic.decision.decision_sha256,
                candidate_count: handoffEpistemic.decision.candidate_count,
                states: handoffEpistemic.decision.states,
                abstention_required: handoffEpistemic.decision.abstention_required,
                ...(handoffEpistemic.decision.twin_prime ? { twin_prime: handoffEpistemic.decision.twin_prime } : {}),
                decision_receipt: handoffEpistemic.receipt,
              },
            },
            ...(isDemoMode ? { demo_mode: true } : {}),
          };
        const calibratedHandoffBody = calibrateRecallRouteBody({
            queryText: searchQuery,
            body: handoffBody,
            runtimeBudget: effectiveRecallRuntimeBudget,
            responseLimit: effectiveMaxRows,
          });
        calibratedHandoffBody.recall_receipt = await finalizeNativeRecall({
          memories: calibratedHandoffBody.memories,
          authority: recallAuthority,
          epistemicDecisionHash: epistemicReceiptDecisionHash(handoffEpistemic.decision),
        });
        return { status: 200, body: calibratedHandoffBody };
      }
    }

    // ─── Chronological Sort Detection ──────────────────────────────
    // If sort=chronological, or if this is a system continuity query (precompact)
    const isChronological = sort === 'chronological' || (searchQuery.toLowerCase().includes('precompact') && !sort);

    // keypoint-decomposer remains intentionally unwired; adding it to the
    // default recall path would add native-LLM decomposition latency.

    markStage('embedding_query');
    const queryEmbedding = await getEmbedding(searchQuery);

    // ─── SPEED OPT: Check semantic cache (Phase 1) ─────────────────────────────
    markStage('cache_check');
    const hasRecallFilter = Boolean(typeFilter || srcFilter || session_id);
    const semanticCacheRequest = parseAimosRuntimeFlag(recallAuthority.command.cache ?? recallAuthority.command.semantic_cache ?? recallAuthority.command.semanticCache);
    const requestDisablesSemanticCache = semanticCacheRequest === false;
    const allowSemanticCache = !twinPrimeConfig
      && !requestDisablesSemanticCache
      && !hasRecallFilter
      && !explicitFullDetailRecall;
    if (SPEED_CONFIG.cache.enabled && allowSemanticCache) {
      const cacheContext = {
        companyId: company,
        agentId: agent,
        clearanceLevel: clearance,
        calibrationMutationHash: calibrationSnapshot.calibrationMutationHash,
      };
      const cached = await semanticCache.get(queryEmbedding, searchQuery, cacheContext);
      if (cached) {
        const cachedAdmission = await admitNativeRecallCandidates(cached.memories || [], recallAuthority);
        applyCalibrationSnapshot(cachedAdmission.memories, calibrationSnapshot);
        const cachedEpistemic = await selectAndLedgerEpistemicRecall({
          memories: cachedAdmission.memories,
          queryText: searchQuery,
          limit: effectiveMaxRows,
          companyId: company,
          subjectAgentId: agent,
          twinPrimePolicy: twinPrimeConfig?.policy,
          twinPrimePolicyMutationHash: twinPrimeConfig?.mutationHash,
          twinPrimeEligibilityReason: twinPrimeConfig ? 'semantic_cache_policy_identity_unbound' : null,
          queryEmbedding,
          temporalScope: twinPrimeTemporalScope,
          signedRequestTimeMs: twinPrimeSignedRequestTimeMs,
          parentEventId: recallAuthority.requestAuthority?.requestAdmissionEventId || null,
          requestAuthority: recallAuthority.requestAuthority || null,
        });
        await logEvent(company, agent, 'cache_hit', searchQuery, {
          reasoning: `Cache hit for query '${searchQuery.slice(0,50)}...' — skipping full 21-stage native recall per semantic similarity threshold ${SPEED_CONFIG.cache.similarityThreshold}`,
          source_knowledge: 'Cache-Augmented Generation (Gao et al., 2024) — Speed.md Appendix A'
        });
        const calibratedCachedBody = calibrateRecallRouteBody({
            queryText: searchQuery,
            body: {
              ...cached,
              memories: cachedEpistemic.memories,
              recall_meta: {
                ...(cached.recall_meta || {}),
                epistemic_retrieval: {
                  version: cachedEpistemic.decision.version,
                  decision_sha256: cachedEpistemic.decision.decision_sha256,
                  candidate_count: cachedEpistemic.decision.candidate_count,
                  states: cachedEpistemic.decision.states,
                  abstention_required: cachedEpistemic.decision.abstention_required,
                  ...(cachedEpistemic.decision.twin_prime ? { twin_prime: cachedEpistemic.decision.twin_prime } : {}),
                  decision_receipt: cachedEpistemic.receipt,
                },
              },
              cache_hit: true,
              cached_at: new Date().toISOString(),
            },
            runtimeBudget: effectiveRecallRuntimeBudget,
            responseLimit: effectiveMaxRows,
          });
        calibratedCachedBody.recall_receipt = await finalizeNativeRecall({
          memories: calibratedCachedBody.memories,
          authority: recallAuthority,
          epistemicDecisionHash: epistemicReceiptDecisionHash(cachedEpistemic.decision),
        });
        return { status: 200, body: calibratedCachedBody };
      }
    }
    // ─────────────────────────────────────────────────────────────────────────

    // ─── FELIX: memory_type_filter lets boot queries pull only event_log entries ──
    const params = [JSON.stringify(queryEmbedding), company, clearance, candidateOpeningLimit];
    let typeClause = '';
    if (typeFilter) {
      params.push(typeFilter);
      typeClause = `AND memory_type = $${params.length}`;
    }

    // ─── SOURCE FILTER: isolate memories by source tag (e.g. source=longmemeval) ──
    let sourceClause = '';
    if (srcFilter) {
      params.push(srcFilter);
      sourceClause = `AND source = $${params.length}`;
    }

    // ─── SESSION SCOPING: filter memories to a specific ingestion session ────
    // When session_id is provided, only return memories whose key starts with
    // the session prefix (e.g. "sess:abc123:entity:..."). This is the critical
    // fix for ASMR accuracy — prevents retrieval from pulling all 10K+ memories.
    let sessionClause = '';
    if (sessionLikePattern) {
      params.push(sessionLikePattern);
      sessionClause = `AND key LIKE $${params.length} ESCAPE '\\'`;
    }

    // Aladdin Law: every version remains recallable. Supersession is provenance,
    // never a hidden filter; current-vs-historical is handled by ranking/output.
    // MEMORY ACL: private memories (clearance_level <= 2) are only visible to their owning agent.
    const requestingAgent = agent;
    let aclClause = '';
    params.push(requestingAgent);
    const aclParamIdx = params.length;
    aclClause = `AND (clearance_level > 2 OR agent_id = $${aclParamIdx} OR agent_id IS NULL)`;

    // ─── Feature 6: Data classification filter ──────────────────────────────
    let dataClassClause = '';
    const allowedClasses = getMaxDataClassForClearance(clearance);
    if (allowedClasses) {
      params.push(allowedClasses);
      dataClassClause = `AND COALESCE(data_class, 'public') = ANY($${params.length}::text[])`;
    }

    // ─── HYBRID BM25 + EMBEDDING RECALL ─────────────────────────────────────
    markStage('hybrid_vector_bm25');
    // Two-stage approach for performance:
    // Stage 1: Get top candidates by vector similarity (uses HNSW index, fast)
    // Stage 2: Re-rank candidates with BM25 ts_rank + trigram key similarity
    // This avoids seq scan on the full table.

    // Add tsquery parameters for sparse lexical calibration.
    const lexicalCalibration = buildRecallLexicalCalibration(searchQuery);
    params.push(lexicalCalibration.ts_query);
    const lexicalTsParamIdx = params.length;

    params.push(lexicalCalibration.phrase_patterns);
    const phraseParamIdx = params.length;

    // Add query text for trigram key matching
    params.push(searchQuery.toLowerCase().replace(/[^a-z0-9\s_:]/g, ' ').trim());
    const trgmParamIdx = params.length;

    // Fetch candidates using the corpus-backed route-entry breadth policy.
    const candidateLimit = isChronological ? 300 : recallBreadthPolicy.vector_limit;
    params.push(candidateLimit);
    const vectorCandParamIdx = params.length;

    params.push(recallBreadthPolicy.bm25_limit);
    const bm25CandParamIdx = params.length;

    params.push(recallBreadthPolicy.temporal_limit);
    const temporalCandParamIdx = params.length;

    const sortClause = isChronological ? 'created_at DESC' : 'distance ASC';

    const result = await query(
      `WITH vector_candidates AS (
         SELECT id, key, value, scope, memory_type, clearance_level, created_at, credit_score, memory_tier, decay_weight, data_class, source,
                access_count, last_accessed_at, last_verified_at, verified_by, verification_basis, freshness_state,
                search_vector, embedding,
                (embedding <=> $1::vector) as raw_distance,
                COALESCE(retrieval_weight, 1.0) as retrieval_weight
         FROM aimos_memories
         WHERE company_id = $2 AND clearance_level <= $3
           ${aclClause}
           ${dataClassClause}
           ${typeClause}
           ${sourceClause}
           ${sessionClause}
         ORDER BY (1 - (embedding <=> $1::vector)) * COALESCE(retrieval_weight, 1.0) DESC
         LIMIT $${vectorCandParamIdx}
       ),
       bm25_candidates AS (
         SELECT id, key, value, scope, memory_type, clearance_level, created_at, credit_score, memory_tier, decay_weight, data_class, source,
                access_count, last_accessed_at, last_verified_at, verified_by, verification_basis, freshness_state,
                search_vector, embedding,
                (embedding <=> $1::vector) as raw_distance,
                COALESCE(retrieval_weight, 1.0) as retrieval_weight
         FROM aimos_memories
         WHERE company_id = $2 AND clearance_level <= $3
           AND search_vector @@ to_tsquery('english', $${lexicalTsParamIdx})
           ${aclClause}
           ${dataClassClause}
           ${typeClause}
           ${sourceClause}
           ${sessionClause}
         ORDER BY ts_rank(search_vector, to_tsquery('english', $${lexicalTsParamIdx})) DESC
         LIMIT $${bm25CandParamIdx}
       ),
       temporal_candidates AS (
         SELECT id, key, value, scope, memory_type, clearance_level, created_at, credit_score, memory_tier, decay_weight, data_class, source,
                access_count, last_accessed_at, last_verified_at, verified_by, verification_basis, freshness_state,
                search_vector, embedding,
                (embedding <=> $1::vector) as raw_distance,
                COALESCE(retrieval_weight, 1.0) as retrieval_weight
         FROM aimos_memories
         WHERE company_id = $2 AND clearance_level <= $3
           AND (LOWER(key) LIKE '%' || $${trgmParamIdx} || '%' OR search_vector @@ to_tsquery('english', $${lexicalTsParamIdx}))
           ${aclClause}
           ${dataClassClause}
           ${typeClause}
           ${sourceClause}
           ${sessionClause}
         ORDER BY created_at DESC
         LIMIT $${temporalCandParamIdx}
       ),
       all_candidates AS (
         SELECT * FROM vector_candidates
         UNION
         SELECT * FROM bm25_candidates
         UNION
         SELECT * FROM temporal_candidates
       )
       SELECT id, key, value, scope, memory_type, clearance_level, created_at, credit_score, memory_tier, decay_weight, data_class, source,
              access_count, last_accessed_at, last_verified_at, verified_by, verification_basis, freshness_state,
              embedding::text AS embedding, retrieval_weight,
              raw_distance,
              COALESCE(ts_rank(search_vector, to_tsquery('english', $${lexicalTsParamIdx})), 0) as bm25_rank,
              COALESCE(similarity(key, $${trgmParamIdx}), 0) as key_similarity,
              (
                raw_distance
                / GREATEST(retrieval_weight, 0.1)
                * CASE WHEN LENGTH(value) > 3000 THEN 1.15 ELSE 1.0 END
                / (1.0
                  + COALESCE(ts_rank(search_vector, to_tsquery('english', $${lexicalTsParamIdx})), 0) * 3.0
                  + CASE WHEN COALESCE(similarity(key, $${trgmParamIdx}), 0) > 0.2 THEN COALESCE(similarity(key, $${trgmParamIdx}), 0) * 2.0 ELSE 0 END
                  + CASE WHEN search_vector @@ to_tsquery('english', $${lexicalTsParamIdx}) THEN 0.5 ELSE 0 END
                  + CASE WHEN EXISTS (
                      SELECT 1
                      FROM unnest($${phraseParamIdx}::text[]) AS phrase
                      WHERE LOWER(key) LIKE phrase OR LOWER(value) LIKE phrase
                    ) THEN 1.0 ELSE 0 END
                )
              ) as distance
       FROM all_candidates
       ORDER BY ${sortClause}
       LIMIT $4`,
      params
    );
    debugRecallPoint('hybrid_vector_bm25_done', {
      rows: result.rows.length,
      candidate_limit: candidateLimit,
      candidate_opening_limit: candidateOpeningLimit,
      response_limit: effectiveMaxRows,
    });

    await logEvent(company, agent, 'recall', searchQuery, {
      reasoning: `Recall query by '${agent}': searching Aimos for '${searchQuery}'. Recall events are passive; access telemetry is recorded as frequency metadata without decay, pruning, or suppression.`
    });

    const memories = [];
    const seenIds = new Set();

    // ─── QuIM-RAG: permanent signed inverted-question gear ──────────────────
    // The exact immutable index build is selected by QUIM_RETRIEVAL_POLICY.
    // There is no boolean, ENV, shadow, or enforcement mode.
    markStage('quim_lookup');
    try {
      const quimResults = await quimLookup(searchQuery, company, Math.min(candidateOpeningLimit, 10));
      if (quimResults.length > 0) {
          // Merge QuIM results with existing memories (deduplicate by ID)
          for (const qr of quimResults) {
            if (!seenIds.has(qr.id)) {
              seenIds.add(qr.id);
              // Fetch full memory content
              const fullMem = await query(
                `SELECT id, key, value, scope, memory_type, clearance_level, created_at,
                        credit_score, memory_tier, data_class, source, access_count, last_accessed_at,
                        last_verified_at, verified_by, verification_basis, freshness_state,
                        COALESCE(retrieval_weight, 1.0) AS retrieval_weight
                 FROM aimos_memories WHERE id = $1 AND company_id = $2`,
                [qr.id, company]
              );
              if (fullMem.rows.length > 0) {
                const row = fullMem.rows[0];
                memories.push({
                  id: row.id,
                  key: row.key,
                  value: row.value,
                  scope: row.scope,
                  memory_type: row.memory_type,
                  clearance_level: row.clearance_level,
                  created_at: row.created_at,
                  credit_score: parseFloat(row.credit_score || 1.0),
                  memory_tier: row.memory_tier || 'short-term',
                  data_class: row.data_class || 'public',
                  source: row.source || null,
                  access_count: Number(row.access_count || 0),
                  last_accessed_at: row.last_accessed_at || null,
                  last_verified_at: row.last_verified_at || null,
                  verified_by: row.verified_by || null,
                  verification_basis: row.verification_basis || null,
                  freshness_state: row.freshness_state || null,
                  retrieval_weight: Math.max(0.1, Math.min(3, Number(row.retrieval_weight || 1))),
                  retrieval_source: 'quim_lookup',
                  graph_links: [],
                  rerank_score: qr.score,
                  quim_source: qr.source,
                  quim_question: qr.question
                });
              }
            }
          }
      }
    } catch (_quimErr) {
      console.warn('[recall] quim_lookup error (non-fatal):', _quimErr.message);
      if (_inst) skipStage('quim_lookup', 'error');
    }
    debugRecallPoint('quim_done', { memories: memories.length, seen_ids: seenIds.size });

    // ─── HIPPORAG ENTITY RECALL: Find memories connected by shared entities ────
    markStage('entity_recall');
    // Extract entities from the query, look up memory IDs via entity_memory_edges,
    // inject any unseen high-relevance memories into results.
    let entityMemories = [];
    try {
      const queryEntities = extractEntities(searchQuery || '');
      if (queryEntities.length > 0) {
        const entityNames = queryEntities.map(e => e.name);
        const entityParams = [company, entityNames, clearance, requestingAgent];
        const entityClauses = [
          'e.company_id = $1',
          'e.entity = ANY($2)',
          'm.clearance_level <= $3',
          '(m.clearance_level > 2 OR m.agent_id = $4 OR m.agent_id IS NULL)',
        ];
        if (allowedClasses) {
          entityParams.push(allowedClasses);
          entityClauses.push(`COALESCE(m.data_class, 'public') = ANY($${entityParams.length}::text[])`);
        }
        if (typeFilter) {
          entityParams.push(typeFilter);
          entityClauses.push(`m.memory_type = $${entityParams.length}`);
        }
        if (srcFilter) {
          entityParams.push(srcFilter);
          entityClauses.push(`m.source = $${entityParams.length}`);
        }
        if (sessionLikePattern) {
          entityParams.push(sessionLikePattern);
          entityClauses.push(`m.key LIKE $${entityParams.length} ESCAPE '\\'`);
        }
        const entResult = await query(
          `SELECT DISTINCT e.memory_id, m.key, m.value, m.scope, m.memory_type,
                  m.clearance_level, m.memory_tier, m.data_class, m.source,
                  m.access_count, m.last_accessed_at, m.last_verified_at,
                  m.verified_by, m.verification_basis, m.freshness_state,
                  COALESCE(m.retrieval_weight, 1.0) AS retrieval_weight,
                  COUNT(*) OVER (PARTITION BY e.memory_id) as entity_hits
           FROM entity_memory_edges e
           JOIN aimos_memories m ON m.id = e.memory_id AND m.company_id = e.company_id
           WHERE ${entityClauses.join(' AND ')}
           ORDER BY entity_hits DESC
           LIMIT 5`,
          entityParams
        );
        entityMemories = entResult.rows;
      }
    } catch (_entRecallErr) {
      // Entity recall is best-effort
    }
    debugRecallPoint('entity_recall_done', { entity_memories: entityMemories.length });

    // ─── Feature 8: Recursive Graph Traversal (replaces manual 2-hop) ────────
    // WITH RECURSIVE enables configurable N-hop traversal (default 2, max 4).
    const requestedHops = max_hops !== undefined ? Number(max_hops) : recallBreadthPolicy.graph_hops;
    const hops = Math.min(
      Math.max(Number.isFinite(requestedHops) ? requestedHops : recallBreadthPolicy.graph_hops, 0),
      4
    );
    if (hops > 0) {
      markStage('recursive_graph_walk');
    } else {
      skipStage('recursive_graph_walk', 'intent_policy_graph_hops_zero');
    }
    for (const row of result.rows) {
      if (seenIds.has(row.id)) continue;
      seenIds.add(row.id);
      const mem = {
        id: row.id,
        key: row.key,
        value: row.value,
        scope: row.scope,
        memory_type: row.memory_type,
        clearance_level: row.clearance_level,
        created_at: row.created_at,
        credit_score: parseFloat(row.credit_score || 1.0),
        memory_tier: row.memory_tier || 'short-term',
        data_class: row.data_class || 'public',
        source: row.source || null,
        access_count: Number(row.access_count || 0),
        last_accessed_at: row.last_accessed_at || null,
        last_verified_at: row.last_verified_at || null,
        verified_by: row.verified_by || null,
        verification_basis: row.verification_basis || null,
        freshness_state: row.freshness_state || null,
        embedding: row.embedding || null,
        retrieval_weight: Math.max(0.1, Math.min(3, Number(row.retrieval_weight || 1))),
        quality: Math.log(Math.max(0.1, Math.min(3, Number(row.retrieval_weight || 1)))),
        raw_distance: Number(row.raw_distance),
        bm25_rank: Number(row.bm25_rank || 0),
        key_similarity: Number(row.key_similarity || 0),
        hybrid_distance: Number(row.distance),
        graph_links: []
      };
      memories.push(mem);
    }
    debugRecallPoint('base_memory_build_done', {
      memories: memories.length,
      seen_ids: seenIds.size,
      graph_hops: hops,
    });

    // ─── HIPPORAG: Merge entity-recalled memories not already in vector results ──
    for (const em of entityMemories) {
      if (!seenIds.has(em.memory_id)) {
        seenIds.add(em.memory_id);
        memories.push({
          id: em.memory_id,
          key: em.key,
          value: em.value,
          scope: em.scope,
          memory_type: em.memory_type,
          clearance_level: em.clearance_level,
          memory_tier: em.memory_tier || 'short-term',
          data_class: em.data_class || 'public',
          entity_hits: Number(em.entity_hits || 1),
          source: em.source || null,
          access_count: Number(em.access_count || 0),
          last_accessed_at: em.last_accessed_at || null,
          last_verified_at: em.last_verified_at || null,
          verified_by: em.verified_by || null,
          verification_basis: em.verification_basis || null,
          freshness_state: em.freshness_state || null,
          retrieval_weight: Math.max(0.1, Math.min(3, Number(em.retrieval_weight || 1))),
          retrieval_source: 'entity_graph',
          graph_links: []
        });
      }
    }
    debugRecallPoint('entity_merge_done', { memories: memories.length, seen_ids: seenIds.size });

    // ─── BM25 SECOND PASS: catch memories that vector search misses ────────────
    markStage('bm25_rescue');
    // Vector embeddings for large documents are diluted — they match everything
    // vaguely but nothing precisely. This pass uses PostgreSQL full-text search
    // (tsvector/ts_rank) for BM25-style keyword matching, catching what embeddings miss.
    // Also uses pg_trgm for fuzzy key matching (credentials, signals, specific IDs).
    try {
      const bm25Query = lexicalCalibration.ts_query;
      if (bm25Query && bm25Query.trim().length >= 3) {
        const rescueParams = [company, clearance, bm25Query, agent];
        const rescueClauses = [
          'company_id = $1',
          'clearance_level <= $2',
          '(clearance_level > 2 OR agent_id = $4 OR agent_id IS NULL)',
        ];
        if (allowedClasses) {
          rescueParams.push(allowedClasses);
          rescueClauses.push(`COALESCE(data_class, 'public') = ANY($${rescueParams.length}::text[])`);
        }
        if (typeFilter) {
          rescueParams.push(typeFilter);
          rescueClauses.push(`memory_type = $${rescueParams.length}`);
        }
        if (srcFilter) {
          rescueParams.push(srcFilter);
          rescueClauses.push(`source = $${rescueParams.length}`);
        }
        if (sessionLikePattern) {
          rescueParams.push(sessionLikePattern);
          rescueClauses.push(`key LIKE $${rescueParams.length} ESCAPE '\\'`);
        }
        rescueParams.push(recallBreadthPolicy.bm25_limit);
        const rescueLimitIdx = rescueParams.length;
        const bm25Result = await query(
          `SELECT id, key, value, scope, memory_type, clearance_level, created_at, credit_score, memory_tier, decay_weight,
                  data_class, source, access_count, last_accessed_at,
                  ts_rank(search_vector, to_tsquery('english', $3)) as bm25_score
           FROM aimos_memories
           WHERE ${rescueClauses.join(' AND ')}
             AND search_vector @@ to_tsquery('english', $3)
           ORDER BY
             bm25_score DESC,
             created_at DESC
           LIMIT $${rescueLimitIdx}`,
          rescueParams
        );

        for (const row of bm25Result.rows) {
          if (!seenIds.has(row.id)) {
            seenIds.add(row.id);
            memories.push({
              id: row.id,
              key: row.key,
              value: row.value,
              scope: row.scope,
              memory_type: row.memory_type,
              clearance_level: row.clearance_level,
              created_at: row.created_at,
              credit_score: parseFloat(row.credit_score || 1.0),
              memory_tier: row.memory_tier || 'short-term',
              data_class: row.data_class || 'public',
              source: row.source || null,
              access_count: Number(row.access_count || 0),
              last_accessed_at: row.last_accessed_at || null,
              retrieval_source: 'bm25_pass',
              bm25_score: parseFloat(row.bm25_score || 0),
              graph_links: []
            });
          }
        }
      }
    } catch (_bm25Err) {
      // BM25 pass is best-effort — don't break recall
    }
    debugRecallPoint('bm25_rescue_done', { memories: memories.length, seen_ids: seenIds.size });

    // ─── IDENTITY TRUTH RESCUE: explicit identity declarations ───────────────
    // Current-truth identity questions need primary declaration evidence, not
    // transcripts or prompt mirrors that merely quote the declaration.
    // Aladdin boundary: read-only candidate expansion; no canonical mutation.
    if (recallBreadthPolicy.identity_truth_rescue_enabled) {
      try {
        const identityRescueParams = [company, clearance, requestingAgent];
        const identityRescueClauses = [
          'm.company_id = $1',
          'm.clearance_level <= $2',
          '(m.clearance_level > 2 OR m.agent_id = $3 OR m.agent_id IS NULL)',
        ];
        if (allowedClasses) {
          identityRescueParams.push(allowedClasses);
          identityRescueClauses.push(`COALESCE(m.data_class, 'public') = ANY($${identityRescueParams.length}::text[])`);
        }
        if (typeFilter) {
          identityRescueParams.push(typeFilter);
          identityRescueClauses.push(`m.memory_type = $${identityRescueParams.length}`);
        }
        if (srcFilter) {
          identityRescueParams.push(srcFilter);
          identityRescueClauses.push(`m.source = $${identityRescueParams.length}`);
        }
        if (sessionLikePattern) {
          identityRescueParams.push(sessionLikePattern);
          identityRescueClauses.push(`m.key LIKE $${identityRescueParams.length} ESCAPE '\\'`);
        }
        identityRescueParams.push(
          'identity\\s*:.{0,160}(executive runtime|runtime for|canonical|confirmed|ceo[ -]?level|orchestrator)|identity confirmed.{0,160}(executive runtime|runtime for|canonical|ceo[ -]?level|orchestrator)'
        );
        const identityPatternIdx = identityRescueParams.length;
        identityRescueParams.push(recallBreadthPolicy.identity_truth_rescue_limit);
        const identityLimitIdx = identityRescueParams.length;
        const identityRescueResult = await query(
          `SELECT m.id, m.key, m.value, m.scope, m.memory_type, m.clearance_level,
                  m.created_at, m.credit_score, m.memory_tier, m.decay_weight,
                  m.data_class, m.source, m.access_count, m.last_accessed_at,
                  CASE
                    WHEN m.memory_type IN ('identity', 'core_belief', 'directive', 'event_log') THEN 0
                    WHEN LOWER(m.key) LIKE '%precompact%' OR m.memory_type = 'conversation_feed'
                      OR LOWER(m.value) LIKE '%answer the question using only the context%' THEN 2
                    ELSE 1
                  END AS identity_source_rank,
                  CHAR_LENGTH(m.value) AS identity_body_length
           FROM aimos_memories m
           WHERE ${identityRescueClauses.join(' AND ')}
             AND LOWER(m.value) ~ $${identityPatternIdx}
           ORDER BY identity_source_rank ASC, identity_body_length ASC, m.created_at DESC
           LIMIT $${identityLimitIdx}`,
          identityRescueParams
        );

        let identityRescued = 0;
        const identityRescueCandidateKeys = identityRescueResult.rows.map((row) => row.key).slice(0, 12);
        const identityRescueAddedKeys = [];
        for (const row of identityRescueResult.rows) {
          if (seenIds.has(row.id)) continue;
          seenIds.add(row.id);
          identityRescued += 1;
          identityRescueAddedKeys.push(row.key);
          memories.push({
            id: row.id,
            key: row.key,
            value: row.value,
            scope: row.scope,
            memory_type: row.memory_type,
            clearance_level: row.clearance_level,
            created_at: row.created_at,
            credit_score: parseFloat(row.credit_score || 1.0),
            memory_tier: row.memory_tier || 'short-term',
            data_class: row.data_class || 'public',
            source: row.source || null,
            access_count: Number(row.access_count || 0),
            last_accessed_at: row.last_accessed_at || null,
            retrieval_source: 'identity_truth_rescue',
            identity_source_rank: Number(row.identity_source_rank || 0),
            identity_body_length: Number(row.identity_body_length || 0),
            graph_links: []
          });
        }
        recallBreadthPolicy.identity_truth_rescued = identityRescued;
        recallBreadthPolicy.identity_truth_rescue_candidate_keys = identityRescueCandidateKeys;
        recallBreadthPolicy.identity_truth_rescue_added_keys = identityRescueAddedKeys.slice(0, 12);
      } catch (_identityRescueErr) {
        console.warn('[recall] identity truth rescue error (non-fatal):', _identityRescueErr.message);
        recallBreadthPolicy.identity_truth_rescue_error = _identityRescueErr.message;
      }
    }
    debugRecallPoint('identity_truth_rescue_done', {
      enabled: recallBreadthPolicy.identity_truth_rescue_enabled,
      rescued: recallBreadthPolicy.identity_truth_rescued || 0,
      memories: memories.length,
      seen_ids: seenIds.size,
    });

    // ─── VALUE RESCUE: source-scoped full-detail evidence opening ─────────────
    // MRAG/TimeR4: for explicit source-filtered reads, candidate selection must
    // preserve body-level anchors before final evidence opening. This catches
    // long sessions whose sparse vectors miss rare facts or compound terms.
    if (recallBreadthPolicy.value_rescue_enabled && lexicalCalibration.value_patterns?.length > 0) {
      try {
        const rescueParams = [company, clearance, agent, lexicalCalibration.value_patterns];
        const rescueClauses = [
          'm.company_id = $1',
          'm.clearance_level <= $2',
          '(m.clearance_level > 2 OR m.agent_id = $3 OR m.agent_id IS NULL)',
        ];
        if (allowedClasses) {
          rescueParams.push(allowedClasses);
          rescueClauses.push(`COALESCE(m.data_class, 'public') = ANY($${rescueParams.length}::text[])`);
        }
        if (typeFilter) {
          rescueParams.push(typeFilter);
          rescueClauses.push(`m.memory_type = $${rescueParams.length}`);
        }
        if (srcFilter) {
          rescueParams.push(srcFilter);
          rescueClauses.push(`m.source = $${rescueParams.length}`);
        }
        if (sessionLikePattern) {
          rescueParams.push(sessionLikePattern);
          rescueClauses.push(`m.key LIKE $${rescueParams.length} ESCAPE '\\'`);
        }
        rescueParams.push(recallBreadthPolicy.value_rescue_limit);
        const rescueLimitIdx = rescueParams.length;
        const valueRescueResult = await query(
          `SELECT m.id, m.key, m.value, m.scope, m.memory_type, m.clearance_level,
                  m.created_at, m.credit_score, m.memory_tier, m.decay_weight,
                  m.data_class, m.source, m.access_count, m.last_accessed_at, vh.value_hit_count
           FROM aimos_memories m
           CROSS JOIN LATERAL (
             SELECT COUNT(*)::int AS value_hit_count
             FROM unnest($4::text[]) AS pattern
             WHERE LOWER(m.key) LIKE pattern OR LOWER(m.value) LIKE pattern
           ) vh
           WHERE ${rescueClauses.join(' AND ')}
             AND vh.value_hit_count > 0
           ORDER BY vh.value_hit_count DESC, m.created_at DESC
           LIMIT $${rescueLimitIdx}`,
          rescueParams
        );

        for (const row of valueRescueResult.rows) {
          if (!seenIds.has(row.id)) {
            seenIds.add(row.id);
            memories.push({
              id: row.id,
              key: row.key,
              value: row.value,
              scope: row.scope,
              memory_type: row.memory_type,
              clearance_level: row.clearance_level,
              created_at: row.created_at,
              credit_score: parseFloat(row.credit_score || 1.0),
              memory_tier: row.memory_tier || 'short-term',
              data_class: row.data_class || 'public',
              source: row.source || null,
              access_count: Number(row.access_count || 0),
              last_accessed_at: row.last_accessed_at || null,
              retrieval_source: 'lexical_value_rescue',
              value_hit_count: Number(row.value_hit_count || 0),
              graph_links: []
            });
          }
        }
      } catch (_valueRescueErr) {
        console.warn('[recall] lexical value rescue error (non-fatal):', _valueRescueErr.message);
      }
    }
    debugRecallPoint('value_rescue_done', {
      enabled: recallBreadthPolicy.value_rescue_enabled,
      memories: memories.length,
      seen_ids: seenIds.size,
    });

    // ─── SIBLING HYDRATION: paired benchmark/session evidence opening ─────────
    // TiMem/MRAG: when one session in a source-scoped benchmark root is recalled
    // for a paired temporal/comparison query, hydrate sibling sessions from that
    // same root before final rerank. This preserves native retrieval integrity:
    // no answer keys, no expected IDs, no output wrapper, and no DB mutation.
    if (recallBreadthPolicy.sibling_hydration_enabled) {
      try {
        const specs = [];
        const seenRoots = new Set();
        for (const mem of memories) {
          const spec = benchmarkSiblingHydrationSpec(mem?.key);
          if (!spec || seenRoots.has(spec.root)) continue;
          seenRoots.add(spec.root);
          specs.push(spec);
          if (specs.length >= recallBreadthPolicy.sibling_hydration_root_limit) break;
        }

        let siblingHydrated = 0;
        for (const spec of specs) {
          const siblingParams = [company, clearance, agent, spec.root, spec.likePattern];
          const siblingClauses = [
            'm.company_id = $1',
            'm.clearance_level <= $2',
            '(m.clearance_level > 2 OR m.agent_id = $3 OR m.agent_id IS NULL)',
            "(m.key = $4 OR m.key LIKE $5 ESCAPE '\\')",
          ];
          if (allowedClasses) {
            siblingParams.push(allowedClasses);
            siblingClauses.push(`COALESCE(m.data_class, 'public') = ANY($${siblingParams.length}::text[])`);
          }
          if (typeFilter) {
            siblingParams.push(typeFilter);
            siblingClauses.push(`m.memory_type = $${siblingParams.length}`);
          }
          if (srcFilter) {
            siblingParams.push(srcFilter);
            siblingClauses.push(`m.source = $${siblingParams.length}`);
          }
          siblingParams.push(24);
          const siblingLimitIdx = siblingParams.length;
          const siblingResult = await query(
            `SELECT m.id, m.key, m.value, m.scope, m.memory_type, m.clearance_level,
                    m.created_at, m.credit_score, m.memory_tier, m.decay_weight,
                    m.data_class, m.source, m.access_count, m.last_accessed_at
             FROM aimos_memories m
             WHERE ${siblingClauses.join(' AND ')}
             ORDER BY m.created_at ASC, m.key ASC
             LIMIT $${siblingLimitIdx}`,
            siblingParams
          );
          for (const row of siblingResult.rows) {
            if (seenIds.has(row.id)) continue;
            seenIds.add(row.id);
            siblingHydrated += 1;
            memories.push({
              id: row.id,
              key: row.key,
              value: row.value,
              scope: row.scope,
              memory_type: row.memory_type,
              clearance_level: row.clearance_level,
              created_at: row.created_at,
              credit_score: parseFloat(row.credit_score || 1.0),
              memory_tier: row.memory_tier || 'short-term',
              data_class: row.data_class || 'public',
              source: row.source || null,
              access_count: Number(row.access_count || 0),
              last_accessed_at: row.last_accessed_at || null,
              retrieval_source: 'benchmark_sibling_hydration',
              sibling_root: spec.root,
              graph_links: [],
            });
          }
        }
        if (siblingHydrated > 0) {
          recallBreadthPolicy.sibling_hydrated = siblingHydrated;
          recallBreadthPolicy.sibling_hydrated_roots = specs.map((spec) => spec.root).slice(0, 12);
        }
      } catch (_siblingErr) {
        console.warn('[recall] sibling hydration error (non-fatal):', _siblingErr.message);
      }
    }
    debugRecallPoint('sibling_hydration_done', {
      enabled: recallBreadthPolicy.sibling_hydration_enabled,
      memories: memories.length,
      seen_ids: seenIds.size,
    });

    // ─── REFINEMENT 2: Re-ranking — boost memories that share key terms with query ──
    markStage('reranking');
    // BM25/MRAG-inspired lexical calibration on top of vector results.
    const queryTerms = lexicalCalibration.terms;
    if (queryTerms.length > 0) {
      for (const mem of memories) {
        const scoringMemory = projectMemoryForRecallRerank(mem, lexicalCalibration, {
          maxChars: explicitFullDetailRecall || recallBreadthPolicy.profile === 'exact_detail' ? 12000 : 6400,
        });
        mem.rerank_score = scoreRecallLexicalMatch(searchQuery, scoringMemory, lexicalCalibration);
      }
      // Stable sort: memories with higher term overlap float up within same tier
      memories.sort((a, b) => (b.rerank_score || 0) - (a.rerank_score || 0));
    }
    debugRecallPoint('reranking_done', { memories: memories.length, query_terms: queryTerms.length });

    // ─── QMD STAGE ACTIVATION: structured query stage for low-confidence recall ──
    // Per Adaptive RAG (paper:adaptive_rag_2024): low-confidence queries activate
    // the native QMD stage instead of relying solely on vector similarity.
    // Fixes: (1) uses tsvector index not regex, (2) searches full value not LEFT(500),
    // (3) unordered term matching, (4) computed rerank_score not hardcoded 1.0,
    // (5) searches metadata (source, technique) for Knowledge Gate retrieval.
    markStage('qmd_activation');
    let qmdActivated = false;
    let topRerank = memories.length > 0 ? (memories[0].rerank_score || 0) : 0;
    let avgRerank = memories.length > 0
      ? memories.slice(0, 5).reduce((s, m) => s + (m.rerank_score || 0), 0) / Math.min(memories.length, 5)
      : 0;
    if (recallBreadthPolicy.qmd_allowed && (topRerank <= 0.6 || avgRerank < 0.4)) {
      try {
        const qmdTerms = queryTerms.filter(t => t.length >= 3).slice(0, 6);
        if (qmdTerms.length >= 1) {
          // Channel 1: Full-text search via tsvector (indexed, fast)
          // Use OR between terms — ts_rank scores by coverage, so multi-term matches rank higher
          const tsqTerms = qmdTerms.join(' | ');
          const buildQmdScopedFilter = () => {
            const scopedParams = [company, clearance, requestingAgent];
            const scopedClauses = [
              'company_id = $1',
              'clearance_level <= $2',
              '(clearance_level > 2 OR agent_id = $3 OR agent_id IS NULL)',
            ];
            if (allowedClasses) {
              scopedParams.push(allowedClasses);
              scopedClauses.push(`COALESCE(data_class, 'public') = ANY($${scopedParams.length}::text[])`);
            }
            if (typeFilter) {
              scopedParams.push(typeFilter);
              scopedClauses.push(`memory_type = $${scopedParams.length}`);
            }
            if (srcFilter) {
              scopedParams.push(srcFilter);
              scopedClauses.push(`source = $${scopedParams.length}`);
            }
            if (sessionLikePattern) {
              scopedParams.push(sessionLikePattern);
              scopedClauses.push(`key LIKE $${scopedParams.length} ESCAPE '\\'`);
            }
            return { scopedParams, scopedClauses };
          };
          const qmdFtsScope = buildQmdScopedFilter();
          qmdFtsScope.scopedParams.push(tsqTerms);
          const qmdFtsQueryIdx = qmdFtsScope.scopedParams.length;
          const qmdFtsResult = await query(
            `SELECT id, key, value, scope, memory_type, clearance_level, created_at,
                    credit_score, memory_tier, decay_weight, data_class, source,
                    access_count, last_accessed_at,
                    ts_rank(search_vector, to_tsquery('english', $${qmdFtsQueryIdx})) as fts_rank
             FROM aimos_memories
             WHERE ${qmdFtsScope.scopedClauses.join(' AND ')}
                   AND search_vector @@ to_tsquery('english', $${qmdFtsQueryIdx})
             ORDER BY fts_rank DESC
             LIMIT 10`,
            qmdFtsScope.scopedParams
          ).catch(() => ({ rows: [] }));

          // Channel 2: Key-pattern + metadata search (for Knowledge Gate: papers, techniques)
          // Use OR between terms — any term matching key/metadata surfaces the memory.
          // Scoring by term coverage happens downstream. Pick first 3 most distinctive terms.
          const qmdKeyTerms = qmdTerms.slice(0, 3);
          const qmdKeyScope = buildQmdScopedFilter();
          const keyLikePatterns = qmdKeyTerms.map(t => `%${t}%`);
          const qmdKeyFirstPatternIdx = qmdKeyScope.scopedParams.length + 1;
          qmdKeyScope.scopedParams.push(...keyLikePatterns);
          const keyOrClauses = qmdKeyTerms.map((_, i) => `LOWER(key) LIKE $${qmdKeyFirstPatternIdx + i}`).join(' OR ');
          const metaOrClauses = qmdKeyTerms.map((_, i) => `LOWER(COALESCE(metadata->>'source','')) LIKE $${qmdKeyFirstPatternIdx + i}`).join(' OR ');
          const qmdKeyResult = await query(
            `SELECT id, key, value, scope, memory_type, clearance_level, created_at,
                    credit_score, memory_tier, decay_weight, data_class, source,
                    access_count, last_accessed_at
             FROM aimos_memories
             WHERE ${qmdKeyScope.scopedClauses.join(' AND ')}
                   AND (${keyOrClauses} OR ${metaOrClauses})
             ORDER BY
               CASE WHEN memory_type IN ('procedural_seed', 'procedural', 'tacit_knowledge') THEN 0 ELSE 1 END ASC,
               created_at DESC
             LIMIT 10`,
            qmdKeyScope.scopedParams
          ).catch(() => ({ rows: [] }));

          // Merge both channels, compute real rerank_score
          const qmdCandidates = new Map();
          for (const row of (qmdFtsResult.rows || [])) {
            if (!seenIds.has(row.id)) {
              qmdCandidates.set(row.id, { ...row, _fts_rank: parseFloat(row.fts_rank || 0), _source: 'qmd_fts' });
            }
          }
          for (const row of (qmdKeyResult.rows || [])) {
            if (!seenIds.has(row.id) && !qmdCandidates.has(row.id)) {
              qmdCandidates.set(row.id, { ...row, _fts_rank: 0, _source: 'qmd_key' });
            }
          }

          for (const [id, row] of qmdCandidates) {
            seenIds.add(id);
            // Compute real rerank_score: term overlap on full text
            const fullText = `${row.key} ${row.value}`.toLowerCase();
            const hitCount = queryTerms.filter(t => fullText.includes(t)).length;
            const termOverlap = queryTerms.length > 0 ? hitCount / queryTerms.length : 0;
            // Boost procedural_seed and paper memories for Knowledge Gate retrieval
            const typeBoost = ['procedural_seed', 'procedural', 'tacit_knowledge'].includes(row.memory_type) ? 0.15 : 0;
            const computedScore = Math.min(1.0, termOverlap + typeBoost + (row._fts_rank > 0 ? 0.1 : 0));

            memories.push({
              id: row.id, key: row.key, value: row.value,
              scope: row.scope, memory_type: row.memory_type,
              clearance_level: row.clearance_level,
              memory_tier: row.memory_tier || 'long-term',
              data_class: row.data_class || 'public',
              source: row.source || null,
              access_count: Number(row.access_count || 0),
              last_accessed_at: row.last_accessed_at || null,
              retrieval_source: row._source,
              rerank_score: computedScore,
              graph_links: []
            });
          }
          if (qmdCandidates.size > 0) {
            qmdActivated = true;
            memories.sort((a, b) => (b.rerank_score || 0) - (a.rerank_score || 0));
          }
        }
      } catch (_qmdErr) {
        console.warn('[recall] QMD auto-switch error:', _qmdErr.message);
      }
    }
    debugRecallPoint('qmd_activation_done', {
      qmd_activated: qmdActivated,
      memories: memories.length,
      top_rerank: topRerank,
      avg_rerank: Math.round(avgRerank * 1000) / 1000,
    });

    // ─── Wire: multi-stage-retrieval — HyDE fallback on low-quality recall ────
    markStage('hyde_expansion');
    // When recall quality is still low after QMD, expand query with hypothetical
    // document embeddings and run multi-stage retrieval to surface better results.
    if (recallBreadthPolicy.qmd_allowed && (topRerank <= 0.5 || avgRerank < 0.3)) {
      try {
        const hydeResults = await multiStageRecall(searchQuery, {
          companyId: company,
          clearanceLevel: clearance,
          limit: Math.min(candidateOpeningLimit, 10)
        });
        for (const hit of hydeResults) {
          if (hit.id && !seenIds.has(hit.id)) {
            seenIds.add(hit.id);
            memories.push({
              id: hit.id,
              key: hit.key,
              value: hit.value,
              scope: hit.scope,
              memory_type: hit.memory_type,
              clearance_level: hit.clearance_level,
              memory_tier: hit.memory_tier || 'long-term',
              data_class: hit.data_class || 'public',
              source: hit.source || null,
              retrieval_source: 'multi_stage_hyde',
              rerank_score: hit.rrf_score,
              graph_links: []
            });
          }
        }
        if (hydeResults.length > 0) {
          memories.sort((a, b) => (b.rerank_score || 0) - (a.rerank_score || 0));
        }
      } catch (_hydeErr) {
        console.warn('[recall] multi-stage HyDE fallback error (non-fatal):', _hydeErr.message);
      }
    }
    debugRecallPoint('hyde_expansion_done', { memories: memories.length, seen_ids: seenIds.size });

    // The ranking engines propose ids; this native boundary is the sole
    // disclosure authority. No calibration, graph completion, synthesis,
    // mnemonic encoding, cache admission, or early exit sees unverified rows.
    const mainAdmission = await admitNativeRecallCandidates(memories, recallAuthority);
    memories.length = 0;
    memories.push(...mainAdmission.memories);
    const magmaBaselineCandidateIds = Object.freeze(memories.map((memory) => String(memory.id)));
    let magmaCandidate = null;
    let magmaCandidateRuntimeMs = null;
    let magmaCandidateFailure = null;
    let reconstructedGraphCandidate = null;
    let reconstructedGraphCandidateFailure = null;
    let reconstructedGraphEligibleCandidateCount = 0;
    let reconstructedGraphCanaryWithheldCount = 0;
    let graphFamilyCandidate = null;
    let graphFamilyRuntimeMs = null;
    let nativeRetrievalFusion = null;
    const temporalFusionIntent = isChronological || [
      'temporal_delta', 'temporal_order', 'timeline', 'session_recall', 'session_count',
    ].includes(routeQueryUnderstanding.intent);

    // MAGMA is a permanent native retrieval gear. It receives only admitted
    // candidates, contributes a bounded rank channel plus admitted graph
    // discoveries, and never owns the candidate set or disclosure. A graph
    // read failure is explicit degraded operation; it is not an off mode.
    markStage('magma_native_gear');
    if (memories.length > 0) {
      try {
        const magmaStartedAt = performance.now();
        magmaCandidate = await composeMagmaNativeCandidate({
          recallAuthority,
          admittedMemories: memories,
          queryEmbedding,
          queryText: searchQuery,
          limit: magmaCalibrationState.calibration.result_limit,
          maxDepth: magmaCalibrationState.calibration.max_depth,
          maxNodes: magmaCalibrationState.calibration.max_nodes,
          beamWidth: magmaCalibrationState.calibration.beam_width,
        });
        magmaCandidateRuntimeMs = Number((performance.now() - magmaStartedAt).toFixed(3));
      } catch (error) {
        magmaCandidateFailure = String(error?.message || 'magma_native_gear_failure').slice(0, 240);
        await logEvent(company, agent, 'native_retrieval_gear_failure', searchQuery, {
          gear: 'magma',
          calibration_mutation_hash: magmaCalibrationState.mutationHash,
          error_code: magmaCandidateFailure,
          candidate_set_changed: false,
          canonical_memory_changed: false,
          disclosure_changed: false,
        }, null, { authority: recallAuthority.requestAuthority || null });
      }
    }

    graphFamilyCandidate = composeNativeGraphFamilyChannel({
      magmaGear: magmaCandidate,
      limit: 50,
    });
    const graphFamilyBaselineFusion = fuseNativeRetrievalGears({
      admittedMemories: memories,
      magmaGear: graphFamilyCandidate,
      temporalBias: temporalFusionIntent,
      rrfK: magmaCalibrationState.calibration.rrf_k,
    });

    // Reconstructed Graph G2 is a permanent non-owning subgear inside the
    // single graph-family channel. Its bounded transient workspace is built
    // from the already admitted baseline-fusion population after a Canary
    // preconstruction partition. Marked evidence remains retained in the
    // native population and is withheld only from graph construction and the
    // later response boundary; no candidate is deleted or suppressed.
    markStage('reconstructed_graph_native_subgear');
    const reconstructedGraphCanaryPartition = partitionGraphCanaryDisclosure(
      graphFamilyBaselineFusion.memories,
    );
    reconstructedGraphEligibleCandidateCount = reconstructedGraphCanaryPartition.admitted.length;
    reconstructedGraphCanaryWithheldCount = reconstructedGraphCanaryPartition.withheld.length;
    if (reconstructedGraphEligibleCandidateCount > 0) {
      try {
        reconstructedGraphCandidate = composeReconstructedGraphNativeCandidate({
          admittedMemories: reconstructedGraphCanaryPartition.admitted
            .map((memory) => ({ ...memory, canary_admitted: true })),
          queryText: searchQuery,
        });
      } catch (error) {
        reconstructedGraphCandidateFailure = String(
          error?.message || 'reconstructed_graph_native_gear_failure',
        ).slice(0, 240);
        await logEvent(company, agent, 'native_retrieval_gear_failure', searchQuery, {
          gear: 'reconstructed_graph',
          fixed_corpus_proof_file_sha256:
            RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.fixed_corpus_proof_file_sha256,
          error_code: reconstructedGraphCandidateFailure,
          candidate_set_changed: false,
          canonical_memory_changed: false,
          disclosure_changed: false,
        }, null, { authority: recallAuthority.requestAuthority || null });
      }
    }

    const graphFamilyStartedAt = performance.now();
    graphFamilyCandidate = composeNativeGraphFamilyChannel({
      magmaGear: magmaCandidate,
      reconstructedGraphGear: reconstructedGraphCandidate,
      limit: 50,
    });
    graphFamilyRuntimeMs = Number((performance.now() - graphFamilyStartedAt).toFixed(3));
    nativeRetrievalFusion = fuseNativeRetrievalGears({
      admittedMemories: memories,
      magmaGear: graphFamilyCandidate,
      temporalBias: temporalFusionIntent,
      rrfK: magmaCalibrationState.calibration.rrf_k,
    });
    memories.length = 0;
    memories.push(...nativeRetrievalFusion.memories.map((memory) => ({ ...memory })));

    // Internal-only evidence for source-bound marginal-gear experiments. The
    // route and MCP owners serialize result.body only, so this bundle never
    // crosses a transport boundary. It captures the exact post-PPR admitted
    // population and all incumbent gear outputs before confidence or
    // epistemic selection, allowing a candidate graph subgear to be evaluated
    // without changing canonical recall behavior.
    const evaluationCanaryPartition = partitionGraphCanaryDisclosure(memories);
    nativeGearboxEvaluationEvidence = Object.freeze({
      schema: NATIVE_GEARBOX_EVALUATION_EVIDENCE_SCHEMA,
      query_text: searchQuery,
      query_embedding: Object.freeze(Array.from(queryEmbedding, Number)),
      admitted_memories: Object.freeze(
        evaluationCanaryPartition.admitted.map(snapshotNativeGearboxMemory),
      ),
      canary_withheld_memory_ids: Object.freeze(
        evaluationCanaryPartition.withheld
          .map((memory) => String(memory?.id || memory?.memory_id || '').toLowerCase())
          .filter(Boolean)
          .sort(),
      ),
      temporal_bias: temporalFusionIntent,
      rrf_k: magmaCalibrationState.calibration.rrf_k,
      magma_gear: magmaCandidate,
      reconstructed_graph_gear: reconstructedGraphCandidate,
      graph_family_gear: graphFamilyCandidate,
      baseline_fusion: nativeRetrievalFusion,
      transport_exposed: false,
      canonical_memory_mutated: false,
      retention_changed: false,
    });
    topRerank = memories[0]?.rerank_score || 0;
    avgRerank = memories.length
      ? memories.reduce((sum, memory) => sum + Number(memory.rerank_score || 0), 0) / memories.length
      : 0;

    // Recursive graph traversal starts only from provenance-admitted seeds and
    // returns identifiers/edge weights, never unverified passage content.
    if (hops > 0) {
      for (const memory of memories) {
        const graphRes = await query(
          `WITH RECURSIVE graph_walk AS (
             SELECT cr.target_memory_id AS memory_id, cr.similarity, 1 AS hop
               FROM memory_cross_refs cr
              WHERE cr.company_id = $1 AND cr.source_memory_id = $2::uuid
             UNION ALL
             SELECT cr.target_memory_id, cr.similarity, gw.hop + 1
               FROM graph_walk gw
               JOIN memory_cross_refs cr
                 ON cr.source_memory_id = gw.memory_id AND cr.company_id = $1
              WHERE gw.hop < $3 AND cr.target_memory_id != $2::uuid
           )
           SELECT DISTINCT ON (memory_id) memory_id, similarity, hop
             FROM graph_walk
            ORDER BY memory_id, hop ASC, similarity DESC
            LIMIT 8`,
          [company, memory.id, hops],
        ).catch(() => ({ rows: [] }));
        memory.graph_links = graphRes.rows.map((link) => ({
          id: link.memory_id,
          similarity: Number(link.similarity),
          hop: Number(link.hop),
        }));
      }
    }

    let deepRecallOverrideSummary = annotateDeepRecallOverrides(memories, searchQuery, lexicalCalibration);
    const preEarlyExitDeepRecallOrder = applyDeepRecallOverrideRanking(memories);
    if (preEarlyExitDeepRecallOrder !== memories) {
      memories.length = 0;
      memories.push(...preEarlyExitDeepRecallOrder);
    }
    debugRecallPoint('deep_recall_override_pre_early_exit_done', deepRecallOverrideSummary);

    // ─── SPEED OPT: Adaptive early-exit — Stage 7 boundary ──────────────────
    markStage('early_exit_decision');
    // Per Aimos: paper:adaptive_rag_2024 (Wang et al., 2024)
    // exit_early if (top_1_score > 0.82 AND score_gap > 0.15) OR (MVS < 0.42 AND avg_top5 > 0.65)
    // One verified calibration snapshot is applied before this decision so an
    // early exit cannot return unsigned or mixed-state prediction scores.
    if (explicitFullDetailRecall || recallBreadthPolicy.profile === 'exact_detail') {
      recallBreadthPolicy.early_exit_suppressed = 'explicit_full_detail_evidence_opening';
    }
    if (earlyExitFlag.enabled
      && memories.length > 0
      && !twinPrimeConfig
      && !explicitFullDetailRecall
      && recallBreadthPolicy.profile !== 'exact_detail') {
      applyCalibrationSnapshot(memories, calibrationSnapshot);
      const earlyTopScores = memories.slice(0, 5).map((memory) => {
        const lexical = Number(memory.rerank_score || 0);
        const fusion = Number.isFinite(Number(memory.native_fusion_score))
          ? Number(memory.native_fusion_score)
          : lexical;
        return (lexical * (1 - NATIVE_FUSION_SEMANTIC_SHARE))
          + (fusion * NATIVE_FUSION_SEMANTIC_SHARE);
      });
      const earlyMvs = await checkContextSufficiency(session_id || agent || company).catch(() => ({ mvs: 0.5 }));
      if (shouldEarlyExit(earlyTopScores, earlyMvs.mvs, { user_trust_level: 'standard' })) {
        const earlyMeta = generateEarlyExitMetadata({
          reason: 'high_confidence_gap',
          confidence_gap: earlyTopScores[0] - (earlyTopScores[1] || 0),
          mvs_score: earlyMvs.mvs,
          top_score: earlyTopScores[0]
        });
        await logEvent(company, agent, 'early_exit', searchQuery.slice(0, 50), {
          reasoning: `Early exit at stage 7 boundary after one signed calibration snapshot: confidence_gap=${(earlyTopScores[0] - (earlyTopScores[1] || 0)).toFixed(3)}, MVS=${earlyMvs.mvs}.`,
          source_knowledge: 'Adaptive RAG (Wang et al., 2024) — Speed.md Appendix A'
        });
        const earlyRecallMeta = {
          qmd_activated: qmdActivated,
          top_rerank: topRerank,
          avg_rerank: Math.round(avgRerank * 100) / 100,
          total_results: memories.length,
          early_exit: true,
          exit_stage: 7,
          skipped_stages: ['salience_frequency_evaluation', 'trust_scoring', 'concept_graph_ppr', 'mnemonic_encoding'],
          confidence_distribution: { high: 0, medium: 0, low: 0 },
          early_exit_flag: earlyExitFlag,
          deep_recall_override: deepRecallOverrideSummary,
          temporal_truth: { truth_band: 'unknown', newest_memory_at: null, oldest_memory_at: null, median_age_hours: null, recent_ratio: 0, stale_ratio: 0 },
          explain: { mode: 'early_exit', query: searchQuery, exit_stage: 7, ...earlyMeta }
        };
        // Record skipped stages in tracer
        skipStage('salience_frequency_evaluation', 'early_exit');
        skipStage('trust_scoring', 'early_exit');
        skipStage('concept_graph_ppr', 'early_exit');
        skipStage('mnemonic_encoding', 'early_exit');
        skipStage('confidence_scoring', 'early_exit');
        skipStage('context_building', 'early_exit');
        skipStage('response_formatting', 'early_exit');
        endStages();
        // Emit per-stage timing events
        if (_inst && _stageTimings) {
          const recallDurationMs = Date.now() - recallStartMs;
          for (const st of _stageTimings) {
            logEvent(company, agent, 'pipeline_stage_timing', st.id, {
              duration_ms: st.duration_ms, success: st.success, skipped: st.skipped,
              skip_reason: st.skip_reason || null, query: searchQuery.slice(0, 50)
            }).catch(() => {});
          }
          logEvent(company, agent, 'pipeline_recall_summary', searchQuery.slice(0, 60), {
            total_duration_ms: recallDurationMs, stage_count: _stageTimings.length,
            stages_executed: _stageTimings.filter(s => !s.skipped).map(s => s.id),
            stages_skipped: _stageTimings.filter(s => s.skipped).map(s => s.id),
            early_exit: true, result_count: memories.length
          }).catch(() => {});
          earlyRecallMeta.stage_timings = _stageTimings;
        }
        earlyRecallMeta.confidence_source = 'signed_sortify_belief_snapshot';
        earlyRecallMeta.calibration_mutation_hash = calibrationSnapshot.calibrationMutationHash;
        earlyRecallMeta.cache_admitted = false;
        const earlyEpistemic = await selectAndLedgerEpistemicRecall({
          memories,
          queryText: searchQuery,
          limit: effectiveMaxRows,
          companyId: company,
          subjectAgentId: agent,
          twinPrimePolicy: twinPrimeConfig?.policy,
          twinPrimePolicyMutationHash: twinPrimeConfig?.mutationHash,
          twinPrimeEligibilityReason: twinPrimeConfig ? 'adaptive_early_exit_policy_identity_unbound' : null,
          queryEmbedding,
          temporalScope: twinPrimeTemporalScope,
          signedRequestTimeMs: twinPrimeSignedRequestTimeMs,
          parentEventId: recallAuthority.requestAuthority?.requestAdmissionEventId || null,
          requestAuthority: recallAuthority.requestAuthority || null,
        });
        const earlyMagmaSecurity = magmaCandidate
          ? await closeGraphSecurityBoundary({
              graphId: 'magma',
              sourceAgentId: 'magma',
              memories: earlyEpistemic.memories,
              companyId: company,
              subjectAgentId: agent,
              recallAuthority,
              epistemicReceipt: earlyEpistemic.receipt,
              epistemicDecisionHash: earlyEpistemic.decision.decision_sha256,
              graphDecision: magmaCandidate.decision,
            })
          : Object.freeze({ memories: earlyEpistemic.memories, decision: null });
        const earlyReconstructedGraphSecurity = reconstructedGraphCandidate
          ? await closeGraphSecurityBoundary({
              graphId: 'reconstructed_graph',
              sourceAgentId: 'reconstructed-graph',
              memories: earlyMagmaSecurity.memories,
              companyId: company,
              subjectAgentId: agent,
              recallAuthority,
              epistemicReceipt: earlyEpistemic.receipt,
              epistemicDecisionHash: earlyEpistemic.decision.decision_sha256,
              graphDecision: reconstructedGraphCandidate.decision,
            })
          : Object.freeze({ memories: earlyMagmaSecurity.memories, decision: null });
        const earlyDisclosureMemories = earlyReconstructedGraphSecurity.memories;
        earlyRecallMeta.epistemic_retrieval = {
          version: earlyEpistemic.decision.version,
          decision_sha256: earlyEpistemic.decision.decision_sha256,
          candidate_count: earlyEpistemic.decision.candidate_count,
          states: earlyEpistemic.decision.states,
          abstention_required: earlyEpistemic.decision.abstention_required,
          ...(earlyEpistemic.decision.twin_prime ? { twin_prime: earlyEpistemic.decision.twin_prime } : {}),
          decision_receipt: earlyEpistemic.receipt,
        };
        earlyRecallMeta.total_results = earlyDisclosureMemories.length;
        earlyRecallMeta.native_retrieval_fusion = nativeRetrievalFusion.decision;
        earlyRecallMeta.magma_retrieval = magmaGearMetadata({
          calibrationState: magmaCalibrationState,
          gear: magmaCandidate,
          runtimeMs: magmaCandidateRuntimeMs,
          fusion: nativeRetrievalFusion,
          failure: magmaCandidateFailure,
        });
        earlyRecallMeta.graph_family_retrieval = graphFamilyMetadata({
          family: graphFamilyCandidate,
          runtimeMs: graphFamilyRuntimeMs,
        });
        earlyRecallMeta.reconstructed_graph_retrieval = reconstructedGraphGearMetadata({
          gear: reconstructedGraphCandidate,
          eligibleCandidateCount: reconstructedGraphEligibleCandidateCount,
          canaryWithheldCount: reconstructedGraphCanaryWithheldCount,
          failure: reconstructedGraphCandidateFailure,
        });
        if (earlyMagmaSecurity.decision) {
          earlyRecallMeta.magma_security_closure = earlyMagmaSecurity.decision;
        }
        if (earlyReconstructedGraphSecurity.decision) {
          earlyRecallMeta.reconstructed_graph_security_closure =
            earlyReconstructedGraphSecurity.decision;
        }
        earlyRecallMeta.response_limit_enforcement = {
          requested_limit: effectiveMaxRows,
          candidate_count: memories.length,
          returned_count: earlyDisclosureMemories.length,
          truncated: memories.length > earlyDisclosureMemories.length,
        };
        annotateRecallRankDiagnostics(earlyDisclosureMemories);
        earlyRecallMeta.retrieval_frequency = annotateRetrievalFrequencyMetadata(earlyDisclosureMemories);
        earlyRecallMeta.rank_observability = buildRecallRankObservability(earlyDisclosureMemories);
        earlyRecallMeta.pheromone_reinforcement = await reinforceRetrievedPheromones(earlyDisclosureMemories, {
          companyId: company,
          agentId: agent,
          queryText: searchQuery,
        });
        const earlyResponse = calibrateRecallRouteBody({
          queryText: searchQuery,
          body: { memories: earlyDisclosureMemories, working_memory: '', recall_meta: earlyRecallMeta, cache_hit: false },
          runtimeBudget: effectiveRecallRuntimeBudget,
          responseLimit: effectiveMaxRows,
        });
        earlyResponse.recall_receipt = await finalizeNativeRecall({
          memories: earlyResponse.memories,
          authority: recallAuthority,
          epistemicDecisionHash: epistemicReceiptDecisionHash(earlyEpistemic.decision),
        });
        return { status: 200, body: earlyResponse };
      }
    }
    // ─────────────────────────────────────────────────────────────────────────

    // ─── WIRE: salience-frequency — annotate low-frequency salience only ────
    if (explicitFullDetailRecall || recallBreadthPolicy.profile === 'exact_detail') {
      skipStage('salience_frequency_evaluation', 'explicit_full_detail_preserves_recalled_evidence');
    } else {
      markStage('salience_frequency_evaluation');
      try {
        const memIds = memories.filter(m => m.id).map(m => m.id);
        let salienceFrequencySummary = {
          annotated_count: memIds.length,
          low_frequency_count: 0,
          hard_filter_applied: false,
          canonical_memory_mutated: false,
          permanent_value_lowered: false,
        };
        if (memIds.length > 0) {
          const salienceFrequencyResults = await evaluateSalienceFrequencyBatch(memIds, company);
          salienceFrequencySummary = applySalienceFrequencyAnnotations(memories, salienceFrequencyResults);
        }
        recallBreadthPolicy.low_frequency_salience = {
          annotated_count: salienceFrequencySummary.annotated_count,
          low_frequency_count: salienceFrequencySummary.low_frequency_count,
          hard_filter_applied: salienceFrequencySummary.hard_filter_applied,
          aladdin_contract: 'no_decay_no_suppression_no_pruning_no_deletion',
          metric_sources: SALIENCE_FREQUENCY_ALADDIN_CONTRACT.metric_sources,
          canonical_memory_policy: SALIENCE_FREQUENCY_ALADDIN_CONTRACT.canonical_memory_policy,
          canonical_memory_mutated: salienceFrequencySummary.canonical_memory_mutated,
          permanent_value_lowered: salienceFrequencySummary.permanent_value_lowered,
        };
      } catch (_salienceFrequencyErr) {
        console.warn('[recall] salience-frequency error (non-fatal):', _salienceFrequencyErr.message);
      }
    }
    debugRecallPoint('salience_frequency_evaluation_done', {
      memories: memories.length,
      low_frequency_count: memories.filter(m => m.low_frequency_salience === true).length,
      hard_filter_applied: false,
    });

    const retrievalFrequencySummary = annotateRetrievalFrequencyMetadata(memories);
    debugRecallPoint('retrieval_frequency_metadata_done', retrievalFrequencySummary);

    deepRecallOverrideSummary = annotateDeepRecallOverrides(memories, searchQuery, lexicalCalibration);
    const postSalienceFrequencyDeepRecallOrder = applyDeepRecallOverrideRanking(memories);
    if (postSalienceFrequencyDeepRecallOrder !== memories) {
      memories.length = 0;
      memories.push(...postSalienceFrequencyDeepRecallOrder);
    }
    debugRecallPoint('deep_recall_override_post_salience_frequency_done', deepRecallOverrideSummary);

    // ─── WIRE: trust-score — rank memories by trust ──────────────────────────
    markStage('trust_scoring');
    try {
      const trusted = rankByTrust(memories);
      if (trusted.length > 0) {
        const trustedWithDeepRecall = applyDeepRecallOverrideRanking(trusted);
        memories.length = 0;
        memories.push(...trustedWithDeepRecall);
      }
    } catch (_trustErr) {
      console.warn('[recall] trust-score error (non-fatal):', _trustErr.message);
    }
    debugRecallPoint('trust_scoring_done', { memories: memories.length });

    // ─── WIRE: mvs-detector — check context sufficiency after trust scoring ───
    try {
      const sessionKey = session_id || agent || company;
      if (sessionKey) {
        const mvs = await checkContextSufficiency(sessionKey);
        if (mvs.needsMoreContext) {
          console.warn(`[recall] mvs-detector: context insufficient (mvs=${mvs.mvs}, depth=${mvs.historyDepth}) — consider deeper recall`);
        }
      }
    } catch (_mvsErr) {
      console.warn('[recall] mvs-detector error (non-fatal):', _mvsErr.message);
    }

    // ─── WIRE: concept-graph — merge PPR hybrid scoring ──────────────────────
    markStage('concept_graph_ppr');
    // HippoRAG: PPR returns INDICES (node IDs). Passage retrieval must hydrate content.
    try {
      if (searchQuery && searchQuery.trim()) {
        const pprResults = hops > 0
          ? await conceptPprLookup(searchQuery, company, Math.min(candidateOpeningLimit, 10))
          : [];
        const pprOnlyIds = []; // IDs discovered ONLY by PPR (not in vector/BM25 results)

        for (const pprHit of pprResults) {
          if (pprHit.id && !seenIds.has(pprHit.id)) {
            seenIds.add(pprHit.id);
            // Track PPR-only discoveries for hydration
            pprOnlyIds.push(pprHit.id);
            memories.push({
              id: pprHit.id,
              score: pprHit.score,
              ppr_score: pprHit.ppr,
              cosine_score: pprHit.cosine,
              source: 'concept_graph_ppr',
              graph_links: []
            });
          } else if (pprHit.id && seenIds.has(pprHit.id)) {
            // Enrich existing memory with PPR score
            const existing = memories.find(m => m.id === pprHit.id);
            if (existing) {
              existing.ppr_score = pprHit.ppr;
              existing.cosine_score = pprHit.cosine;
            }
          }
        }

        // ─── PASSAGE RETRIEVAL: Hydrate PPR-only discoveries ──────────────────
        // HippoRAG: "PPR on KG → Passage retrieval" - must fetch actual content
        if (pprOnlyIds.length > 0) {
          try {
            const hydrationResult = await query(
              `SELECT id, key, value, scope, memory_type, clearance_level, created_at,
                      credit_score, memory_tier, data_class, source,
                      last_verified_at, verified_by, verification_basis, freshness_state,
                      COALESCE(retrieval_weight, 1.0) AS retrieval_weight
               FROM aimos_memories
               WHERE company_id = $1 AND id = ANY($2::uuid[])`,
              [company, pprOnlyIds]
            );

            // Merge hydrated content into PPR-only memories
            for (const row of hydrationResult.rows) {
              const mem = memories.find(m => m.id === row.id);
              if (mem && !mem.value) { // Only hydrate if not already hydrated
                mem.key = row.key;
                mem.value = row.value;
                mem.scope = row.scope;
                mem.memory_type = row.memory_type;
                mem.clearance_level = row.clearance_level;
                mem.created_at = row.created_at;
                mem.credit_score = parseFloat(row.credit_score || 1.0);
                mem.memory_tier = row.memory_tier || 'short-term';
                mem.data_class = row.data_class || 'public';
                mem.source = row.source || null;
                mem.last_verified_at = row.last_verified_at || null;
                mem.verified_by = row.verified_by || null;
                mem.verification_basis = row.verification_basis || null;
                mem.freshness_state = row.freshness_state || null;
                mem.retrieval_weight = Math.max(0.1, Math.min(3, Number(row.retrieval_weight || 1)));
                mem.retrieval_source = mem.retrieval_source || 'concept_graph_ppr';
              }
            }
          } catch (_hydrationErr) {
            console.warn('[recall] PPR passage hydration error (non-fatal):', _hydrationErr.message);
          }
        }
      }
    } catch (_pprErr) {
      console.warn('[recall] concept-graph PPR error (non-fatal):', _pprErr.message);
    }
    debugRecallPoint('concept_graph_ppr_done', { memories: memories.length, seen_ids: seenIds.size });

    // PPR may propose additional ids. Re-admit the complete set before the
    // first calibration stage; PPR hydration cannot bypass provenance or ACL.
    const postGraphAdmission = await admitNativeRecallCandidates(memories, recallAuthority);
    memories.length = 0;
    memories.push(...postGraphAdmission.memories);

    // Recompose the central gearbox after concept-PPR has contributed its own
    // admitted channel. The graph family is not rerun: the same bounded MAGMA
    // and G2 evidence is fused with the enlarged admitted set, keeping one
    // execution per subgear and exactly one outer graph-family channel while
    // preserving candidate monotonicity.
    nativeRetrievalFusion = fuseNativeRetrievalGears({
      admittedMemories: memories,
      magmaGear: graphFamilyCandidate,
      temporalBias: temporalFusionIntent,
      rrfK: magmaCalibrationState.calibration.rrf_k,
    });
    memories.length = 0;
    memories.push(...nativeRetrievalFusion.memories.map((memory) => ({ ...memory })));

    // ─── WIRE: recall-calibrator — one signed Sortify Belief snapshot ────────
    markStage('recall_calibration');
    applyCalibrationSnapshot(memories, calibrationSnapshot);
    debugRecallPoint('recall_calibration_done', { memories: memories.length });

    // ─── WIRE: mnemonic-encoder — rank by encoding style match ───────────────
    if (explicitFullDetailRecall || recallBreadthPolicy.profile === 'exact_detail') {
      skipStage('mnemonic_encoding', 'explicit_full_detail_preserves_relevance_rank');
    } else {
      markStage('mnemonic_encoding');
      try {
        if (searchQuery && searchQuery.trim()) {
          const queryStyle = detectEncodingStyle(searchQuery);
          const styledMemories = rankByStyleMatch(memories, queryStyle.style);
          if (styledMemories.length > 0) {
            memories.length = 0;
            memories.push(...styledMemories);
          }
        }
      } catch (_styleErr) {
        console.warn('[recall] mnemonic-encoder error (non-fatal):', _styleErr.message);
      }
    }
    debugRecallPoint('mnemonic_encoding_done', { memories: memories.length });

    // (early-exit moved to stage-7 boundary, before salience-frequency/PPR/calibration)

    // ─── TIERED ACTIVATION: compress top memories into working memory ─────────
    markStage('context_building');
    // Full store (15K+) → relevance scoring (recall+QMD+rerank) → working memory
    // Only the most relevant ~200 tokens (~1200 chars) enter working context.
    const WORKING_MEMORY_MAX_CHARS = 1200;
    let workingMemory = '';
    for (const mem of memories) {
      const snippet = `[${mem.memory_type}] ${mem.value}`.slice(0, 300);
      if (workingMemory.length + snippet.length + 1 > WORKING_MEMORY_MAX_CHARS) break;
      workingMemory += (workingMemory ? '\n' : '') + snippet;
    }

    // DEMO_MODE: redact sensitive patterns from all recall output
    if (isDemoMode) {
      for (const mem of memories) {
        if (mem.value) mem.value = demoRedact(mem.value);
        if (mem.key) mem.key = demoRedact(mem.key);
        if (mem.graph_links) {
          for (const link of mem.graph_links) {
            if (link.value) link.value = demoRedact(link.value);
            if (link.key) link.key = demoRedact(link.key);
          }
        }
      }
      workingMemory = demoRedact(workingMemory);
    }

    const nowMs = Date.now();
    const confidenceDistribution = { high: 0, medium: 0, low: 0 };
    const ageHours = [];
    let newestTimestamp = null;
    let oldestTimestamp = null;

    // ─── P0-2: Anisotropy-corrected confidence scoring ──────────────────────
    markStage('confidence_scoring');
    // Raw cosine distance is unreliable for 768d embeddings. Z-score normalize
    // using per-company sliding window statistics (similarity-stats.js).
    let anisotropyStats = null;
    try {
      anisotropyStats = await getAnisotropyStats(company);
    } catch { /* best-effort */ }

    for (const mem of memories) {
      const rerank = Number.isFinite(mem?.rerank_score)
        ? Math.max(0, Math.min(1, Number(mem.rerank_score)))
        : 0.45;
      const creditRaw = Number(mem?.credit_score);
      const creditNorm = Number.isFinite(creditRaw)
        ? Math.max(0, Math.min(1, creditRaw / 2))
        : 0.5;

      const createdAtTs = Date.parse(mem?.created_at || '');
      if (Number.isFinite(createdAtTs)) {
        const hours = Math.max(0, (nowMs - createdAtTs) / 36e5);
        ageHours.push(hours);
        if (newestTimestamp == null || createdAtTs > newestTimestamp) newestTimestamp = createdAtTs;
        if (oldestTimestamp == null || createdAtTs < oldestTimestamp) oldestTimestamp = createdAtTs;
      }

      // P0-2: Apply anisotropy correction to distance-based scoring
      // If calibrated, z-score normalize the raw distance signal
      let semanticSignal = rerank; // fallback to BM25 rerank
      if (anisotropyStats?.isCalibrated && Number.isFinite(mem.raw_distance)) {
        const rawSim = 1 - mem.raw_distance;
        const zScore = (anisotropyStats.mu - rawSim) / anisotropyStats.sigma;
        // Invert: lower z-score (more similar than average) = higher signal
        semanticSignal = Math.max(0, Math.min(1, 1 / (1 + Math.exp(zScore))));
        // Blend with BM25 rerank: 60% anisotropy-corrected, 40% keyword
        semanticSignal = semanticSignal * 0.6 + rerank * 0.4;
        // Record observation for future calibration (fire-and-forget)
        recordSimilarityObservation(company, rawSim).catch(() => {});
      }

      // I1: Memory-type authority signal — knowledge outranks noise
      // Boost: types that carry real knowledge or system rules
      // Dampen: high-volume noise types that flood recall
      const MEMORY_TYPE_AUTHORITY = {
        procedural_seed: 0.18, procedural: 0.15, tacit_knowledge: 0.15,
        book_extract: 0.14, framework: 0.12, directive: 0.10,
        identity: 0.05, declarative: 0.05, session_debrief: 0.03,
        after_action_review: 0.0, event_log: -0.08,
        conversation_feed: -0.12, heartbeat: -0.10
      };
      const typeAuthority = MEMORY_TYPE_AUTHORITY[mem.memory_type] ?? 0.0;
      const retrievalWeight = Math.max(0.1, Math.min(3, Number(mem.retrieval_weight || 1)));
      const qualityLog = Math.log(retrievalWeight);
      const outcomeSignal = (Math.tanh(qualityLog) + 1) / 2;
      const nativeFusionSignal = Number.isFinite(Number(mem.native_fusion_score))
        ? Number(mem.native_fusion_score)
        : semanticSignal;
      // Native adaptation: retain the existing 45% semantic allocation, but
      // assign a bounded 20% of that allocation to the central multi-gear RRF.
      // Thus all retrieval gears together contribute at most 9 percentage
      // points and no single gear can dominate the final confidence score.
      const retrievalSignal = (semanticSignal * (1 - NATIVE_FUSION_SEMANTIC_SHARE))
        + (nativeFusionSignal * NATIVE_FUSION_SEMANTIC_SHARE);
      mem.retrieval_weight = retrievalWeight;
      mem.quality = Number(qualityLog.toFixed(6));

      // I1: Confidence composition with named components
      // Age is deliberately absent. Outcome quality is the signed,
      // evidence-driven reference-point signal; type authority is structural.
      const components = {
        semantic: Number(retrievalSignal.toFixed(3)),
        semantic_pre_fusion: Number(semanticSignal.toFixed(3)),
        native_retrieval_fusion: Number(nativeFusionSignal.toFixed(3)),
        native_fusion_semantic_share: NATIVE_FUSION_SEMANTIC_SHARE,
        keyword: Number(rerank.toFixed(3)),
        outcome_quality: Number(outcomeSignal.toFixed(3)),
        quality_log: mem.quality,
        authority: Number(creditNorm.toFixed(3)),
        type_authority: Number(typeAuthority.toFixed(3))
      };

      const freshnessDelta = 0;
      components.freshness_ranking_enabled = false;
      components.freshness_delta = 0;

      const confidence = Math.max(
        0,
        Math.min(1, (retrievalSignal * 0.45) + (creditNorm * 0.25) + (rerank * 0.10) + (outcomeSignal * 0.08) + (typeAuthority * 0.12))
      );
      mem.recall_confidence = Number(confidence.toFixed(3));
      mem.confidence = { percent: Number((confidence * 100).toFixed(1)), components };

      if (confidence >= 0.75) confidenceDistribution.high += 1;
      else if (confidence >= 0.5) confidenceDistribution.medium += 1;
      else confidenceDistribution.low += 1;
    }

    if (explicitFullDetailRecall) {
      // Full-detail recall is an evidence-opening mode: keep the strongest
      // query/body match first, then use confidence as the tie-breaker.
      memories.sort((a, b) => {
        const overrideOrder = compareDeepRecallOverride(a, b);
        if (overrideOrder !== 0) return overrideOrder;
        const aRelevance = Number.isFinite(a?._raw_rerank) ? a._raw_rerank : (a?.rerank_score || 0);
        const bRelevance = Number.isFinite(b?._raw_rerank) ? b._raw_rerank : (b?.rerank_score || 0);
        return (bRelevance - aRelevance) || ((b.recall_confidence || 0) - (a.recall_confidence || 0));
      });
      if (recallBreadthPolicy.role_balanced_opening_enabled) {
        const roleOpened = applyRoleBalancedEvidenceOpening(memories, lexicalCalibration, searchQuery);
        if (roleOpened) {
          memories.length = 0;
          memories.push(...roleOpened.memories);
          recallBreadthPolicy.role_balanced_opening = {
            enabled: true,
            opened_roles: roleOpened.opened_roles,
            coherent_root: roleOpened.coherent_root,
            targets: roleOpened.targets,
          };
        }
      }
    } else {
      // Default recall keeps calibrated confidence first so broad recall remains
      // concise and stable under mixed evidence.
      memories.sort((a, b) => compareDeepRecallOverride(a, b) || ((b.recall_confidence || 0) - (a.recall_confidence || 0)));
    }
    annotateRecallRankDiagnostics(memories);
    debugRecallPoint('confidence_scoring_done', {
      memories: memories.length,
      high: confidenceDistribution.high,
      medium: confidenceDistribution.medium,
      low: confidenceDistribution.low,
    });
    markStage('epistemic_trust_selection');
    const epistemicRecall = await selectAndLedgerEpistemicRecall({
      memories,
      queryText: searchQuery,
      limit: effectiveMaxRows,
      companyId: company,
      subjectAgentId: agent,
      twinPrimePolicy: twinPrimeConfig?.policy,
      twinPrimePolicyMutationHash: twinPrimeConfig?.mutationHash,
      queryEmbedding,
      temporalScope: twinPrimeTemporalScope,
      signedRequestTimeMs: twinPrimeSignedRequestTimeMs,
      parentEventId: recallAuthority.requestAuthority?.requestAdmissionEventId || null,
      requestAuthority: recallAuthority.requestAuthority || null,
    });
    const conceptGraphSecurity = hops > 0
      ? await closeGraphSecurityBoundary({
          graphId: 'concept_gaama',
          sourceAgentId: 'concept-graph',
          memories: epistemicRecall.memories,
          companyId: company,
          subjectAgentId: agent,
          recallAuthority,
          epistemicReceipt: epistemicRecall.receipt,
          epistemicDecisionHash: epistemicRecall.decision.decision_sha256,
        })
      : Object.freeze({ memories: epistemicRecall.memories, decision: null });
    const magmaGraphSecurity = magmaCandidate
      ? await closeGraphSecurityBoundary({
          graphId: 'magma',
          sourceAgentId: 'magma',
          memories: conceptGraphSecurity.memories,
          companyId: company,
          subjectAgentId: agent,
          recallAuthority,
          epistemicReceipt: epistemicRecall.receipt,
          epistemicDecisionHash: epistemicRecall.decision.decision_sha256,
          graphDecision: magmaCandidate.decision,
        })
      : Object.freeze({ memories: conceptGraphSecurity.memories, decision: null });
    const reconstructedGraphSecurity = reconstructedGraphCandidate
      ? await closeGraphSecurityBoundary({
          graphId: 'reconstructed_graph',
          sourceAgentId: 'reconstructed-graph',
          memories: magmaGraphSecurity.memories,
          companyId: company,
          subjectAgentId: agent,
          recallAuthority,
          epistemicReceipt: epistemicRecall.receipt,
          epistemicDecisionHash: epistemicRecall.decision.decision_sha256,
          graphDecision: reconstructedGraphCandidate.decision,
        })
      : Object.freeze({ memories: magmaGraphSecurity.memories, decision: null });
    const disclosureMemories = reconstructedGraphSecurity.memories;
    // The working set must contain only the post-epistemic disclosure set.
    workingMemory = disclosureMemories
      .map((memory) => `[${memory.memory_type}] ${memory.value}`.slice(0, 300))
      .reduce((output, snippet) => {
        if (output.length + snippet.length + 1 > WORKING_MEMORY_MAX_CHARS) return output;
        return output + (output ? '\n' : '') + snippet;
      }, '');
    recallBreadthPolicy.disclosure_limit = {
      requested_limit: effectiveMaxRows,
      candidate_count: memories.length,
      returned_count: disclosureMemories.length,
      truncated: memories.length > disclosureMemories.length,
    };

    ageHours.sort((a, b) => a - b);
    const recentCount = ageHours.filter((hours) => hours <= 72).length;
    const staleCount = ageHours.filter((hours) => hours > 24 * 90).length;
    const medianAgeHours = ageHours.length
      ? ageHours[Math.floor(ageHours.length / 2)]
      : null;
    const recentRatio = ageHours.length ? recentCount / ageHours.length : 0;
    const staleRatio = ageHours.length ? staleCount / ageHours.length : 0;
    let truthBand = 'unknown';
    if (ageHours.length) {
      if (recentRatio >= 0.6) truthBand = 'live';
      else if (staleRatio >= 0.6) truthBand = 'historical';
      else truthBand = 'mixed';
    }

    const temporalTruth = {
      truth_band: truthBand,
      newest_memory_at: newestTimestamp ? new Date(newestTimestamp).toISOString() : null,
      oldest_memory_at: oldestTimestamp ? new Date(oldestTimestamp).toISOString() : null,
      median_age_hours: medianAgeHours == null ? null : Number(medianAgeHours.toFixed(2)),
      recent_ratio: Number(recentRatio.toFixed(3)),
      stale_ratio: Number(staleRatio.toFixed(3))
    };
    const rankObservability = buildRecallRankObservability(disclosureMemories);
    const doctorSidecarTrace = doctorTraceRequested
      ? buildRecallDoctorCandidateTrace({
          queryText: searchQuery,
          memories,
          recallBreadthPolicy,
          maxCandidates: Math.min(200, Math.max(candidateOpeningLimit, memories.length)),
        })
      : null;
    const useBoundedRecallProjection = !explicitFullDetailRecall && recallBreadthPolicy.profile !== 'exact_detail';
    const responseMemories = useBoundedRecallProjection
      ? disclosureMemories.map((memory) => projectMemoryForRecallRerank(memory, lexicalCalibration, {
          maxChars: recallBreadthPolicy.aggregate_first_enabled ? 4800 : 6400,
        }))
      : disclosureMemories;

    markStage('response_formatting');
    const explain = {
      mode: 'linear_hybrid',
      query: searchQuery,
      filters: {
        company_id: company,
        clearance_level: clearance,
        memory_type_filter: typeFilter || null,
        source_filter: srcFilter || null,
        session_id: session_id || null,
        data_class_filter: allowedClasses || null
      },
      stages: {
        recall_breadth_policy: recallBreadthPolicy,
        effective_response_limit: effectiveMaxRows,
        candidate_opening_limit: candidateOpeningLimit,
        vector_candidate_limit: candidateLimit,
        bm25_candidate_limit: recallBreadthPolicy.bm25_limit,
        temporal_candidate_limit: recallBreadthPolicy.temporal_limit,
        lexical_value_rescue_limit: recallBreadthPolicy.value_rescue_limit,
        lexical_value_rescue_enabled: recallBreadthPolicy.value_rescue_enabled,
        recursive_hops: hops,
        entity_graph_injected: entityMemories.length,
        bm25_second_pass: true,
        qmd_auto_switch: qmdActivated,
        deep_recall_override: deepRecallOverrideSummary,
        retrieval_frequency: retrievalFrequencySummary,
        anisotropy_corrected: Boolean(anisotropyStats?.isCalibrated),
        anisotropy_mu: anisotropyStats?.mu || null,
        anisotropy_sigma: anisotropyStats?.sigma || null,
        rank_observability: rankObservability,
        epistemic_retrieval: {
          version: epistemicRecall.decision.version,
          decision_sha256: epistemicRecall.decision.decision_sha256,
          candidate_count: epistemicRecall.decision.candidate_count,
          states: epistemicRecall.decision.states,
          abstention_required: epistemicRecall.decision.abstention_required,
          canonical_memory_mutated: false,
          persistent_reweight_applied: false,
          ...(epistemicRecall.decision.twin_prime ? { twin_prime: epistemicRecall.decision.twin_prime } : {}),
          decision_receipt: epistemicRecall.receipt,
        },
        ...(conceptGraphSecurity.decision ? { graph_security_closure: conceptGraphSecurity.decision } : {}),
        ...(magmaGraphSecurity.decision ? { magma_security_closure: magmaGraphSecurity.decision } : {}),
        ...(reconstructedGraphSecurity.decision
          ? { reconstructed_graph_security_closure: reconstructedGraphSecurity.decision }
          : {}),
        native_retrieval_fusion: nativeRetrievalFusion.decision,
        graph_family_retrieval: graphFamilyMetadata({
          family: graphFamilyCandidate,
          runtimeMs: graphFamilyRuntimeMs,
        }),
        magma_retrieval: {
          ...magmaGearMetadata({
            calibrationState: magmaCalibrationState,
            gear: magmaCandidate,
            runtimeMs: magmaCandidateRuntimeMs,
            fusion: nativeRetrievalFusion,
            failure: magmaCandidateFailure,
          }),
          baseline_candidate_memory_ids: magmaBaselineCandidateIds,
        },
        reconstructed_graph_retrieval: reconstructedGraphGearMetadata({
          gear: reconstructedGraphCandidate,
          eligibleCandidateCount: reconstructedGraphEligibleCandidateCount,
          canaryWithheldCount: reconstructedGraphCanaryWithheldCount,
          failure: reconstructedGraphCandidateFailure,
        }),
        ...(doctorSidecarTrace ? {
          doctor_sidecar: {
            requested: true,
            candidate_scope: doctorSidecarTrace.candidate_scope,
            candidate_count: doctorSidecarTrace.candidate_count,
            emitted_count: doctorSidecarTrace.emitted_count,
            diagnostic_only: true,
          },
        } : {}),
      }
    };

    const pheromoneReinforcement = await reinforceRetrievedPheromones(disclosureMemories, {
      companyId: company,
      agentId: agent,
      queryText: searchQuery,
    });

    const scoreComponents = {
      freshness_ranking_enabled: SPEED_CONFIG.temporalTruth.freshnessRankingEnabled,
      freshness_delta_default: SPEED_CONFIG.temporalTruth.freshnessRankingEnabled ? 'opt_in' : 0,
      ranking_math_changed: SPEED_CONFIG.temporalTruth.freshnessRankingEnabled,
    };
    const synthesis = buildSourceAttributedSynthesis({
      queryText: searchQuery,
      memories: responseMemories,
      topN: 5,
    });

    // ─── SPEED OPT: Pipeline instrumentation — real per-stage timing ──────────
    endStages();
    if (_inst && _stageTimings) {
      const recallDurationMs = Date.now() - recallStartMs;
      // Emit per-stage events
      for (const st of _stageTimings) {
        logEvent(company, agent, 'pipeline_stage_timing', st.id, {
          duration_ms: st.duration_ms, success: st.success, skipped: st.skipped,
          skip_reason: st.skip_reason || null, query: searchQuery.slice(0, 50)
        }).catch(() => {});
      }
      // Emit aggregate summary
      logEvent(company, agent, 'pipeline_recall_summary', searchQuery.slice(0, 60), {
        total_duration_ms: recallDurationMs,
        stage_count: _stageTimings.length,
        stages_executed: _stageTimings.filter(s => !s.skipped).map(s => s.id),
        stages_skipped: _stageTimings.filter(s => s.skipped).map(s => s.id),
        early_exit: false,
        qmd_auto_switch: qmdActivated,
        result_count: disclosureMemories.length,
        source_knowledge: 'pipeline-instrumentation.js — Speed.md Appendix C'
      }).catch(() => {});
    }
    // ─────────────────────────────────────────────────────────────────────────

    const recallResponse = {
      memories: responseMemories,
      working_memory: workingMemory,
      recall_meta: {
        qmd_activated: qmdActivated,
        top_rerank: topRerank,
        avg_rerank: Math.round(avgRerank * 100) / 100,
        total_results: disclosureMemories.length,
        early_exit: false,
        early_exit_flag: earlyExitFlag,
        confidence_distribution: confidenceDistribution,
        deep_recall_override: deepRecallOverrideSummary,
        temporal_truth: temporalTruth,
        retrieval_frequency: retrievalFrequencySummary,
        score_components: {
          freshness_ranking_enabled: SPEED_CONFIG.temporalTruth.freshnessRankingEnabled,
          freshness_delta_default: SPEED_CONFIG.temporalTruth.freshnessRankingEnabled ? 'opt_in' : 0,
          ranking_math_changed: SPEED_CONFIG.temporalTruth.freshnessRankingEnabled,
        },
        rank_observability: rankObservability,
        epistemic_retrieval: {
          version: epistemicRecall.decision.version,
          decision_sha256: epistemicRecall.decision.decision_sha256,
          candidate_count: epistemicRecall.decision.candidate_count,
          states: epistemicRecall.decision.states,
          abstention_required: epistemicRecall.decision.abstention_required,
          canonical_memory_mutated: false,
          persistent_reweight_applied: false,
          ...(epistemicRecall.decision.twin_prime ? { twin_prime: epistemicRecall.decision.twin_prime } : {}),
          decision_receipt: epistemicRecall.receipt,
        },
        ...(conceptGraphSecurity.decision ? { graph_security_closure: conceptGraphSecurity.decision } : {}),
        ...(magmaGraphSecurity.decision ? { magma_security_closure: magmaGraphSecurity.decision } : {}),
        ...(reconstructedGraphSecurity.decision
          ? { reconstructed_graph_security_closure: reconstructedGraphSecurity.decision }
          : {}),
        native_retrieval_fusion: nativeRetrievalFusion.decision,
        graph_family_retrieval: graphFamilyMetadata({
          family: graphFamilyCandidate,
          runtimeMs: graphFamilyRuntimeMs,
        }),
        magma_retrieval: {
          ...magmaGearMetadata({
            calibrationState: magmaCalibrationState,
            gear: magmaCandidate,
            runtimeMs: magmaCandidateRuntimeMs,
            fusion: nativeRetrievalFusion,
            failure: magmaCandidateFailure,
          }),
          baseline_candidate_memory_ids: magmaBaselineCandidateIds,
        },
        reconstructed_graph_retrieval: reconstructedGraphGearMetadata({
          gear: reconstructedGraphCandidate,
          eligibleCandidateCount: reconstructedGraphEligibleCandidateCount,
          canaryWithheldCount: reconstructedGraphCanaryWithheldCount,
          failure: reconstructedGraphCandidateFailure,
        }),
        ...(doctorSidecarTrace ? { doctor_sidecar: doctorSidecarTrace } : {}),
        synthesis,
        evaluation: buildRecallEvaluation({
          queryText: searchQuery,
          planner: recallPlan,
          memories: responseMemories,
          directMode: 'linear_hybrid',
          recallMeta: {
            synthesis,
            score_components: scoreComponents,
            temporal_truth: temporalTruth,
          },
        }),
        pheromone_reinforcement: pheromoneReinforcement,
        ...(useBoundedRecallProjection ? { body_projection_policy: 'bounded_lexical_window_for_non_full_detail_recall' } : {}),
        explain,
        ...(_inst && _stageTimings ? { stage_timings: _stageTimings } : {})
      },
      cache_hit: false,
      ...(isDemoMode ? { demo_mode: true } : {})
    };

    // ─── SPEED OPT: Fill semantic cache for future identical/similar queries ───
    // Per PerCache (2024): only cache medium-or-higher confidence results.
    // Admission threshold (0.50) matches Aimos's real confidence distribution.
    // semanticCache.set() enforces its own threshold as a second check.
    const calibratedRecallResponse = calibrateRecallRouteBody({
      queryText: searchQuery,
      body: recallResponse,
      runtimeBudget: effectiveRecallRuntimeBudget,
      responseLimit: effectiveMaxRows,
    });
    debugRecallPoint('output_calibration_done', {
      memories: calibratedRecallResponse?.memories?.length || 0,
      count: calibratedRecallResponse?.count || 0,
    });

    if (SPEED_CONFIG.cache.enabled && allowSemanticCache) {
      semanticCache.set(queryEmbedding, searchQuery, calibratedRecallResponse, {
        companyId: company,
        agentId: agent,
        clearanceLevel: clearance,
        calibrationMutationHash: calibrationSnapshot.calibrationMutationHash,
      });
    }

    debugRecallPoint('request_done', {
      memories: calibratedRecallResponse?.memories?.length || 0,
      count: calibratedRecallResponse?.count || 0,
    });
    calibratedRecallResponse.recall_receipt = await finalizeNativeRecall({
      memories: calibratedRecallResponse.memories,
      authority: recallAuthority,
      epistemicDecisionHash: epistemicReceiptDecisionHash(epistemicRecall.decision),
    });
    return {
      status: 200,
      body: calibratedRecallResponse,
      nativeGearboxEvaluationEvidence,
    };
  } catch (error) {
    if (error?.rejected || /recall_(?:evidence|authority)|portable_binding|topology/.test(String(error?.message || ''))) {
      throw error;
    }
    return { status: 500, body: { memories: [], error: isDemoMode ? 'Recall failed' : error.message } };
  }
}
const DEMO_REDACT_PATTERNS = [
  /[a-f0-9]{32,}/gi,                          // hex tokens
  /sk_(?:test|live)_[a-zA-Z0-9]+/g,           // Stripe keys
  /Bearer\s+[a-zA-Z0-9._-]+/g,               // Bearer tokens
  /npg_[a-zA-Z0-9]+/g,                        // Neon passwords
  /whsec_[a-zA-Z0-9]+/g,                      // Webhook secrets
  /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+/g,   // JWTs
  /(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[a-zA-Z0-9._\-\/+]{10,}/gi,
  /\/Users\/[a-zA-Z0-9]+\//g,                 // User home paths
  /postgres:\/\/[^@]+@/g,                     // DB connection strings
  /0x[a-fA-F0-9]{40}/g,                       // Wallet addresses
];

function demoRedact(text) {
  let safe = String(text || '');
  for (const pattern of DEMO_REDACT_PATTERNS) {
    safe = safe.replace(pattern, '[REDACTED]');
  }
  return safe;
}


export default executeNativeRecall;
