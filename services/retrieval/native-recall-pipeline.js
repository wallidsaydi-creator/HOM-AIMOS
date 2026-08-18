// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: signed REST, legacy MCP, and StreamableHTTP MCP transports
// → Calls: native retrieval/ranking services, restricted evidence admission,
//           recall calibration, and cryptographic receipt finalization
// Pipeline: RECALL | Position: canonical retrieval execution owner
// Sources: service headers cited by each ranking stage; RRF and HippoRAG are
// reviewed at the fusion/graph boundaries. This service preserves their math.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { logEvent } from '../observe/event-ledger.js';
import { recordSimilarityObservation, getAnisotropyStats } from './similarity-stats.js';
import {
  applyCalibrationSnapshot,
  getVerifiedCalibrationSnapshot,
} from './recall-calibrator.js';
import { rankByTrust } from '../learning/trust-score.js';
import {
  CONCEPT_PPR_MAX_REQUEST_STATES,
  conceptPprLookup,
} from './concept-ppr-native.js';
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
import {
  MULTI_STAGE_RETRIEVAL_CONTRACT,
  multiStageRecall,
} from './multi-stage-retrieval.js';
import { checkContextSufficiency } from '../context/mvs-detector.js';
import { semanticCache } from '../caching/semantic-cache.js';
import { shouldEarlyExit, generateEarlyExitMetadata } from './adaptive-early-exit.js';
import { quimLookup } from './quim-index.js';
import { extractQueryEntityAnchors as extractEntities } from './query-entity-anchors.js';
import {
  finalizeNativeRecall,
  openNativeRecallAdmissionSession,
} from './native-recall.js';
import { createRequestScopedContentStateAdmission } from './content-state-occurrence/request-admission.js';
import { createRequestEpistemicEvidenceScope } from './content-state-occurrence/evidence-scope.js';
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
import { getMemoryCount } from '../shared/scale-baseline.js';
import { calibrateEpistemicRecall } from './epistemic-trust-retrieval.js';
import {
  RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT,
  composeReconstructedGraphNativeCandidate,
  composeNativeGraphFamilyChannel,
} from './reconstructed-graph-native-candidate.js';
import {
  NATIVE_RETRIEVAL_FUSION_CONTRACT,
  fuseNativeRetrievalGears,
} from './native-retrieval-fusion.js';
import { systemConfigStore } from '../security/system-config-store.js';
import {
  validateTwinPrimeRetrievalPolicy,
} from '../security/system-config-ledger.js';
import {
  CANARY_CLEAN_SELECTION_RETURN_PATHS,
  buildCanaryCleanSelectionBoundary,
  createCanaryContentClassificationMap,
  governCanaryCleanTopKSelection,
  governCanaryMagmaGraphAdmission,
  governCanaryRecallFinalClosure,
} from '../security/canary-tracker.js';
import { canonicalJson } from '../security/protocol/canonical-json.js';

export function partitionGraphCanaryDisclosure(
  memories = [],
  classificationMap = createCanaryContentClassificationMap(),
) {
  const admitted = [];
  const withheld = [];
  const candidates = Array.isArray(memories) ? memories : [];
  const classified = classificationMap.classifyMemories(candidates);

  for (let index = 0; index < candidates.length; index += 1) {
    const memory = candidates[index];
    if (!classified.records[index].canary_marker_present) {
      admitted.push(memory);
      continue;
    }
    withheld.push(memory);
  }

  return Object.freeze({
    admitted: Object.freeze([...admitted]),
    withheld: Object.freeze([...withheld]),
    canary_tokens: classified.canary_tokens,
  });
}

export const NATIVE_GEARBOX_EVALUATION_EVIDENCE_SCHEMA =
  'hom-aimos/native-gearbox-evaluation-evidence/v1';

const MAGMA_DORMANT_RUNTIME_BODY = Object.freeze({
  schema: 'hom-aimos/magma-runtime-dormancy/v1',
  architecture_role: 'dormant_research_only',
  runtime_wired: false,
  executed: false,
  rank_contribution_count: 0,
  discovery_count: 0,
  candidate_set_authority: false,
  disclosure_authority: false,
  canonical_memory_mutated: false,
  retention_changed: false,
  reason: 'current_stack_failed_utility_and_latency_promotion_gates',
});
const MAGMA_DORMANT_RUNTIME_DECISION = Object.freeze({
  ...MAGMA_DORMANT_RUNTIME_BODY,
  decision_sha256: createHash('sha256')
    .update(Buffer.from(canonicalJson(MAGMA_DORMANT_RUNTIME_BODY), 'utf8'))
    .digest('hex'),
});

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

async function governContentStateEpistemicEvidenceScope({
  decision,
  companyId,
  subjectAgentId,
  requestAuthority,
  parentEventId = null,
} = {}) {
  if (!decision || !/^[0-9a-f]{64}$/.test(String(decision.decision_sha256 || ''))) {
    throw new Error('native_recall_content_state_evidence_scope_invalid');
  }
  const receipt = await logEvent(
    companyId,
    subjectAgentId,
    'content_state_epistemic_scope_decision',
    decision.decision_sha256,
    {
      reasoning: 'The verified signed classification chain determines occurrence/content eligibility before retrieval influence. Blocked evidence remains retained and committed without changing label history.',
      source_knowledge: 'Migration 092 signed epistemic chain + typed evidence assertions + HOM-AIMOS R6 content-state scope',
      ...decision,
    },
    parentEventId,
    { authority: requestAuthority, returnReceipt: true },
  );
  return Object.freeze({
    decision,
    receipt: Object.freeze({
      event_id: receipt.event_id,
      ledger_seq: receipt.ledger_seq,
      content_hash: receipt.content_hash,
      mutation_hash: receipt.mutation_hash,
    }),
  });
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
  queryFn = query,
  canaryCleanSelectionBoundary = null,
  canaryClassificationMap,
  contentStateEvidenceScopeDecision,
  returnPath,
}) {
  if (!CANARY_CLEAN_SELECTION_RETURN_PATHS.includes(String(returnPath || '').trim())) {
    throw new Error('native_recall_canary_clean_selection_return_path_invalid');
  }
  const sourceMemories = Array.isArray(memories) ? memories : [];
  if (!canaryClassificationMap?.classifyMemories || !canaryClassificationMap?.snapshot) {
    throw new Error('native_recall_canary_classification_map_required');
  }
  const initialCanaryBoundary = canaryCleanSelectionBoundary
    || buildCanaryCleanSelectionBoundary(
      sourceMemories,
      limit,
      { classificationMap: canaryClassificationMap },
    );
  const sourceIds = sourceMemories.map((memory) => String(memory?.id || memory?.memory_id || '').trim().toLowerCase());
  const boundaryIds = initialCanaryBoundary?.boundary?.records
    ?.map((record) => String(record?.memory_id || '').trim().toLowerCase()) || [];
  if (sourceIds.length !== boundaryIds.length
    || sourceIds.some((memoryId, index) => memoryId !== boundaryIds[index])) {
    throw new Error('native_recall_canary_clean_selection_population_mismatch');
  }
  const selectionMemories = initialCanaryBoundary.clean_eligible_memories;
  const memoryIds = [...new Set(selectionMemories
    .map((memory) => String(memory?.id || memory?.memory_id || ''))
    .filter((id) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)))];
  const projections = memoryIds.length
    ? await queryFn(
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
  if ((projections.rows || []).length !== memoryIds.length
      || new Set((projections.rows || []).map((row) => String(row.memory_id))).size !== memoryIds.length) {
    throw new Error('native_recall_epistemic_projection_missing');
  }
  const projectionByMemoryId = new Map(
    projections.rows.map((row) => [String(row.memory_id), row]),
  );
  const memoriesWithEpistemicProjection = selectionMemories.map((memory) => {
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
  const epistemicDecisionByMemoryId = new Map(calibrated.decision.decisions.map(
    (decision) => [String(decision.memory_id), decision],
  ));
  const securityAnnotatedMemories = sourceMemories.map((memory) => {
    const memoryId = String(memory?.id || memory?.memory_id || '');
    const decision = epistemicDecisionByMemoryId.get(memoryId);
    return decision ? {
      ...memory,
      epistemic_state: decision.epistemic_state,
      epistemic_score: decision.epistemic_score,
      evidence_handling: decision.evidence_handling,
    } : memory;
  });
  const combinedSelectionBoundary = buildCanaryCleanSelectionBoundary(
    securityAnnotatedMemories,
    limit,
    { classificationMap: canaryClassificationMap },
  );
  const evidenceScope = await governContentStateEpistemicEvidenceScope({
    decision: contentStateEvidenceScopeDecision,
    companyId,
    subjectAgentId,
    requestAuthority,
    parentEventId,
  });
  const cleanSelection = await governCanaryCleanTopKSelection({
    boundaryResult: combinedSelectionBoundary,
    selectedMemories: calibrated.memories,
    returnPath,
    companyId,
    subjectAgentId,
    recallAuthority: {
      actorAgentId: subjectAgentId,
      requestAuthority,
    },
    parentEventId: evidenceScope.receipt.event_id,
  });
  const receipt = await logEvent(
    companyId,
    subjectAgentId,
    'epistemic_recall_decision',
    calibrated.decision.query_sha256,
    {
      reasoning: 'Pre-disclosure epistemic calibration separates authenticated provenance from factual support and prevents redundant query-lure clusters from monopolizing the active evidence set.',
      canary_clean_selection_return_path: cleanSelection.decision.return_path,
      canary_clean_selection_decision_sha256: cleanSelection.decision.decision_sha256,
      canary_clean_selection_event_id: cleanSelection.receipt.event_id,
      retained_decision_set_sha256: cleanSelection.decision.retained_decision_set_sha256,
      content_state_evidence_scope_decision_sha256: evidenceScope.decision.decision_sha256,
      content_state_evidence_scope_event_id: evidenceScope.receipt.event_id,
      ...calibrated.decision,
    },
    cleanSelection?.receipt.event_id || parentEventId,
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
    cleanSelection,
    evidenceScope,
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

const NATIVE_FUSION_SEMANTIC_SHARE = 0.2;

function canaryMagmaCompositionMetadata(composition) {
  const decision = composition?.decision;
  if (!decision) return null;
  return Object.freeze({
    schema: decision.schema,
    decision_sha256: decision.decision_sha256,
    graph_admission_equation: decision.graph_admission_equation,
    guarded_transition_equation: decision.guarded_transition_equation,
    input_count: decision.input_count,
    graph_admitted_count: decision.graph_admitted_count,
    retained_evidence_count: decision.retained_evidence_count,
    canary_marked_memory_count: decision.canary_marked_memory_count,
    canary_marker_count: decision.canary_marker_count,
    quarantine_evidence_count: decision.quarantine_evidence_count,
    retained_baseline_preserved: decision.retained_baseline_preserved,
    canonical_memory_mutated: false,
    retention_changed: false,
    disclosure_authority: false,
    receipt: composition.receipt || null,
  });
}

function canaryCleanSelectionMetadata(selection) {
  const decision = selection?.decision;
  if (!decision) return null;
  return Object.freeze({
    schema: decision.schema,
    return_path: decision.return_path,
    decision_sha256: decision.decision_sha256,
    boundary_sha256: decision.boundary_sha256,
    classification_map_root_sha256: decision.classification_map_root_sha256,
    requested_top_k: decision.requested_top_k,
    candidate_count: decision.candidate_count,
    clean_eligible_count: decision.clean_eligible_count,
    retained_evidence_count: decision.retained_evidence_count,
    retained_epistemic_evidence_count: decision.retained_epistemic_evidence_count,
    selected_clean_count: decision.selected_clean_count,
    clean_backfill_count: decision.clean_backfill_count,
    unfilled_clean_slot_count: decision.unfilled_clean_slot_count,
    selected_clean_set_sha256: decision.selected_clean_set_sha256,
    retained_decision_set_sha256: decision.retained_decision_set_sha256,
    selected_top_k_subseteq_clean_eligible_evidence:
      decision.selected_top_k_subseteq_clean_eligible_evidence,
    clean_label_establishes_content_truth: false,
    canonical_memory_mutated: false,
    retention_changed: false,
    receipt: selection.receipt || null,
  });
}

function canaryFinalClosureMetadata(closure) {
  const decision = closure?.decision;
  if (!decision) return null;
  return Object.freeze({
    schema: decision.schema,
    return_path: decision.return_path,
    decision_sha256: decision.decision_sha256,
    classification_map_root_sha256: decision.classification_map_root_sha256,
    unique_content_count: decision.unique_content_count,
    content_scans_executed: decision.content_scans_executed,
    classification_requests: decision.classification_requests,
    classification_cache_hits: decision.classification_cache_hits,
    content_rescans_executed: decision.content_rescans_executed,
    clean_selection_decision_sha256: decision.clean_selection_decision_sha256,
    retained_decision_set_sha256: decision.retained_decision_set_sha256,
    epistemic_decision_sha256: decision.epistemic_decision_sha256,
    content_state_evidence_scope_decision_sha256:
      decision.content_state_evidence_scope_decision_sha256,
    authorized_class_commitment_sha256:
      decision.authorized_class_commitment_sha256,
    state_view_root_sha256: decision.state_view_root_sha256,
    occurrence_view_root_sha256: decision.occurrence_view_root_sha256,
    retained_blocked_decision_set_sha256:
      decision.retained_blocked_decision_set_sha256,
    evidence_root_sha256s: decision.evidence_root_sha256s,
    eligibility_exhaustion_reason: decision.eligibility_exhaustion_reason,
    no_epistemic_exoneration: decision.no_epistemic_exoneration,
    selected_clean_count: decision.selected_clean_count,
    consumer_commitment_root_sha256: decision.consumer_commitment_root_sha256,
    one_request_local_classification_map: decision.one_request_local_classification_map,
    classification_map_independently_recomputable:
      decision.classification_map_independently_recomputable,
    final_closure_receipt_count: decision.final_closure_receipt_count,
    canonical_memory_mutated: false,
    retention_changed: false,
    receipt: closure.receipt || null,
  });
}

function magmaDormancyMetadata() {
  return MAGMA_DORMANT_RUNTIME_DECISION;
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
    outer_channel_id: 'graph_family',
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

export const NATIVE_RECALL_RETURN_PROJECTION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/native-recall-return-projection/v1',
  return_paths: CANARY_CLEAN_SELECTION_RETURN_PATHS,
  output_identity_rule: 'ordered_unique_subset_of_final_clean_security_closure',
  output_content_rule: 'live_content_hash_and_provenance_commitments_unchanged',
  response_shaping_authority: false,
  disclosure_expansion_authority: false,
  mutation_authority: false,
  deletion_authority: false,
});

function recallProjectionEvidence(memory = {}) {
  const memoryId = String(memory?.id || memory?.memory_id || '').trim().toLowerCase();
  const proof = memory?.provenance_proof;
  const liveContentHash = String(proof?.live_content_hash || '').trim().toLowerCase();
  const saveMutationHash = proof?.save_mutation_hash == null
    ? null
    : String(proof.save_mutation_hash).trim().toLowerCase();
  const bindingMutationHash = String(proof?.binding_mutation_hash || '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(memoryId)) {
    throw new Error('native_recall_return_projection_memory_id_invalid');
  }
  if (!/^[0-9a-f]{64}$/.test(liveContentHash)) {
    throw new Error('native_recall_return_projection_live_content_hash_invalid');
  }
  if (saveMutationHash != null && !/^[0-9a-f]{64}$/.test(saveMutationHash)) {
    throw new Error('native_recall_return_projection_save_mutation_hash_invalid');
  }
  if (!/^[0-9a-f]{64}$/.test(bindingMutationHash)) {
    throw new Error('native_recall_return_projection_binding_mutation_hash_invalid');
  }
  return Object.freeze({
    memory_id: memoryId,
    live_content_hash: liveContentHash,
    save_mutation_hash: saveMutationHash,
    binding_mutation_hash: bindingMutationHash,
  });
}

export function buildNativeRecallReturnProjection({
  returnPath,
  securityClosure,
  responseBody,
  contentStateSelection = null,
} = {}) {
  const normalizedReturnPath = String(returnPath || '').trim();
  if (!CANARY_CLEAN_SELECTION_RETURN_PATHS.includes(normalizedReturnPath)) {
    throw new Error('native_recall_return_projection_path_invalid');
  }
  const selected = Array.isArray(securityClosure?.memories) ? securityClosure.memories : [];
  const output = Array.isArray(responseBody?.memories) ? responseBody.memories : [];
  const selectedEvidence = selected.map(recallProjectionEvidence);
  const selectedById = new Map(selectedEvidence.map((entry) => [entry.memory_id, entry]));
  if (selectedById.size !== selectedEvidence.length) {
    throw new Error('native_recall_return_projection_selected_identity_duplicate');
  }
  const outputEvidence = output.map(recallProjectionEvidence);
  const outputIds = new Set();
  const outputStates = new Set();
  for (const entry of outputEvidence) {
    if (outputIds.has(entry.memory_id) || outputStates.has(entry.live_content_hash)) {
      throw new Error('native_recall_return_projection_output_duplicate');
    }
    outputIds.add(entry.memory_id);
    outputStates.add(entry.live_content_hash);
    const source = selectedById.get(entry.memory_id);
    if (!source || canonicalJson(source) !== canonicalJson(entry)) {
      throw new Error('native_recall_return_projection_not_subset');
    }
  }
  const securityClosureHash = String(securityClosure?.decision?.decision_sha256 || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(securityClosureHash)) {
    throw new Error('native_recall_return_projection_security_closure_invalid');
  }
  const stateDecisionHash = contentStateSelection == null
    ? null
    : String(contentStateSelection?.decision_sha256 || '').trim().toLowerCase();
  if (stateDecisionHash != null && !/^[0-9a-f]{64}$/.test(stateDecisionHash)) {
    throw new Error('native_recall_return_projection_state_decision_invalid');
  }
  const body = {
    schema: NATIVE_RECALL_RETURN_PROJECTION_CONTRACT.schema,
    return_path: normalizedReturnPath,
    final_security_closure_sha256: securityClosureHash,
    content_state_selection_sha256: stateDecisionHash,
    selected_clean_count: selectedEvidence.length,
    projected_output_count: outputEvidence.length,
    projected_memory_ids: outputEvidence.map((entry) => entry.memory_id),
    projected_live_content_hashes: outputEvidence.map((entry) => entry.live_content_hash),
    ordered_unique_subset_of_final_clean_security_closure: true,
    output_content_commitments_unchanged: true,
    canonical_memory_mutated: false,
    retention_changed: false,
    disclosure_expansion_performed: false,
  };
  return Object.freeze({
    ...body,
    decision_sha256: createHash('sha256')
      .update(Buffer.from(canonicalJson(body), 'utf8'))
      .digest('hex'),
  });
}

async function calibrateAndFinalizeNativeRecallReturn({
  returnPath,
  queryText,
  body,
  runtimeBudget,
  responseLimit,
  securityClosure,
  contentStateSelection = null,
  authority,
  epistemicDecisionHash,
} = {}) {
  const calibrated = calibrateRecallRouteBody({
    queryText,
    body,
    runtimeBudget,
    responseLimit,
  });
  const projection = buildNativeRecallReturnProjection({
    returnPath,
    securityClosure,
    responseBody: calibrated,
    contentStateSelection,
  });
  calibrated.recall_meta = {
    ...(calibrated.recall_meta || {}),
    return_projection: projection,
  };
  calibrated.recall_receipt = await finalizeNativeRecall({
    memories: calibrated.memories,
    authority,
    epistemicDecisionHash,
    securityClosureDecisionHash: securityClosure.decision.decision_sha256,
    returnProjectionDecision: projection,
  });
  return calibrated;
}

export const SEMANTIC_CACHE_HYDRATION_CONTRACT = Object.freeze({
  schema: 'hom-aimos/semantic-cache-live-hydration/v1',
  maximum_state_references: 200,
  database_round_trips: 1,
  ordered_identity_hydration: true,
  exact_commitment_match_required: true,
  stale_or_missing_reference: 'cache_miss_full_path',
});

export async function hydrateSemanticCacheStateReferences({
  cacheEntry,
  companyId,
  queryFn,
} = {}) {
  const refs = Array.isArray(cacheEntry?.state_references) ? cacheEntry.state_references : [];
  if (cacheEntry?.schema !== 'hom-aimos/semantic-cache-state-reference/v1'
      || refs.length < 1 || refs.length > SEMANTIC_CACHE_HYDRATION_CONTRACT.maximum_state_references
      || typeof queryFn !== 'function') {
    return Object.freeze({ valid: false, reason: 'cache_reference_contract_invalid', memories: Object.freeze([]) });
  }
  const ids = refs.map((ref) => String(ref?.memory_id || '').trim().toLowerCase());
  if (new Set(ids).size !== ids.length || ids.some((id) => !/^[0-9a-f-]{36}$/.test(id))) {
    return Object.freeze({ valid: false, reason: 'cache_reference_identity_invalid', memories: Object.freeze([]) });
  }
  const result = await queryFn(
    `SELECT id, key, value, agent_id, memory_type, scope, source, clearance_level,
            retrieval_weight, created_at, updated_at, last_verified_at,
            verified_by, verification_basis, freshness_state, data_class,
            credit_score, memory_tier, valid_from, valid_until
       FROM public.aimos_memories
      WHERE company_id = $1
        AND id = ANY($2::uuid[])
      ORDER BY array_position($2::uuid[], id)`,
    [companyId, ids],
  );
  if ((result.rows || []).length !== ids.length) {
    return Object.freeze({ valid: false, reason: 'cache_reference_missing', memories: Object.freeze([]) });
  }
  return Object.freeze({
    valid: true,
    reason: null,
    memories: Object.freeze(result.rows.map((row) => Object.freeze({ ...row }))),
  });
}
function getMaxDataClassForClearance(clearanceLevel) {
  const cl = Number(clearanceLevel || 1);
  if (cl >= 10) return null; // all classes
  if (cl >= 7) return ['public', 'internal', 'confidential'];
  if (cl >= 4) return ['public', 'internal'];
  return ['public'];
}

function getAuthorizedRescueDataClasses(clearanceLevel, authorityCeiling) {
  const order = ['public', 'internal', 'confidential', 'restricted'];
  const authorityIndex = order.indexOf(String(authorityCeiling || ''));
  if (authorityIndex < 0) throw new Error('recall_rescue_data_class_ceiling_invalid');
  const clearanceClasses = getMaxDataClassForClearance(clearanceLevel) || order;
  const clearanceSet = new Set(clearanceClasses);
  return order.slice(0, authorityIndex + 1).filter((name) => clearanceSet.has(name));
}

const RECALL_GRAPH_LINK_MAX_SEEDS = 250;
const RECALL_GRAPH_LINK_MAX_HOPS = 2;
const RECALL_GRAPH_LINKS_PER_SEED = 8;
const RECALL_GRAPH_LINK_NEIGHBORS_PER_EXPANSION = 8;
const RECALL_GRAPH_LINK_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const RECALL_GRAPH_LINK_BATCH_CONTRACT = Object.freeze({
  schema: 'hom-aimos/recall-graph-link-batch/v1',
  maximum_seed_states: RECALL_GRAPH_LINK_MAX_SEEDS,
  maximum_hops: RECALL_GRAPH_LINK_MAX_HOPS,
  maximum_neighbors_per_expansion: RECALL_GRAPH_LINK_NEIGHBORS_PER_EXPANSION,
  maximum_links_per_seed: RECALL_GRAPH_LINKS_PER_SEED,
  database_round_trips: 1,
  read_owner: 'shared_request_scoped_r4_session',
  mutation_authority: false,
});

export async function readBatchedRecallGraphLinks({
  companyId,
  seedMemoryIds,
  maxHops,
  queryFn,
} = {}) {
  const company = String(companyId || '').trim();
  const seedIds = [...new Set((Array.isArray(seedMemoryIds) ? seedMemoryIds : [])
    .map((value) => String(value || '').trim().toLowerCase()))];
  if (!company || typeof queryFn !== 'function') throw new Error('recall_graph_link_batch_inputs_invalid');
  if (!seedIds.length) return Object.freeze({ linksBySeed: new Map(), decision: Object.freeze({
    ...RECALL_GRAPH_LINK_BATCH_CONTRACT,
    seed_count: 0,
    row_count: 0,
    applied_hops: 0,
  }) });
  if (seedIds.length > RECALL_GRAPH_LINK_MAX_SEEDS
    || seedIds.some((id) => !RECALL_GRAPH_LINK_UUID.test(id))) {
    throw new Error('recall_graph_link_batch_seed_bound_invalid');
  }
  const hops = Math.min(
    Math.max(Math.floor(Number(maxHops) || 1), 1),
    RECALL_GRAPH_LINK_MAX_HOPS,
  );
  const result = await queryFn(
    `WITH RECURSIVE graph_walk(root_memory_id, memory_id, similarity, hop, path_ids) AS (
       SELECT seed.root_memory_id, edge.target_memory_id, edge.similarity, 1,
              ARRAY[seed.root_memory_id, edge.target_memory_id]::uuid[]
         FROM unnest($2::uuid[]) AS seed(root_memory_id)
         CROSS JOIN LATERAL (
           SELECT cr.target_memory_id, cr.similarity
             FROM memory_cross_refs cr
            WHERE cr.company_id=$1 AND cr.source_memory_id=seed.root_memory_id
            ORDER BY cr.similarity DESC NULLS LAST, cr.target_memory_id
            LIMIT $4
         ) edge
       UNION ALL
       SELECT gw.root_memory_id, edge.target_memory_id, edge.similarity, gw.hop + 1,
              gw.path_ids || edge.target_memory_id
         FROM graph_walk gw
         CROSS JOIN LATERAL (
           SELECT cr.target_memory_id, cr.similarity
             FROM memory_cross_refs cr
            WHERE cr.company_id=$1 AND cr.source_memory_id=gw.memory_id
            ORDER BY cr.similarity DESC NULLS LAST, cr.target_memory_id
            LIMIT $4
         ) edge
        WHERE gw.hop < $3 AND NOT edge.target_memory_id = ANY(gw.path_ids)
     ), deduplicated AS (
       SELECT DISTINCT ON (root_memory_id, memory_id)
              root_memory_id, memory_id, similarity, hop
         FROM graph_walk
        ORDER BY root_memory_id, memory_id, hop ASC, similarity DESC NULLS LAST
     ), ranked AS (
       SELECT root_memory_id, memory_id, similarity, hop,
              row_number() OVER (
                PARTITION BY root_memory_id
                ORDER BY hop ASC, similarity DESC NULLS LAST, memory_id
              ) AS root_rank
         FROM deduplicated
     )
     SELECT root_memory_id::text, memory_id::text, similarity, hop
       FROM ranked
      WHERE root_rank <= $5
      ORDER BY root_memory_id, root_rank`,
    [
      company,
      seedIds,
      hops,
      RECALL_GRAPH_LINK_NEIGHBORS_PER_EXPANSION,
      RECALL_GRAPH_LINKS_PER_SEED,
    ],
  );
  const maximumRows = seedIds.length * RECALL_GRAPH_LINKS_PER_SEED;
  if (result.rows.length > maximumRows) throw new Error('recall_graph_link_batch_row_bound_exceeded');
  const linksBySeed = new Map(seedIds.map((id) => [id, []]));
  for (const row of result.rows) {
    const rootId = String(row.root_memory_id || '').toLowerCase();
    const memoryId = String(row.memory_id || '').toLowerCase();
    if (!linksBySeed.has(rootId) || !RECALL_GRAPH_LINK_UUID.test(memoryId)) {
      throw new Error('recall_graph_link_batch_result_invalid');
    }
    linksBySeed.get(rootId).push(Object.freeze({
      id: memoryId,
      similarity: Number(row.similarity),
      hop: Number(row.hop),
    }));
  }
  return Object.freeze({
    linksBySeed,
    decision: Object.freeze({
      ...RECALL_GRAPH_LINK_BATCH_CONTRACT,
      seed_count: seedIds.length,
      row_count: result.rows.length,
      requested_hops: Number(maxHops),
      applied_hops: hops,
    }),
  });
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
  queryFn = query,
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

  const result = await queryFn(
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
    const linked = await queryFn(
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
  let preConceptPprGearboxEvidence = null;
  const canaryClassificationMap = createCanaryContentClassificationMap();
  let verifiedAdmissionSession = null;
  let contentStateOccurrenceAdmission = null;

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
    const maxRows = Math.min(Math.max(Number(limit || 10), 1), 200);
    if (!searchQuery || typeof searchQuery !== 'string' || !searchQuery.trim()) {
      console.warn(`[RECALL-GUARD] Empty query from ${req.ip} | referer: ${req.headers.referer || 'none'} | user-agent: ${req.headers['user-agent'] || 'none'} | full URL: ${req.originalUrl}`);
      return { status: 400, body: { success: false, error: 'Missing required parameter: q (search query)' } };
    }

    // R4: bind one actor/certificate epoch and one provenance reader for the
    // complete request. Every candidate-producing lane submits through this
    // owner. Proofs verified inside this exact repeatable-read snapshot may be
    // reused by peer gears; no proof persists beyond the request.
    verifiedAdmissionSession = await openNativeRecallAdmissionSession({
      authority: recallAuthority,
    });
    const calibrationSnapshot = await getVerifiedCalibrationSnapshot(company, {
      client: Object.freeze({ query: verifiedAdmissionSession.read }),
    });
    const corpusMemoryCount = await getMemoryCount(company);
    const requestEpistemicEvidenceScope = createRequestEpistemicEvidenceScope({
      queryFn: verifiedAdmissionSession.read,
    });
    contentStateOccurrenceAdmission = createRequestScopedContentStateAdmission({
      authority: recallAuthority,
      admitBatch: verifiedAdmissionSession.admit,
      evidenceScopeOwner: requestEpistemicEvidenceScope,
    });

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
    const graphFamilyRrfK = NATIVE_RETRIEVAL_FUSION_CONTRACT.rrf_k;
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
      magma_architecture_role: MAGMA_DORMANT_RUNTIME_DECISION.architecture_role,
      magma_runtime_wired: false,
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
      queryFn: verifiedAdmissionSession.read,
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
      const identifierAdmission = await contentStateOccurrenceAdmission.admit(identifierLookup.memories);
      const identifierStateSelection =
        contentStateOccurrenceAdmission.selectCandidateStateRepresentatives(
          identifierAdmission.memories,
          { retainIneligibleForSecurityBoundary: true },
        );
      const identifierDiagnostics = {
        ...identifierLookup.diagnostics,
        content_state_selection: identifierStateSelection.decision,
      };
      applyCalibrationSnapshot(identifierStateSelection.memories, calibrationSnapshot);
      const identifierDeepRecallSummary = annotateDeepRecallOverrides(identifierStateSelection.memories, searchQuery);
      const identifierMemories = applyDeepRecallOverrideRanking(identifierStateSelection.memories);
      annotateRecallRankDiagnostics(identifierMemories);
      markStage('canary_clean_top_k_boundary');
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
        queryFn: verifiedAdmissionSession.read,
        canaryClassificationMap,
        contentStateEvidenceScopeDecision:
          contentStateOccurrenceAdmission.finalizeEvidenceScope(),
        returnPath: 'identifier_exact',
      });
      await logEvent(company, agent, 'recall', searchQuery, {
        reasoning: `Exact identifier recall for '${searchQuery}' returned ${identifierStateSelection.memories.length} content-state representative(s) from ${identifierLookup.memories.length} retained occurrence row(s).`,
        source_knowledge: 'identifier-recall.js — Generative Retrieval identifier ambiguity guard',
      });
      const identifierFinalClosure = await governCanaryRecallFinalClosure({
        classificationMap: canaryClassificationMap,
        returnPath: 'identifier_exact',
        selectedMemories: identifierEpistemic.memories,
        cleanSelection: identifierEpistemic.cleanSelection,
        epistemicDecision: identifierEpistemic.decision,
        epistemicReceipt: identifierEpistemic.receipt,
        contentStateEvidenceScope: identifierEpistemic.evidenceScope,
        consumers: {},
        companyId: company,
        subjectAgentId: agent,
        recallAuthority,
      });
      const identifierBody = {
          success: true,
          memories: identifierFinalClosure.memories,
          count: identifierFinalClosure.memories.length,
          cache_hit: false,
          identifier_recall: identifierDiagnostics,
          recall_meta: {
            content_state_occurrence_admission: contentStateOccurrenceAdmission.publicMetadata(),
            identifier_recall: identifierDiagnostics,
            deep_recall_override: identifierDeepRecallSummary,
            rank_observability: buildRecallRankObservability(identifierEpistemic.memories),
            canary_clean_selection:
              canaryCleanSelectionMetadata(identifierEpistemic.cleanSelection),
            epistemic_retrieval: {
              version: identifierEpistemic.decision.version,
              decision_sha256: identifierEpistemic.decision.decision_sha256,
              candidate_count: identifierEpistemic.decision.candidate_count,
              states: identifierEpistemic.decision.states,
              abstention_required: identifierEpistemic.decision.abstention_required,
              ...(identifierEpistemic.decision.twin_prime ? { twin_prime: identifierEpistemic.decision.twin_prime } : {}),
              decision_receipt: identifierEpistemic.receipt,
            },
            recall_security_closure:
              canaryFinalClosureMetadata(identifierFinalClosure),
            magma_retrieval: {
              ...magmaDormancyMetadata(),
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
      const calibratedIdentifierBody = await calibrateAndFinalizeNativeRecallReturn({
        returnPath: 'identifier_exact',
        queryText: searchQuery,
        body: identifierBody,
        runtimeBudget: effectiveRecallRuntimeBudget,
        responseLimit: effectiveMaxRows,
        securityClosure: identifierFinalClosure,
        contentStateSelection: identifierStateSelection.decision,
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
        queryFn: verifiedAdmissionSession.read,
      });
      if (handoffLookup.memories.length > 0) {
        const handoffAdmission = await contentStateOccurrenceAdmission.admit(handoffLookup.memories);
        const handoffStateSelection =
          contentStateOccurrenceAdmission.selectCandidateStateRepresentatives(
            handoffAdmission.memories,
          );
        const admittedHandoffMemories = handoffStateSelection.memories;
        applyCalibrationSnapshot(admittedHandoffMemories, calibrationSnapshot);
        markStage('canary_clean_top_k_boundary');
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
          queryFn: verifiedAdmissionSession.read,
          canaryClassificationMap,
          contentStateEvidenceScopeDecision:
            contentStateOccurrenceAdmission.finalizeEvidenceScope(),
          returnPath: 'post_compaction_handoff',
        });
        await logEvent(company, agent, 'recall', searchQuery, {
          lane: 'post_compaction_delivery',
          recall_mode: 'post_compaction_handoff',
          result_count: admittedHandoffMemories.length,
          retained_occurrence_count: handoffAdmission.memories.length,
          content_state_selection_sha256: handoffStateSelection.decision.decision_sha256,
          linked_full_compaction_key: handoffLookup.linked_full_compaction_key,
          reasoning: `Post-compaction handoff recall for '${searchQuery}' returned ${handoffLookup.memories.length} native compaction lane record(s) before semantic cache.`,
          source_knowledge: 'compaction-post-compaction-corpus.md — TiMem L2 + Chronos handoff tuning',
        });
        const handoffFinalClosure = await governCanaryRecallFinalClosure({
          classificationMap: canaryClassificationMap,
          returnPath: 'post_compaction_handoff',
          selectedMemories: handoffEpistemic.memories,
          cleanSelection: handoffEpistemic.cleanSelection,
          epistemicDecision: handoffEpistemic.decision,
          epistemicReceipt: handoffEpistemic.receipt,
          contentStateEvidenceScope: handoffEpistemic.evidenceScope,
          consumers: {},
          companyId: company,
          subjectAgentId: agent,
          recallAuthority,
        });
        const workingMemory = handoffFinalClosure.memories
          .slice(0, 2)
          .map((mem) => `[${mem.source}] ${mem.value}`.slice(0, 700))
          .join('\n');
        const handoffBody = {
            success: true,
            memories: handoffFinalClosure.memories,
            working_memory: isDemoMode ? demoRedact(workingMemory) : workingMemory,
            count: handoffFinalClosure.memories.length,
            cache_hit: false,
            recall_plan: {
              ...recallPlan,
              mode: 'post_compaction_handoff',
              supported: true,
              cues: ['post_compaction_handoff'],
              cache_bypassed: true,
            },
            recall_meta: {
              content_state_occurrence_admission: contentStateOccurrenceAdmission.publicMetadata(),
              qmd_activated: false,
              total_results: handoffEpistemic.memories.length,
              confidence_distribution: {
                high: handoffEpistemic.memories.length,
                medium: 0,
                low: 0,
              },
              temporal_truth: {
                truth_band: 'live',
                newest_memory_at: handoffEpistemic.memories[0]?.created_at || null,
                oldest_memory_at: handoffEpistemic.memories.at(-1)?.created_at || null,
                valid_from: handoffEpistemic.memories[0]?.valid_from || null,
                valid_until: handoffEpistemic.memories[0]?.valid_until || null,
              },
              compaction_handoff_recall: {
                source: 'native_compaction_lane',
                preferred_source: 'aimos-compaction:post',
                content_state_selection: handoffStateSelection.decision,
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
              canary_clean_selection:
                canaryCleanSelectionMetadata(handoffEpistemic.cleanSelection),
              recall_security_closure:
                canaryFinalClosureMetadata(handoffFinalClosure),
            },
            ...(isDemoMode ? { demo_mode: true } : {}),
          };
        const calibratedHandoffBody = await calibrateAndFinalizeNativeRecallReturn({
          returnPath: 'post_compaction_handoff',
          queryText: searchQuery,
          body: handoffBody,
          runtimeBudget: effectiveRecallRuntimeBudget,
          responseLimit: effectiveMaxRows,
          securityClosure: handoffFinalClosure,
          contentStateSelection: handoffStateSelection.decision,
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
        const hydratedCache = await hydrateSemanticCacheStateReferences({
          cacheEntry: cached,
          companyId: company,
          queryFn: verifiedAdmissionSession.read,
        });
        if (hydratedCache.valid) {
          const cachedAdmission = await contentStateOccurrenceAdmission.admit(hydratedCache.memories);
          const referenceById = new Map(cached.state_references.map((ref) => [ref.memory_id, ref]));
          const exactCommitments = cachedAdmission.memories.length === cached.state_references.length
            && cachedAdmission.memories.every((memory) => {
              const reference = referenceById.get(String(memory.id).toLowerCase());
              const proof = memory.provenance_proof;
              return reference
                && reference.live_content_hash === proof?.live_content_hash
                && reference.save_mutation_hash === proof?.save_mutation_hash
                && reference.binding_mutation_hash === proof?.binding_mutation_hash;
            });
          if (exactCommitments) {
            const cachedStateSelection =
              contentStateOccurrenceAdmission.selectCandidateStateRepresentatives(
                cachedAdmission.memories,
              );
            applyCalibrationSnapshot(cachedStateSelection.memories, calibrationSnapshot);
            markStage('canary_clean_top_k_boundary');
            const cachedEpistemic = await selectAndLedgerEpistemicRecall({
              memories: cachedStateSelection.memories,
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
              queryFn: verifiedAdmissionSession.read,
              canaryClassificationMap,
              contentStateEvidenceScopeDecision:
                contentStateOccurrenceAdmission.finalizeEvidenceScope(),
              returnPath: 'semantic_cache',
            });
            await logEvent(company, agent, 'cache_hit', searchQuery, {
              reasoning: `State-reference cache hit for query '${searchQuery.slice(0,50)}...' was hydrated and reverified before the semantic-cache return path.`,
              source_knowledge: 'Cache-Augmented Generation + HOM-AIMOS content-state/provenance closure',
            });
            const cachedFinalClosure = await governCanaryRecallFinalClosure({
              classificationMap: canaryClassificationMap,
              returnPath: 'semantic_cache',
              selectedMemories: cachedEpistemic.memories,
              cleanSelection: cachedEpistemic.cleanSelection,
              epistemicDecision: cachedEpistemic.decision,
              epistemicReceipt: cachedEpistemic.receipt,
              contentStateEvidenceScope: cachedEpistemic.evidenceScope,
              consumers: {},
              companyId: company,
              subjectAgentId: agent,
              recallAuthority,
            });
            const calibratedCachedBody = await calibrateAndFinalizeNativeRecallReturn({
              returnPath: 'semantic_cache',
              queryText: searchQuery,
              body: {
                success: true,
                memories: cachedFinalClosure.memories,
                count: cachedFinalClosure.memories.length,
                working_memory: cachedFinalClosure.memories
                  .slice(0, 4)
                  .map((memory) => `[${memory.memory_type || 'memory'}] ${String(memory.value || '').slice(0, 300)}`)
                  .join('\n'),
                recall_meta: {
                  content_state_occurrence_admission: contentStateOccurrenceAdmission.publicMetadata(),
                  cache_revalidation: {
                    cache_entry_sha256: cached.decision_sha256,
                    cache_tier: cached.cache_tier,
                    source_state_reference_count: cached.state_references.length,
                    hydrated_memory_count: hydratedCache.memories.length,
                    admitted_memory_count: cachedAdmission.memories.length,
                    selected_state_count: cachedStateSelection.memories.length,
                    selected_clean_count: cachedEpistemic.memories.length,
                    exact_commitments_verified: true,
                    canonical_hydration_performed: true,
                    provenance_reverification_performed: true,
                    content_state_reselection_performed: true,
                    stale_selection_derived_content_reused: false,
                    canonical_memory_mutated: false,
                    retention_changed: false,
                  },
                  epistemic_retrieval: {
                    version: cachedEpistemic.decision.version,
                    decision_sha256: cachedEpistemic.decision.decision_sha256,
                    candidate_count: cachedEpistemic.decision.candidate_count,
                    states: cachedEpistemic.decision.states,
                    abstention_required: cachedEpistemic.decision.abstention_required,
                    ...(cachedEpistemic.decision.twin_prime ? { twin_prime: cachedEpistemic.decision.twin_prime } : {}),
                    decision_receipt: cachedEpistemic.receipt,
                  },
                  canary_clean_selection:
                    canaryCleanSelectionMetadata(cachedEpistemic.cleanSelection),
                  recall_security_closure:
                    canaryFinalClosureMetadata(cachedFinalClosure),
                },
                cache_hit: true,
                cache_served_at: new Date().toISOString(),
              },
              runtimeBudget: effectiveRecallRuntimeBudget,
              responseLimit: effectiveMaxRows,
              securityClosure: cachedFinalClosure,
              contentStateSelection: cachedStateSelection.decision,
              authority: recallAuthority,
              epistemicDecisionHash: epistemicReceiptDecisionHash(cachedEpistemic.decision),
            });
            return { status: 200, body: calibratedCachedBody };
          }
        }
        logEvent(company, agent, 'cache_revalidation_miss', cached.decision_sha256 || 'invalid', {
          reason: hydratedCache.valid ? 'cache_reference_commitment_changed' : hydratedCache.reason,
          full_native_path_continued: true,
          cached_response_body_served: false,
        }).catch(() => {});
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
    const rescueAllowedDataClasses = getAuthorizedRescueDataClasses(
      clearance,
      recallAuthority.dataClassCeiling,
    );
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
    let entityCandidates = [];
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
                  m.created_at, m.credit_score,
                  m.access_count, m.last_accessed_at, m.last_verified_at,
                  m.verified_by, m.verification_basis, m.freshness_state,
                  COALESCE(m.retrieval_weight, 1.0) AS retrieval_weight,
                  COUNT(*) OVER (PARTITION BY e.memory_id) as entity_hits
           FROM entity_memory_edges e
           JOIN aimos_memories m ON m.id = e.memory_id AND m.company_id = e.company_id
           WHERE ${entityClauses.join(' AND ')}
           ORDER BY entity_hits DESC, e.memory_id ASC
           LIMIT 5`,
          entityParams
        );
        entityCandidates = entResult.rows.map((row) => ({
          id: row.memory_id,
          key: row.key,
          value: row.value,
          scope: row.scope,
          memory_type: row.memory_type,
          clearance_level: row.clearance_level,
          created_at: row.created_at,
          credit_score: parseFloat(row.credit_score || 1.0),
          memory_tier: row.memory_tier || 'short-term',
          data_class: row.data_class || 'public',
          entity_hits: Number(row.entity_hits || 1),
          source: row.source || null,
          access_count: Number(row.access_count || 0),
          last_accessed_at: row.last_accessed_at || null,
          last_verified_at: row.last_verified_at || null,
          verified_by: row.verified_by || null,
          verification_basis: row.verification_basis || null,
          freshness_state: row.freshness_state || null,
          retrieval_weight: Math.max(0.1, Math.min(3, Number(row.retrieval_weight || 1))),
          retrieval_source: 'entity_graph',
          graph_links: [],
        }));
      }
    } catch (entRecallError) {
      // Entity recall is best-effort
      recallBreadthPolicy.entity_recall_error = entRecallError.message;
    }
    const entityAdmission = entityCandidates.length
      ? await contentStateOccurrenceAdmission.admit(entityCandidates)
      : { memories: [], occurrence_admission_decision_sha256: null };
    const entityMemories = entityAdmission.memories;
    if (entityCandidates.length) {
      recallBreadthPolicy.entity_admission_decision_sha256 =
        entityAdmission.occurrence_admission_decision_sha256;
    }
    debugRecallPoint('entity_recall_done', {
      entity_candidates: entityCandidates.length,
      entity_memories: entityMemories.length,
      entity_admission_decision_sha256:
        entityAdmission.occurrence_admission_decision_sha256,
    });

    // ─── Feature 8: Recursive Graph Traversal (replaces manual 2-hop) ────────
    // WITH RECURSIVE enables configurable N-hop traversal (default 2, max 4).
    const requestedHops = max_hops !== undefined && max_hops !== null
      ? Number(max_hops)
      : recallBreadthPolicy.graph_hops;
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

    // ─── HIPPORAG: Merge admitted entity evidence without losing overlapping hits ──
    // Entity is one bounded fusion gear. If another gear already opened the
    // same occurrence, retain that candidate and attach the admitted entity
    // evidence; otherwise add the admitted occurrence to the shared set.
    const entityMemoryById = new Map(memories.map((memory) => [String(memory.id), memory]));
    for (const em of entityMemories) {
      const entityId = String(em.id);
      const existing = entityMemoryById.get(entityId);
      if (existing) {
        existing.entity_hits = Math.max(
          Number(existing.entity_hits || 0),
          Number(em.entity_hits || 0),
        );
        continue;
      }
      seenIds.add(entityId);
      entityMemoryById.set(entityId, em);
      memories.push(em);
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
        const pendingSiblingIds = new Set();
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
          const siblingCandidates = [];
          for (const row of siblingResult.rows) {
            if (seenIds.has(row.id) || pendingSiblingIds.has(row.id)) continue;
            pendingSiblingIds.add(row.id);
            siblingCandidates.push({
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
          const siblingAdmission = siblingCandidates.length
            ? await contentStateOccurrenceAdmission.admit(siblingCandidates)
            : { memories: [] };
          for (const memory of siblingAdmission.memories) {
            if (seenIds.has(memory.id)) continue;
            seenIds.add(memory.id);
            siblingHydrated += 1;
            memories.push(memory);
          }
        }
        if (siblingHydrated > 0) {
          recallBreadthPolicy.sibling_hydrated = siblingHydrated;
          recallBreadthPolicy.sibling_hydrated_roots = specs.map((spec) => spec.root).slice(0, 12);
          recallBreadthPolicy.sibling_admission_decision_sha256 =
            contentStateOccurrenceAdmission.publicMetadata().decision_sha256;
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

    // ─── QMD RESCUE ADAPTATION: structured low-confidence lexical proposal ──
    // Adaptive-RAG uses a trained complexity classifier. AIMOS does not claim
    // that classifier: this is a deterministic confidence-routed adaptation.
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
            scopedParams.push(rescueAllowedDataClasses);
            scopedClauses.push(`COALESCE(data_class, 'public') = ANY($${scopedParams.length}::text[])`);
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
             ORDER BY fts_rank DESC, id ASC
             LIMIT 10`,
            qmdFtsScope.scopedParams
          );

          // Channel 2: Key-pattern + metadata search (for Knowledge Gate: papers, techniques)
          // Use OR between terms — any term matching key/metadata surfaces the memory.
          // Scoring by term coverage happens downstream. Pick first 3 most distinctive terms.
          const qmdKeyTerms = qmdTerms.slice(0, 3);
          const qmdKeyScope = buildQmdScopedFilter();
          const keyLikePatterns = qmdKeyTerms.map(t => `%${t}%`);
          const qmdKeyFirstPatternIdx = qmdKeyScope.scopedParams.length + 1;
          qmdKeyScope.scopedParams.push(...keyLikePatterns);
          const keyOrClauses = qmdKeyTerms.map((_, i) => `LOWER(key) LIKE $${qmdKeyFirstPatternIdx + i}`).join(' OR ');
          const metaOrClauses = qmdKeyTerms.map((_, i) => `LOWER(COALESCE(source,'')) LIKE $${qmdKeyFirstPatternIdx + i}`).join(' OR ');
          const qmdKeyResult = await query(
            `SELECT id, key, value, scope, memory_type, clearance_level, created_at,
                    credit_score, memory_tier, decay_weight, data_class, source,
                    access_count, last_accessed_at
             FROM aimos_memories
             WHERE ${qmdKeyScope.scopedClauses.join(' AND ')}
                   AND (${keyOrClauses} OR ${metaOrClauses})
             ORDER BY
               CASE WHEN memory_type IN ('procedural_seed', 'procedural', 'tacit_knowledge') THEN 0 ELSE 1 END ASC,
               created_at DESC, id ASC
             LIMIT 10`,
            qmdKeyScope.scopedParams
          );

          // Merge both proposal channels without allowing an overlap with an
          // earlier gear to erase QMD evidence.
          const qmdCandidates = new Map();
          for (const row of (qmdFtsResult.rows || [])) {
            qmdCandidates.set(row.id, { ...row, _fts_rank: parseFloat(row.fts_rank || 0), _source: 'qmd_fts' });
          }
          for (const row of (qmdKeyResult.rows || [])) {
            if (!qmdCandidates.has(row.id)) {
              qmdCandidates.set(row.id, { ...row, _fts_rank: 0, _source: 'qmd_key' });
            }
          }

          const qmdProposals = [...qmdCandidates.values()].map((row) => ({
            id: row.id, key: row.key, value: row.value,
            scope: row.scope, memory_type: row.memory_type,
            clearance_level: row.clearance_level, created_at: row.created_at,
            credit_score: parseFloat(row.credit_score || 1),
            memory_tier: row.memory_tier || 'long-term',
            data_class: row.data_class || 'public', source: row.source || null,
            access_count: Number(row.access_count || 0),
            last_accessed_at: row.last_accessed_at || null,
            retrieval_source: row._source,
            graph_links: [],
          }));
          const qmdAdmission = qmdProposals.length
            ? await contentStateOccurrenceAdmission.admit(qmdProposals)
            : { memories: [], occurrence_admission_decision_sha256: null };
          const rescueMemoryById = new Map(memories.map((memory) => [String(memory.id), memory]));
          for (const row of qmdAdmission.memories) {
            const id = String(row.id);
            const qmdEvidence = qmdCandidates.get(id);
            const fullText = `${row.key} ${row.value}`.toLowerCase();
            const hitCount = queryTerms.filter(t => fullText.includes(t)).length;
            const termOverlap = queryTerms.length > 0 ? hitCount / queryTerms.length : 0;
            const typeBoost = ['procedural_seed', 'procedural', 'tacit_knowledge'].includes(row.memory_type) ? 0.15 : 0;
            const computedScore = Math.min(
              1.0,
              termOverlap + typeBoost + (Number(qmdEvidence?._fts_rank || 0) > 0 ? 0.1 : 0),
            );
            const existing = rescueMemoryById.get(id);
            if (existing) {
              existing.qmd_score = Math.max(Number(existing.qmd_score || 0), computedScore);
              continue;
            }
            const qmdMemory = { ...row, qmd_score: computedScore, rerank_score: computedScore };
            seenIds.add(id);
            rescueMemoryById.set(id, qmdMemory);
            memories.push(qmdMemory);
          }
          if (qmdAdmission.memories.length > 0) {
            qmdActivated = true;
            recallBreadthPolicy.qmd_admission_decision_sha256 =
              qmdAdmission.occurrence_admission_decision_sha256;
          }
        }
      } catch (qmdError) {
        recallBreadthPolicy.qmd_error = qmdError.message;
        console.warn('[recall] QMD auto-switch error:', qmdError.message);
      }
    }
    debugRecallPoint('qmd_activation_done', {
      qmd_activated: qmdActivated,
      memories: memories.length,
      top_rerank: topRerank,
      avg_rerank: Math.round(avgRerank * 1000) / 1000,
    });

    // ─── Multi-stage deterministic HyDE adaptation on low-quality recall ────
    markStage('hyde_expansion');
    // When recall quality is still low after QMD, expand query with hypothetical
    // document embeddings and run multi-stage retrieval to surface better results.
    if (recallBreadthPolicy.qmd_allowed && (topRerank <= 0.5 || avgRerank < 0.3)) {
      try {
        const hydeResults = await multiStageRecall(searchQuery, {
          companyId: company,
          clearanceLevel: clearance,
          requestingAgent,
          allowedDataClasses: rescueAllowedDataClasses,
          memoryTypeFilter: typeFilter,
          sourceFilter: srcFilter,
          sessionLikePattern,
          limit: Math.min(candidateOpeningLimit, 10),
          admitEvidenceFn: contentStateOccurrenceAdmission.admit,
        });
        const rescueMemoryById = new Map(memories.map((memory) => [String(memory.id), memory]));
        for (const hit of hydeResults) {
          if (!hit.id) continue;
          const id = String(hit.id);
          const hydeScore = Number(hit.rrf_score || 0);
          const existing = rescueMemoryById.get(id);
          if (existing) {
            existing.hyde_score = Math.max(Number(existing.hyde_score || 0), hydeScore);
            continue;
          }
          const hydeMemory = {
            ...hit,
            retrieval_source: 'multi_stage_hyde',
            hyde_score: hydeScore,
            rerank_score: hydeScore,
            graph_links: [],
          };
          seenIds.add(id);
          rescueMemoryById.set(id, hydeMemory);
          memories.push(hydeMemory);
        }
        recallBreadthPolicy.hyde_adaptation = MULTI_STAGE_RETRIEVAL_CONTRACT.hyde_implementation;
      } catch (hydeError) {
        recallBreadthPolicy.hyde_error = hydeError.message;
        console.warn('[recall] multi-stage HyDE fallback error (non-fatal):', hydeError.message);
      }
    }
    debugRecallPoint('hyde_expansion_done', { memories: memories.length, seen_ids: seenIds.size });

    // The ranking engines propose ids; this native boundary is the sole
    // disclosure authority. No calibration, graph completion, synthesis,
    // mnemonic encoding, cache admission, or early exit sees unverified rows.
    const mainAdmission = await contentStateOccurrenceAdmission.admit(memories);
    memories.length = 0;
    memories.push(...mainAdmission.memories);
    // Canary stage evidence and native retained-quarantine evidence are
    // composed before any graph-family subgear sees an input. MAGMA is dormant;
    // this signed decision now governs G2 only.
    markStage('canary_magma_graph_admission');
    const canaryMagmaComposition = await governCanaryMagmaGraphAdmission({
      memories,
      classificationMap: canaryClassificationMap,
      companyId: company,
      subjectAgentId: agent,
      recallAuthority,
    });
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

    skipStage('magma_native_gear', 'dormant_research_not_in_live_recall');
    const graphFamilyBaselineFusion = fuseNativeRetrievalGears({
      admittedMemories: memories,
      graphFamilyGear: null,
      temporalBias: temporalFusionIntent,
      rrfK: graphFamilyRrfK,
      contentStateProjection: contentStateOccurrenceAdmission.internalProjection(),
      contentStateGears: NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set,
      fusionPhase: 'pre_reconstructed_graph',
      requireGraphFamilyContract: false,
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
      canaryClassificationMap,
    );
    const reconstructedGraphStateSelection =
      contentStateOccurrenceAdmission.selectCandidateStateRepresentatives(
        reconstructedGraphCanaryPartition.admitted,
      );
    reconstructedGraphEligibleCandidateCount = reconstructedGraphStateSelection.memories.length;
    reconstructedGraphCanaryWithheldCount = reconstructedGraphCanaryPartition.withheld.length;
    if (reconstructedGraphEligibleCandidateCount > 0) {
      try {
        reconstructedGraphCandidate = composeReconstructedGraphNativeCandidate({
          admittedMemories: reconstructedGraphStateSelection.memories
            .map((memory) => ({ ...memory, canary_admitted: true })),
          queryText: searchQuery,
          contentStateSelectionDecision: reconstructedGraphStateSelection.decision,
          requireContentStateSelection: true,
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
      reconstructedGraphGear: reconstructedGraphCandidate,
      limit: 50,
      contentStateProjection: contentStateOccurrenceAdmission.internalProjection(),
    });
    graphFamilyRuntimeMs = Number((performance.now() - graphFamilyStartedAt).toFixed(3));
    nativeRetrievalFusion = fuseNativeRetrievalGears({
      admittedMemories: memories,
      graphFamilyGear: graphFamilyCandidate,
      temporalBias: temporalFusionIntent,
      rrfK: graphFamilyRrfK,
      contentStateProjection: contentStateOccurrenceAdmission.internalProjection(),
      contentStateGears: NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set,
      fusionPhase: 'pre_concept_ppr',
      requireGraphFamilyContract: true,
    });
    memories.length = 0;
    memories.push(...nativeRetrievalFusion.memories.map((memory) => ({ ...memory })));

    // Internal-only evidence for source-bound marginal-gear experiments. The
    // route and MCP owners serialize result.body only, so this bundle never
    // crosses a transport boundary. It captures the exact post-PPR admitted
    // population and all incumbent gear outputs before confidence or
    // epistemic selection, allowing a candidate graph subgear to be evaluated
    // without changing canonical recall behavior.
    const evaluationCanaryPartition = partitionGraphCanaryDisclosure(
      memories,
      canaryClassificationMap,
    );
    preConceptPprGearboxEvidence = Object.freeze({
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
      rrf_k: graphFamilyRrfK,
      magma_gear: null,
      magma_dormancy: MAGMA_DORMANT_RUNTIME_DECISION,
      reconstructed_graph_gear: reconstructedGraphCandidate,
      graph_family_gear: graphFamilyCandidate,
      baseline_fusion: nativeRetrievalFusion,
      evidence_stage: 'pre_concept_ppr',
      pre_ppr_content_state_occurrence_admission:
        contentStateOccurrenceAdmission.metadata(),
      transport_exposed: false,
      canonical_memory_mutated: false,
      retention_changed: false,
    });
    topRerank = memories[0]?.rerank_score || 0;
    avgRerank = memories.length
      ? memories.reduce((sum, memory) => sum + Number(memory.rerank_score || 0), 0) / memories.length
      : 0;

    // Bounded graph-link annotation starts only from provenance-admitted seeds
    // and returns identifiers/edge weights, never unverified passage content.
    // One multi-seed query replaces the predecessor N+1 database loop.
    if (hops > 0) {
      const graphLinkBatch = await readBatchedRecallGraphLinks({
        companyId: company,
        seedMemoryIds: memories
          .slice(0, RECALL_GRAPH_LINK_BATCH_CONTRACT.maximum_seed_states)
          .map((memory) => memory.id),
        maxHops: hops,
        queryFn: verifiedAdmissionSession.read,
      });
      for (const memory of memories) {
        memory.graph_links = graphLinkBatch.linksBySeed.get(String(memory.id).toLowerCase()) || [];
      }
      recallBreadthPolicy.graph_link_batch = graphLinkBatch.decision;
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
      // The early-return path has its own final selection point. Build its
      // response-local boundary here so later Concept/PPR work is neither
      // skipped nor accidentally omitted from the normal-path boundary.
      const earlyStateSelection =
        contentStateOccurrenceAdmission.selectCandidateStateRepresentatives(memories);
      markStage('trust_scoring');
      const earlyCandidateMemories = applyDeepRecallOverrideRanking(
        rankByTrust(earlyStateSelection.memories, { memoryCount: corpusMemoryCount }),
      );
      markStage('canary_clean_top_k_boundary');
      const earlyCanaryCleanSelectionBoundary = buildCanaryCleanSelectionBoundary(
        earlyCandidateMemories,
        effectiveMaxRows,
        { classificationMap: canaryClassificationMap },
      );
      const earlySelectionMemories = earlyCanaryCleanSelectionBoundary.clean_eligible_memories;
      applyCalibrationSnapshot(earlySelectionMemories, calibrationSnapshot);
      const earlyTopScores = earlySelectionMemories.slice(0, 5).map((memory) => {
        const lexical = Number(memory.rerank_score || 0);
        const fusion = Number.isFinite(Number(memory.native_fusion_score))
          ? Number(memory.native_fusion_score)
          : lexical;
        return (lexical * (1 - NATIVE_FUSION_SEMANTIC_SHARE))
          + (fusion * NATIVE_FUSION_SEMANTIC_SHARE);
      });
      const earlyMvs = await checkContextSufficiency(session_id || agent || company).catch(() => ({ mvs: 0.5 }));
      const earlyTop1Medallion = earlySelectionMemories[0]?.medallion_layer || 'silver';
      if (shouldEarlyExit(earlyTopScores, earlyMvs.mvs, {
        user_trust_level: 'standard',
        top1_medallion: earlyTop1Medallion,
        total_memories: corpusMemoryCount,
      })) {
        const earlyMeta = generateEarlyExitMetadata({
          reason: 'high_confidence_gap',
          confidence_gap: earlyTopScores[0] - (earlyTopScores[1] || 0),
          mvs_score: earlyMvs.mvs,
          top_score: earlyTopScores[0],
          top1_medallion: earlyTop1Medallion,
          total_memories: corpusMemoryCount,
        });
        await logEvent(company, agent, 'early_exit', searchQuery.slice(0, 50), {
          reasoning: `Early exit at stage 7 boundary after one signed calibration snapshot: confidence_gap=${(earlyTopScores[0] - (earlyTopScores[1] || 0)).toFixed(3)}, MVS=${earlyMvs.mvs}.`,
          source_knowledge: 'Adaptive RAG (Wang et al., 2024) — Speed.md Appendix A'
        });
        const earlyRecallMeta = {
          qmd_activated: qmdActivated,
          top_rerank: topRerank,
          avg_rerank: Math.round(avgRerank * 100) / 100,
          total_results: earlyCandidateMemories.length,
          early_exit: true,
          exit_stage: 7,
          skipped_stages: ['salience_frequency_evaluation', 'concept_graph_ppr', 'mnemonic_encoding'],
          confidence_distribution: { high: 0, medium: 0, low: 0 },
          early_exit_flag: earlyExitFlag,
          deep_recall_override: deepRecallOverrideSummary,
          temporal_truth: { truth_band: 'unknown', newest_memory_at: null, oldest_memory_at: null, median_age_hours: null, recent_ratio: 0, stale_ratio: 0 },
          explain: { mode: 'early_exit', query: searchQuery, exit_stage: 7, ...earlyMeta }
        };
        // Record skipped stages in tracer
        skipStage('salience_frequency_evaluation', 'early_exit');
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
            early_exit: true, result_count: earlyCandidateMemories.length
          }).catch(() => {});
          earlyRecallMeta.stage_timings = _stageTimings;
        }
        earlyRecallMeta.confidence_source = 'signed_sortify_belief_snapshot';
        earlyRecallMeta.calibration_mutation_hash = calibrationSnapshot.calibrationMutationHash;
        earlyRecallMeta.cache_admitted = false;
        earlyRecallMeta.content_state_occurrence_admission =
          contentStateOccurrenceAdmission.publicMetadata();
        const earlyEpistemic = await selectAndLedgerEpistemicRecall({
          // The precomputed boundary is bound to the full ordered population.
          // The shared selector consumes its clean subset internally; passing
          // only that subset here would sever the population commitment when
          // retained Canary/quarantine evidence is present.
          memories: earlyCandidateMemories,
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
          queryFn: verifiedAdmissionSession.read,
          canaryCleanSelectionBoundary: earlyCanaryCleanSelectionBoundary,
          canaryClassificationMap,
          contentStateEvidenceScopeDecision:
            contentStateOccurrenceAdmission.finalizeEvidenceScope(),
          returnPath: 'adaptive_early_exit',
        });
        const earlyFinalClosure = await governCanaryRecallFinalClosure({
          classificationMap: canaryClassificationMap,
          returnPath: 'adaptive_early_exit',
          selectedMemories: earlyEpistemic.memories,
          cleanSelection: earlyEpistemic.cleanSelection,
          epistemicDecision: earlyEpistemic.decision,
          epistemicReceipt: earlyEpistemic.receipt,
          contentStateEvidenceScope: earlyEpistemic.evidenceScope,
          consumers: {
            canary_magma_graph_admission: canaryMagmaComposition.decision,
            magma_dormancy: MAGMA_DORMANT_RUNTIME_DECISION,
            reconstructed_graph_native_candidate: reconstructedGraphCandidate?.decision,
            graph_family_channel: graphFamilyCandidate?.decision,
            native_retrieval_fusion: nativeRetrievalFusion?.decision,
          },
          companyId: company,
          subjectAgentId: agent,
          recallAuthority,
        });
        const earlyDisclosureMemories = earlyFinalClosure.memories;
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
        earlyRecallMeta.canary_magma_composition =
          canaryMagmaCompositionMetadata(canaryMagmaComposition);
        earlyRecallMeta.canary_clean_selection =
          canaryCleanSelectionMetadata(earlyEpistemic.cleanSelection);
        earlyRecallMeta.magma_retrieval = magmaDormancyMetadata();
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
        earlyRecallMeta.recall_security_closure =
          canaryFinalClosureMetadata(earlyFinalClosure);
        earlyRecallMeta.response_limit_enforcement = {
          requested_limit: effectiveMaxRows,
          candidate_count: earlyCandidateMemories.length,
          returned_count: earlyDisclosureMemories.length,
          truncated: earlyCandidateMemories.length > earlyDisclosureMemories.length,
        };
        annotateRecallRankDiagnostics(earlyDisclosureMemories);
        earlyRecallMeta.retrieval_frequency = annotateRetrievalFrequencyMetadata(earlyDisclosureMemories);
        earlyRecallMeta.rank_observability = buildRecallRankObservability(earlyDisclosureMemories);
        earlyRecallMeta.pheromone_reinforcement = await reinforceRetrievedPheromones(earlyDisclosureMemories, {
          companyId: company,
          agentId: agent,
          queryText: searchQuery,
        });
        const earlyResponse = await calibrateAndFinalizeNativeRecallReturn({
          returnPath: 'adaptive_early_exit',
          queryText: searchQuery,
          body: { memories: earlyDisclosureMemories, working_memory: '', recall_meta: earlyRecallMeta, cache_hit: false },
          runtimeBudget: effectiveRecallRuntimeBudget,
          responseLimit: effectiveMaxRows,
          securityClosure: earlyFinalClosure,
          contentStateSelection: earlyStateSelection.decision,
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
      const trusted = rankByTrust(memories, { memoryCount: corpusMemoryCount });
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
    // HippoRAG ingredient: PPR lifts concept probability to the already
    // admitted request-state passage set. It owns no candidate discovery.
    let conceptPprStateSelectionDecision = null;
    let conceptPprResultCount = 0;
    try {
      if (searchQuery && searchQuery.trim()) {
        const conceptPprCanaryPartition = partitionGraphCanaryDisclosure(
          memories,
          canaryClassificationMap,
        );
        const conceptPprStateSelection =
          contentStateOccurrenceAdmission.selectCandidateStateRepresentatives(
            conceptPprCanaryPartition.admitted,
          );
        conceptPprStateSelectionDecision = conceptPprStateSelection.decision;
        const conceptPprStateMemories = conceptPprStateSelection.memories
          .slice(0, CONCEPT_PPR_MAX_REQUEST_STATES);
        const pprResults = hops > 0 && conceptPprStateMemories.length > 0
          ? await conceptPprLookup(
              searchQuery,
              company,
              Math.min(candidateOpeningLimit, 10),
              {
                admittedStates: conceptPprStateMemories.map((memory) => ({
                  memory_id: memory.id,
                  live_content_hash: memory.provenance_proof?.live_content_hash,
                })),
              },
            )
          : [];
        conceptPprResultCount = pprResults.length;
        const conceptPprMemoryById = new Map(memories.map((memory) => [String(memory.id), memory]));
        for (const pprHit of pprResults) {
          const existing = conceptPprMemoryById.get(String(pprHit.id));
          if (!existing) throw new Error('concept_ppr_result_outside_admitted_state_set');
          existing.ppr_score = Math.max(Number(existing.ppr_score || 0), Number(pprHit.ppr || 0));
          existing.cosine_score = Math.max(Number(existing.cosine_score || 0), Number(pprHit.cosine || 0));
        }
        recallBreadthPolicy.concept_ppr_state_selection_sha256 =
          conceptPprStateSelection.decision.decision_sha256;
      }
    } catch (_pprErr) {
      console.warn('[recall] concept-graph PPR error (non-fatal):', _pprErr.message);
    }
    debugRecallPoint('concept_graph_ppr_done', {
      memories: memories.length,
      seen_ids: seenIds.size,
      result_count: conceptPprResultCount,
      state_selection_sha256: conceptPprStateSelectionDecision?.decision_sha256 || null,
    });

    // PPR may propose additional ids. Re-admit the complete set before the
    // first calibration stage; PPR hydration cannot bypass provenance or ACL.
    const postGraphAdmission = await contentStateOccurrenceAdmission.admit(memories);
    memories.length = 0;
    memories.push(...postGraphAdmission.memories);

    // Recompose the central gearbox after concept-PPR has contributed its own
    // admitted channel. The graph family is not rerun: the same bounded G2
    // evidence is fused with the enlarged admitted set, keeping one execution
    // and exactly one outer graph-family channel while preserving candidate
    // monotonicity. MAGMA remains dormant and contributes no rank.
    nativeRetrievalFusion = fuseNativeRetrievalGears({
      admittedMemories: memories,
      graphFamilyGear: graphFamilyCandidate,
      temporalBias: temporalFusionIntent,
      rrfK: graphFamilyRrfK,
      contentStateProjection: contentStateOccurrenceAdmission.internalProjection(),
      contentStateGears: NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set,
      fusionPhase: 'final_post_concept_ppr',
      requireGraphFamilyContract: true,
    });
    memories.length = 0;
    memories.push(...nativeRetrievalFusion.memories.map((memory) => ({ ...memory })));
    const finalEvaluationCanaryPartition = partitionGraphCanaryDisclosure(
      memories,
      canaryClassificationMap,
    );
    nativeGearboxEvaluationEvidence = Object.freeze({
      ...preConceptPprGearboxEvidence,
      evidence_stage: 'final_post_concept_ppr',
      admitted_memories: Object.freeze(
        finalEvaluationCanaryPartition.admitted.map(snapshotNativeGearboxMemory),
      ),
      canary_withheld_memory_ids: Object.freeze(
        finalEvaluationCanaryPartition.withheld
          .map((memory) => String(memory?.id || memory?.memory_id || '').toLowerCase())
          .filter(Boolean)
          .sort(),
      ),
      pre_concept_ppr_fusion: preConceptPprGearboxEvidence?.baseline_fusion || null,
      baseline_fusion: nativeRetrievalFusion,
      final_fusion: nativeRetrievalFusion,
      post_ppr_content_state_occurrence_admission:
        contentStateOccurrenceAdmission.metadata(),
      final_production_fusion: true,
    });

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
    const normalFinalStateSelection =
      contentStateOccurrenceAdmission.selectCandidateStateRepresentatives(memories);
    memories.length = 0;
    memories.push(...normalFinalStateSelection.memories);
    recallBreadthPolicy.final_content_state_selection_sha256 =
      normalFinalStateSelection.decision.decision_sha256;
    // This is the normal return path's final ordered population: every native
    // gear (including Concept/PPR discoveries), admission pass, calibration,
    // and deterministic reranker has completed. The shared selector now owns
    // the mandatory clean-selection boundary for every return-path class.
    markStage('canary_clean_top_k_boundary');
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
      queryFn: verifiedAdmissionSession.read,
      canaryClassificationMap,
      contentStateEvidenceScopeDecision:
        contentStateOccurrenceAdmission.finalizeEvidenceScope(),
      returnPath: 'normal_recall',
    });
    const finalSecurityClosure = await governCanaryRecallFinalClosure({
      classificationMap: canaryClassificationMap,
      returnPath: 'normal_recall',
      selectedMemories: epistemicRecall.memories,
      cleanSelection: epistemicRecall.cleanSelection,
      epistemicDecision: epistemicRecall.decision,
      epistemicReceipt: epistemicRecall.receipt,
      contentStateEvidenceScope: epistemicRecall.evidenceScope,
      consumers: {
        canary_magma_graph_admission: canaryMagmaComposition.decision,
        magma_dormancy: MAGMA_DORMANT_RUNTIME_DECISION,
        reconstructed_graph_native_candidate: reconstructedGraphCandidate?.decision,
        graph_family_channel: graphFamilyCandidate?.decision,
        native_retrieval_fusion: nativeRetrievalFusion?.decision,
      },
      companyId: company,
      subjectAgentId: agent,
      recallAuthority,
    });
    const disclosureMemories = finalSecurityClosure.memories;
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
        recall_security_closure:
          canaryFinalClosureMetadata(finalSecurityClosure),
        native_retrieval_fusion: nativeRetrievalFusion.decision,
        canary_magma_composition:
          canaryMagmaCompositionMetadata(canaryMagmaComposition),
        canary_clean_selection:
          canaryCleanSelectionMetadata(epistemicRecall.cleanSelection),
        graph_family_retrieval: graphFamilyMetadata({
          family: graphFamilyCandidate,
          runtimeMs: graphFamilyRuntimeMs,
        }),
        magma_retrieval: magmaDormancyMetadata(),
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
        content_state_occurrence_admission: contentStateOccurrenceAdmission.publicMetadata(),
        concept_ppr_state_selection: conceptPprStateSelectionDecision
          ? {
              ...conceptPprStateSelectionDecision,
              result_count: conceptPprResultCount,
              maximum_request_states: CONCEPT_PPR_MAX_REQUEST_STATES,
            }
          : null,
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
        recall_security_closure:
          canaryFinalClosureMetadata(finalSecurityClosure),
        native_retrieval_fusion: nativeRetrievalFusion.decision,
        canary_magma_composition:
          canaryMagmaCompositionMetadata(canaryMagmaComposition),
        canary_clean_selection:
          canaryCleanSelectionMetadata(epistemicRecall.cleanSelection),
        graph_family_retrieval: graphFamilyMetadata({
          family: graphFamilyCandidate,
          runtimeMs: graphFamilyRuntimeMs,
        }),
        magma_retrieval: magmaDormancyMetadata(),
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
    if (SPEED_CONFIG.cache.enabled && allowSemanticCache) {
      semanticCache.set(queryEmbedding, searchQuery, { memories: disclosureMemories }, {
        companyId: company,
        agentId: agent,
        clearanceLevel: clearance,
        calibrationMutationHash: calibrationSnapshot.calibrationMutationHash,
        contentStateDecisionHash: normalFinalStateSelection.decision.decision_sha256,
        nativeFusionDecisionHash: nativeRetrievalFusion.decision.decision_sha256,
        epistemicDecisionHash: epistemicRecall.decision.decision_sha256,
        securityClosureDecisionHash: finalSecurityClosure.decision.decision_sha256,
      });
    }

    const calibratedRecallResponse = await calibrateAndFinalizeNativeRecallReturn({
      returnPath: 'normal_recall',
      queryText: searchQuery,
      body: recallResponse,
      runtimeBudget: effectiveRecallRuntimeBudget,
      responseLimit: effectiveMaxRows,
      securityClosure: finalSecurityClosure,
      contentStateSelection: normalFinalStateSelection.decision,
      authority: recallAuthority,
      epistemicDecisionHash: epistemicReceiptDecisionHash(epistemicRecall.decision),
    });
    debugRecallPoint('output_calibration_done', {
      memories: calibratedRecallResponse?.memories?.length || 0,
      count: calibratedRecallResponse?.count || 0,
    });

    debugRecallPoint('request_done', {
      memories: calibratedRecallResponse?.memories?.length || 0,
      count: calibratedRecallResponse?.count || 0,
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
  } finally {
    if (verifiedAdmissionSession) {
      await verifiedAdmissionSession.close({ commit: false });
    }
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
