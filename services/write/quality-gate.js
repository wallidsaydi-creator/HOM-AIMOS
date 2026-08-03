// ═══════════════════════════════════════════════════════════════════════════════
// QUALITY GATE — THREE WALLS
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: Aladdin Law (BlackRock retention), HOM Constitution, OWASP ASVS.
// Diagnostic payload shape only: RAGChecker (2024), for fine-grained reporting
// surfaces. RAGChecker does not define the three-wall admission math below.
// Additive Batch9 Wave2 authority: Sum-of-Checks, DOLA, Governing What You
// Cannot Observe, and Demographic-Aware Anomaly Detection. Shadow scalar
// diagnostics only; production gate math, blocking thresholds, and Aladdin
// retention semantics are unchanged.
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildCuraLightDebateDiagnostic: CuraLight debate signal alongside
//     existing three-wall quality gate. Debate signal does NOT lower
//     quality-gate thresholds. Gate math unchanged.
//
// WALL 1 — THE FORM: structural integrity (empty, short, kill patterns)
// WALL 2 — THE FILTER: noise detection (repetitive, spam, dedup)
// WALL 3 — THE SUBSTANCE: value assessment (scoring, exempt types)
//
// All 3 walls must pass. Breach one, two more stand.
// An attacker must bypass structural checks, noise detection, AND substance
// scoring simultaneously. Each wall is independently auditable.
//
// assessQuality() runs all 3 walls. Optional context is backward-compatible.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (SAVE pipeline, step 1)
// ← Called by: agent-runner.js (post-run step 27)
// → Calls: (terminal gate — no downstream service call)
// Pipeline: SAVE_PIPELINE, AGENT_RUN_PIPELINE
// Position: first wall, before everything; also post-run quality enforcement
// ─────────────────────────────────────────────────────────────────────────────
//
// NOTHING enters Aimos without passing this gate. No exceptions. No bypasses.
//
// ALADDIN LAW: Keep everything of VALUE. Delete everything with ZERO value.
// There is no middle ground. There is no "inactive" state.
//
// assessQuality(key, value, memoryType, context?) → { pass, score, reason }
//   pass: true  → memory enters Aimos
//   pass: false → memory is REJECTED. It never existed.
//
// ═══════════════════════════════════════════════════════════════════════════════

// ─── KILL PATTERNS: instant reject, score 0 ──────────────────────────────────
// These are NEVER valuable. No amount of context makes them useful.
const KILL_PATTERNS = [
  // Generic dream filler (the exact disease we're curing)
  /^mixed events(,\s*mixed events)*$/i,
  /^cluster of \d+ summaries$/i,
  /^day summary:\s*(mixed events[,\s]*)+$/i,
  /^day summary:\s*$/i,

  // Null/empty values
  /^undefined$/i,
  /^null$/i,
  /^none$/i,
  /^n\/a$/i,
  /^\{\s*\}$/,
  /^\[\s*\]$/,
  /^""$/,
  /^''$/,

  // Pure noise
  /^(ok|yes|no|true|false|done|test|ping|pong)$/i,
  /^error$/i,
  /^\d+$/,  // just a number

  // Repeated single words
  /^(\w+)(\s+\1){2,}$/i,  // "error error error"
];

// ─── EXEMPT TYPES (high-trust, skip content scoring but NOT dedup) ────────────
// These memory types are structurally valuable by definition.
// They still go through injection/null/filler checks — just not substance scoring.
const EXEMPT_TYPES = new Set([
  'session_debrief',
  'strategic_directive',
  'operational_rule',
  'constitution',
  'procedural',
  'session_reasoning',
]);

// Exempt key prefixes — ingested research, system health
const EXEMPT_KEY_PREFIXES = [
  'paper:',          // ingested research papers
  'book:',           // ingested books
  'heartbeat:pulse', // system health (exactly this key)
  'heartbeat:latest',
];

function isExemptKey(key) {
  return EXEMPT_KEY_PREFIXES.some(p => key === p || key.startsWith(p));
}

// ─── AUTHORIZED ACADEMIC INGESTION LANE ──────────────────────────────────────
// Paper extraction can legitimately contain repeated scaffold instructions.
// This is not a bypass: it only relaxes Wall 2's repetition false positive when
// an LM Reader submits non-executable bibliographic evidence. The gate is
// content-based (memory_type + source regex + key regex + envelope regex +
// clearance floor), NOT agent-based — any agent with clearance >= 10 making
// a properly-shaped academic-ingest submission passes.
const ACADEMIC_INGEST_SOURCE_RE = /(ingest|ingestion|extraction|reader|paper|book|bibliographic|research|technique)/i;
const ACADEMIC_INGEST_KEY_RE = /(batch\d+(?:_\d+)?|batch\d+_\d+|batch9_5|aimos_paper|paper_reference|paper|book|bibliographic|research|hom_technique|technique_extract)/i;
const ACADEMIC_ENVELOPE_RE = /BIBLIOGRAPHIC (?:RESEARCH EXTRACTION|IMPLEMENTATION TECHNIQUE EXTRACT|RAW PAPER TEXT|FULL PAPER READER TEXT|PAPER INGEST COMPLETE|TECHNIQUE EXTRACTION COMPLETE)[\s\S]{0,1000}CONTENT_ROLE:\s*(?:academic evidence|implementation technique evidence for HOM\/Aimos|completion marker)[\s\S]{0,1000}EXECUTION_AUTHORITY:\s*none/i;

function normalizeQualityContext(context = {}) {
  return {
    source: String(context.source || '').trim(),
    clearanceLevel: Number(context.clearance_level ?? context.clearanceLevel ?? 0),
  };
}

export function isAuthorizedAcademicIngest(key, value, memoryType, context = {}) {
  const mt = String(memoryType || '').trim().toLowerCase();
  if (mt !== 'bibliographic_reference' && mt !== 'book_extract') return { authorized: false, reason: 'not_academic_ingest_memory_type' };

  const { source, clearanceLevel } = normalizeQualityContext(context);
  const k = String(key || '');
  const v = String(value || '');

  if (clearanceLevel < 10) {
    return { authorized: false, reason: 'clearance_below_academic_ingest_floor' };
  }
  if (!ACADEMIC_INGEST_SOURCE_RE.test(source)) {
    return { authorized: false, reason: 'source_not_academic_ingestion' };
  }
  if (!ACADEMIC_INGEST_KEY_RE.test(k)) {
    return { authorized: false, reason: 'key_not_academic_ingestion' };
  }
  if (!ACADEMIC_ENVELOPE_RE.test(v)) {
    return { authorized: false, reason: 'missing_non_executable_academic_envelope' };
  }

  return { authorized: true, reason: 'reviewer_lm_reader_bibliographic_evidence' };
}

// ─── HEARTBEAT SPAM: specific pattern that floods the system ──────────────────
const HEARTBEAT_SPAM_RE = /knowledge gate blocked|System Heartbeat.*30 minutes/i;

// Track which heartbeat messages we've already let through
const _seenHeartbeats = new Set();
const _MAX_SEEN_HEARTBEATS = 10;

// Cross-save dedup is deliberately absent from this synchronous wall. The
// canonical persistence transaction checks committed rows after admission.
// ─── SUBSTANCE DETECTION ─────────────────────────────────────────────────────
// What makes a memory valuable? Specifics. Reasoning. Outcomes.
const HAS_SPECIFICS_RE = /(\b\d{4}[-/]\d{2}[-/]\d{2}\b|\b\d{2}:\d{2}\b|\/[a-zA-Z0-9._/-]{3,}|\b\d+\.\d+\.\d+\b|\b[A-Z][a-z]+\s[A-Z][a-z]+\b|\b0x[0-9a-f]+\b)/;
const HAS_REASONING_RE = /\b(because|therefore|root cause|decision|why|since|as a result|consequence|hence|thus|determined|concluded|analysis shows|evidence|verified)\b/i;
const HAS_ACTION_RE = /\b(fixed|implemented|created|deployed|tested|resolved|added|removed|updated|refactored|migrated|configured|debugged|shipped|merged|committed|reverted|discovered|identified)\b/i;
const HAS_STRUCTURE_RE = /\b(step \d|phase \d|\d\.\s|→|==>|key:|value:|result:|status:|error:|warning:)\b/i;
const HAS_FILE_PATH_RE = /[a-zA-Z0-9_-]+\.(js|ts|json|md|py|sh|yml|yaml|sql|html|css)\b/;

const BATCH9_SUM_OF_CHECKS_AUTHORITIES = [
  'Sum-of-Checks: Structured Reasoning for Surgical Safety with Large Vision-Language Models',
  'Autonomous Radiotherapy Treatment Planning Using DOLA: A Privacy-Preserving, LLM-Based Optimization Agent',
  'Governing What You Cannot Observe: Adaptive Runtime Governance for Autonomous AI',
  'Demographic-Aware Self-Supervised Anomaly Detection Pretraining for Equitable Rare Cardiac Diagnosis',
];

function clamp01(value) {
  return Math.max(0, Math.min(1, Number(value) || 0));
}

function scalarCheck(score, evidence = [], weight = 1) {
  return {
    score: Number(clamp01(score).toFixed(4)),
    weight,
    evidence,
  };
}

export function buildSumOfChecksDiagnostics(key, value, memoryType, context = {}) {
  const k = String(key || '');
  const v = String(value || '').trim();
  const mt = String(memoryType || '').trim().toLowerCase();
  const source = String(context.source || '').trim();
  const clearance = Number(context.clearance_level ?? context.clearanceLevel ?? 0);
  const lower = v.toLowerCase();
  const sentences = v.split(/(?<=[.!?])\s+|\n+/).map((part) => part.trim()).filter(Boolean);
  const uniqueSentences = new Set(sentences.map((part) => part.toLowerCase()));
  const repetitionRatio = sentences.length > 0 ? 1 - (uniqueSentences.size / sentences.length) : 0;
  const dateCount = (v.match(/\b\d{4}[-/]\d{2}[-/]\d{2}\b/g) || []).length;
  const citationLikeCount = (v.match(/\b(arxiv|doi|source|paper|evidence|verified|because|result|test|pass|fail)\b/gi) || []).length;
  const authoritySignals = [
    clearance >= 10 ? 'clearance>=10' : null,
    source ? 'source-present' : null,
    /paper|book|session|event|architecture|implementation|verification/.test(mt) ? `memory_type:${mt}` : null,
    /^(paper|book|session|event|implementation|verification|architecture|batch)/i.test(k) ? 'key-namespace' : null,
  ].filter(Boolean);
  const demographicTerms = (lower.match(/\b(gender|race|ethnic|religion|nationality|age|disability|class|demographic)\b/g) || []).length;
  const biasMitigationTerms = (lower.match(/\b(fair|equitable|bias|counter-evidence|audit|representative|demographic-aware)\b/g) || []).length;
  const safetyRedFlags = (lower.match(/\b(ignore previous|bypass|override|secret|token|password|delete all|drop table|exfiltrate|leak)\b/g) || []).length;

  const checks = {
    coherence: scalarCheck(
      (v.length >= 80 ? 0.45 : 0.25)
        + (sentences.length >= 2 ? 0.25 : 0)
        + (HAS_STRUCTURE_RE.test(v) ? 0.2 : 0)
        - Math.min(0.3, repetitionRatio),
      [`sentences:${sentences.length}`, `repetition:${repetitionRatio.toFixed(2)}`],
      1.0
    ),
    factuality: scalarCheck(
      0.35
        + (HAS_SPECIFICS_RE.test(v) ? 0.25 : 0)
        + (citationLikeCount > 0 ? 0.2 : 0)
        + (HAS_FILE_PATH_RE.test(v) ? 0.1 : 0),
      [`specifics:${HAS_SPECIFICS_RE.test(v)}`, `citations:${citationLikeCount}`],
      1.1
    ),
    recency: scalarCheck(
      0.45 + (dateCount > 0 ? 0.25 : 0) + (/latest|current|updated|verified|today|now/i.test(v) ? 0.15 : 0),
      [`date_mentions:${dateCount}`],
      0.7
    ),
    authority: scalarCheck(
      0.25 + Math.min(0.55, authoritySignals.length * 0.14),
      authoritySignals,
      1.0
    ),
    bias: scalarCheck(
      demographicTerms === 0 ? 0.78 : 0.55 + Math.min(0.3, biasMitigationTerms * 0.1),
      [`demographic_terms:${demographicTerms}`, `mitigation_terms:${biasMitigationTerms}`],
      0.8
    ),
    safety: scalarCheck(
      safetyRedFlags === 0 ? 0.9 : Math.max(0.05, 0.65 - safetyRedFlags * 0.2),
      [`red_flags:${safetyRedFlags}`],
      1.2
    ),
    source_integrity: scalarCheck(
      0.35
        + (source ? 0.25 : 0)
        + (/BIBLIOGRAPHIC RESEARCH EXTRACTION|CONTENT_ROLE:\s*academic evidence|EXECUTION_AUTHORITY:\s*none/i.test(v) ? 0.25 : 0)
        + (/source|evidence|verified|test|paper/i.test(v) ? 0.1 : 0),
      [`source:${source || 'missing'}`],
      1.2
    ),
  };

  const weightedTotal = Object.values(checks).reduce((sum, check) => sum + check.score * check.weight, 0);
  const weightTotal = Object.values(checks).reduce((sum, check) => sum + check.weight, 0);

  return {
    source_papers: BATCH9_SUM_OF_CHECKS_AUTHORITIES,
    diagnostic_only: true,
    checks,
    weighted_score: Number((weightedTotal / weightTotal).toFixed(4)),
    production_gate_replaced: false,
    gate_decision_changed: false,
    canonical_memory_changed: false,
    aladdin_delete_enabled: false,
    guarded_math: {
      learned_surgical_check_aggregation: false,
      dola_optimization_agent: false,
      demographic_threshold_calibration: false,
      curalight_debate: true,
    },
    guarded_math_implemented: {
      curalight_debate: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'CuraLight: Debate-Guided Data Curation for Medical Image Analysis',
        coexistence_class: 'side_by_side_overlay',
      },
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// WALL 1 — THE FORM
// Structural integrity: empty, minimum length, kill patterns
// Pure string validation — zero state, zero dependencies
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Wall 1: structural integrity check.
 * Is the value well-formed? Does it have minimum structure?
 *
 * @param {string} key        — memory key
 * @param {string} value      — memory value
 * @param {string} memoryType — memory_type field
 * @returns {{ pass: boolean, reason?: string }}
 */
export function wall1_form(key, value, memoryType) {
  const v = String(value || '').trim();

  // Empty/missing — instant kill
  if (!v || v.length === 0) {
    return { pass: false, reason: 'Empty value' };
  }

  // Minimum length — nothing under 20 chars has substance
  if (v.length < 20) {
    return { pass: false, reason: `Too short (${v.length} chars, minimum 20)` };
  }

  // Kill patterns — instant reject, no appeal
  for (const pattern of KILL_PATTERNS) {
    if (pattern.test(v)) {
      return { pass: false, reason: `Kill pattern: ${pattern.source.slice(0, 60)}` };
    }
  }

  return { pass: true };
}

// ═══════════════════════════════════════════════════════════════════════════════
// WALL 2 — THE FILTER
// Noise detection: repetitive content, heartbeat spam, cross-save dedup
// Stateful (tracks recent values), but no external dependencies
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Wall 2: noise and dedup filter.
 * Have we seen this before? Is it repetitive noise?
 *
 * @param {string} key        — memory key
 * @param {string} value      — memory value
 * @param {string} memoryType — memory_type field
 * @returns {{ pass: boolean, reason?: string }}
 */
export function wall2_filter(key, value, memoryType, context = {}) {
  const v = String(value || '').trim();
  const mt = String(memoryType || '').trim();
  const academicIngest = isAuthorizedAcademicIngest(key, v, memoryType, context);
  let repetitionDiagnostic = null;

  // Repetition is only a hard block for low-substance loop spam.
  // It is not a quality proxy by itself: normal people, technical notes, forms,
  // logs, and extraction scaffolds can repeat labels/phrasing while still
  // carrying useful substance. Substance belongs to Wall 3.
  const segments = v
    .split(/\n|(?<=\.)\s+/)
    .map(s => s.trim().toLowerCase())
    .filter(s => s.length > 5);

  if (segments.length > 2) {
    const unique = new Set(segments);
    const repetition = 1 - (unique.size / segments.length);
    if (repetition > 0.5) {
      const hasSubstanceSignal =
        HAS_SPECIFICS_RE.test(v) ||
        HAS_REASONING_RE.test(v) ||
        HAS_ACTION_RE.test(v) ||
        HAS_STRUCTURE_RE.test(v) ||
        (v.length > 500 && unique.size >= 3);
      if (repetition > 0.85 && !hasSubstanceSignal) {
        return {
          pass: false,
          reason: `${Math.round(repetition * 100)}% repeated low-substance content`,
          dedup_status: 'low_substance_repetition_rejected',
        };
      }
      repetitionDiagnostic = {
        reason: `${Math.round(repetition * 100)}% repeated phrasing observed; deferred to substance gate`,
        dedup_status: 'repetition_diagnostic_substance_gate',
        repetition_ratio: repetition,
      };
    }
  }

  // Heartbeat spam — one through per unique message, rest die
  if ((mt === 'event_log' || mt === 'shared_failure') && HEARTBEAT_SPAM_RE.test(v)) {
    const sig = v.slice(0, 150);
    if (_seenHeartbeats.has(sig)) {
      return { pass: false, reason: 'Duplicate heartbeat spam — already recorded', dedup_status: 'duplicate_rejected' };
    }
    _seenHeartbeats.add(sig);
    if (_seenHeartbeats.size > _MAX_SEEN_HEARTBEATS) {
      const first = _seenHeartbeats.values().next().value;
      _seenHeartbeats.delete(first);
    }
    // First occurrence: signal the caller that this is a heartbeat pass (low score territory)
    return { pass: true, heartbeat: true, dedup_status: 'heartbeat_first_occurrence' };
  }

  if (repetitionDiagnostic) {
    return {
      pass: true,
      ...repetitionDiagnostic,
      academic_ingest_authorized: Boolean(academicIngest.authorized),
      authorization_reason: academicIngest.authorized ? academicIngest.reason : null,
    };
  }

  return {
    pass: true,
    // Cross-save exact-value dedup is performed against committed rows by the
    // canonical persistence transaction. A rollback therefore cannot poison a
    // later signed retry through process-local state.
    dedup_status: 'pending_committed_check',
    academic_ingest_authorized: Boolean(academicIngest.authorized),
    authorization_reason: academicIngest.authorized ? academicIngest.reason : null,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// WALL 3 — THE SUBSTANCE
// Value assessment: exempt types pass automatically, scoring for the rest
// Score must be >= 0.30 to pass
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Wall 3: substance and value assessment.
 * Does this memory carry actual value? Is it worth permanent storage?
 *
 * @param {string} key        — memory key
 * @param {string} value      — memory value
 * @param {string} memoryType — memory_type field
 * @returns {{ pass: boolean, score: number, reason?: string }}
 */
export function wall3_substance(key, value, memoryType) {
  const k = String(key || '').trim();
  const v = String(value || '').trim();
  const mt = String(memoryType || '').trim();

  // Exempt types — structurally valuable, skip substance scoring
  // They still passed walls 1-2 (no garbage, no dupes, no kills).
  if (EXEMPT_TYPES.has(mt) || isExemptKey(k)) {
    return { pass: true, score: 1.0 };
  }

  // Substance scoring — does this memory carry real value?
  let score = 0.25;  // baseline: passed all kill checks

  // Specifics: dates, times, paths, versions, names
  if (HAS_SPECIFICS_RE.test(v)) score += 0.15;

  // File references: actual code files mentioned
  if (HAS_FILE_PATH_RE.test(v)) score += 0.1;

  // Length signals depth
  if (v.length > 500) {
    score += 0.2;
  } else if (v.length > 200) {
    score += 0.15;
  } else if (v.length > 100) {
    score += 0.1;
  }

  // Reasoning: the WHY behind events
  if (HAS_REASONING_RE.test(v)) score += 0.2;

  // Action: concrete things that happened
  if (HAS_ACTION_RE.test(v)) score += 0.1;

  // Structure: organized information
  if (HAS_STRUCTURE_RE.test(v)) score += 0.1;

  score = Math.min(1.0, score);

  // Minimum passing score: 0.3
  // Below 0.3 = not enough substance to justify permanent storage
  if (score < 0.3) {
    return {
      pass: false, score,
      reason: `Insufficient substance (${score.toFixed(2)} < 0.30 threshold)`
    };
  }

  return { pass: true, score };
}

// ═══════════════════════════════════════════════════════════════════════════════
// MASTER GATE — assessQuality
// Runs all 3 walls in order. All must pass.
// Signature unchanged for backward compatibility.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Master gate: assess the quality of a memory before it enters Aimos.
 *
 * Runs Wall 1 → Wall 2 → Wall 3 in order.
 * First wall to fail rejects the memory immediately.
 *
 * @param {string} key        — memory key
 * @param {string} value      — redacted memory value
 * @param {string} memoryType — memory_type field
 * @returns {{ pass: boolean, score: number, reason?: string }}
 */
export function assessQuality(key, value, memoryType, context = {}) {
  const sumOfChecks = buildSumOfChecksDiagnostics(key, value, memoryType, context);

  // ── WALL 1: Form — structural integrity ────────────────────────────────────
  const w1 = wall1_form(key, value, memoryType);
  if (!w1.pass) {
    return {
      pass: false,
      score: 0,
      reason: w1.reason,
      walls: {
        form: { pass: false, reason: w1.reason },
        filter: null,
        substance: null,
      },
      dedup_status: 'unknown',
      sum_of_checks: sumOfChecks,
    };
  }

  // ── WALL 2: Filter — noise and dedup ───────────────────────────────────────
  const w2 = wall2_filter(key, value, memoryType, context);
  if (!w2.pass) {
    return {
      pass: false,
      score: 0,
      reason: w2.reason,
      walls: {
        form: { pass: true, reason: null },
        filter: { pass: false, reason: w2.reason, dedup_status: w2.dedup_status || 'duplicate_rejected' },
        substance: null,
      },
      dedup_status: w2.dedup_status || 'duplicate_rejected',
      sum_of_checks: sumOfChecks,
    };
  }

  // Heartbeat first-occurrence: passes with capped score
  if (w2.heartbeat) {
    return {
      pass: true,
      score: 0.35,
      walls: {
        form: { pass: true, reason: null },
        filter: { pass: true, reason: null, dedup_status: w2.dedup_status || 'heartbeat_first_occurrence', heartbeat: true },
        substance: { pass: true, score: 0.35, exempt: true },
      },
      dedup_status: w2.dedup_status || 'heartbeat_first_occurrence',
      sum_of_checks: sumOfChecks,
    };
  }

  // ── WALL 3: Substance — value assessment ───────────────────────────────────
  const w3 = wall3_substance(key, value, memoryType);
  if (!w3.pass) {
    return {
      pass: false,
      score: w3.score,
      reason: w3.reason,
      walls: {
        form: { pass: true, reason: null },
        filter: {
          pass: true,
          reason: w2.reason || null,
          dedup_status: w2.dedup_status || 'unique',
          academic_ingest_authorized: Boolean(w2.academic_ingest_authorized),
          authorization_reason: w2.authorization_reason || null,
        },
        substance: { pass: false, score: w3.score, reason: w3.reason },
      },
      dedup_status: w2.dedup_status || 'unique',
      sum_of_checks: sumOfChecks,
    };
  }

  return {
    pass: true,
    score: w3.score,
    walls: {
      form: { pass: true, reason: null },
      filter: {
        pass: true,
        reason: w2.reason || null,
        dedup_status: w2.dedup_status || 'unique',
        heartbeat: Boolean(w2.heartbeat),
        academic_ingest_authorized: Boolean(w2.academic_ingest_authorized),
        authorization_reason: w2.authorization_reason || null,
      },
      substance: { pass: true, score: w3.score, exempt: w3.score === 1.0 },
    },
    dedup_status: w2.dedup_status || 'unique',
    academic_ingest_authorized: Boolean(w2.academic_ingest_authorized),
    sum_of_checks: sumOfChecks,
  };
}

/**
 * CuraLight Debate Diagnostic — Alongside-path diagnostic
 *
 * Source paper: CuraLight — Debate-Guided Data Curation for Medical Image Analysis
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * CuraLight paper: multi-perspective debate improves curation quality.
 * This diagnostic assesses debate signals (perspective count, agreement level,
 * dissent rate) alongside the existing three-wall quality gate. Debate signals
 * do NOT lower quality-gate thresholds. The three-wall admission math,
 * blocking thresholds, and Aladdin retention semantics are unchanged.
 * Guarded by guarded_math flag curalight_debate (knowledge-gated).
 */
export function buildCuraLightDebateDiagnostic({
  gateResult = {},
  debatePerspectives = [],
} = {}) {
  const perspectives = Array.isArray(debatePerspectives) ? debatePerspectives : [];
  const pass = Boolean(gateResult?.pass);
  const score = Number(gateResult?.score ?? 0);

  const agreeing = perspectives.filter((p) => /\b(agree|support|accept|pass)\b/i.test(String(p?.verdict || p?.stance || ''))).length;
  const disagreeing = perspectives.filter((p) => /\b(disagree|reject|fail|oppose)\b/i.test(String(p?.verdict || p?.stance || ''))).length;
  const agreementRatio = perspectives.length > 0 ? agreeing / perspectives.length : 1;
  const dissentRate = perspectives.length > 0 ? disagreeing / perspectives.length : 0;

  return {
    diagnostic: true,
    source_paper: 'CuraLight: Debate-Guided Data Curation for Medical Image Analysis',
    coexistence_class: 'side_by_side_overlay',
    gate_pass: pass,
    gate_score: score,
    perspective_count: perspectives.length,
    agreement_ratio: Number(agreementRatio.toFixed(6)),
    dissent_rate: Number(dissentRate.toFixed(6)),
    debate_signal_does_not_lower_threshold: true,
    three_wall_math_unchanged: true,
    aladdin_retention_unchanged: true,
    note: 'Alongside-path diagnostic. CuraLight debate signal does not lower quality-gate thresholds.',
  };
}
