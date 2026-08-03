// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into AGENT_RUN XAI explanation capture
// Purpose: XAI 3-pillar explainability (transparency, interpretability,
//          contrastive post-hoc) for AI decision explanation
// Called by: orchestration/agent-xai-explanation.js (post-run capture)
// Pipeline: AGENT_RUN
// ─────────────────────────────────────────────────────────────────────────────

/**
 * explainer.js — XAI 3-pillar user-facing explainability
 * Source: DARPA XAI program (Gunning 2017, 2019)
 * Additive TEM authority: Learning Hierarchical Procedural Memory for LLM
 * Agents through Bayesian Selection and Contrastive Refinement (MACLA)
 *
 * Implements transparency (glass-box), interpretability (proxy model),
 * and contrastive (post-hoc) explanations for AI decisions.
 * MACLA alignment: explanations can now be recalled as persistent procedural
 * reasoning artifacts, but this service does not perform Bayesian action
 * selection or contrastive procedure refinement.
 * Additive Batch9 Wave5 authority: ELISA, Ontology-Aware Design Patterns, and
 * DesigNet. Aimos exposes typed evidence-path explanations only; hidden
 * reasoning and unsupported media payloads are not exposed.
 * Batch9.75 Wave 1 authority: Chain-of-Thought Prompting. CoT trace presence
 * diagnostic assesses whether explanations contain structured reasoning
 * chains; never stored as canonical memory.
 *
 * Created: 2026-04-03
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const EXPLANATION_LEVEL = {
  BRIEF: 'brief',
  DETAILED: 'detailed',
  TECHNICAL: 'technical',
};

export const COT_EXPLANATION_SOURCE = 'Chain-of-Thought Prompting';

const TOP_FEATURE_COUNT = 5;
const MAX_FIDELITY_CAP = 0.95;
const USER_FRIENDLY_CHAR_LIMIT = 200;
const WAVE5_EVIDENCE_EXPLANATION_AUTHORITIES = [
  'ELISA: An Interpretable Hybrid Generative AI Agent for Expression-Grounded Discovery in Single-Cell Genomics',
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture',
  'DesigNet: Learning to Draw Vector Graphics as Designers Do',
];

// ---------------------------------------------------------------------------
// Pillar 1 — Transparency (Glass-Box)
// ---------------------------------------------------------------------------

/**
 * Build a transparency report from an ordered reasoning chain.
 *
 * @param {Array<{step: string|number, action: string, rationale?: string}>} reasoningSteps
 * @param {Object} context  Optional metadata (agent_id, timestamp, etc.)
 * @returns {{ pillar: 'transparency', narrative: string, steps: Array, confidence: number }}
 */
export function buildTransparencyReport(reasoningSteps, context = {}) {
  if (!Array.isArray(reasoningSteps) || reasoningSteps.length === 0) {
    return {
      pillar: 'transparency',
      narrative: 'No reasoning steps were recorded for this decision.',
      steps: [],
      confidence: 0,
    };
  }

  // Normalise steps — ensure each has step/action/rationale fields.
  const steps = reasoningSteps.map((s, i) => ({
    step: s.step ?? i + 1,
    action: s.action ?? '(unknown action)',
    rationale: s.rationale ?? null,
  }));

  // Confidence = fraction of steps that carry an explicit rationale.
  const stepsWithRationale = steps.filter((s) => s.rationale !== null && s.rationale !== '');
  const confidence = steps.length > 0 ? stepsWithRationale.length / steps.length : 0;

  // Build narrative prose from the chain.
  const sentences = steps.map((s) => {
    const base = `Step ${s.step}: ${s.action}`;
    return s.rationale ? `${base} — ${s.rationale}` : base;
  });

  const agentTag = context.agent_id ? ` (agent: ${context.agent_id})` : '';
  const narrative =
    `The decision was reached through ${steps.length} step${steps.length !== 1 ? 's' : ''}${agentTag}. ` +
    sentences.join('. ') +
    '.';

  return {
    pillar: 'transparency',
    narrative,
    steps,
    confidence: Math.round(confidence * 1000) / 1000,
  };
}

// ---------------------------------------------------------------------------
// Pillar 2 — Interpretability (Proxy / Linear Approximation)
// ---------------------------------------------------------------------------

/**
 * Build an interpretability report using a simplified linear proxy model.
 *
 * @param {{ [feature: string]: number }} features  Map of feature name → weight
 * @param {Object} context  Optional metadata
 * @returns {{ pillar: 'interpretability', top_features: Array, linear_approximation: string, fidelity_score: number }}
 */
export function buildInterpretabilityReport(features, context = {}) {
  if (!features || typeof features !== 'object' || Object.keys(features).length === 0) {
    return {
      pillar: 'interpretability',
      top_features: [],
      linear_approximation: 'Insufficient feature data to build a proxy model.',
      fidelity_score: 0,
    };
  }

  const entries = Object.entries(features);
  const totalAbsWeight = entries.reduce((sum, [, w]) => sum + Math.abs(w), 0);

  // Sort by absolute weight descending and take top-5.
  const sorted = [...entries].sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
  const top = sorted.slice(0, TOP_FEATURE_COUNT);

  const top_features = top.map(([feature, weight]) => ({
    feature,
    weight: Math.round(weight * 10000) / 10000,
    direction: weight >= 0 ? 'positive' : 'negative',
  }));

  // Fidelity: how much of total variance the top features capture.
  const topAbsWeight = top.reduce((sum, [, w]) => sum + Math.abs(w), 0);
  const fidelity_score =
    totalAbsWeight > 0
      ? Math.min(MAX_FIDELITY_CAP, Math.round((topAbsWeight / totalAbsWeight) * 1000) / 1000)
      : 0;

  // Build human-readable linear approximation string.
  const terms = top_features.map((f) => {
    const sign = f.direction === 'positive' ? '+' : '';
    return `${sign}${f.weight}×[${f.feature}]`;
  });
  const linear_approximation = `decision ≈ ${terms.join(' ')}`;

  return {
    pillar: 'interpretability',
    top_features,
    linear_approximation,
    fidelity_score,
  };
}

// ---------------------------------------------------------------------------
// Pillar 3 — Contrastive / Post-Hoc Explanation
// ---------------------------------------------------------------------------

/**
 * Build a contrastive explanation comparing the chosen action against alternatives.
 *
 * @param {{ action: string, [key: string]: any }} chosen
 * @param {Array<{ action: string, [key: string]: any }>} rejected  Alternative actions
 * @param {Object} context  Optional metadata
 * @returns {{ pillar: 'contrastive', chosen: string, rejected: string[], key_differentiators: string[], why_not: Array }}
 */
export function buildContrastiveExplanation(chosen, rejected, context = {}) {
  if (!chosen || typeof chosen.action !== 'string') {
    return {
      pillar: 'contrastive',
      chosen: '(unknown)',
      rejected: [],
      key_differentiators: [],
      why_not: [],
    };
  }

  const rejectedList = Array.isArray(rejected) ? rejected : [];

  /**
   * Derive a human-readable differentiator between chosen and an alternative.
   * Compares all shared scalar/string properties to surface meaningful deltas.
   */
  function getDifferentiator(chosenObj, altObj) {
    const chosenKeys = new Set(Object.keys(chosenObj).filter((k) => k !== 'action'));
    const altKeys = new Set(Object.keys(altObj).filter((k) => k !== 'action'));
    const shared = [...chosenKeys].filter((k) => altKeys.has(k));

    for (const key of shared) {
      const cv = chosenObj[key];
      const av = altObj[key];
      if (cv !== av && (typeof cv === 'number' || typeof cv === 'string' || typeof cv === 'boolean')) {
        if (typeof cv === 'number' && typeof av === 'number') {
          const diff = cv - av;
          const direction = diff > 0 ? 'higher' : 'lower';
          return `${key} is ${direction} (${cv} vs ${av})`;
        }
        return `${key} differs: "${cv}" vs "${av}"`;
      }
    }

    // Fallback: no shared comparable properties.
    if (altObj.reason) return altObj.reason;
    return `"${altObj.action}" was not preferred over "${chosenObj.action}"`;
  }

  const why_not = rejectedList.map((alt) => ({
    action: alt.action ?? '(unnamed alternative)',
    reason: getDifferentiator(chosen, alt),
  }));

  const key_differentiators = [...new Set(why_not.map((w) => w.reason))];

  return {
    pillar: 'contrastive',
    chosen: chosen.action,
    rejected: rejectedList.map((a) => a.action ?? '(unnamed)'),
    key_differentiators,
    why_not,
  };
}

// ---------------------------------------------------------------------------
// Orchestrator — generateExplanation
// ---------------------------------------------------------------------------

let _explanationCounter = 0;

/**
 * Generate a unified XAI explanation from a decision context.
 *
 * @param {{
 *   action: string,
 *   reasoning_steps?: Array,
 *   features?: Object,
 *   alternatives?: Array,
 *   confidence?: number,
 *   agent_id?: string
 * }} decisionContext
 * @param {string} level  One of EXPLANATION_LEVEL values
 * @returns {{
 *   explanation_id: string,
 *   level: string,
 *   transparency: Object,
 *   interpretability: Object,
 *   contrastive: Object,
 *   user_summary: string,
 *   technical_summary: string,
 *   generated_at: string
 * }}
 */
export function generateExplanation(decisionContext, level = EXPLANATION_LEVEL.BRIEF) {
  _explanationCounter += 1;
  const explanation_id = `xai-${Date.now()}-${String(_explanationCounter).padStart(4, '0')}`;

  const {
    action = '(unspecified action)',
    reasoning_steps = [],
    features = {},
    alternatives = [],
    confidence,
    agent_id,
  } = decisionContext || {};

  const context = { agent_id, level };

  // --- Build each pillar ---
  const transparency = buildTransparencyReport(reasoning_steps, context);
  const interpretability = buildInterpretabilityReport(features, context);
  const contrastive = buildContrastiveExplanation(
    { action, ...(confidence !== undefined ? { confidence } : {}) },
    alternatives,
    context,
  );

  // --- Compose user_summary ---
  const topFeaturePart =
    interpretability.top_features.length > 0
      ? ` The most influential factor was "${interpretability.top_features[0].feature}".`
      : '';

  const contrastivePart =
    contrastive.why_not.length > 0
      ? ` It was preferred because: ${contrastive.why_not[0].reason}.`
      : '';

  // Derive a concise lead sentence from the transparency narrative.
  const narrativeLead = transparency.steps.length > 0
    ? `The system chose "${action}" after ${transparency.steps.length} reasoning step${transparency.steps.length !== 1 ? 's' : ''}.`
    : `The system chose "${action}".`;

  const user_summary = `${narrativeLead}${topFeaturePart}${contrastivePart}`;

  // --- Compose technical_summary ---
  const technical_summary = [
    `[XAI | ${explanation_id}]`,
    `Action: ${action}`,
    `Transparency — confidence: ${transparency.confidence}`,
    `Interpretability — ${interpretability.linear_approximation} (fidelity: ${interpretability.fidelity_score})`,
    `Contrastive — rejected ${contrastive.rejected.length} alternative(s)`,
    `Level: ${level}`,
  ].join(' | ');

  return {
    explanation_id,
    level,
    transparency,
    interpretability,
    contrastive,
    user_summary,
    technical_summary,
    generated_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------------

/**
 * Convert an explanation object to a human-readable string.
 *
 * @param {Object} explanation  Return value of generateExplanation
 * @param {'brief'|'normal'|'verbose'} verbosity
 * @returns {string}
 */
export function formatForUser(explanation, verbosity = 'normal') {
  if (!explanation) return '(no explanation available)';

  if (verbosity === 'brief') {
    return explanation.user_summary || '(no summary)';
  }

  if (verbosity === 'verbose') {
    const lines = [
      `=== Explanation ${explanation.explanation_id} ===`,
      `Generated: ${explanation.generated_at}`,
      `Level: ${explanation.level}`,
      '',
      '-- Transparency --',
      explanation.transparency?.narrative ?? '(none)',
      `Confidence: ${explanation.transparency?.confidence ?? 'n/a'}`,
      '',
      '-- Interpretability --',
      explanation.interpretability?.linear_approximation ?? '(none)',
      `Fidelity: ${explanation.interpretability?.fidelity_score ?? 'n/a'}`,
    ];

    if (explanation.interpretability?.top_features?.length > 0) {
      lines.push('Top features:');
      for (const f of explanation.interpretability.top_features) {
        lines.push(`  ${f.direction === 'positive' ? '+' : '-'} ${f.feature} (${f.weight})`);
      }
    }

    lines.push('', '-- Contrastive --');
    lines.push(`Chosen: ${explanation.contrastive?.chosen ?? '(unknown)'}`);
    if (explanation.contrastive?.why_not?.length > 0) {
      lines.push('Why not alternatives:');
      for (const w of explanation.contrastive.why_not) {
        lines.push(`  × ${w.action}: ${w.reason}`);
      }
    }

    lines.push('', '-- Summary --');
    lines.push(explanation.user_summary ?? '(none)');

    return lines.join('\n');
  }

  // 'normal' — balanced view
  const parts = [];
  if (explanation.user_summary) parts.push(explanation.user_summary);

  if (explanation.interpretability?.top_features?.length > 0) {
    const featureList = explanation.interpretability.top_features
      .slice(0, 3)
      .map((f) => `${f.feature} (${f.direction})`)
      .join(', ');
    parts.push(`Key factors: ${featureList}.`);
  }

  if (explanation.contrastive?.rejected?.length > 0) {
    parts.push(`Alternatives considered: ${explanation.contrastive.rejected.join(', ')}.`);
  }

  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// Quality Scorer
// ---------------------------------------------------------------------------

/**
 * Score the quality of an explanation across 4 XAI dimensions.
 *
 * @param {Object} explanation  Return value of generateExplanation
 * @returns {{ coverage: number, fidelity: number, parsimony: number, user_friendliness: number, overall: number }}
 */
export function scoreExplanationQuality(explanation) {
  if (!explanation) {
    return { coverage: 0, fidelity: 0, parsimony: 0, user_friendliness: 0, overall: 0 };
  }

  // Coverage — how many reasoning steps are present relative to expected minimum (5).
  const stepCount = explanation.transparency?.steps?.length ?? 0;
  const coverage = Math.min(1, stepCount / Math.max(stepCount, 5));

  // Fidelity — proxy model's fidelity score (already 0-1 from interpretability pillar).
  const fidelity = explanation.interpretability?.fidelity_score ?? 0;

  // Parsimony — penalises complexity: more features = more complex.
  const featureCount = explanation.interpretability?.top_features?.length ?? 0;
  const alternativeCount = explanation.contrastive?.why_not?.length ?? 0;
  const complexity = featureCount + alternativeCount;
  const parsimony = 1 / (1 + complexity);

  // User-friendliness — can the brief summary fit in 200 characters?
  const summary = explanation.user_summary ?? '';
  const user_friendliness = summary.length <= USER_FRIENDLY_CHAR_LIMIT ? 1 : 0.7;

  // Overall — equally weighted average.
  const overall =
    Math.round(((coverage + fidelity + parsimony + user_friendliness) / 4) * 1000) / 1000;

  return {
    coverage: Math.round(coverage * 1000) / 1000,
    fidelity: Math.round(fidelity * 1000) / 1000,
    parsimony: Math.round(parsimony * 1000) / 1000,
    user_friendliness,
    overall,
  };
}

export function buildEvidencePathExplanation({
  typedEvidencePaths = {},
  multimodalContract = {},
} = {}) {
  const edges = Array.isArray(typedEvidencePaths.edges) ? typedEvidencePaths.edges : [];
  const relationshipTypes = typedEvidencePaths.relationship_types || [...new Set(edges.map((edge) => edge.relationship_type))];
  const sourceCount = Number(typedEvidencePaths.source_count || 0);
  const contractClaimsSupport = Boolean(multimodalContract.claims_support);
  const summary = edges.length > 0
    ? `Evidence path uses ${relationshipTypes.length} typed relationship(s) across ${sourceCount} source(s).`
    : 'No typed evidence path was available for this explanation.';

  return {
    explanation_type: 'typed_evidence_path_explanation',
    source_papers: WAVE5_EVIDENCE_EXPLANATION_AUTHORITIES,
    status: edges.length > 0 ? 'explainable' : 'no_evidence_path',
    diagnostic_only: true,
    user_summary: summary,
    relationship_types: relationshipTypes,
    source_count: sourceCount,
    path_count: edges.length,
    multimodal_contract_status: multimodalContract.status || 'not_supplied',
    unsupported_multimodal_claim: contractClaimsSupport,
    guardrails: {
      hidden_chain_of_thought_exposed: false,
      raw_tool_protocol_exposed: false,
      raw_media_payload_exposed: false,
      production_multimodal_claim: false,
      ranking_math_changed: false,
      canonical_memory_changed: false,
    },
  };
}

/**
 * CoT Explanation Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Chain-of-Thought Prompting
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Assesses whether an explanation contains a structured reasoning chain
 * (step-by-step logical progression). The CoT presence signal does NOT
 * replace the explanation quality scorer. Guarded by guarded_math flag
 * cot_explanation (knowledge-gated).
 */
export function buildCoTExplanationDiagnostic(explanation = {}) {
  const steps = Array.isArray(explanation?.transparency?.steps)
    ? explanation.transparency.steps
    : Array.isArray(explanation?.steps)
      ? explanation.steps
      : [];
  const stepCount = steps.length;
  const stepsWithRationale = steps.filter(s => s.rationale && String(s.rationale).length > 0).length;
  const hasSequentialProgression = stepCount >= 2 && stepsWithRationale >= Math.ceil(stepCount * 0.5);
  const cotPresence = hasSequentialProgression ? 0.8 : stepCount > 0 ? 0.3 : 0;

  return {
    diagnostic: true,
    source_paper: COT_EXPLANATION_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    step_count: stepCount,
    steps_with_rationale: stepsWithRationale,
    cot_presence_score: Number(cotPresence.toFixed(6)),
    has_sequential_progression: hasSequentialProgression,
    explanation_quality_scorer_unchanged: true,
    note: 'Alongside-path diagnostic. CoT presence does not replace explanation quality scorer.',
  };
}
