/**
 * agent-investigation-loop.js — Investigation Loop (Gap 4 extraction)
 *
 * Extracts investigation loop classification, technique construction,
 * evidence normalization, and context building from agent-runner.js.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: agent-runner.js (pre-LLM investigation, context assembly)
 * 2. → Calls: explore-exploit-loop.js (runInvestigationLoop)
 * 3. Pipeline: AGENT_RUN_PIPELINE | Position: pre-LLM investigation
 *
 * Created: 2026-05-05 (Gap 4 extraction from agent-runner.js)
 */

import { runInvestigationLoop } from './explore-exploit-loop.js';
import { compactEvidenceText } from './agent-xai-explanation.js';

// ─── INVESTIGATION CLASSIFICATION ──────────────────────────────────────────────

const INVESTIGATION_TASK_TYPES = new Set(['research', 'analysis', 'investigation']);
const INVESTIGATION_PROMPT_REGEX = /\b(analyze|analysis|research|investigate|investigation|audit|compare|deep dive|root cause|synthesize|review)\b/i;

/**
 * Determine whether an investigation loop should run for this task.
 */
export function shouldRunInvestigationLoop({ taskType, userPrompt, fastLane, options = {} }) {
  if (fastLane || options._investigationLoopActive || options.skipInvestigationLoop) {
    return false;
  }
  if (options.enableInvestigationLoop === true) {
    return true;
  }
  return INVESTIGATION_TASK_TYPES.has(String(taskType || '').toLowerCase())
    || INVESTIGATION_PROMPT_REGEX.test(String(userPrompt || ''));
}

// ─── TECHNIQUE CONSTRUCTION ────────────────────────────────────────────────────

/**
 * Build the list of investigation techniques for a given task.
 */
export function buildInvestigationTechniques(taskType, taskRoute) {
  const techniques = [
    {
      id: 'aimos_recall_probe',
      instruction: 'Use Aimos-first recall to retrieve the strongest directly relevant artifacts, session debriefs, and continuity evidence before drawing conclusions.'
    },
    {
      id: 'verification_probe',
      instruction: 'Stress-test the leading explanation against concrete evidence and mark unsupported claims as unresolved rather than inferring them.'
    },
    {
      id: 'counterexample_probe',
      instruction: 'Search for the strongest counterexample, contradiction, or alternative explanation that would overturn the current conclusion.'
    }
  ];

  const frameworks = Array.isArray(taskRoute?.frameworks)
    ? taskRoute.frameworks.filter(Boolean).slice(0, 2)
    : [];
  for (const framework of frameworks) {
    techniques.push({
      id: `framework_${String(framework).toLowerCase().replace(/[^a-z0-9]+/g, '_')}`,
      instruction: `Cross-check the objective using the ${framework} framework and surface only evidence that survives that perspective.`
    });
  }

  return techniques.slice(0, 4);
}

// ─── EVIDENCE NORMALIZATION ─────────────────────────────────────────────────────

function coerceRateNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value > 1 && value <= 100 ? Number((value / 100).toFixed(4)) : Number(value.toFixed(4));
  }
  const raw = String(value).trim();
  if (!raw) return null;
  if (raw.endsWith('%')) {
    const parsed = Number.parseFloat(raw.slice(0, -1));
    return Number.isFinite(parsed) ? Number((parsed / 100).toFixed(4)) : null;
  }
  const parsed = Number.parseFloat(raw);
  if (!Number.isFinite(parsed)) return null;
  return parsed > 1 && parsed <= 100 ? Number((parsed / 100).toFixed(4)) : Number(parsed.toFixed(4));
}

function coerceInteger(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Normalize investigation evidence items for structured storage.
 */
export function normalizeInvestigationEvidence(items = []) {
  if (!Array.isArray(items)) return [];
  return items
    .slice(0, 6)
    .map((item) => ({
      claim: compactEvidenceText(item?.claim || item?.summary || item?.source || '', 160) || 'Unlabeled evidence',
      baseRate: coerceRateNumber(item?.baseRate),
      observedRate: coerceRateNumber(item?.observedRate),
      sampleSize: coerceInteger(item?.sampleSize),
      source: compactEvidenceText(item?.source || item?.note || '', 180) || 'No source note',
      note: compactEvidenceText(item?.note || '', 180) || ''
    }))
    .filter((item) => item.claim || item.baseRate !== null || item.observedRate !== null || item.sampleSize !== null);
}

// ─── JSON PARSING ───────────────────────────────────────────────────────────────

function extractJsonCandidate(text) {
  const source = String(text || '').trim();
  if (!source) return null;
  const fenced = source.match(/```json\s*([\s\S]*?)```/i) || source.match(/```\s*([\s\S]*?)```/);
  if (fenced?.[1]) {
    return fenced[1].trim();
  }
  const firstBrace = source.indexOf('{');
  const lastBrace = source.lastIndexOf('}');
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    return source.slice(firstBrace, lastBrace + 1);
  }
  return null;
}

/**
 * Parse an LLM response from an investigation iteration into structured data.
 */
export function parseInvestigationIterationResponse(responseText, technique) {
  const raw = String(responseText || '').trim();
  const candidate = extractJsonCandidate(raw);
  if (candidate) {
    try {
      const parsed = JSON.parse(candidate);
      return {
        summary: compactEvidenceText(parsed?.summary || parsed?.finding || raw, 320),
        evidence: normalizeInvestigationEvidence(parsed?.evidence),
        objectiveMet: Boolean(parsed?.objectiveMet)
      };
    } catch {
      // Fall through to plain-text fallback.
    }
  }

  return {
    summary: compactEvidenceText(raw || `Iteration completed for ${technique.id}.`, 320),
    evidence: [],
    objectiveMet: false
  };
}

// ─── CONTEXT BUILDING ──────────────────────────────────────────────────────────

/**
 * Summarize prior investigation findings for prompt injection.
 */
export function summarizePriorInvestigationFindings(priorFindings = []) {
  if (!Array.isArray(priorFindings) || priorFindings.length === 0) {
    return 'No prior investigation findings recorded yet.';
  }
  return priorFindings
    .slice(-3)
    .map((entry, index) => {
      const status = String(entry?.status || 'unknown');
      const technique = String(entry?.technique || `technique_${index + 1}`);
      const finding = compactEvidenceText(entry?.finding || '', 180) || 'No summary recorded.';
      return `- ${technique} [${status}] ${finding}`;
    })
    .join('\n');
}

/**
 * Build the prompt for a single investigation iteration.
 */
export function buildInvestigationIterationPrompt({ objective, technique, priorFindings, taskType }) {
  return [
    'You are running a bounded investigation iteration for the parent objective below.',
    `Objective: ${compactEvidenceText(objective, 800)}`,
    `Task type: ${taskType || 'analysis'}`,
    `Technique: ${technique.id}`,
    `Technique instruction: ${technique.instruction}`,
    'Prior findings:',
    summarizePriorInvestigationFindings(priorFindings),
    '',
    'Rules:',
    '- Aimos-first retrieval and live tools before unsupported reasoning.',
    '- If the evidence is weak, say so explicitly.',
    '- Never invent metrics or retrieval results.',
    '- Return strict JSON only.',
    '',
    'Schema:',
    '{"summary":"string","objectiveMet":false,"evidence":[{"claim":"string","baseRate":null,"observedRate":null,"sampleSize":null,"source":"string","note":"string"}]}'
  ].join('\n');
}

/**
 * Build the investigation context string for prompt injection.
 */
export function buildInvestigationContext(loopResult) {
  if (!loopResult?.findings?.length) {
    return '';
  }
  const lines = [
    '',
    '### INVESTIGATION LOOP (bounded fast-slow probe):'
  ];
  for (const finding of loopResult.findings.slice(0, 4)) {
    lines.push(`- ${finding.technique} [${finding.status}] ${compactEvidenceText(finding.finding || '', 180) || 'No summary recorded.'}`);
  }
  const confirmed = loopResult.findings.filter((entry) => entry.status === 'confirmed').length;
  const partial = loopResult.findings.filter((entry) => entry.status === 'partial').length;
  const insufficient = loopResult.findings.filter((entry) => entry.status === 'insufficient_evidence').length;
  lines.push(`Investigation totals: confirmed=${confirmed}, partial=${partial}, insufficient=${insufficient}.`);
  return `${lines.join('\n')}\n`;
}