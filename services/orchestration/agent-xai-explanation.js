/**
 * agent-xai-explanation.js — XAI Explanation & Architecture Decision (Gap 4 extraction)
 *
 * Extracts explanation artifact generation, persistence, and architecture
 * decision logging from agent-runner.js.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: agent-runner.js (post-run explanation capture)
 * 2. → Calls: observe/explainer.js, observe/architecture-registry.js, write/persist-memory.js
 * 3. Pipeline: AGENT_RUN_PIPELINE | Position: post-LLM explanation persistence
 *
 * Created: 2026-05-05 (Gap 4 extraction from agent-runner.js)
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { generateExplanation, EXPLANATION_LEVEL } from '../observe/explainer.js';
import { logAIDecision } from '../observe/architecture-registry.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;

// ─── PURE HELPER FUNCTIONS ─────────────────────────────────────────────────────

/**
 * Build a human-readable action label from run metadata.
 */
export function buildRunActionLabel({ taskType, delegatedTo, rerouted, fallbackUsed }) {
  if (delegatedTo) {
    return `delegate_${taskType || 'task'}_to_${delegatedTo}`;
  }
  if (rerouted) {
    return `reroute_${taskType || 'task'}`;
  }
  if (fallbackUsed) {
    return `fallback_${taskType || 'task'}`;
  }
  return `respond_${taskType || 'task'}`;
}

/**
 * Build structured reasoning steps for XAI explanation.
 */
export function buildRunReasoningSteps({
  taskType,
  executedModel,
  taskRoute,
  delegatedTo,
  rerouted,
  fallbackUsed,
  reasoningSignals
}) {
  const steps = [];
  steps.push({
    step: 1,
    action: `Classified the request as ${taskType || 'chat'}`,
    rationale: taskRoute
      ? `Applied frameworks ${(taskRoute.frameworks || []).join(', ')} with threshold ${taskRoute.confidence_threshold || 0.6}.`
      : `Handled the request as ${taskType || 'chat'} without an explicit framework override.`
  });
  steps.push({
    step: 2,
    action: `Selected model ${executedModel || 'unknown'}`,
    rationale: fallbackUsed
      ? 'The primary model path degraded, so the run used a fallback model to preserve continuity.'
      : 'The selected model matched the resolved execution preference for this task.'
  });
  if (delegatedTo) {
    steps.push({
      step: steps.length + 1,
      action: `Delegated to ${delegatedTo}`,
      rationale: 'Delegation was chosen because another lane looked better suited for part of the task.'
    });
  }
  if (rerouted) {
    steps.push({
      step: steps.length + 1,
      action: 'Rerouted the run',
      rationale: 'Confidence fell below the active task threshold, so the run shifted to an alternative route.'
    });
  }
  for (const signal of (Array.isArray(reasoningSignals) ? reasoningSignals.slice(0, 3) : [])) {
    steps.push({
      step: steps.length + 1,
      action: 'Recorded an explicit rationale signal',
      rationale: String(signal).trim()
    });
  }
  return steps.slice(0, 6);
}

/**
 * Build feature weight vector for XAI explanation.
 */
export function buildRunFeatureWeights({
  confidence,
  allowedToolNames,
  promptChars,
  response,
  delegatedTo,
  rerouted,
  fallbackUsed
}) {
  const responseChars = String(response || '').length;
  return {
    confidence_signal: Number(Number(confidence || 0).toFixed(3)),
    tool_count_signal: Number(Math.min(1, (Array.isArray(allowedToolNames) ? allowedToolNames.length : 0) / 8).toFixed(3)),
    prompt_load_signal: Number(Math.min(1, promptChars / 6000).toFixed(3)),
    response_density_signal: Number(Math.min(1, responseChars / 4000).toFixed(3)),
    delegation_signal: delegatedTo ? 0.24 : 0.04,
    reroute_penalty: rerouted ? -0.28 : 0.05,
    fallback_penalty: fallbackUsed ? -0.22 : 0.05
  };
}

/**
 * Build alternative actions for XAI explanation.
 */
export function buildRunAlternatives({ taskType, delegatedTo, rerouted, fallbackUsed, resolvedModel }) {
  const alternatives = [];
  if (delegatedTo) {
    alternatives.push({
      action: `keep_${taskType || 'task'}_local`,
      reason: 'The run could have stayed on the current agent without delegation.'
    });
  }
  if (rerouted) {
    alternatives.push({
      action: `stay_on_primary_${taskType || 'task'}_route`,
      reason: 'The run could have remained on the primary route despite reduced confidence.'
    });
  }
  if (fallbackUsed) {
    alternatives.push({
      action: `stay_on_primary_model`,
      reason: `The run could have stayed on the originally preferred model instead of using ${resolvedModel || 'a fallback'}.`
    });
  }
  return alternatives;
}

/**
 * Map confidence to an uncertainty band label.
 */
export function confidenceBand(confidence) {
  if (confidence >= 0.8) return 'low-uncertainty';
  if (confidence >= 0.55) return 'medium-uncertainty';
  return 'high-uncertainty';
}

/**
 * Infer blast radius from task type and intent.
 */
export function inferBlastRadius({ taskType, intent }) {
  const corpus = `${String(taskType || '')} ${String(intent || '')}`.toLowerCase();
  if (/\b(post|email|calendar|notify|message|trade|deploy)\b/.test(corpus)) {
    return 'external-surface';
  }
  if (/\b(frontend|ui|model|provider|stream|aimos|memory|backend)\b/.test(corpus)) {
    return 'product-surface';
  }
  return 'local-run';
}

/**
 * Compact text for evidence fields, truncating with ellipsis.
 */
export function compactEvidenceText(value, maxLength = 220) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}

// ─── MAIN EXPLANATION PERSISTENCE ──────────────────────────────────────────────

/**
 * Capture XAI explanation and architecture decision for a completed run.
 * Generates a DARPA XAI explanation artifact, persists it to aimos memory,
 * and logs an architecture decision.
 *
 * @param {Object} params
 * @returns {Promise<{explanationArtifact: Object|null, architectureDecision: Object|null}>}
 */
export async function captureExplanationAndDecision({
  runtimeAgent,
  taskType,
  executedModel,
  finalConfidence,
  response,
  userPrompt,
  reasoningSignals,
  delegatedTo,
  rerouteCheck,
  fallbackUsed,
  fastLane,
  options,
  allowedToolNames,
  promptChars,
  autonomy,
  taskRoute,
  runEndTime,
  successTraceEventId,
  skipAimos
}) {
  const shouldCapture =
    !fastLane
    && !skipAimos
    && !(options?._investigationLoopActive)
    && response
    && String(response).length > 120
    && (
      reasoningSignals.length > 0
      || taskType !== 'chat'
      || delegatedTo
      || !!rerouteCheck?.reroute
      || fallbackUsed
    );

  if (!shouldCapture) {
    return { explanationArtifact: null, architectureDecision: null };
  }

  let explanationArtifact = null;
  let architectureDecision = null;

  try {
    const actionLabel = buildRunActionLabel({
      taskType,
      delegatedTo,
      rerouted: !!rerouteCheck?.reroute,
      fallbackUsed
    });

    const reasoningSteps = buildRunReasoningSteps({
      taskType,
      executedModel,
      taskRoute,
      delegatedTo,
      rerouted: !!rerouteCheck?.reroute,
      fallbackUsed,
      reasoningSignals
    });

    explanationArtifact = generateExplanation({
      action: actionLabel,
      reasoning_steps: reasoningSteps,
      features: buildRunFeatureWeights({
        confidence: finalConfidence,
        allowedToolNames,
        promptChars,
        response,
        delegatedTo,
        rerouted: !!rerouteCheck?.reroute,
        fallbackUsed
      }),
      alternatives: buildRunAlternatives({
        taskType,
        delegatedTo,
        rerouted: !!rerouteCheck?.reroute,
        fallbackUsed,
        resolvedModel: executedModel
      }),
      confidence: finalConfidence,
      agent_id: runtimeAgent.id
    }, EXPLANATION_LEVEL.DETAILED);

    const explanationKey = `event_explanation_${runtimeAgent.id}_${runEndTime}`;
    const explanationBullet = [
      `• ${new Date(runEndTime).toISOString().slice(11, 16)} — [explanation] ${runtimeAgent.id} ${taskType} decision`,
      `  result: ${compactEvidenceText(explanationArtifact.technical_summary, 280)}`,
      `  reasoning: ${compactEvidenceText(explanationArtifact.user_summary, 280)}`,
      `  source: DARPA XAI (Gunning 2017, 2019)`,
      `  next: ${autonomy.action === 'escalate' ? 'human review' : rerouteCheck?.reroute ? 'review alternate route outcome' : 'continue session'}`
    ].join('\n');

    await persistMemory({
      company_id: COMPANY,
      agent_id: runtimeAgent.id,
      key: explanationKey,
      value: explanationBullet,
      scope: 'system',
      memory_type: 'event_log',
      clearance_level: 3,
      source: 'agent-runner',
      mutation_authority: 'housekeeper',
    });

    const reasoningTraceKey = `session_reasoning:${runtimeAgent.id}:${runEndTime}`;
    const reasoningTraceArtifact = {
      trace_id: reasoningTraceKey,
      problem: compactEvidenceText(String(userPrompt || ''), 320),
      steps: reasoningSteps.map((step, index) => ({
        step: step.step ?? index + 1,
        action: step.action ?? '(unknown action)',
        rationale: step.rationale ?? null,
      })),
      evidence: reasoningSignals.slice(0, 8),
      decision: compactEvidenceText(
        delegatedTo
          ? `Delegated part of the ${taskType} run to ${delegatedTo} while completing the active response on ${executedModel}.`
          : `Completed the ${taskType} run on ${executedModel}${fallbackUsed ? ' using fallback routing' : ''}${rerouteCheck?.reroute ? ' after rerouting' : ''}.`,
        320
      ),
      why: compactEvidenceText(explanationArtifact.user_summary, 320),
      confidence: Number(finalConfidence.toFixed(3)),
      linked_outputs: {
        response_preview: compactEvidenceText(String(response || ''), 360),
        explanation_id: explanationArtifact.explanation_id,
        explanation_event_key: explanationKey,
      },
      parent_session: options?.sessionId || options?.threadId || null,
      parent_trace: options?.parentTraceId || null,
      task_type: taskType,
      model: executedModel,
      created_at: new Date(runEndTime).toISOString(),
    };

    await persistMemory({
      company_id: COMPANY,
      agent_id: runtimeAgent.id,
      key: reasoningTraceKey,
      value: JSON.stringify(reasoningTraceArtifact),
      scope: 'system',
      memory_type: 'session_reasoning',
      clearance_level: 4,
      source: 'agent-runner',
      mutation_authority: 'housekeeper',
    });

    architectureDecision = await logAIDecision({
      title: `${runtimeAgent.id}:${taskType}:run_decision`,
      context: compactEvidenceText(String(userPrompt || ''), 320),
      decision: compactEvidenceText(
        delegatedTo
          ? `Delegated part of the ${taskType} run to ${delegatedTo} while completing the active response on ${executedModel}.`
          : `Completed the ${taskType} run on ${executedModel}${fallbackUsed ? ' using a fallback path' : ''}${rerouteCheck?.reroute ? ' after rerouting' : ''}.`,
        320
      ),
      consequences: compactEvidenceText(
        `Run produced ${String(response || '').length} response chars at confidence ${finalConfidence.toFixed(2)} with autonomy action ${autonomy.action}.`,
        320
      ),
      status: 'applied',
      uncertainty_estimate: confidenceBand(finalConfidence),
      drift_potential: finalConfidence >= 0.75 ? 'low' : finalConfidence >= 0.5 ? 'medium' : 'high',
      blast_radius: inferBlastRadius({ taskType, intent: options?.intent || taskType }),
      reversibility: delegatedTo || rerouteCheck?.reroute ? 'reversible' : 'costly',
      evaluation_criteria: `Confidence ${(finalConfidence || 0).toFixed(2)} against threshold ${(taskRoute?.confidence_threshold || 0.6).toFixed(2)}; user-visible run completed without tool approval violations.`,
      human_oversight_level: autonomy.action === 'escalate' ? 'full' : autonomy.action === 'notify' ? 'partial' : 'automated',
      governance_approved_by: 'agent-runner',
      what: compactEvidenceText(String(userPrompt || ''), 220),
      how: compactEvidenceText(
        delegatedTo
          ? `Resolved with ${executedModel}, delegated to ${delegatedTo}, tools ${allowedToolNames.slice(0, 6).join(', ') || 'none'}.`
          : `Resolved with ${executedModel}, tools ${allowedToolNames.slice(0, 6).join(', ') || 'none'}, reroute=${!!rerouteCheck?.reroute}.`,
        220
      ),
      why: compactEvidenceText(explanationArtifact.user_summary, 220),
      affected_surface: taskType,
      confidence: Number(finalConfidence.toFixed(2)),
      evidence: {
        explanation_id: explanationArtifact.explanation_id,
        explanation_event_key: explanationKey,
        reasoning_signal_count: reasoningSignals.length,
        source_event_id: successTraceEventId || null
      }
    });
  } catch (explainErr) {
    console.warn('[agent-runner] explanation / architecture decision capture failed (non-fatal):', explainErr.message);
  }

  return { explanationArtifact, architectureDecision };
}
