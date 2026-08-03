// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js, tests
// Pipeline: AGENT_RUN_PIPELINE
// Position: passive run diagnostics
// Batch8 Wave4 sources: GrandCode, LLM-Agent-Controller, AI Agent Systems,
// FronTalk. Benchmark traces are diagnostic only; agentic RL remains guarded.
// Batch9 Wave3 boundary: raw tool protocol is never user-visible; plaintext
// tool-call syntax from a model is guarded, not executed or displayed.
// ─────────────────────────────────────────────────────────────────────────────

const RAW_TOOL_PROTOCOL_PATTERNS = [
  /<\s*function_calls?\s*>/i,
  /<\s*\/\s*function_calls?\s*>/i,
  /<\s*invoke\s+name\s*=/i,
  /<\s*arg\s+name\s*=/i,
  /<\s*\/\s*invoke\s*>/i,
  /"tool_calls"\s*:/i,
  /"function_call"\s*:/i
];

export function detectRawToolProtocolText(text = '') {
  const value = String(text || '');
  if (!value.trim()) return false;
  return RAW_TOOL_PROTOCOL_PATTERNS.some((pattern) => pattern.test(value));
}

export function guardRawToolProtocolText(text = '') {
  const value = String(text || '');
  if (!detectRawToolProtocolText(value)) {
    return {
      guarded: false,
      reason: null,
      response: value,
      raw_protocol_exposed: false,
      tool_executed: false
    };
  }

  return {
    guarded: true,
    reason: 'raw_tool_protocol_text_detected',
    response: 'A model emitted raw tool-call protocol text. The protocol was withheld, no tool was executed, and the run is marked for guarded retry or human review.',
    raw_protocol_exposed: false,
    tool_executed: false
  };
}

export function buildAgentBenchmarkTrace({
  runId,
  taskType,
  modelRequested,
  modelResolved,
  latencyMs,
  confidence,
  promptChars,
  responseChars,
  toolCount,
  fallbackUsed = false,
  rerouted = false,
  metaAction = null,
  scratReflectionCount = 0,
} = {}) {
  return {
    source_papers: [
      'GrandCode',
      'LLM-Agent-Controller — Universal Multi-Agent System as Control Engineer',
      'AI Agent Systems',
      'FronTalk'
    ],
    diagnostic_only: true,
    behavior_changed: false,
    run_id: runId || null,
    task_type: taskType || 'unknown',
    model_requested: modelRequested || null,
    model_resolved: modelResolved || null,
    latency_ms: Number.isFinite(Number(latencyMs)) ? Number(latencyMs) : null,
    confidence: Number.isFinite(Number(confidence)) ? Number(Number(confidence).toFixed(4)) : null,
    prompt_chars: Math.max(0, Number(promptChars || 0)),
    response_chars: Math.max(0, Number(responseChars || 0)),
    tool_count: Math.max(0, Number(toolCount || 0)),
    fallback_used: fallbackUsed === true,
    rerouted: rerouted === true,
    meta_action: metaAction || null,
    scrat_reflection_count: Math.max(0, Number(scratReflectionCount || 0)),
    convergence_status: fallbackUsed || rerouted ? 'needs_review' : 'bounded',
    guarded_math: {
      agentic_rl_enabled: false,
      online_test_time_rl_enabled: false,
      controller_autocorrection_enabled: false,
      visual_feedback_ranking_enabled: false
    }
  };
}
