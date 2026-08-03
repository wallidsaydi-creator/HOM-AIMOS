// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js, tests
// Pipeline: AGENT_RUN_PIPELINE
// Position: passive tool representation diagnostics
// Batch8 Wave4 sources: ASA, Transparent and Controllable Recommendation
// Filtering, AI Agent Systems. Representations explain tool fit without
// changing authorization or execution.
// ─────────────────────────────────────────────────────────────────────────────

function summarizeToolSchema(toolDef) {
  const fn = toolDef?.schema?.function || {};
  const parameters = fn.parameters || {};
  const properties = parameters.properties && typeof parameters.properties === 'object'
    ? Object.keys(parameters.properties)
    : [];
  return {
    description: String(fn.description || '').slice(0, 220),
    required: Array.isArray(parameters.required) ? parameters.required.slice(0, 12) : [],
    properties: properties.slice(0, 20)
  };
}

function findSuiteSources(toolName, suiteToTools = {}) {
  return Object.entries(suiteToTools || {})
    .filter(([, tools]) => Array.isArray(tools) && tools.includes(toolName))
    .map(([suite]) => suite)
    .slice(0, 12);
}

export function buildToolRepresentation(name, options = {}) {
  const toolName = String(name || '').trim();
  const toolDefs = options.toolDefs || {};
  const tool = toolDefs[toolName];
  if (!tool) {
    return {
      tool: toolName,
      exists: false,
      diagnostic_only: true,
      automatic_tool_unlock_enabled: false,
      issues: [`Unknown tool: ${toolName}`]
    };
  }

  const directionResolver = typeof options.resolveToolDirection === 'function'
    ? options.resolveToolDirection
    : () => 'internal';
  const sideEffectTools = options.sideEffectTools instanceof Set ? options.sideEffectTools : new Set();
  const quotaSpendingTools = options.quotaSpendingTools instanceof Set ? options.quotaSpendingTools : new Set();
  const toolClearanceLevels = options.toolClearanceLevels || {};
  const direction = directionResolver(toolName);
  const sideEffecting = sideEffectTools.has(toolName);
  const approvalNeed = options.autonomous === true && quotaSpendingTools.has(toolName);
  const clearance = toolClearanceLevels[toolName] || 1;
  const agentClearance = Number(options.clearanceLevel || 1);
  const blockedByClearance = agentClearance < clearance;

  return {
    source_papers: [
      'ASA',
      'Transparent and Controllable Recommendation Filtering',
      'AI Agent Systems'
    ],
    diagnostic_only: true,
    automatic_tool_unlock_enabled: false,
    behavior_changed: false,
    tool: toolName,
    exists: true,
    schema_summary: summarizeToolSchema(tool),
    direction,
    side_effect_class: sideEffecting ? 'side_effecting' : 'read_or_internal',
    required_clearance: clearance,
    agent_clearance: agentClearance,
    clearance_satisfied: !blockedByClearance,
    approval_required_if_autonomous: approvalNeed,
    suite_sources: findSuiteSources(toolName, options.suiteToTools),
    rationale: sideEffecting
      ? `Tool ${toolName} can change external or persistent state, so approval and clearance gates remain authoritative.`
      : `Tool ${toolName} is represented for selection transparency; this diagnostic does not grant access.`,
    guarded_control: {
      tool_activation_steering_enabled: false,
      autonomous_tool_unlock_enabled: false,
      hidden_filtering_enabled: false,
      preference_graph_mutation_enabled: false
    }
  };
}

export function getToolRepresentationsForAgent(toolNames = [], options = {}) {
  return (Array.isArray(toolNames) ? toolNames : [])
    .map((name) => buildToolRepresentation(name, options));
}
