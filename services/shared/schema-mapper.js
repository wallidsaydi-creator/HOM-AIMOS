// ═══════════════════════════════════════════════════════════════════════════════
// SCHEMA MAPPER (schema-mapper.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Source: OpenAI Function Calling, Semantic parsing (Lisp s-expressions)
// P1-1: LLM as Extractor Not Planner
//
// Deterministic bridge between LLM extraction output and tool execution.
// The LLM's role is strictly extraction of structured intermediate facts —
// it does NOT decide which tools to call or in what order.
// The mapper performs deterministic, schema-validated dispatch.
//
// Design principle: separate the "what is in the world" (LLM's domain) from
// "what should be executed" (deterministic rule domain). Prevents hallucinated
// tool calls from reaching execution.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run step 15)
// → Calls: services/shared/native-llm.js (LLM extraction call)
// → Calls: services/observe/event-ledger.js (extraction events)
// Pipeline: AGENT_RUN_PIPELINE
// Position: structured fact extraction
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { runProvider } from '../core/providers.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// Supported primitive types for parameter validation
const SUPPORTED_TYPES = new Set(['string', 'number', 'boolean', 'array', 'object']);

/**
 * Derive a JSON schema from an array of tool definitions.
 * Each tool definition is expected to have: name, description, parameters.
 *
 * @param {Array<{name: string, description: string, parameters: Object}>} tools
 * @returns {Object} JSON Schema object describing available tools
 */
export function getToolSchema(tools) {
  if (!Array.isArray(tools) || tools.length === 0) {
    return { tools: [] };
  }

  return {
    tools: tools.map((tool) => ({
      name: String(tool.name || ''),
      description: String(tool.description || ''),
      parameters: tool.parameters && typeof tool.parameters === 'object'
        ? tool.parameters
        : { type: 'object', properties: {}, required: [] },
    })),
  };
}

/**
 * Validate that a value matches a given JSON Schema type descriptor.
 * Supports: string, number, boolean, array, object, integer.
 *
 * @param {*} value - Value to validate
 * @param {string} expectedType - Expected JSON schema type
 * @returns {boolean}
 */
function validateType(value, expectedType) {
  if (expectedType === 'integer') return Number.isInteger(value);
  if (expectedType === 'number') return typeof value === 'number' && !Number.isNaN(value);
  if (expectedType === 'array') return Array.isArray(value);
  if (expectedType === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  return typeof value === expectedType;
}

/**
 * Deterministically map extracted facts to validated tool calls.
 * Rejects any fact that does not exactly match the tool schema.
 *
 * @param {Array<{tool: string, params: Object}>} facts - Extracted intermediate facts
 * @param {Object} toolSchema - Schema from getToolSchema()
 * @returns {Array<{tool: string, params: Object, valid: boolean, violations: string[]}>}
 */
export function mapFactsToToolCalls(facts, toolSchema) {
  if (!Array.isArray(facts)) return [];

  const toolIndex = new Map(
    (toolSchema?.tools || []).map((t) => [t.name, t])
  );

  return facts.map((fact) => {
    const toolName = String(fact?.tool || '');
    const params = fact?.params && typeof fact.params === 'object' ? fact.params : {};

    // Unknown tool
    if (!toolIndex.has(toolName)) {
      return {
        tool: toolName,
        params,
        valid: false,
        violations: [`Unknown tool: '${toolName}'`],
      };
    }

    const schema = toolIndex.get(toolName);
    const schemaProps = schema.parameters?.properties || {};
    const required = Array.isArray(schema.parameters?.required)
      ? schema.parameters.required
      : [];
    const violations = [];

    // Check required parameters are present
    for (const req of required) {
      if (!(req in params)) {
        violations.push(`Missing required parameter: '${req}'`);
      }
    }

    // Check parameter types match schema
    for (const [key, val] of Object.entries(params)) {
      if (!Object.prototype.hasOwnProperty.call(schemaProps, key)) {
        violations.push(`Unknown parameter: '${key}'`);
        continue;
      }
      const expectedType = schemaProps[key]?.type;
      if (expectedType && SUPPORTED_TYPES.has(expectedType) || expectedType === 'integer') {
        if (!validateType(val, expectedType)) {
          violations.push(`Parameter '${key}' expected type '${expectedType}', got '${typeof val}'`);
        }
      }
    }

    return {
      tool: toolName,
      params,
      valid: violations.length === 0,
      violations,
    };
  });
}

/**
 * Extract structured facts from a prompt via LLM, constrained to the
 * available tool schema. The LLM returns an intermediate representation;
 * the mapper (mapFactsToToolCalls) handles deterministic dispatch.
 *
 * @param {string} prompt - User/agent prompt describing work to be done
 * @param {Array<{name: string, description: string, parameters: Object}>} availableTools
 * @returns {Promise<Array<{tool: string, params: Object}>>}
 */
export async function extractStructuredFacts(prompt, availableTools) {
  if (!prompt || typeof prompt !== 'string') return [];

  const schema = getToolSchema(availableTools);
  const schemaJson = JSON.stringify(schema, null, 2);

  const extractionPrompt = `You are a structured fact extractor. Extract what actions need to be performed based on the user prompt.

AVAILABLE TOOLS (JSON Schema):
${schemaJson}

USER PROMPT:
${String(prompt).slice(0, 3000)}

Return ONLY a JSON array of tool invocations — no markdown, no explanation, no prose.
Each element must exactly match a tool from the schema above.

Output format:
[{"tool": "<tool_name>", "params": {"<param_name>": <value>}}, ...]

Rules:
- Only include tools that are listed in AVAILABLE TOOLS
- Only include parameters that exist in the tool's schema
- Use the exact parameter types specified in the schema
- Return [] if no tools apply
- Do NOT invent tool names or parameters`;

  let raw = '';
  try {
    raw = await runProvider({ prompt: extractionPrompt });
  } catch (err) {
    console.error('[schema-mapper] extractStructuredFacts LLM call failed:', err.message);
    return [];
  }

  try {
    const fenceStripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    // Extract the first JSON array found
    const arrayMatch = fenceStripped.match(/\[[\s\S]*\]/);
    if (!arrayMatch) return [];
    const parsed = JSON.parse(arrayMatch[0]);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch (err) {
    console.error('[schema-mapper] Failed to parse LLM extraction output:', err.message);
    return [];
  }
}
