/**
 * aimos-mcp-catalog.js — Aimos MCP Tool Catalog
 *
 * Status: Live catalog surface
 *
 * Purpose:
 * Provides the shared MCP tool manifest consumed by routes/mcp.js,
 * routes/aimos-mcp-streamable.js, and the legacy /aimos/mcp endpoints.
 *
 * Boundary:
 * This file is intentionally data-only. It does not call Aimos services,
 * does not change save/recall behavior, and does not alter calibration math.
 */

const DEFAULT_COMPANY = 'hom';

function objectSchema(properties, required = []) {
  return {
    type: 'object',
    properties,
    required,
    additionalProperties: false,
  };
}

export const AIMOS_MCP_TOOLS = Object.freeze([
  {
    name: 'aimos_status',
    category: 'system',
    endpoint: '/aimos/status',
    description: 'Return Aimos memory count, speed flags, cache stats, and server boot state.',
    inputSchema: objectSchema({
      company_id: { type: 'string', default: DEFAULT_COMPANY },
    }),
  },
  {
    name: 'aimos_system_health',
    category: 'system',
    endpoint: '/aimos/system-health',
    description: 'Return Aimos topology, pipeline validation, and high-level runtime health.',
    inputSchema: objectSchema({
      company_id: { type: 'string', default: DEFAULT_COMPANY },
    }),
  },
  {
    name: 'aimos_recall',
    category: 'memory',
    endpoint: '/aimos/recall',
    description: 'Recall Aimos memories by query, exact key, or memory id through the configured recall path.',
    inputSchema: objectSchema({
      query: { type: 'string', description: 'Semantic recall query. Required unless key or memory_id is provided.' },
      key: { type: 'string', description: 'Exact Aimos memory key.' },
      memory_id: { type: 'string', description: 'Exact Aimos memory UUID.' },
      company_id: { type: 'string', default: DEFAULT_COMPANY },
      clearance_level: { type: 'integer', description: 'Optional cap; cannot exceed the master-signed recall grant.' },
      limit: { type: 'integer', default: 10, minimum: 1, maximum: 200 },
      memory_type_filter: { type: 'string' },
      source_filter: { type: 'string' },
      mode: { type: 'string', enum: ['adaptive', 'linear'], default: 'adaptive' },
      sort: { type: 'string', enum: ['semantic', 'chronological'], default: 'semantic' },
      selectivity: { type: 'string', default: 'standard' },
      lazy: { type: 'boolean', default: true },
    }),
  },
  {
    name: 'aimos_open_memory',
    category: 'memory',
    endpoint: '/aimos/open-memory',
    description: 'Open exact Aimos memory records by key or UUID.',
    inputSchema: objectSchema({
      key: { type: 'string' },
      memory_id: { type: 'string' },
      company_id: { type: 'string', default: DEFAULT_COMPANY },
      clearance_level: { type: 'integer', description: 'Optional cap; cannot exceed the master-signed recall grant.' },
      limit: { type: 'integer', default: 10, minimum: 1, maximum: 200 },
    }),
  },
  {
    name: 'aimos_qmd_explain',
    category: 'query',
    endpoint: '/aimos/qmd/explain',
    description: 'Parse and explain a QMD query without executing it.',
    inputSchema: objectSchema({
      query: { type: 'string' },
      company_id: { type: 'string', default: DEFAULT_COMPANY },
    }, ['query']),
  },
  {
    name: 'aimos_save',
    category: 'memory_write',
    endpoint: '/aimos/save',
    description: 'Persist a quality-gated Aimos memory through the configured save path.',
    inputSchema: objectSchema({
      key: { type: 'string' },
      value: { type: 'string' },
      company_id: { type: 'string', default: DEFAULT_COMPANY },
      memory_type: { type: 'string', default: 'declarative' },
      scope: { type: 'string', default: 'global' },
      clearance_level: { type: 'integer', default: 1 },
      source: { type: 'string' },
    }, ['key', 'value']),
  },
]);

export function findAimosMcpTool(name) {
  const normalized = String(name || '').trim();
  if (!normalized) return null;
  return AIMOS_MCP_TOOLS.find((tool) => tool.name === normalized) || null;
}

export function buildAimosMcpManifest(options = {}) {
  return {
    name: options.name || 'HOM Aimos MCP',
    version: options.version || '2.0.0',
    protocol: options.protocol || 'mcp',
    transport: options.transport || 'streamablehttp',
    tools: AIMOS_MCP_TOOLS,
  };
}

export default {
  AIMOS_MCP_TOOLS,
  findAimosMcpTool,
  buildAimosMcpManifest,
};
