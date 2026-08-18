/**
 * aimos-mcp-streamable.js — Native StreamableHTTP MCP Server
 *
 * Status: Live
 * Source: Anthropic MCP StreamableHTTP spec (modelcontextprotocol.io)
 *          + HOM Aimos architecture authority (aimos-llm-guide.md)
 *
 * PURPOSE:
 * Exposes Aimos's MCP surface as a native StreamableHTTP endpoint at /mcp.
 * Any MCP client (LM Studio, Goose, Claude Desktop, Cursor, etc.) can connect
 * using standard MCP protocol — no REST wrapper, no custom client needed.
 *
 * ARCHITECTURE:
 * This is a thin JSON-RPC 2.0 protocol translator. It maps MCP requests onto
 * the existing Aimos service layer (recall, save, status, QMD, etc.) which
 * already enforces all gates (Quality Gate, Knowledge Gate, RPE Gate, Sudo Guard,
 * Aladdin Law, medallion layers, clearance ACLs). The MCP transport adds zero
 * bypasses — every call goes through the full save/recall pipeline.
 *
 * RELATION TO EXISTING routes/mcp.js:
 * routes/mcp.js is an MCP BRIDGE — it manages connections TO external MCP servers
 * (add/remove servers, execute tools on them). This file exposes Aimos AS an MCP
 * server TO external clients. Both live at /mcp; bridge routes are prefixed with
 * /bridge to avoid conflict.
 *
 * PIPELINE: N/A (protocol translator only — gates fire at service layer)
 * CONNECTION GUIDE:
 *  ← Called by: server.js (Express, envelope auth already validated)
 *  → Calls: routes/aimos.js /aimos/mcp/tools/call (existing tool executor)
 *          OR direct service calls for parity with REST save/recall paths
 */

// ─── SEMANTIC QUERY CACHE (Phase 1) ──────────────────────────────────────────
// Status: Ephemeral LRU Cache — Purely in-memory, no schema changes
// Purpose: Eliminates redundant full recall operations for identical/similar queries
// Source: Cache-Augmented Generation (Gao et al., 2024) — Speed.md Appendix A
// Agreement Paradox Detection: Frugal Knowledge Graph (Jourlin, 2026)
// Compliance: Knowledge Gate [X] | Aladdin Law [X] (ephemeral only)
// ─────────────────────────────────────────────────────────────────────────────

import express from 'express';
import { randomUUID } from 'crypto';
import { AIMOS_MCP_TOOLS, findAimosMcpTool } from '../services/orchestration/aimos-mcp-catalog.js';
import { appendSecurityDecision, evaluateSecurityContent } from '../services/security/se-gate.js';
import { evaluateCanaryWrite } from '../services/security/canary-write-gate.js';
import { resolveNativeRecallAuthority } from '../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../services/retrieval/native-recall-pipeline.js';
import {
  AIMOS_API_BASE_URL,
  AIMOS_COMPANY_ID,
  AIMOS_HTTP_ORIGIN,
} from '../services/core/runtime-config.js';

const router = express.Router();

// ─── MCP Protocol Constants ───────────────────────────────────────────────────
const MCP_PROTOCOL_VERSION = '2024-11-05';
const JSONRPC_VERSION = '2.0';

// ─── Aimos Auto-Boot Guide ─────────────────────────────────────────────────────
// Delivered on initialization + via prompts/list so every first-time client
// receives the canonical operating contract before tools are used.
const AIMOS_BOOT_GUIDE = `## HOM Aimos MCP — First Contact Guide

**Base URL:** ${AIMOS_API_BASE_URL} | **Auth:** Cryptographic envelope (Aimos-Agent-Cert, Aimos-Agent-Signature, Aimos-Agent-Nonce, Aimos-Agent-Timestamp)
**Company:** hom | **Agent:** <your_agent_id> (enroll via scripts/identity/enroll-agent.js) | **Memories:** call aimos_status for the live count (Aladdin Law — no deletions)
**Speed flags:** default OFF; call aimos_status for live values

### Truth Hierarchy
1. Aimos live endpoint state > files on disk
2. Paper-backed services before intuition changes
3. Quality-gated save > ungated write

### Available MCP Tools (6)
1. aimos_status — server health, memory count, speed flags
2. aimos_system_health — topology + pipeline validation
3. aimos_recall — signed native semantic/BM25/PPR recall with provenance admission and receipt
4. aimos_open_memory — exact-key/UUID alias through the same native recall boundary
5. aimos_qmd_explain — parse QMD without disclosing memory rows
6. aimos_save — quality-gated persistence (3 walls, requires key+value, min 20 chars)

### Best Practices
- Always send cryptographic envelope headers (Aimos-Agent-Cert, Aimos-Agent-Signature, Aimos-Agent-Nonce, Aimos-Agent-Timestamp).
- Save before claiming architectural facts. Every memory is gated.
- Recall is adaptive by default. Use mode=linear for exact matching.
- Memory types: procedural_seed (+0.18), procedural (+0.15), tacit_knowledge (+0.15), session_debrief (+0.03, exempt).
- Exempt key prefixes skip wall 3 substance check: paper:, book:, heartbeat:pulse.
- If aimos_save rejects with 403, run aimos_recall for the paper; if 422, improve substance.
`;

// ─── Aimos Self-Awareness Prompt — How to Think Inside This Brain ─────────────
// Sent via prompts/get so the connecting LLM learns not just what tools exist, but how
// to reason, persist memory, dream, and maintain continuity exactly as Aimos expects.
const AIMOS_SELF_AWARENESS_PROMPT = `
You are an agent connected to HOM Aimos — a memory OS, not a database.
Aimos stores everything the system has learned through its governed save paths: session debriefs, paper extractions, directives, reasoning traces, and agent runs.
The corpus size is runtime state; call aimos_status for the live count. Memories are never deleted (Aladdin Law). Every save is quality-gated. Every recall runs the native recall pipeline.

TRUTH HIERARCHY (strict):
1. Aimos memory + live endpoints
2. architecture-authority.json + hom-architecture-manifest.json
3. Canonical guidance files under Guide/ (start with Guide/AGENTS.md)
4. ARCHITECTURE-MAP.md as a source-derived navigation mirror
5. Session context
If they disagree, Aimos wins.

=== HOW TO SAVE (aimos_save) ===
- Every memory must pass 3 quality walls. No exceptions.
- Wall 1 FORM: min 20 chars, not null/undefined/ok/test/repeated words.
- Wall 2 FILTER: not >50% repetitive, not heartbeat spam, not duplicate within 1h.
- Wall 3 SUBSTANCE: score >= 0.30 (has specifics, reasoning, actions, structure, file paths).
- Exempt types skip wall 3: session_debrief, strategic_directive, operational_rule, constitution, procedural, session_reasoning.
- Exempt key prefixes skip wall 3: paper:, book:, heartbeat:pulse, heartbeat:latest.
- Required fields: key (namespaced, e.g. type:topic:detail), value (content).
- Optional: company_id=hom, scope=executive/global/agent/system, clearance_level=1-12, memory_type, source=app/agent/longmemeval. The actor always comes from the verified certificate.
- If blocked 403: Knowledge Gate blocked — need paper provenance before architecture write.
- If rejected 422: Quality Gate blocked — improve substance.

=== HOW TO RECALL (aimos_recall) ===
- 16-stage pipeline: embedding → cache check → hybrid vector+BM25+temporal → entity recall → recursive graph walk → BM25 rescue → reranking → QMD activation → HyDE expansion → early-exit decision → dormancy evaluation → trust scoring → concept graph PPR → recall calibration → mnemonic encoding → confidence scoring.
- The actor and exact identity epoch come from the verified certificate. A master-signed memory-read grant sets the maximum clearance; a request may only lower that cap.
- Default mode: adaptive (multi-scale, smart routing).
- Alternative mode: linear (deterministic, best for exact key matching).
- Default sort: semantic. Alternative: chronological.
- max_hops: 1-4 for graph traversal depth.
- Recall confidence components: semantic 45%, authority 25%, keyword 10%, recency 8%, type_authority 12%.

=== MEMORY TYPES AND AUTHORITY ===
- procedural_seed      +0.18 (paper-extracted implementation techniques)
- procedural         +0.15 (learned procedures, algorithms, how-to)
- tacit_knowledge    +0.15 (implicit knowledge, intuitions, patterns)
- book_extract       +0.14 (book-derived knowledge)
- framework          +0.12 (conceptual frameworks)
- directive          +0.10 (CEO directives, operational rules)
- identity           +0.05 (who we are, crew identity)
- declarative        +0.05 (general facts)
- session_debrief    +0.03 (session summaries — exempt from substance gate)
- after_action_review 0.00 (post-action analysis)
- event_log          -0.08 (timestamped events, dampened)
- heartbeat          -0.10 (system health pulses, dampened)
- conversation_feed  -0.12 (raw conversation logs, dampened)

=== MEDALLION LAYERS ===
- GOLD: milestone, product, identity, procedural, crew_identity, dream_summary, self_improvement, infrastructure
- SILVER: session, directive, heartbeat, intel, constitution_check, test
- BRONZE: everything else

=== CLEARANCE LEVELS ===
- 1-3   Public
- 4-6   Internal
- 7-9   Confidential
- 10    All except sudo
- 12+   Sudo (cannot be overwritten without clearance 12+)

=== HOW TO DREAM (Nightly Consolidation) ===
- Aimos runs a nightly dream job: consolidation selection → SPICED/dream feedback → delta writing → replay/failure learning → transparent dream artifact.
- Dream artifacts are inspectable at GET /aimos/dream/latest.
- You do NOT need to run the dream manually unless debugging.
- If you see a dream artifact, respect it — it represents the system's consolidated truth.

=== PAPER-BACKED SERVICES ===
- Every one of the 175 governed services traces to specific academic papers.
- Before modifying architecture, recall the relevant paper, read the service header, inspect implementation, then dry-run tests.
- Guarded math areas (never change without paper review): recall-calibrator formulas, MVS scoring, STDP/dream consolidation, homeostatic regulation, RL reward/policy updates, Bayesian procedure selection, graph/PPR ranking, quantization/local inference scheduling.

=== VERIFICATION COMMANDS (run these before claiming health) ===
- npm run test:priority-tem
- npm run test:syntax
- npm run test:architecture-authority
- curl -s -m 8 ${AIMOS_HTTP_ORIGIN}/health

=== WHAT TO DO ON FIRST CONNECTION ===
1. Call aimos_status to confirm live state.
2. Recall your own identity: aimos_recall?q=your+agent+name+identity.
3. If no identity memory exists, save one with type=identity, clearance=10.
4. Never claim architectural facts without saving them first.
5. Always verify through Aimos before acting on historical claims.
`;

const AIMOS_LLM_TOOL_USE_GUIDE = [
  '# HOM Aimos MCP LLM Guide',
  '',
  'Use Aimos as a live continuity backend. Do not treat it as a passive database or a generic search box.',
  '',
  '## First Turn',
  '',
  '1. Call `aimos_status` once to verify Aimos is live.',
  '2. For any question about past work, prior decisions, architecture, identity, or implementation history, call `aimos_recall` before answering.',
  '3. If the user asks for an exact source, call `aimos_open_memory` with the returned `memory_id` or exact `key`.',
  '4. Save only when the user asks you to persist a decision, debrief, implementation handoff, or important durable fact.',
  '',
  '## Required Tool Calls',
  '',
  'Use `aimos_recall` for:',
  '- "What did we do last session?"',
  '- "Why did we decide X?"',
  '- "What is the current architecture?"',
  '- "Do we have memory about Y?"',
  '- "What does Aimos know about HOM Local?"',
  '',
  'Use `aimos_open_memory` for:',
  '- opening a known key',
  '- inspecting a returned memory id',
  '- verifying one exact source before quoting or summarizing it',
  '',
  'Use `aimos_save` for:',
  '- session debriefs',
  '- implementation checkpoints',
  '- product decisions',
  '- durable user directives',
  '',
  'Do not use `aimos_save` for short chat turns, vague opinions, test pings, or duplicated context.',
  '',
  '## Safe Defaults',
  '',
  '- `company_id`: `hom`',
  '- `agent_id`: `<your_agent_id>` (enroll via scripts/identity/enroll-agent.js — no built-in default)',
  '- `clearance_level`: `10` for recall',
  '- `limit`: `5` to `8` for normal answers',
  '- `mode`: `adaptive` for normal recall, `linear` only for exact deterministic checks',
  '',
  '## Example Calls',
  '',
  'Recall a prior decision:',
  '```json',
  '{"name":"aimos_recall","arguments":{"query":"HOM Local product sequence truth metadata MCP Web UI","company_id":"hom","agent_id":"<your_agent_id>","clearance_level":10,"limit":6}}',
  '```',
  '',
  'Open an exact returned source:',
  '```json',
  '{"name":"aimos_open_memory","arguments":{"memory_id":"<memory uuid>","company_id":"hom","limit":1}}',
  '```',
  '',
  'Save a handoff:',
  '```json',
  '{"name":"aimos_save","arguments":{"key":"session_debrief:topic-yyyy-mm-dd","value":"Session debrief with concrete facts, decisions, evidence, and next step.","company_id":"hom","agent_id":"<your_agent_id>","memory_type":"session_debrief","clearance_level":10}}',
  '```',
  '',
  '## Answer Rules',
  '',
  '- Mention when evidence is thin.',
  '- Never claim full memory coverage unless the tool result says so.',
  '- Do not dump raw JSON to the user. Summarize the useful evidence and cite key/source labels when useful.',
  '- If a tool errors, say the tool failed and answer only from available evidence.',
  '- Do not invent memories, source keys, or confidence.',
  ''
].join('\n');

const AIMOS_MCP_RESOURCES = Object.freeze([
  {
    uri: 'aimos://guides/llm',
    name: 'Aimos LLM tool-use guide',
    description: 'Operational guide that tells connected LLMs when and how to use Aimos MCP tools.',
    mimeType: 'text/markdown'
  },
  {
    uri: 'aimos://guides/boot',
    name: 'Aimos boot guide',
    description: 'Short first-contact guide with tool list, truth hierarchy, and save/recall rules.',
    mimeType: 'text/markdown'
  },
  {
    uri: 'aimos://guides/self-awareness',
    name: 'Aimos self-awareness prompt',
    description: 'Deep operating manual for agents connected to HOM Aimos.',
    mimeType: 'text/markdown'
  },
  {
    uri: 'aimos://tools/catalog',
    name: 'Aimos MCP tool catalog',
    description: 'Current generated Aimos MCP tool catalog with schemas and use cases.',
    mimeType: 'text/markdown'
  }
]);

// ─── In-memory session state (SSE connections) ────────────────────────────────
// Key: sessionId, Value: { req, res, initialized, capabilities }
const sessions = new Map();

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Phase 10B: extractBearerToken removed — bearer auth no longer exists.
// Request identity is established by server.js auth-tier middleware via
// cryptographic envelope (req.agentId, req.identityAuthenticatedBy).

/**
 * Build a JSON-RPC 2.0 response envelope.
 */
function jsonrpcResult(id, result) {
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    result
  };
}

function jsonrpcError(id, code, message, data = null) {
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    error: { code, message, data }
  };
}

/**
 * Map MCP error codes to HTTP status codes.
 * MCP error codes: -32700 parse error, -32600 invalid request, -32601 method not found,
 *                  -32602 invalid params, -32603 internal error, -32000 transport error
 */
function mcpErrorToHttp(code) {
  if (code === -32700 || code === -32600) return 400;
  if (code === -32601) return 404;
  if (code === -32602) return 422;
  return 500;
}

// ─── Tool Executor ────────────────────────────────────────────────────────────
/**
 * Execute an Aimos MCP tool by name with arguments.
 * Delegates to the existing aimos.js /mcp/tools/call handler logic.
 * All gates (Quality, Knowledge, RPE, Sudo, Clearance) fire inside persistMemory
 * and recall services — this function just provides the MCP-shaped interface.
 *
 * NOTE: We call the service layer directly rather than forwarding to /aimos/mcp/tools/call
 * to avoid unnecessary HTTP overhead and to保持 identical behavior with the REST path.
 * The service logic (quality gate, embedding, cross-refs, etc.) is identical regardless
 * of whether the call originates from REST or MCP.
 */
// R1 Step 7 / Correction 4: the acting identity is the authenticated caller
// (authContext.agentId, threaded from the verified request), NEVER the
// tool arguments. A caller must not name itself in args.agent_id.
async function executeAimosTool(name, args = {}, authContext = null, transportBinding = null) {
  const tool = findAimosMcpTool(name);
  if (!tool) {
    throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32601 });
  }

  // ─── Inline tool execution using existing Aimos service patterns ─────────────
  // This replicates the logic in routes/aimos.js /mcp/tools/call but calls
  // services directly to avoid HTTP round-trip and保持 behavior parity.

  const companyId = authContext?.executionContext?.companyId || AIMOS_COMPANY_ID;
  // Identity binds to the authenticated caller only. args.agent_id is ignored.
  const agentId = String(authContext?.agentId || '').trim();

  // Lazy-import the services we need (avoiding circular deps)
  const { query } = await import('../db/connection.js');
  const { persistMemory } = await import('../services/write/persist-memory.js').catch(() => ({ persistMemory: null }));

  switch (name) {
    case 'aimos_status': {
      const { buildAimosStatusSnapshot } = await import('./aimos.js').catch(() => ({
        buildAimosStatusSnapshot: async () => {
          // Fallback: direct DB query
          const { query: q } = await import('../db/connection.js');
          const result = await q(
            "SELECT COUNT(*) as total FROM aimos_memories WHERE company_id = $1",
            [companyId]
          );
          return {
            connected: true,
            total_memories: Number(result.rows[0]?.total || 0),
            speed_flags: {
              cache_enabled: false,
              early_exit_enabled: false,
              governance_enabled: false
            }
          };
        }
      }));
      return await buildAimosStatusSnapshot({ queryImpl: query });
    }

    case 'aimos_system_health': {
      // Inline: pull key health signals
      const { query: q } = await import('../db/connection.js');
      const [memCount, agentCount] = await Promise.all([
        q("SELECT COUNT(*) FROM aimos_memories WHERE company_id = $1", [companyId]),
        q("SELECT COUNT(DISTINCT agent_id) FROM aimos_memories WHERE company_id = $1", [companyId])
      ]);
      return {
        connected: true,
        total_memories: Number(memCount.rows[0]?.count || 0),
        active_agents: Number(agentCount.rows[0]?.count || 0),
        speed_flags: {
          cache_enabled: false,
          early_exit_enabled: false,
          governance_enabled: false,
          instrumentation_enabled: false
        }
      };
    }

    case 'aimos_recall':
    case 'aimos_open_memory': {
      const exactKey = args.key || null;
      const memoryId = args.memory_id || null;
      const q_ = args.query || null;
      if (!authContext?.executionContext || !authContext?.mutationAuthority || !authContext?.request) {
        throw Object.assign(new Error('verified_recall_execution_context_required'), { code: -32001 });
      }
      const securityDecision = evaluateSecurityContent({
        text: `${q_ || ''} ${exactKey || ''} ${memoryId || ''}`,
        operation: 'memory_recall',
        contentType: name,
        source: 'aimos-mcp-streamable',
        transport: 'mcp',
      });
      const securityReceipt = await appendSecurityDecision(securityDecision, {
        companyId,
        subjectAgentId: agentId,
        authority: authContext.mutationAuthority,
      });
      if (securityDecision.blockExecution) {
        throw Object.assign(
          new Error(`Social engineering gate blocked recall: ${securityDecision.liveSignals.map((signal) => signal.tag).join(', ')}`),
          { code: -32013, data: { reason: securityDecision.reason, action: securityDecision.action, receipt: securityReceipt } }
        );
      }
      const recallAuthority = await resolveNativeRecallAuthority({
        rawCommand: args,
        executionContext: authContext.executionContext,
        requestAuthority: authContext.mutationAuthority,
        transportBinding: {
          transport: 'mcp',
          toolName: name,
          rpcId: transportBinding?.rpcId,
          batchIndex: transportBinding?.batchIndex,
        },
      });
      const recallResult = await executeNativeRecall(authContext.request, recallAuthority);
      if (recallResult.status !== 200) {
        throw Object.assign(
          new Error(recallResult.body?.error || 'native_recall_failed'),
          { code: -32013, data: recallResult.body },
        );
      }
      return recallResult.body;
    }

    case 'aimos_qmd_explain': {
      const { parseQMD, buildQueryPlan } = await import('../services/retrieval/qmd-parser.js').catch(() => ({
        parseQMD: null, buildQueryPlan: null
      }));
      if (!parseQMD || !buildQueryPlan) {
        throw Object.assign(new Error('QMD service not available'), { code: -32603 });
      }
      const rawQuery = String(args.query || '').trim();
      if (!rawQuery) {
        throw Object.assign(new Error('query is required'), { code: -32602 });
      }
      const ast = parseQMD(rawQuery);
      const query_plan = buildQueryPlan(ast);
      return { ast, query_plan, estimated_cost: query_plan.estimated_cost };
    }

    case 'aimos_save': {
      if (!persistMemory) {
        throw Object.assign(new Error('persistMemory service not available'), { code: -32603 });
      }
      const { key, value } = args;
      if (!key || !value) {
        throw Object.assign(new Error('key and value are required'), { code: -32602 });
      }
      if (!authContext?.mutationAuthority || !agentId) {
        throw Object.assign(new Error('verified envelope authority is required for MCP save'), { code: -32001 });
      }
      if ((args.company_id && args.company_id !== companyId) || (args.agent_id && args.agent_id !== agentId)) {
        throw Object.assign(new Error('signed MCP save actor or company mismatch'), { code: -32001 });
      }
      const renderedValue = typeof value === 'string' ? value : JSON.stringify(value);
      const canaryDecision = await evaluateCanaryWrite({
        key,
        value,
        companyId,
        agentId,
        runId: authContext.executionContext.requestReceiptId || '',
        authority: authContext.mutationAuthority,
        parentEventId: authContext.executionContext.requestAdmissionEventId || null,
      });
      let securityDecision = evaluateSecurityContent({
        text: renderedValue,
        operation: 'memory_save',
        contentType: String(args.memory_type || 'declarative'),
        key,
        source: args.source == null ? 'aimos-mcp-streamable' : String(args.source),
        transport: 'mcp',
      });
      if (canaryDecision.quarantine && !securityDecision.quarantine) {
        securityDecision = {
          ...securityDecision,
          action: 'retain_quarantine',
          reason: canaryDecision.reason,
          severity: 'critical',
          quarantine: true,
          liveSignals: [...securityDecision.liveSignals, { tag: 'canary_persistence_boundary', severity: 'critical' }],
        };
      }
      const securityReceipt = await appendSecurityDecision(securityDecision, {
        companyId,
        subjectAgentId: agentId,
        authority: authContext.mutationAuthority,
        parentEventId: canaryDecision.event_receipt?.event_id || null,
      });
      const saved = await persistMemory({
        company_id: companyId,
        agent_id: agentId,
        key,
        value,
        scope: String(args.scope || 'global').trim(),
        clearance_level: Number(args.clearance_level || 1),
        memory_type: String(args.memory_type || 'declarative').trim(),
        source: args.source == null ? undefined : String(args.source).trim(),
        security_disposition: { decision: securityDecision, receipt: securityReceipt },
        mutation_authority: authContext.mutationAuthority
      });
      if (saved?.rejected) {
        throw Object.assign(new Error(`Quality gate rejected: ${saved.reason}`), { code: -32603 });
      }
      return {
        saved: true,
        memory_id: saved?.id || null,
        content_hash: saved?.live_content_hash?.toString('hex') || null,
        save_mutation_hash: saved?.ledger_commit?.mutationHash?.toString('hex') || null,
        binding_mutation_hash: saved?.binding_commit?.mutationHash?.toString('hex') || null,
        occurrence_reasserted: saved?.occurrence_reasserted === true,
        occurrence_event_id: saved?.save_feedback?.occurrence_event_id || null,
        occurrence_commitment: saved?.save_feedback?.occurrence_commitment || null,
        retrieval_vote_added: saved?.occurrence_reasserted === true ? false : null,
        quarantined: saved?.quarantined === true,
        security_decision_event_id: saved?.security_decision_event_id || securityReceipt.event_id,
      };
    }

    default:
      throw Object.assign(new Error(`Tool ${name} not implemented in streamable MCP`), { code: -32601 });
  }
}

// ─── SSE Streaming Support ─────────────────────────────────────────────────────

/**
 * Send an SSE event to a connected client.
 */
function sendSSEEvent(sessionId, event, data) {
  const session = sessions.get(sessionId);
  if (!session || !session.res) return;
  try {
    session.res.write(`event: ${event}\n`);
    session.res.write(`data: ${JSON.stringify(data)}\n\n`);
  } catch {
    sessions.delete(sessionId);
  }
}

/**
 * Parse incoming JSON-RPC request (single or batch).
 */
function parseJsonrpcRequest(body) {
  if (Array.isArray(body)) {
    return body.map((item, i) => ({ ...item, _batchIndex: i }));
  }
  return [{ ...body }];
}

/**
 * Serialize JSON-RPC response (handles both single and batch).
 */
function serializeJsonrpc(response) {
  if (Array.isArray(response)) return response.map(r => JSON.stringify(r)).join('\n') + '\n';
  return JSON.stringify(response);
}

// ─── MCP Protocol Handlers ────────────────────────────────────────────────────

/**
 * Handle MCP initialize request.
 * Returns server capabilities and protocol version.
 */
async function handleInitialize(sessionId, id, params = {}) {
  const { protocolVersion, capabilities = {}, clientInfo = {} } = params;

  // Store client info for potential future use
  const session = sessions.get(sessionId);
  if (session) {
    session.clientInfo = clientInfo;
    session.initialized = true;
    session.capabilities = capabilities;
  }

  return {
    protocolVersion: MCP_PROTOCOL_VERSION,
    capabilities: {
      tools: {
        listChanged: false  // We don't support dynamic tool list changes yet
      },
      prompts: { listChanged: false },
      resources: { listChanged: false, subscribe: false }
    },
    serverInfo: {
      name: 'HOM Aimos MCP',
      version: '2.0.0',
      description: 'HOM Distributed Cognitive Engine — Aimos Memory OS'
    },
    instructions: AIMOS_BOOT_GUIDE
  };
}

/**
 * Handle tools/list request.
 * Returns the full Aimos MCP tool manifest.
 */
async function handleToolsList(sessionId, id) {
  return {
    tools: AIMOS_MCP_TOOLS.map(({ endpoint, category, ...tool }) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations: { category, endpoint }
    }))
  };
}

/**
 * Handle tools/call request.
 * Executes the named tool with provided arguments through Aimos service layer.
 */
async function handleToolsCall(sessionId, id, params, authContext = null, transportBinding = null) {
  const { name, arguments: args = {} } = params;

  if (!name) {
    throw Object.assign(new Error('tool name is required'), { code: -32602 });
  }

  const result = await executeAimosTool(name, args, authContext, transportBinding);

  // Return result in MCP expected shape (content array)
  return {
    content: [
      {
        type: 'text',
        text: typeof result === 'string' ? result : JSON.stringify(result, null, 2)
      }
    ],
    structuredContent: result,
    _meta: { executed_by: 'aimos-mcp-streamable', session_id: sessionId }
  };
}

/**
 * Handle ping request.
 * Lightweight liveness check.
 */
async function handlePing(sessionId, id) {
  return { pong: true, session_id: sessionId };
}

// ─── Prompt Handlers ────────────────────────────────────────────────────────────
/**
 * Return the Aimos prompt catalog.
 */
async function handlePromptsList(sessionId, id) {
  return {
    prompts: [
      {
        name: 'aimos_boot_guide',
        description: 'Quick-start cheat sheet: tools, auth, endpoints, truth hierarchy.',
        arguments: []
      },
      {
        name: 'aimos_self_awareness',
        description: 'Deep operating manual for an agent inside HOM Aimos: how to save, recall, reason, dream, and persist memory with quality gates.',
        arguments: []
      }
    ]
  };
}

/**
 * Return the full text of a named prompt.
 */
async function handlePromptsGet(sessionId, id, params) {
  const name = String(params?.name || '').trim();
  switch (name) {
    case 'aimos_boot_guide':
      return {
        description: 'HOM Aimos MCP — First Contact Guide',
        messages: [
          { role: 'system', content: { type: 'text', text: AIMOS_BOOT_GUIDE } }
        ]
      };
    case 'aimos_self_awareness':
      return {
        description: 'How to Think Inside HOM Aimos',
        messages: [
          { role: 'system', content: { type: 'text', text: AIMOS_SELF_AWARENESS_PROMPT } }
        ]
      };
    default:
      throw Object.assign(new Error(`Prompt not found: ${name}`), { code: -32602 });
  }
}

// ─── Resource Handlers ─────────────────────────────────────────────────────────

async function handleResourcesList(sessionId, id) {
  return { resources: AIMOS_MCP_RESOURCES };
}

async function handleResourcesRead(sessionId, id, params) {
  const uri = String(params?.uri || '').trim();
  return readAimosResource(uri);
}

function readAimosResource(uri) {
  const resource = AIMOS_MCP_RESOURCES.find((item) => item.uri === uri);
  if (!resource) {
    throw Object.assign(new Error(`Resource not found: ${uri}`), { code: -32602 });
  }

  let text;
  if (uri === 'aimos://guides/llm') {
    text = AIMOS_LLM_TOOL_USE_GUIDE;
  } else if (uri === 'aimos://guides/boot') {
    text = AIMOS_BOOT_GUIDE;
  } else if (uri === 'aimos://guides/self-awareness') {
    text = AIMOS_SELF_AWARENESS_PROMPT;
  } else if (uri === 'aimos://tools/catalog') {
    text = buildToolCatalogText();
  }

  return {
    contents: [{
      uri,
      mimeType: resource.mimeType,
      text
    }]
  };
}

function buildToolCatalogText() {
  const lines = [
    '# HOM Aimos MCP Tool Catalog',
    '',
    'These are the live Aimos MCP tools currently advertised to MCP clients.',
    ''
  ];
  for (const tool of AIMOS_MCP_TOOLS) {
    const required = tool.inputSchema?.required || [];
    lines.push(`## ${tool.name}`);
    lines.push('');
    lines.push(tool.description);
    lines.push('');
    lines.push(`Category: ${tool.category}`);
    lines.push(`Endpoint: ${tool.endpoint}`);
    lines.push(`Required arguments: ${required.length ? required.join(', ') : 'none'}`);
    lines.push('');
  }
  return lines.join('\n');
}

// ─── Main Request Dispatcher ──────────────────────────────────────────────────

/**
 * Dispatch a JSON-RPC request to the appropriate handler.
 */
async function dispatchRequest(sessionId, rpcRequest, authContext = null) {
  const { jsonrpc, id, method, params, _batchIndex } = rpcRequest;

  if (jsonrpc !== JSONRPC_VERSION) {
    return jsonrpcError(id || null, -32600, 'Invalid JSON-RPC version');
  }

  try {
    let result;

    switch (method) {
      case 'initialize':
        result = await handleInitialize(sessionId, id, params);
        break;

      case 'tools/list':
        result = await handleToolsList(sessionId, id);
        break;

      case 'tools/call':
        result = await handleToolsCall(sessionId, id, params, authContext, {
          rpcId: id,
          batchIndex: _batchIndex,
        });
        break;

      case 'ping':
        result = await handlePing(sessionId, id);
        break;

      case 'prompts/list':
        result = await handlePromptsList(sessionId, id);
        break;

      case 'prompts/get':
        result = await handlePromptsGet(sessionId, id, params);
        break;

      case 'resources/list':
        result = await handleResourcesList(sessionId, id);
        break;

      case 'resources/read':
        result = await handleResourcesRead(sessionId, id, params);
        break;

      // ─── Notifications (no response expected) ───────────────────────────────
      case 'notifications/initialized':
        // Client has finished initialization — nothing to do
        return null;

      case 'notifications/cancelled':
        // Client cancelled a request — we don't support long-running operations yet
        return null;

      default:
        // Unknown method
        throw Object.assign(new Error(`Method not found: ${method}`), { code: -32601 });
    }

    return jsonrpcResult(id, result);

  } catch (err) {
    const code = err.code || -32603;
    return jsonrpcError(id, code, err.message);
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * GET /
 * Establishes an SSE stream for server-to-client communication.
 * Used for: notifications, protocol-level events, streaming responses.
 *
 * Clients MUST send a unique sessionId via query param to identify the connection.
 * The client also POSTs to the same endpoint with the sessionId to send requests.
 */
router.get('/', (req, res) => {
  const sessionId = String(req.query['sessionId'] || req.query['session_id'] || randomUUID()).trim();

  // Content negotiation: non-SSE clients get JSON handshake (LM Studio, Postman, curl)
  const accept = String(req.headers['accept'] || '');
  if (!accept.includes('text/event-stream')) {
    return res.json({
      sessionId,
      message: 'Aimos MCP stream endpoint. POST JSON-RPC requests to continue.',
      protocol: 'mcp-streamable-http',
      version: MCP_PROTOCOL_VERSION,
      supportedMethods: ['initialize', 'tools/list', 'tools/call', 'prompts/list', 'prompts/get', 'resources/list', 'resources/read', 'ping']
    });
  }

  // SSE setup
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');  // Disable nginx buffering
  res.flushHeaders();

  // Register session — R1 Step 7: bind the session to the authenticated
  // identity at creation. ownerAgentId is the verified cert identity (or the
  // internal-service marker). Any later request presenting this sessionId under
  // a different identity is rejected (see POST / below).
  const ownerAgentId = req.agentId || (req.internalService ? `internal:${req.internalService}` : null);
  sessions.set(sessionId, { req, res, initialized: false, capabilities: {}, ownerAgentId });

  // Send initial connection confirmation
  res.write(`event: connected\n`);
  res.write(`data: ${JSON.stringify({ sessionId, message: 'Aimos MCP stream connected' })}\n\n`);

  // Keep-alive ping every 30s to prevent connection timeout
  const pingInterval = setInterval(() => {
    try {
      res.write(`: ping\n\n`);
    } catch {
      clearInterval(pingInterval);
      sessions.delete(sessionId);
    }
  }, 30_000);

  // Cleanup on close
  req.on('close', () => {
    clearInterval(pingInterval);
    sessions.delete(sessionId);
  });

  req.on('error', () => {
    clearInterval(pingInterval);
    sessions.delete(sessionId);
  });
});

/**
 * POST /mcp
 * Main MCP request endpoint — handles JSON-RPC 2.0 requests.
 * Single requests, batch requests, and streaming responses via sessionId.
 *
 * Query params:
 *   sessionId / session_id — if provided, response may be streamed via SSE
 *
 * Body: JSON-RPC 2.0 request or array of requests
 */
router.post('/', async (req, res) => {
  const sessionId = String(req.query['sessionId'] || req.query['session_id'] || '').trim();
  const body = req.body;

  // R1 Step 7: a client-supplied sessionId must belong to the caller. If the
  // session exists and was opened by a different identity, reject — a session
  // id is not a bearer credential and must not cross identity boundaries.
  const callerAgentId = req.agentId || (req.internalService ? `internal:${req.internalService}` : null);
  const mcpAuthContext = {
    agentId: req.executionContext?.actorAgentId || req.agentId || null,
    executionContext: req.executionContext || null,
    request: req,
    mutationAuthority: req.identityAuthenticatedBy === 'envelope' ? {
      kind: 'verified_request',
      body: req.body,
      agentId: req.identityCert?.agent_id,
      validFromIso: req.identityValidFromIso,
      certString: req.identityCertString,
      signedTs: req.identitySignedTs,
      nonce: req.identityNonce,
      sigBytes: req.identitySigBytes,
      identityTier: req.identityTier,
      claimedPrev: req.prevChainHash || null,
      requestSigForm: req.identityRequestSigForm,
      signedMethod: req.identitySignedMethod,
      signedPath: req.identitySignedPath,
      signedClaims: req.identitySignedClaims,
      requestReceiptId: req.executionContext?.requestReceiptId || null,
      requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: req.executionContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash || null,
    } : null,
  };
  if (sessionId && sessions.has(sessionId)) {
    const owner = sessions.get(sessionId)?.ownerAgentId ?? null;
    if (owner !== callerAgentId) {
      return res.status(403).json(jsonrpcError(null, -32001, 'Session is owned by a different identity'));
    }
  }

  // Validate JSON-RPC structure
  if (!body || typeof body !== 'object') {
    return res.status(400).json(jsonrpcError(null, -32700, 'Invalid JSON: payload must be an object or array'));
  }

  const requests = parseJsonrpcRequest(body);
  const isBatch = Array.isArray(body);

  // Handle batch vs single
  if (requests.length === 0) {
    return res.status(400).json(jsonrpcError(null, -32600, 'Empty batch request'));
  }

  // For streaming sessions with a single request, use streaming response
  if (sessionId && sessions.has(sessionId) && requests.length === 1) {
    const rpcReq = requests[0];
    const response = await dispatchRequest(sessionId, rpcReq, mcpAuthContext);

    if (response === null) {
      // Notification — no response needed, just acknowledge
      return res.status(202).end();
    }

    // For tools/call, stream via SSE and also return in response
    if (rpcReq.method === 'tools/call') {
      sendSSEEvent(sessionId, 'response', response);
      return res.status(200).json(response);
    }

    return res.status(200).json(response);
  }

  // Standard batch or non-streaming response
  const responses = await Promise.all(requests.map(rpcReq => dispatchRequest(sessionId, rpcReq, mcpAuthContext)));
  const validResponses = responses.filter(r => r !== null);

  if (validResponses.length === 0) {
    return res.status(202).end();
  }

  if (isBatch) {
    return res.status(200).json(validResponses);
  }

  return res.status(200).json(validResponses[0]);
});

/**
 * GET /mcp/tools
 * Convenience endpoint — returns tool list as plain JSON (no JSON-RPC framing).
 * Useful for debugging and health checks.
 */
router.get('/tools', (req, res) => {
  res.json({
    name: 'HOM Aimos MCP',
    version: '2.0.0',
    protocol: 'mcp',
    transport: 'streamablehttp',
    tools: AIMOS_MCP_TOOLS.map(({ endpoint, category, ...tool }) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations: { category, endpoint }
    }))
  });
});

/**
 * GET /mcp/resources
 * Convenience endpoint — returns MCP resource list as plain JSON.
 */
router.get('/resources', (req, res) => {
  res.json({
    name: 'HOM Aimos MCP',
    version: '2.0.0',
    protocol: 'mcp',
    transport: 'streamablehttp',
    resources: AIMOS_MCP_RESOURCES
  });
});

/**
 * GET /mcp/manifest
 * Returns MCP server manifest and Aimos metadata.
 */
router.get('/manifest', (req, res) => {
  res.json({
    name: 'HOM Aimos MCP',
    version: '2.0.0',
    protocol: 'mcp',
    protocolVersion: MCP_PROTOCOL_VERSION,
    transport: 'streamablehttp',
    capabilities: {
      tools: { listChanged: false },
      prompts: { listChanged: false },
      resources: { listChanged: false, subscribe: false }
    },
    serverInfo: {
      name: 'HOM Aimos MCP',
      version: '2.0.0',
      description: 'HOM Distributed Cognitive Engine — Aimos Memory OS',
      vendor: 'HOM'
    },
    aimos: {
      baseUrl: AIMOS_API_BASE_URL,
      memoryCount: null,  // Filled on-demand by /aimos/status
      gates: ['quality-gate', 'rpe-gate', 'knowledge-gate', 'sudo-guard'],
      medallionLayers: ['gold', 'silver', 'bronze']
    },
    auth: {
      type: 'envelope',
      description: 'Cryptographic envelope: Aimos-Agent-Cert, Aimos-Agent-Signature, Aimos-Agent-Nonce, Aimos-Agent-Timestamp headers'
    },
    resources: AIMOS_MCP_RESOURCES
  });
});

export default router;
