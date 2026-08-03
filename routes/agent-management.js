/**
 * agent-management.js — CRUD + lifecycle routes for agents.
 *
 * Mounts under the /agents prefix (via agents.js main router).
 * Routes: GET /, GET /statuses, GET /delegation-chain, GET /sessions,
 *   POST /score-recommendations, GET /system-patterns, GET /:id,
 *   GET /:id/status
 */

import express from 'express';
import { agents, listAgents } from '../services/orchestration/agent-store.js';
import {
  identifySystemPatterns,
  scoreDueRecommendations
} from '../services/learning/agent-learning.js';
import { query } from '../db/connection.js';
import {
  ensureGovernanceReady,
  hydrateAgentStoreFromGovernance
} from '../services/orchestration/governance-resolver.js';
import {
  getAllSessionStats
} from '../services/orchestration/session-runner.js';
import {
  COMPANY,
  TOOL_SUITES,
  getDefaultToolset
} from './agent-shared.js';

const router = express.Router();

// ─── Governance helpers ───────────────────────────────────────────────────────

let lastGovernanceSyncAt = 0;

// purgeNonOllamaFromModelPolicy removed — Ollama retired 2026-03-25

export async function syncGovernance(force = false) {
  const now = Date.now();
  if (!force && (now - lastGovernanceSyncAt) < 10_000) return;
  await ensureGovernanceReady(COMPANY, { force: false });
  await hydrateAgentStoreFromGovernance(COMPANY);
  lastGovernanceSyncAt = now;
}

// ─── Agent normalisation helpers ──────────────────────────────────────────────

function normalizeToolDeltasForResponse(value) {
  if (!value || typeof value !== 'object') return { allow: [], deny: [] };
  return {
    allow: Array.isArray(value.allow) ? value.allow.filter(Boolean) : [],
    deny: Array.isArray(value.deny) ? value.deny.filter(Boolean) : []
  };
}

function deriveToolDeltasFromLegacySuite(agent) {
  const currentTools = Array.isArray(agent?.tools) ? agent.tools : [];
  const suite = String(currentTools[0] || 'full').trim();
  const allowed = new Set(TOOL_SUITES[suite] || TOOL_SUITES.full);
  const deny = (TOOL_SUITES.full || []).filter((toolName) => !allowed.has(toolName));
  return { allow: [], deny };
}

function normalizeAgentForResponse(agent) {
  const normalizedDeltas = normalizeToolDeltasForResponse(agent?.toolDeltas);
  const hasExplicitDeltas = normalizedDeltas.allow.length > 0 || normalizedDeltas.deny.length > 0;
  const toolDeltas = hasExplicitDeltas ? normalizedDeltas : deriveToolDeltasFromLegacySuite(agent);
  return {
    ...agent,
    toolProfile: 'full',
    tools: ['full'],
    toolDeltas
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

router.get('/', async (req, res) => {
  await syncGovernance();
  const all = listAgents();
  const { tier } = req.query;
  const filtered = tier ? all.filter((a) => a.tier === tier) : all;
  const normalizedAgents = filtered.map(normalizeAgentForResponse);

  res.json({
    total: all.length,
    tiers: {
      heavy: all.filter((a) => a.tier === 'heavy').length,
      balanced: all.filter((a) => a.tier === 'balanced').length,
      light: all.filter((a) => a.tier === 'light').length
    },
    agents: normalizedAgents
  });
});

router.get('/statuses', async (req, res) => {
  await syncGovernance();
  const all = listAgents();
  const statuses = Object.fromEntries(
    all.map((agent) => [String(agent.id), agent.isActive ? 'active' : 'idle'])
  );

  try {
    const running = await query(
      `SELECT resolved_agent_id, status
       FROM agent_runs
       WHERE company_id = $1
         AND created_at >= NOW() - INTERVAL '30 minutes'
         AND status IN ('running', 'awaiting_approval')
       ORDER BY updated_at DESC`,
      [COMPANY]
    );
    for (const row of running.rows) {
      const agentId = String(row.resolved_agent_id || '').trim();
      if (!agentId) continue;
      statuses[agentId] = row.status === 'awaiting_approval' ? 'awaiting_approval' : 'running';
    }
  } catch {
    // Keep base status map if run metadata is temporarily unavailable.
  }

  res.json(statuses);
});

// ─── OUTCOME SCORER: grade expired recommendations ─────────────────────────
router.post('/score-recommendations', async (req, res, next) => {
  try {
    const result = await scoreDueRecommendations();
    res.json({ success: true, ...result });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── SENGE #4: Systems Thinking — cross-agent pattern detection ────────────
router.get('/system-patterns', async (req, res, next) => {
  try {
    const patterns = await identifySystemPatterns();
    res.json({ success: true, ...patterns });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── PER-AGENT IDENTITY: token management ────────────────────────────────
router.get('/delegation-chain', async (req, res) => {
  await syncGovernance();
  const agentId = String(req.query.agentId || '').trim();
  const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 200);
  if (!agentId) {
    return res.status(400).json({ success: false, error: 'agentId is required' });
  }

  try {
    const rows = await query(
      `SELECT
         source_agent_id,
         delegated_to,
         status,
         model_resolved,
         created_at
       FROM agent_runs
       WHERE company_id = $1
         AND delegated_to IS NOT NULL
         AND (source_agent_id = $2 OR delegated_to = $2)
       ORDER BY created_at DESC
       LIMIT $3`,
      [COMPANY, agentId, limit]
    );

    const chain = rows.rows.map((row) => ({
      from: String(row.source_agent_id || ''),
      to: String(row.delegated_to || ''),
      status: String(row.status || 'unknown'),
      model: String(row.model_resolved || ''),
      createdAt: row.created_at
    }));
    // Backward-compatible raw array consumed by GraphView.
    res.json(chain);
  } catch (error) {
    res.status(500).json([]);
  }
});

// ─── SESSION CONTEXT MANAGEMENT ───────────────────────────────────────────────

router.get('/sessions', (req, res) => {
  res.json({ sessions: getAllSessionStats() });
});

router.get('/:id/status', async (req, res) => {
  await syncGovernance();
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ success: false, error: 'Agent not found' });

  try {
    const runs = await query(
      `SELECT
         COUNT(*) FILTER (WHERE status = 'running')::int AS running,
         COUNT(*) FILTER (WHERE status = 'awaiting_approval')::int AS awaiting_approval
       FROM agent_runs
       WHERE company_id = $1
         AND (source_agent_id = $2 OR resolved_agent_id = $2)
         AND created_at >= NOW() - INTERVAL '30 minutes'`,
      [COMPANY, agent.id]
    );
    const running = Number(runs.rows[0]?.running || 0);
    const awaiting = Number(runs.rows[0]?.awaiting_approval || 0);
    const status = awaiting > 0
      ? 'awaiting_approval'
      : (running > 0 ? 'running' : (agent.isActive ? 'active' : 'idle'));

    return res.json({
      success: true,
      agentId: agent.id,
      status,
      isActive: !!agent.isActive,
      model: agent.model,
      lastSeen: agent.lastSeen || null,
      pendingRuns: running + awaiting
    });
  } catch (error) {
    return res.json({
      success: true,
      agentId: agent.id,
      status: agent.isActive ? 'active' : 'idle',
      isActive: !!agent.isActive,
      model: agent.model,
      lastSeen: agent.lastSeen || null,
      pendingRuns: 0
    });
  }
});

router.get('/:id', async (req, res) => {
  await syncGovernance();
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  return res.json(agent);
});

export default router;
