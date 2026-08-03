// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (post-run step 33)
// → Calls: event-ledger.js (signed trace append), db/connection.js (trace reads)
// Pipeline: AGENT_RUN_PIPELINE
// Position: trace logging
// Source: Distributed Tracing (OpenTelemetry), Agent introspection
// Wave 3 source: Thinking into the Future — Latent Lookahead Training for
// Transformers. Aimos uses the paper as an orchestration/prefetch contract
// only: no hidden-state recursion, no latent attention-mask training, and no
// multi-token prediction claim are implemented here.
// ─────────────────────────────────────────────────────────────────────────────

import { query } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { logEvent } from './event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const LATENT_LOOKAHEAD_SOURCE = 'Thinking into the Future: Latent Lookahead Training for Transformers';
const LOOKAHEAD_POSITIONS = Object.freeze({
  BEGINNING: 'beginning_of_response',
  AFTER_EVIDENCE: 'after_first_evidence_or_tool_result',
  BEFORE_COMMIT: 'before_commitment_decision',
});

function clampNumber(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n));
}

function normalizeTaskText(value = '') {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function estimateLookaheadDifficulty({ prompt = '', taskType = 'chat', turnBudgetPlan = null, psychometricProfile = null } = {}) {
  const text = normalizeTaskText(prompt).toLowerCase();
  const turnLevel = Number(turnBudgetPlan?.turn_difficulty?.difficulty_level);
  if (Number.isFinite(turnLevel) && turnLevel > 0) {
    return clampNumber(Math.round(turnLevel), 1, 4);
  }

  const psychDifficulty = Number(psychometricProfile?.psychometric_model?.task_difficulty?.difficulty_proxy_0_1);
  if (Number.isFinite(psychDifficulty)) {
    return clampNumber(Math.ceil(psychDifficulty * 4), 1, 4);
  }

  let score = 1;
  if (/\b(implement|wire|architecture|debug|prove|audit|investigate|reasoning|why|root cause)\b/.test(text)) score += 1;
  if (/\b(test|dry run|verify|evidence|paper|formula|math|calibrate)\b/.test(text)) score += 1;
  if (['research', 'analysis', 'architecture', 'investigation'].includes(String(taskType || '').toLowerCase())) score += 1;
  return clampNumber(score, 1, 4);
}

function selectLookaheadPositions(difficultyLevel, maxThoughts = 2) {
  const limit = clampNumber(maxThoughts, 1, 3);
  const positions = [LOOKAHEAD_POSITIONS.BEGINNING];
  if (positions.length < limit && difficultyLevel >= 2) {
    positions.push(LOOKAHEAD_POSITIONS.AFTER_EVIDENCE);
  }
  if (positions.length < limit && difficultyLevel >= 4) {
    positions.push(LOOKAHEAD_POSITIONS.BEFORE_COMMIT);
  }
  return positions;
}

function summarizePromptTopic(prompt = '') {
  const text = normalizeTaskText(prompt);
  if (!text) return 'current task';
  const withoutFiller = text
    .replace(/\b(please|continue|start|with|the|this|that|and|or|we|can|you|now|lets|let's)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return (withoutFiller || text).slice(0, 120);
}

function buildPrefetchQueries({ prompt = '', taskType = 'chat', difficultyLevel = 1 } = {}) {
  const topic = summarizePromptTopic(prompt);
  const queries = new Set();
  queries.add(topic);

  const lower = normalizeTaskText(prompt).toLowerCase();
  if (/\b(why|reasoning|decision|because)\b/.test(lower)) {
    queries.add(`reasoning trace for ${topic}`);
  }
  if (/\b(implement|wire|fix|debug|architecture)\b/.test(lower) || difficultyLevel >= 2) {
    queries.add(`implementation evidence for ${topic}`);
    queries.add(`test and dry run status for ${topic}`);
  }
  if (/\b(paper|formula|math|calibrate|tau|graph|temporal|retrieval)\b/.test(lower) || difficultyLevel >= 3) {
    queries.add(`paper authority and guarded math for ${topic}`);
  }
  if (String(taskType || '').toLowerCase().includes('research') || difficultyLevel >= 4) {
    queries.add(`related Aimos memories and follow-up risks for ${topic}`);
  }

  return [...queries].filter(Boolean).slice(0, 5);
}

function buildLatentLookaheadPlan({
  prompt = '',
  taskType = 'chat',
  turnBudgetPlan = null,
  psychometricProfile = null,
  conversationHistory = [],
  maxThoughts = 2,
} = {}) {
  const difficultyLevel = estimateLookaheadDifficulty({ prompt, taskType, turnBudgetPlan, psychometricProfile });
  const latentHorizonTau = clampNumber(difficultyLevel, 1, 4);
  const thinkingPositions = selectLookaheadPositions(difficultyLevel, maxThoughts);
  const prefetchQueries = buildPrefetchQueries({ prompt, taskType, difficultyLevel });
  const recentTurnCount = Array.isArray(conversationHistory) ? conversationHistory.length : 0;

  return {
    status: 'wired',
    source_paper: LATENT_LOOKAHEAD_SOURCE,
    mode: 'audited_anticipatory_prefetch',
    latent_horizon_tau: latentHorizonTau,
    thinking_positions: thinkingPositions,
    selected_position_strategy: 'beginning_reserved_then_difficulty_bounded',
    difficulty_level: difficultyLevel,
    recent_turn_count: recentTurnCount,
    prefetch_queries: prefetchQueries,
    anticipated_followups: prefetchQueries
      .filter((queryText) => queryText !== summarizePromptTopic(prompt))
      .slice(0, 3),
    promotion_policy: {
      default_lane: 'ephemeral_operational_prefetch',
      promote_when: 'the user asks a matching follow-up or the prefetched evidence is used in a verified response',
      discard_behavior: 'do not persist as long-term memory unless promoted by real use',
    },
    guarded_math: {
      hidden_state_recursion: false,
      latent_attention_mask_training: false,
      l_ntp_plus_l_latent_training: false,
      multi_token_prediction: false,
      transformer_finetuning: false,
    },
    aladdin_boundary: {
      physical_delete_allowed: false,
      unpromoted_prefetch_is_ephemeral: true,
    },
  };
}

function buildAnticipatoryReasoningPrefetch({
  prompt = '',
  responsePreview = '',
  taskType = 'chat',
  evidence = [],
  turnBudgetPlan = null,
  psychometricProfile = null,
} = {}) {
  const plan = buildLatentLookaheadPlan({
    prompt,
    taskType,
    turnBudgetPlan,
    psychometricProfile,
  });
  return {
    ...plan,
    response_preview_chars: normalizeTaskText(responsePreview).length,
    evidence_count: Array.isArray(evidence) ? evidence.length : 0,
    prefetch_state: plan.prefetch_queries.length > 0 ? 'ready' : 'no_prefetch_needed',
  };
}

function buildLatentLookaheadStatus(options = {}) {
  const plan = buildLatentLookaheadPlan({
    prompt: options.prompt || 'Implement a paper-backed Aimos orchestration fix and verify it.',
    taskType: options.taskType || 'architecture',
    turnBudgetPlan: options.turnBudgetPlan || {
      turn_difficulty: { difficulty_level: 3 },
      selected_budget_tokens: 2048,
      route_hint: 'deep_reasoning',
    },
    maxThoughts: options.maxThoughts || 2,
  });

  return {
    success: true,
    ...plan,
    contract: {
      paper_adaptation: 'latent lookahead becomes bounded pre-generation recall/prefetch metadata',
      first_position_reserved: plan.thinking_positions[0] === LOOKAHEAD_POSITIONS.BEGINNING,
      visible_scratchpad_only: true,
      hidden_chain_of_thought_exposed: false,
    },
  };
}

// ─── Traced Event Logging ───────────────────────────────────────────────────

async function logTracedEvent(agentId, operation, key, metadata = {}, parentEventId = null) {
  const eventId = await logEvent(COMPANY, agentId, operation, key, metadata, parentEventId);
  return { id: eventId };
}

// ─── Backward BFS Root-Cause Localization ───────────────────────────────────

async function backwardBFS(errorEventId, maxDepth = 10) {
  const visited = new Set();
  const nodes = [];
  let frontier = [{ id: errorEventId, depth: 0 }];

  while (frontier.length > 0) {
    const nextFrontier = [];

    for (const current of frontier) {
      if (visited.has(current.id)) continue;
      visited.add(current.id);

      const res = await query(
        `SELECT id, agent_id, operation, key, metadata, parent_event_id, ts
         FROM aimos_events
         WHERE id = $1 AND company_id = $2`,
        [current.id, COMPANY]
      );

      if (res.rows.length === 0) continue;

      const row = res.rows[0];
      nodes.push({
        id: row.id,
        agentId: row.agent_id,
        operation: row.operation,
        key: row.key,
        metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata,
        parentEventId: row.parent_event_id,
        createdAt: row.ts,
        depth: current.depth,
      });

      if (row.parent_event_id && current.depth < maxDepth) {
        nextFrontier.push({ id: row.parent_event_id, depth: current.depth + 1 });
      }
    }

    frontier = nextFrontier;
  }

  return nodes;
}

// ─── 5-Group Weighted Root-Cause Ranking ────────────────────────────────────

const EPSILON = 1e-8;

const WEIGHTS = {
  position: 0.70,
  structure: 0.20,
  content: 0.05,
  flow: 0.03,
  confidence: 0.02,
};

const ERROR_KEYWORDS = ['error', 'fail', 'exception', 'timeout', 'crash', 'abort', 'reject', 'fatal'];

function minMaxNormalize(values) {
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min + EPSILON;
  return values.map((v) => (v - min) / range);
}

function rankRootCauses(bfsResults) {
  if (bfsResults.length === 0) return [];

  const maxDepth = Math.max(...bfsResults.map((n) => n.depth));

  // Precompute in-degree and out-degree maps
  const inDegree = new Map();
  const outDegree = new Map();
  for (const node of bfsResults) {
    inDegree.set(node.id, 0);
    outDegree.set(node.id, 0);
  }
  for (const node of bfsResults) {
    if (node.parentEventId) {
      outDegree.set(node.parentEventId, (outDegree.get(node.parentEventId) || 0) + 1);
      inDegree.set(node.id, (inDegree.get(node.id) || 0) + 1);
    }
  }

  // Sort by createdAt for temporal gap computation
  const sorted = [...bfsResults].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const temporalGaps = new Map();
  for (let i = 0; i < sorted.length; i++) {
    if (i === 0) {
      temporalGaps.set(sorted[i].id, 0);
    } else {
      const gap = new Date(sorted[i].createdAt) - new Date(sorted[i - 1].createdAt);
      temporalGaps.set(sorted[i].id, gap);
    }
  }

  // Raw feature vectors
  const rawPosition = [];
  const rawStructure = [];
  const rawContent = [];
  const rawFlow = [];
  const rawConfidence = [];

  for (const node of bfsResults) {
    const isLeaf = (outDegree.get(node.id) || 0) === 0 ? 1 : 0;
    const depthScore = maxDepth > 0 ? node.depth / maxDepth : 0;
    rawPosition.push(depthScore * 0.6 + isLeaf * 0.4);

    const inDeg = inDegree.get(node.id) || 0;
    const outDeg = outDegree.get(node.id) || 0;
    rawStructure.push(inDeg + outDeg);

    const metaStr = JSON.stringify(node.metadata || {}).toLowerCase();
    const opStr = (node.operation || '').toLowerCase();
    const keyStr = (node.key || '').toLowerCase();
    const combined = `${metaStr} ${opStr} ${keyStr}`;
    const hasError = ERROR_KEYWORDS.some((kw) => combined.includes(kw)) ? 1 : 0;
    rawContent.push(hasError);

    rawFlow.push(temporalGaps.get(node.id) || 0);

    const confidence = node.metadata?.confidence ?? node.metadata?.agent_confidence ?? 0;
    rawConfidence.push(1 - confidence); // lower confidence = higher suspicion
  }

  // Normalize each feature group
  const normPosition = minMaxNormalize(rawPosition);
  const normStructure = minMaxNormalize(rawStructure);
  const normContent = minMaxNormalize(rawContent);
  const normFlow = minMaxNormalize(rawFlow);
  const normConfidence = minMaxNormalize(rawConfidence);

  // Compute weighted scores
  const scored = bfsResults.map((node, i) => {
    const score =
      WEIGHTS.position * normPosition[i] +
      WEIGHTS.structure * normStructure[i] +
      WEIGHTS.content * normContent[i] +
      WEIGHTS.flow * normFlow[i] +
      WEIGHTS.confidence * normConfidence[i];

    return {
      ...node,
      score,
      features: {
        position: normPosition[i],
        structure: normStructure[i],
        content: normContent[i],
        flow: normFlow[i],
        confidence: normConfidence[i],
      },
    };
  });

  // Sort descending by score — highest score = most likely root cause
  scored.sort((a, b) => b.score - a.score);

  return scored;
}

// ─── Forward Trace Tree ─────────────────────────────────────────────────────

async function getTraceTree(rootEventId) {
  const res = await query(
    `WITH RECURSIVE trace AS (
       SELECT id, agent_id, operation, key, metadata, parent_event_id, ts, 0 AS depth
       FROM aimos_events
       WHERE id = $1 AND company_id = $2

       UNION ALL

       SELECT e.id, e.agent_id, e.operation, e.key, e.metadata, e.parent_event_id, e.ts, t.depth + 1
       FROM aimos_events e
       INNER JOIN trace t ON e.parent_event_id = t.id
       WHERE e.company_id = $2
     )
     SELECT * FROM trace ORDER BY depth, ts`,
    [rootEventId, COMPANY]
  );

  // Build tree structure
  const nodeMap = new Map();
  let root = null;

  for (const row of res.rows) {
    const node = {
      id: row.id,
      agentId: row.agent_id,
      operation: row.operation,
      key: row.key,
      metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata,
      parentEventId: row.parent_event_id,
      createdAt: row.ts,
      depth: row.depth,
      children: [],
    };
    nodeMap.set(node.id, node);

    if (node.parentEventId && nodeMap.has(node.parentEventId)) {
      nodeMap.get(node.parentEventId).children.push(node);
    }

    if (row.depth === 0) {
      root = node;
    }
  }

  return root;
}

// ─── Exports ────────────────────────────────────────────────────────────────

export {
  logTracedEvent,
  buildLatentLookaheadPlan,
  buildAnticipatoryReasoningPrefetch,
  buildLatentLookaheadStatus,
  backwardBFS,
  rankRootCauses,
  getTraceTree,
};
