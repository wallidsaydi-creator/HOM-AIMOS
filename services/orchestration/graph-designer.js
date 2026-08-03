/**
 * graph-designer.js — Dynamic Multi-Agent DAG Construction (P1-5)
 * Source: BIGMAS (arXiv 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: governance-resolver.js
 * 2. → Pulls from: services/core/embeddings.js (Task similarity)
 * 3. → Pulls from: agent_profiles (Available role-slots)
 * 4. → Pushes to: Task-specific agent topology (JSON DAG)
 *
 * LOGIC GUIDE: Analyzes task complexity to build an optimal agent pipeline. 
 * Simple tasks get 3 nodes; complex tasks get the full 6-slot deliberation graph.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
/**
 * graph-designer.js — Dynamic Graph Construction (P1-5)
 *
 * Problem: Always deploying the full judge/jury/attorney/executor/auditor/retriever
 * pipeline wastes compute on simple tasks. Simple retrieval needs 3 nodes, not 6.
 *
 * Fix: GraphDesigner meta-agent analyzes task and constructs task-specific DAG
 * from the role-slot pool. Stores successful topologies as episodic memories
 * for reuse on similar tasks.
 *
 * Source: BIGMAS (Brain-Inspired Graph Multi-Agent System, arXiv 2026)
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;

// ─── ROLE SLOT DEFINITIONS ────────────────────────────────────────────────
// Fixed enum from I5 (Role-Slot Governance)
const ROLE_SLOTS = {
  judge: { description: 'Makes final decisions, resolves conflicts', weight: 'heavy' },
  jury: { description: 'Evaluates evidence, provides consensus scoring', weight: 'medium' },
  attorney: { description: 'Argues a position, builds cases from evidence', weight: 'medium' },
  executor: { description: 'Executes approved actions, tool calls', weight: 'light' },
  auditor: { description: 'Validates output, checks compliance', weight: 'medium' },
  retriever: { description: 'Fetches data from Aimos, tools, external sources', weight: 'light' },
};

// ─── TOPOLOGY TEMPLATES (pre-built for common patterns) ────────────────────
const TOPOLOGY_TEMPLATES = {
  simple_retrieval: {
    nodes: ['retriever', 'executor'],
    edges: [['retriever', 'executor']],
    description: 'Simple data retrieval and formatting',
    maxComplexity: 2,
  },
  standard_query: {
    nodes: ['retriever', 'executor', 'auditor'],
    edges: [['retriever', 'executor'], ['executor', 'auditor']],
    description: 'Query with validation',
    maxComplexity: 4,
  },
  governed_action: {
    nodes: ['retriever', 'attorney', 'judge', 'executor', 'auditor'],
    edges: [
      ['retriever', 'attorney'],
      ['attorney', 'judge'],
      ['judge', 'executor'],
      ['executor', 'auditor'],
    ],
    description: 'Action requiring governance approval',
    maxComplexity: 7,
  },
  full_deliberation: {
    nodes: ['retriever', 'attorney', 'jury', 'judge', 'executor', 'auditor'],
    edges: [
      ['retriever', 'attorney'],
      ['attorney', 'jury'],
      ['jury', 'judge'],
      ['judge', 'executor'],
      ['executor', 'auditor'],
      ['auditor', 'judge'], // cycle: auditor can send back to judge
    ],
    description: 'Full deliberative pipeline with review cycles',
    maxComplexity: 10,
  },
};

/**
 * Assess task complexity based on multiple signals.
 *
 * @param {string} prompt - user's prompt/task
 * @param {string} intent - classified intent
 * @param {number} constraintCount - number of constraints/requirements detected
 * @returns {{ complexity: number, signals: object }}
 */
export function assessComplexity(prompt, intent = '', constraintCount = 0) {
  const text = `${prompt || ''} ${intent || ''}`.toLowerCase();
  const len = text.length;
  const signals = {};

  let complexity = 1; // base

  // Length signal
  if (len > 500) { complexity += 2; signals.long_prompt = true; }
  else if (len > 200) { complexity += 1; signals.medium_prompt = true; }

  // Constraint count
  complexity += Math.min(constraintCount, 3);
  signals.constraints = constraintCount;

  // Multi-step detection
  const stepWords = (text.match(/\b(then|after|next|finally|first|second|third|step|phase)\b/g) || []).length;
  if (stepWords >= 3) { complexity += 2; signals.multi_step = true; }
  else if (stepWords >= 1) { complexity += 1; signals.sequential = true; }

  // Governance-triggering keywords
  if (/\b(approve|authorize|permission|clearance|escalat|override)\b/.test(text)) {
    complexity += 2;
    signals.governance_required = true;
  }

  // External action keywords
  if (/\b(send|post|tweet|email|deploy|delete|create|modify|update)\b/.test(text)) {
    complexity += 1;
    signals.external_action = true;
  }

  // Reasoning depth keywords
  if (/\b(analyze|compare|evaluate|assess|recommend|strategy|trade-?off)\b/.test(text)) {
    complexity += 1;
    signals.reasoning_depth = true;
  }

  // Risk keywords
  if (/\b(risk|danger|critical|production|security|sensitive|confidential)\b/.test(text)) {
    complexity += 1;
    signals.risk_elevated = true;
  }

  return { complexity: Math.min(complexity, 10), signals };
}

/**
 * Select the optimal topology for a task based on complexity.
 *
 * @param {{ complexity: number, signals: object }} assessment
 * @returns {{ topology: object, templateName: string }}
 */
export function selectTopology(assessment) {
  const { complexity, signals } = assessment;

  // Governance required → at least governed_action
  if (signals.governance_required && complexity >= 5) {
    return { topology: TOPOLOGY_TEMPLATES.full_deliberation, templateName: 'full_deliberation' };
  }
  if (signals.governance_required) {
    return { topology: TOPOLOGY_TEMPLATES.governed_action, templateName: 'governed_action' };
  }

  // Route by complexity score
  if (complexity <= 2) {
    return { topology: TOPOLOGY_TEMPLATES.simple_retrieval, templateName: 'simple_retrieval' };
  }
  if (complexity <= 4) {
    return { topology: TOPOLOGY_TEMPLATES.standard_query, templateName: 'standard_query' };
  }
  if (complexity <= 7) {
    return { topology: TOPOLOGY_TEMPLATES.governed_action, templateName: 'governed_action' };
  }
  return { topology: TOPOLOGY_TEMPLATES.full_deliberation, templateName: 'full_deliberation' };
}

/**
 * Design a task-specific agent DAG.
 * First checks for cached successful topologies, then falls back to template selection.
 *
 * @param {string} taskPrompt
 * @param {string} intent
 * @param {{ constraintCount?: number }} options
 * @returns {Promise<{ topology: object, templateName: string, fromCache: boolean, assessment: object }>}
 */
export async function designTaskGraph(taskPrompt, intent = '', options = {}) {
  const assessment = assessComplexity(taskPrompt, intent, options.constraintCount || 0);

  // Try to find a cached successful topology for a similar task
  const cached = await findCachedTopology(taskPrompt);
  if (cached) {
    return {
      topology: cached.topology,
      templateName: cached.templateName,
      fromCache: true,
      assessment
    };
  }

  // Fall back to template selection
  const selected = selectTopology(assessment);
  return {
    ...selected,
    fromCache: false,
    assessment
  };
}

/**
 * Find a cached successful topology for a similar task.
 * Uses embedding similarity to match against past successful runs.
 *
 * @param {string} taskPrompt
 * @returns {Promise<{ topology: object, templateName: string } | null>}
 */
async function findCachedTopology(taskPrompt) {
  try {
    const embedding = await getEmbedding(taskPrompt);
    if (!embedding || embedding._degraded) return null;

    const result = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND memory_type = 'procedural'
         AND key LIKE 'topology_cache:%'
       ORDER BY embedding <=> $2::vector ASC
       LIMIT 1`,
      [COMPANY, JSON.stringify(embedding)]
    );

    if (result.rows.length === 0) return null;

    // Check similarity threshold
    const simResult = await query(
      `SELECT 1 - (embedding <=> $1::vector) as similarity
       FROM aimos_memories
       WHERE company_id = $2 AND memory_type = 'procedural'
         AND key LIKE 'topology_cache:%'
       ORDER BY embedding <=> $1::vector ASC
       LIMIT 1`,
      [JSON.stringify(embedding), COMPANY]
    );

    const similarity = parseFloat(simResult.rows[0]?.similarity || 0);
    if (similarity < 0.85) return null; // not similar enough to reuse

    try {
      return JSON.parse(result.rows[0].value);
    } catch {
      return null;
    }
  } catch {
    return null;
  }
}

/**
 * Cache a successful topology for future reuse.
 *
 * @param {string} taskPrompt - the task that was successfully completed
 * @param {string} templateName - which template was used
 * @param {object} topology - the topology that succeeded
 */
export async function cacheSuccessfulTopology(taskPrompt, templateName, topology) {
  try {
    const key = `topology_cache:${templateName}:${Date.now()}`;
    const value = JSON.stringify({ topology, templateName, cached_at: new Date().toISOString() });

    await persistMemory({
      company_id: COMPANY,
      agent_id: 'graph-designer',
      key,
      value,
      scope: 'system',
      memory_type: 'procedural',
      memory_tier: 'long-term',
      clearance_level: 5,
      mutation_authority: 'housekeeper',
    });
  } catch (err) {
    console.warn('[graph-designer] topology caching failed:', err.message);
  }
}

/**
 * Get available topology templates for diagnostic/admin purposes.
 */
export function getTopologyTemplates() {
  return { ...TOPOLOGY_TEMPLATES };
}

/**
 * Validate that a topology is well-formed (all edges reference existing nodes).
 */
export function validateTopology(topology) {
  const nodeSet = new Set(topology.nodes || []);
  const errors = [];

  for (const [from, to] of (topology.edges || [])) {
    if (!nodeSet.has(from)) errors.push(`Edge source '${from}' not in node list`);
    if (!nodeSet.has(to)) errors.push(`Edge target '${to}' not in node list`);
    if (!ROLE_SLOTS[from]) errors.push(`Unknown role slot: '${from}'`);
    if (!ROLE_SLOTS[to]) errors.push(`Unknown role slot: '${to}'`);
  }

  return { valid: errors.length === 0, errors };
}
