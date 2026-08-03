/**
 * agent-bdi-state.js — BDI State Management (Gap 4 extraction)
 *
 * Reads and persists Belief-Desire-Intention state for Aimos agents.
 * Includes BDI ghosting prevention (Fix 1 from premortem):
 * empty BDI never overwrites existing real data.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: agent-runner.js (post-run BDI update, pre-run BDI read)
 * 2. → Calls: db/connection.js (query)
 * 3. Pipeline: AGENT_RUN_PIPELINE | Position: state persistence
 *
 * Created: 2026-05-05 (Gap 4 extraction from agent-runner.js)
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';

const COMPANY = AIMOS_COMPANY_ID;

// ─── BDI GHOSTING PREVENTION ────────────────────────────────────────────────────
// Fix 1 from premortem analysis: empty BDI (beliefs={}, desires={}, intentions=[])
// never overwrites existing real data. The COALESCE(NULLIF(...)) pattern in the
// SQL ensures empty JSON objects fall back to the existing column value.
// Additionally, we log a CRITICAL warning when ghosting is detected.

/**
 * Persist BDI state for an agent after a run.
 * Uses COALESCE(NULLIF(...)) pattern to prevent ghosting:
 * empty JSON objects fall back to existing column values.
 *
 * @param {string} agentId - Agent identifier
 * @param {string} phase - Current phase (e.g., 'idle', 'executing')
 * @param {string} currentTask - Current task description
 * @param {string|null} lastAction - Last action taken
 * @param {string|null} nextAction - Next action planned
 * @param {number} confidence - Confidence score (0-1)
 * @param {Object} bdi - BDI state {beliefs, desires, intentions}
 */
export async function updateAgentState(agentId, phase, currentTask, lastAction, nextAction, confidence, bdi = {}) {
  try {
    const beliefsRaw = bdi.beliefs;
    const desiresRaw = bdi.desires;
    const intentionsRaw = bdi.intentions;
    const beliefsEmpty = !beliefsRaw || (typeof beliefsRaw === 'object' && Object.keys(beliefsRaw).length === 0);
    const desiresEmpty = !desiresRaw || (typeof desiresRaw === 'object' && Object.keys(desiresRaw).length === 0);
    const intentionsEmpty = !intentionsRaw ||
      (Array.isArray(intentionsRaw) && intentionsRaw.length === 0) ||
      (typeof intentionsRaw === 'object' && !Array.isArray(intentionsRaw) && Object.keys(intentionsRaw).length === 0);

    if (beliefsEmpty && desiresEmpty && intentionsEmpty) {
      console.error(`[BDI-GHOSTING] CRITICAL: Agent ${agentId} produced empty BDI state (beliefs={}, desires={}, intentions=[]). Preserving existing state.`);
    }

    const beliefs = (beliefsRaw && Object.keys(beliefsRaw).length > 0) ? JSON.stringify(beliefsRaw) : null;
    const desires = (desiresRaw && Object.keys(desiresRaw).length > 0) ? JSON.stringify(desiresRaw) : null;
    const intentions = (intentionsRaw && (Array.isArray(intentionsRaw) ? intentionsRaw.length > 0 : Object.keys(intentionsRaw).length > 0)) ? JSON.stringify(intentionsRaw) : null;

    await query(
      `INSERT INTO agent_state (company_id, agent_id, phase, current_task, last_action, next_action, confidence,
                                beliefs, desires, intentions, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, NOW())
       ON CONFLICT (company_id, agent_id)
       DO UPDATE SET phase = $3, current_task = $4, last_action = $5, next_action = $6, confidence = $7,
                     beliefs = COALESCE(NULLIF($8::jsonb, '{}'::jsonb), agent_state.beliefs),
                     desires = COALESCE(NULLIF($9::jsonb, '{}'::jsonb), agent_state.desires),
                     intentions = COALESCE(NULLIF($10::jsonb, '[]'::jsonb), agent_state.intentions),
                     updated_at = NOW()`,
      [COMPANY, agentId, phase, currentTask, lastAction, nextAction, confidence, beliefs, desires, intentions]
    );
  } catch { /* best effort */ }
}

/**
 * Read BDI state for an agent.
 * Returns parsed JSON for beliefs/desires/intentions, or null if not found.
 *
 * @param {string} agentId - Agent identifier
 * @returns {Promise<Object|null>} BDI state or null
 */
export async function readAgentBDIState(agentId) {
  try {
    const res = await query(
      `SELECT beliefs, desires, intentions, confidence, phase
       FROM agent_state WHERE company_id = $1 AND agent_id = $2 LIMIT 1`,
      [COMPANY, agentId]
    );
    if (!res.rows.length) return null;
    const row = res.rows[0];
    return {
      beliefs: typeof row.beliefs === 'string' ? JSON.parse(row.beliefs) : row.beliefs,
      desires: typeof row.desires === 'string' ? JSON.parse(row.desires) : row.desires,
      intentions: typeof row.intentions === 'string' ? JSON.parse(row.intentions) : row.intentions,
      confidence: parseFloat(row.confidence) || 0,
      phase: row.phase || 'unknown'
    };
  } catch { return null; }
}
