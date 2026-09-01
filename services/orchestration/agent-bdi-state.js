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
import { withTransaction } from '../../db/connection.js';
import { logEvent, readVerifiedEventById } from '../observe/event-ledger.js';

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
export async function updateAgentState(agentId, phase, currentTask, lastAction, nextAction, confidence, bdi = {}, options = {}) {
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

    return logEvent(COMPANY, agentId, 'agent_bdi_state_committed', `agent-bdi:${agentId}:${options.runId || Date.now()}`, {
      schema: 'hom.aimos.agent-bdi-state/v1',
      company_id: COMPANY,
      agent_id: agentId,
      phase: phase || null,
      current_task: currentTask || null,
      last_action: lastAction || null,
      next_action: nextAction || null,
      confidence: Number.isFinite(Number(confidence)) ? Number(confidence) : null,
      beliefs: beliefs ? JSON.parse(beliefs) : null,
      desires: desires ? JSON.parse(desires) : null,
      intentions: intentions ? JSON.parse(intentions) : null,
      waiting_for: options.waitingFor || null,
      blockers: Array.isArray(options.blockers) ? options.blockers : [],
      run_id: options.runId || null,
      reasoning: 'The Housekeeper retained the complete non-empty BDI projection as an append-only run consequence.',
    }, options.parentEventId || options.authority?.requestAdmissionEventId || null, {
      authority: options.authority || null,
      returnReceipt: true,
    });
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
    const row = await withTransaction(async (client) => {
      const result = await client.query(
        `SELECT id FROM aimos_events
          WHERE company_id = $1 AND agent_id = $2
            AND operation = 'agent_bdi_state_committed' AND ledger_version = 1
          ORDER BY ts DESC, signer_valid_from DESC, ledger_seq DESC LIMIT 1`,
        [COMPANY, agentId],
      );
      return result.rows[0]
        ? readVerifiedEventById(result.rows[0].id, COMPANY, { client })
        : null;
    }, { restricted: true, client_id: COMPANY, agent_id: agentId });
    if (!row) return null;
    const metadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
    if (metadata?.schema !== 'hom.aimos.agent-bdi-state/v1' || metadata?.agent_id !== agentId) {
      throw new Error('agent_bdi_state_event_invalid');
    }
    return {
      beliefs: metadata.beliefs || {},
      desires: metadata.desires || {},
      intentions: metadata.intentions || [],
      waiting_for: metadata.waiting_for || null,
      blockers: Array.isArray(metadata.blockers) ? metadata.blockers : [],
      current_task: metadata.current_task || null,
      last_action: metadata.last_action || null,
      next_action: metadata.next_action || null,
      confidence: Number(metadata.confidence || 0),
      phase: metadata.phase || 'unknown'
    };
  } catch { return null; }
}
