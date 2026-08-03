// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — recall post-recall reinforcement only
// Purpose: Ant colony-inspired pheromone trails between related memories;
//          deposits on successful retrieval and dampens hubs
// Wire into: routes/aimos.js (RECALL pipeline, post-recall reinforcement only)
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// RETRIEVAL PHEROMONE (retrieval-pheromone.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-4: Ant colony-inspired pheromone system for memory retrieval.
// Deposits pheromone trails between related memories and uses hub dampening to
// prevent over-centralization. Aladdin law excludes decay from this service.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query, withTransaction } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const DEFAULT_DEPOSIT_INTENSITY = 0.1;
const DEFAULT_MAX_REINFORCED_MEMORIES = 6;
const DEFAULT_MAX_REINFORCED_EDGES = 15;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizeMemoryId(value) {
  const id = String(value || '').trim();
  return UUID_RE.test(id) ? id : '';
}

function uniqueMemoryIds(memories = [], limit = DEFAULT_MAX_REINFORCED_MEMORIES) {
  const seen = new Set();
  const ids = [];
  for (const memory of Array.isArray(memories) ? memories : []) {
    const id = normalizeMemoryId(memory?.id ?? memory?.memory_id ?? memory);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
    if (ids.length >= limit) break;
  }
  return ids;
}

/**
 * Deposit pheromone between two memories.
 * Positive reinforcement for a successful retrieval pathway.
 *
 * @param {string} memoryIdA - First memory UUID
 * @param {string} memoryIdB - Second memory UUID
 * @param {number} signal - must be positive
 * @param {string} companyId - Company ID
 * @returns {Promise<boolean>} - true on success
 */
export async function depositPheromone(memoryIdA, memoryIdB, signal, companyId, options = {}) {
  const cid = companyId || COMPANY;

  try {
    const left = normalizeMemoryId(memoryIdA);
    const right = normalizeMemoryId(memoryIdB);
    if (!left || !right || left === right) return false;

    // Ensure consistent ordering (A < B) for symmetric edges
    const [id1, id2] = left <= right
      ? [left, right]
      : [right, left];

    const intensity = Math.max(0, Math.min(
      DEFAULT_DEPOSIT_INTENSITY,
      Number(options.intensity ?? DEFAULT_DEPOSIT_INTENSITY)
    ));
    if (!(Number(signal) > 0) || !Number.isFinite(intensity) || intensity <= 0) return false;

    await withTransaction(async (client) => {
      const edge = await applyPositiveDeposit(client, cid, id1, id2, intensity);
      await logEvent(
        cid,
        String(options.agentId || 'aimos'),
        'retrieval_pheromone_deposited',
        `pheromone:${id1}:${id2}`,
        {
          edge,
          decay_applied: false,
          reasoning: 'A successful retrieval produced bounded positive co-retrieval reinforcement.',
          source_knowledge: 'retrieval-pheromone.js internal bounded reinforcement heuristic',
        },
        null,
        { client }
      );
    }, { restricted: true, client_id: cid, agent_id: 'housekeeper' });

    return true;
  } catch (err) {
    console.error('[retrieval-pheromone] depositPheromone error:', err.message);
    return false;
  }
}

async function applyPositiveDeposit(client, companyId, memoryIdA, memoryIdB, intensity) {
  const result = await client.query(
    `INSERT INTO retrieval_pheromones (company_id, memory_id_a, memory_id_b, tau, updated_at)
     VALUES ($1, $2, $3, $4::real, NOW())
     ON CONFLICT (company_id, memory_id_a, memory_id_b) DO UPDATE
     SET tau = COALESCE(retrieval_pheromones.tau, 0) + $4::real,
         updated_at = NOW()
     RETURNING tau`,
    [companyId, memoryIdA, memoryIdB, intensity]
  );
  const newTau = Number(result.rows[0]?.tau || 0);
  return {
    memory_id_a: memoryIdA,
    memory_id_b: memoryIdB,
    intensity: Number(intensity.toFixed(6)),
    prior_tau: Number(Math.max(0, newTau - intensity).toFixed(6)),
    new_tau: Number(newTau.toFixed(6)),
  };
}

/**
 * Get pheromone strength between two memories.
 *
 * @param {string} memoryIdA - First memory UUID
 * @param {string} memoryIdB - Second memory UUID
 * @param {string} companyId - Company ID
 * @returns {Promise<number>} - tau value (0 if no pheromone)
 */
export async function getPheromoneStrength(memoryIdA, memoryIdB, companyId) {
  const cid = companyId || COMPANY;

  try {
    const [id1, id2] = memoryIdA <= memoryIdB
      ? [memoryIdA, memoryIdB]
      : [memoryIdB, memoryIdA];

    const result = await query(
      `SELECT tau FROM retrieval_pheromones
       WHERE company_id = $1 AND memory_id_a = $2 AND memory_id_b = $3`,
      [cid, id1, id2]
    );

    return result.rows.length > 0 ? parseFloat(result.rows[0].tau) : 0;
  } catch (err) {
    console.error('[retrieval-pheromone] getPheromoneStrength error:', err.message);
    return 0;
  }
}

/**
 * Get top connected memories by pheromone strength.
 *
 * @param {string} memoryId - Source memory UUID
 * @param {string} companyId - Company ID
 * @param {number} limit - Max results (default: 10)
 * @returns {Promise<Array>} - [{memory_id, tau}, ...]
 */
export async function getPheromonePaths(memoryId, companyId, limit = 10) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT CASE
               WHEN memory_id_a = $1 THEN memory_id_b
               ELSE memory_id_a
             END as connected_memory_id,
             tau
       FROM retrieval_pheromones
       WHERE company_id = $2 AND (memory_id_a = $1 OR memory_id_b = $1)
       ORDER BY tau DESC
       LIMIT $3`,
      [memoryId, cid, limit]
    );

    return result.rows.map(row => ({
      memory_id: row.connected_memory_id,
      tau: parseFloat(row.tau)
    }));
  } catch (err) {
    console.error('[retrieval-pheromone] getPheromonePaths error:', err.message);
    return [];
  }
}

/**
 * Apply hub dampening to prevent over-centralization.
 * Scale pheromone strength by: min(1, threshold / degree)
 * where degree = number of connected memories.
 *
 * @param {string} memoryId - Memory UUID
 * @param {number} degree - Number of connected memories
 * @param {number} threshold - Dampening threshold (default: 5)
 * @returns {number} - Dampening factor [0, 1]
 */
export function applyHubDampening(memoryId, degree, threshold = 5) {
  if (degree <= 0) return 1;
  return Math.min(1, threshold / degree);
}

async function getPheromoneDegreeMap(memoryIds = [], companyId) {
  const cid = companyId || COMPANY;
  const ids = uniqueMemoryIds(memoryIds, DEFAULT_MAX_REINFORCED_MEMORIES);
  if (!ids.length) return new Map();

  const result = await query(
    `SELECT memory_id, COUNT(*)::int AS degree
       FROM (
         SELECT memory_id_a AS memory_id
           FROM retrieval_pheromones
          WHERE company_id = $1 AND memory_id_a = ANY($2::uuid[])
         UNION ALL
         SELECT memory_id_b AS memory_id
           FROM retrieval_pheromones
          WHERE company_id = $1 AND memory_id_b = ANY($2::uuid[])
       ) edges
      GROUP BY memory_id`,
    [cid, ids]
  );

  return new Map(result.rows.map(row => [String(row.memory_id), Number(row.degree || 0)]));
}

/**
 * Reinforce co-retrieved memory paths after successful recall.
 *
 * This is the Aladdin-safe live path: positive bounded reinforcement only.
 * It does not decay pheromones, delete memories, mutate retrieval weights,
 * or alter ranking math for the current response.
 */
export async function reinforceRetrievedPheromones(memories = [], options = {}) {
  const cid = options.companyId || COMPANY;
  const agentId = String(options.agentId || 'aimos').trim() || 'aimos';
  const queryText = String(options.queryText || '').trim();
  const maxMemories = Math.max(2, Math.min(12, Number(options.maxMemories || DEFAULT_MAX_REINFORCED_MEMORIES)));
  const maxEdges = Math.max(1, Math.min(66, Number(options.maxEdges || DEFAULT_MAX_REINFORCED_EDGES)));
  const memoryIds = uniqueMemoryIds(memories, maxMemories);

  if (memoryIds.length < 2) {
    return {
      reinforced: false,
      skipped: true,
      reason: 'need_at_least_two_recalled_memories',
      memory_count: memoryIds.length,
      edge_count: 0,
    };
  }

  try {
    const degreeMap = await getPheromoneDegreeMap(memoryIds, cid);
    const result = await withTransaction(async (client) => {
      const edges = [];
      let attempts = 0;

      for (let i = 0; i < memoryIds.length; i++) {
        for (let j = i + 1; j < memoryIds.length; j++) {
          if (attempts >= maxEdges) break;
          const left = memoryIds[i];
          const right = memoryIds[j];
          const dampening = Math.min(
            applyHubDampening(left, degreeMap.get(left) || 0),
            applyHubDampening(right, degreeMap.get(right) || 0)
          );
          const intensity = DEFAULT_DEPOSIT_INTENSITY * dampening;
          attempts += 1;
          edges.push(await applyPositiveDeposit(client, cid, left, right, intensity));
        }
        if (attempts >= maxEdges) break;
      }

      const eventId = edges.length > 0
        ? await logEvent(cid, agentId, 'retrieval_pheromone_reinforced', `recall:${queryText.slice(0, 80) || 'unknown'}`, {
          memory_count: memoryIds.length,
          edge_count: edges.length,
          max_edges: maxEdges,
          edges,
          decay_applied: false,
          ranking_math_changed: false,
          retrieval_weight_changed: false,
          canonical_memory_changed: false,
          hub_dampening_applied: true,
          reasoning: 'Successful recall returned multiple memories, so Aimos reinforced bounded co-retrieval trails without decay or ranking mutation.',
          source_knowledge: 'retrieval-pheromone.js internal bounded reinforcement heuristic; Aladdin law excludes decay.',
        }, null, { client })
        : null;
      return { edges, eventId };
    }, { restricted: true, client_id: cid, agent_id: 'housekeeper' });

    return {
      reinforced: result.edges.length > 0,
      skipped: result.edges.length === 0,
      memory_count: memoryIds.length,
      edge_count: result.edges.length,
      event_id: result.eventId,
      decay_applied: false,
      ranking_math_changed: false,
      retrieval_weight_changed: false,
      canonical_memory_changed: false,
    };
  } catch (err) {
    console.error('[retrieval-pheromone] reinforceRetrievedPheromones error:', err.message);
    return {
      reinforced: false,
      skipped: true,
      reason: err.message,
      memory_count: memoryIds.length,
      edge_count: 0,
    };
  }
}
