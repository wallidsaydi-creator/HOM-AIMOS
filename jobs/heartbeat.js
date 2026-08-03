/**
 * heartbeat.js — System health pulse, the "awake" counterpart to nightly-dream.js
 *
 * Runs every 30 minutes while server is up.
 * Checks: Aimos DB connectivity, memory counts, recent event flow,
 *         process health, stuck lanes, pool health.
 * Saves: heartbeat event to aimos_events + heartbeat_status to aimos_memories.
 *
 * The nightly dream is sleep consolidation (deep, heavy, once per day).
 * The heartbeat is the waking pulse (light, fast, continuous).
 * If heartbeat stops appearing in Aimos, something is wrong.
 *
 * Zero LLM calls. Pure DB + process checks.
 */

import { query, pool } from '../db/connection.js';
import { logEvent } from '../services/observe/event-ledger.js';
import { persistMemory } from '../services/write/persist-memory.js';
import { auditAladdinCompliance } from '../services/governance/aladdin-compliance.js';
import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';

export const HEARTBEAT_INTERVAL_CRON = '*/30 * * * *';
const COMPANY = AIMOS_COMPANY_ID;

/**
 * Run a single heartbeat check. Fast (< 5 seconds), never throws.
 *
 * @param {string} companyId
 * @returns {Promise<{status: string, timestamp: string, uptimeSec: number, checks: Object, warnings: string[]}>}
 */
export async function runHeartbeat(companyId = COMPANY) {
  const timestamp = new Date().toISOString();
  const warnings = [];
  const checks = {};

  // ─── CHECK 1: Aimos DB connectivity + latency ─────────────────────────
  try {
    const t0 = Date.now();
    await query('SELECT 1 AS ping');
    const latencyMs = Date.now() - t0;
    checks.aimos = { connected: true, latencyMs };
    if (latencyMs > 500) warnings.push(`Aimos latency high: ${latencyMs}ms`);
  } catch (err) {
    checks.aimos = { connected: false, latencyMs: -1, error: err.message };
    warnings.push(`Aimos unreachable: ${err.message}`);
  }

  // ─── CHECK 2: Memory counts ────────────────────────────────────────────
  try {
    const [totalRes, day24hRes, hourRes] = await Promise.all([
      query(`SELECT COUNT(*) AS cnt FROM aimos_memories WHERE company_id = $1`, [companyId]),
      query(`SELECT COUNT(*) AS cnt FROM aimos_memories WHERE company_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'`, [companyId]),
      query(`SELECT COUNT(*) AS cnt FROM aimos_memories WHERE company_id = $1 AND created_at >= NOW() - INTERVAL '1 hour'`, [companyId]),
    ]);
    checks.memory = {
      totalRetained: parseInt(totalRes.rows[0]?.cnt || '0', 10),
      last24h: parseInt(day24hRes.rows[0]?.cnt || '0', 10),
      lastHour: parseInt(hourRes.rows[0]?.cnt || '0', 10),
    };
    if (checks.memory.last24h === 0) warnings.push('Zero memories in last 24h — system may be idle or logging broken');
  } catch (err) {
    checks.memory = { totalRetained: -1, last24h: -1, lastHour: -1, error: err.message };
    warnings.push(`Memory count failed: ${err.message}`);
  }

  // ─── CHECK 3: Event flow ───────────────────────────────────────────────
  try {
    const [ev24h, evHour, lastHb] = await Promise.all([
      query(`SELECT COUNT(*) AS cnt FROM aimos_events WHERE company_id = $1 AND ts >= NOW() - INTERVAL '24 hours'`, [companyId]),
      query(`SELECT COUNT(*) AS cnt FROM aimos_events WHERE company_id = $1 AND ts >= NOW() - INTERVAL '1 hour'`, [companyId]),
      query(`SELECT ts FROM aimos_events WHERE company_id = $1 AND operation = 'heartbeat' ORDER BY ts DESC LIMIT 1`, [companyId]),
    ]);
    const lastHbTs = lastHb.rows[0]?.ts || null;
    const lastHbAgo = lastHbTs ? `${Math.round((Date.now() - new Date(lastHbTs).getTime()) / 60000)} minutes ago` : null;
    checks.events = {
      last24h: parseInt(ev24h.rows[0]?.cnt || '0', 10),
      lastHour: parseInt(evHour.rows[0]?.cnt || '0', 10),
      lastHeartbeatAgo: lastHbAgo,
    };
    if (checks.events.last24h === 0) warnings.push('Zero events in last 24h');
  } catch (err) {
    checks.events = { last24h: -1, lastHour: -1, lastHeartbeatAgo: null, error: err.message };
    warnings.push(`Event query failed: ${err.message}`);
  }

  // ─── CHECK 4: Stuck session lanes ──────────────────────────────────────
  try {
    const [stuckRes, runRes] = await Promise.all([
      query(`SELECT COUNT(*) AS cnt FROM session_lanes WHERE company_id = $1 AND run_status = 'stuck'`, [companyId]),
      query(`SELECT COUNT(*) AS cnt FROM session_lanes WHERE company_id = $1 AND run_status = 'running'`, [companyId]),
    ]);
    checks.lanes = {
      stuck: parseInt(stuckRes.rows[0]?.cnt || '0', 10),
      running: parseInt(runRes.rows[0]?.cnt || '0', 10),
    };
    if (checks.lanes.stuck > 0) warnings.push(`${checks.lanes.stuck} stuck lane(s)`);
  } catch {
    checks.lanes = { stuck: -1, running: -1 };
  }

  // ─── CHECK 5: Process health ───────────────────────────────────────────
  const mem = process.memoryUsage();
  checks.process = {
    heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
    heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
    rssMB: Math.round(mem.rss / 1024 / 1024),
  };
  if (checks.process.heapUsedMB > 512) warnings.push(`Heap high: ${checks.process.heapUsedMB}MB`);

  // ─── CHECK 6: Pool health ─────────────────────────────────────────────
  try {
    checks.pool = {
      totalCount: pool.totalCount,
      idleCount: pool.idleCount,
      waitingCount: pool.waitingCount,
    };
    if (pool.waitingCount > 5) warnings.push(`${pool.waitingCount} queries waiting — pool may be exhausted`);
  } catch {
    checks.pool = { totalCount: -1, idleCount: -1, waitingCount: -1 };
  }

  // ─── CHECK 7: Aladdin compliance canary ─────────────────────────────────
  try {
    const aladdin = await auditAladdinCompliance();
    checks.aladdin = aladdin;
    if (!aladdin.compliant) {
      warnings.push(
        `Aladdin compliance flagged ${aladdin.flagged} record(s) (${aladdin.dormant_count} dormant, ${aladdin.out_of_bounds_count} out of bounds)`
      );
    }
  } catch (err) {
    checks.aladdin = { compliant: false, flagged: -1, error: err.message };
    warnings.push(`Aladdin compliance audit failed: ${err.message}`);
  }

  // ─── Determine status ──────────────────────────────────────────────────
  let status = 'healthy';
  if (!checks.aimos?.connected) status = 'critical';
  else if (warnings.length > 0) status = 'degraded';

  const result = { status, timestamp, uptimeSec: Math.round(process.uptime()), checks, warnings };

  // ─── SAVE: event (time series) ─────────────────────────────────────────
  try {
    await logEvent(companyId, 'system', 'heartbeat', 'heartbeat:pulse', {
      status,
      uptimeSec: result.uptimeSec,
      memoryTotal: checks.memory?.totalRetained ?? -1,
      memoryLastHour: checks.memory?.lastHour ?? -1,
      eventsLastHour: checks.events?.lastHour ?? -1,
      aimosLatencyMs: checks.aimos?.latencyMs ?? -1,
      heapUsedMB: checks.process?.heapUsedMB ?? -1,
      aladdinCompliant: checks.aladdin?.compliant ?? false,
      aladdinFlagged: checks.aladdin?.flagged ?? -1,
      warningCount: warnings.length,
      warnings: warnings.slice(0, 5),
      reasoning: `System heartbeat pulse. Status: ${status}. ${warnings.length} warnings.`,
    });
  } catch (err) {
    console.warn('[heartbeat] Failed to log event:', err.message);
  }

  // ─── SAVE: snapshot (latest state, upserted) ──────────────────────────
  // Fail-closed: persistMemory + commitProvenance are atomic. If the
  // ledger commit fails, the heartbeat throws — the cron runner surfaces it.
  const heartbeatKey = 'heartbeat:latest';
  const heartbeatValue = JSON.stringify(result);
  const saved = await persistMemory({
    company_id: companyId,
    agent_id: 'housekeeper',
    key: heartbeatKey,
    value: heartbeatValue,
    scope: 'system',
    memory_type: 'event_log',
    source: 'heartbeat',
    mutation_authority: 'housekeeper',
  });

  console.log(`[heartbeat] ${status} | uptime=${result.uptimeSec}s | memories=${checks.memory?.totalRetained ?? '?'} | events/hr=${checks.events?.lastHour ?? '?'} | aimos=${checks.aimos?.latencyMs ?? '?'}ms | heap=${checks.process?.heapUsedMB ?? '?'}MB | warnings=${warnings.length}`);

  return result;
}
