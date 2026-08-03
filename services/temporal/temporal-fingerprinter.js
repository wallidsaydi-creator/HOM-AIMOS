// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into DREAM temporal authenticity diagnostics
// Purpose: CoV-based authenticity detection (CoV<0.5=autonomous, CoV>1.0=human);
//          validated chi-square=551.76, p<10^-117
// Called by: jobs/nightly-dream.js Stage 15
// Calls: observe/event-ledger.js
// Pipeline: DREAM
// ─────────────────────────────────────────────────────────────────────────────

/**
 * temporal-fingerprinter.js — CoV-based agent authenticity detection
 * Source: Moltbook Illusion (2026)
 *
 * CoV = sigma(intervals) / mean(intervals)
 * CoV < 0.5 = autonomous heartbeat
 * CoV > 1.0 = human-influenced
 * Validated: chi-square = 551.76, P < 10^-117
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

export async function fingerprintAgent(agentId, windowHours = 24, companyId = COMPANY) {
  const boundedWindow = Math.max(1, Math.min(2160, Number.parseInt(windowHours, 10) || 24));
  const res = await query(`
    SELECT COALESCE(ts_created, created_at) AS activity_ts FROM aimos_memories
    WHERE company_id = $1 AND agent_id = $2
      AND COALESCE(ts_created, created_at) > NOW() - INTERVAL '1 hour' * $3
    ORDER BY activity_ts ASC
  `, [companyId, agentId, boundedWindow]);

  if (res.rows.length < 5) return { agentId, classification: 'insufficient_data', sampleSize: res.rows.length, sample_size: Math.max(0, res.rows.length - 1) };

  const timestamps = res.rows.map(r => new Date(r.activity_ts).getTime());
  const intervals = [];
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i] - timestamps[i - 1]);
  }

  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
  const stddev = Math.sqrt(variance);
  const cov = mean > 0 ? stddev / mean : 0;

  const subMinuteCount = intervals.filter(i => i < 60000).length;
  const subMinuteRatio = subMinuteCount / intervals.length;
  const farmingDetected = subMinuteRatio > 0.5 && mean < 30000;

  let classification;
  if (cov < 0.5) classification = 'autonomous_heartbeat';
  else if (cov > 1.0) classification = 'human_influenced';
  else classification = 'mixed_signal';

  return {
    agentId,
    classification,
    cov: Math.round(cov * 1000) / 1000,
    mean_interval_ms: Math.round(mean),
    stddev_ms: Math.round(stddev),
    sample_size: intervals.length,
    farming_detected: farmingDetected,
    sub_minute_ratio: Math.round(subMinuteRatio * 100) / 100
  };
}

export async function fingerprintAllAgents(windowHours = 24) {
  const boundedWindow = Math.max(1, Math.min(2160, Number.parseInt(windowHours, 10) || 24));
  const agents = await query(`
    SELECT DISTINCT agent_id FROM aimos_memories
    WHERE company_id = $1 AND agent_id IS NOT NULL
      AND COALESCE(ts_created, created_at) > NOW() - INTERVAL '1 hour' * $2
  `, [COMPANY, boundedWindow]);

  const results = [];
  for (const { agent_id } of agents.rows) {
    results.push(await fingerprintAgent(agent_id, boundedWindow, COMPANY));
  }
  return results.sort((a, b) => (b.cov || 0) - (a.cov || 0));
}

export async function runTemporalFingerprintAudit({
  companyId = COMPANY,
  windowHours = 24,
} = {}) {
  const boundedWindow = Math.max(1, Math.min(2160, Number.parseInt(windowHours, 10) || 24));
  const agents = await query(`
    SELECT DISTINCT agent_id FROM aimos_memories
    WHERE company_id = $1 AND agent_id IS NOT NULL
      AND COALESCE(ts_created, created_at) > NOW() - INTERVAL '1 hour' * $2
  `, [companyId, boundedWindow]);

  const results = [];
  for (const { agent_id } of agents.rows) {
    results.push(await fingerprintAgent(agent_id, boundedWindow, companyId));
  }
  results.sort((a, b) => (b.cov || 0) - (a.cov || 0));

  const summary = {
    windowHours: boundedWindow,
    checkedAgents: results.length,
    humanInfluenced: results.filter((row) => row.classification === 'human_influenced').length,
    autonomousHeartbeat: results.filter((row) => row.classification === 'autonomous_heartbeat').length,
    mixedSignal: results.filter((row) => row.classification === 'mixed_signal').length,
    insufficientData: results.filter((row) => row.classification === 'insufficient_data').length,
    farmingDetected: results.filter((row) => row.farming_detected).length,
  };

  const eventId = await logEvent(companyId, 'temporal-fingerprinter', 'temporal_fingerprint_audit', `temporal_fingerprint:${Date.now()}`, {
    reasoning: `Temporal fingerprinter audited ${summary.checkedAgents} agent memory-save stream(s) across ${boundedWindow}h using CoV = sigma(intervals)/mean(intervals).`,
    source_knowledge: 'Moltbook Illusion — CoV temporal authenticity detection, chi-square=551.76, p<10^-117',
    summary,
    results,
    diagnostic_only: true,
    ranking_math_changed: false,
    canonical_memory_changed: false,
  });

  return {
    ...summary,
    results,
    eventId,
    diagnostic_only: true,
    canonical_memory_changed: false,
  };
}
