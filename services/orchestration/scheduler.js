// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: server.js
// → Calls: cron (node-cron), db (connection.js), x-automation.js (dynamic)
// Pipeline: SCHEDULER | Position: Cron engine (job scheduling)
//
// SERVICE CONNECTION GUIDE:
// 1. ↔ Interacts with: heartbeat.js (Triggers pulse, then triggers Reviewer-LLM evaluation)
// 2. ↔ Interacts with: agent-runner.js (Dispatches autonomous heartbeat & briefing tasks)
// 3. → Pushes to: aimos_events (Logs bottlenecks, loop-stuck events, and weekly assessments)
// 4. Public core scheduling starts only after the signed Genesis Guide corpus
//    matches the shipped deterministic manifest.
//
// LOGIC GUIDE (Heartbeat Fix): The runReviewerHeartbeat function MUST allow aimos_recall.
// This is required to satisfy the Knowledge Gate evidence acquisition mandate.
// ─────────────────────────────────────────────────────────────────────────────
import cron from 'node-cron';
import { createHash, randomUUID } from 'crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { agentPool, query, withTransaction } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';
import { logEvent, readVerifiedEventHistory } from '../observe/event-ledger.js';
import { verifyPayloadSigWithContext } from '../security/agent-identity.js';
import { contentHash } from '../security/identity-chain.js';
import { verifyMutationHash } from '../security/memory-provenance.js';
import { verifyGenesisManifest } from '../../scripts/verify-genesis-manifest.mjs';

const COMPANY = 'hom';
const CRON_TIMEZONE = 'UTC';
const scheduledJobs = new Map();
const LOOP_CHECKER_JOB_ID = '__loop_checker__';
const LOOP_CHECKER_CRON = '*/5 * * * *';
const BOTTLENECK_SCAN_JOB_ID = '__bottleneck_scan__';
const BOTTLENECK_SCAN_CRON = '0 * * * *';
const WEEKLY_ASSESSMENT_JOB_ID = '__weekly_assessment__';
const WEEKLY_ASSESSMENT_CRON = '0 2 * * 0';
const WEEKLY_AUDIT_JOB_ID = '__weekly_audit__';
const WEEKLY_AUDIT_CRON = '0 3 * * 0';
const NIGHTLY_DREAM_JOB_ID = '__nightly_dream__';
const NIGHTLY_DREAM_CRON = '0 2 * * *';
const BRAIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCHEDULE_EVENT_SCHEMA = 'hom.aimos.schedule/v1';
export const AGENTICCACHE_SOURCE = 'AGENTICCACHE: Cache-Driven Asynchronous Planning for Embodied AI Agents';
export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';

function normalizeText(value) {
  return String(value || '').trim();
}

function contentSha256(value) {
  return createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function parseBodyJson(value) {
  if (value && typeof value === 'object') return value;
  try {
    return JSON.parse(String(value || ''));
  } catch {
    return null;
  }
}

/**
 * Prove the scheduler may start against this installation.
 *
 * The disk Guide must match the public manifest, the housekeeper system identity
 * must exist, and every manifest file must have a signed provenance body that
 * commits to the same corpus root/version. A failed proof prevents ALL scheduler
 * registration; server.js awaits startScheduler(), so downstream background
 * watchers do not start either.
 */
export async function verifySchedulerGenesisReadiness({ queryFn = null, brainRoot = BRAIN_ROOT } = {}) {
  let manifest;
  try {
    manifest = verifyGenesisManifest({ brainRoot });
  } catch (error) {
    return { ok: false, reason: 'genesis_manifest_invalid', detail: error.message };
  }

  const expectedKeys = manifest.files.map((record) => `guide:housekeeper:${path.basename(record.path, '.md')}`);
  let housekeeperResult;
  let corpusResult;
  try {
    const readReadiness = async (runQuery) => {
      const identity = await runQuery(
        `SELECT agent_id, pubkey
          FROM agent_identity
          WHERE agent_id = 'housekeeper'
            AND NOT EXISTS (
              SELECT 1 FROM aimos_agent_revocation_events revocation
               WHERE revocation.agent_id = agent_identity.agent_id
                 AND revocation.agent_valid_from = agent_identity.valid_from
            )
          ORDER BY valid_from DESC
          LIMIT 1`
      );
      const corpus = await runQuery(
        `SELECT m.key, m.value,
                p.agent_id, p.body_json, p.content_hash, p.mutation_hash,
                p.prev_mutation_hash, p.ts_signed, p.nonce, p.sig
           FROM aimos_memories m
           JOIN aimos_memory_provenance p ON p.memory_id = m.id
          WHERE m.company_id = $2
            AND m.source = 'guide:genesis-install'
            AND m.key = ANY($1::text[])
            AND p.backfilled = false`,
        [expectedKeys, COMPANY]
      );
      return [identity, corpus];
    };
    [housekeeperResult, corpusResult] = queryFn
      ? await readReadiness(queryFn)
      : await withTransaction(
        (client) => readReadiness(client.query.bind(client)),
        { restricted: true, clientId: COMPANY, agentId: 'housekeeper' },
      );
  } catch (error) {
    return { ok: false, reason: 'genesis_readiness_query_failed', detail: error.message };
  }

  if (!housekeeperResult?.rows?.length) {
    return { ok: false, reason: 'housekeeper_system_identity_missing' };
  }
  const housekeeperPubkey = housekeeperResult.rows[0].pubkey;

  const rows = Array.isArray(corpusResult?.rows) ? corpusResult.rows : [];
  const missing = [];
  for (const record of manifest.files) {
    const key = `guide:housekeeper:${path.basename(record.path, '.md')}`;
    const matched = rows.some((row) => {
      const body = parseBodyJson(row.body_json);
      const signedTs = Number(row.ts_signed);
      const storedSignature = Buffer.isBuffer(row.sig) ? row.sig.toString('base64url') : '';
      const computedContentHash = body ? contentHash(body) : null;
      const signatureCheck = body
        ? verifyPayloadSigWithContext(
          housekeeperPubkey,
          body,
          'POST',
          '/aimos/save',
          String(row.nonce || ''),
          signedTs,
          storedSignature,
          { skewSeconds: 0, nowFn: () => signedTs }
        )
        : { valid: false };
      return row.key === key
        && contentSha256(row.value) === record.sha256
        && row.agent_id === 'housekeeper'
        && signatureCheck.valid === true
        && Buffer.isBuffer(row.content_hash)
        && computedContentHash.equals(row.content_hash)
        && verifyMutationHash(
          row.content_hash,
          Buffer.isBuffer(row.prev_mutation_hash) ? row.prev_mutation_hash : null,
          String(row.nonce || ''),
          signedTs,
          row.mutation_hash
        )
        && body?.genesis_manifest_schema === manifest.schema
        && Number(body?.genesis_manifest_version) === manifest.version
        && body?.genesis_corpus_root === manifest.corpusRoot
        && body?.genesis_file_path === record.path
        && body?.genesis_file_sha256 === record.sha256
        && Number(body?.genesis_file_bytes) === record.bytes;
    });
    if (!matched) missing.push(key);
  }

  if (missing.length > 0) {
    return {
      ok: false,
      reason: 'genesis_corpus_incomplete_or_unbound',
      missing,
      expected: manifest.files.length,
      verified: manifest.files.length - missing.length,
      corpusRoot: manifest.corpusRoot,
    };
  }

  return {
    ok: true,
    manifestVersion: manifest.version,
    corpusRoot: manifest.corpusRoot,
    guideMemories: manifest.files.length,
  };
}

// ─── OVERLAP PROTECTION (defect 7) ────────────────────────────────────────────
// Postgres session-level advisory lock. Survives process restarts and works
// across replicas. If the previous run of the same jobKey is still in flight,
// pg_try_advisory_lock returns false and we skip with a warning rather than
// re-entering concurrently. The lock is session-scoped, so we MUST unlock on the
// same dedicated client before releasing it back to the pool — otherwise the
// lock leaks into a pooled connection.
async function withJobLock(jobKey, fn) {
  let client;
  try {
    client = await agentPool.connect();
  } catch (err) {
    // Authority and overlap protection are unavailable. Running anyway could
    // duplicate arbitrary autonomous side effects, so the housekeeper skips.
    console.warn('[scheduler] advisory-lock authority unavailable; job skipped:', err?.message || String(err), { jobKey });
    return { skipped: true, reason: 'scheduler_lock_authority_unavailable' };
  }
  try {
    const { rows } = await client.query('SELECT pg_try_advisory_lock(hashtext($1)) AS got', [jobKey]);
    if (!rows[0]?.got) {
      console.warn('[scheduler] previous run still in flight — skipping', { jobKey });
      return { skipped: true };
    }
    try {
      return await fn();
    } finally {
      await client.query('SELECT pg_advisory_unlock(hashtext($1))', [jobKey]).catch(
        e => console.warn('[scheduler] advisory-unlock failed', { jobKey, err: e?.message })
      );
    }
  } finally {
    client.release();
  }
}

function rowToSchedule(row) {
  return {
    id: row.id,
    companyId: row.company_id,
    label: row.label,
    cronExpression: row.cron_expression,
    taskDescription: row.task_description,
    agentId: row.agent_id,
    isActive: !!row.is_active,
    lastRunAt: row.last_run_at || null,
    lastStatus: row.last_status || null,
    lastError: row.last_error || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function ensureSchedulerSchema() {
  const result = await withTransaction(
    (client) => client.query(`WITH required(table_name, columns) AS (
       VALUES
         ('scheduled_tasks', ARRAY[
           'id','company_id','label','cron_expression','task_description','agent_id',
           'is_active','last_run_at','last_status','last_error','created_at','updated_at'
         ]::text[])
     )
     SELECT required.table_name,
            ARRAY(
              SELECT required_column.column_name
                FROM unnest(required.columns) AS required_column(column_name)
               WHERE NOT EXISTS (
                 SELECT 1 FROM information_schema.columns actual
                  WHERE actual.table_schema = current_schema()
                    AND actual.table_name = required.table_name
                    AND actual.column_name = required_column.column_name
               )
            ) AS missing_columns
       FROM required`),
    { restricted: true, clientId: COMPANY, agentId: 'housekeeper' },
  );
  const missing = result.rows.filter((row) => row.missing_columns?.length);
  if (missing.length) {
    const error = new Error(`MIGRATION_SCHEMA_MISSING:${missing.map((row) => `${row.table_name}[${row.missing_columns.join(',')}]`).join(';')}`);
    error.code = 'MIGRATION_SCHEMA_MISSING';
    throw error;
  }
}

// Aladdin retention: no tiering, no expiry, no decay, no maintenance needed.
// The former memory-maintenance job was a pure no-op (`// No-op. Everything is
// long-term.`) yet was registered on a */30 cron — a wasted timer slot every
// 30 minutes. Both the stub and its registration were removed (defect 14). If a
// real maintenance job is ever needed, register it explicitly here.

async function runLoopChecker() {
  try {
    const stuck = await query(
      `SELECT * FROM session_lanes
       WHERE run_status = 'running'
         AND last_run_at < NOW() - INTERVAL '5 minutes'
         AND company_id = $1`,
      [COMPANY]
    );

    const stuckRows = stuck.rows || [];

    for (const lane of stuckRows) {
      const runningFor = Math.round(
        (Date.now() - new Date(lane.last_run_at).getTime()) / 1000
      );

      await query(
        `UPDATE session_lanes
         SET run_status = 'stuck',
             updated_at = NOW()
         WHERE company_id = $1 AND session_key = $2`,
        [lane.company_id, lane.session_key]
      );

      await logEvent(
        COMPANY,
        'system',
        'loop_checker_stuck',
        LOOP_CHECKER_JOB_ID,
        {
          session_key: lane.session_key,
          running_for_seconds: runningFor
        }
      );
    }

    console.log(`[scheduler] Loop checker: ${stuckRows.length} stuck lane(s) detected and marked`);
  } catch (error) {
    console.warn('[scheduler] Loop checker failed:', error?.message || String(error));
  }
}

export async function runBottleneckScan() {
  try {
    const errorAgents = await query(
      `SELECT agent_id, COUNT(*) as error_count
       FROM aimos_events
       WHERE company_id = $1
         AND ts > NOW() - INTERVAL '1 hour'
         AND (operation ILIKE '%error%' OR operation ILIKE '%fail%')
       GROUP BY agent_id
       ORDER BY error_count DESC
       LIMIT 10`,
      [COMPANY]
    );

    const latencyAgents = await query(
      `SELECT agent_id, AVG(gap_seconds) AS avg_seconds_between_events FROM (
         SELECT agent_id, EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (PARTITION BY agent_id ORDER BY ts))) AS gap_seconds
         FROM aimos_events
         WHERE company_id = $1 AND ts > NOW() - INTERVAL '1 hour'
       ) sub
       WHERE gap_seconds IS NOT NULL
       GROUP BY agent_id
       ORDER BY avg_seconds_between_events DESC NULLS LAST
       LIMIT 10`,
      [COMPANY]
    );

    const topErrorAgents = (errorAgents.rows || []).map(r => ({
      agent_id: r.agent_id,
      error_count: parseInt(r.error_count, 10)
    }));

    const slowestAgents = (latencyAgents.rows || []).map(r => ({
      agent_id: r.agent_id,
      avg_seconds_between_events: parseFloat(r.avg_seconds_between_events) || null
    }));

    // Theory of Constraints (Goldratt via Phoenix Project): identify THE constraint
    // The agent with the highest error count OR slowest throughput is the system bottleneck.
    // All optimization should focus here first — improving non-constraints yields zero system improvement.
    const constraint = topErrorAgents[0] || slowestAgents[0] || null;
    const constraintId = constraint ? constraint.agent_id : null;

    // WIP check: count agents with active runs (Four Categories of Work — unplanned work ratio)
    const wipResult = await query(
      `SELECT COUNT(DISTINCT agent_id) as active_agents FROM aimos_events
       WHERE company_id = $1 AND operation = 'agent_run_metric' AND ts > NOW() - INTERVAL '5 minutes'`,
      [COMPANY]
    );
    const currentWip = parseInt((wipResult.rows[0] || {}).active_agents, 10) || 0;

    await logEvent(
      COMPANY,
      'system',
      'bottleneck_scan',
      BOTTLENECK_SCAN_JOB_ID,
      {
        top_error_agents: topErrorAgents,
        slowest_agents: slowestAgents,
        system_constraint: constraintId,
        current_wip: currentWip,
        constraint_recommendation: constraintId
          ? `Focus optimization on agent '${constraintId}' — this is the system bottleneck. Improving other agents yields zero system throughput improvement.`
          : 'No constraint identified — system is flowing.'
      }
    );

    console.log(
      `[scheduler] Bottleneck scan: ${topErrorAgents.length} error(s), ${slowestAgents.length} latency, constraint=${constraintId || 'none'}, WIP=${currentWip}`
    );
  } catch (error) {
    console.warn('[scheduler] Bottleneck scan failed:', error?.message || String(error));
  }
}

async function runWeeklyAssessment() {
  try {
    const totalResult = await query(
      `SELECT COUNT(*) as total FROM aimos_events WHERE company_id = $1 AND ts > NOW() - INTERVAL '7 days'`,
      [COMPANY]
    );

    const byOperation = await query(
      `SELECT operation, COUNT(*) as cnt
       FROM aimos_events
       WHERE company_id = $1 AND ts > NOW() - INTERVAL '7 days'
       GROUP BY operation
       ORDER BY cnt DESC
       LIMIT 20`,
      [COMPANY]
    );

    const uniqueAgents = await query(
      `SELECT COUNT(DISTINCT agent_id) as cnt FROM aimos_events WHERE company_id = $1 AND ts > NOW() - INTERVAL '7 days'`,
      [COMPANY]
    );

    const corrections = await query(
      `SELECT COUNT(*) as cnt FROM aimos_events WHERE company_id = $1 AND ts > NOW() - INTERVAL '7 days' AND operation = 'correction'`,
      [COMPANY]
    );

    const totalEvents = parseInt(totalResult.rows[0]?.total || 0, 10);
    const totalCorrections = parseInt(corrections.rows[0]?.cnt || 0, 10);
    const healthScore =
      totalEvents > 0 ? Math.round(100 * (1 - totalCorrections / totalEvents)) : 0;

    const weekLabel = new Date().toISOString().slice(0, 10);
    const report = {
      week_ending: weekLabel,
      total_events: totalEvents,
      unique_agents_active: parseInt(uniqueAgents.rows[0]?.cnt || 0, 10),
      corrections: totalCorrections,
      health_score: healthScore,
      by_operation: (byOperation.rows || []).map(r => ({
        operation: r.operation,
        count: parseInt(r.cnt, 10)
      }))
    };

    await persistMemory({
      company_id: COMPANY,
      agent_id: 'system',
      memory_type: 'weekly_assessment',
      key: `weekly_assessment_${weekLabel}`,
      value: JSON.stringify(report),
      scope: 'global',
      clearance_level: 5,
      memory_tier: 'long-term',
      mutation_authority: 'housekeeper',
    });

    await logEvent(
      COMPANY,
      'system',
      'weekly_assessment',
      WEEKLY_ASSESSMENT_JOB_ID,
      { health_score: healthScore, total_events: totalEvents, week_ending: weekLabel }
    );

    console.log(
      `[scheduler] Weekly assessment: health_score=${healthScore}, total_events=${totalEvents}, corrections=${totalCorrections}`
    );
  } catch (error) {
    console.warn('[scheduler] Weekly assessment failed:', error?.message || String(error));
  }
}

async function runWeeklyAudit() {
  try {
    const memoryDist = await query(
      `SELECT memory_type, COUNT(*) as cnt, COUNT(*) as active
       FROM aimos_memories
       WHERE company_id = $1
       GROUP BY memory_type`,
      [COMPANY]
    );

    const recentEvents = await query(
      `SELECT COUNT(*) as cnt FROM aimos_events WHERE company_id = $1 AND ts > NOW() - INTERVAL '7 days' AND operation = 'event_log'`,
      [COMPANY]
    );

    const activeLoops = await query(
      `SELECT COUNT(*) as cnt FROM aimos_memories WHERE company_id = $1 AND memory_type = 'active_loop'`,
      [COMPANY]
    );

    const proceduralSkills = await query(
      `SELECT COUNT(*) as cnt FROM procedural_skills WHERE company_id = $1`,
      [COMPANY]
    ).catch(() => ({ rows: [{ cnt: 0 }] }));

    const memoryTypes = (memoryDist.rows || []).map(r => r.memory_type);
    const stuckLanes = await query(
      `SELECT COUNT(*) as cnt FROM session_lanes WHERE company_id = $1 AND run_status = 'stuck'`,
      [COMPANY]
    ).catch(() => ({ rows: [{ cnt: 0 }] }));

    const hasEventLog = parseInt(recentEvents.rows[0]?.cnt || 0, 10) > 0;
    const hasActiveLoops = parseInt(activeLoops.rows[0]?.cnt || 0, 10) > 0;
    const hasProceduralSkills = parseInt(proceduralSkills.rows[0]?.cnt || 0, 10) > 0;
    const hasDistributedMemory = memoryTypes.length > 3;
    const noStuckLanes = parseInt(stuckLanes.rows[0]?.cnt || 0, 10) === 0;

    const complianceScore =
      (hasEventLog ? 20 : 0) +
      (hasActiveLoops ? 20 : 0) +
      (hasProceduralSkills ? 20 : 0) +
      (hasDistributedMemory ? 20 : 0) +
      (noStuckLanes ? 20 : 0);

    const auditLabel = new Date().toISOString().slice(0, 10);
    const auditReport = {
      audit_date: auditLabel,
      compliance_score: complianceScore,
      checks: {
        has_event_log_last_7_days: hasEventLog,
        has_active_loops: hasActiveLoops,
        has_procedural_skills: hasProceduralSkills,
        memory_types_distributed: hasDistributedMemory,
        no_stuck_lanes: noStuckLanes
      },
      memory_distribution: (memoryDist.rows || []).map(r => ({
        memory_type: r.memory_type,
        total: parseInt(r.cnt, 10),
        active: parseInt(r.active, 10)
      }))
    };

    await persistMemory({
      company_id: COMPANY,
      agent_id: 'system',
      memory_type: 'audit_report',
      key: `audit_${auditLabel}`,
      value: JSON.stringify(auditReport),
      scope: 'global',
      clearance_level: 5,
      memory_tier: 'long-term',
      mutation_authority: 'housekeeper',
    });

    await logEvent(
      COMPANY,
      'system',
      'weekly_audit',
      WEEKLY_AUDIT_JOB_ID,
      { compliance_score: complianceScore, audit_date: auditLabel }
    );

    console.log(`[scheduler] Weekly audit: compliance_score=${complianceScore}/100, date=${auditLabel}`);
  } catch (error) {
    console.warn('[scheduler] Weekly audit failed:', error?.message || String(error));
  }
}

function scheduleTimestamp(value) {
  return value == null ? null : new Date(value).toISOString();
}

function parseEventMetadata(row) {
  return typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
}

async function readScheduleProjections(client) {
  // A pg client owns one protocol stream. Concurrent queries on the same
  // transaction client are deprecated and can reorder unexpectedly; preserve
  // the signed projection snapshot with explicit sequential reads.
  const projectionResult = await client.query(
    `SELECT id, company_id, label, cron_expression, task_description, agent_id,
            is_active, last_run_at, last_status, last_error, created_at, updated_at
       FROM scheduled_tasks
      WHERE company_id = $1
      ORDER BY created_at ASC`,
    [COMPANY],
  );

  // No retained projection means there is nothing the autonomous housekeeper
  // may activate. Avoid reading and verifying the unrelated universal event
  // stream in that exact state; as soon as one schedule projection exists,
  // every schedule event is still read and cryptographically verified below.
  if (projectionResult.rows.length === 0) return [];

  const eventRows = await readVerifiedEventHistory(COMPANY, { client });

  const creationById = new Map();
  const statusById = new Map();
  for (const event of eventRows) {
    if (!String(event.operation || '').startsWith('schedule_')) continue;
    const metadata = parseEventMetadata(event);
    if (metadata?.schema !== SCHEDULE_EVENT_SCHEMA) continue;
    const scheduleId = String(metadata.schedule_id || '');
    if (!scheduleId || String(event.key || '') !== scheduleId) {
      throw new Error('schedule_event_key_mismatch');
    }
    if (event.operation === 'schedule_created') {
      if (creationById.has(scheduleId)) throw new Error('schedule_creation_not_unique');
      creationById.set(scheduleId, { event, metadata });
    } else if (
      event.operation === 'schedule_run_reserved'
      || event.operation === 'schedule_run_completed'
      || event.operation === 'schedule_run_failed'
      || event.operation === 'schedule_invalid'
    ) {
      statusById.set(scheduleId, { event, metadata });
    }
  }

  return projectionResult.rows.map((row) => {
    const created = creationById.get(String(row.id));
    if (!created) return { ...rowToSchedule(row), verified: false, proofError: 'schedule_creation_proof_missing' };
    const creation = created.metadata;
    const latestStatus = statusById.get(String(row.id))?.metadata || null;
    const expectedLastRunAt = latestStatus?.last_run_at || null;
    const expectedLastStatus = latestStatus?.last_status || null;
    const expectedLastError = latestStatus?.last_error || null;
    const staticFieldsMatch = creation.company_id === row.company_id
      && creation.label === row.label
      && creation.cron_expression === row.cron_expression
      && creation.task_description === row.task_description
      && creation.agent_id === row.agent_id
      && creation.is_active === true
      && row.is_active === true
      && scheduleTimestamp(creation.created_at) === scheduleTimestamp(row.created_at);
    const statusFieldsMatch = scheduleTimestamp(expectedLastRunAt) === scheduleTimestamp(row.last_run_at)
      && expectedLastStatus === (row.last_status || null)
      && expectedLastError === (row.last_error || null)
      && scheduleTimestamp(latestStatus?.updated_at || creation.created_at) === scheduleTimestamp(row.updated_at);
    if (!staticFieldsMatch || !statusFieldsMatch) {
      return { ...rowToSchedule(row), verified: false, proofError: 'schedule_projection_proof_mismatch' };
    }
    return {
      ...rowToSchedule(row),
      verified: true,
      creationEventId: created.event.id,
      creationMutationHash: Buffer.from(created.event.mutation_hash).toString('hex'),
      statusEventId: statusById.get(String(row.id))?.event?.id || null,
      statusMutationHash: statusById.get(String(row.id))?.event?.mutation_hash
        ? Buffer.from(statusById.get(String(row.id)).event.mutation_hash).toString('hex')
        : null,
      proofError: null,
    };
  });
}

async function markScheduleStatus(schedule, { operation, status, error = null } = {}) {
  const allowedOperations = new Set([
    'schedule_run_reserved',
    'schedule_run_completed',
    'schedule_run_failed',
    'schedule_invalid',
  ]);
  if (!allowedOperations.has(operation)) throw new Error('schedule_status_operation_invalid');
  const occurredAt = new Date();
  return withTransaction(async (client) => {
    const verified = (await readScheduleProjections(client)).find((item) => item.id === schedule.id);
    if (!verified?.verified) throw new Error(verified?.proofError || 'schedule_not_verified');
    const updated = await client.query(
      `UPDATE scheduled_tasks
          SET last_run_at = $3,
              last_status = $4,
              last_error = $5,
              updated_at = $3
        WHERE id = $1 AND company_id = $2
        RETURNING id`,
      [schedule.id, COMPANY, occurredAt, status || null, error],
    );
    if (updated.rowCount !== 1) throw new Error('schedule_projection_missing');
    return logEvent(COMPANY, schedule.agentId, operation, schedule.id, {
      schema: SCHEDULE_EVENT_SCHEMA,
      schedule_id: schedule.id,
      last_run_at: occurredAt.toISOString(),
      last_status: status || null,
      last_error: error,
      updated_at: occurredAt.toISOString(),
      reasoning: `housekeeper recorded ${operation} for retained schedule ${schedule.id}`,
    }, null, { client, returnReceipt: true });
  }, { restricted: true, clientId: COMPANY, agentId: 'housekeeper' });
}

async function executeScheduledTask(schedule) {
  const reservationReceipt = await markScheduleStatus(schedule, {
    operation: 'schedule_run_reserved',
    status: 'running',
    error: null,
  });
  try {
    let result;
    if (schedule.label.startsWith('X ')) {
      const { runXAutoEngage, runXDailyPosts, runXDailySummary } = await import('../integrations/x-automation.js');
      if (schedule.label.includes('Auto-Engage')) result = await runXAutoEngage();
      else if (schedule.label.includes('Daily Posts')) result = await runXDailyPosts();
      else if (schedule.label.includes('Daily Summary')) result = await runXDailySummary();
    }
    if (result === undefined) {
      const { runAgent } = await import('./agent-runner.js');
      result = await runAgent(schedule.agentId, schedule.taskDescription, {
        skipAimos: false,
        autonomous: true,
        securityParentEventId: reservationReceipt.event_id,
      });
    }
    await markScheduleStatus(schedule, {
      operation: 'schedule_run_completed',
      status: 'success',
      error: null,
    });
    return result;
  } catch (error) {
    await markScheduleStatus(schedule, {
      operation: 'schedule_run_failed',
      status: 'failed',
      error: error?.message || String(error)
    });
    throw error;
  }
}

function unschedule(id) {
  const existing = scheduledJobs.get(id);
  if (existing) {
    existing.stop();
    scheduledJobs.delete(id);
  }
}

function scheduleInMemory(schedule) {
  unschedule(schedule.id);
  const task = cron.schedule(
    schedule.cronExpression,
    () => {
      void withJobLock(`scheduled_task:${schedule.id}`, () => executeScheduledTask(schedule))
        .catch(e => console.warn('[scheduler] scheduled task run failed', { id: schedule.id, err: e?.message }));
    },
    {
      timezone: CRON_TIMEZONE
    }
  );
  scheduledJobs.set(schedule.id, task);
}

export function buildSchedulerRuntimeDiagnostics({
  scheduledCount = scheduledJobs.size,
  invalidCronCount = 0,
  runningCount = 0,
  failedLastHour = 0,
  prefetchableTasks = [],
} = {}) {
  const total = Math.max(0, Number(scheduledCount || 0));
  const failures = Math.max(0, Number(failedLastHour || 0));
  const invalid = Math.max(0, Number(invalidCronCount || 0));
  const running = Math.max(0, Number(runningCount || 0));
  const taskRows = (Array.isArray(prefetchableTasks) ? prefetchableTasks : [])
    .map((task, index) => ({
      key: String(task?.id || task?.label || `task_${index + 1}`).slice(0, 96),
      label: String(task?.label || task?.taskDescription || '').slice(0, 160),
      expected_access_at: task?.nextRunAt || null,
    }))
    .filter((row) => row.key);

  return {
    status: failures || invalid ? 'watch' : 'stable',
    source_papers: [AGENTICCACHE_SOURCE, AGENTPULSE_SOURCE],
    diagnostic_only: true,
    scheduler_state: {
      scheduled_count: total,
      running_count: running,
      invalid_cron_count: invalid,
      failed_last_hour: failures,
    },
    asynchronous_planning_cache: {
      prefetchable_task_count: taskRows.length,
      task_hints: taskRows.slice(0, 8),
      cache_scope: 'ephemeral_scheduler_runtime',
      canonical_memory_eviction: false,
    },
    action_contract: {
      jobs_started_by_diagnostic: false,
      schedule_mutated: false,
      policy_changed: false,
    },
  };
}

export async function startScheduler() {
  const genesisReadiness = await verifySchedulerGenesisReadiness();
  if (!genesisReadiness.ok) {
    const error = new Error(`scheduler_genesis_not_ready:${genesisReadiness.reason}`);
    error.code = 'SCHEDULER_GENESIS_NOT_READY';
    error.readiness = genesisReadiness;
    throw error;
  }
  console.log(`[scheduler] Genesis ready: manifest v${genesisReadiness.manifestVersion}, ${genesisReadiness.guideMemories} Guide memories, root=${genesisReadiness.corpusRoot}`);

  await ensureSchedulerSchema();
  const schedules = await withTransaction(
    (client) => readScheduleProjections(client),
    { restricted: true, clientId: COMPANY, agentId: 'housekeeper' },
  );

  for (const schedule of schedules) {
    if (!schedule.verified || !schedule.isActive) {
      console.warn('[scheduler] retained schedule not activated because its authority is unverified', {
        id: schedule.id,
        reason: schedule.proofError || 'schedule_inactive',
      });
      continue;
    }
    if (!cron.validate(schedule.cronExpression)) {
      await markScheduleStatus(schedule, {
        operation: 'schedule_invalid',
        status: 'invalid_cron',
        error: `Invalid cron expression: ${schedule.cronExpression}`
      });
      continue;
    }
    scheduleInMemory(schedule);
  }

  // NOTE: the no-op memory-maintenance */30 cron was removed (defect 14) — it
  // was a pure no-op stub burning a timer slot every 30 minutes.

  if (!scheduledJobs.has(LOOP_CHECKER_JOB_ID)) {
    const loopCheckerTask = cron.schedule(
      LOOP_CHECKER_CRON,
      () => {
        void withJobLock(LOOP_CHECKER_JOB_ID, () => runLoopChecker())
          .catch(e => console.warn('[scheduler] loop checker failed', e?.message));
      },
      { timezone: CRON_TIMEZONE }
    );
    scheduledJobs.set(LOOP_CHECKER_JOB_ID, loopCheckerTask);
  }

  // System heartbeat — replaces old runReviewerHeartbeat() that burned LLM tokens on kimi
  // New heartbeat: zero LLM calls, 6 DB/process checks, saves to Aimos
  if (!scheduledJobs.has('__system_heartbeat__')) {
    const heartbeatTask = cron.schedule(
      '*/30 * * * *',
      () => {
        void withJobLock('__system_heartbeat__', async () => {
          const { runHeartbeat } = await import('../../jobs/heartbeat.js');
          await runHeartbeat(COMPANY);
        }).catch(async (err) => {
          console.warn('[scheduler] System heartbeat failed:', err?.message || String(err));
          // Defect 15: a persistently failing heartbeat must be LOUD. A silent
          // heartbeat is indistinguishable from "nothing to report" — the worst
          // failure mode for a health monitor. Emit a distinct, alertable event.
          await logEvent('hom', 'system', 'heartbeat_failed_alert', '__system_heartbeat__', {
            severity: 'alert',
            reason: 'heartbeat cron threw — health signal is going dark',
            error: err?.message || String(err),
            source_knowledge: 'scheduler.js heartbeat wrapper (defect 15) — monitor-goes-dark detection'
          }).catch(e => console.error('[scheduler] CRITICAL: heartbeat failed AND its alert failed to log', e?.message));
        });
      },
      { timezone: CRON_TIMEZONE }
    );
    scheduledJobs.set('__system_heartbeat__', heartbeatTask);
  }

  if (!scheduledJobs.has(BOTTLENECK_SCAN_JOB_ID)) {
    const bottleneckTask = cron.schedule(
      BOTTLENECK_SCAN_CRON,
      () => {
        void withJobLock(BOTTLENECK_SCAN_JOB_ID, () => runBottleneckScan())
          .catch(e => console.warn('[scheduler] bottleneck scan failed', e?.message));
      },
      { timezone: CRON_TIMEZONE }
    );
    scheduledJobs.set(BOTTLENECK_SCAN_JOB_ID, bottleneckTask);
  }

  if (!scheduledJobs.has(NIGHTLY_DREAM_JOB_ID)) {
    const nightlyDreamTask = cron.schedule(
      NIGHTLY_DREAM_CRON,
      () => {
        void withJobLock(NIGHTLY_DREAM_JOB_ID, async () => {
          const { runNightlyDream } = await import('../../jobs/nightly-dream.js');
          await runNightlyDream(COMPANY);
        }).catch((err) => console.warn('[scheduler] Nightly Dream failed:', err?.message || String(err)));
      },
      { timezone: CRON_TIMEZONE }
    );
    scheduledJobs.set(NIGHTLY_DREAM_JOB_ID, nightlyDreamTask);
  }

  if (!scheduledJobs.has(WEEKLY_ASSESSMENT_JOB_ID)) {
    const weeklyAssessmentTask = cron.schedule(
      WEEKLY_ASSESSMENT_CRON,
      () => {
        void withJobLock(WEEKLY_ASSESSMENT_JOB_ID, () => runWeeklyAssessment())
          .catch(e => console.warn('[scheduler] weekly assessment failed', e?.message));
      },
      { timezone: CRON_TIMEZONE }
    );
    scheduledJobs.set(WEEKLY_ASSESSMENT_JOB_ID, weeklyAssessmentTask);
  }

  if (!scheduledJobs.has(WEEKLY_AUDIT_JOB_ID)) {
    const weeklyAuditTask = cron.schedule(
      WEEKLY_AUDIT_CRON,
      () => {
        void withJobLock(WEEKLY_AUDIT_JOB_ID, () => runWeeklyAudit())
          .catch(e => console.warn('[scheduler] weekly audit failed', e?.message));
      },
      { timezone: CRON_TIMEZONE }
    );
    scheduledJobs.set(WEEKLY_AUDIT_JOB_ID, weeklyAuditTask);
  }

}

export function stopScheduler() {
  for (const task of scheduledJobs.values()) {
    task.stop();
  }
  scheduledJobs.clear();
}

export async function createScheduledTask({
  cronExpression,
  taskDescription,
  label,
  agentId,
  authority,
}) {
  const normalizedCron = normalizeText(cronExpression);
  const normalizedTask = normalizeText(taskDescription);
  const normalizedLabel = normalizeText(label);
  const normalizedAgentId = normalizeText(agentId);

  if (!normalizedCron) throw new Error('cron_expression is required');
  if (!normalizedTask) throw new Error('task_description is required');
  if (!normalizedLabel) throw new Error('label is required');
  if (!normalizedAgentId) throw new Error('agent_id is required');
  if (!cron.validate(normalizedCron)) throw new Error(`Invalid cron expression: ${normalizedCron}`);
  if (
    authority?.kind !== 'verified_request'
    || !authority.actorAgentId
    || !authority.actorValidFromIso
    || !authority.requestReceiptId
    || !authority.requestReceiptMutationHash
  ) {
    throw new Error('schedule_verified_request_authority_required');
  }

  await ensureSchedulerSchema();
  const id = randomUUID();
  const createdAt = new Date();
  const schedule = await withTransaction(
    async (client) => {
      const inserted = await client.query(
        `INSERT INTO scheduled_tasks
           (id, company_id, label, cron_expression, task_description, agent_id, is_active, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, true, $7, $7)
         RETURNING id, company_id, label, cron_expression, task_description, agent_id,
                   is_active, last_run_at, last_status, last_error, created_at, updated_at`,
        [id, COMPANY, normalizedLabel, normalizedCron, normalizedTask, normalizedAgentId, createdAt],
      );
      const eventReceipt = await logEvent(COMPANY, normalizedAgentId, 'schedule_created', id, {
        schema: SCHEDULE_EVENT_SCHEMA,
        schedule_id: id,
        company_id: COMPANY,
        label: normalizedLabel,
        cron_expression: normalizedCron,
        task_description: normalizedTask,
        agent_id: normalizedAgentId,
        is_active: true,
        created_at: createdAt.toISOString(),
        request_receipt_id: authority.requestReceiptId,
        request_receipt_mutation_hash: authority.requestReceiptMutationHash,
        reasoning: `verified actor ${authority.actorAgentId} delegated a retained autonomous schedule to ${normalizedAgentId}`,
      }, null, { client, authority, returnReceipt: true });
      return {
        ...rowToSchedule(inserted.rows[0]),
        verified: true,
        creationEventId: eventReceipt.event_id,
        creationMutationHash: eventReceipt.mutation_hash,
        statusEventId: null,
        statusMutationHash: null,
        proofError: null,
      };
    },
    { restricted: true, clientId: COMPANY, agentId: 'housekeeper' },
  );

  scheduleInMemory(schedule);
  return schedule;
}

export async function listScheduledTasks() {
  await ensureSchedulerSchema();
  const schedules = await withTransaction(
    (client) => readScheduleProjections(client),
    { restricted: true, clientId: COMPANY, agentId: 'housekeeper' },
  );
  return schedules.sort((left, right) => new Date(right.createdAt) - new Date(left.createdAt));
}
