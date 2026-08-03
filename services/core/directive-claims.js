/**
 * directive-claims.js — CEO Directive Execution Lease Management
 * Source: Distributed Systems (lease-based coordination), Raft consensus
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js (Directive endpoints)
 * 2. → Pulls from: aimos_directives (SQL state read)
 * 3. → Pushes to: directive_claims (Lease persistence)
 * 4. ↔ Interacts with: services/db/connection.js (Pool management)
 *
 * LOGIC GUIDE: Manages the lifecycle of CEO-issued directives.
 * Enforces execution leases to prevent agent collision on high-priority goals.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: aimos.js, agent-execution.js
// → Calls: db (connection.js)
// Pipeline: SAVE + AGENT_RUN | Position: Directive claim persistence
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from './runtime-config.js';
import { createHash, randomUUID } from 'node:crypto';
import { agentPool } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

function normalizeLeaseSeconds(value) {
  const n = Number(value || 120);
  if (!Number.isFinite(n)) return 120;
  return Math.min(Math.max(n, 15), 3600);
}

function toIso(date) {
  return new Date(date).toISOString();
}

async function claimSpecificDirectiveTx(client, {
  companyId,
  directiveId,
  agentId,
  runId,
  leaseSeconds,
  authority,
}) {
  const directive = await client.query(
    `SELECT id::text, company_id, agent_id, status
     FROM aimos_directives
     WHERE id = $1
       AND company_id = $2
       AND authority_event_id IS NOT NULL
     FOR UPDATE`,
    [directiveId, companyId]
  );

  if (!directive.rows.length) {
    return { claimed: false, reason: 'directive_not_found' };
  }

  const row = directive.rows[0];
  if (row.agent_id !== agentId) {
    return { claimed: false, reason: 'directive_assigned_to_other_agent' };
  }

  const claim = await client.query(
    `SELECT directive_id::text, claimed_by, lease_until
     FROM directive_claims
     WHERE directive_id = $1
     FOR UPDATE`,
    [directiveId]
  );

  if (claim.rows.length) {
    const activeLease = new Date(claim.rows[0].lease_until).getTime() > Date.now();
    if (activeLease && claim.rows[0].claimed_by !== agentId) {
      return { claimed: false, reason: 'directive_already_claimed', leaseUntil: claim.rows[0].lease_until };
    }
  }

  if (!['pending', 'running', 'in_progress'].includes(String(row.status || '').toLowerCase())) {
    return { claimed: false, reason: 'directive_not_claimable_status', status: row.status };
  }

  const leaseUntil = new Date(Date.now() + (leaseSeconds * 1000));
  const eventId = await logEvent(companyId, agentId, 'directive_claim_reserved', directiveId, {
    directive_id: directiveId,
    claimed_by: agentId,
    run_id: runId || null,
    lease_until: toIso(leaseUntil),
    reasoning: `The verified execution principal reserved directive ${directiveId} for one run.`,
    source_knowledge: 'directive-claims.js retained signed claim transition',
  }, null, { client, authority });

  await client.query(
    `INSERT INTO directive_claims
       (directive_id, company_id, claimed_by, run_id, lease_until, status, created_at, updated_at, last_event_id)
     VALUES ($1, $2, $3, $4, $5, 'claimed', NOW(), NOW(), $6)
     ON CONFLICT (directive_id) DO UPDATE
     SET company_id = EXCLUDED.company_id,
         claimed_by = EXCLUDED.claimed_by,
         run_id = EXCLUDED.run_id,
         lease_until = EXCLUDED.lease_until,
         status = 'claimed',
         updated_at = NOW(),
         last_event_id = EXCLUDED.last_event_id`,
    [directiveId, companyId, agentId, runId || null, leaseUntil, eventId]
  );

  await client.query(
    `UPDATE aimos_directives
     SET status = 'running',
         updated_at = NOW(),
         last_event_id = $2
     WHERE id = $1`,
    [directiveId, eventId]
  );

  return {
    claimed: true,
    directiveId,
    leaseUntil: toIso(leaseUntil),
    status: 'running'
  };
}

export async function createDirective({
  companyId = COMPANY,
  targetAgentId,
  goal,
  priority = 1,
  clearanceLevel = 5,
  authority,
} = {}) {
  if (!targetAgentId || !goal || !authority?.actorAgentId) throw new Error('verified_directive_authority_required');
  const directiveId = randomUUID();
  const client = await agentPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', companyId]);
    await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', authority.actorAgentId]);
    const eventId = await logEvent(companyId, targetAgentId, 'directive_created', directiveId, {
      directive_id: directiveId,
      target_agent_id: targetAgentId,
      goal_hash: createHash('sha256').update(String(goal), 'utf8').digest('hex'),
      priority: Number(priority),
      clearance_level: Number(clearanceLevel),
      reasoning: `Verified actor ${authority.actorAgentId} delegated retained directive ${directiveId} to ${targetAgentId}.`,
      source_knowledge: 'directive-claims.js retained signed directive creation',
    }, null, { client, authority });
    await client.query(
      `INSERT INTO aimos_directives
         (id, company_id, agent_id, goal, priority, clearance_level, status, authority_event_id, last_event_id)
       VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$7)`,
      [directiveId, companyId, targetAgentId, goal, Number(priority), Number(clearanceLevel), eventId],
    );
    await client.query('COMMIT');
    return { directiveId, eventId };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
}

export async function claimDirective({
  companyId = COMPANY,
  directiveId = null,
  agentId,
  runId = null,
  leaseSeconds = 120,
  authority = null,
}) {
  const safeLease = normalizeLeaseSeconds(leaseSeconds);
  if (!agentId) return { claimed: false, reason: 'agent_id_required' };

  const client = await agentPool.connect();
  try {
    await client.query('BEGIN');

    let targetDirectiveId = directiveId;
    if (!targetDirectiveId) {
      const next = await client.query(
        `SELECT id::text
         FROM aimos_directives
         WHERE company_id = $1
           AND agent_id = $2
           AND status = 'pending'
           AND authority_event_id IS NOT NULL
         ORDER BY priority DESC, created_at ASC
         LIMIT 1
         FOR UPDATE SKIP LOCKED`,
        [companyId, agentId]
      );

      if (!next.rows.length) {
        await client.query('ROLLBACK');
        return { claimed: false, reason: 'no_pending_directive' };
      }
      targetDirectiveId = next.rows[0].id;
    }

    const claimed = await claimSpecificDirectiveTx(client, {
      companyId,
      directiveId: targetDirectiveId,
      agentId,
      runId,
      leaseSeconds: safeLease,
      authority,
    });

    if (!claimed.claimed) {
      await client.query('ROLLBACK');
      return claimed;
    }

    await client.query('COMMIT');
    return claimed;
  } catch (error) {
    await client.query('ROLLBACK');
    return { claimed: false, reason: 'claim_error', error: error.message };
  } finally {
    client.release();
  }
}

export async function completeDirectiveClaim({
  companyId = COMPANY,
  directiveId,
  agentId,
  status = 'completed',
  resultData = null,
  authority = null,
}) {
  if (!directiveId) return false;

  const allowed = new Set(['completed', 'failed', 'running', 'pending']);
  const safeStatus = allowed.has(status) ? status : 'completed';

  const client = await agentPool.connect();
  try {
    await client.query('BEGIN');

    const eventId = await logEvent(companyId, agentId, 'directive_terminal', directiveId, {
      directive_id: directiveId,
      status: safeStatus,
      result_hash: resultData == null ? null : Buffer.from(JSON.stringify(resultData)).toString('base64url'),
      reasoning: `Directive ${directiveId} entered retained terminal projection ${safeStatus}.`,
      source_knowledge: 'directive-claims.js retained signed terminal transition',
    }, null, { client, authority });
    const claimUpdate = await client.query(
      `UPDATE directive_claims
       SET status = $3,
           updated_at = NOW(),
           lease_until = NOW(),
           last_event_id = $4
       WHERE directive_id = $1
         AND company_id = $2
         AND claimed_by = $5`,
      [directiveId, companyId, safeStatus, eventId, agentId]
    );
    if (claimUpdate.rowCount !== 1) throw new Error('directive_claim_not_owned');

    await client.query(
      `UPDATE aimos_directives
       SET status = $3,
           result = $4,
           updated_at = NOW(),
           last_event_id = $5
       WHERE id = $1
         AND company_id = $2`,
      [directiveId, companyId, safeStatus === 'running' ? 'running' : safeStatus,
       resultData == null ? null : JSON.stringify(resultData), eventId]
    );

    await client.query('COMMIT');
    return true;
  } catch {
    await client.query('ROLLBACK');
    return false;
  } finally {
    client.release();
  }
}
