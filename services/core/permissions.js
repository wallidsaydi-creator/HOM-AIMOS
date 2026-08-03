// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: aimos.js, agent-runner.js, write-validator.js
// Pipeline: Cross-cutting ACL | Position: Capability permission gating
// Additive Batch9 Wave2 authority: Security Considerations for AI Agents,
// Governing What You Cannot Observe, and The Midas Touch. Permission-scope
// diagnostics expose denied/privileged capabilities without automatic unlock.
// Cryptographic ordering: Traceability Through a Cryptographic Ledger, §3.3
// (one genesis, one successor per predecessor, topology-derived chain head).
// ─────────────────────────────────────────────────────────────────────────────
import { createHash } from 'node:crypto';
import { agentPool, withTransaction } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from './runtime-config.js';
import {
  canonicalJson,
  verifyStoredPayloadSigWithContext,
  verifyStoredPayloadSigWithEnvelopeClaims,
} from '../security/agent-identity.js';
import { contentHash } from '../security/identity-chain.js';

const DEFAULT_CAPS = [
  'internet',
  'memory_read',
  'memory_write',
  'delegate',
  'email',
  'shell',
  'files',
  'x',
  'youtube',
  'github',
  'n8n',
  'railway',
  'salesforce',
  'admin_override'
];

function normalizeCapabilities(values = []) {
  return (Array.isArray(values) ? values : Object.keys(values || {}))
    .map((capability) => String(capability || '').trim())
    .filter(Boolean);
}

export function buildPermissionScopeDiagnostics({
  requestedCapabilities = [],
  currentPermissions = null,
  requestedScope = '',
  actor = '',
} = {}) {
  const requested = normalizeCapabilities(requestedCapabilities);
  const perms = currentPermissions || defaultPermissions();
  const denied = requested.filter((capability) => perms[capability] !== true);
  const privileged = requested.filter((capability) => ['shell', 'files', 'memory_write', 'admin_override', 'email', 'github'].includes(capability));
  return {
    source_papers: [
      'Security Considerations for Artificial Intelligence Agents',
      'Governing What You Cannot Observe: Adaptive Runtime Governance for Autonomous AI',
      'The Midas Touch: Triggering LLMs with Hidden Intentions',
    ],
    diagnostic_only: true,
    actor: String(actor || ''),
    requested_scope: String(requestedScope || ''),
    requested_capabilities: requested,
    denied_capabilities: denied,
    privileged_capabilities: privileged,
    permission_status: denied.length ? 'requires_explicit_grant' : 'permitted_by_current_policy',
    automatic_tool_unlock_enabled: false,
    permission_policy_changed: false,
  };
}

export function defaultPermissions() {
  const out = {};
  DEFAULT_CAPS.forEach(c => { out[c] = false; });
  // No ambient grants. Every capability must have explicit authorization
  // evidence; authentication alone is never permission.
  return out;
}

export async function getPermissions(agentId, companyId) {
  const company = companyId || AIMOS_COMPANY_ID;
  const res = await withTransaction((client) => client.query(
    `WITH active_subject AS (
       SELECT valid_from
         FROM agent_identity
        WHERE agent_id = $2
          AND NOT EXISTS (
            SELECT 1 FROM aimos_agent_revocation_events revocation
             WHERE revocation.agent_id = agent_identity.agent_id
               AND revocation.agent_valid_from = agent_identity.valid_from
          )
        ORDER BY valid_from DESC
        LIMIT 1
     )
     SELECT event.*, actor.pubkey AS actor_pubkey
       FROM aimos_authorization_events event
       JOIN active_subject subject ON subject.valid_from = event.subject_valid_from
       JOIN agent_identity actor
         ON actor.agent_id = event.actor_agent_id
        AND actor.valid_from = event.actor_valid_from
      WHERE event.company_id = $1
        AND event.subject_agent_id = $2`,
    [company, agentId]
  ), {
    restricted: true,
    client_id: company,
    agent_id: agentId,
  }
  );
  const verification = verifyAuthorizationEventChain(res.rows, { companyId: company, agentId });
  const perms = defaultPermissions();
  for (const row of verification.latestByCapability.values()) {
    perms[row.capability] = row.allowed;
  }
  return perms;
}

function sameBuffer(left, right) {
  const a = Buffer.from(left || []);
  const b = Buffer.from(right || []);
  return a.length === b.length && a.equals(b);
}

function mutationHashKey(value, errorCode) {
  const hash = Buffer.from(value || []);
  if (hash.length !== 32) throw new Error(errorCode);
  return hash.toString('hex');
}

function resolveCapabilityTopology(rows) {
  const byMutationHash = new Map();
  const childByPredecessor = new Map();
  const referencedPredecessors = new Set();
  const genesis = [];

  for (const row of rows) {
    const mutationKey = mutationHashKey(row.mutation_hash, 'authorization_chain_hash_malformed');
    if (byMutationHash.has(mutationKey)) throw new Error('authorization_chain_mutation_duplicate');
    byMutationHash.set(mutationKey, row);
    if (!row.prev_mutation_hash) {
      genesis.push(row);
      continue;
    }
    const predecessorKey = mutationHashKey(row.prev_mutation_hash, 'authorization_chain_predecessor_malformed');
    referencedPredecessors.add(predecessorKey);
    const siblings = childByPredecessor.get(predecessorKey) || [];
    siblings.push(row);
    childByPredecessor.set(predecessorKey, siblings);
  }

  if (genesis.length !== 1) throw new Error('authorization_chain_genesis_invalid');
  for (const predecessorKey of referencedPredecessors) {
    if (!byMutationHash.has(predecessorKey)) throw new Error('authorization_chain_disconnected');
  }
  const heads = rows.filter((row) => !referencedPredecessors.has(
    mutationHashKey(row.mutation_hash, 'authorization_chain_hash_malformed')
  ));
  if (heads.length !== 1) throw new Error('authorization_chain_head_invalid');
  for (const children of childByPredecessor.values()) {
    if (children.length !== 1) throw new Error('authorization_chain_head_invalid');
  }

  const ordered = [];
  const visited = new Set();
  let current = genesis[0];
  while (current) {
    const mutationKey = mutationHashKey(current.mutation_hash, 'authorization_chain_hash_malformed');
    if (visited.has(mutationKey)) throw new Error('authorization_chain_cycle');
    visited.add(mutationKey);
    ordered.push(current);
    current = childByPredecessor.get(mutationKey)?.[0] || null;
  }
  if (ordered.length !== rows.length) throw new Error('authorization_chain_disconnected');
  if (ordered[ordered.length - 1] !== heads[0]) throw new Error('authorization_chain_head_invalid');
  return ordered;
}

export function verifyAuthorizationEventChain(rows = [], { companyId, agentId } = {}) {
  const rowsByCapability = new Map();
  for (const row of rows) {
    const capability = String(row.capability || '');
    const grouped = rowsByCapability.get(capability) || [];
    grouped.push(row);
    rowsByCapability.set(capability, grouped);
  }

  const orderedRows = [];
  const latestByCapability = new Map();
  for (const capability of [...rowsByCapability.keys()].sort()) {
    const chain = resolveCapabilityTopology(rowsByCapability.get(capability));
    const subjectEpoch = new Date(chain[0].subject_valid_from).toISOString();
    let expectedPrev = null;
    for (const row of chain) {
      const body = typeof row.signed_body === 'string' ? JSON.parse(row.signed_body) : row.signed_body;
      const signedClaims = typeof row.signed_claims === 'string' ? JSON.parse(row.signed_claims) : row.signed_claims;
      const storedPrev = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
      const bodyPermissions = body?.permissions || {};
      if (
        row.company_id !== companyId
        || row.subject_agent_id !== agentId
        || new Date(row.subject_valid_from).toISOString() !== subjectEpoch
        || !DEFAULT_CAPS.includes(capability)
        || String(body?.agent_id || '') !== agentId
        || bodyPermissions[capability] !== row.allowed
        || ![3, 4].includes(Number(row.request_sig_form))
        || canonicalJson(bodyPermissions) !== canonicalJson(body?.permissions || {})
        || (expectedPrev === null ? storedPrev !== null : !sameBuffer(expectedPrev, storedPrev))
      ) {
        throw new Error('authorization_chain_row_mismatch');
      }
      const computedContentHash = contentHash(body);
      const computedMutationHash = authorizationMutationHash(
        computedContentHash,
        expectedPrev,
        capability,
        row.nonce,
        Number(row.ts_signed)
      );
      if (!sameBuffer(computedContentHash, row.content_hash) || !sameBuffer(computedMutationHash, row.mutation_hash)) {
        throw new Error('authorization_chain_hash_mismatch');
      }
      const signature = Number(row.request_sig_form) === 4
        ? verifyStoredPayloadSigWithEnvelopeClaims(
            row.actor_pubkey,
            body,
            row.signed_method,
            row.signed_path,
            signedClaims || {},
            row.nonce,
            Number(row.ts_signed),
            Buffer.from(row.sig).toString('base64url')
          )
        : verifyStoredPayloadSigWithContext(
            row.actor_pubkey,
            body,
            row.signed_method,
            row.signed_path,
            row.nonce,
            Number(row.ts_signed),
            Buffer.from(row.sig).toString('base64url')
          );
      if (!signature.valid) throw new Error(`authorization_signature_invalid:${signature.reason}`);
      expectedPrev = Buffer.from(row.mutation_hash);
      orderedRows.push(row);
    }
    latestByCapability.set(capability, chain[chain.length - 1]);
  }
  return {
    verified: true,
    rowCount: rows.length,
    orderedRows,
    latestByCapability,
  };
}

function authorizationMutationHash(contentHashBuf, prevHash, capability, nonce, signedTs) {
  return createHash('sha256').update(Buffer.concat([
    contentHashBuf,
    prevHash || Buffer.alloc(0),
    Buffer.from(String(capability), 'utf8'),
    Buffer.from(String(nonce), 'utf8'),
    Buffer.from(String(signedTs), 'utf8'),
  ])).digest();
}

export async function setPermissions(agentId, permissions, authority, companyId) {
  const company = companyId || AIMOS_COMPANY_ID;
  const entries = Object.entries(permissions || {});
  if (!entries.length) {
    return buildPermissionScopeDiagnostics({ requestedCapabilities: [], actor: authority?.agentId, requestedScope: agentId });
  }
  if (
    authority?.kind !== 'verified_request'
    || typeof authority.agentId !== 'string'
    || typeof authority.validFromIso !== 'string'
    || !Number.isInteger(authority.signedTs)
    || typeof authority.nonce !== 'string'
    || !Buffer.isBuffer(authority.sigBytes)
    || authority.sigBytes.length !== 64
    || ![3, 4].includes(authority.requestSigForm)
    || String(authority.signedMethod || '').toUpperCase() !== 'POST'
    || authority.signedPath !== '/permissions/set'
    || (authority.requestSigForm === 3 && authority.signedClaims !== null)
    || (authority.requestSigForm === 4 && !authority.signedClaims?.prev_chain_hash)
    || canonicalJson(authority.body?.permissions || {}) !== canonicalJson(permissions)
    || String(authority.body?.agent_id || '') !== String(agentId)
  ) {
    throw new Error('verified_authorization_envelope_required');
  }
  for (const [capability] of entries) {
    if (!DEFAULT_CAPS.includes(capability)) throw new Error(`unknown_capability:${capability}`);
  }

  const client = await agentPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
    await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', authority.agentId]);
    const subjectIdentity = await client.query(
      `SELECT valid_from
         FROM agent_identity
        WHERE agent_id = $1
          AND NOT EXISTS (
            SELECT 1 FROM aimos_agent_revocation_events r
             WHERE r.agent_id = agent_identity.agent_id
               AND r.agent_valid_from = agent_identity.valid_from
          )
        ORDER BY valid_from DESC
        LIMIT 1`,
      [agentId]
    );
    if (!subjectIdentity.rows[0]) throw new Error('authorization_subject_not_active');
    const subjectValidFrom = subjectIdentity.rows[0].valid_from;
    const requestContentHash = contentHash(authority.body);
    const certFingerprint = createHash('sha256').update(String(authority.certString || ''), 'utf8').digest('hex');

    for (const [capability, allowed] of entries.sort(([a], [b]) => a.localeCompare(b))) {
      const lockKey = `${company.length}:${company}${agentId.length}:${agentId}${capability}`;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
      const previous = await client.query(
        `SELECT event.*, actor.pubkey AS actor_pubkey
           FROM aimos_authorization_events event
           JOIN agent_identity actor
             ON actor.agent_id = event.actor_agent_id
            AND actor.valid_from = event.actor_valid_from
          WHERE event.company_id = $1
            AND event.subject_agent_id = $2
            AND event.capability = $3
            AND event.subject_valid_from = $4`,
        [company, agentId, capability, subjectValidFrom]
      );
      const prevHash = previous.rows.length
        ? verifyAuthorizationEventChain(previous.rows, { companyId: company, agentId })
            .latestByCapability.get(capability).mutation_hash
        : null;
      const mutationHash = authorizationMutationHash(
        requestContentHash,
        prevHash,
        capability,
        authority.nonce,
        authority.signedTs
      );
      await client.query(
        `INSERT INTO aimos_authorization_events
           (company_id, subject_agent_id, subject_valid_from, capability, allowed,
            actor_agent_id, actor_valid_from, cert_fingerprint,
            signed_body, content_hash, mutation_hash, prev_mutation_hash,
            ts_signed, nonce, sig, identity_tier,
            request_sig_form, signed_method, signed_path, signed_claims)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
        [
          company, agentId, subjectValidFrom, capability, Boolean(allowed),
          authority.agentId, authority.validFromIso, certFingerprint,
          JSON.stringify(authority.body), requestContentHash, mutationHash, prevHash,
          authority.signedTs, authority.nonce, authority.sigBytes, authority.identityTier,
          authority.requestSigForm, authority.signedMethod, authority.signedPath,
          authority.signedClaims ? JSON.stringify(authority.signedClaims) : null,
        ]
      );
    }
    await client.query('COMMIT');
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
  const updatedPermissions = { ...defaultPermissions(), ...permissions };
  return buildPermissionScopeDiagnostics({
    requestedCapabilities: entries.map(([capability]) => capability),
    currentPermissions: updatedPermissions,
    requestedScope: agentId,
    actor: authority.agentId,
  });
}

export async function listPermissions(companyId) {
  const company = companyId || AIMOS_COMPANY_ID;
  const res = await withTransaction((client) => client.query(
    `SELECT DISTINCT event.subject_agent_id AS agent_id
       FROM aimos_authorization_events event
       JOIN agent_identity identity
         ON identity.agent_id = event.subject_agent_id
        AND identity.valid_from = event.subject_valid_from
      WHERE event.company_id = $1
        AND NOT EXISTS (
          SELECT 1 FROM aimos_agent_revocation_events revocation
           WHERE revocation.agent_id = identity.agent_id
             AND revocation.agent_valid_from = identity.valid_from
        )
      ORDER BY event.subject_agent_id`,
    [company]
  ), {
    restricted: true,
    client_id: company,
    agent_id: 'housekeeper',
  }
  );
  const grouped = {};
  for (const row of res.rows) {
    grouped[row.agent_id] = await getPermissions(row.agent_id, company);
  }
  return grouped;
}
