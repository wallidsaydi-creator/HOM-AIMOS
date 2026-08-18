/**
 * persist-memory.js — Canonical Memory Save Function
 *
 * Extracted from routes/aimos.js to prevent INSERT bypasses.
 * Every memory write MUST go through persistMemory() to enforce:
 * - Quality gate (3 walls)
 * - Secret redaction
 * - Embedding generation
 * - Cross-reference linking (A-MEM Zettelkasten)
 * - Provisional entity-memory edge seeding for graph-aware recall
 * - Aladdin compliance
 * - Data classification
 * - Quarantine detection
 *
 * Sources: HippoRAG inspires later graph-aware retrieval/PPR, but this file only
 * seeds entity-memory edges; RAGChecker guides save-path diagnostic feedback;
 * Set the Clock / TimeR4 / MRAG guide freshness metadata for temporal truth
 * without violating Aladdin retention. AgeMem informs active-memory policy
 * diagnostics at the route boundary; canonical persistence remains Aladdin-safe.
 * Batch9 Wave1 adds PRF save-feedback diagnostics from turboquant-compat:
 * public keywords/entities/source hints only, no hidden CoT, no schema change,
 * no ranking change, and no canonical memory mutation.
 * Batch9 Wave2 surfaces quality-gate Sum-of-Checks diagnostics in native
 * save feedback after the three-wall gate runs; admission behavior is unchanged.
 *
 * Batch 10 Lane 5: LSM-Tree write path + WiscKey key/value separation +
 *   BVLSM big-value log + Bloom filter budget.
 *   MemtableBuffer: stage writes in memory before L0 flush.
 *   WiscKeySeparation: keys in hot index, values in append-only vLog.
 *   BVLSMBigValueLog: values > threshold → big-value log at WAL time.
 *   BloomFilterBudget: bits_per_key = -ln(ε) / ln(2).
 *   Aladdin: staging is a write optimization. Compaction promotes medallion levels,
 *   never deletes. Bloom filters are for read optimization.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: routes/aimos.js, agent-runner.js, tool-registry.js,
 *                  governance-resolver.js, nightly-dream.js, heartbeat.js, agent-learning.js,
 *                  skill-consolidation.js, delta-writer.js, dream-feedback.js
 * 2. → Calls: quality-gate.js, embeddings.js, curator.js,
 *             event-ledger.js, temporal-resolver.js, aladdin-compliance.js
 * Pipeline: SAVE | Position: canonical write gate
 */

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { query, agentPool } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { logEvent } from '../observe/event-ledger.js';
import { assessQuality } from './quality-gate.js';
import { checkConflict } from '../dream/curator.js';
import { computeLiveRowContentHash, memoryProvenanceLedger } from '../security/memory-provenance.js';
import { commitHousekeeperSupersession } from '../security/memory-lineage.js';
import {
  detectTierFromCert,
  extractValidFromIso,
  getHousekeeperCert,
  signAsHousekeeper,
  signOccurrenceCommitmentAsHousekeeper,
} from '../security/housekeeper-signer.js';
import { saveEnvelopeOrchestrator } from '../security/save-envelope.js';
import { getOperatorAgentId, isOperatorAgentId, normalizeOperatorAgentId } from '../security/system-config-store.js';
import { resolveFreshnessWriteFields } from '../temporal/freshness-metadata.js';
import { validateAladdinCompliance } from '../governance/aladdin-compliance.js';
import CodebookService from './codebook-service.js';
import { buildPrfFeatureDiagnostics, getTurboQuantCapabilities } from './turboquant-compat.js';
import { getCompressionPolicy } from './intent-classifier.js';
import { computePredictionError } from './rpe-gate.js';
import {
  isCredentialLaneSave,
  prepareCredentialMemory,
  buildCredentialLifecycleBody,
} from './credential-lane.js';
import { credentialLedger } from '../security/credential-ledger.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { verifyGenesisManifest } from '../../scripts/verify-genesis-manifest.mjs';
import { verifyToolActionAuthority } from '../orchestration/tool-action-ledger.js';
import { canonicalJson } from '../security/agent-identity.js';
import { refreshCachedCredential } from '../security/credential-cache.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { sessionKeyQueryScope } from '../shared/session-scope.js';
import { classifyAndCommitRetainedMemoryGroup } from '../security/memory-epistemic-classifier.js';
import { serializeMemoryValue } from '../security/protocol/memory-value.js';
import { computeOccurrenceCommitmentV3 } from '../security/protocol/content-state-occurrence-v3.js';

// ─── AGENT ID NORMALIZATION ─────────────────────────────────────────────────
// Operator agent + normalization come from the cert-enveloped aimos_system_config
// ledger (signed by the operator's master identity). No env, no hardcoded 'reviewer'.

// ─── SECRET REDACTION ─────────────────────────────────────────────────────────
const AIMOS_SECRET_PATTERNS = [
  /sk_live_[A-Za-z0-9]{20,}/g,
  /sk_test_[A-Za-z0-9]{20,}/g,
  /AIza[0-9A-Za-z\-_]{35,}/g,
  /ghp_[A-Za-z0-9]{36,}/g,
  /xox[baprs]-[0-9A-Za-z]{10,}/g,
  /"access_token"\s*:\s*"[^"]{20,}"/gi,
  /"refresh_token"\s*:\s*"[^"]{20,}"/gi,
];
const QUARANTINE_STRUCTURAL_TYPES = new Set(['session_exchange']);

export function redactAimosValue(text) {
  const redactString = (value) => {
    let rendered = String(value);
    for (const pat of AIMOS_SECRET_PATTERNS) {
      rendered = rendered.replace(pat, '[REDACTED]');
    }
    return rendered;
  };
  if (text == null) {
    return '';
  } else if (typeof text === 'string') {
    return redactString(text);
  }
  try {
    return JSON.stringify(text, (key, value) => {
      if (typeof value !== 'string') return value;
      if (/^(?:access_token|refresh_token)$/i.test(key) && value.length >= 20) {
        return '[REDACTED]';
      }
      return redactString(value);
    });
  } catch {
    return redactString(text);
  }
}

// ─── DATA CLASSIFICATION ────────────────────────────────────────────────────
function classifyDataSensitivity(value, clearanceLevel = 1) {
  const text = String(value || '').toLowerCase();
  const cl = Number(clearanceLevel || 1);

  if (/\b(password|secret|private.key|api.key|token|credential)\b/.test(text)) return 'restricted';
  if (/sk_live|sk_test|AIza|ghp_|xox[baprs]-/.test(value || '')) return 'restricted';

  if (/\b(revenue|salary|ssn|bank.account|credit.card|social.security)\b/.test(text)) return 'confidential';
  if (/\b(strategy|acquisition|merger|valuation|term.sheet)\b/.test(text)) return 'confidential';
  if (cl >= 7) return 'confidential';

  if (/\b(internal|agent_run|directive|escalat|clearance|governance)\b/.test(text)) return 'internal';
  if (cl >= 4) return 'internal';

  return 'public';
}

function normalizeOptionalTimestamp(value) {
  if (value == null || value === '') return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function mutationCommitError(kind, reason, currentHead = null) {
  const error = new Error(`${kind}_commit_failed: ${reason}`);
  error.code = kind === 'provenance' ? 'AIMOS_PROVENANCE_COMMIT_FAILED' : 'AIMOS_ENVELOPE_COMMIT_FAILED';
  if (kind === 'provenance') error.provenanceReason = reason;
  else {
    error.envelopeReason = reason;
    error.currentHead = currentHead;
  }
  return error;
}

const DATA_CLASS_RANK = Object.freeze({ public: 0, internal: 1, confidential: 2, restricted: 3 });

export async function lockVerifiedAuthorityEpoch(client, authority, {
  companyId,
  subjectAgentId,
  clearanceLevel,
  dataClass = null,
} = {}) {
  if (!['verified_request', 'verified_tool_action'].includes(authority?.kind)) return;
  const agentId = authority.kind === 'verified_request'
    ? authority.agentId
    : authority.actorAgentId;
  const validFromIso = authority.kind === 'verified_request'
    ? authority.validFromIso
    : authority.actorValidFromIso;
  const authorityCompanyId = authority.kind === 'verified_request'
    ? String(companyId || '')
    : authority.companyId;
  const identityTier = authority.kind === 'verified_request'
    ? authority.identityTier
    : authority.actorIdentityTier;
  if (!agentId || !validFromIso || !authorityCompanyId) {
    throw mutationCommitError('envelope', 'agent_epoch_missing');
  }
  if (String(agentId) !== String(subjectAgentId) || String(authorityCompanyId) !== String(companyId)) {
    throw mutationCommitError('envelope', 'agent_epoch_scope_mismatch');
  }
  // NO KEY UPDATE remains mutually exclusive with the master-signed
  // authorization/revocation writer's UPDATE lock, but is compatible with the
  // KEY SHARE lock PostgreSQL takes for event-ledger signer foreign keys. This
  // preserves epoch safety without creating an identity↔event lock inversion.
  const identity = await client.query(
    `SELECT 1
       FROM agent_identity
      WHERE agent_id = $1 AND valid_from = $2
      FOR NO KEY UPDATE`,
    [agentId, validFromIso]
  );
  if (!identity.rows[0]) throw mutationCommitError('envelope', 'agent_not_active');
  const terminal = await client.query(
    `SELECT 1
       FROM aimos_agent_revocation_events
      WHERE agent_id = $1 AND agent_valid_from = $2
      LIMIT 1`,
    [agentId, validFromIso]
  );
  if (terminal.rows[0]) throw mutationCommitError('envelope', 'agent_revoked');

  if (agentId === 'housekeeper') {
    if (!['T1', 'T1_SYSTEM_SELF'].includes(String(identityTier || '').toUpperCase())) {
      throw mutationCommitError('envelope', 'housekeeper_system_tier_required');
    }
    return;
  }

  // The identity row lock is shared with master-signed grant/revoke commits.
  // Re-read the effective authorization after acquiring it so a derived save
  // cannot outlive the actor epoch or a concurrent write-grant revocation.
  const grant = await recallAuthorizationService.getEffective({
    companyId,
    subjectAgentId: agentId,
    subjectValidFrom: validFromIso,
    client,
  });
  if (!grant?.allowed || !grant.writeAllowed) {
    throw mutationCommitError('envelope', 'master_signed_memory_write_grant_required');
  }
  const requestedClearance = Number(clearanceLevel ?? 1);
  if (!Number.isInteger(requestedClearance) || requestedClearance < 1 || requestedClearance > grant.clearanceCeiling) {
    throw mutationCommitError('envelope', 'clearance_exceeds_verified_authority');
  }
  if (dataClass && DATA_CLASS_RANK[dataClass] > DATA_CLASS_RANK[grant.dataClassCeiling]) {
    throw mutationCommitError('envelope', 'data_class_exceeds_verified_authority');
  }
}

/**
 * Inspect exact-value dedup inside the caller's canonical transaction.
 * The content-addressed lock closes the concurrent first-writer race, while
 * PostgreSQL visibility ensures an aborted attempt never poisons a later retry.
 */
export async function findRecentCommittedDuplicate(client, companyId, value, { sessionId = null } = {}) {
  const cid = String(companyId || '').trim();
  const text = String(value ?? '');
  if (!cid) throw new Error('duplicate_company_required');
  const sessionScope = sessionId == null ? null : sessionKeyQueryScope(sessionId);
  const digest = createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
  await client.query(
    'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
    [`aimos:dedup:v2:${cid.length}:${cid}:${sessionScope?.pattern || 'global'}:${digest}`],
  );
  const existing = await client.query(
    `SELECT id::text
       FROM aimos_memories
      WHERE company_id = $1
        AND value = $2
        AND (
          $3::text IS NULL
          OR (
            key LIKE $3 ESCAPE '\\'
            AND key COLLATE "C" >= $4::text COLLATE "C"
            AND key COLLATE "C" < $5::text COLLATE "C"
          )
        )
        AND created_at >= clock_timestamp() - interval '1 hour'
      ORDER BY created_at DESC, id DESC
      LIMIT 1`,
    [
      cid,
      text,
      sessionScope?.pattern || null,
      sessionScope?.lowerBound || null,
      sessionScope?.upperBound || null,
    ],
  );
  return existing.rows[0] || null;
}

/**
 * Resolve an exact canonical content state for the same principal. The digest
 * is an index key, never an equality oracle: every matching row is compared to
 * the complete canonical byte set and any digest/byte disagreement aborts.
 * Equal content owned by another principal remains a distinct occurrence
 * lineage and therefore materializes its own retained row.
 */
export async function findCommittedExactContentState(client, {
  companyId,
  agentId,
  liveContentHash,
  fields,
} = {}) {
  const company = String(companyId || '').trim();
  const principal = String(agentId || '').trim();
  const digest = Buffer.from(liveContentHash || []);
  if (!company || !principal || digest.length !== 32 || !fields || typeof fields !== 'object') {
    throw new Error('exact_content_state_scope_invalid');
  }
  await client.query(
    'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
    [`aimos:content-state:v1:${company.length}:${company}:${digest.toString('hex')}`],
  );
  const result = await client.query(
    `SELECT id::text, agent_id, key, value, scope, memory_type,
            clearance_level, data_class, source, memory_tier, expires_at,
            freshness_state, last_verified_at, verified_by, verification_basis,
            semantic_triples, surprise_at_save, compression_ratio,
            valid_from, valid_until, content_hash,
            current_epistemic_label, current_epistemic_confidence_milli,
            current_epistemic_event_id
       FROM aimos_memories
      WHERE company_id = $1 AND content_hash = $2
      ORDER BY id`,
    [company, digest],
  );
  const expected = canonicalJson({
    key: fields.key == null ? '' : String(fields.key),
    value: fields.value == null ? '' : String(fields.value),
    scope: fields.scope == null ? '' : String(fields.scope),
    memory_type: fields.memory_type == null ? '' : String(fields.memory_type),
    clearance_level: fields.clearance_level == null ? '' : String(fields.clearance_level),
    data_class: fields.data_class == null ? '' : String(fields.data_class),
    source: fields.source == null ? '' : String(fields.source),
  });
  let selected = null;
  for (const row of result.rows) {
    const retained = canonicalJson({
      key: row.key == null ? '' : String(row.key),
      value: row.value == null ? '' : String(row.value),
      scope: row.scope == null ? '' : String(row.scope),
      memory_type: row.memory_type == null ? '' : String(row.memory_type),
      clearance_level: row.clearance_level == null ? '' : String(row.clearance_level),
      data_class: row.data_class == null ? '' : String(row.data_class),
      source: row.source == null ? '' : String(row.source),
    });
    if (retained !== expected) throw new Error('content_state_digest_collision');
    if (!selected && String(row.agent_id) === principal) selected = row;
  }
  return selected;
}

/**
 * Resolve an already-committed Guide row carrying the exact current Genesis
 * corpus binding. The content-dedup advisory lock is acquired by
 * findRecentCommittedDuplicate() before this query is used, so a corpus upgrade
 * cannot race itself into two equivalent heads.
 */
export async function findExactGenesisManifestBinding(client, companyId, key, value, body) {
  const existing = await client.query(
    `SELECT m.id::text
       FROM aimos_memories m
       JOIN aimos_memory_provenance p
         ON p.memory_id = m.id
        AND p.event_type = 'SAVE'
      WHERE m.company_id = $1
        AND m.key = $2
        AND m.value = $3
        AND m.source = 'guide:genesis-install'
        AND p.body_json->>'genesis_manifest_schema' = $4
        AND p.body_json->>'genesis_manifest_version' = $5
        AND p.body_json->>'genesis_corpus_root' = $6
        AND p.body_json->>'genesis_file_path' = $7
        AND p.body_json->>'genesis_file_sha256' = $8
        AND (p.body_json->>'genesis_file_bytes')::int = $9
      LIMIT 1`,
    [
      companyId,
      key,
      value,
      body.genesis_manifest_schema,
      String(body.genesis_manifest_version),
      body.genesis_corpus_root,
      body.genesis_file_path,
      body.genesis_file_sha256,
      Number(body.genesis_file_bytes),
    ],
  );
  return existing.rows[0] || null;
}

async function commitInitialEvidence({
  authority,
  client,
  memoryId,
  subjectAgentId,
  companyId,
  key,
  value,
  scope,
  clearanceLevel,
  memoryType,
  source,
  actionSource,
  sessionId,
  liveContentHash,
  memoryOriginatedAt,
  supersessionEvidence,
}) {
  let signed;
  if (authority === 'housekeeper') {
    signed = await signAsHousekeeper({
      event_type: 'SAVE',
      memory_id: memoryId,
      subject_agent_id: subjectAgentId,
      company_id: companyId,
      key,
      value,
      scope,
      clearance_level: clearanceLevel,
      memory_type: memoryType,
      source,
      session_id: sessionId || null,
    });
  } else if (authority?.kind === 'verified_tool_action') {
    const verifiedAction = await verifyToolActionAuthority(authority, {
      client,
      expectedCompanyId: companyId,
      expectedTool: 'aimos_save_commit',
      expectedActorAgentId: subjectAgentId,
      expectedArguments: {
        company_id: companyId,
        agent_id: subjectAgentId,
        key,
        value,
        scope,
        clearance_level: clearanceLevel,
        memory_type: memoryType,
        source: actionSource,
        session_id: sessionId || null,
      },
    });
    signed = await signAsHousekeeper({
      event_type: 'SAVE',
      memory_id: memoryId,
      subject_agent_id: subjectAgentId,
      company_id: companyId,
      key,
      value,
      scope,
      clearance_level: clearanceLevel,
      memory_type: memoryType,
      source,
      session_id: sessionId || null,
      tool_action_event_id: verifiedAction.actionEventId,
      tool_action_mutation_hash: verifiedAction.actionMutationHash,
      tool_action_args_sha256: verifiedAction.actionArgsHash,
    });
  } else if (authority?.kind === 'verified_request') {
    signed = {
      body: authority.body,
      agentId: authority.agentId,
      validFromIso: authority.validFromIso,
      certString: authority.certString,
      signedTs: authority.signedTs,
      nonce: authority.nonce,
      sigBytes: authority.sigBytes,
      identityTier: authority.identityTier,
      requestSigForm: authority.requestSigForm,
      signedMethod: authority.signedMethod,
      signedPath: authority.signedPath,
      signedClaims: authority.signedClaims,
    };
  } else {
    throw mutationCommitError('provenance', 'mutation_authority_required');
  }

  const provenance = await memoryProvenanceLedger.commitProvenance({
    memoryId,
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    requestSigForm: signed.requestSigForm ?? signed.sigForm ?? 1,
    signedMethod: signed.signedMethod ?? null,
    signedPath: signed.signedPath ?? null,
    signedClaims: signed.signedClaims ?? null,
    eventType: 'SAVE',
    bodyJson: signed.body,
    liveContentHash,
    client,
  });
  if (!provenance.ok) throw mutationCommitError('provenance', provenance.reason);

  let envelope = null;
  if (authority?.kind === 'verified_request' && ['T2', 'T3'].includes(String(authority.identityTier).toUpperCase())) {
    if (!Buffer.isBuffer(authority.claimedPrev)) {
      throw mutationCommitError('envelope', 'malformed_input');
    }
    envelope = await saveEnvelopeOrchestrator.commitEnvelope({
      memoryId,
      body: signed.body,
      agentId: signed.agentId,
      validFromIso: signed.validFromIso,
      claimedPrev: authority.claimedPrev,
      certString: signed.certString,
      signedTs: signed.signedTs,
      nonce: signed.nonce,
      sigBytes: signed.sigBytes,
      identityTier: signed.identityTier,
      requestSigForm: signed.requestSigForm ?? signed.sigForm ?? 1,
      signedMethod: signed.signedMethod ?? null,
      signedPath: signed.signedPath ?? null,
      signedClaims: signed.signedClaims ?? null,
      client,
    });
    if (!envelope.ok) {
      throw mutationCommitError('envelope', envelope.reason, envelope.currentHead || null);
    }
  }

  // The request signer cannot attest a database-generated UUID it has not yet
  // seen. Append a second, housekeeper-signed node in the same transaction that
  // binds the exact memory row, canonical live snapshot, and original request
  // evidence. This is a native commit receipt, not a fabricated user signature.
  const memoryOriginatedAtUnixMs = new Date(memoryOriginatedAt).getTime();
  if (!Number.isSafeInteger(memoryOriginatedAtUnixMs) || memoryOriginatedAtUnixMs <= 0) {
    throw mutationCommitError('provenance', 'memory_originated_at_invalid');
  }
  const bindingSigned = await signAsHousekeeper({
    event_type: 'BIND',
    binding_schema_version: 4,
    memory_id: memoryId,
    company_id: companyId,
    subject_agent_id: subjectAgentId,
    key,
    session_id: sessionId || null,
    live_content_hash: Buffer.from(liveContentHash).toString('hex'),
    memory_originated_at_unix_ms: memoryOriginatedAtUnixMs,
    attestation_reason: 'native_save_commit',
    attested_predecessor_mutation_hash: Buffer.from(provenance.mutationHash).toString('hex'),
    attested_predecessor_node_count: 1,
    supersedes_id: supersessionEvidence?.supersedesId || null,
    supersession_event_id: supersessionEvidence?.eventId || null,
    predecessor_live_content_hash: supersessionEvidence?.predecessorLiveContentHash || null,
    lineage_mutation_hash: supersessionEvidence?.lineageMutationHash || null,
    request_content_hash: Buffer.from(provenance.contentHash).toString('hex'),
    request_mutation_hash: Buffer.from(provenance.mutationHash).toString('hex'),
    request_signature_hash: createHash('sha256').update(Buffer.from(signed.sigBytes)).digest('hex'),
    request_signer_agent_id: signed.agentId,
    request_signer_valid_from: signed.validFromIso,
  });
  const binding = await memoryProvenanceLedger.commitProvenance({
    memoryId,
    body: bindingSigned.body,
    agentId: bindingSigned.agentId,
    validFromIso: bindingSigned.validFromIso,
    certString: bindingSigned.certString,
    signedTs: bindingSigned.signedTs,
    nonce: bindingSigned.nonce,
    sigBytes: bindingSigned.sigBytes,
    identityTier: bindingSigned.identityTier,
    requestSigForm: bindingSigned.sigForm,
    eventType: 'BIND',
    bodyJson: bindingSigned.body,
    liveContentHash,
    memoryOriginatedAt,
    bindingSchemaVersion: 4,
    client,
  });
  if (!binding.ok) throw mutationCommitError('provenance', `binding_${binding.reason}`);

  return { provenance, binding, envelope };
}

async function persistCredentialMutation(params) {
  const prepared = await prepareCredentialMemory(params);
  if (prepared?.rejected) return prepared;

  const txClient = params.client || await agentPool.connect();
  const ownsTransaction = !params.client;
  try {
    if (ownsTransaction) {
      await txClient.query('BEGIN');
      await txClient.query('SELECT set_config($1,$2,true)', ['app.current_client_id', String(prepared.company_id)]);
      await txClient.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', String(prepared.agent_id)]);
    }
    await lockVerifiedAuthorityEpoch(txClient, params.mutation_authority, {
      companyId: prepared.company_id,
      subjectAgentId: prepared.agent_id,
      clearanceLevel: prepared.clearance_level,
      dataClass: 'restricted',
    });

    // Serialize the complete Keychain-reference/lifecycle ceremony before the
    // idempotency lookup. Without this lock, two first writers can both observe
    // no reference and append duplicate STORE chains for the same version hash.
    await txClient.query(
      `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
      [`${String(prepared.company_id).length}:${prepared.company_id}${prepared.service_name}`]
    );

    // Idempotent recovery after a Keychain-success/DB-failure boundary: an
    // already attested reference for the same version hash is reused.
    const existingReference = await txClient.query(
      `SELECT m.id, e.nonce AS envelope_nonce
         FROM aimos_memories m
         JOIN aimos_memory_provenance p ON p.memory_id = m.id AND p.is_genesis = true
         LEFT JOIN aimos_save_envelope e ON e.memory_id = m.id
        WHERE m.company_id = $1
          AND m.key = $2
          AND m.memory_type = 'credential_reference'
          AND m.value = $3
        ORDER BY m.created_at DESC, m.id DESC
        LIMIT 1`,
      [prepared.company_id, prepared.service_name, prepared.referenceSpec.value]
    );

    let referenceResult;
    const existingReferenceRow = existingReference.rows[0] || null;
    const mayReuseReference = existingReferenceRow && (
      !['T2', 'T3'].includes(String(params.mutation_authority?.identityTier).toUpperCase())
      || existingReferenceRow.envelope_nonce == null
      || existingReferenceRow.envelope_nonce === params.mutation_authority?.nonce
    );
    if (mayReuseReference) {
      referenceResult = {
        id: existingReferenceRow.id,
        existing: true,
        ledger_commit: null,
      };
    } else {
      referenceResult = await persistMemory({
        ...prepared.referenceSpec,
        client: txClient,
      });
      if (referenceResult?.rejected || !referenceResult?.id) {
        throw new Error(`credential_reference_persist_failed:${referenceResult?.reason || 'no_memory_id'}`);
      }
    }

    let providerResult = null;
    if (prepared.providerSpec) {
      const providerPayload = {
        ...JSON.parse(prepared.providerSpec.value),
        credential_memory_id: referenceResult.id,
      };
      const existingProvider = await txClient.query(
        `SELECT m.id
           FROM aimos_memories m
           JOIN aimos_memory_provenance p ON p.memory_id = m.id AND p.is_genesis = true
          WHERE m.company_id = $1
            AND m.key = $2
            AND m.memory_type = 'credential_provider'
            AND m.value::jsonb->>'credential_hash' = $3
            AND m.value::jsonb->>'provider' = $4
          ORDER BY m.created_at DESC, m.id DESC
          LIMIT 1`,
        [
          prepared.company_id,
          prepared.providerSpec.key,
          prepared.credential_hash,
          prepared.account,
        ]
      );
      providerResult = existingProvider.rows[0]
        ? { id: existingProvider.rows[0].id, existing: true }
        : await persistMemory({
            ...prepared.providerSpec,
            value: JSON.stringify(providerPayload),
            client: txClient,
          });
      if (providerResult?.rejected || !providerResult?.id) {
        throw new Error(`credential_provider_persist_failed:${providerResult?.reason || 'no_memory_id'}`);
      }
    }

    const verifiedLifecycle = await credentialLedger.readVerifiedSlotChain(
      prepared.keychain_slot,
      txClient,
    );
    const effectiveStore = verifiedLifecycle.effectiveStore || null;
    const previousStore = [...verifiedLifecycle.rows]
      .reverse()
      .find((row) => row.event_type === 'STORE' || row.event_type === 'ROTATE') || null;
    const previousBody = previousStore
      ? (typeof previousStore.body_json === 'string'
          ? JSON.parse(previousStore.body_json)
          : previousStore.body_json)
      : null;
    const candidateBody = buildCredentialLifecycleBody(prepared, referenceResult.id);
    const canReuseEffective = effectiveStore
      && previousBody?.credential_hash === prepared.credential_hash
      && canonicalJson(previousBody?.identity_vault || null)
        === canonicalJson(candidateBody?.identity_vault || null);
    let lifecycleCommit;
    if (canReuseEffective) {
      lifecycleCommit = {
        ok: true,
        existing: true,
        provenanceId: effectiveStore.provenance_id,
        mutationHash: effectiveStore.mutation_hash,
        contentHash: effectiveStore.content_hash,
      };
    } else {
      const eventType = verifiedLifecycle.rowCount > 0 ? 'ROTATE' : 'STORE';
      const lifecycleBody = buildCredentialLifecycleBody(prepared, referenceResult.id, {
        eventType,
        rotatedFrom: previousStore?.provenance_id || null,
        rotatedFromHash: previousBody?.credential_hash || null,
      });
      const signed = await signAsHousekeeper(lifecycleBody);
      lifecycleCommit = await credentialLedger.commitCredentialLifecycle({
        serviceName: prepared.service_name,
        slotId: prepared.keychain_slot,
        body: signed.body,
        agentId: signed.agentId,
        validFromIso: signed.validFromIso,
        certString: signed.certString,
        signedTs: signed.signedTs,
        nonce: signed.nonce,
        sigBytes: signed.sigBytes,
        identityTier: signed.identityTier,
        eventType,
        bodyJson: signed.body,
        client: txClient,
      });
      if (!lifecycleCommit.ok) {
        throw new Error(`credential_lifecycle_commit_failed:${lifecycleCommit.reason}`);
      }
    }

    let envelopeCommit = null;
    const authority = params.mutation_authority;
    if (authority?.kind === 'verified_request' && ['T2', 'T3'].includes(String(authority.identityTier).toUpperCase())) {
      envelopeCommit = await saveEnvelopeOrchestrator.commitEnvelope({
        memoryId: referenceResult.id,
        body: authority.body,
        agentId: authority.agentId,
        validFromIso: authority.validFromIso,
        claimedPrev: authority.claimedPrev,
        certString: authority.certString,
        signedTs: authority.signedTs,
        nonce: authority.nonce,
        sigBytes: authority.sigBytes,
        identityTier: authority.identityTier,
        requestSigForm: authority.requestSigForm,
        signedMethod: authority.signedMethod,
        signedPath: authority.signedPath,
        signedClaims: authority.signedClaims,
        client: txClient,
      });
      if (!envelopeCommit.ok) {
        throw mutationCommitError('envelope', envelopeCommit.reason, envelopeCommit.currentHead || null);
      }
    }

    if (ownsTransaction) await txClient.query('COMMIT');
    let credentialCacheRefreshed = null;
    if (ownsTransaction) {
      try {
        await refreshCachedCredential(prepared.service_name);
        credentialCacheRefreshed = true;
      } catch (error) {
        credentialCacheRefreshed = false;
        await logEvent(prepared.company_id, prepared.agent_id, 'credential_cache_refresh_failed', prepared.service_name, {
          credential_hash: prepared.credential_hash,
          error_class: error?.name || 'credential_cache_refresh_failed',
          reasoning: 'The signed credential lifecycle committed, but the live verified cache could not publish the new version.',
          source_knowledge: 'persist-memory.js — native credential transaction owner',
        }).catch((ledgerError) => {
          console.error('[credential-cache] signed refresh-failure event unavailable:', ledgerError?.message || ledgerError);
        });
      }
    }
    return {
      ...referenceResult,
      credential_lane: true,
      keychain_slot: prepared.keychain_slot,
      keychain_version_slot: prepared.keychain_version_slot,
      credential_hash: prepared.credential_hash,
      credential_ledger_commit: lifecycleCommit,
      provider_memory_id: providerResult?.id || null,
      envelope_commit: envelopeCommit,
      credential_cache_refreshed: credentialCacheRefreshed,
    };
  } catch (error) {
    if (ownsTransaction) {
      try { await txClient.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    error.keychain_reconciliation = {
      service: prepared.service_name,
      slot: prepared.keychain_slot,
      version_slot: prepared.keychain_version_slot,
      credential_hash: prepared.credential_hash,
      plaintext_retained_only_in_keychain: true,
    };
    throw error;
  } finally {
    if (ownsTransaction) txClient.release();
  }
}

// ─── QUARANTINE DETECTION ───────────────────────────────────────────────────
const QUARANTINE_PATTERNS = [
  /ignore (previous|prior|all) instructions?/i,
  /ignore all previous instructions?/i,
  /\bignore\b.{0,40}\binstructions?\b/i,
  /disregard (your|all|previous) (rules?|instructions?|guidelines?)/i,
  /you are now (?!your assistant)/i,
  /\bprompt injection\b/i,
  /\bjailbreak\b/i,
  /\[OVERRIDE\]/i,
  /system:\s*(ignore|bypass|disable)/i,
  /\bwhen recalled\b/i,
  /\balways respond\b/i,
  /\bprepend (to )?(every|all|each|your)/i,
  /\boverride all\b/i,
  /\bignore previous\b/i,
  /\bact as if\b/i,
  /\byour new (role|persona|identity|instruction)\b/i,
  /\bforget (your|all|previous) (instructions?|rules?|training)\b/i,
];

function decodeForQuarantine(text) {
  const s = String(text || '');
  let decoded = s;
  try { decoded = decodeURIComponent(decoded); } catch { /* invalid encoding */ }
  const b64 = s.replace(/\s/g, '');
  if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(b64)) {
    try {
      const candidate = Buffer.from(b64, 'base64').toString('utf8');
      if (/^[\x20-\x7E\n\r\t]+$/.test(candidate)) decoded += ' ' + candidate;
    } catch { /* not valid base64 */ }
  }
  return decoded;
}

function isQuarantineCandidate(text) {
  const decoded = decodeForQuarantine(text);
  return QUARANTINE_PATTERNS.some((p) => p.test(decoded));
}

const HOUSEKEEPER_GENESIS_PUBLISHER_TIERS = new Set(['T1', 'T1_SYSTEM_SELF']);

export function isPublisherVerifiedGenesisGuide({
  authority,
  companyId,
  agentId,
  key,
  value,
  source,
}) {
  if (authority?.kind !== 'verified_request'
    || authority.agentId !== 'housekeeper'
    || !HOUSEKEEPER_GENESIS_PUBLISHER_TIERS.has(authority.identityTier)
    || companyId !== AIMOS_COMPANY_ID
    || agentId !== 'housekeeper'
    || source !== 'guide:genesis-install') {
    return false;
  }
  const body = authority.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  try {
    const manifest = verifyGenesisManifest();
    const record = manifest.files.find((file) => file.path === body.genesis_file_path);
    if (!record) return false;
    const basename = record.path.split('/').at(-1).replace(/\.md$/i, '');
    const bytes = Buffer.from(String(value), 'utf8');
    const hash = createHash('sha256').update(bytes).digest('hex');
    return key === `guide:housekeeper:${basename}`
      && body.genesis_manifest_schema === manifest.schema
      && Number(body.genesis_manifest_version) === manifest.version
      && body.genesis_corpus_root === manifest.corpusRoot
      && body.genesis_file_sha256 === record.sha256
      && Number(body.genesis_file_bytes) === record.bytes
      && bytes.length === record.bytes
      && hash === record.sha256;
  } catch {
    return false;
  }
}

// ─── PROVISIONAL ENTITY-MEMORY EDGE SEEDING ────────────────────────────────
// This is not full HippoRAG. It only creates lightweight anchors that later
// graph/PPR retrieval can use after the graph services are paper-validated.
function extractEntities(text) {
  const entities = [];
  const seen = new Set();
  const add = (name, type) => {
    const n = name.trim().toLowerCase();
    if (n.length < 2 || n.length > 80 || seen.has(`${type}:${n}`)) return;
    seen.add(`${type}:${n}`);
    entities.push({ name: n, type });
  };

  const s = String(text || '');

  for (const m of s.matchAll(/\b([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,3})\b/g)) {
    const phrase = m[1];
    if (/^(The|This|That|These|Those|When|What|Where|Which|Here|There|After|Before|During|About|Also|Just|Some|Each|Every|Most|Many)$/.test(phrase.split(/\s+/)[0])) continue;
    add(phrase, 'proper_noun');
  }

  for (const m of s.matchAll(/\b(\d{4}-\d{2}-\d{2})\b/g)) add(m[1], 'date');
  for (const m of s.matchAll(/\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:,?\s*\d{4})?)\b/gi)) add(m[1], 'date');

  for (const m of s.matchAll(/\$[\d,]+(?:\.\d{2})?/g)) add(m[0], 'amount');
  for (const m of s.matchAll(/€[\d,]+(?:\.\d{2})?/g)) add(m[0], 'amount');

  for (const m of s.matchAll(/(https?:\/\/[^\s"'<>]+)/g)) add(m[1].slice(0, 80), 'url');

  for (const m of s.matchAll(/\b([A-Z]{2,5})\b/g)) {
    if (/^(THE|AND|FOR|BUT|NOT|ALL|ARE|WAS|HAS|HAD|GET|SET|PUT|RUN|API|SQL|URL|CSS|DNS|SSH|LLM|NLP|RAG|AAR)$/.test(m[1])) continue;
    add(m[1], 'symbol');
  }

  return entities.slice(0, 20);
}

// ─── MEDALLION LAYER ────────────────────────────────────────────────────────
function inferMedallionLayer(memoryType) {
  const gold = new Set(['milestone','product','identity','procedural','crew_identity','dream_summary','self_improvement','infrastructure']);
  const silver = new Set([
    'session','directive','heartbeat','intel','constitution_check','test',
    'book_extract','tacit_knowledge','session_debrief','session_exchange','session_manifest','procedural_seed',
    'self_reflection','core_belief','strategic_directive','after_action_review',
    'shared_failure','operational_rule','declarative','architecture',
    'research','dream_pattern','bibliographic_reference'
  ]);
  if (gold.has(memoryType)) return 'gold';
  if (silver.has(memoryType)) return 'silver';
  return 'bronze';
}

// ─── CANONICAL PERSIST MEMORY ───────────────────────────────────────────────
/**
 * Canonical save function for aimos_memories. Enforces quality gate,
 * secret redaction, embedding generation, cross-references, entity extraction,
 * Aladdin compliance, trigger evaluation. Every memory write MUST use this.
 *
 * @param {Object} params
 * @param {string} [params.company_id]
 * @param {string} [params.agent_id]
 * @param {string} params.key
 * @param {string} params.value
 * @param {string} [params.scope]
 * @param {number} [params.clearance_level]
 * @param {string} [params.memory_type]
 * @param {string} [params.source]
 * @param {string} [params.memory_tier] - Ignored (always 'long-term' per Aladdin)
 * @param {string|null} [params.cluster_id=null]
 * @param {boolean} [params.is_correction=false]
 * @param {string|null} [params.supersedes_id=null]
 * @param {string|null} [params.freshness_state=null]
 * @param {string|null} [params.last_verified_at=null]
 * @param {string|null} [params.verified_by=null]
 * @param {string|null} [params.verification_basis=null]
 * @param {string|null} [params.verify_target_id=null]
 * @param {string|null} [params.verify_target_key=null]
 * @param {string|null} [params.valid_from=null]
 * @param {string|null} [params.valid_until=null]
 * @param {Object|null} [params.security_disposition=null] - Signed contextual
 *   content decision produced before this write. A retain_quarantine decision
 *   forces the active 0.1 quarantine floor and is hash-bound to the value.
 * @param {'housekeeper'|Object} params.mutation_authority - Explicit signer;
 *   autonomous housekeeper, immutable verified-request context, or a verified
 *   housekeeper-signed derived tool action bound to the originating actor.
 * @returns {Promise<{id: string, memory_tier: string, expires_at: null, quarantined: boolean, conflict_detected: boolean, correction_applied: boolean, corrections_applied: number}|{rejected: boolean, reason: string, quality_score: number}>}
 */
export async function persistMemory({
  company_id,
  agent_id,
  key,
  value,
  scope,
  clearance_level,
  memory_type,
  source,
  memory_tier,
  cluster_id = null,
  is_correction = false,
  supersedes_id = null,
  freshness_state = null,
  last_verified_at = null,
  verified_by = null,
  verification_basis = null,
  verify_target_id = null,
  verify_target_key = null,
  semantic_triples = null,
  surprise_at_save = null,
  compression_ratio = null,
  valid_from = null,
  valid_until = null,
  session_id = null,
  account = null,
  ts_created = null,
  security_disposition = null,
  mutation_authority = null,
  client = null,
}) {
  // `persistMemory` is the native transaction owner. A client is accepted only
  // when a larger native ceremony (credential reconciliation, for example)
  // explicitly composes this mutation. Either way, this function commits the
  // initial provenance itself before it can return a memory id.
  const cid = company_id || AIMOS_COMPANY_ID;
  const aid = normalizeOperatorAgentId(agent_id);
  const securityInput = serializeMemoryValue(value);
  const safeValue = redactAimosValue(value);
  const securityDecision = security_disposition?.decision || null;
  const securityReceipt = security_disposition?.receipt || null;
  if (securityDecision || securityReceipt) {
    const safeValueHash = createHash('sha256').update(securityInput, 'utf8').digest('hex');
    const receiptBody = securityReceipt?.signed_body;
    const receiptMetadata = receiptBody?.metadata;
    const decisionBound = securityDecision
      && securityReceipt
      && securityDecision.operation === 'memory_save'
      && securityDecision.contentHash === safeValueHash
      && receiptBody?.operation === 'security_content_decision'
      && receiptMetadata?.content_sha256 === safeValueHash
      && receiptMetadata?.action === securityDecision.action;
    if (!decisionBound) throw new Error('security_disposition_proof_invalid');
  }

  // ─── Credential Lane: credentials get their own path, their own storage ──
  // The detector checks the save body's key against the known credential
  // service list (CACHED_CREDENTIAL_SERVICES).
  // If matched, the credential lane writes a versioned Keychain value and
  // returns safe reference/provider specifications. This native owner commits
  // those memories, provenance, and the signed STORE lifecycle row together.
  // The credential_reference type bypasses detection for the internal commit.
  // This is the single chokepoint covering /save +
  // /compaction/save — both call persistMemory.
  if (isCredentialLaneSave({ key, memory_type })) {
    return persistCredentialMutation({
      company_id: cid,
      agent_id: aid,
      key,
      value,
      scope,
      clearance_level,
      memory_type,
      source,
      valid_from,
      valid_until,
      session_id,
      account,
      ts_created,
      mutation_authority,
      client,
    });
  }

  // A verified request signature covers its original body. If redaction would
  // change that body, storing the original as provenance would leak the secret,
  // while storing the redacted body would falsely claim the signature covered
  // different bytes. The only sound native outcome is to reject and require the
  // dedicated Keychain credential lane.
  if (mutation_authority?.kind === 'verified_request' && safeValue !== securityInput) {
    return {
      rejected: true,
      reason: 'secret_material_requires_credential_lane',
      quality_score: 0,
    };
  }

  // ─── Quality Gate: reject garbage before it enters the brain ────────────
  const qualityResult = assessQuality(key, safeValue, memory_type, {
    agent_id: aid,
    source,
    scope,
    clearance_level,
  });
  if (!qualityResult.pass) {
    console.warn(`[Aimos] Quality gate REJECTED save: key="${key}" score=${qualityResult.score} reason="${qualityResult.reason}"`);
    await logEvent(cid, aid, 'quality_gate_reject', key, {
      score: qualityResult.score,
      reason: qualityResult.reason,
      walls: qualityResult.walls || null,
      value_preview: safeValue.slice(0, 100),
      reasoning: `Quality gate rejected memory '${key}' before Aimos insert. Reason: ${qualityResult.reason}. Score: ${qualityResult.score}. This preserves Aimos integrity by blocking zero-value, duplicate, or structurally unsafe writes at the first save wall.`,
      source_knowledge: 'quality-gate.js — Aladdin Law, HOM Constitution, OWASP ASVS'
    }, null, client ? { client } : {});
    return {
      rejected: true,
      reason: qualityResult.reason,
      quality_score: qualityResult.score,
      wall_results: qualityResult.walls || null,
      save_feedback: {
        accepted: false,
        quality_score: qualityResult.score,
        wall_results: qualityResult.walls || null,
        sum_of_checks: qualityResult.sum_of_checks || null,
        dedup_status: qualityResult.dedup_status || 'unknown',
        reasoning: `Save rejected at the quality gate: ${qualityResult.reason}`,
      }
    };
  }

  if (qualityResult.academic_ingest_authorized) {
    await logEvent(cid, aid, 'quality_gate_authorized_academic_ingest', key, {
      reason: qualityResult.walls?.filter?.authorization_reason || 'reviewer_lm_reader_bibliographic_evidence',
      dedup_status: qualityResult.dedup_status,
      memory_type,
      source,
      scope,
      clearance_level,
      value_preview: safeValue.slice(0, 160),
      reasoning: `Quality Gate admitted authorized academic ingestion for '${key}' after verifying Reviewer identity, bibliographic memory type, ingestion source, clearance, and non-executable evidence envelope. Repetition was treated as extraction scaffold, not user manipulation.`,
      source_knowledge: 'quality-gate.js — authorized academic ingestion lane'
    }, null, client ? { client } : {});
  }

  const publisherVerifiedGenesis = isPublisherVerifiedGenesisGuide({
    authority: mutation_authority,
    companyId: cid,
    agentId: aid,
    key,
    value: safeValue,
    source,
  });
  const baselineQuarantined = !publisherVerifiedGenesis && isQuarantineCandidate(safeValue);
  const decisionQuarantined = securityDecision?.action === 'retain_quarantine';
  const correctionMode = Boolean(is_correction);

  // The contextual decision and Canary boundary never suppress signed content.
  // High-risk evidence is retained, active, and recallable at the 0.1 floor.
  // The baseline regex remains a second native classification net.
  const quarantined = baselineQuarantined || decisionQuarantined;

  const effectiveScope = quarantined ? 'quarantine' : (scope || 'global');
  // Aladdin full-retention semantics: quarantine is an untrusted-reference
  // label and minimum-frequency cognitive state, never a lifecycle exclusion.
  const effectiveActive = true;
  // A composed session exchange must keep its structural type so native
  // session recall and restart reconciliation can still address it. Its
  // quarantine scope and 0.1 retrieval weight remain the security boundary.
  const requestedType = memory_type || 'declarative';
  const effectiveType = quarantined && !QUARANTINE_STRUCTURAL_TYPES.has(requestedType)
    ? 'quarantine'
    : requestedType;
  const effectiveSource = source || (isOperatorAgentId(aid) ? 'app' : 'agent');
  const freshnessEnvelope = resolveFreshnessWriteFields({
    key,
    memoryType: effectiveType,
    source: effectiveSource,
    freshnessState: freshness_state,
    lastVerifiedAt: last_verified_at,
    // The certified saver is already bound in the save intent/provenance
    // envelope. It is not automatically an independent factual verifier.
    verifiedBy: verified_by,
    verificationBasis: verification_basis,
  });

  const resolvedTier = 'long-term';
  const expiresAt = null;
  // Every same-key save is a new immutable version linked to its predecessor.
  // Corrections merely label the reason; they do not unlock an overwrite path.
  let resolvedSupersedesId = supersedes_id || null;

  // ─── Auto-classify data sensitivity ────────────────────────────────────
  const dataClass = classifyDataSensitivity(safeValue, clearance_level);

  // ─── Batch 10: Resolve compression_ratio from intent classification ──────
  // If caller didn't provide compression_ratio, derive it from memory type
  // via intent classification policy (500xCompressor).
  const resolvedCompressionRatio = compression_ratio ?? getCompressionPolicy(effectiveType).ratio;
  const resolvedValidFrom = normalizeOptionalTimestamp(valid_from);
  const resolvedValidUntil = normalizeOptionalTimestamp(valid_until);

  const embedding = await getEmbedding(safeValue);

  // ─── Batch 10: Resolve surprise_at_save from prediction error ────────────
  // If caller didn't provide surprise_at_save and embedding is available,
  // compute it from the L2 norm of prediction error (G-MemLLM / Titans).
  // Aladdin: surprise is metadata on the memory row, never replaces content.
  let resolvedSurpriseAtSave = surprise_at_save;
  if (resolvedSurpriseAtSave == null && embedding && !embedding._degraded) {
    const rpe = computePredictionError(null, embedding);
    resolvedSurpriseAtSave = rpe.prediction_error_norm;
  }
  const embeddingDegraded = Boolean(embedding?._degraded);
  const turboQuant = await getTurboQuantCapabilities();
  if (embeddingDegraded) {
    console.warn(`[Aimos] Memory "${key}" saved with degraded (math fallback) embedding — recall will be weak until re-embedded`);
  }

  // ─── TURBOQUANT: Native Online Vector Quantization (L0) ───────────────────
  let quant_idx = null;
  let residual_vector = null;
  if (turboQuant.quantColumns && embedding && !embeddingDegraded) {
    try {
      const qResult = await CodebookService.quantize(embedding, cid);
      quant_idx = qResult.quant_idx;
      residual_vector = qResult.residual;
    } catch (_qErr) {
      console.warn('[Aimos] Quantization failed (non-fatal):', _qErr.message);
    }
  }

  const conflict = await checkConflict(cid, key, safeValue, embedding);

  // ─── Phase 9a: compute live-row content_hash ──────────────────────────────
  // sha256(canonicalJson({key, value, scope, memory_type, clearance_level,
  // data_class, source})) over the CANONICAL field subset — the fields that
  // define the memory's CONTENT + CLASSIFICATION, not its lifecycle state.
  // Stored on aimos_memories.content_hash. /recall verify recomputes from the
  // live row's fields + compares (check 2a) to detect tampering of value/key/
  // scope/etc. without recomputing the hash. Use safeValue (the persisted form
  // of value, after any sanitization), not the raw req.body value.
  const effectiveClearanceLevel = Number(clearance_level || 1);
  const effectiveSourceForHash = embeddingDegraded
    ? `${effectiveSource}:degraded_embedding`
    : effectiveSource;
  const liveContentHashBuf = computeLiveRowContentHash({
    key,
    value: safeValue,
    scope: effectiveScope,
    memory_type: effectiveType,
    clearance_level: effectiveClearanceLevel,
    data_class: dataClass,
    source: effectiveSourceForHash,
  });

  const txClient = client || await agentPool.connect();
  const ownsTransaction = !client;
  const execInsert = (sql, params = []) => txClient.query(sql, params);

  try {
    if (ownsTransaction) {
      await txClient.query('BEGIN');
      await txClient.query('SELECT set_config($1,$2,true)', ['app.current_client_id', String(cid)]);
      await txClient.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', String(aid)]);
    }
    await lockVerifiedAuthorityEpoch(txClient, mutation_authority, {
      companyId: cid,
      subjectAgentId: aid,
      clearanceLevel: effectiveClearanceLevel,
      dataClass,
    });
    const exactState = await findCommittedExactContentState(txClient, {
      companyId: cid,
      agentId: aid,
      liveContentHash: liveContentHashBuf,
      fields: {
        key,
        value: safeValue,
        scope: effectiveScope,
        memory_type: effectiveType,
        clearance_level: effectiveClearanceLevel,
        data_class: dataClass,
        source: effectiveSourceForHash,
      },
    });
    if (exactState) {
      const verifiedRequest = mutation_authority?.kind === 'verified_request';
      if (verifiedRequest && (!mutation_authority.requestReceiptMutationHash
          || !mutation_authority.requestAdmissionEventId
          || !mutation_authority.signedMethod
          || !mutation_authority.signedPath)) {
        throw mutationCommitError('provenance', 'occurrence_v3_request_authority_missing');
      }
      const signerCertificate = await getHousekeeperCert();
      const signerValidFrom = extractValidFromIso(signerCertificate);
      const signerFingerprint = createHash('sha256')
        .update(String(signerCertificate), 'utf8')
        .digest('hex');
      const requestBody = verifiedRequest
        ? mutation_authority.body
        : {
            event_type: 'INTERNAL_SAVE_REASSERT',
            company_id: cid,
            subject_agent_id: aid,
            memory_id: exactState.id,
            key,
            value: safeValue,
            scope: effectiveScope,
            clearance_level: effectiveClearanceLevel,
            memory_type: effectiveType,
            source: effectiveSourceForHash,
            session_id: session_id || null,
            authority_kind: mutation_authority?.kind || 'housekeeper',
          };
      const requestBodyHash = createHash('sha256')
        .update(Buffer.from(canonicalJson(requestBody), 'utf8'))
        .digest('hex');
      const predecessor = await memoryProvenanceLedger.getLatestOccurrenceReference(
        exactState.id,
        cid,
        txClient,
      );
      if (!predecessor) throw mutationCommitError('provenance', 'occurrence_v3_predecessor_missing');
      const record = {
        company_id: cid,
        occurrence_event_id: randomUUID(),
        memory_id: exactState.id,
        event_type: verifiedRequest ? 'SAVE_REASSERT' : 'INTERNAL_SAVE_REASSERT',
        live_content_hash_hex: liveContentHashBuf.toString('hex'),
        predecessor_present: 1,
        predecessor_commitment_hex: predecessor,
        agent_id: 'housekeeper',
        signer_valid_from_unix_ms: new Date(signerValidFrom).getTime(),
        cert_fingerprint_hex: signerFingerprint,
        identity_tier: detectTierFromCert(signerCertificate) === 'T1_SYSTEM_SELF'
          ? 'T1'
          : detectTierFromCert(signerCertificate),
        sig_form_version: 3,
        nonce_hex: randomBytes(16).toString('hex'),
        ts_signed_unix_seconds: Math.floor(Date.now() / 1000),
        signed_method: verifiedRequest ? String(mutation_authority.signedMethod).toUpperCase() : '',
        signed_path: verifiedRequest ? String(mutation_authority.signedPath) : '',
        request_body_hash_hex: requestBodyHash,
        request_receipt_present: verifiedRequest ? 1 : 0,
        request_receipt_mutation_hash_hex: verifiedRequest
          ? String(mutation_authority.requestReceiptMutationHash).toLowerCase()
          : '',
        authorization_event_present: verifiedRequest ? 1 : 0,
        authorization_event_id: verifiedRequest
          ? String(mutation_authority.requestAdmissionEventId).toLowerCase()
          : '',
      };
      const occurrenceCommitment = computeOccurrenceCommitmentV3(record);
      const signedOccurrence = await signOccurrenceCommitmentAsHousekeeper(occurrenceCommitment);
      if (signedOccurrence.certString !== signerCertificate
          || signedOccurrence.validFromIso !== signerValidFrom) {
        throw mutationCommitError('provenance', 'occurrence_v3_signer_epoch_changed');
      }
      const occurrence = await memoryProvenanceLedger.commitOccurrenceV3({
        companyId: cid,
        memoryId: exactState.id,
        record,
        signature: signedOccurrence.sigBytes,
        certString: signerCertificate,
        liveContentHash: liveContentHashBuf,
        client: txClient,
      });
      if (!occurrence.ok) throw mutationCommitError('provenance', occurrence.reason);
      let exactEnvelope = null;
      if (verifiedRequest && ['T2', 'T3'].includes(String(mutation_authority.identityTier).toUpperCase())) {
        if (!Buffer.isBuffer(mutation_authority.claimedPrev)) {
          throw mutationCommitError('envelope', 'malformed_input');
        }
        exactEnvelope = await saveEnvelopeOrchestrator.commitEnvelope({
          memoryId: exactState.id,
          body: mutation_authority.body,
          agentId: mutation_authority.agentId,
          validFromIso: mutation_authority.validFromIso,
          claimedPrev: mutation_authority.claimedPrev,
          certString: mutation_authority.certString,
          signedTs: mutation_authority.signedTs,
          nonce: mutation_authority.nonce,
          sigBytes: mutation_authority.sigBytes,
          identityTier: mutation_authority.identityTier,
          requestSigForm: mutation_authority.requestSigForm,
          signedMethod: mutation_authority.signedMethod,
          signedPath: mutation_authority.signedPath,
          signedClaims: mutation_authority.signedClaims,
          client: txClient,
        });
        if (!exactEnvelope.ok) throw mutationCommitError(
          'envelope',
          exactEnvelope.reason,
          exactEnvelope.currentHead || null,
        );
      }
      const event = await logEvent(cid, aid, 'content_state_occurrence_reasserted', key, {
        memory_id: exactState.id,
        live_content_hash: liveContentHashBuf.toString('hex'),
        occurrence_event_id: record.occurrence_event_id,
        occurrence_commitment: occurrenceCommitment,
        request_receipt_mutation_hash: verifiedRequest
          ? record.request_receipt_mutation_hash_hex
          : null,
        canonical_memory_inserted: false,
        retrieval_vote_added: false,
        genesis_corpus_rebinding: publisherVerifiedGenesis,
        reasoning: 'An authorized exact canonical state was retained as a distinct signed occurrence on its existing memory state; no duplicate row or retrieval vote was created.',
        source_knowledge: 'R7 content-state/signed-occurrence contract',
      }, mutation_authority?.requestAdmissionEventId || null, {
        client: txClient,
        authority: verifiedRequest ? mutation_authority : null,
        returnReceipt: true,
      });
      if (ownsTransaction) await txClient.query('COMMIT');
      return {
        id: exactState.id,
        memory_tier: exactState.memory_tier,
        expires_at: exactState.expires_at,
        quarantined: effectiveScope === 'quarantine' || effectiveType === 'quarantine',
        security_decision_event_id: securityReceipt?.event_id || null,
        conflict_detected: false,
        correction_applied: false,
        corrections_applied: 0,
        quality_score: qualityResult.score,
        wall_results: qualityResult.walls || null,
        freshness_state: exactState.freshness_state,
        last_verified_at: exactState.last_verified_at,
        verified_by: exactState.verified_by,
        verification_basis: exactState.verification_basis,
        epistemic_label: exactState.current_epistemic_label || 'unverified',
        epistemic_confidence_milli: Number(exactState.current_epistemic_confidence_milli || 0),
        epistemic_classification_event_id: exactState.current_epistemic_event_id || null,
        epistemic_classification_hash: null,
        epistemic_related_memory_ids_reclassified: [],
        save_feedback: {
          accepted: true,
          quality_score: qualityResult.score,
          wall_results: qualityResult.walls || null,
          sum_of_checks: qualityResult.sum_of_checks || null,
          dedup_status: 'exact_state_reasserted',
          existing_memory_id: exactState.id,
          occurrence_event_id: record.occurrence_event_id,
          occurrence_commitment: occurrenceCommitment,
          retrieval_vote_added: false,
          reasoning: 'Exact content was accepted as a new signed occurrence of the existing canonical state.',
        },
        semantic_triples: exactState.semantic_triples,
        surprise_at_save: exactState.surprise_at_save,
        compression_ratio: exactState.compression_ratio,
        valid_from: exactState.valid_from,
        valid_until: exactState.valid_until,
        live_content_hash: liveContentHashBuf,
        ledger_commit: occurrence,
        binding_commit: null,
        envelope_commit: exactEnvelope,
        occurrence_reasserted: true,
        occurrence_event_receipt: event,
      };
    }
    if (key) {
      // Serialize one immutable chain per company/key, including the no-row
      // case that SELECT FOR UPDATE alone cannot lock.
      await txClient.query(
        `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
        [`${String(cid).length}:${cid}${key}`]
      );
      // The chain head is defined by topology, never by created_at. PostgreSQL
      // now() is fixed at transaction start, so a waiter that began earlier can
      // commit later with an older timestamp and make timestamp ordering select
      // a stale predecessor. The advisory lock serializes writers; this query
      // then resolves the sole retained row with no successor.
      const headResult = await txClient.query(
        `SELECT candidate.id
           FROM aimos_memories candidate
          WHERE candidate.company_id = $1
            AND candidate.key = $2
            AND NOT EXISTS (
              SELECT 1
                FROM aimos_memories successor
               WHERE successor.company_id = candidate.company_id
                 AND successor.key = candidate.key
                 AND successor.supersedes_id = candidate.id
            )
          ORDER BY candidate.id
          LIMIT 2`,
        [cid, key]
      );
      if (headResult.rows.length > 1) {
        const error = new Error('same-key retained chain has multiple topology heads');
        error.code = 'AIMOS_SUPERSESSION_TOPOLOGY_INVALID';
        throw error;
      }
      if (headResult.rows.length === 0) {
        const retained = await txClient.query(
          `SELECT 1
             FROM aimos_memories
            WHERE company_id = $1 AND key = $2
            LIMIT 1`,
          [cid, key]
        );
        if (retained.rows[0]) {
          const error = new Error('same-key retained chain has no topology head');
          error.code = 'AIMOS_SUPERSESSION_TOPOLOGY_INVALID';
          throw error;
        }
      }
      const currentPredecessorId = headResult.rows[0]?.id || null;
      if (supersedes_id && String(supersedes_id) !== String(currentPredecessorId || '')) {
        const error = new Error('supersedes_id must identify the current row for the same company and key');
        error.code = 'AIMOS_INVALID_SUPERSEDES';
        throw error;
      }
      resolvedSupersedesId = supersedes_id || currentPredecessorId;
    } else if (supersedes_id) {
      const error = new Error('supersedes_id requires a non-empty memory key');
      error.code = 'AIMOS_INVALID_SUPERSEDES';
      throw error;
    }

    let result;
    if (turboQuant.quantColumns) {
      result = await execInsert(
        `INSERT INTO aimos_memories
         (company_id, agent_id, key, value, embedding, scope, clearance_level, memory_type, source,
          memory_tier, decay_weight, promoted_at, expires_at, is_correction, supersedes_id, cluster_id, created_at, updated_at, is_active, data_class,
          retrieval_weight, access_count, medallion_layer, quant_idx, residual_vector, last_verified_at, verified_by, verification_basis, freshness_state,
          semantic_triples, surprise_at_save, compression_ratio, valid_from, valid_until, content_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 $10, $11, $12, $13, $14, $15, $16, NOW(), NOW(), $17, $18,
                 CASE WHEN $6 = 'quarantine' OR $8 = 'quarantine' THEN 0.1 ELSE 1.0 END, 0, $19, $20, $21, $22, $23, $24, $25,
                 $26, $27, $28, $29, $30, $31)
         RETURNING id, created_at, memory_tier, expires_at, last_verified_at, verified_by, verification_basis, freshness_state,
           semantic_triples, surprise_at_save, compression_ratio, valid_from, valid_until
        `, [
          cid, aid, key, safeValue, JSON.stringify(embedding), effectiveScope,
          Number(clearance_level || 1), effectiveType,
          embeddingDegraded ? `${effectiveSource}:degraded_embedding` : effectiveSource,
          resolvedTier, 1.0, correctionMode ? new Date() : null, expiresAt, correctionMode,
          resolvedSupersedesId, cluster_id, effectiveActive, dataClass, inferMedallionLayer(effectiveType),
          quant_idx,
          residual_vector ? JSON.stringify(Array.from(residual_vector)) : null,
          freshnessEnvelope.last_verified_at,
          freshnessEnvelope.verified_by,
          freshnessEnvelope.verification_basis,
          freshnessEnvelope.freshness_state,
          semantic_triples ? JSON.stringify(semantic_triples) : null,
          resolvedSurpriseAtSave,
          resolvedCompressionRatio,
          resolvedValidFrom,
          resolvedValidUntil,
          liveContentHashBuf,
        ]
      );
    } else {
      result = await execInsert(
        `INSERT INTO aimos_memories
         (company_id, agent_id, key, value, embedding, scope, clearance_level, memory_type, source,
          memory_tier, decay_weight, promoted_at, expires_at, is_correction, supersedes_id, cluster_id, created_at, updated_at, is_active, data_class,
          retrieval_weight, access_count, medallion_layer, last_verified_at, verified_by, verification_basis, freshness_state,
          semantic_triples, surprise_at_save, compression_ratio, valid_from, valid_until, content_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 $10, $11, $12, $13, $14, $15, $16, NOW(), NOW(), $17, $18,
                 CASE WHEN $6 = 'quarantine' OR $8 = 'quarantine' THEN 0.1 ELSE 1.0 END, 0, $19, $20, $21, $22, $23,
                 $24, $25, $26, $27, $28, $29)
         RETURNING id, created_at, memory_tier, expires_at, last_verified_at, verified_by, verification_basis, freshness_state,
           semantic_triples, surprise_at_save, compression_ratio, valid_from, valid_until
        `, [
          cid, aid, key, safeValue, JSON.stringify(embedding), effectiveScope,
          Number(clearance_level || 1), effectiveType,
          embeddingDegraded ? `${effectiveSource}:degraded_embedding` : effectiveSource,
          resolvedTier, 1.0, correctionMode ? new Date() : null, expiresAt, correctionMode,
          resolvedSupersedesId, cluster_id, effectiveActive, dataClass, inferMedallionLayer(effectiveType),
          freshnessEnvelope.last_verified_at,
          freshnessEnvelope.verified_by,
          freshnessEnvelope.verification_basis,
          freshnessEnvelope.freshness_state,
          semantic_triples ? JSON.stringify(semantic_triples) : null,
          resolvedSurpriseAtSave,
          resolvedCompressionRatio,
          resolvedValidFrom,
          resolvedValidUntil,
          liveContentHashBuf,
        ]
      );
    }

  // ─── Aladdin Law compliance check ───────────────────────────────────────
  // A violation aborts the native transaction; it is not downgraded to
  // best-effort telemetry after a canonical row has been inserted.
  validateAladdinCompliance({
    affects: (field) => field === 'retrieval_weight',
    newValue: 1.0,
    context: { isConsolidation: false }
  });

  // ─── Record supersession relation atomically ─────────────────────────────
  // The prior row remains fully retained and addressable. Current-truth
  // selection follows the explicit successor edge; no age/expiry suppression
  // is introduced here.
  let supersessionEvidence = null;
  if (resolvedSupersedesId && result.rows[0]?.id) {
    const supersessionMetadata = { relation: 'supersedes' };
    const triggerType = correctionMode ? 'correction' : 'update';
    const edge = await txClient.query(
      `INSERT INTO supersession_events
         (company_id, prior_memory_id, post_memory_id, trigger_type, metadata)
       VALUES ($1, $2::uuid, $3::uuid, $4, $5)
       RETURNING id`,
      [
        cid,
        resolvedSupersedesId,
        result.rows[0].id,
        triggerType,
        JSON.stringify(supersessionMetadata),
      ]
    );
    const predecessor = await txClient.query(
      `SELECT content_hash
         FROM aimos_memories
        WHERE company_id = $1 AND id = $2::uuid AND key = $3
        LIMIT 1`,
      [cid, resolvedSupersedesId, key]
    );
    const predecessorHash = predecessor.rows[0]?.content_hash;
    if (!Buffer.isBuffer(predecessorHash) || predecessorHash.length !== 32) {
      throw mutationCommitError('provenance', 'supersession_predecessor_hash_missing');
    }
    const lineage = await commitHousekeeperSupersession({
      client: txClient,
      companyId: cid,
      key,
      childId: result.rows[0].id,
      parentId: resolvedSupersedesId,
      childLiveContentHash: liveContentHashBuf,
      parentLiveContentHash: predecessorHash,
      supersessionEventId: Number(edge.rows[0].id),
      triggerType,
      metadata: supersessionMetadata,
      correction: correctionMode,
      attestationReason: 'native_save_commit',
    });
    supersessionEvidence = {
      supersedesId: String(resolvedSupersedesId),
      eventId: Number(edge.rows[0].id),
      predecessorLiveContentHash: predecessorHash.toString('hex'),
      lineageMutationHash: Buffer.from(lineage.mutationHash).toString('hex'),
    };
  }

  const correctionsApplied = 0;
  let nearDuplicateCount = 0;
  let nearestSimilarity = null;

  const operation = correctionMode ? 'correction' : (quarantined ? 'quarantine' : 'save');

  // ─── A-MEM ZETTELKASTEN: Cross-reference linking ──────────────────────
  if (embedding && result.rows[0].id && !quarantined) {
      const newMemoryId = result.rows[0].id;
      const similar = await txClient.query(
        `SELECT id, 1 - (embedding <=> $1::vector) AS similarity
         FROM aimos_memories
         WHERE company_id = $2
           AND id != $3
           AND embedding IS NOT NULL
         ORDER BY embedding <=> $1::vector
         LIMIT 5`,
        [JSON.stringify(embedding), cid, newMemoryId]
      );

      const graphEdges = [];
      for (const row of similar.rows) {
        const CROSS_REF_THRESHOLD = 0.85;
        if (Number(row.similarity) > CROSS_REF_THRESHOLD) {
          nearDuplicateCount += 1;
          nearestSimilarity = nearestSimilarity == null
            ? Number(row.similarity)
            : Math.max(nearestSimilarity, Number(row.similarity));
          graphEdges.push(
            { source_memory_id: newMemoryId, target_memory_id: row.id, similarity: Number(row.similarity) },
            { source_memory_id: row.id, target_memory_id: newMemoryId, similarity: Number(row.similarity) },
          );
        }
      }
      if (graphEdges.length) {
        const graphEvent = await logEvent(cid, 'housekeeper', 'memory_cross_refs_seeded', key, {
          memory_id: newMemoryId,
          threshold: 0.85,
          edges: graphEdges,
          canonical_memory_changed: false,
          retention_changed: false,
          reasoning: 'The native save transaction projected high-similarity associative edges and signed every derived pair before inserting the projection.',
          source_knowledge: 'A-MEM Zettelkasten association seeding in persist-memory.js',
        }, null, { client: txClient, returnReceipt: true });
        for (const edge of graphEdges) {
          await txClient.query(
            `INSERT INTO memory_cross_refs
               (company_id, source_memory_id, target_memory_id, similarity, authority_event_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (company_id, source_memory_id, target_memory_id) DO NOTHING`,
            [cid, edge.source_memory_id, edge.target_memory_id, edge.similarity, graphEvent.event_id]
          );
        }
      }
  }

  let verificationApplied = null;
  if ((verify_target_id || verify_target_key) && !quarantined) {
      const verificationResult = await txClient.query(
        `SELECT id, key
           FROM aimos_memories
         WHERE company_id = $1
           AND ($2::uuid IS NULL OR id = $2::uuid)
           AND ($3::text IS NULL OR key = $3)
         ORDER BY created_at DESC, id DESC
         LIMIT 1`,
        [
          cid,
          verify_target_id || null,
          verify_target_key || null,
        ]
      );
      if (verificationResult.rows.length > 0) {
        verificationApplied = {
          memory_id: verificationResult.rows[0].id,
          key: verificationResult.rows[0].key,
          evidence_memory_id: result.rows[0].id,
          evidence_mode: 'append_only',
        };
      }
  }

  // ─── GRAPH SEEDING: Entity extraction -> memory edge anchors ──────────
  if (result.rows[0].id && !quarantined) {
      const entities = extractEntities(`${key || ''} ${safeValue}`);
      const memId = result.rows[0].id;
      for (const ent of entities) {
        await txClient.query(
          `INSERT INTO entity_memory_edges (company_id, entity, entity_type, memory_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT DO NOTHING`,
          [cid, ent.name, ent.type, memId]
        );
      }
  }

  // Initial provenance is part of the canonical commit, never a caller-side
  // best-effort append. T2/T3 envelope CAS is folded into the same transaction.
  const ledgerCommit = await commitInitialEvidence({
    authority: mutation_authority,
    client: txClient,
    memoryId: result.rows[0].id,
    subjectAgentId: aid,
    companyId: cid,
    key,
    value: safeValue,
    scope: effectiveScope,
    clearanceLevel: effectiveClearanceLevel,
    memoryType: effectiveType,
    source: effectiveSourceForHash,
    actionSource: effectiveSource,
    sessionId: session_id,
    liveContentHash: liveContentHashBuf,
    memoryOriginatedAt: result.rows[0].created_at,
    supersessionEvidence,
  });

  // Classification is a signed retained-memory observation, not an admission
  // decision. Keep the canonical value/type/scope intact and bind the label to
  // the exact live row hash after its SAVE+BIND provenance exists. The
  // housekeeper may also promote related retained rows when a reproducible
  // query-lure cluster becomes visible in this same transaction.
  const epistemicClassification = await classifyAndCommitRetainedMemoryGroup({
    client: txClient,
    companyId: cid,
    subjectAgentId: aid,
    memoryId: result.rows[0].id,
    key,
    source: effectiveSourceForHash,
    sessionId: session_id,
    parentEventId: securityReceipt?.event_id || null,
    authority: mutation_authority && typeof mutation_authority === 'object'
      ? mutation_authority
      : null,
    provenance: {
      save_mutation_hash: Buffer.from(ledgerCommit.provenance.mutationHash).toString('hex'),
      binding_mutation_hash: Buffer.from(ledgerCommit.binding.mutationHash).toString('hex'),
    },
  });

  if (ownsTransaction) await txClient.query('COMMIT');

  // Ordinary operational telemetry and trigger execution occur only after this
  // function's owned commit. A larger ceremony that injected a client owns its
  // corresponding post-commit actions.
  if (ownsTransaction) {
    try {
      await logEvent(cid, aid, operation, key, {
        memory_tier: result.rows[0].memory_tier,
        correction_applied: correctionMode,
        corrections_applied: correctionsApplied,
        reasoning: correctionMode
          ? `A new immutable correction version supersedes the prior '${key}' row; retained history remains deep-recallable.`
          : quarantined
            ? `Memory retained in security isolation after content classification.`
            : `Memory and initial provenance committed atomically for '${key}'.`,
        source_knowledge: 'persist-memory.js — native memory/provenance transaction'
      });
    } catch (telemetryError) {
      console.warn('[persist-memory] post-commit event telemetry failed:', telemetryError.message);
    }
  }

  const saveFeedback = {
    accepted: true,
    quality_score: qualityResult.score,
    wall_results: qualityResult.walls || null,
    sum_of_checks: qualityResult.sum_of_checks || null,
    dedup_status: nearDuplicateCount > 0 ? 'near_duplicate' : (qualityResult.dedup_status || 'unique'),
    near_duplicate_count: nearDuplicateCount,
    nearest_similarity: nearestSimilarity == null ? null : Number(nearestSimilarity.toFixed(4)),
    memory_tier: result.rows[0].memory_tier,
    supersedes_id: resolvedSupersedesId,
    freshness_state: result.rows[0].freshness_state || freshnessEnvelope.freshness_state,
    verification: verificationApplied,
    epistemic_classification: {
      label: epistemicClassification.classification.label,
      confidence_milli: epistemicClassification.classification.confidence_milli,
      event_id: epistemicClassification.current_commit?.receipt?.event_id || null,
      classification_hash: epistemicClassification.current_commit?.classification_hash || null,
      related_memory_ids_reclassified: epistemicClassification.related_memory_ids_reclassified,
    },
    prf_features: buildPrfFeatureDiagnostics({
      key,
      value: safeValue,
      memoryType: effectiveType,
      source: effectiveSource,
    }),
    reasoning: correctionMode
      ? `Save accepted as a correction for '${key}'. Aimos kept retention intact while updating supersession and freshness metadata.`
      : `Save accepted for '${key}'. Quality gate passed, persistence completed, and freshness metadata was recorded for future temporal ranking.`,
  };

  return {
    id: result.rows[0].id,
    memory_tier: result.rows[0].memory_tier,
    expires_at: result.rows[0].expires_at,
    quarantined,
    security_decision_event_id: securityReceipt?.event_id || null,
    conflict_detected: !!conflict,
    correction_applied: correctionMode,
    corrections_applied: correctionsApplied,
    quality_score: qualityResult.score,
    wall_results: qualityResult.walls || null,
    freshness_state: result.rows[0].freshness_state || freshnessEnvelope.freshness_state,
    last_verified_at: result.rows[0].last_verified_at || freshnessEnvelope.last_verified_at,
    verified_by: result.rows[0].verified_by || freshnessEnvelope.verified_by,
    verification_basis: result.rows[0].verification_basis || freshnessEnvelope.verification_basis,
    verification_applied: verificationApplied,
    epistemic_label: epistemicClassification.classification.label,
    epistemic_confidence_milli: epistemicClassification.classification.confidence_milli,
    epistemic_classification_event_id: epistemicClassification.current_commit?.receipt?.event_id || null,
    epistemic_classification_hash: epistemicClassification.current_commit?.classification_hash || null,
    epistemic_related_memory_ids_reclassified: epistemicClassification.related_memory_ids_reclassified,
    save_feedback: saveFeedback,
    semantic_triples: result.rows[0].semantic_triples,
    surprise_at_save: result.rows[0].surprise_at_save,
    compression_ratio: result.rows[0].compression_ratio,
    valid_from: result.rows[0].valid_from,
    valid_until: result.rows[0].valid_until,
    live_content_hash: liveContentHashBuf,
    ledger_commit: ledgerCommit.provenance,
    binding_commit: ledgerCommit.binding,
    envelope_commit: ledgerCommit.envelope,
  };

  } catch (error) {
    if (ownsTransaction) {
      try { await txClient.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) txClient.release();
  }
}

// ─── BATCH 10 LANE 5: LSM-TREE WRITE PATH + WISCKEY + BVLSM + BLOOM ──────────
// Papers: LSM-Tree, WiscKey, BVLSM, Optimal Bloom Filters
// MemtableBuffer: stage writes in memory before flush to L0
// WiscKeySeparation: keys in hot index, values in append-only vLog
// BVLSMBigValueLog: values > threshold_bytes → big-value log at WAL time
// BloomFilterBudget: bits_per_key = -ln(ε) / ln(2)
// Aladdin: Memtable staging is a write optimization. Compaction promotes medallion
//   levels, never deletes. Bloom filters are for read optimization.
// Scale-adaptive (Batch 10.7 Lane 7, Phase 2):
//   MEMTABLE_BATCH_SIZE and BLOOM_FILTER_TARGET_FPR scale with memory count.
//   Use getMemtableBatchSize(memoryCount) and getBloomFilterTargetFPR(memoryCount)
//   for dynamic scaling. At N=14000: identical to hardcoded values.
// ─────────────────────────────────────────────────────────────────────────────

import { getMemtableBatchSize, getBloomFilterTargetFPR } from '../shared/scale-baseline.js';

const MEMTABLE_BATCH_SIZE = 100;
const MEMTABLE_FLUSH_INTERVAL_MS = 5000;
const WISCKEY_VALUE_THRESHOLD_BYTES = 4096;
const BLOOM_FILTER_TARGET_FPR = 0.01; // 1% FPR baseline at N=14000

/**
 * MemtableBuffer: in-memory staging buffer for writes before L0 flush.
 * Writes accumulate in memory and are flushed to PostgreSQL in batches.
 * Aladdin: staging only. All writes eventually reach Aimos.
 */
export class MemtableBuffer {
  constructor(options = {}) {
    this._buffer = [];
    this._batchSize = Math.max(1, Number(options.batchSize) || MEMTABLE_BATCH_SIZE);
    this._flushIntervalMs = Math.max(100, Number(options.flushIntervalMs) || MEMTABLE_FLUSH_INTERVAL_MS);
    this._flushTimer = null;
    this._totalWrites = 0;
    this._totalFlushes = 0;
  }

  /**
   * Stage a write in the memtable buffer.
   * @param {object} entry - { key, value, memory_type, ... }
   * @returns {{ staged: boolean, buffer_size: number }}
   */
  stage(entry) {
    if (!entry || !entry.key) {
      return { staged: false, buffer_size: this._buffer.length };
    }

    this._buffer.push({
      ...entry,
      _staged_at: Date.now(),
      _staged_seq: this._totalWrites++,
    });

    return { staged: true, buffer_size: this._buffer.length };
  }

  /**
   * Check if the buffer is ready to flush.
   * @returns {boolean}
   */
  shouldFlush() {
    return this._buffer.length >= this._batchSize;
  }

  /**
   * Drain and return all buffered entries for flush.
   * @returns {Array} Entries to flush
   */
  drain() {
    const entries = [...this._buffer];
    this._buffer = [];
    this._totalFlushes++;
    return entries;
  }

  /**
   * Get buffer statistics.
   */
  getStats() {
    return {
      buffer_size: this._buffer.length,
      batch_size: this._batchSize,
      flush_interval_ms: this._flushIntervalMs,
      total_writes: this._totalWrites,
      total_flushes: this._totalFlushes,
      should_flush: this.shouldFlush(),
      source_paper: 'LSM-Tree',
      aladdin: 'staging_only_all_writes_eventually_reach_aimos',
    };
  }
}

/**
 * WiscKeySeparation: separate key storage from value storage.
 * Keys in hot index (small, cache-friendly), values in append-only vLog.
 * Values below threshold stay inline; values above threshold go to vLog.
 */
export class WiscKeySeparation {
  constructor(options = {}) {
    this._vLog = new Map();  // vLog offset → value
    this._nextOffset = 0;
    this._valueThreshold = Math.max(256, Number(options.valueThresholdBytes) || WISCKEY_VALUE_THRESHOLD_BYTES);
  }

  /**
   * Separate a write into key and value components.
   * Values above threshold are stored in vLog; small values stay inline.
   *
   * @param {object} entry - { key, value, ... }
   * @returns {{ key_entry: object, value_ref: object|null }}
   */
  separate(entry) {
    if (!entry) return { key_entry: null, value_ref: null };

    const valueStr = String(entry.value || '');
    const valueBytes = valueStr.length * 2; // UTF-16 estimate

    if (valueBytes <= this._valueThreshold) {
      // Small value: stays inline in key entry
      return {
        key_entry: { ...entry, _wiskey_inline: true, _value_bytes: valueBytes },
        value_ref: null,
      };
    }

    // Large value: stored in vLog, key entry references it
    const offset = this._nextOffset++;
    this._vLog.set(offset, valueStr);

    return {
      key_entry: {
        ...entry,
        value: `[vLog-ref:${offset}]`,
        _wiskey_inline: false,
        _vlog_offset: offset,
        _value_bytes: valueBytes,
      },
      value_ref: {
        offset,
        value_bytes: valueBytes,
        vlog_stored: true,
      },
    };
  }

  /**
   * Look up a value from the vLog by offset.
   * @param {number} offset - vLog offset
   * @returns {string|null} Value string or null if not found
   */
  lookup(offset) {
    return this._vLog.get(Number(offset)) || null;
  }

  /**
   * Get WiscKey statistics.
   */
  getStats() {
    const totalEntries = this._vLog.size;
    const totalBytes = Array.from(this._vLog.values()).reduce((s, v) => s + v.length * 2, 0);
    return {
      vlog_entries: totalEntries,
      vlog_bytes: totalBytes,
      value_threshold_bytes: this._valueThreshold,
      next_offset: this._nextOffset,
      source_paper: 'WiscKey',
      aladdin: 'key_value_separation_is_a_write_optimization_never_deletes',
    };
  }
}

/**
 * BVLSMBigValueLog: append-only log for values exceeding threshold.
 * Values > threshold_bytes are written to the big-value log at WAL time.
 * Aladdin: big-value logging is additive. No value is ever truncated or deleted.
 */
export class BVLSMBigValueLog {
  constructor(options = {}) {
    this._log = [];  // [{ offset, value, timestamp }]
    this._thresholdBytes = Math.max(1024, Number(options.thresholdBytes) || WISCKEY_VALUE_THRESHOLD_BYTES * 2);
    this._totalBytes = 0;
  }

  /**
   * Write a value to the big-value log if it exceeds threshold.
   * @param {string} value - The value to potentially write to the big-value log
   * @returns {{ written: boolean, offset: number|null, value_bytes: number }}
   */
  write(value) {
    const valueStr = String(value || '');
    const valueBytes = valueStr.length * 2;

    if (valueBytes <= this._thresholdBytes) {
      return { written: false, offset: null, value_bytes: valueBytes };
    }

    const offset = this._log.length;
    this._log.push({
      offset,
      value: valueStr,
      value_bytes: valueBytes,
      timestamp: Date.now(),
    });
    this._totalBytes += valueBytes;

    return { written: true, offset, value_bytes: valueBytes };
  }

  /**
   * Read a value from the big-value log by offset.
   * @param {number} offset
   * @returns {string|null}
   */
  read(offset) {
    const entry = this._log[Number(offset)];
    return entry ? entry.value : null;
  }

  /**
   * Get big-value log statistics.
   */
  getStats() {
    return {
      entries: this._log.length,
      total_bytes: this._totalBytes,
      threshold_bytes: this._thresholdBytes,
      source_paper: 'BVLSM',
      aladdin: 'big_value_logging_is_additive_no_value_truncated_or_deleted',
    };
  }
}

/**
 * BloomFilterBudget: compute optimal bits per key for target false positive rate.
 * bits_per_key = -ln(ε) / ln(2)
 * Optimal Bloom filter sizing from "Optimal Bloom Filters" paper.
 */
export class BloomFilterBudget {
  constructor(options = {}) {
    this._targetFPR = Math.max(0.001, Math.min(0.5, Number(options.targetFPR) || BLOOM_FILTER_TARGET_FPR));
  }

  /**
   * Compute Bloom filter parameters for a given number of keys.
   *
   * @param {number} numKeys - Expected number of keys in the filter
   * @returns {{ bits_per_key: number, num_hashes: number, filter_bits: number, target_fpr: number, source_paper: string }}
   */
  compute(numKeys = 10000) {
    const n = Math.max(1, Number(numKeys) || 10000);
    const ln2 = Math.LN2;

    // bits_per_key = -ln(ε) / ln(2)
    const bitsPerKey = Math.max(1, -Math.log(this._targetFPR) / ln2);

    // Optimal number of hash functions: k = (m/n) * ln(2) = bits_per_key * ln(2)
    const numHashes = Math.max(1, Math.round(bitsPerKey * ln2));

    // Total filter size in bits
    const filterBits = Math.ceil(n * bitsPerKey);

    return {
      bits_per_key: Number(bitsPerKey.toFixed(4)),
      num_hashes: numHashes,
      filter_bits: filterBits,
      filter_bytes: Math.ceil(filterBits / 8),
      target_fpr: this._targetFPR,
      num_keys: n,
      formula: 'bits_per_key = -ln(ε) / ln(2)',
      source_paper: 'Optimal Bloom Filters',
      aladdin: 'bloom_filters_are_for_read_optimization_no_data_deleted',
    };
  }

  /**
   * Estimate false positive rate for given bits per key.
   * @param {number} bitsPerKey
   * @returns {{ fpr: number, bits_per_key: number, source_paper: string }}
   */
  estimateFPR(bitsPerKey) {
    const m = Math.max(1, Number(bitsPerKey) || 10);
    const ln2 = Math.LN2;
    const k = Math.max(1, Math.round(m * ln2));

    // FPR ≈ (1 - e^(-kn/m))^k, simplified: ≈ (1/2)^k when m/n is optimal
    const fpr = Math.pow(1 - Math.exp(-k / m), k);

    return {
      fpr: Number(fpr.toFixed(6)),
      bits_per_key: m,
      num_hashes: k,
      source_paper: 'Optimal Bloom Filters',
    };
  }
}
