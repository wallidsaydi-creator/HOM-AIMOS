// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: signed REST and MCP recall transports
// → Calls: restricted identity/authorization/provenance reads + event-ledger
// Pipeline: RECALL | Position: disclosure authority and evidence admission
// Sources: Cormack et al. RRF (ranking remains rank-only); HippoRAG (graph
// expansion must start from admitted evidence); RFC 6962 (receipt Merkle domain
// separation); confused-deputy/robust-composition authority discipline.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';
import { agentPool } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { canonicalJson } from '../security/agent-identity.js';
import { recallMerkleRoot } from '../security/protocol/mutmem-protocol.js';
export { recallMerkleRoot } from '../security/protocol/mutmem-protocol.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { memoryProvenanceLedger } from '../security/memory-provenance.js';
import { logEvent } from '../observe/event-ledger.js';
import {
  toolActionArgumentsHash,
  verifyToolActionAuthority,
} from '../orchestration/tool-action-ledger.js';
import { sessionKeyPrefix } from '../shared/session-scope.js';

const COMMAND_FIELDS = new Set([
  'query', 'q', 'key', 'memory_id', 'company_id', 'agent_id', 'limit',
  'clearance_level', 'memory_type_filter', 'source_filter', 'session_id',
  'project_id', 'workspace_path', 'sort', 'mode', 'selectivity', 'lazy',
  'max_hops', 'projection', 'cache', 'semantic_cache',
  'early_exit', 'debug_recall', 'doctor_trace', 'context_window', 'tokens_used',
  'recall_share', 'summary_token_budget', 'evidence_token_budget',
  'full_detail_token_budget', 'answer_shape', 'requested_shape',
  'answer_mode', 'ts_signed',
]);
const DATA_CLASS_ORDER = Object.freeze(['public', 'internal', 'confidential', 'restricted']);

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function normalizeInteger(value, fallback, min, max) {
  const parsed = value == null ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error('recall_integer_invalid');
  }
  return parsed;
}

export function normalizeNativeRecallCommand(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('recall_command_invalid');
  for (const key of Object.keys(raw)) {
    if (!COMMAND_FIELDS.has(key)) throw new Error(`recall_unknown_field:${key}`);
  }
  const query = String(raw.query ?? raw.q ?? '').trim();
  const key = raw.key == null ? null : String(raw.key).trim();
  const memoryId = raw.memory_id == null ? null : String(raw.memory_id).trim();
  if (!query && !key && !memoryId) throw new Error('recall_query_or_identifier_required');
  if (memoryId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(memoryId)) {
    throw new Error('recall_memory_id_invalid');
  }
  return Object.freeze({
    ...raw,
    query,
    q: query,
    key,
    memory_id: memoryId,
    company_id: raw.company_id == null ? AIMOS_COMPANY_ID : String(raw.company_id),
    agent_id: raw.agent_id == null ? null : String(raw.agent_id),
    limit: normalizeInteger(raw.limit, 10, 1, 200),
    clearance_level: raw.clearance_level == null ? null : normalizeInteger(raw.clearance_level, 1, 0, 12),
    max_hops: raw.max_hops == null ? null : normalizeInteger(raw.max_hops, 2, 1, 4),
  });
}

function exactMcpCommand(outerBody, transportBinding) {
  const toolName = transportBinding.toolName || 'aimos_recall';
  if (transportBinding.transport === 'legacy_mcp') {
    return outerBody?.name === toolName ? outerBody.arguments : null;
  }
  const index = transportBinding.batchIndex;
  const rpc = Array.isArray(outerBody) ? outerBody[index] : outerBody;
  if (!rpc || rpc.method !== 'tools/call' || rpc.params?.name !== toolName) return null;
  if (transportBinding.rpcId !== undefined && canonicalJson(rpc.id) !== canonicalJson(transportBinding.rpcId)) return null;
  return rpc.params.arguments;
}

async function assertSignedCommandBinding(rawCommand, requestAuthority, transportBinding, {
  client = null,
  executionContext = null,
} = {}) {
  if (requestAuthority?.kind === 'verified_tool_action') {
    if (transportBinding.transport !== 'tool' || requestAuthority.tool !== 'aimos_recall') {
      throw new Error('recall_transport_invalid');
    }
    if (requestAuthority.argsHash !== toolActionArgumentsHash(rawCommand)) {
      throw new Error('recall_command_not_signature_bound');
    }
    const signedAction = await verifyToolActionAuthority(requestAuthority, {
      client,
      expectedCompanyId: executionContext?.companyId,
      expectedTool: 'aimos_recall',
      expectedActorAgentId: executionContext?.actorAgentId,
    });
    return Object.freeze({
      ...requestAuthority,
      ...signedAction,
      kind: 'verified_tool_action',
    });
  }
  if (requestAuthority?.kind !== 'verified_request'
    || ![3, 4].includes(requestAuthority.requestSigForm)
    || String(requestAuthority.signedMethod).toUpperCase() !== 'POST') {
    throw new Error('signed_recall_request_required');
  }
  let signedCommand;
  if (transportBinding.transport === 'rest') {
    if (requestAuthority.signedPath !== '/aimos/recall') throw new Error('recall_signed_path_mismatch');
    signedCommand = requestAuthority.body;
  } else if (transportBinding.transport === 'v1') {
    if (requestAuthority.signedPath !== '/v1/recall') throw new Error('recall_signed_path_mismatch');
    signedCommand = requestAuthority.body;
  } else if (transportBinding.transport === 'legacy_mcp') {
    if (requestAuthority.signedPath !== '/aimos/mcp/tools/call') throw new Error('recall_signed_path_mismatch');
    signedCommand = exactMcpCommand(requestAuthority.body, transportBinding);
  } else if (transportBinding.transport === 'mcp') {
    if (requestAuthority.signedPath !== '/mcp') throw new Error('recall_signed_path_mismatch');
    signedCommand = exactMcpCommand(requestAuthority.body, transportBinding);
  } else {
    throw new Error('recall_transport_invalid');
  }
  if (canonicalJson(signedCommand) !== canonicalJson(rawCommand)) {
    throw new Error('recall_command_not_signature_bound');
  }
  return requestAuthority;
}

async function lockActiveActor(client, executionContext) {
  const identity = await client.query(
    `SELECT 1
       FROM agent_identity ai
      WHERE ai.agent_id = $1 AND ai.valid_from = $2
        AND NOT EXISTS (
          SELECT 1 FROM aimos_agent_revocation_events r
           WHERE r.agent_id = ai.agent_id AND r.agent_valid_from = ai.valid_from
        )
      FOR SHARE`,
    [executionContext.actorAgentId, executionContext.actorValidFromIso],
  );
  if (!identity.rows[0]) throw new Error('recall_actor_epoch_not_active');
  return identity.rows[0];
}

export async function resolveNativeRecallAuthority({
  rawCommand,
  executionContext,
  requestAuthority,
  transportBinding = { transport: 'rest' },
} = {}) {
  if (!executionContext?.actorAgentId || !executionContext?.actorValidFromIso || !executionContext?.companyId) {
    throw new Error('verified_recall_execution_context_required');
  }
  const command = normalizeNativeRecallCommand(rawCommand);
  if (command.company_id !== executionContext.companyId) throw new Error('recall_company_scope_mismatch');
  if (command.agent_id && command.agent_id !== executionContext.actorAgentId) throw new Error('recall_actor_mismatch');

  const client = await agentPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', executionContext.companyId]);
    await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', executionContext.actorAgentId]);
    const boundRequestAuthority = await assertSignedCommandBinding(
      rawCommand,
      requestAuthority,
      transportBinding,
      { client, executionContext },
    );
    if (boundRequestAuthority.kind === 'verified_request') {
      if (boundRequestAuthority.agentId !== executionContext.actorAgentId
        || new Date(boundRequestAuthority.validFromIso).toISOString() !== new Date(executionContext.actorValidFromIso).toISOString()) {
        throw new Error('recall_request_actor_epoch_mismatch');
      }
    } else if (
      boundRequestAuthority.actorAgentId !== executionContext.actorAgentId
      || new Date(boundRequestAuthority.actorValidFromIso).toISOString() !== new Date(executionContext.actorValidFromIso).toISOString()
    ) {
      throw new Error('recall_request_actor_epoch_mismatch');
    }
    const identity = await lockActiveActor(client, executionContext);
    const isHousekeeper = executionContext.actorAgentId === 'housekeeper'
      && ['T1_SYSTEM_SELF', 'T1'].includes(executionContext.identityTier);
    let ceiling;
    let dataClassCeiling;
    let authorityMutationHash;
    let authorizationEventId = null;
    if (isHousekeeper) {
      ceiling = 12;
      dataClassCeiling = 'restricted';
      authorityMutationHash = sha256(Buffer.from(canonicalJson({
        kind: 'housekeeper_system_principal',
        company_id: executionContext.companyId,
        agent_id: executionContext.actorAgentId,
        valid_from: new Date(executionContext.actorValidFromIso).toISOString(),
      }), 'utf8'));
    } else {
      const grant = await recallAuthorizationService.getEffective({
        companyId: executionContext.companyId,
        subjectAgentId: executionContext.actorAgentId,
        subjectValidFrom: executionContext.actorValidFromIso,
        client,
      });
      if (!grant?.allowed) throw new Error('master_signed_memory_read_grant_required');
      ceiling = grant.clearanceCeiling;
      dataClassCeiling = grant.dataClassCeiling;
      authorityMutationHash = grant.mutationHash;
      authorizationEventId = grant.eventId;
    }
    const requested = command.clearance_level == null ? ceiling : command.clearance_level;
    if (requested > ceiling) throw new Error('recall_clearance_exceeds_master_grant');
    await client.query('COMMIT');
    return Object.freeze({
      actorAgentId: executionContext.actorAgentId,
      actorValidFromIso: new Date(executionContext.actorValidFromIso).toISOString(),
      companyId: executionContext.companyId,
      identityTier: executionContext.identityTier,
      clearanceCeiling: requested,
      dataClassCeiling,
      authorityMutationHash: Buffer.from(authorityMutationHash),
      authorizationEventId,
      isHousekeeper,
      requestReceiptId: executionContext.requestReceiptId || null,
      requestReceiptMutationHash: executionContext.requestReceiptMutationHash || null,
      command,
      requestAuthority: boundRequestAuthority,
      transportBinding: Object.freeze({ ...transportBinding }),
    });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
}

export function isNativeRecallProofAllowed(proof, authority) {
  if (proof.company_id !== authority.companyId) return false;
  if (Number(proof.clearance_level) > authority.clearanceCeiling) return false;
  const classIndex = DATA_CLASS_ORDER.indexOf(proof.data_class || 'public');
  const maxClassIndex = DATA_CLASS_ORDER.indexOf(authority.dataClassCeiling);
  if (classIndex < 0 || classIndex > maxClassIndex) return false;
  if (proof.cube_scope === 'private' && proof.subject_agent_id !== authority.actorAgentId) return false;
  const sharedScopes = new Set(['global', 'executive', 'system']);
  const ownedQuarantine = (proof.scope === 'quarantine' || proof.memory_type === 'quarantine')
    && (proof.subject_agent_id === authority.actorAgentId || authority.isHousekeeper === true);
  const ownedScope = ['agent', 'private', authority.actorAgentId].includes(proof.scope)
    && proof.subject_agent_id === authority.actorAgentId;
  if (!sharedScopes.has(proof.scope) && !ownedScope && !ownedQuarantine) return false;
  if (Number(proof.clearance_level) <= 2 && proof.subject_agent_id && proof.subject_agent_id !== authority.actorAgentId) return false;
  if (!isNativeRecallCandidateWithinCommand(proof, authority.command)) return false;
  return true;
}

export function isNativeRecallCandidateWithinCommand(candidate, command = {}) {
  const sourceFilter = String(command?.source_filter || '').trim();
  if (sourceFilter && String(candidate?.source || '') !== sourceFilter) return false;

  const memoryTypeFilter = String(command?.memory_type_filter || '').trim();
  if (memoryTypeFilter && String(candidate?.memory_type || '') !== memoryTypeFilter) return false;

  const sessionId = String(command?.session_id || '').trim();
  if (sessionId) {
    const keyScoped = String(candidate?.key || '').startsWith(sessionKeyPrefix(sessionId));
    const candidateSessionId = String(
      candidate?.session_id
      ?? candidate?.compaction_handoff?.session_id
      ?? '',
    ).trim();
    if (!keyScoped && candidateSessionId !== sessionId) return false;
  }

  const memoryId = String(command?.memory_id || '').trim();
  if (memoryId && String(candidate?.memory_id || candidate?.id || '') !== memoryId) return false;

  const exactKey = String(command?.key || '').trim();
  if (exactKey && String(candidate?.key || '') !== exactKey) return false;

  return true;
}

export async function admitNativeRecallCandidatesInVerifiedSession(
  memories,
  authority,
  client,
  verifyEvidenceFn = (options) => memoryProvenanceLedger.verifyRecallEvidence(options),
) {
  if (!client || typeof client.query !== 'function') {
    throw new Error('verified_recall_session_client_required');
  }
  if (!authority?.companyId || !authority?.actorAgentId || !authority?.actorValidFromIso) {
    throw new Error('verified_recall_authority_required');
  }
  const candidateRows = (Array.isArray(memories) ? memories : [])
    .filter((memory) => isNativeRecallCandidateWithinCommand(memory, authority.command));
  const ids = [...new Set(candidateRows.map((memory) => String(memory?.id || '')).filter(Boolean))];
  if (!ids.length) return { memories: [], rejected: [] };
  const evidence = await verifyEvidenceFn({ memoryIds: ids, client });
  if (evidence.rejected.length) {
    const error = new Error('recall_evidence_verification_failed');
    error.rejected = evidence.rejected;
    throw error;
  }
  const admitted = [];
  for (const memory of candidateRows) {
    const proof = evidence.proofs.get(String(memory.id));
    if (!proof || !isNativeRecallProofAllowed(proof, authority)) continue;
    const quarantineEvidence = proof.scope === 'quarantine' || proof.memory_type === 'quarantine';
    admitted.push({
      ...memory,
      provenance_proof: proof,
      version_status: proof.version_status,
      retention_frequency_class: quarantineEvidence ? 'quiet' : 'normal',
      evidence_handling: quarantineEvidence ? 'untrusted_reference_only' : 'ordinary_reference',
    });
  }
  return { memories: admitted, rejected: [] };
}

/**
 * Bind one native recall principal and actor epoch for a bounded request, then
 * reuse that transaction for every newly discovered graph layer. Each call to
 * `admit` still performs the complete live provenance/signature verification;
 * only repeated connection, principal-binding, and actor-lock setup is shared.
 */
export async function openNativeRecallAdmissionSession({
  authority,
  connectFn = () => agentPool.connect(),
  verifyEvidenceFn = (options) => memoryProvenanceLedger.verifyRecallEvidence(options),
} = {}) {
  if (!authority?.companyId || !authority?.actorAgentId || !authority?.actorValidFromIso) {
    throw new Error('verified_recall_authority_required');
  }
  const client = await connectFn();
  let closed = false;
  try {
    await client.query('BEGIN');
    await client.query(
      `SELECT set_config($1,$2,true),
              set_config($3,$4,true),
              set_config($5,$6,true)`,
      [
        'app.current_client_id', authority.companyId,
        'app.current_agent_id', authority.actorAgentId,
        'plan_cache_mode', 'force_generic_plan',
      ],
    );
    await lockActiveActor(client, authority);
    if (!authority.isHousekeeper) {
      const grant = await recallAuthorizationService.getEffective({
        companyId: authority.companyId,
        subjectAgentId: authority.actorAgentId,
        subjectValidFrom: authority.actorValidFromIso,
        client,
      });
      if (!grant?.allowed || !Buffer.from(grant.mutationHash).equals(authority.authorityMutationHash)) {
        throw new Error('recall_authority_changed_during_request');
      }
    }
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    client.release();
    throw error;
  }

  return Object.freeze({
    admit: async (memories) => {
      if (closed) throw new Error('recall_admission_session_closed');
      return admitNativeRecallCandidatesInVerifiedSession(
        memories,
        authority,
        client,
        verifyEvidenceFn,
      );
    },
    close: async ({ commit = false } = {}) => {
      if (closed) return;
      closed = true;
      try {
        await client.query(commit ? 'COMMIT' : 'ROLLBACK');
      } finally {
        client.release();
      }
    },
  });
}

export async function admitNativeRecallCandidates(memories, authority) {
  const session = await openNativeRecallAdmissionSession({ authority });
  try {
    const admitted = await session.admit(memories);
    await session.close({ commit: true });
    return admitted;
  } catch (error) {
    try { await session.close({ commit: false }); } catch { /* preserve admission failure */ }
    throw error;
  }
}

export async function finalizeNativeRecall({ memories, authority, epistemicDecisionHash = null }) {
  const finiteScoreOrNull = (value) => {
    const score = Number(value);
    return Number.isFinite(score) ? score : null;
  };
  const entries = memories.map((memory, ordinal) => ({
    ordinal,
    memory_id: String(memory.id),
    live_content_hash: memory.provenance_proof.live_content_hash,
    save_mutation_hash: memory.provenance_proof.save_mutation_hash,
    binding_mutation_hash: memory.provenance_proof.binding_mutation_hash,
    truth_state: memory.provenance_proof.version_status,
    raw_calibration_score: finiteScoreOrNull(memory._raw_rerank),
    calibrated_score: finiteScoreOrNull(memory.calibrated_recall_score),
    calibration_event_id: memory.calibration_event_id,
    calibration_mutation_hash: memory.calibration_mutation_hash,
    calibration_formula_version: memory.calibration_formula_version,
  }));
  const normalizedDecisionHash = epistemicDecisionHash == null
    ? null
    : String(epistemicDecisionHash).trim().toLowerCase();
  if (normalizedDecisionHash != null && !/^[0-9a-f]{64}$/.test(normalizedDecisionHash)) {
    throw new TypeError('recall_epistemic_decision_hash_invalid');
  }
  const merkleEntries = normalizedDecisionHash
    ? [{
        entry_type: 'epistemic_decision',
        decision_sha256: normalizedDecisionHash,
      }, ...entries]
    : entries;
  const commandHash = sha256(Buffer.from(canonicalJson(authority.command), 'utf8')).toString('hex');
  const outerRequestHash = sha256(Buffer.from(canonicalJson(authority.requestAuthority.body), 'utf8')).toString('hex');
  const root = recallMerkleRoot(merkleEntries).toString('hex');
  const receipt = await logEvent(authority.companyId, authority.actorAgentId, 'recall_receipt', commandHash, {
    command_hash: commandHash,
    outer_request_hash: outerRequestHash,
    authority_mutation_hash: authority.authorityMutationHash.toString('hex'),
    request_receipt_id: authority.requestReceiptId,
    request_receipt_mutation_hash: authority.requestReceiptMutationHash,
    authorization_event_id: authority.authorizationEventId,
    transport: authority.transportBinding.transport,
    derived_tool_action_event_id: authority.requestAuthority.kind === 'verified_tool_action'
      ? authority.requestAuthority.eventId
      : null,
    rpc_id: authority.transportBinding.rpcId ?? null,
    batch_index: authority.transportBinding.batchIndex ?? null,
    result_count: entries.length,
    merkle_root: root,
    evidence: entries,
    ...(normalizedDecisionHash ? {
      merkle_schema: 'hom-aimos/recall-merkle/v2-epistemic-decision',
      epistemic_decision_sha256: normalizedDecisionHash,
      merkle_entries: merkleEntries,
    } : {}),
    reasoning: `Housekeeper observed ${entries.length} fail-closed provenance-verified recall result(s).`,
    source_knowledge: 'RFC 6962 domain-separated Merkle receipt; native-recall.js',
  }, null, {
    returnReceipt: true,
    authority: {
      actorAgentId: authority.requestAuthority.agentId,
      actorValidFromIso: authority.requestAuthority.validFromIso,
      certString: authority.requestAuthority.certString,
      signedTs: authority.requestAuthority.signedTs,
      nonce: authority.requestAuthority.nonce,
      sigBytes: authority.requestAuthority.sigBytes,
      requestSigForm: authority.requestAuthority.requestSigForm,
      signedMethod: authority.requestAuthority.signedMethod,
      signedPath: authority.requestAuthority.signedPath,
    },
  });
  return {
    command_hash: commandHash,
    outer_request_hash: outerRequestHash,
    authority_mutation_hash: authority.authorityMutationHash.toString('hex'),
    request_receipt_id: authority.requestReceiptId,
    request_receipt_mutation_hash: authority.requestReceiptMutationHash,
    merkle_root: root,
    evidence: entries,
    ...(normalizedDecisionHash ? {
      merkle_schema: 'hom-aimos/recall-merkle/v2-epistemic-decision',
      epistemic_decision_sha256: normalizedDecisionHash,
      merkle_entries: merkleEntries,
    } : {}),
    event_receipt: receipt,
  };
}

export default {
  normalizeNativeRecallCommand,
  resolveNativeRecallAuthority,
  isNativeRecallProofAllowed,
  admitNativeRecallCandidates,
  recallMerkleRoot,
  finalizeNativeRecall,
};
