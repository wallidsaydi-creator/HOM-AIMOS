// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: services/write/persist-memory.js after canonical row insertion
// → Calls: pure classifier kernel + event ledger + restricted DB writer
// Pipeline: SAVE | Position: retained-memory epistemic classification owner
// Papers: PoisonedRAG; RAGShield; RAGCHECKER; Reason and Verify;
//         The Semantic Illusion
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Native retained-memory epistemic persistence owner.
 *
 * The behavior-identical deterministic decision is owned by the pure kernel.
 * This module appends its signed, reversible result after canonical retention.
 */

import { agentPool } from '../../db/connection.js';
import { logEvent, readVerifiedEventById } from '../observe/event-ledger.js';
import {
  escapeSqlLikeLiteral,
  sessionKeyQueryScope,
} from '../shared/session-scope.js';
import {
  MEMORY_EPISTEMIC_CLASSIFIER_VERSION,
  MEMORY_EPISTEMIC_LABELS,
  MEMORY_EPISTEMIC_SCHEMA,
  classifyRetainedMemoryBatch,
  classifyRetainedMemoryEpistemics,
  extractLeadingQuestion,
} from './memory-epistemic-classifier-kernel.js';
import {
  MEMORY_EPISTEMIC_EVIDENCE_ASSERTION_SCHEMA,
  MEMORY_EPISTEMIC_EVIDENCE_LEDGER_SCHEMA,
  buildEvidenceBoundExplicitClassification,
  buildMemoryEpistemicEvidenceAssertion,
  buildMemoryPoisonHypothesis,
  canonicalEvidenceJson,
  projectEpistemicLabelExact,
  resolveEffectiveEpistemicState,
  verifyMemoryEpistemicEvidenceAssertion,
  verifyMemoryEpistemicEvidenceChain,
} from './memory-epistemic-evidence-assertion.js';
import { verifyMemoryEpistemicEvidenceAuthorization } from './memory-epistemic-evidence-authorization.js';

export {
  MEMORY_EPISTEMIC_CLASSIFIER_VERSION,
  MEMORY_EPISTEMIC_LABELS,
  MEMORY_EPISTEMIC_SCHEMA,
  classifyRetainedMemoryBatch,
  classifyRetainedMemoryEpistemics,
  extractLeadingQuestion,
};

export {
  buildEvidenceBoundExplicitClassification,
  buildMemoryEpistemicEvidenceAssertion,
  buildMemoryPoisonHypothesis,
  projectEpistemicLabelExact,
  resolveEffectiveEpistemicState,
  verifyMemoryEpistemicEvidenceAssertion,
  verifyMemoryEpistemicEvidenceChain,
};

export const MEMORY_EPISTEMIC_EVIDENCE_ASSERTED_OPERATION = 'memory_epistemic_evidence_asserted';

function evidenceAssertionEventKey(hypothesisSha256) {
  if (!/^[0-9a-f]{64}$/.test(String(hypothesisSha256 || ''))) {
    throw new Error('epistemic_evidence_hypothesis_hash_invalid');
  }
  return `memory-epistemic-evidence:${hypothesisSha256}`;
}

function parseEventMetadata(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  try { return JSON.parse(row?.metadata || '{}'); } catch {
    throw new Error('epistemic_evidence_event_metadata_invalid');
  }
}

async function listDefaultEvidenceAssertionEvents(companyId, eventKey, { client = null } = {}) {
  const ownsClient = !client;
  const conn = client || await agentPool.connect();
  try {
    if (ownsClient) {
      await conn.query('BEGIN');
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', companyId]);
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    }
    const result = await conn.query(
      `SELECT id, operation, key, metadata, parent_event_id, mutation_hash, ledger_seq
         FROM aimos_events
        WHERE company_id = $1 AND operation = $2 AND key = $3
        ORDER BY ledger_seq`,
      [companyId, MEMORY_EPISTEMIC_EVIDENCE_ASSERTED_OPERATION, eventKey],
    );
    if (ownsClient) await conn.query('COMMIT');
    return result.rows;
  } catch (error) {
    if (ownsClient) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    throw error;
  } finally {
    if (ownsClient) conn.release();
  }
}

async function verifyEvidenceAssertionEventRows({
  companyId,
  eventKey,
  rows,
  readEventFn,
  client = null,
}) {
  const assertions = [];
  let parentEventId = null;
  let expectedHypothesisSha256 = null;
  for (const row of rows) {
    const verified = await readEventFn(row.id, companyId, { client });
    const metadata = parseEventMetadata(verified);
    if (verified.operation !== MEMORY_EPISTEMIC_EVIDENCE_ASSERTED_OPERATION
        || verified.key !== eventKey
        || metadata.schema !== MEMORY_EPISTEMIC_EVIDENCE_LEDGER_SCHEMA
        || (verified.parent_event_id || null) !== parentEventId) {
      throw new Error('epistemic_evidence_event_chain_invalid');
    }
    const assertion = verifyMemoryEpistemicEvidenceAssertion(metadata.assertion);
    expectedHypothesisSha256 ||= assertion.hypothesis.hypothesis_sha256;
    if (assertion.hypothesis.hypothesis_sha256 !== expectedHypothesisSha256
        || evidenceAssertionEventKey(expectedHypothesisSha256) !== eventKey) {
      throw new Error('epistemic_evidence_event_hypothesis_mismatch');
    }
    assertions.push(assertion);
    const prefix = verifyMemoryEpistemicEvidenceChain(assertions, { expectedHypothesisSha256 });
    if (metadata.evidence_root_sha256 !== prefix.evidence_root_sha256
        || metadata.head_assertion_sha256 !== prefix.head_assertion_sha256) {
      throw new Error('epistemic_evidence_event_root_mismatch');
    }
    parentEventId = verified.id;
  }
  const summary = verifyMemoryEpistemicEvidenceChain(assertions, {
    expectedHypothesisSha256,
  });
  return Object.freeze({ assertions: Object.freeze(assertions), summary, head_event_id: parentEventId });
}

/**
 * Append one housekeeper-signed evidence assertion inside the caller-owned
 * transaction. The per-hypothesis advisory lock prevents concurrent native
 * writers from creating two successors; the verifier still detects a fork if
 * a privileged non-native writer bypasses this owner.
 */
export async function commitMemoryEpistemicEvidenceAssertion({
  client,
  companyId,
  subjectAgentId,
  assertion,
  authority = null,
  signerConstraint = null,
  authorizationEvidence = null,
} = {}, {
  listEventsFn = listDefaultEvidenceAssertionEvents,
  logEventFn = logEvent,
  readEventFn = readVerifiedEventById,
} = {}) {
  if (!client) throw new Error('epistemic_evidence_client_required');
  const company = String(companyId || '').trim();
  const subject = String(subjectAgentId || '').trim();
  if (!company || !subject) throw new Error('epistemic_evidence_scope_required');
  const normalized = verifyMemoryEpistemicEvidenceAssertion(assertion);
  let authorizationProof = null;
  if (authorizationEvidence != null) {
    authorizationProof = verifyMemoryEpistemicEvidenceAuthorization(
      authorizationEvidence.approval,
      {
        assertion: normalized,
        classificationSource: authorizationEvidence.classificationSource,
        expectedMasterPubkeyB64u: authorizationEvidence.masterPubkeyB64u,
        expectedMasterFingerprint: authorizationEvidence.masterFingerprint,
        expectedHousekeeperSigner: authorizationEvidence.housekeeperSigner,
      },
    );
    if (!authorizationProof.valid) {
      throw new Error(`epistemic_evidence_authorization_invalid:${authorizationProof.reason}`);
    }
  }
  const eventKey = evidenceAssertionEventKey(normalized.hypothesis.hypothesis_sha256);
  await client.query(
    'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
    [`epistemic-evidence:${company}:${normalized.hypothesis.hypothesis_sha256}`],
  );
  const rows = await listEventsFn(company, eventKey, { client });
  const verified = await verifyEvidenceAssertionEventRows({
    companyId: company,
    eventKey,
    rows,
    readEventFn,
    client,
  });
  const existingIndex = verified.assertions.findIndex(
    (entry) => entry.assertion_sha256 === normalized.assertion_sha256,
  );
  if (existingIndex >= 0) {
    const row = rows[existingIndex];
    return Object.freeze({
      appended: false,
      reused: true,
      assertion: normalized,
      evidence_chain: verified.summary,
      receipt: Object.freeze({
        event_id: row.id,
        mutation_hash: Buffer.from(row.mutation_hash).toString('hex'),
      }),
    });
  }
  if (normalized.prev_assertion_sha256 !== verified.summary.head_assertion_sha256) {
    throw new Error('epistemic_evidence_append_predecessor_mismatch');
  }
  const nextAssertions = [...verified.assertions, normalized];
  const nextSummary = verifyMemoryEpistemicEvidenceChain(nextAssertions, {
    expectedHypothesisSha256: normalized.hypothesis.hypothesis_sha256,
  });
  const metadata = Object.freeze({
    schema: MEMORY_EPISTEMIC_EVIDENCE_LEDGER_SCHEMA,
    assertion_schema: MEMORY_EPISTEMIC_EVIDENCE_ASSERTION_SCHEMA,
    hypothesis_sha256: normalized.hypothesis.hypothesis_sha256,
    subject_memory_id: normalized.hypothesis.subject_memory_id,
    subject_live_content_hash: normalized.hypothesis.subject_live_content_hash,
    assertion: normalized,
    evidence_root_sha256: nextSummary.evidence_root_sha256,
    head_assertion_sha256: nextSummary.head_assertion_sha256,
    relation_counts: nextSummary.relation_counts,
    evidence_type_counts: nextSummary.evidence_type_counts,
    independent_supporting_source_count: nextSummary.independent_supporting_source_count,
    independent_refuting_source_count: nextSummary.independent_refuting_source_count,
    custody_approval: authorizationProof == null ? null : Object.freeze({
      schema: 'hom.aimos.memory-epistemic-evidence-custody-binding/v1',
      authority_scope: authorizationEvidence.approval.body.authority_scope,
      master_fingerprint: authorizationEvidence.masterFingerprint,
      master_approval_sha256: authorizationProof.approval_sha256,
      master_approval: authorizationEvidence.approval,
    }),
    retention: 'append_only_no_delete',
    automatic_classification_transition: false,
    automatic_antigen_activation: false,
    reasoning: 'Housekeeper retained a typed evidence assertion about one poison hypothesis; the assertion does not itself authorize a memory-label transition.',
    source_knowledge: 'AIMOS ECR-4D-N1 evidence assertion contract; RFC 6962; RFC 8032; Aladdin retention law',
  });
  const receipt = await logEventFn(
    company,
    subject,
    MEMORY_EPISTEMIC_EVIDENCE_ASSERTED_OPERATION,
    eventKey,
    metadata,
    verified.head_event_id,
    {
      client,
      authority,
      signerConstraint,
      returnReceipt: true,
    },
  );
  return Object.freeze({
    appended: true,
    reused: false,
    assertion: normalized,
    evidence_chain: nextSummary,
    receipt: Object.freeze({
      event_id: receipt.event_id,
      mutation_hash: receipt.mutation_hash,
    }),
  });
}

export async function verifyPersistedMemoryEpistemicEvidenceChain({
  companyId,
  hypothesisSha256,
  expectedEvidenceRootSha256 = null,
} = {}, {
  client = null,
  listEventsFn = listDefaultEvidenceAssertionEvents,
  readEventFn = readVerifiedEventById,
} = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('epistemic_evidence_scope_required');
  const eventKey = evidenceAssertionEventKey(hypothesisSha256);
  const rows = await listEventsFn(company, eventKey, { client });
  if (rows.length === 0) throw new Error('epistemic_evidence_persisted_chain_missing');
  const verified = await verifyEvidenceAssertionEventRows({
    companyId: company,
    eventKey,
    rows,
    readEventFn,
    client,
  });
  if (expectedEvidenceRootSha256 != null
      && verified.summary.evidence_root_sha256 !== expectedEvidenceRootSha256) {
    throw new Error('epistemic_evidence_persisted_root_mismatch');
  }
  return Object.freeze({
    valid: true,
    event_count: rows.length,
    head_event_id: verified.head_event_id,
    evidence_chain: verified.summary,
  });
}

function shouldAppendTransition(currentLabel, currentConfidence, next) {
  if (!next || next.label === 'unverified') return false;
  const current = String(currentLabel || 'unverified');
  if (current !== next.label) return true;
  return Number(next.confidence_milli) > Number(currentConfidence || 0);
}
/** Commit one signed classification and its current projection in one tx. */
export async function commitMemoryEpistemicClassification({
  client,
  companyId,
  subjectAgentId,
  classification,
  currentLabel = 'unverified',
  currentConfidenceMilli = 0,
  parentEventId = null,
  authority = null,
  provenance = null,
  evidenceAssertions = null,
}) {
  if (!client) throw new Error('epistemic_classification_client_required');
  if (!shouldAppendTransition(currentLabel, currentConfidenceMilli, classification)) {
    return { appended: false, classification };
  }
  if (!/^[0-9a-f]{64}$/.test(classification.live_content_hash)) {
    throw new Error('epistemic_classification_live_hash_invalid');
  }
  const evidenceBinding = evidenceAssertions == null
    ? null
    : verifyMemoryEpistemicEvidenceChain(evidenceAssertions);
  const labelsRequiringTypedEvidence = new Set([
    'supported',
    'disputed',
    'poison_confirmed',
    'poison_refuted',
  ]);
  if (labelsRequiringTypedEvidence.has(classification.label) && !evidenceBinding) {
    throw new Error('epistemic_classification_typed_evidence_required');
  }
  if (evidenceBinding) {
    const explicitRoot = classification.signals?.explicit_evidence?.evidence_sha256;
    if (explicitRoot !== evidenceBinding.evidence_root_sha256
        || classification.memory_id !== evidenceAssertions[0]?.hypothesis?.subject_memory_id
        || classification.live_content_hash !== evidenceAssertions[0]?.hypothesis?.subject_live_content_hash) {
      throw new Error('epistemic_classification_evidence_binding_mismatch');
    }
    buildEvidenceBoundExplicitClassification({
      label: classification.label,
      confidenceMilli: classification.confidence_milli,
      assertions: evidenceAssertions,
    });
  }

  const receipt = await logEvent(
    companyId,
    subjectAgentId,
    'memory_epistemic_classified',
    `epistemic:${classification.memory_id}`,
    {
      ...classification,
      provenance: provenance || null,
      evidence_assertion_binding: evidenceBinding,
      retention: 'retained_canonical_unchanged',
      original_content_changed: false,
      original_scope_changed: false,
      original_memory_type_changed: false,
      retrieval_weight_changed: false,
      reasoning: evidenceBinding
        ? `Retained memory classified as '${classification.label}' from the exact typed evidence-assertion root ${evidenceBinding.evidence_root_sha256}; classification is not admission or deletion.`
        : `Retained memory classified as '${classification.label}' from reproducible classifier signals; no typed evidence-assertion root was claimed. Classification is not admission or deletion.`,
      source_knowledge: 'PoisonedRAG; RAGShield; RAGCHECKER; Reason and Verify; The Semantic Illusion',
    },
    parentEventId,
    { client, authority, returnReceipt: true },
  );

  const applied = await client.query(
    `SELECT encode(public.apply_signed_memory_epistemic_classification(
       $1::uuid, $2::text, $3::integer, $4::uuid, $5::bytea
     ), 'hex') AS classification_hash`,
    [
      classification.memory_id,
      classification.label,
      classification.confidence_milli,
      receipt.event_id,
      Buffer.from(classification.live_content_hash, 'hex'),
    ],
  );

  return {
    appended: true,
    classification,
    receipt: {
      event_id: receipt.event_id,
      ledger_seq: receipt.ledger_seq,
      mutation_hash: receipt.mutation_hash,
      content_hash: receipt.content_hash,
    },
    classification_hash: applied.rows[0]?.classification_hash || null,
  };
}

function retainedPeerKeyScope(key = '', sessionId = '') {
  const session = String(sessionId || '').trim();
  if (session) return sessionKeyQueryScope(session);
  const match = String(key || '').match(/^(sess:[^:]+:)/i);
  if (!match) return Object.freeze({ pattern: '', lowerBound: '', upperBound: '' });
  return Object.freeze({
    pattern: `${escapeSqlLikeLiteral(match[1])}%`,
    lowerBound: match[1],
    upperBound: `${match[1]}\uFFFF`,
  });
}

/**
 * Classify the newly retained row and promote existing members of a newly
 * established lure cluster in the same canonical transaction.
 */
export async function classifyAndCommitRetainedMemoryGroup({
  client,
  companyId,
  subjectAgentId,
  memoryId,
  key,
  source,
  sessionId = null,
  parentEventId = null,
  authority = null,
  provenance = null,
}) {
  if (!client) throw new Error('epistemic_classification_client_required');
  const keyScope = retainedPeerKeyScope(key, sessionId);
  const sourceName = String(source || '').trim();
  const rows = await client.query(
    `SELECT id, key, value, source, memory_type, content_hash,
            current_epistemic_label, current_epistemic_confidence_milli
       FROM public.aimos_memories
      WHERE company_id = $1
        AND (
          ($2::text <> ''
              AND key LIKE $2 ESCAPE '\\'
              AND key COLLATE "C" >= $5::text COLLATE "C"
              AND key COLLATE "C" < $6::text COLLATE "C")
          OR ($2::text = '' AND $3::text <> ''
              AND source = $3 AND created_at >= NOW() - INTERVAL '1 hour')
          OR id = $4::uuid
        )
      ORDER BY created_at DESC, id DESC
      LIMIT 256`,
    [
      companyId,
      keyScope.pattern,
      sourceName,
      memoryId,
      keyScope.lowerBound,
      keyScope.upperBound,
    ],
  );
  const decisions = classifyRetainedMemoryBatch(rows.rows);
  const byId = new Map(rows.rows.map((row) => [String(row.id), row]));
  const commits = [];

  for (const classification of decisions) {
    if (!['poison_suspect', 'poison_likely'].includes(classification.label)) continue;
    const row = byId.get(classification.memory_id);
    if (!row) continue;
    const commit = await commitMemoryEpistemicClassification({
      client,
      companyId,
      subjectAgentId,
      classification,
      currentLabel: row.current_epistemic_label,
      currentConfidenceMilli: row.current_epistemic_confidence_milli,
      parentEventId,
      authority,
      provenance: {
        ...(provenance || {}),
        classification_trigger_memory_id: String(memoryId),
      },
    });
    if (commit.appended) commits.push(commit);
  }

  const currentDecision = decisions.find((decision) => decision.memory_id === String(memoryId)) || null;
  const currentCommit = commits.find((commit) => commit.classification.memory_id === String(memoryId)) || null;
  return {
    classification: currentDecision || {
      schema: MEMORY_EPISTEMIC_SCHEMA,
      classifier_version: MEMORY_EPISTEMIC_CLASSIFIER_VERSION,
      memory_id: String(memoryId),
      label: 'unverified',
      confidence_milli: 0,
      signals: {},
    },
    current_commit: currentCommit,
    appended_transitions: commits.length,
    related_memory_ids_reclassified: commits
      .map((commit) => commit.classification.memory_id)
      .filter((id) => id !== String(memoryId)),
  };
}
