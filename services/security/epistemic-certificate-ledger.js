// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: ECR certificate ceremonies only; no save/recall caller
// → Calls: portable certificate verifier + restricted signed event writer
// Pipeline: SECURITY | Housekeeper-signed ECR evidence custody
// Sources: CERT-ED (Findings EMNLP 2024); RFC 6962; RFC 8032
// ─────────────────────────────────────────────────────────────────────────────

import { randomUUID } from 'node:crypto';

import { agentPool } from '../../db/connection.js';
import { logEvent, readVerifiedEventById } from '../observe/event-ledger.js';
import { canonicalJson, sha256Canonical } from './epistemic-edit-certificate-math.js';
import { verifyEpistemicEditCertificate } from './epistemic-edit-certificate-verifier.js';
import {
  EPISTEMIC_MULTICLASS_CERTIFICATE_SCHEMA,
} from './epistemic-edit-certificate-multiclass-certifier.js';
import {
  verifyEpistemicMulticlassEditCertificate,
} from './epistemic-edit-certificate-multiclass-verifier.js';

export const EPISTEMIC_CERTIFICATE_LEDGER_SCHEMA = 'aimos.epistemic-certificate-custody/v1';
export const EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS = Object.freeze({
  STARTED: 'epistemic_certificate_started',
  TRANSCRIPT_CHUNK: 'epistemic_certificate_transcript_chunk',
  COMPLETED: 'epistemic_certificate_completed',
  FAILED: 'epistemic_certificate_failed',
});

const DEFAULT_CHUNK_BYTES = 700_000;
const MAX_EVENT_METADATA_BYTES = 1_048_576;

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function parseMetadata(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  try { return JSON.parse(row?.metadata || '{}'); } catch { throw new Error('epistemic_certificate_event_metadata_invalid'); }
}

function jsonBase64(value) {
  return Buffer.from(canonicalJson(value), 'utf8').toString('base64');
}

function decodeJsonBase64(value, reason) {
  try {
    return JSON.parse(Buffer.from(String(value || ''), 'base64').toString('utf8'));
  } catch {
    throw new Error(reason);
  }
}

function exactMetadata(actual, expected, reason) {
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(reason);
}

function certificateHeader(certificate) {
  const body = {
    schema: certificate.schema,
    certifier_version: certificate.certifier_version,
    projection_version: certificate.projection_version,
    formula_version: certificate.formula_version,
    input: certificate.input,
    parameters: certificate.parameters,
    decision: certificate.decision,
    transcripts: certificate.transcripts == null ? null : Object.freeze({
      selection_sha256: certificate.transcripts.selection_sha256,
      certification_sha256: certificate.transcripts.certification_sha256,
      selection_count: certificate.transcripts.selection.length,
      certification_count: certificate.transcripts.certification.length,
    }),
  };
  if (certificate.deletion_plan_sha256 != null) {
    body.deletion_plan_sha256 = certificate.deletion_plan_sha256;
  }
  if (certificate.automatic_policy_activation != null) {
    body.automatic_policy_activation = certificate.automatic_policy_activation;
  }
  return Object.freeze(body);
}

function verifyPortableCertificate({
  certificate,
  memory,
  peers,
  expectedClassifierSourceSha256,
  expectedSignedLabel,
  expectedBaseDecisionSha256,
}) {
  if (certificate?.schema === EPISTEMIC_MULTICLASS_CERTIFICATE_SCHEMA) {
    return verifyEpistemicMulticlassEditCertificate({
      certificate,
      memory,
      peers,
      expectedClassifierSourceSha256,
      expectedSignedLabel,
      expectedBaseDecisionSha256,
    });
  }
  return verifyEpistemicEditCertificate({
    certificate,
    memory,
    peers,
    expectedClassifierSourceSha256,
  });
}

function chunkRows(stream, rows, maxChunkBytes) {
  const chunks = [];
  let current = [];
  let rowStart = 0;
  const flush = () => {
    if (!current.length) return;
    const rowsSha256 = sha256Canonical(current);
    chunks.push(Object.freeze({
      stream,
      chunk_index: chunks.length,
      row_start: rowStart,
      row_count: current.length,
      rows_sha256: rowsSha256,
      rows_json_b64: jsonBase64(current),
    }));
    rowStart += current.length;
    current = [];
  };

  for (const row of rows) {
    const candidate = [...current, row];
    if (Buffer.byteLength(jsonBase64(candidate), 'utf8') > maxChunkBytes) {
      assert(current.length > 0, 'epistemic_certificate_transcript_row_too_large');
      flush();
    }
    current.push(row);
  }
  flush();
  return chunks;
}

export function buildEpistemicCertificateCustodyPlan({
  ceremonyId = randomUUID(),
  certificate,
  maxChunkBytes = DEFAULT_CHUNK_BYTES,
} = {}) {
  assert(/^[0-9a-f-]{36}$/i.test(String(ceremonyId || '')), 'epistemic_certificate_ceremony_id_invalid');
  assert(certificate && /^[0-9a-f]{64}$/.test(String(certificate.certificate_sha256 || '')),
    'epistemic_certificate_hash_invalid');
  assert(Number.isSafeInteger(maxChunkBytes) && maxChunkBytes > 1024
    && maxChunkBytes < MAX_EVENT_METADATA_BYTES, 'epistemic_certificate_chunk_ceiling_invalid');

  const { certificate_sha256: claimedHash, ...unsignedCertificate } = certificate;
  assert(sha256Canonical(unsignedCertificate) === claimedHash, 'epistemic_certificate_hash_mismatch');
  const header = certificateHeader(certificate);
  const headerSha256 = sha256Canonical(header);
  const chunks = certificate.transcripts == null
    ? []
    : [
        ...chunkRows('selection', certificate.transcripts.selection, maxChunkBytes),
        ...chunkRows('certification', certificate.transcripts.certification, maxChunkBytes),
      ];
  const chunkManifest = chunks.map(({ rows_json_b64: _rows, ...entry }) => entry);
  const evidenceRootSha256 = sha256Canonical({
    certificate_sha256: claimedHash,
    header_sha256: headerSha256,
    chunks: chunkManifest,
  });
  const eventKey = `${ceremonyId}:${claimedHash}`;
  const startMetadata = Object.freeze({
    schema: EPISTEMIC_CERTIFICATE_LEDGER_SCHEMA,
    ceremony_id: ceremonyId,
    certificate_sha256: claimedHash,
    header_sha256: headerSha256,
    header_json_b64: jsonBase64(header),
    evidence_root_sha256: evidenceRootSha256,
    chunk_manifest: chunkManifest,
    reasoning: 'Housekeeper started append-only custody for the exact verified ECR certificate and transcript commitment.',
    source_knowledge: 'CERT-ED Findings EMNLP 2024; RFC 6962; RFC 8032',
  });
  assert(Buffer.byteLength(canonicalJson(startMetadata), 'utf8') < MAX_EVENT_METADATA_BYTES,
    'epistemic_certificate_start_metadata_too_large');
  return Object.freeze({
    ceremony_id: ceremonyId,
    event_key: eventKey,
    certificate_sha256: claimedHash,
    header,
    header_sha256: headerSha256,
    chunks: Object.freeze(chunks),
    chunk_manifest: Object.freeze(chunkManifest),
    evidence_root_sha256: evidenceRootSha256,
    start_metadata: startMetadata,
  });
}

async function listDefaultEvents(companyId, eventKey, { client = null } = {}) {
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
        WHERE company_id = $1 AND key = $2
          AND operation = ANY($3::text[])
        ORDER BY ledger_seq`,
      [companyId, eventKey, Object.values(EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS)],
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

async function verifyExisting(row, companyId, readEventFn, expectedOperation, expectedKey, expectedParent, expectedMetadata) {
  const verified = await readEventFn(row.id, companyId);
  const actualMetadata = parseMetadata(verified);
  assert(verified.operation === expectedOperation, 'epistemic_certificate_event_operation_mismatch');
  assert(verified.key === expectedKey, 'epistemic_certificate_event_key_mismatch');
  assert((verified.parent_event_id || null) === (expectedParent || null), 'epistemic_certificate_event_parent_mismatch');
  exactMetadata(actualMetadata, expectedMetadata, 'epistemic_certificate_event_metadata_mismatch');
  return verified;
}

export async function persistEpistemicCertificateEvidence({
  companyId,
  subjectAgentId,
  ceremonyId,
  certificate,
  memory,
  peers = [],
  expectedClassifierSourceSha256,
  expectedSignedLabel = null,
  expectedBaseDecisionSha256 = null,
  maxChunkBytes = DEFAULT_CHUNK_BYTES,
  eventAuthority = null,
  signerConstraint = null,
} = {}, {
  listEventsFn = listDefaultEvents,
  logEventFn = logEvent,
  readEventFn = readVerifiedEventById,
} = {}) {
  const company = String(companyId || '').trim();
  const subject = String(subjectAgentId || '').trim();
  assert(company && subject, 'epistemic_certificate_scope_required');
  const portable = verifyPortableCertificate({
    certificate,
    memory,
    peers,
    expectedClassifierSourceSha256,
    expectedSignedLabel,
    expectedBaseDecisionSha256,
  });
  assert(portable.valid === true, `epistemic_certificate_pre_persistence_invalid:${portable.reason || 'unknown'}`);
  const plan = buildEpistemicCertificateCustodyPlan({ ceremonyId, certificate, maxChunkBytes });
  const existing = await listEventsFn(company, plan.event_key);
  const starts = existing.filter((row) => row.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.STARTED);
  const terminals = existing.filter((row) => row.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.COMPLETED);
  assert(starts.length <= 1 && terminals.length <= 1, 'epistemic_certificate_custody_fork_detected');

  let startReceipt;
  let reused = 0;
  if (starts[0]) {
    const row = await verifyExisting(starts[0], company, readEventFn,
      EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.STARTED, plan.event_key, null, plan.start_metadata);
    startReceipt = { event_id: row.id, mutation_hash: Buffer.from(row.mutation_hash).toString('hex') };
    reused += 1;
  } else {
    startReceipt = await logEventFn(company, subject,
      EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.STARTED, plan.event_key,
      plan.start_metadata, null, {
        authority: eventAuthority,
        signerConstraint,
        returnReceipt: true,
      });
  }

  const chunkBindings = [];
  for (const chunk of plan.chunks) {
    const metadata = Object.freeze({
      schema: EPISTEMIC_CERTIFICATE_LEDGER_SCHEMA,
      ceremony_id: plan.ceremony_id,
      certificate_sha256: plan.certificate_sha256,
      evidence_root_sha256: plan.evidence_root_sha256,
      stream: chunk.stream,
      chunk_index: chunk.chunk_index,
      row_start: chunk.row_start,
      row_count: chunk.row_count,
      rows_sha256: chunk.rows_sha256,
      rows_json_b64: chunk.rows_json_b64,
      reasoning: 'Housekeeper appended an exact hash-bound ECR transcript chunk; no memory or classification state changed.',
      source_knowledge: 'CERT-ED Findings EMNLP 2024; AIMOS restricted event writer',
    });
    assert(Buffer.byteLength(canonicalJson(metadata), 'utf8') < MAX_EVENT_METADATA_BYTES,
      'epistemic_certificate_chunk_metadata_too_large');
    const matches = existing.filter((row) => {
      if (row.operation !== EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.TRANSCRIPT_CHUNK) return false;
      const actual = parseMetadata(row);
      return actual.stream === chunk.stream && Number(actual.chunk_index) === chunk.chunk_index;
    });
    assert(matches.length <= 1, 'epistemic_certificate_chunk_fork_detected');
    let receipt;
    if (matches[0]) {
      const row = await verifyExisting(matches[0], company, readEventFn,
        EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.TRANSCRIPT_CHUNK,
        plan.event_key, startReceipt.event_id, metadata);
      receipt = { event_id: row.id, mutation_hash: Buffer.from(row.mutation_hash).toString('hex') };
      reused += 1;
    } else {
      receipt = await logEventFn(company, subject,
        EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.TRANSCRIPT_CHUNK,
        plan.event_key, metadata, startReceipt.event_id, {
          authority: eventAuthority,
          signerConstraint,
          returnReceipt: true,
        });
    }
    chunkBindings.push(Object.freeze({
      stream: chunk.stream,
      chunk_index: chunk.chunk_index,
      event_id: receipt.event_id,
      mutation_hash: receipt.mutation_hash,
      rows_sha256: chunk.rows_sha256,
    }));
  }

  const terminalMetadata = Object.freeze({
    schema: EPISTEMIC_CERTIFICATE_LEDGER_SCHEMA,
    ceremony_id: plan.ceremony_id,
    certificate_sha256: plan.certificate_sha256,
    header_sha256: plan.header_sha256,
    evidence_root_sha256: plan.evidence_root_sha256,
    start_event_id: startReceipt.event_id,
    chunk_event_bindings: chunkBindings,
    outcome: portable.outcome,
    selected_class: portable.selected_class,
    radius: portable.radius,
    reasoning: 'Housekeeper completed ECR certificate custody after portable transcript replay verification.',
    source_knowledge: 'CERT-ED Findings EMNLP 2024; RFC 6962; RFC 8032',
  });
  let terminalReceipt;
  if (terminals[0]) {
    const row = await verifyExisting(terminals[0], company, readEventFn,
      EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.COMPLETED,
      plan.event_key, startReceipt.event_id, terminalMetadata);
    terminalReceipt = { event_id: row.id, mutation_hash: Buffer.from(row.mutation_hash).toString('hex') };
    reused += 1;
  } else {
    terminalReceipt = await logEventFn(company, subject,
      EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.COMPLETED,
      plan.event_key, terminalMetadata, startReceipt.event_id, {
        authority: eventAuthority,
        signerConstraint,
        returnReceipt: true,
      });
  }
  return Object.freeze({
    success: true,
    reused,
    appended: 2 + plan.chunks.length - reused,
    plan,
    start_receipt: startReceipt,
    chunk_bindings: Object.freeze(chunkBindings),
    terminal_receipt: terminalReceipt,
    portable_verification: portable,
  });
}

export async function verifyPersistedEpistemicCertificateEvidence({
  companyId,
  terminalEventId,
  memory,
  peers = [],
  expectedClassifierSourceSha256,
  expectedSignedLabel = null,
  expectedBaseDecisionSha256 = null,
} = {}, { readEventFn = readVerifiedEventById } = {}) {
  const company = String(companyId || '').trim();
  assert(company && terminalEventId, 'epistemic_certificate_terminal_scope_required');
  const terminal = await readEventFn(terminalEventId, company);
  assert(terminal.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.COMPLETED,
    'epistemic_certificate_terminal_operation_invalid');
  const terminalMetadata = parseMetadata(terminal);
  assert(terminalMetadata.schema === EPISTEMIC_CERTIFICATE_LEDGER_SCHEMA,
    'epistemic_certificate_terminal_schema_invalid');
  const start = await readEventFn(terminalMetadata.start_event_id, company);
  const startMetadata = parseMetadata(start);
  assert(start.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.STARTED,
    'epistemic_certificate_start_operation_invalid');
  assert(start.key === terminal.key && terminal.parent_event_id === start.id,
    'epistemic_certificate_terminal_binding_invalid');
  assert(startMetadata.evidence_root_sha256 === terminalMetadata.evidence_root_sha256,
    'epistemic_certificate_evidence_root_mismatch');
  const header = decodeJsonBase64(startMetadata.header_json_b64, 'epistemic_certificate_header_invalid');
  assert(sha256Canonical(header) === startMetadata.header_sha256,
    'epistemic_certificate_header_hash_mismatch');

  const streams = { selection: [], certification: [] };
  const observedManifest = [];
  const bindings = terminalMetadata.chunk_event_bindings || [];
  for (const binding of bindings) {
    const row = await readEventFn(binding.event_id, company);
    const metadata = parseMetadata(row);
    assert(row.operation === EPISTEMIC_CERTIFICATE_LEDGER_OPERATIONS.TRANSCRIPT_CHUNK,
      'epistemic_certificate_chunk_operation_invalid');
    assert(row.key === start.key && row.parent_event_id === start.id,
      'epistemic_certificate_chunk_binding_invalid');
    assert(Buffer.from(row.mutation_hash).toString('hex') === binding.mutation_hash,
      'epistemic_certificate_chunk_mutation_mismatch');
    assert(metadata.rows_sha256 === binding.rows_sha256,
      'epistemic_certificate_chunk_root_binding_invalid');
    const rows = decodeJsonBase64(metadata.rows_json_b64, 'epistemic_certificate_chunk_rows_invalid');
    assert(sha256Canonical(rows) === metadata.rows_sha256,
      'epistemic_certificate_chunk_rows_hash_mismatch');
    assert(Array.isArray(streams[metadata.stream]), 'epistemic_certificate_chunk_stream_invalid');
    streams[metadata.stream].push({ index: metadata.chunk_index, start: metadata.row_start, rows });
    observedManifest.push({
      stream: metadata.stream,
      chunk_index: metadata.chunk_index,
      row_start: metadata.row_start,
      row_count: metadata.row_count,
      rows_sha256: metadata.rows_sha256,
    });
  }
  const rebuild = (stream) => stream
    .sort((left, right) => left.index - right.index)
    .flatMap((entry, index, all) => {
      const expectedStart = all.slice(0, index).reduce((sum, item) => sum + item.rows.length, 0);
      assert(entry.start === expectedStart, 'epistemic_certificate_chunk_sequence_invalid');
      return entry.rows;
    });
  const selection = rebuild(streams.selection);
  const certification = rebuild(streams.certification);
  const certificate = {
    schema: header.schema,
    certifier_version: header.certifier_version,
    projection_version: header.projection_version,
    formula_version: header.formula_version,
    input: header.input,
    parameters: header.parameters,
    transcripts: header.transcripts == null ? null : {
      selection,
      certification,
      selection_sha256: header.transcripts.selection_sha256,
      certification_sha256: header.transcripts.certification_sha256,
    },
    decision: header.decision,
    certificate_sha256: terminalMetadata.certificate_sha256,
  };
  if (header.deletion_plan_sha256 != null) {
    certificate.deletion_plan_sha256 = header.deletion_plan_sha256;
  }
  if (header.automatic_policy_activation != null) {
    certificate.automatic_policy_activation = header.automatic_policy_activation;
  }
  const portable = verifyPortableCertificate({
    certificate,
    memory,
    peers,
    expectedClassifierSourceSha256,
    expectedSignedLabel,
    expectedBaseDecisionSha256,
  });
  assert(portable.valid === true, `epistemic_certificate_persisted_portable_invalid:${portable.reason || 'unknown'}`);
  observedManifest.sort((left, right) => {
    const leftStream = left.stream === 'selection' ? 0 : 1;
    const rightStream = right.stream === 'selection' ? 0 : 1;
    return leftStream - rightStream || left.chunk_index - right.chunk_index;
  });
  exactMetadata(observedManifest, startMetadata.chunk_manifest,
    'epistemic_certificate_chunk_manifest_mismatch');
  const reconstructedRoot = sha256Canonical({
    certificate_sha256: certificate.certificate_sha256,
    header_sha256: startMetadata.header_sha256,
    chunks: observedManifest,
  });
  assert(reconstructedRoot === terminalMetadata.evidence_root_sha256,
    'epistemic_certificate_reconstructed_root_mismatch');
  return Object.freeze({
    valid: true,
    certificate,
    portable_verification: portable,
    start_event_id: start.id,
    terminal_event_id: terminal.id,
    chunk_event_ids: Object.freeze(bindings.map((binding) => binding.event_id)),
    evidence_root_sha256: reconstructedRoot,
    chunk_count: bindings.length,
  });
}
