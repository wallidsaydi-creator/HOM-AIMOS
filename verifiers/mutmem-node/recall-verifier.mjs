// Standalone, authority-free MutMem recall/corpus verifier.
//
// This release verifier intentionally imports only Node.js built-ins. It has
// no AIMOS runtime, authority store, filesystem, network, signer, policy, or
// model dependency. All authority is explicit public evidence in the bundle.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export const RECALL_SCHEMA = 'hom.aimos.mutmem-recall-evidence/v1';
export const CORPUS_SCHEMA = 'hom.aimos.mutmem-recall-corpus/v1';
export const VERIFIER_VERSION = '0.1.0';
export const MAX_SAFE_INTEGER = 2 ** 53 - 1;
export const MAX_DEPTH = 32;

const EVENT_LINK_DOMAIN = Buffer.from('AIMOS-EVENT-LINK-v1\0', 'utf8');
const RECALL_LEAF_PREFIX = Buffer.from([0x00]);
const RECALL_NODE_PREFIX = Buffer.from([0x01]);
const RECALL_CORPUS_ROOT_DOMAIN = Buffer.from('aimos.mutmem-recall-corpus/v1\0', 'utf8');
const MASTER_ISSUERS = new Set(['aimos-master']);
const HEX_32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COMMAND_FIELDS = new Set([
  'query', 'q', 'key', 'memory_id', 'company_id', 'agent_id', 'limit',
  'clearance_level', 'memory_type_filter', 'source_filter', 'session_id',
  'project_id', 'workspace_path', 'sort', 'mode', 'selectivity', 'lazy',
  'max_hops', 'projection', 'cache', 'semantic_cache', 'early_exit',
  'debug_recall', 'doctor_trace', 'context_window', 'tokens_used',
  'recall_share', 'summary_token_budget', 'evidence_token_budget',
  'full_detail_token_budget', 'answer_shape', 'requested_shape', 'answer_mode',
  'ts_signed',
]);

export class RecallVerificationError extends Error {}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function jsonNumber(value) {
  if (!Number.isFinite(value)) throw new RecallVerificationError('canonical_json_non_finite_number');
  return JSON.stringify(value);
}

export function canonicalJson(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new RecallVerificationError('canonical_json_depth_limit');
  if (value === null) return 'null';
  if (value === undefined) throw new RecallVerificationError('canonical_json_undefined');
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) && Number.isInteger(value)) {
      throw new RecallVerificationError('canonical_json_integer_out_of_range');
    }
    return jsonNumber(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry, depth + 1)).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`
    )).join(',')}}`;
  }
  throw new RecallVerificationError('canonical_json_type_invalid');
}

function exactObject(value, keys, reason) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) {
    throw new RecallVerificationError(reason);
  }
  return value;
}

function allowedObject(value, required, allowed, reason) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !required.every((key) => Object.hasOwn(value, key))
      || Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new RecallVerificationError(reason);
  }
  return value;
}

function exactHex(value, reason) {
  if (typeof value !== 'string' || !HEX_32.test(value)) throw new RecallVerificationError(reason);
  return Buffer.from(value, 'hex');
}

function b64u(value, reason) {
  if (typeof value !== 'string' || !value) throw new RecallVerificationError(reason);
  try {
    return Buffer.from(value, 'base64url');
  } catch {
    throw new RecallVerificationError(reason);
  }
}

function publicKey(value) {
  try {
    return createPublicKey({ key: b64u(value, 'public_key_invalid'), format: 'der', type: 'spki' });
  } catch {
    throw new RecallVerificationError('public_key_invalid');
  }
}

function verifyRaw(pubkey, message, signature) {
  try {
    return cryptoVerify(null, message, publicKey(pubkey), signature);
  } catch {
    return false;
  }
}

function canonicalSha(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function normalizeInteger(value, fallback, min, max) {
  const parsed = value == null ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new RecallVerificationError('recall_integer_invalid');
  }
  return parsed;
}

export function normalizeRecallCommand(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new RecallVerificationError('recall_command_invalid');
  }
  for (const key of Object.keys(raw)) {
    if (!COMMAND_FIELDS.has(key)) throw new RecallVerificationError(`recall_unknown_field:${key}`);
  }
  const query = String(raw.query ?? raw.q ?? '').trim();
  const key = raw.key == null ? null : String(raw.key).trim();
  const memoryId = raw.memory_id == null ? null : String(raw.memory_id).trim();
  if (!query && !key && !memoryId) throw new RecallVerificationError('recall_query_or_identifier_required');
  if (memoryId && !UUID.test(memoryId)) throw new RecallVerificationError('recall_memory_id_invalid');
  return {
    ...raw,
    query,
    q: query,
    key,
    memory_id: memoryId,
    company_id: raw.company_id == null ? 'hom' : String(raw.company_id),
    agent_id: raw.agent_id == null ? null : String(raw.agent_id),
    limit: normalizeInteger(raw.limit, 10, 1, 200),
    clearance_level: raw.clearance_level == null ? null : normalizeInteger(raw.clearance_level, 1, 0, 12),
    max_hops: raw.max_hops == null ? null : normalizeInteger(raw.max_hops, 2, 1, 4),
  };
}

export function recallMerkleRoot(entries = []) {
  if (!Array.isArray(entries)) throw new RecallVerificationError('recall_entries_invalid');
  const leaves = entries.map((entry) => sha256(Buffer.concat([
    RECALL_LEAF_PREFIX,
    Buffer.from(canonicalJson(entry), 'utf8'),
  ])));
  if (!leaves.length) return sha256(Buffer.alloc(0));
  function tree(nodes) {
    if (nodes.length === 1) return nodes[0];
    let split = 1;
    while ((split << 1) < nodes.length) split <<= 1;
    return sha256(Buffer.concat([
      RECALL_NODE_PREFIX,
      tree(nodes.slice(0, split)),
      tree(nodes.slice(split)),
    ]));
  }
  return tree(leaves);
}

export function recallCorpusRoot(intendedN, members) {
  if (!Number.isSafeInteger(intendedN) || intendedN < 1
      || !Array.isArray(members) || members.length !== intendedN) {
    throw new RecallVerificationError('recall_corpus_intended_n_invalid');
  }
  const seen = new Set();
  const normalized = members.map((member, ordinal) => {
    if (!member || typeof member !== 'object' || Array.isArray(member)
        || member.ordinal !== ordinal || typeof member.bundle_id !== 'string' || !member.bundle_id
        || !HEX_32.test(String(member.bundle_sha256 || '')) || seen.has(member.bundle_id)) {
      throw new RecallVerificationError('recall_corpus_member_invalid');
    }
    seen.add(member.bundle_id);
    return { ordinal, bundle_id: member.bundle_id, bundle_sha256: member.bundle_sha256 };
  });
  const n = Buffer.alloc(8);
  n.writeBigInt64BE(BigInt(intendedN));
  return sha256(Buffer.concat([RECALL_CORPUS_ROOT_DOMAIN, n, recallMerkleRoot(normalized)]));
}

function decodeCertificate(certificate) {
  let envelope;
  let decoded;
  try {
    decoded = b64u(certificate, 'cert_malformed').toString('utf8');
    envelope = JSON.parse(decoded);
  } catch {
    throw new RecallVerificationError('cert_malformed');
  }
  const required = ['v', 'agent_id', 'pubkey', 'device_fp', 'valid_from', 'valid_until', 'issuer', 'issued_at'];
  if (!envelope || typeof envelope !== 'object'
      || Object.keys(envelope).sort().join('\0') !== ['body', 'sig'].join('\0')
      || !envelope.body || typeof envelope.body !== 'object'
      || Object.keys(envelope.body).sort().join('\0') !== [...required].sort().join('\0')
      || typeof envelope.sig !== 'string' || canonicalJson(envelope) !== decoded) {
    throw new RecallVerificationError('cert_schema');
  }
  return envelope;
}

function verifyTrustAnchors(bundle) {
  const anchors = exactObject(bundle.trust_anchors, ['master', 'certificates'], 'recall_trust_anchor_schema_invalid');
  if (anchors.master !== null) {
    exactObject(anchors.master, ['public_key_b64u', 'fingerprint'], 'recall_trust_anchor_schema_invalid');
    if (!HEX_32.test(String(anchors.master.fingerprint || ''))
        || sha256(b64u(anchors.master.public_key_b64u, 'master_key_invalid')).toString('hex') !== anchors.master.fingerprint) {
      throw new RecallVerificationError('recall_trust_anchor_schema_invalid');
    }
  }
  if (!Array.isArray(anchors.certificates) || anchors.certificates.length > 16) {
    throw new RecallVerificationError('recall_trust_anchor_schema_invalid');
  }
  const seen = new Set();
  for (const anchor of anchors.certificates) {
    exactObject(anchor, ['certificate_sha256', 'public_key_b64u'], 'recall_trust_anchor_schema_invalid');
    if (!HEX_32.test(String(anchor.certificate_sha256 || '')) || seen.has(anchor.certificate_sha256)) {
      throw new RecallVerificationError('recall_trust_anchor_schema_invalid');
    }
    publicKey(anchor.public_key_b64u);
    seen.add(anchor.certificate_sha256);
  }
}

function trustedCertificate(bundle, certificate, signedAt) {
  const envelope = decodeCertificate(certificate);
  const body = envelope.body;
  const certSha = sha256(Buffer.from(certificate, 'utf8')).toString('hex');
  let authority = null;
  if (body.issuer === body.agent_id) {
    const anchor = bundle.trust_anchors.certificates.find((entry) => entry.certificate_sha256 === certSha);
    if (anchor?.public_key_b64u === body.pubkey) authority = body.pubkey;
  } else {
    const master = bundle.trust_anchors.master;
    if (master && (MASTER_ISSUERS.has(body.issuer) || body.issuer === master.fingerprint)
        && sha256(b64u(master.public_key_b64u, 'master_key_invalid')).toString('hex') === master.fingerprint) {
      authority = master.public_key_b64u;
    }
  }
  if (!authority) throw new RecallVerificationError('recall_trust_anchor_missing');
  if (!verifyRaw(authority, Buffer.from(canonicalJson(body), 'utf8'), b64u(envelope.sig, 'cert_sig_invalid'))) {
    throw new RecallVerificationError('cert_sig_invalid');
  }
  if (!Number.isSafeInteger(signedAt) || signedAt < body.valid_from || signedAt > body.valid_until) {
    throw new RecallVerificationError('cert_epoch_invalid');
  }
  return { body, certSha };
}

function verifyRequest(bundle) {
  const request = exactObject(bundle.request,
    ['body', 'method', 'path', 'nonce', 'ts_signed', 'signature', 'certificate'],
    'recall_request_schema_invalid');
  if (!request.body || typeof request.body !== 'object' || Array.isArray(request.body)) {
    throw new RecallVerificationError('recall_request_schema_invalid');
  }
  const cert = trustedCertificate(bundle, request.certificate, request.ts_signed);
  if (cert.body.agent_id !== request.body.agent_id) throw new RecallVerificationError('recall_request_identity_invalid');
  if (request.method !== 'POST' || request.path !== '/aimos/recall'
      || request.body.ts_signed !== request.ts_signed || typeof request.nonce !== 'string' || !request.nonce) {
    throw new RecallVerificationError('recall_request_context_invalid');
  }
  const message = `${canonicalJson(request.body)}\nPOST\n/aimos/recall\n${request.nonce}\n${request.ts_signed}`;
  if (!verifyRaw(cert.body.pubkey, Buffer.from(message, 'utf8'), b64u(request.signature, 'recall_request_signature_invalid'))) {
    throw new RecallVerificationError('recall_request_signature_invalid');
  }
  return normalizeRecallCommand(request.body);
}

function verifyEventReceipt(bundle, receipt, expected) {
  const event = receipt.event_receipt;
  if (!event) return { verdict: 'indeterminate', primary_reason: 'recall_mandatory_evidence_missing' };
  exactObject(event, [
    'event_id', 'proof_required', 'ledger_version', 'ledger_seq', 'signed_body',
    'content_hash', 'mutation_hash', 'prev_mutation_hash', 'signer_agent_id',
    'signer_valid_from', 'cert_fingerprint', 'signer_certificate', 'identity_tier',
    'ts_signed', 'nonce', 'signature',
  ], 'recall_event_receipt_schema_invalid');
  const cert = trustedCertificate(bundle, event.signer_certificate, event.ts_signed);
  const body = event.signed_body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new RecallVerificationError('recall_event_body_invalid');
  }
  const content = canonicalSha(body);
  const previous = exactHex(event.prev_mutation_hash, 'recall_event_previous_hash_invalid');
  const mutation = sha256(Buffer.concat([
    EVENT_LINK_DOMAIN, previous, content,
    Buffer.from(String(event.nonce), 'utf8'), Buffer.from(String(event.ts_signed), 'utf8'),
  ]));
  if (event.proof_required !== true || event.ledger_version !== 1 || body.ledger_version !== 1
      || event.event_id !== body.event_id || event.signer_agent_id !== body.signer_agent_id
      || event.signer_valid_from !== body.signer_valid_from || event.ts_signed !== body.ts_signed
      || event.cert_fingerprint !== cert.certSha || event.cert_fingerprint !== body.cert_fingerprint
      || event.content_hash !== content.toString('hex')
      || event.mutation_hash !== mutation.toString('hex')
      || event.prev_mutation_hash !== body.prev_mutation_hash
      || body.company_id !== bundle.company_id || body.operation !== 'recall_receipt'
      || body.key !== expected.commandHash || body.metadata?.command_hash !== expected.commandHash
      || body.metadata?.outer_request_hash !== expected.outerHash
      || body.metadata?.merkle_root !== expected.merkleRoot
      || body.metadata?.result_count !== receipt.evidence.length
      || canonicalJson(body.metadata?.evidence) !== canonicalJson(receipt.evidence)) {
    throw new RecallVerificationError('recall_event_binding_invalid');
  }
  const message = `${canonicalJson(body)}\n${event.nonce}\n${event.ts_signed}`;
  if (!verifyRaw(cert.body.pubkey, Buffer.from(message, 'utf8'), b64u(event.signature, 'recall_event_signature_invalid'))) {
    throw new RecallVerificationError('recall_event_signature_invalid');
  }
  return null;
}

function verifyMemoryBindings(bundle, receipt, command) {
  for (let index = 0; index < bundle.memories.length; index += 1) {
    const memory = bundle.memories[index];
    const evidence = receipt.evidence[index];
    const reason = `recall_receipt_memory_binding_invalid:${index}`;
    exactObject(memory, ['id', 'source', 'memory_type', 'provenance_proof'], reason);
    exactObject(memory.provenance_proof,
      ['live_content_hash', 'save_mutation_hash', 'binding_mutation_hash'], reason);
    exactObject(evidence, [
      'ordinal', 'memory_id', 'live_content_hash', 'save_mutation_hash', 'binding_mutation_hash',
      'truth_state', 'raw_calibration_score', 'calibrated_score', 'calibration_event_id',
      'calibration_mutation_hash', 'calibration_formula_version',
    ], reason);
    if (evidence.ordinal !== index || evidence.memory_id !== memory.id
        || memory.source !== command.source_filter
        || (command.memory_type_filter != null && memory.memory_type !== command.memory_type_filter)
        || evidence.live_content_hash !== memory.provenance_proof.live_content_hash
        || evidence.save_mutation_hash !== memory.provenance_proof.save_mutation_hash
        || evidence.binding_mutation_hash !== memory.provenance_proof.binding_mutation_hash
        || !HEX_32.test(String(evidence.live_content_hash || ''))
        || !HEX_32.test(String(evidence.save_mutation_hash || ''))
        || !HEX_32.test(String(evidence.binding_mutation_hash || ''))) {
      throw new RecallVerificationError(reason);
    }
  }
}

export function verifyRecallBundle(bundle) {
  try {
    if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
      throw new RecallVerificationError('recall_bundle_invalid');
    }
    const expectedKeys = ['bundle_id', 'company_id', 'format', 'memories', 'recall_receipt', 'request', 'trust_anchors'];
    exactObject(bundle, expectedKeys, 'recall_bundle_schema_invalid');
    if (canonicalJson(bundle.format) !== canonicalJson({
      schema: RECALL_SCHEMA, version: 1, authority: 'descriptive_only',
      canonicalization: 'hom-aimos/canonical-json/v1', hash: 'sha256', signature: 'ed25519',
    }) || typeof bundle.bundle_id !== 'string' || !bundle.bundle_id
        || typeof bundle.company_id !== 'string' || !bundle.company_id
        || !Array.isArray(bundle.memories)) {
      throw new RecallVerificationError('recall_bundle_schema_invalid');
    }
    verifyTrustAnchors(bundle);
    const command = verifyRequest(bundle);
    if (command.company_id !== bundle.company_id) throw new RecallVerificationError('recall_scope_binding_invalid');
    const receipt = bundle.recall_receipt;
    if (!receipt || !Array.isArray(receipt.evidence)) {
      return { verdict: 'indeterminate', schema: RECALL_SCHEMA, primary_reason: 'recall_mandatory_evidence_missing' };
    }
    const receiptBase = [
      'command_hash', 'outer_request_hash', 'authority_mutation_hash', 'request_receipt_id',
      'request_receipt_mutation_hash', 'merkle_root', 'evidence',
    ];
    allowedObject(receipt, receiptBase, [
      ...receiptBase, 'event_receipt', 'merkle_schema', 'epistemic_decision_sha256', 'merkle_entries',
    ], 'recall_receipt_schema_invalid');
    if (receipt.evidence.length !== bundle.memories.length) {
      throw new RecallVerificationError('recall_receipt_evidence_count_mismatch');
    }
    verifyMemoryBindings(bundle, receipt, command);
    let merkleEntries = receipt.evidence;
    if (receipt.merkle_schema != null) {
      if (receipt.merkle_schema !== 'hom-aimos/recall-merkle/v2-epistemic-decision'
          || !HEX_32.test(String(receipt.epistemic_decision_sha256 || ''))
          || !Array.isArray(receipt.merkle_entries)
          || receipt.merkle_entries.length !== receipt.evidence.length + 1
          || canonicalJson(receipt.merkle_entries[0]) !== canonicalJson({
            entry_type: 'epistemic_decision', decision_sha256: receipt.epistemic_decision_sha256,
          })
          || canonicalJson(receipt.merkle_entries.slice(1)) !== canonicalJson(receipt.evidence)) {
        throw new RecallVerificationError('recall_receipt_epistemic_binding_invalid');
      }
      merkleEntries = receipt.merkle_entries;
    }
    const commandHash = canonicalSha(command).toString('hex');
    const outerHash = canonicalSha(bundle.request.body).toString('hex');
    const merkleRoot = recallMerkleRoot(merkleEntries).toString('hex');
    if (receipt.command_hash !== commandHash || receipt.outer_request_hash !== outerHash
        || receipt.merkle_root !== merkleRoot
        || !HEX_32.test(String(receipt.authority_mutation_hash || ''))
        || !HEX_32.test(String(receipt.request_receipt_mutation_hash || ''))) {
      throw new RecallVerificationError('recall_receipt_cryptographic_binding_invalid');
    }
    const eventIndeterminate = verifyEventReceipt(bundle, receipt, { commandHash, outerHash, merkleRoot });
    if (eventIndeterminate) return { ...eventIndeterminate, schema: RECALL_SCHEMA };
    return {
      verdict: 'valid', schema: RECALL_SCHEMA, verifier_version: VERIFIER_VERSION,
      primary_reason: null, bundle_sha256: canonicalSha(bundle).toString('hex'),
      command_hash: commandHash, outer_request_hash: outerHash, merkle_root: merkleRoot,
      counts: { memories: bundle.memories.length, recall_leaves: merkleEntries.length },
    };
  } catch (error) {
    return {
      verdict: 'invalid', schema: RECALL_SCHEMA, verifier_version: VERIFIER_VERSION,
      primary_reason: error instanceof RecallVerificationError ? error.message : 'recall_verifier_internal_failure',
    };
  }
}

export function verifyRecallCorpus(corpus) {
  try {
    exactObject(corpus, ['format', 'intended_n', 'members', 'corpus_root'], 'recall_corpus_schema_invalid');
    if (canonicalJson(corpus.format) !== canonicalJson({
      schema: CORPUS_SCHEMA, version: 1, authority: 'descriptive_only',
    }) || !Number.isSafeInteger(corpus.intended_n) || corpus.intended_n < 1
        || !Array.isArray(corpus.members) || corpus.members.length !== corpus.intended_n) {
      throw new RecallVerificationError('recall_corpus_intended_n_invalid');
    }
    const summaries = [];
    const verdicts = [];
    const seen = new Set();
    for (let ordinal = 0; ordinal < corpus.members.length; ordinal += 1) {
      const member = corpus.members[ordinal];
      exactObject(member, ['ordinal', 'bundle_id', 'bundle_sha256', 'bundle'], 'recall_corpus_member_invalid');
      const actualHash = canonicalSha(member.bundle).toString('hex');
      if (member.ordinal !== ordinal || member.bundle_id !== member.bundle?.bundle_id
          || !member.bundle_id || seen.has(member.bundle_id)
          || member.bundle_sha256 !== actualHash) {
        throw new RecallVerificationError('recall_corpus_member_invalid');
      }
      seen.add(member.bundle_id);
      const verdict = verifyRecallBundle(member.bundle);
      verdicts.push({ ordinal, bundle_id: member.bundle_id, verdict: verdict.verdict, primary_reason: verdict.primary_reason });
      summaries.push({ ordinal, bundle_id: member.bundle_id, bundle_sha256: actualHash });
    }
    const root = recallCorpusRoot(corpus.intended_n, summaries).toString('hex');
    if (corpus.corpus_root !== root) throw new RecallVerificationError('recall_corpus_root_mismatch');
    const invalid = verdicts.find((entry) => entry.verdict === 'invalid');
    const indeterminate = verdicts.find((entry) => entry.verdict === 'indeterminate');
    return {
      verdict: invalid ? 'invalid' : indeterminate ? 'indeterminate' : 'valid',
      schema: CORPUS_SCHEMA, verifier_version: VERIFIER_VERSION,
      primary_reason: invalid?.primary_reason || indeterminate?.primary_reason || null,
      intended_n: corpus.intended_n, observed_n: corpus.members.length,
      corpus_root: root, members: verdicts,
    };
  } catch (error) {
    return {
      verdict: 'invalid', schema: CORPUS_SCHEMA, verifier_version: VERIFIER_VERSION,
      primary_reason: error instanceof RecallVerificationError ? error.message : 'recall_verifier_internal_failure',
    };
  }
}
