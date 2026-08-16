#!/usr/bin/env node

/** Standalone housekeeper-custody receipt verifier. Node built-ins only. */

import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from 'node:crypto';
import fs from 'node:fs';

const C = Object.freeze({
  agent: 'housekeeper',
  masterActor: 'aimos-master',
  company: 'hom',
  validUntil: 253402300799,
  approvalSchema: 'hom.aimos.housekeeper-custody-approval/v1',
  transitionSchema: 'hom.aimos.housekeeper-custody-transition/v1',
  receiptSchema: 'hom.aimos.housekeeper-custody-receipt/v1',
  metadataSchema: 'hom.aimos.housekeeper-custody-event/v1',
  operation: 'housekeeper_custody_promoted',
  scope: 'housekeeper_certificate_custody_promotion_only',
  method: 'CEREMONY',
  path: '/identity/housekeeper/custody-promotion',
});

function fail(code) { throw new Error(code); }
function assert(value, code) { if (!value) fail(code); }
function sha256(value) { return createHash('sha256').update(value).digest(); }
function sha256Hex(value) { return sha256(value).toString('hex'); }

function canonicalJson(value, depth = 0) {
  if (depth > 32) fail('canonical_depth');
  if (value === null) return 'null';
  if (value === undefined) fail('canonical_undefined');
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    assert(Number.isFinite(value), 'canonical_number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry, depth + 1)).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`).join(',')}}`;
  }
  fail('canonical_type');
}

function stableReadJson(filename) {
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    assert(before.isFile(), 'receipt_not_regular');
    for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
      assert(before[field] === after[field], 'receipt_changed');
    }
    return JSON.parse(bytes.toString('utf8'));
  } finally {
    fs.closeSync(descriptor);
  }
}

function loadPublic(pubkey) {
  return createPublicKey({
    key: Buffer.from(String(pubkey || ''), 'base64url'),
    format: 'der',
    type: 'spki',
  });
}

function pubkeyFingerprint(pubkey) {
  return sha256Hex(Buffer.from(String(pubkey), 'base64url'));
}

function verifySignature(pubkey, message, signature) {
  try {
    return cryptoVerify(null, Buffer.from(message, 'utf8'), loadPublic(pubkey), Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

function decodeCert(cert) {
  const envelope = JSON.parse(Buffer.from(String(cert || ''), 'base64url').toString('utf8'));
  assert(envelope?.body && typeof envelope.sig === 'string', 'certificate_malformed');
  return envelope;
}

function verifyCert(cert, authority, at) {
  const envelope = decodeCert(cert);
  assert(verifySignature(authority, canonicalJson(envelope.body), envelope.sig), 'certificate_signature');
  assert(Number(at) >= Number(envelope.body.valid_from)
    && Number(at) <= Number(envelope.body.valid_until), 'certificate_validity');
  return envelope.body;
}

function eventGenesisHash(signerValidFrom) {
  return sha256(Buffer.concat([
    Buffer.from('aimos-event-genesis/v1\0', 'utf8'),
    Buffer.from(C.company, 'utf8'), Buffer.from('\0', 'utf8'),
    Buffer.from(C.agent, 'utf8'), Buffer.from('\0', 'utf8'),
    Buffer.from(new Date(signerValidFrom).toISOString(), 'utf8'),
  ]));
}

function eventMutationHash(previous, content, nonce, timestamp) {
  return sha256(Buffer.concat([
    Buffer.from('AIMOS-EVENT-LINK-v1\0', 'utf8'),
    previous,
    content,
    Buffer.from(String(nonce), 'utf8'),
    Buffer.from(String(timestamp), 'utf8'),
  ]));
}

function authorityDigest(approval) {
  const body = {
    actor_agent_id: C.masterActor,
    actor_valid_from: approval.body.master_epoch,
    request_sig_form: 1,
    signed_method: C.method,
    signed_path: C.path,
    signed_ts: approval.ts_signed,
    nonce: approval.nonce,
    cert_fingerprint: null,
    signature_hash: sha256Hex(Buffer.from(approval.signature, 'base64url')),
  };
  return sha256Hex(Buffer.from(canonicalJson(body), 'utf8'));
}

function verify(receipt) {
  assert(receipt?.schema === C.receiptSchema, 'receipt_schema');
  assert(pubkeyFingerprint(receipt.master_public_key) === receipt.master_fingerprint,
    'master_fingerprint');
  const predecessorEnvelope = decodeCert(receipt.predecessor_certificate);
  const successorEnvelope = decodeCert(receipt.successor_certificate);
  const predecessor = verifyCert(
    receipt.predecessor_certificate,
    predecessorEnvelope.body.pubkey,
    predecessorEnvelope.body.valid_from,
  );
  const approval = receipt.master_approval;
  const successor = verifyCert(
    receipt.successor_certificate,
    receipt.master_public_key,
    approval.ts_signed,
  );
  assert(predecessor.agent_id === C.agent && predecessor.issuer === C.agent,
    'predecessor_identity');
  assert(successor.agent_id === C.agent && successor.issuer === C.masterActor,
    'successor_identity');
  assert(predecessor.pubkey === successor.pubkey, 'stable_key_continuity');
  assert(predecessor.device_fp === successor.device_fp, 'device_continuity');
  assert(Number(successor.valid_from) > Number(predecessor.valid_from), 'epoch_order');
  assert(Number(successor.valid_until) === C.validUntil, 'successor_validity');

  assert(approval?.schema === C.approvalSchema, 'approval_schema');
  const approvalWithoutHash = {
    schema: approval.schema,
    body: approval.body,
    nonce: approval.nonce,
    ts_signed: approval.ts_signed,
    signature: approval.signature,
  };
  assert(sha256Hex(Buffer.from(canonicalJson(approvalWithoutHash), 'utf8')) === approval.approval_sha256,
    'approval_hash');
  assert(verifySignature(
    receipt.master_public_key,
    `${canonicalJson(approval.body)}\n${approval.nonce}\n${approval.ts_signed}`,
    approval.signature,
  ), 'approval_signature');
  const predecessorSha = sha256Hex(Buffer.from(receipt.predecessor_certificate, 'utf8'));
  const successorSha = sha256Hex(Buffer.from(receipt.successor_certificate, 'utf8'));
  const predecessorFp = pubkeyFingerprint(predecessor.pubkey);
  const successorFp = pubkeyFingerprint(successor.pubkey);
  const predecessorDevice = sha256Hex(Buffer.from(predecessor.device_fp, 'utf8'));
  const successorDevice = sha256Hex(Buffer.from(successor.device_fp, 'utf8'));
  const body = approval.body;
  assert(body?.schema === C.transitionSchema
    && body.event_type === 'PROMOTE_HOUSEKEEPER_CUSTODY'
    && body.company_id === C.company
    && body.subject_agent_id === C.agent
    && body.authority_scope === C.scope
    && body.master_fingerprint === receipt.master_fingerprint
    && body.predecessor?.certificate_sha256 === predecessorSha
    && body.successor?.certificate_sha256 === successorSha
    && body.predecessor?.pubkey_fingerprint === predecessorFp
    && body.successor?.pubkey_fingerprint === successorFp
    && body.predecessor?.device_fp_sha256 === predecessorDevice
    && body.successor?.device_fp_sha256 === successorDevice
    && body.stable_key_reused === true
    && body.key_file_modified === false
    && body.genesis_certificate_retained === true
    && body.automatic_policy_activation === false
    && body.save_authority === false
    && body.recall_authority === false
    && body.ranking_authority === false
    && body.memory_mutation_authority === false
    && Number(body.ts_signed) === Number(approval.ts_signed), 'approval_body');

  const expectedMetadata = {
    schema: C.metadataSchema,
    authority_scope: C.scope,
    master_approval: approval,
    master_approval_sha256: approval.approval_sha256,
    predecessor_certificate_sha256: predecessorSha,
    successor_certificate_sha256: successorSha,
    stable_key_reused: true,
    key_file_modified: false,
    genesis_certificate_retained: true,
    automatic_policy_activation: false,
    reasoning: 'The operator master promotes custody of the existing housekeeper key to a master-signed certificate while retaining the Genesis certificate and signed history.',
  };
  const event = receipt.housekeeper_event;
  const eventBody = event.signed_body;
  assert(event.signer_agent_id === C.agent
    && event.signer_valid_from === new Date(Number(successor.valid_from) * 1000).toISOString()
    && event.signer_certificate === receipt.successor_certificate
    && event.cert_fingerprint === successorSha
    && event.identity_tier === 'T1'
    && Number(event.ledger_seq) === 1, 'event_signer');
  assert(eventBody?.company_id === C.company
    && eventBody.subject_agent_id === C.agent
    && eventBody.actor_agent_id === C.masterActor
    && eventBody.actor_valid_from === body.master_epoch
    && eventBody.signer_agent_id === C.agent
    && eventBody.operation === C.operation
    && eventBody.key === successorSha
    && eventBody.authority_kind === 'housekeeper_observation_of_verified_request'
    && eventBody.request_envelope_digest === authorityDigest(approval)
    && canonicalJson(eventBody.metadata) === canonicalJson(expectedMetadata)
    && Number(eventBody.ts_signed) === Number(event.ts_signed), 'event_body');
  const genesis = eventGenesisHash(event.signer_valid_from);
  assert(event.prev_mutation_hash === genesis.toString('hex'), 'event_genesis');
  const content = sha256(Buffer.from(canonicalJson(eventBody), 'utf8'));
  const mutation = eventMutationHash(genesis, content, event.nonce, Number(event.ts_signed));
  assert(event.content_hash === content.toString('hex')
    && event.mutation_hash === mutation.toString('hex'), 'event_hash');
  assert(verifySignature(
    successor.pubkey,
    `${canonicalJson(eventBody)}\n${event.nonce}\n${event.ts_signed}`,
    event.signature,
  ), 'event_signature');
  return {
    valid: true,
    predecessor_certificate_sha256: predecessorSha,
    successor_certificate_sha256: successorSha,
    event_id: event.event_id,
    mutation_hash: event.mutation_hash,
  };
}

function argument(name) {
  const inline = process.argv.find((entry) => entry.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

try {
  const filename = argument('--receipt') || process.argv[2];
  assert(filename, 'receipt_path_required');
  console.log(JSON.stringify(verify(stableReadJson(filename)), null, 2));
} catch (error) {
  console.error(JSON.stringify({ valid: false, reason: String(error?.message || error) }, null, 2));
  process.exitCode = 1;
}
