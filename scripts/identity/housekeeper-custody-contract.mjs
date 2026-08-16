import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
} from 'node:crypto';

import {
  canonicalJson,
  issueCert,
  pubkeyEquals,
  pubkeyFingerprint,
  signPayload,
  verifyCertChain,
  verifyStoredPayloadSig,
} from '../../services/security/agent-identity.js';
import {
  eventGenesisHash,
  eventMutationHash,
} from '../../services/security/protocol/mutmem-protocol.js';

export const HOUSEKEEPER_CUSTODY = Object.freeze({
  AGENT_ID: 'housekeeper',
  MASTER_ACTOR_ID: 'aimos-master',
  COMPANY_ID: 'hom',
  CERTIFICATE_VALID_UNTIL: 253402300799,
  TRANSITION_SCHEMA: 'hom.aimos.housekeeper-custody-transition/v1',
  APPROVAL_SCHEMA: 'hom.aimos.housekeeper-custody-approval/v1',
  RECEIPT_SCHEMA: 'hom.aimos.housekeeper-custody-receipt/v1',
  EVENT_METADATA_SCHEMA: 'hom.aimos.housekeeper-custody-event/v1',
  EVENT_OPERATION: 'housekeeper_custody_promoted',
  AUTHORITY_SCOPE: 'housekeeper_certificate_custody_promotion_only',
  SIGNED_METHOD: 'CEREMONY',
  SIGNED_PATH: '/identity/housekeeper/custody-promotion',
});

function fail(code, detail = '') {
  throw new Error(`housekeeper_custody_${code}${detail ? `:${detail}` : ''}`);
}

function assert(condition, code, detail = '') {
  if (!condition) fail(code, detail);
}

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function decodeCertificate(certString) {
  try {
    const envelope = JSON.parse(Buffer.from(String(certString || ''), 'base64url').toString('utf8'));
    assert(envelope && typeof envelope === 'object' && envelope.body && typeof envelope.sig === 'string',
      'certificate_malformed');
    return envelope;
  } catch (error) {
    if (String(error?.message || '').startsWith('housekeeper_custody_')) throw error;
    fail('certificate_malformed');
  }
}

export function publicKeyFromPrivate(privateKeyB64u) {
  try {
    const privateKey = createPrivateKey({
      key: Buffer.from(String(privateKeyB64u || ''), 'base64url'),
      format: 'der',
      type: 'pkcs8',
    });
    return createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  } catch {
    fail('private_key_malformed');
  }
}

function certificateSummary(certString) {
  const body = decodeCertificate(certString).body;
  return Object.freeze({
    agent_id: body.agent_id,
    issuer: body.issuer,
    valid_from: Number(body.valid_from),
    valid_until: Number(body.valid_until),
    pubkey: body.pubkey,
    pubkey_fingerprint: pubkeyFingerprint(body.pubkey),
    device_fp: body.device_fp,
    device_fp_sha256: sha256Hex(Buffer.from(String(body.device_fp), 'utf8')),
    certificate_sha256: sha256Hex(Buffer.from(String(certString), 'utf8')),
  });
}

export function buildSuccessorCertificateBody({ predecessorCert, validFrom } = {}) {
  const predecessor = certificateSummary(predecessorCert);
  const issuedAt = Number(validFrom);
  assert(predecessor.agent_id === HOUSEKEEPER_CUSTODY.AGENT_ID, 'predecessor_agent_invalid');
  assert(Number.isSafeInteger(issuedAt) && issuedAt > predecessor.valid_from,
    'successor_epoch_not_ordered');
  return Object.freeze({
    v: 1,
    agent_id: HOUSEKEEPER_CUSTODY.AGENT_ID,
    pubkey: predecessor.pubkey,
    device_fp: predecessor.device_fp,
    valid_from: issuedAt,
    valid_until: HOUSEKEEPER_CUSTODY.CERTIFICATE_VALID_UNTIL,
    issuer: HOUSEKEEPER_CUSTODY.MASTER_ACTOR_ID,
    issued_at: issuedAt,
  });
}

export function issueHousekeeperSuccessorCertificate({
  predecessorCert,
  validFrom,
  masterPrivkeyB64u,
  masterPubkeyB64u,
} = {}) {
  const derivedMaster = publicKeyFromPrivate(masterPrivkeyB64u);
  assert(pubkeyEquals(derivedMaster, masterPubkeyB64u), 'master_private_key_mismatch');
  const body = buildSuccessorCertificateBody({ predecessorCert, validFrom });
  const certificate = issueCert(masterPrivkeyB64u, body);
  const proof = verifyCertChain(certificate, masterPubkeyB64u, { nowFn: () => validFrom });
  assert(proof.valid === true, 'successor_certificate_self_check_failed', proof.reason || 'unknown');
  return Object.freeze({ certificate, body });
}

export function verifyHousekeeperCustodyContinuity({
  predecessorCert,
  successorCert,
  masterPubkeyB64u,
  expectedMasterFingerprint,
  now,
} = {}) {
  const predecessor = certificateSummary(predecessorCert);
  const successor = certificateSummary(successorCert);
  const observedNow = Number.isSafeInteger(now) ? now : successor.valid_from;
  assert(pubkeyFingerprint(masterPubkeyB64u) === expectedMasterFingerprint,
    'master_fingerprint_mismatch');
  assert(predecessor.agent_id === HOUSEKEEPER_CUSTODY.AGENT_ID
    && successor.agent_id === HOUSEKEEPER_CUSTODY.AGENT_ID,
  'certificate_agent_invalid');
  assert(predecessor.issuer === HOUSEKEEPER_CUSTODY.AGENT_ID,
    'predecessor_not_genesis_self_signed');
  assert(successor.issuer === HOUSEKEEPER_CUSTODY.MASTER_ACTOR_ID,
    'successor_not_master_signed');
  const predecessorProof = verifyCertChain(predecessorCert, predecessor.pubkey, {
    nowFn: () => predecessor.valid_from,
  });
  const successorProof = verifyCertChain(successorCert, masterPubkeyB64u, {
    nowFn: () => observedNow,
  });
  assert(predecessorProof.valid === true, 'predecessor_certificate_invalid', predecessorProof.reason || 'unknown');
  assert(successorProof.valid === true, 'successor_certificate_invalid', successorProof.reason || 'unknown');
  assert(pubkeyEquals(predecessor.pubkey, successor.pubkey), 'stable_key_continuity_broken');
  assert(predecessor.device_fp === successor.device_fp, 'device_binding_changed');
  assert(successor.valid_from > predecessor.valid_from, 'successor_epoch_not_ordered');
  assert(successor.valid_until === HOUSEKEEPER_CUSTODY.CERTIFICATE_VALID_UNTIL,
    'successor_validity_invalid');
  return Object.freeze({ valid: true, predecessor, successor });
}

export function buildHousekeeperCustodyApprovalBody({
  predecessorCert,
  successorCert,
  masterFingerprint,
  masterEpoch,
  reason,
  signedTs,
} = {}) {
  const predecessor = certificateSummary(predecessorCert);
  const successor = certificateSummary(successorCert);
  const timestamp = Number(signedTs);
  const normalizedReason = String(reason || '').trim();
  assert(/^[0-9a-f]{64}$/.test(String(masterFingerprint || '')), 'master_fingerprint_invalid');
  assert(Number.isSafeInteger(timestamp) && timestamp === successor.valid_from,
    'approval_timestamp_invalid');
  assert(normalizedReason.length >= 24 && normalizedReason.length <= 1000, 'approval_reason_invalid');
  return Object.freeze({
    schema: HOUSEKEEPER_CUSTODY.TRANSITION_SCHEMA,
    event_type: 'PROMOTE_HOUSEKEEPER_CUSTODY',
    company_id: HOUSEKEEPER_CUSTODY.COMPANY_ID,
    subject_agent_id: HOUSEKEEPER_CUSTODY.AGENT_ID,
    authority_scope: HOUSEKEEPER_CUSTODY.AUTHORITY_SCOPE,
    master_fingerprint: masterFingerprint,
    master_epoch: new Date(masterEpoch).toISOString(),
    predecessor: Object.freeze({
      certificate_sha256: predecessor.certificate_sha256,
      valid_from: new Date(predecessor.valid_from * 1000).toISOString(),
      valid_until: new Date(predecessor.valid_until * 1000).toISOString(),
      issuer: predecessor.issuer,
      pubkey_fingerprint: predecessor.pubkey_fingerprint,
      device_fp_sha256: predecessor.device_fp_sha256,
    }),
    successor: Object.freeze({
      certificate_sha256: successor.certificate_sha256,
      valid_from: new Date(successor.valid_from * 1000).toISOString(),
      valid_until: new Date(successor.valid_until * 1000).toISOString(),
      issuer: successor.issuer,
      pubkey_fingerprint: successor.pubkey_fingerprint,
      device_fp_sha256: successor.device_fp_sha256,
    }),
    stable_key_reused: true,
    key_file_modified: false,
    genesis_certificate_retained: true,
    automatic_policy_activation: false,
    save_authority: false,
    recall_authority: false,
    ranking_authority: false,
    memory_mutation_authority: false,
    reason: normalizedReason,
    ts_signed: timestamp,
  });
}

export function createHousekeeperCustodyApproval({
  body,
  masterPrivkeyB64u,
  masterPubkeyB64u,
  nonce = randomBytes(16).toString('base64url'),
} = {}) {
  const derivedMaster = publicKeyFromPrivate(masterPrivkeyB64u);
  assert(pubkeyEquals(derivedMaster, masterPubkeyB64u), 'master_private_key_mismatch');
  const tsSigned = Number(body?.ts_signed);
  const signature = signPayload(masterPrivkeyB64u, body, nonce, tsSigned);
  const approval = {
    schema: HOUSEKEEPER_CUSTODY.APPROVAL_SCHEMA,
    body,
    nonce,
    ts_signed: tsSigned,
    signature,
  };
  approval.approval_sha256 = sha256Hex(Buffer.from(canonicalJson(approval), 'utf8'));
  return Object.freeze(approval);
}

export function verifyHousekeeperCustodyApproval(approval, {
  predecessorCert,
  successorCert,
  masterPubkeyB64u,
  expectedMasterFingerprint,
} = {}) {
  try {
    assert(approval?.schema === HOUSEKEEPER_CUSTODY.APPROVAL_SCHEMA, 'approval_schema_invalid');
    const body = approval.body;
    const approvalWithoutHash = {
      schema: approval.schema,
      body,
      nonce: approval.nonce,
      ts_signed: approval.ts_signed,
      signature: approval.signature,
    };
    assert(sha256Hex(Buffer.from(canonicalJson(approvalWithoutHash), 'utf8')) === approval.approval_sha256,
      'approval_hash_invalid');
    const continuity = verifyHousekeeperCustodyContinuity({
      predecessorCert,
      successorCert,
      masterPubkeyB64u,
      expectedMasterFingerprint,
      now: Number(approval.ts_signed),
    });
    assert(body?.schema === HOUSEKEEPER_CUSTODY.TRANSITION_SCHEMA
      && body.event_type === 'PROMOTE_HOUSEKEEPER_CUSTODY'
      && body.company_id === HOUSEKEEPER_CUSTODY.COMPANY_ID
      && body.subject_agent_id === HOUSEKEEPER_CUSTODY.AGENT_ID
      && body.authority_scope === HOUSEKEEPER_CUSTODY.AUTHORITY_SCOPE
      && body.master_fingerprint === expectedMasterFingerprint
      && body.predecessor?.certificate_sha256 === continuity.predecessor.certificate_sha256
      && body.successor?.certificate_sha256 === continuity.successor.certificate_sha256
      && body.predecessor?.pubkey_fingerprint === continuity.predecessor.pubkey_fingerprint
      && body.successor?.pubkey_fingerprint === continuity.successor.pubkey_fingerprint
      && body.predecessor?.device_fp_sha256 === continuity.predecessor.device_fp_sha256
      && body.successor?.device_fp_sha256 === continuity.successor.device_fp_sha256
      && body.stable_key_reused === true
      && body.key_file_modified === false
      && body.genesis_certificate_retained === true
      && body.automatic_policy_activation === false
      && body.save_authority === false
      && body.recall_authority === false
      && body.ranking_authority === false
      && body.memory_mutation_authority === false
      && Number(body.ts_signed) === Number(approval.ts_signed),
    'approval_body_invalid');
    const signature = verifyStoredPayloadSig(
      masterPubkeyB64u,
      body,
      approval.nonce,
      Number(approval.ts_signed),
      approval.signature,
    );
    assert(signature.valid === true, 'approval_signature_invalid', signature.reason || 'unknown');
    return Object.freeze({ valid: true, continuity });
  } catch (error) {
    return Object.freeze({ valid: false, reason: String(error?.message || error) });
  }
}

export function housekeeperCustodyAuthorityContext(approval) {
  return Object.freeze({
    actorAgentId: HOUSEKEEPER_CUSTODY.MASTER_ACTOR_ID,
    actorValidFromIso: approval.body.master_epoch,
    requestSigForm: 1,
    signedMethod: HOUSEKEEPER_CUSTODY.SIGNED_METHOD,
    signedPath: HOUSEKEEPER_CUSTODY.SIGNED_PATH,
    signedTs: approval.ts_signed,
    nonce: approval.nonce,
    sigBytes: Buffer.from(approval.signature, 'base64url'),
  });
}

export function housekeeperCustodyAuthorityDigest(approval) {
  const authority = housekeeperCustodyAuthorityContext(approval);
  const body = {
    actor_agent_id: authority.actorAgentId,
    actor_valid_from: authority.actorValidFromIso,
    request_sig_form: authority.requestSigForm,
    signed_method: authority.signedMethod,
    signed_path: authority.signedPath,
    signed_ts: authority.signedTs,
    nonce: authority.nonce,
    cert_fingerprint: null,
    signature_hash: sha256Hex(authority.sigBytes),
  };
  return sha256Hex(Buffer.from(canonicalJson(body), 'utf8'));
}

export function buildHousekeeperCustodyEventMetadata(approval) {
  return Object.freeze({
    schema: HOUSEKEEPER_CUSTODY.EVENT_METADATA_SCHEMA,
    authority_scope: HOUSEKEEPER_CUSTODY.AUTHORITY_SCOPE,
    master_approval: approval,
    master_approval_sha256: approval.approval_sha256,
    predecessor_certificate_sha256: approval.body.predecessor.certificate_sha256,
    successor_certificate_sha256: approval.body.successor.certificate_sha256,
    stable_key_reused: true,
    key_file_modified: false,
    genesis_certificate_retained: true,
    automatic_policy_activation: false,
    reasoning: 'The operator master promotes custody of the existing housekeeper key to a master-signed certificate while retaining the Genesis certificate and signed history.',
  });
}

export function verifyHousekeeperCustodyReceipt(receipt) {
  try {
    assert(receipt?.schema === HOUSEKEEPER_CUSTODY.RECEIPT_SCHEMA, 'receipt_schema_invalid');
    const approval = receipt.master_approval;
    const event = receipt.housekeeper_event;
    const approvalProof = verifyHousekeeperCustodyApproval(approval, {
      predecessorCert: receipt.predecessor_certificate,
      successorCert: receipt.successor_certificate,
      masterPubkeyB64u: receipt.master_public_key,
      expectedMasterFingerprint: receipt.master_fingerprint,
    });
    assert(approvalProof.valid === true, 'receipt_approval_invalid', approvalProof.reason || 'unknown');
    const continuity = approvalProof.continuity;
    assert(receipt.master_fingerprint === approval.body.master_fingerprint
      && event.signer_agent_id === HOUSEKEEPER_CUSTODY.AGENT_ID
      && new Date(event.signer_valid_from).toISOString()
        === new Date(continuity.successor.valid_from * 1000).toISOString()
      && event.signer_certificate === receipt.successor_certificate
      && event.cert_fingerprint === continuity.successor.certificate_sha256
      && event.identity_tier === 'T1'
      && Number(event.ledger_seq) === 1,
    'receipt_signer_invalid');
    const expectedMetadata = buildHousekeeperCustodyEventMetadata(approval);
    const body = event.signed_body;
    assert(body?.company_id === HOUSEKEEPER_CUSTODY.COMPANY_ID
      && body.subject_agent_id === HOUSEKEEPER_CUSTODY.AGENT_ID
      && body.actor_agent_id === HOUSEKEEPER_CUSTODY.MASTER_ACTOR_ID
      && body.actor_valid_from === approval.body.master_epoch
      && body.signer_agent_id === HOUSEKEEPER_CUSTODY.AGENT_ID
      && body.operation === HOUSEKEEPER_CUSTODY.EVENT_OPERATION
      && body.key === continuity.successor.certificate_sha256
      && body.authority_kind === 'housekeeper_observation_of_verified_request'
      && body.request_envelope_digest === housekeeperCustodyAuthorityDigest(approval)
      && canonicalJson(body.metadata) === canonicalJson(expectedMetadata)
      && Number(body.ts_signed) === Number(event.ts_signed),
    'receipt_event_body_invalid');
    const genesis = eventGenesisHash(
      HOUSEKEEPER_CUSTODY.COMPANY_ID,
      HOUSEKEEPER_CUSTODY.AGENT_ID,
      event.signer_valid_from,
    );
    assert(event.prev_mutation_hash === genesis.toString('hex'), 'receipt_event_genesis_invalid');
    const contentHash = createHash('sha256').update(Buffer.from(canonicalJson(body), 'utf8')).digest();
    const mutationHash = eventMutationHash(
      genesis,
      contentHash,
      event.nonce,
      Number(event.ts_signed),
    );
    assert(event.content_hash === contentHash.toString('hex')
      && event.mutation_hash === mutationHash.toString('hex'),
    'receipt_event_hash_invalid');
    const signature = verifyStoredPayloadSig(
      continuity.successor.pubkey,
      body,
      event.nonce,
      Number(event.ts_signed),
      event.signature,
    );
    assert(signature.valid === true, 'receipt_event_signature_invalid', signature.reason || 'unknown');
    return Object.freeze({
      valid: true,
      predecessor_certificate_sha256: continuity.predecessor.certificate_sha256,
      successor_certificate_sha256: continuity.successor.certificate_sha256,
      event_id: event.event_id,
      mutation_hash: event.mutation_hash,
    });
  } catch (error) {
    return Object.freeze({ valid: false, reason: String(error?.message || error) });
  }
}
