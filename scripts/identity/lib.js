// scripts/identity/lib.js
// Phase 2B — pure enrollment logic. Takes injected `keychain` and `db` deps.
// No I/O of its own except OS introspection for device fingerprint.
// Tested in tests/enrollment-test.js with mocked deps.

import {
  generateKeypair,
  issueCert,
  verifyCertChain,
  pubkeyFingerprint,
  createAgentRevocationProof,
  verifyAgentRevocationProof,
} from '../../services/security/agent-identity.js';
import {
  scryptSync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import os from 'node:os';

// ─── Master privkey at-rest encryption ───────────────────────────────────────
// AES-256-GCM, key derived via scrypt from user passphrase.
// scrypt params: N=2^16, r=8, p=1, keylen=32 — interactive-grade.
//   Memory cost = 128 * N * r = 64 MiB. Time on Apple Silicon ~150ms.
//   maxmem must be raised above Node's 32 MiB default (we set 128 MiB).
// Blob layout (binary): [salt(16) || nonce(12) || ciphertext(N) || authTag(16)]
// Returned and stored as base64url.

const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const SCRYPT_N = 1 << 16;
const SCRYPT_r = 8;
const SCRYPT_p = 1;
const SCRYPT_MAXMEM = 128 * 1024 * 1024;
const KEY_BYTES = 32;
const SCRYPT_OPTS = { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p, maxmem: SCRYPT_MAXMEM };

export function encryptMasterPrivkey(passphrase, privkeyB64u) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('encryptMasterPrivkey: passphrase required');
  }
  const salt = randomBytes(SALT_BYTES);
  const key = scryptSync(passphrase, salt, KEY_BYTES, SCRYPT_OPTS);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(privkeyB64u, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, nonce, ct, tag]).toString('base64url');
}

export function decryptMasterPrivkey(passphrase, blobB64u) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) return null;
  let blob;
  try { blob = Buffer.from(blobB64u, 'base64url'); }
  catch { return null; }
  if (blob.length < SALT_BYTES + NONCE_BYTES + TAG_BYTES + 1) return null;

  const salt = blob.subarray(0, SALT_BYTES);
  const nonce = blob.subarray(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
  const tag = blob.subarray(blob.length - TAG_BYTES);
  const ct = blob.subarray(SALT_BYTES + NONCE_BYTES, blob.length - TAG_BYTES);
  const key = scryptSync(passphrase, salt, KEY_BYTES, SCRYPT_OPTS);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  try {
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString('utf8');
  } catch {
    return null; // wrong passphrase or tampered blob
  }
}

// ─── Device fingerprint ──────────────────────────────────────────────────────
// SHA-256 over (machine_uuid || brain_root_path || hostname || os_build).
// All four components are stable across reboots; change one and the device
// re-enrollment is forced. Hostname change triggers re-enrollment by design.

export function computeDeviceFp(brainRoot) {
  let machineUuid = '';
  try {
    const out = execFileSync('ioreg', ['-d2', '-c', 'IOPlatformExpertDevice'], { encoding: 'utf8' });
    const m = out.match(/IOPlatformUUID"\s*=\s*"([^"]+)"/);
    if (m) machineUuid = m[1];
  } catch { /* leave empty */ }

  const hostname = os.hostname();

  let osBuild = '';
  try {
    osBuild = execFileSync('sw_vers', ['-buildVersion'], { encoding: 'utf8' }).trim();
  } catch { /* leave empty */ }

  const composite = [machineUuid, brainRoot, hostname, osBuild].join('|');
  return createHash('sha256').update(composite).digest('hex');
}

// ─── Enrollment operations (dependency-injected) ─────────────────────────────
// deps shape:
//   { keychain: { get(svc, acct), set(svc, acct, val), delete(svc, acct) },
//     db:       { getMaster(), insertMaster(pubkey, fp),
//                 getAgent(id), insertAgent(row), revokeAgent(id) },
//     kcService: 'aimos.master',
//     kcAccount: '<your_keychain_account>',
//     brainRoot: '/Users/.../backend/brain' }

export async function enrollMasterWithDeps(passphrase, deps) {
  const existing = await deps.db.getMaster();
  if (existing) {
    return {
      ok: false,
      reason: 'master_already_enrolled',
      fingerprint: existing.fingerprint
    };
  }
  const existingBlob = await deps.keychain.get(deps.kcService, deps.kcAccount);
  if (existingBlob) {
    const recoveredPrivkey = decryptMasterPrivkey(passphrase, existingBlob);
    if (!recoveredPrivkey) return { ok: false, reason: 'wrong_passphrase_for_recovery' };
    const privateKey = createPrivateKey({
      key: Buffer.from(recoveredPrivkey, 'base64url'),
      format: 'der',
      type: 'pkcs8',
    });
    const recoveredPubkey = createPublicKey(privateKey)
      .export({ type: 'spki', format: 'der' })
      .toString('base64url');
    const recoveredFingerprint = pubkeyFingerprint(recoveredPubkey);
    await deps.db.insertMaster(recoveredPubkey, recoveredFingerprint, deps.kcService, deps.kcAccount);
    return { ok: true, pubkey: recoveredPubkey, fingerprint: recoveredFingerprint, recovered: true };
  }

  const { pubkey, privkey } = generateKeypair();
  const fingerprint = pubkeyFingerprint(pubkey);
  const blob = encryptMasterPrivkey(passphrase, privkey);
  await deps.keychain.set(deps.kcService, deps.kcAccount, blob);
  await deps.db.insertMaster(pubkey, fingerprint, deps.kcService, deps.kcAccount);
  return { ok: true, pubkey, fingerprint };
}

export async function enrollAgentWithDeps(agentId, passphrase, deps, opts = {}) {
  if (typeof agentId !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(agentId)) {
    return { ok: false, reason: 'invalid_agent_id' };
  }
  if (new Set(['housekeeper', 'aimos_flag_signer']).has(agentId.toLowerCase())) {
    return { ok: false, reason: 'reserved_system_agent_id' };
  }
  const validityDays = Number.isInteger(opts.validityDays) ? opts.validityDays : 30;
  if (validityDays <= 0 || validityDays > 365) {
    return { ok: false, reason: 'invalid_validity_days' };
  }

  const masterRow = await deps.db.getMaster();
  if (!masterRow) return { ok: false, reason: 'no_master' };

  const blob = await deps.keychain.get(deps.kcService, deps.kcAccount);
  if (!blob) return { ok: false, reason: 'master_keychain_missing' };

  const masterPrivkey = decryptMasterPrivkey(passphrase, blob);
  if (!masterPrivkey) return { ok: false, reason: 'wrong_passphrase' };

  const existingAgent = await deps.db.getAgent(agentId);
  if (existingAgent) {
    return {
      ok: false,
      reason: 'agent_already_enrolled',
      detail: `revoke first or pick a different agent_id; existing valid_from=${existingAgent.valid_from}`
    };
  }

  const { pubkey: agentPubkey, privkey: agentPrivkey } = generateKeypair();
  const now = Math.floor(Date.now() / 1000);
  const validFrom = now;
  const validUntil = now + validityDays * 24 * 3600;
  const deviceFp = computeDeviceFp(deps.brainRoot);

  const certBody = {
    v: 1,
    agent_id: agentId,
    pubkey: agentPubkey,
    device_fp: deviceFp,
    valid_from: validFrom,
    valid_until: validUntil,
    issuer: 'aimos-master',
    issued_at: now
  };
  const cert = issueCert(masterPrivkey, certBody);

  // Self-check: cert must verify against the on-disk master pubkey.
  const verify = verifyCertChain(cert, masterRow.master_pubkey);
  if (!verify.valid) {
    return { ok: false, reason: 'cert_self_check_failed', detail: verify.reason };
  }

  await deps.db.insertAgent({
    agent_id: agentId,
    pubkey: agentPubkey,
    cert,
    device_fp: deviceFp,
    valid_from: new Date(validFrom * 1000).toISOString(),
    valid_until: new Date(validUntil * 1000).toISOString()
  });

  return {
    ok: true,
    agentPubkey,
    agentPrivkey,
    cert,
    deviceFp,
    validFrom,
    validUntil,
    fingerprint: pubkeyFingerprint(agentPubkey)
  };
}

export async function revokeAgentWithDeps(agentId, passphrase, deps, opts = {}) {
  if (new Set(['housekeeper', 'aimos_flag_signer']).has(String(agentId || '').toLowerCase())) {
    return { ok: false, reason: 'reserved_system_agent_id' };
  }
  const masterRow = await deps.db.getMaster();
  if (!masterRow) return { ok: false, reason: 'no_master' };

  const blob = await deps.keychain.get(deps.kcService, deps.kcAccount);
  if (!blob) return { ok: false, reason: 'master_keychain_missing' };

  const masterPrivkey = decryptMasterPrivkey(passphrase, blob);
  if (!masterPrivkey) return { ok: false, reason: 'wrong_passphrase' };

  const agent = await deps.db.getAgent(agentId);
  if (!agent) {
    return { ok: false, reason: 'agent_not_found_or_already_revoked' };
  }
  const proof = createAgentRevocationProof(masterPrivkey, {
    agentId,
    agentValidFrom: agent.valid_from,
    targetCert: agent.cert,
    masterFingerprint: masterRow.fingerprint,
    reasonCode: opts.reasonCode || 'operator_revoked',
  });
  const selfCheck = verifyAgentRevocationProof({
    agent_id: agentId,
    agent_valid_from: agent.valid_from,
    master_fingerprint: masterRow.fingerprint,
    target_cert_hash: proof.targetCertHash,
    prior_identity_hash: proof.priorIdentityHash,
    signed_body: proof.body,
    content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    ts_signed: proof.signedTs,
    nonce: proof.nonce,
    sig: proof.sigBytes,
  }, masterRow.master_pubkey, agent.cert);
  if (!selfCheck.valid) return { ok: false, reason: 'revocation_self_check_failed', detail: selfCheck.reason };

  if (opts.dryRun) {
    return {
      ok: true,
      dryRun: true,
      agentId,
      agentValidFrom: agent.valid_from,
      contentHash: proof.contentHash,
      mutationHash: proof.mutationHash,
    };
  }
  const committed = await deps.db.insertRevocationEvent({
    agent_id: agentId,
    agent_valid_from: agent.valid_from,
    master_fingerprint: masterRow.fingerprint,
    target_cert_hash: proof.targetCertHash,
    prior_identity_hash: proof.priorIdentityHash,
    signed_body: proof.body,
    content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    ts_signed: proof.signedTs,
    nonce: proof.nonce,
    sig: proof.sigBytes,
  });
  if (!committed?.ok) return committed || { ok: false, reason: 'revocation_commit_failed' };
  return {
    ok: true,
    agentId,
    agentValidFrom: agent.valid_from,
    revokedAt: committed.created_at,
    revocationEventId: committed.revocation_event_id,
    contentHash: proof.contentHash,
    mutationHash: proof.mutationHash,
  };
}

// ─── Constants exported for CLI scripts ──────────────────────────────────────

export const KC_SERVICE = 'aimos.master';
export const KC_ACCOUNT_DEFAULT = null;
