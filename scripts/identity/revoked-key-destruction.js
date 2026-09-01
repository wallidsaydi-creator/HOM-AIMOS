import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { AIMOS_AGENT_KEY_ROOT } from '../../services/core/runtime-config.js';

function assertAgentId(agentId) {
  const normalized = String(agentId || '').trim();
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(normalized)) {
    throw new Error('revoked_key_agent_id_invalid');
  }
  return normalized;
}

export function derivePrivateKeyPublicFingerprint(keyPath, fsRef = fs) {
  const material = fsRef.readFileSync(keyPath, 'utf8').trim();
  const privateKey = createPrivateKey({
    key: Buffer.from(material, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return createHash('sha256').update(publicDer).digest('hex');
}

export function destroyRevokedKeyRepresentation({
  agentId,
  targetFingerprint,
  activeFingerprints = [],
  keyRoot = AIMOS_AGENT_KEY_ROOT,
  fsRef = fs,
} = {}) {
  const normalizedAgentId = assertAgentId(agentId);
  const fingerprint = String(targetFingerprint || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) {
    throw new Error('revoked_key_target_fingerprint_invalid');
  }
  const resolvedRoot = path.resolve(keyRoot);
  const keyPath = path.join(resolvedRoot, `${normalizedAgentId}.key`);
  if (path.dirname(keyPath) !== resolvedRoot) throw new Error('revoked_key_path_escape');
  if (!fsRef.existsSync(keyPath)) {
    return { agent_id: normalizedAgentId, key_path: keyPath, status: 'ALREADY_ABSENT' };
  }
  const stat = fsRef.statSync(keyPath);
  if (!stat.isFile()) throw new Error('revoked_key_not_regular_file');
  if ((stat.mode & 0o777) !== 0o600) throw new Error('revoked_key_mode_invalid');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new Error('revoked_key_owner_invalid');
  }
  const derivedFingerprint = derivePrivateKeyPublicFingerprint(keyPath, fsRef);
  if (derivedFingerprint !== fingerprint) {
    return {
      agent_id: normalizedAgentId,
      key_path: keyPath,
      status: 'RETAINED_DIFFERENT_EPOCH',
      derived_public_fingerprint: derivedFingerprint,
    };
  }
  const stillActive = new Set(activeFingerprints.map((value) => String(value).toLowerCase()));
  if (stillActive.has(derivedFingerprint)) {
    return {
      agent_id: normalizedAgentId,
      key_path: keyPath,
      status: 'RETAINED_ACTIVE_EPOCH',
      derived_public_fingerprint: derivedFingerprint,
    };
  }

  const descriptor = fsRef.openSync(keyPath, 'r+');
  try {
    const zeros = Buffer.alloc(Math.max(1, stat.size));
    fsRef.writeSync(descriptor, zeros, 0, zeros.length, 0);
    fsRef.fsyncSync(descriptor);
    zeros.fill(0);
  } finally {
    fsRef.closeSync(descriptor);
  }
  fsRef.unlinkSync(keyPath);
  if (fsRef.existsSync(keyPath)) throw new Error('revoked_key_postcondition_failed');
  return {
    agent_id: normalizedAgentId,
    key_path: keyPath,
    status: 'DESTROYED',
    destroyed_bytes: stat.size,
    derived_public_fingerprint: derivedFingerprint,
  };
}
