#!/usr/bin/env node
// One-passphrase, one-file operator read. The master key signs the exact file
// and content hash; the enrolled agent signs the local HTTP request. Neither
// private key nor the short-lived proof is printed or persisted.

import { createPrivateKey, createPublicKey } from 'node:crypto';
import path from 'node:path';

import { pool, agentPool, identityWriterPool } from '../../db/connection.js';
import { AIMOS_COMPANY_ID, AIMOS_SERVER_PORT } from '../../services/core/runtime-config.js';
import { pubkeyFingerprint } from '../../services/security/agent-identity.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import {
  assertLocalFileNotProtected,
  createPurposeAuthorizationProof,
  hashBoundedLocalFile,
  LOCAL_FILE_READ_PROOF_MAX_SECONDS,
  serializePurposeAuthorizationProof,
} from '../../services/security/purpose-authorization.js';
import { getOperatorAgentId, systemConfigStore } from '../../services/security/system-config-store.js';
import { decryptMasterPrivkey } from './lib.js';
import { keychainGet } from './keychain.js';
import { getAgent, getMaster } from './db.js';
import { readPassphrase } from './passphrase.js';

function option(name) {
  return process.argv.slice(2).find((arg) => arg.startsWith(`--${name}=`))?.slice(name.length + 3) || '';
}

function masterPublicKey(privateKeyB64u) {
  return createPublicKey(createPrivateKey({
    key: Buffer.from(privateKeyB64u, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  })).export({ type: 'spki', format: 'der' }).toString('base64url');
}

async function main() {
  const filepath = option('file');
  const readRoot = option('root');
  const purposeId = option('purpose');
  if (!filepath || !readRoot || !purposeId || !path.isAbsolute(filepath) || !path.isAbsolute(readRoot)) {
    throw new Error('usage: node scripts/identity/authorize-file-read.js --file=/absolute/file --root=/owner-only/directory --purpose=reason');
  }
  assertLocalFileNotProtected(filepath);
  const loaded = await systemConfigStore.loadAll();
  if (!loaded.ok) throw new Error(`verified_operator_config_unavailable:${loaded.reason}`);
  const agentId = getOperatorAgentId();
  if (!agentId) throw new Error('operator_agent_not_designated');
  const master = await getMaster();
  const agent = await getAgent(agentId);
  if (!master || !agent || agent.is_system_role === true
      || !master.keychain_service || !master.keychain_account) {
    throw new Error('operator_identity_authority_unavailable');
  }
  const now = Date.now();
  if (Date.parse(agent.valid_from) > now || Date.parse(agent.valid_until) <= now) {
    throw new Error('operator_certificate_epoch_inactive');
  }
  const blob = await keychainGet(master.keychain_service, master.keychain_account);
  if (!blob) throw new Error('master_keychain_missing');
  const passphrase = await readPassphrase('Master passphrase for one-file read: ');
  const masterPrivkeyB64u = decryptMasterPrivkey(passphrase, blob);
  if (!masterPrivkeyB64u || masterPublicKey(masterPrivkeyB64u) !== master.master_pubkey
      || pubkeyFingerprint(master.master_pubkey) !== master.fingerprint) {
    throw new Error('master_key_material_mismatch');
  }
  const signedTs = Math.floor(Date.now() / 1000);
  const expiresTs = Math.min(signedTs + LOCAL_FILE_READ_PROOF_MAX_SECONDS,
    Math.floor(Date.parse(agent.valid_until) / 1000));
  if (expiresTs <= signedTs) throw new Error('operator_certificate_epoch_expiring');
  const proof = serializePurposeAuthorizationProof(createPurposeAuthorizationProof(masterPrivkeyB64u, {
    purposeId,
    companyId: AIMOS_COMPANY_ID,
    subjectAgentId: agentId,
    subjectValidFrom: agent.valid_from,
    subjectValidUntil: agent.valid_until,
    operation: 'local_file_read',
    tool: 'read_file',
    readRoot,
    targetFile: filepath,
    targetContentSha256: hashBoundedLocalFile(filepath),
    clearanceCeiling: 12,
    expiresAt: new Date(expiresTs * 1000).toISOString(),
    masterFingerprint: master.fingerprint,
  }, { signedTs }));
  const requestPath = '/tools/files/read';
  const body = { filepath: path.resolve(filepath), purpose_authorization: proof };
  const headers = await buildEnvelopeHeaders(agentId, 'POST', requestPath, body);
  const response = await fetch(`http://127.0.0.1:${AIMOS_SERVER_PORT}${requestPath}`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json();
  if (!response.ok || typeof result?.content !== 'string') {
    throw new Error(`local_file_read_denied:${response.status}:${result?.error || 'unknown'}`);
  }
  process.stdout.write(result.content);
  if (!result.content.endsWith('\n')) process.stdout.write('\n');
}

main().catch((error) => {
  console.error('[ERR]', error?.message || error);
  process.exitCode = 1;
}).finally(async () => {
  try { await pool.end(); } catch {}
  try { await agentPool.end(); } catch {}
  try { await identityWriterPool.end(); } catch {}
});
