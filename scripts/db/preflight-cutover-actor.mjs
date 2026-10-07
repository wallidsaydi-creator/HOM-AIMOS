// Read-only authority proof for the ordinary agent used by the canonical
// cutover's signed SAVE probes. The native certificate resolver and recall
// authorization chain verifier remain the authority for the exact epoch.

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import fs from 'node:fs';
import pg from 'pg';

import { getAgentCert, pubkeyFingerprint, verifyCertChain } from
  '../../services/security/agent-identity.js';
import { verifyRecallAuthorizationChain } from '../../services/security/recall-authorization.js';

const REQUIRED_SAVE_CLEARANCE = 5;

function fail(reason) { throw new Error(`canonical_cutover_actor_${reason}`); }

function keyPublicKey(keyPath) {
  const stat = fs.lstatSync(keyPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o777) !== 0o600 || stat.size < 32 || stat.size > 8192) {
    fail('key_custody_invalid');
  }
  const fd = fs.openSync(keyPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let bytes;
  try {
    const descriptor = fs.fstatSync(fd);
    if (!descriptor.isFile() || descriptor.uid !== process.getuid()
        || (descriptor.mode & 0o777) !== 0o600
        || descriptor.ino !== stat.ino || descriptor.dev !== stat.dev) {
      fail('key_descriptor_invalid');
    }
    bytes = fs.readFileSync(fd);
    const privateKey = createPrivateKey({
      key: Buffer.from(bytes.toString('utf8').trim(), 'base64url'),
      format: 'der', type: 'pkcs8',
    });
    return createPublicKey(privateKey)
      .export({ format: 'der', type: 'spki' }).toString('base64url');
  } catch {
    fail('key_material_invalid');
  } finally {
    fs.closeSync(fd);
    bytes?.fill(0);
  }
}

export function assertCutoverActorAuthority({ actor, cert, identity, grant, publicKey,
  nowMs = Date.now() } = {}) {
  const validFrom = Date.parse(identity?.valid_from);
  const validUntil = Date.parse(identity?.valid_until);
  if (!identity || identity.agent_id !== actor || identity.cert !== cert
      || identity.is_system_role === true
      || !Number.isFinite(validFrom) || !Number.isFinite(validUntil)
      || validFrom > nowMs || validUntil <= nowMs) {
    fail('certificate_epoch_inactive');
  }
  if (identity.pubkey !== publicKey) fail('key_does_not_match_certificate_epoch');
  if (!identity.master_pubkey || !identity.master_fingerprint
      || pubkeyFingerprint(identity.master_pubkey) !== identity.master_fingerprint) {
    fail('certificate_root_invalid');
  }
  const verified = verifyCertChain(cert, identity.master_pubkey,
    { nowFn: () => Math.floor(nowMs / 1000) });
  if (!verified.valid || !['aimos-master', identity.master_fingerprint]
    .includes(verified.body?.issuer)
      || verified.body?.agent_id !== actor
      || verified.body?.pubkey !== identity.pubkey
      || verified.body?.device_fp !== identity.device_fp
      || Number(verified.body?.valid_from) * 1000 !== validFrom
      || Number(verified.body?.valid_until) * 1000 !== validUntil) {
    fail('certificate_master_chain_invalid');
  }
  if (grant?.company_id !== 'hom' || grant?.subject_agent_id !== actor
      || Date.parse(grant.subject_valid_from) !== validFrom
      || grant.allowed !== true || grant.write_allowed !== true
      || !Number.isInteger(grant.clearance_ceiling)
      || grant.clearance_ceiling < REQUIRED_SAVE_CLEARANCE) {
    fail('exact_epoch_write_grant_insufficient');
  }
  return true;
}

export async function preflightCutoverActor({ client, actor, keyPath,
  nowMs = Date.now() } = {}) {
  if (!client || !/^[a-z][a-z0-9_-]{0,63}$/.test(String(actor || ''))
      || actor === 'housekeeper' || !Number.isFinite(nowMs)) fail('inputs_invalid');
  const publicKey = keyPublicKey(keyPath);
  let cert;
  try {
    cert = await getAgentCert(actor, {
      nowFn: () => nowMs,
      queryFn: (sql, params) => client.query(sql, params),
    });
  } catch {
    fail('certificate_invalid_or_revoked');
  }
  const identities = await client.query(`SELECT i.agent_id, i.cert, i.pubkey,
      i.device_fp, i.valid_from, i.valid_until, i.is_system_role,
      m.master_pubkey, m.fingerprint AS master_fingerprint
      FROM public.agent_identity i
      JOIN public.aimos_master_identity m ON m.id=1
      WHERE i.agent_id=$1 AND i.cert=$2`, [actor, cert]);
  if (identities.rowCount !== 1) fail('certificate_epoch_ambiguous');
  const identity = identities.rows[0];
  const exactEpoch = new Date(identity.valid_from).toISOString();
  const result = await client.query(`SELECT r.*, m.master_pubkey
      FROM public.aimos_recall_authorization_events r
      JOIN public.aimos_master_identity m ON m.fingerprint=r.master_fingerprint
      WHERE r.company_id='hom' AND r.subject_agent_id=$1
        AND r.subject_valid_from=$2`, [actor, exactEpoch]);
  if (!result.rows.length) fail('exact_epoch_write_grant_missing');
  let chain;
  try { chain = verifyRecallAuthorizationChain(result.rows); }
  catch { fail('exact_epoch_write_grant_chain_invalid'); }
  const grant = chain.latest;
  assertCutoverActorAuthority({ actor, cert, identity, grant, publicKey, nowMs });
  return Object.freeze({
    actor, valid_from: exactEpoch,
    valid_until: new Date(identity.valid_until).toISOString(),
    certificate_sha256: createHash('sha256').update(cert, 'utf8').digest('hex'),
    grant_event_id: String(grant.recall_authorization_event_id),
    grant_mutation_sha256: Buffer.from(chain.mutationHash).toString('hex'),
    write_allowed: true, clearance_ceiling: grant.clearance_ceiling,
  });
}

export async function preflightCutoverActorConnection({ connection, actor,
  keyPath } = {}) {
  const client = new pg.Client({ ...connection, statement_timeout: 20_000 });
  try {
    await client.connect();
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const result = await preflightCutoverActor({ client, actor, keyPath });
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end().catch(() => {}); }
}
