// scripts/identity/db.js
// Thin DB wrapper using the existing pool. All queries against the live
// aimos DB. Read-only operations are safe; writes are init-time only.

import { pool } from '../../db/connection.js';
import { getAgentCert } from '../../services/security/agent-identity.js';

export async function getMaster() {
  const r = await pool.query(
    'SELECT master_pubkey, fingerprint, keychain_service, keychain_account, created_at FROM aimos_master_identity WHERE id = 1'
  );
  return r.rows[0] || null;
}

export async function insertMaster(masterPubkey, fingerprint, keychainService, keychainAccount) {
  await pool.query(
    `INSERT INTO aimos_master_identity
       (id, master_pubkey, fingerprint, keychain_service, keychain_account)
     VALUES (1, $1, $2, $3, $4)`,
    [masterPubkey, fingerprint, keychainService, keychainAccount]
  );
}

export async function getAgent(agentId) {
  let cert;
  try {
    cert = await getAgentCert(agentId, { queryFn: (sql, params = []) => pool.query(sql, params) });
  } catch {
    return null;
  }
  const r = await pool.query(
    `SELECT agent_id, pubkey, cert, device_fp, valid_from, valid_until,
            issued_at, chain_head, is_system_role
      FROM agent_identity
      WHERE agent_id = $1 AND cert = $2
      ORDER BY valid_from DESC
      LIMIT 1`,
    [agentId, cert]
  );
  return r.rows[0] || null;
}

export async function insertAgent(row) {
  await pool.query(
    `INSERT INTO agent_identity
       (agent_id, pubkey, cert, device_fp, valid_from, valid_until)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [row.agent_id, row.pubkey, row.cert, row.device_fp, row.valid_from, row.valid_until]
  );
}

export async function insertRevocationEvent(proof) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const reject = async (reason) => {
      await client.query('ROLLBACK');
      return { ok: false, reason };
    };
    const identity = await client.query(
      `SELECT agent_id, valid_from, cert,
              encode(digest(cert, 'sha256'), 'hex') AS target_cert_hash_hex
         FROM agent_identity
        WHERE agent_id = $1 AND valid_from = $2
        FOR UPDATE`,
      [proof.agent_id, proof.agent_valid_from]
    );
    const row = identity.rows[0];
    if (!row) return await reject('agent_epoch_not_found');
    if (row.agent_id === 'housekeeper') return await reject('reserved_system_agent_id');
    if (row.target_cert_hash_hex !== Buffer.from(proof.target_cert_hash).toString('hex')) {
      return await reject('target_cert_hash_mismatch');
    }
    const master = await client.query(
      `SELECT fingerprint FROM aimos_master_identity WHERE id = 1 FOR SHARE`
    );
    if (master.rows[0]?.fingerprint !== proof.master_fingerprint) {
      return await reject('master_fingerprint_mismatch');
    }

    const inserted = await client.query(
      `INSERT INTO aimos_agent_revocation_events
         (agent_id, agent_valid_from, master_identity_id, master_fingerprint,
          target_cert_hash, prior_identity_hash, signed_body, content_hash,
          mutation_hash, ts_signed, nonce, sig)
       VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING revocation_event_id, created_at`,
      [
        proof.agent_id,
        proof.agent_valid_from,
        proof.master_fingerprint,
        proof.target_cert_hash,
        proof.prior_identity_hash,
        JSON.stringify(proof.signed_body),
        proof.content_hash,
        proof.mutation_hash,
        proof.ts_signed,
        proof.nonce,
        proof.sig,
      ]
    );
    await client.query('COMMIT');
    return { ok: true, ...inserted.rows[0] };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    if (error.code === '23505') return { ok: false, reason: 'agent_epoch_already_revoked' };
    throw error;
  } finally {
    client.release();
  }
}
