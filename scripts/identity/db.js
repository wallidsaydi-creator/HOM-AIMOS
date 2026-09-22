// scripts/identity/db.js
// Thin DB wrapper using the existing pool. All queries against the live
// aimos DB. Read-only operations are safe; writes are init-time only.

import { createHash, randomUUID } from 'node:crypto';
import { pool } from '../../db/connection.js';
import { canonicalJson, getAgentCert, verifyCertChain, issueCert } from '../../services/security/agent-identity.js';
import { AIMOS_COMPANY_ID } from '../../services/core/runtime-config.js';
import { logEvent, readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { recallAuthorizationService } from '../../services/security/recall-authorization.js';

// Renewal appends a certificate epoch for an existing key. It is not enrollment,
// key rotation, an UPDATE of historical identity bytes, or a new permission.
export async function inspectAgentRenewal(agentId, publicKey, validityDays, { client = null } = {}) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(String(agentId))
      || ['housekeeper', 'aimos_flag_signer', 'aimos-master'].includes(String(agentId).toLowerCase())
      || !Number.isInteger(validityDays) || validityDays < 1 || validityDays > 365) {
    throw new Error('identity_renewal_input_invalid');
  }
  const run = client ? client.query.bind(client) : pool.query.bind(pool);
  const row = (await run(`SELECT * FROM agent_identity WHERE agent_id=$1
    ORDER BY valid_from DESC LIMIT 1${client ? ' FOR UPDATE' : ''}`, [agentId])).rows[0];
  if (!row || row.is_system_role === true || row.pubkey !== publicKey) throw new Error('identity_renewal_key_continuity_invalid');
  const revoked = await run('SELECT 1 FROM aimos_agent_revocation_events WHERE agent_id=$1 AND agent_valid_from=$2', [agentId,row.valid_from]);
  if (row.revoked_at || revoked.rowCount) throw new Error('identity_renewal_revoked_epoch');
  const master = (await run('SELECT master_pubkey,fingerprint,keychain_service,keychain_account FROM aimos_master_identity WHERE id=1')).rows[0];
  if (!master) throw new Error('identity_renewal_master_missing');
  const oldProof = verifyCertChain(row.cert,master.master_pubkey,{nowFn:()=>Math.floor(new Date(row.valid_from).getTime()/1000)});
  const projection = enrollmentProjection(row);
  if (!oldProof.valid || oldProof.body?.agent_id !== agentId || oldProof.body.pubkey !== publicKey
      || oldProof.body.device_fp !== row.device_fp
      || new Date(oldProof.body.valid_until*1000).toISOString() !== projection.valid_until
      || new Date(oldProof.body.valid_from*1000).toISOString() !== projection.valid_from) {
    throw new Error('identity_renewal_predecessor_invalid');
  }
  const grant = await recallAuthorizationService.getEffective({ companyId:AIMOS_COMPANY_ID,
    subjectAgentId:agentId,subjectValidFrom:row.valid_from,client });
  if (!grant?.allowed) throw new Error('identity_renewal_existing_grant_not_allowed');
  if (new Date(row.valid_until).getTime() > Date.now()) {
    const receipt = (await run(`SELECT id FROM aimos_events WHERE company_id=$1
      AND operation='identity_certificate_renewed' AND key=$2
      AND metadata->'successor'->>'certificate_sha256'=$3 ORDER BY ts DESC LIMIT 1`,
    [AIMOS_COMPANY_ID,agentId,projection.certificate_sha256])).rows[0];
    if (!receipt) throw new Error('identity_renewal_current_certificate_not_expired');
    const event = await readVerifiedEventById(receipt.id,AIMOS_COMPANY_ID,{client});
    if (event.metadata.validity_days !== validityDays
        || event.metadata.grant_mutation_hash !== grant.mutationHash.toString('hex')
        || canonicalJson(event.metadata.successor) !== canonicalJson(projection)) {
      throw new Error('identity_renewal_existing_terminal_mismatch');
    }
    return { row,master,grant,projection,alreadyRenewed:true,terminalId:event.id };
  }
  return { row,master,grant,projection,alreadyRenewed:false };
}

export async function renewAgentCertificate({ agentId,publicKey,validityDays,expectedCertificateSha256,
  masterPrivkeyB64u,signingMaterialSha256 }) {
  if (!/^[0-9a-f]{64}$/.test(String(signingMaterialSha256))) throw new Error('identity_renewal_key_commitment_invalid');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`identity-enrollment:${agentId}`]);
    const state = await inspectAgentRenewal(agentId,publicKey,validityDays,{client});
    if (state.alreadyRenewed) { await client.query('COMMIT'); return { alreadyRenewed:true,terminalId:state.terminalId,successor:state.projection }; }
    if (state.projection.certificate_sha256 !== expectedCertificateSha256) throw new Error('identity_renewal_predecessor_changed');
    // The existing grant writer locks this same predecessor identity row.
    // Holding it prevents a concurrent grant/revocation change during copying.
    const now = Math.floor(Date.now()/1000);
    const certBody = { v:1,agent_id:agentId,pubkey:publicKey,device_fp:state.row.device_fp,
      valid_from:now,valid_until:now+validityDays*86400,issuer:'aimos-master',issued_at:now };
    const certificate = issueCert(masterPrivkeyB64u,certBody);
    if (!verifyCertChain(certificate,state.master.master_pubkey).valid) throw new Error('identity_renewal_certificate_self_check_failed');
    const row = { agent_id:agentId,pubkey:publicKey,cert:certificate,device_fp:state.row.device_fp,
      valid_from:new Date(certBody.valid_from*1000).toISOString(),valid_until:new Date(certBody.valid_until*1000).toISOString() };
    await client.query(`INSERT INTO agent_identity(agent_id,pubkey,cert,device_fp,valid_from,valid_until)
      VALUES($1,$2,$3,$4,$5,$6)`,[row.agent_id,row.pubkey,row.cert,row.device_fp,row.valid_from,row.valid_until]);
    const grant = await recallAuthorizationService.commit({ companyId:AIMOS_COMPANY_ID,
      subjectAgentId:agentId,subjectValidFrom:row.valid_from,allowed:state.grant.allowed,
      writeAllowed:state.grant.writeAllowed,clearanceCeiling:state.grant.clearanceCeiling,
      dataClassCeiling:state.grant.dataClassCeiling,masterPrivkeyB64u,masterFingerprint:state.master.fingerprint,
      reason:'certificate_renewal_preserve_verified_grant',client });
    const successor = enrollmentProjection(row);
    const terminal = await logEvent(AIMOS_COMPANY_ID,agentId,'identity_certificate_renewed',agentId,{
      schema:'hom.aimos.identity-certificate-renewal/v1',predecessor:state.projection,successor,
      validity_days:validityDays,signing_material_sha256:signingMaterialSha256,
      previous_grant_mutation_hash:state.grant.mutationHash.toString('hex'),
      grant_mutation_hash:grant.mutationHash.toString('hex'),grant_event_id:grant.recall_authorization_event_id,
      allowed:state.grant.allowed,write_allowed:state.grant.writeAllowed,
      clearance_ceiling:state.grant.clearanceCeiling,data_class_ceiling:state.grant.dataClassCeiling,
      same_key:true,same_agent:true,historical_identity_preserved:true,
      reasoning:'Operator-authorized renewal appends a master-signed certificate for the existing key and exactly preserves the verified memory grant. Both rows and this terminal commit atomically.'
    },null,{client,returnReceipt:true});
    const verified = await readVerifiedEventById(terminal.event_id,AIMOS_COMPANY_ID,{client});
    if (verified.metadata.successor.certificate_sha256 !== successor.certificate_sha256) throw new Error('identity_renewal_terminal_binding_invalid');
    await client.query('COMMIT');
    return { alreadyRenewed:false,terminalId:terminal.event_id,successor,grantMutationHash:grant.mutationHash.toString('hex') };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* a lost commit ACK must be reconciled by the signed terminal */ }
    throw error;
  } finally { client.release(); }
}

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

function masterProjection(row) {
  const publicKeySha256 = createHash('sha256')
    .update(Buffer.from(String(row.master_pubkey), 'base64url'))
    .digest('hex');
  if (String(row.fingerprint) !== publicKeySha256) {
    throw new Error('master_identity_fingerprint_mismatch');
  }
  return {
    master_fingerprint: String(row.fingerprint),
    master_pubkey_sha256: publicKeySha256,
    keychain_locator_sha256: createHash('sha256')
      .update(`${String(row.keychain_service)}\0${String(row.keychain_account)}`, 'utf8')
      .digest('hex'),
  };
}

export async function beginMasterEnrollment(row, encryptedBlobSha256) {
  const projection = masterProjection(row);
  const blobHash = String(encryptedBlobSha256 || '');
  if (!/^[0-9a-f]{64}$/.test(blobHash)) throw new Error('master_enrollment_blob_commitment_invalid');
  const actionId = randomUUID();
  const projectionSha256 = createHash('sha256')
    .update(Buffer.from(`HOM-AIMOS-MASTER-ENROLLMENT-v1\0${canonicalJson({ ...projection, encrypted_blob_sha256: blobHash })}`, 'utf8'))
    .digest('hex');
  const receipt = await logEvent(
    AIMOS_COMPANY_ID,
    'aimos-master',
    'master_enrollment_started',
    actionId,
    {
      schema: 'hom.aimos.master-enrollment-start/v1',
      enrollment_action_id: actionId,
      identity_projection_sha256: projectionSha256,
      ...projection,
      encrypted_blob_sha256: blobHash,
      reasoning: 'The Housekeeper committed the exact master public identity and encrypted Keychain material hash before the pointer write.',
    },
    null,
    { returnReceipt: true },
  );
  return Object.freeze({ actionId, projection, projectionSha256, encryptedBlobSha256: blobHash, ...receipt });
}

export async function commitMasterEnrollment(row, start, observedEncryptedBlobSha256) {
  if (!start?.event_id || !/^[0-9a-f]{64}$/.test(String(start.mutation_hash || ''))
      || String(observedEncryptedBlobSha256) !== start.encryptedBlobSha256
      || canonicalJson(masterProjection(row)) !== canonicalJson(start.projection)) {
    throw new Error('master_enrollment_projection_invalid');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', ['master-enrollment']);
    const startEvent = await readVerifiedEventById(start.event_id, AIMOS_COMPANY_ID, { client });
    const startMetadata = typeof startEvent.metadata === 'string'
      ? JSON.parse(startEvent.metadata)
      : startEvent.metadata;
    if (startEvent.operation !== 'master_enrollment_started'
        || String(startEvent.key) !== start.actionId
        || Buffer.from(startEvent.mutation_hash || []).toString('hex') !== start.mutation_hash
        || startMetadata?.schema !== 'hom.aimos.master-enrollment-start/v1'
        || startMetadata?.identity_projection_sha256 !== start.projectionSha256
        || startMetadata?.encrypted_blob_sha256 !== start.encryptedBlobSha256
        || startMetadata?.master_fingerprint !== start.projection.master_fingerprint
        || startMetadata?.master_pubkey_sha256 !== start.projection.master_pubkey_sha256
        || startMetadata?.keychain_locator_sha256 !== start.projection.keychain_locator_sha256) {
      throw new Error('master_enrollment_start_binding_invalid');
    }
    const existing = await client.query('SELECT 1 FROM aimos_master_identity WHERE id = 1');
    if (existing.rows[0]) throw new Error('master_already_enrolled');
    await client.query(
      `INSERT INTO aimos_master_identity
         (id, master_pubkey, fingerprint, keychain_service, keychain_account)
       VALUES (1, $1, $2, $3, $4)`,
      [row.master_pubkey, row.fingerprint, row.keychain_service, row.keychain_account],
    );
    const terminal = await logEvent(
      AIMOS_COMPANY_ID,
      'aimos-master',
      'master_enrollment_committed',
      start.actionId,
      {
        schema: 'hom.aimos.master-enrollment-terminal/v1',
        enrollment_action_id: start.actionId,
        start_event_id: start.event_id,
        start_mutation_hash: start.mutation_hash,
        identity_projection_sha256: start.projectionSha256,
        encrypted_blob_sha256: start.encryptedBlobSha256,
        disposition: 'SUCCESS',
        reasoning: 'The encrypted Keychain material was read back and the exact master row co-committed with this terminal.',
      },
      start.event_id,
      { returnReceipt: true, client, identityQueryFn: client.query.bind(client) },
    );
    await client.query('COMMIT');
    return Object.freeze({ ok: true, terminal });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
}

export async function markMasterEnrollmentIndeterminate(start, error) {
  if (!start?.event_id) return null;
  return logEvent(
    AIMOS_COMPANY_ID,
    'aimos-master',
    'master_enrollment_indeterminate',
    start.actionId,
    {
      schema: 'hom.aimos.master-enrollment-terminal/v1',
      enrollment_action_id: start.actionId,
      start_event_id: start.event_id,
      start_mutation_hash: start.mutation_hash,
      identity_projection_sha256: start.projectionSha256,
      encrypted_blob_sha256: start.encryptedBlobSha256,
      disposition: 'INDETERMINATE',
      error_class: error?.name || 'master_enrollment_failure',
      reasoning: 'Master enrollment did not reach a verified Keychain/row success terminal.',
    },
    start.event_id,
    { returnReceipt: true },
  );
}

export async function bindMasterKeychainLocator(keychainService, keychainAccount) {
  const service = String(keychainService || '').trim();
  const account = String(keychainAccount || '').trim();
  if (!service || !account) throw new Error('master_keychain_locator_invalid');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = (await client.query(
      'SELECT keychain_service,keychain_account FROM aimos_master_identity WHERE id=1 FOR UPDATE',
    )).rows[0];
    if (!current) throw new Error('master_identity_missing');
    if (current.keychain_service || current.keychain_account) {
      if (current.keychain_service !== service || current.keychain_account !== account) {
        throw new Error('master_keychain_locator_conflict');
      }
      await client.query('COMMIT');
      return { bound: true, inserted: false, keychain_service: service, keychain_account: account };
    }
    const updated = await client.query(
      `UPDATE aimos_master_identity
          SET keychain_service=$1,keychain_account=$2
        WHERE id=1 AND keychain_service IS NULL AND keychain_account IS NULL
      RETURNING keychain_service,keychain_account`,
      [service, account],
    );
    if (updated.rowCount !== 1) throw new Error('master_keychain_locator_compare_and_swap_failed');
    await client.query('COMMIT');
    return { bound: true, inserted: true, ...updated.rows[0] };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
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

export async function getAgentEpoch(agentId, validFrom) {
  const result = await pool.query(
    `SELECT identity.agent_id,identity.pubkey,identity.cert,identity.device_fp,
            identity.valid_from,identity.valid_until,identity.issued_at,
            identity.chain_head,identity.is_system_role
       FROM agent_identity identity
      WHERE identity.agent_id = $1
        AND identity.valid_from = $2
        AND NOT EXISTS (
          SELECT 1 FROM aimos_agent_revocation_events revocation
           WHERE revocation.agent_id = identity.agent_id
             AND revocation.agent_valid_from = identity.valid_from
        )
      LIMIT 1`,
    [agentId, new Date(validFrom).toISOString()],
  );
  return result.rows[0] || null;
}

export async function insertAgent(row) {
  await pool.query(
    `INSERT INTO agent_identity
       (agent_id, pubkey, cert, device_fp, valid_from, valid_until)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [row.agent_id, row.pubkey, row.cert, row.device_fp, row.valid_from, row.valid_until]
  );
}

function enrollmentProjection(row) {
  return {
    agent_id: String(row.agent_id),
    pubkey_fingerprint: createHash('sha256').update(Buffer.from(String(row.pubkey), 'base64url')).digest('hex'),
    certificate_sha256: createHash('sha256').update(String(row.cert), 'utf8').digest('hex'),
    device_fingerprint: String(row.device_fp),
    valid_from: new Date(row.valid_from).toISOString(),
    valid_until: new Date(row.valid_until).toISOString(),
  };
}

export async function beginAgentEnrollment(row, { authority = null } = {}) {
  const projection = enrollmentProjection(row);
  const actionId = randomUUID();
  const projectionSha256 = createHash('sha256')
    .update(Buffer.from(`HOM-AIMOS-IDENTITY-ENROLLMENT-v1\0${canonicalJson(projection)}`, 'utf8'))
    .digest('hex');
  const receipt = await logEvent(
    AIMOS_COMPANY_ID,
    projection.agent_id,
    'identity_enrollment_started',
    actionId,
    {
      schema: 'hom.aimos.identity-enrollment-start/v1',
      enrollment_action_id: actionId,
      identity_projection_sha256: projectionSha256,
      ...projection,
      authority_basis: 'master_signed_certificate',
      reasoning: 'The Housekeeper verified the exact master-signed identity projection before any enrollment file or identity row was committed.',
    },
    authority?.requestAdmissionEventId || null,
    { returnReceipt: true, authority },
  );
  if (!receipt?.event_id || !/^[0-9a-f]{64}$/.test(String(receipt.mutation_hash || ''))) {
    throw new Error('identity_enrollment_start_unavailable');
  }
  return Object.freeze({ actionId, projection, projectionSha256, ...receipt });
}

export async function commitAgentEnrollment(row, start, fileProjection) {
  if (!start?.actionId || !start?.event_id || !/^[0-9a-f]{64}$/.test(String(start.mutation_hash || ''))) {
    throw new Error('identity_enrollment_start_required');
  }
  const projection = enrollmentProjection(row);
  if (canonicalJson(projection) !== canonicalJson(start.projection)) {
    throw new Error('identity_enrollment_projection_changed');
  }
  const signingMaterialSha256 = String(fileProjection?.signing_material_sha256 || '');
  const certCacheSha256 = String(fileProjection?.cert_cache_sha256 || '');
  if (!/^[0-9a-f]{64}$/.test(signingMaterialSha256) || !/^[0-9a-f]{64}$/.test(certCacheSha256)) {
    throw new Error('identity_enrollment_file_projection_invalid');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`identity-enrollment:${projection.agent_id}`],
    );
    const existing = await client.query(
      `SELECT 1 FROM agent_identity identity
        WHERE identity.agent_id = $1
          AND NOT EXISTS (
            SELECT 1 FROM aimos_agent_revocation_events revocation
             WHERE revocation.agent_id = identity.agent_id
               AND revocation.agent_valid_from = identity.valid_from
          )
        LIMIT 1`,
      [projection.agent_id],
    );
    if (existing.rows[0]) throw new Error('agent_already_enrolled');
    const startEvent = await readVerifiedEventById(start.event_id, AIMOS_COMPANY_ID, { client });
    const startMetadata = typeof startEvent.metadata === 'string'
      ? JSON.parse(startEvent.metadata)
      : startEvent.metadata;
    if (startEvent.operation !== 'identity_enrollment_started'
        || String(startEvent.key) !== start.actionId
        || Buffer.from(startEvent.mutation_hash || []).toString('hex') !== start.mutation_hash
        || startMetadata?.schema !== 'hom.aimos.identity-enrollment-start/v1'
        || startMetadata?.identity_projection_sha256 !== start.projectionSha256
        || startMetadata?.certificate_sha256 !== projection.certificate_sha256
        || startMetadata?.pubkey_fingerprint !== projection.pubkey_fingerprint
        || startMetadata?.device_fingerprint !== projection.device_fingerprint
        || new Date(startMetadata?.valid_from).toISOString() !== projection.valid_from
        || new Date(startMetadata?.valid_until).toISOString() !== projection.valid_until) {
      throw new Error('identity_enrollment_start_binding_invalid');
    }
    const master = await client.query(
      'SELECT master_pubkey, fingerprint FROM aimos_master_identity WHERE id = 1 FOR SHARE',
    );
    const masterRow = master.rows[0];
    const certificate = verifyCertChain(row.cert, masterRow?.master_pubkey);
    if (!certificate.valid
        || certificate.body?.issuer !== 'aimos-master'
        || certificate.body?.agent_id !== row.agent_id
        || certificate.body?.pubkey !== row.pubkey
        || certificate.body?.device_fp !== row.device_fp
        || new Date(Number(certificate.body?.valid_from) * 1000).toISOString() !== projection.valid_from
        || new Date(Number(certificate.body?.valid_until) * 1000).toISOString() !== projection.valid_until) {
      throw new Error(`identity_enrollment_certificate_invalid:${certificate.reason || 'projection_mismatch'}`);
    }
    await client.query(
      `INSERT INTO agent_identity
         (agent_id, pubkey, cert, device_fp, valid_from, valid_until)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [row.agent_id, row.pubkey, row.cert, row.device_fp, row.valid_from, row.valid_until],
    );
    const terminal = await logEvent(
      AIMOS_COMPANY_ID,
      projection.agent_id,
      'identity_enrollment_committed',
      start.actionId,
      {
        schema: 'hom.aimos.identity-enrollment-terminal/v1',
        enrollment_action_id: start.actionId,
        start_event_id: start.event_id,
        start_mutation_hash: start.mutation_hash,
        identity_projection_sha256: start.projectionSha256,
        signing_material_sha256: signingMaterialSha256,
        cert_cache_sha256: certCacheSha256,
        disposition: 'SUCCESS',
        reasoning: 'The exact identity row and non-reconstructive file commitments were verified before this terminal co-committed with the row.',
      },
      start.event_id,
      { returnReceipt: true, client, identityQueryFn: client.query.bind(client) },
    );
    await client.query('COMMIT');
    return Object.freeze({ ok: true, terminal });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
}

export async function markAgentEnrollmentIndeterminate(start, error) {
  if (!start?.actionId || !start?.event_id) return null;
  return logEvent(
    AIMOS_COMPANY_ID,
    start.projection?.agent_id || 'unknown',
    'identity_enrollment_indeterminate',
    start.actionId,
    {
      schema: 'hom.aimos.identity-enrollment-terminal/v1',
      enrollment_action_id: start.actionId,
      start_event_id: start.event_id,
      start_mutation_hash: start.mutation_hash,
      identity_projection_sha256: start.projectionSha256,
      disposition: 'INDETERMINATE',
      error_class: error?.name || 'identity_enrollment_failure',
      reasoning: 'Enrollment did not reach a verified identity-row/file success terminal; reconciliation is required.',
    },
    start.event_id,
    { returnReceipt: true },
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
