// Database-facing reader for MutMem cognitive-weight evidence.
//
// This module owns only the read-side transaction and schema projection. It
// emits a versioned JSON-safe evidence bundle, then delegates all cryptographic
// and structural decisions to the authority-free verifier in protocol/.
// It has no signing, mutation, policy, route, model, or private-key authority.

import { agentPool } from '../../db/connection.js';
import {
  createCognitiveWeightEvidenceBundle,
  verifyCognitiveWeightEvidenceBundle,
  verifyPortableCognitiveBaseline,
  verifyPortableCognitiveState,
} from './protocol/cognitive-weight-evidence.js';

export {
  verifyPortableCognitiveBaseline,
  verifyPortableCognitiveState,
};

/**
 * Read one transaction-consistent cognitive evidence snapshot.
 *
 * Passing a client preserves the caller-owned transaction boundary. Without a
 * client, this function opens and closes its own read transaction.
 */
export async function readCognitiveWeightEvidenceBundle({ companyId, client = null } = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('cognitive_company_scope_required');
  const ownsTransaction = !client;
  const conn = client || await agentPool.connect();
  try {
    if (ownsTransaction) {
      await conn.query('BEGIN READ ONLY');
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    }

    // One PostgreSQL client owns this snapshot. Queries stay sequential so the
    // evidence bundle cannot mix transaction states.
    const master = await conn.query(
      `SELECT master_pubkey, fingerprint AS master_fingerprint
         FROM aimos_master_identity WHERE id=1`,
    );
    const memories = await conn.query(
      `SELECT id::text, company_id, content_hash, retrieval_weight
         FROM aimos_memories
        WHERE company_id=$1
        ORDER BY id`,
      [company],
    );
    const baselines = await conn.query(
      `SELECT b.*, i.agent_id, i.pubkey, i.cert, i.device_fp,
              i.valid_from, i.valid_until,
              master.master_pubkey, master.master_fingerprint,
              rev.master_fingerprint AS revocation_master_fingerprint,
              rev.target_cert_hash AS revocation_target_cert_hash,
              rev.prior_identity_hash AS revocation_prior_identity_hash,
              rev.signed_body AS revocation_signed_body,
              rev.content_hash AS revocation_content_hash,
              rev.mutation_hash AS revocation_mutation_hash,
              rev.ts_signed AS revocation_ts_signed,
              rev.nonce AS revocation_nonce, rev.sig AS revocation_sig
         FROM aimos_cognitive_weight_baselines b
         JOIN agent_identity i
           ON i.agent_id=b.signer_agent_id AND i.valid_from=b.signer_valid_from
         LEFT JOIN LATERAL (
           SELECT master_pubkey, fingerprint AS master_fingerprint
             FROM aimos_master_identity WHERE id=1
         ) master ON true
         LEFT JOIN aimos_agent_revocation_events rev
           ON rev.agent_id=i.agent_id AND rev.agent_valid_from=i.valid_from
        WHERE b.company_id=$1`,
      [company],
    );
    const events = await conn.query(
      `SELECT e.*, i.pubkey, i.cert, i.device_fp, i.valid_until,
              rev.master_fingerprint AS revocation_master_fingerprint,
              rev.target_cert_hash AS revocation_target_cert_hash,
              rev.prior_identity_hash AS revocation_prior_identity_hash,
              rev.signed_body AS revocation_signed_body,
              rev.content_hash AS revocation_content_hash,
              rev.mutation_hash AS revocation_mutation_hash,
              rev.ts_signed AS revocation_ts_signed,
              rev.nonce AS revocation_nonce, rev.sig AS revocation_sig
         FROM aimos_events e
         JOIN agent_identity i
           ON i.agent_id=e.signer_agent_id AND i.valid_from=e.signer_valid_from
         LEFT JOIN aimos_agent_revocation_events rev
           ON rev.agent_id=i.agent_id AND rev.agent_valid_from=i.valid_from
        WHERE e.company_id=$1 AND e.signer_agent_id='housekeeper'
          AND e.ledger_version=1
        ORDER BY e.signer_valid_from,e.ledger_seq`,
      [company],
    );
    const projections = await conn.query(
      `SELECT p.*,
              pr.provenance_id, pr.body_json, pr.content_hash AS prov_content_hash,
              pr.mutation_hash, pr.prev_mutation_hash, pr.ts_signed, pr.nonce,
              pr.sig, pr.event_type, pr.binding_schema_version,
              pr.agent_id AS provenance_agent_id,
              pr.agent_valid_from, pr.cert_fingerprint, pr.identity_tier,
              pr.sig_form_version, pr.request_sig_form, pr.signed_method,
              pr.signed_path, pr.signed_claims, pr.is_genesis, pr.backfilled,
              pr.memory_originated_at, i.pubkey AS signer_pubkey,
              i.cert AS signer_cert, i.valid_until AS signer_valid_until,
              i.device_fp AS signer_device_fp,
              master.master_pubkey, master.fingerprint AS master_fingerprint,
              rev.master_fingerprint AS revocation_master_fingerprint,
              rev.target_cert_hash AS revocation_target_cert_hash,
              rev.prior_identity_hash AS revocation_prior_identity_hash,
              rev.signed_body AS revocation_signed_body,
              rev.content_hash AS revocation_content_hash,
              rev.mutation_hash AS revocation_mutation_hash,
              rev.ts_signed AS revocation_ts_signed,
              rev.nonce AS revocation_nonce, rev.sig AS revocation_sig
         FROM aimos_cognitive_weight_projections p
         JOIN aimos_memory_provenance pr
           ON pr.memory_id=p.memory_id AND pr.mutation_hash=p.provenance_mutation_hash
         JOIN agent_identity i
           ON i.agent_id=pr.agent_id AND i.valid_from=pr.agent_valid_from
         LEFT JOIN aimos_agent_revocation_events rev
           ON rev.agent_id=i.agent_id AND rev.agent_valid_from=i.valid_from
         LEFT JOIN LATERAL (
           SELECT master_pubkey, fingerprint FROM aimos_master_identity WHERE id=1
         ) master ON true
        WHERE p.company_id=$1
        ORDER BY p.memory_id,p.projection_id`,
      [company],
    );
    const sqlRows = await conn.query(
      `SELECT * FROM public.verify_all_cognitive_weight_chains() ORDER BY memory_id`,
    );

    const bundle = createCognitiveWeightEvidenceBundle({
      companyId: company,
      masterIdentity: master.rows[0] || {},
      memories: memories.rows,
      baselines: baselines.rows,
      events: events.rows,
      projections: projections.rows,
      sqlRows: sqlRows.rows,
    });
    if (ownsTransaction) await conn.query('COMMIT');
    return bundle;
  } catch (error) {
    if (ownsTransaction) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be unavailable */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) conn.release();
  }
}

/**
 * Compatibility entry point retained for ceremonies and existing tests.
 */
export async function verifyCognitiveWeightCorpus({ companyId, client = null } = {}) {
  const bundle = await readCognitiveWeightEvidenceBundle({ companyId, client });
  const verified = verifyCognitiveWeightEvidenceBundle(bundle);
  return {
    ...verified,
    bundle,
  };
}
