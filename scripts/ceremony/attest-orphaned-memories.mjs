#!/usr/bin/env node

// Append a v3 portable BIND to every retained memory that predates the native
// SAVE -> BIND protocol. The new housekeeper signature attests the exact
// retained provenance head (if any), current live-content hash, and exact
// supersession edge. It never rewrites history or fabricates an origin SAVE.
//
// Safe recovery boundary: one restricted transaction per memory. A failed
// memory rolls back its supersession edge and BIND together; successful prior
// memories remain retained. The unique v3 index makes reruns idempotent.

import { createHash } from 'node:crypto';

import { agentPool, pool, query } from '../../db/connection.js';
import { canonicalJson } from '../../services/security/agent-identity.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import {
  memoryProvenanceLedger,
  orderProvenanceRowsByTopology,
  retainedProvenanceMerkleRoot,
  verifyRecallEvidenceRow,
} from '../../services/security/memory-provenance.js';
import { commitHousekeeperSupersession } from '../../services/security/memory-lineage.js';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';

const live = process.argv.includes('--live');
const database = resolveAimosDatabaseName();

async function census() {
  const result = await query(
    `SELECT count(*)::int AS memories,
            count(*) FILTER (WHERE binding.memory_id IS NULL)::int AS requiring_upgrade,
            count(*) FILTER (WHERE p.memory_id IS NULL)::int AS without_provenance,
            count(*) FILTER (
              WHERE m.supersedes_id IS NOT NULL AND edge.post_memory_id IS NULL
            )::int AS missing_supersession_edges
       FROM aimos_memories m
       LEFT JOIN (
         SELECT DISTINCT memory_id FROM aimos_memory_provenance
          WHERE event_type = 'BIND' AND binding_schema_version = 3
       ) binding ON binding.memory_id = m.id
       LEFT JOIN (
         SELECT DISTINCT memory_id FROM aimos_memory_provenance
       ) p ON p.memory_id = m.id
       LEFT JOIN supersession_events edge
         ON edge.company_id = m.company_id
        AND edge.post_memory_id = m.id
        AND edge.prior_memory_id = m.supersedes_id`
  );
  return result.rows[0];
}

async function attestMemory(memoryId) {
  const identity = await query(
    `SELECT company_id, agent_id FROM aimos_memories WHERE id = $1`,
    [memoryId]
  );
  if (!identity.rows[0]) throw new Error(`${memoryId}: memory_missing`);
  const { company_id: companyId } = identity.rows[0];
  const client = await agentPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', companyId]);
    await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`memory-provenance:${memoryId}`]
    );

    const memoryResult = await client.query(
      `SELECT id::text, company_id, agent_id, key, value, scope,
              clearance_level, data_class, memory_type, source, created_at,
              content_hash, supersedes_id::text
         FROM aimos_memories
        WHERE id = $1`,
      [memoryId]
    );
    const memory = memoryResult.rows[0];
    if (!memory) throw new Error(`${memoryId}: memory_not_visible`);
    if (!Buffer.isBuffer(memory.content_hash) || memory.content_hash.length !== 32) {
      throw new Error(`${memoryId}: live_content_hash_missing`);
    }

    const existing = await client.query(
      `SELECT mutation_hash
         FROM aimos_memory_provenance
        WHERE memory_id = $1 AND event_type = 'BIND' AND binding_schema_version = 3
        LIMIT 1`,
      [memoryId]
    );
    if (existing.rows[0]) {
      await client.query('ROLLBACK');
      return {
        memory_id: memoryId,
        status: 'already_bound',
        binding_mutation_hash: Buffer.from(existing.rows[0].mutation_hash).toString('hex'),
      };
    }

    let supersessionEventId = null;
    let predecessorLiveContentHash = null;
    let lineageMutationHash = null;
    if (memory.supersedes_id) {
      const predecessor = await client.query(
        `SELECT content_hash
           FROM aimos_memories
          WHERE company_id = $1 AND id = $2::uuid AND key = $3
          LIMIT 1`,
        [memory.company_id, memory.supersedes_id, memory.key]
      );
      const predecessorHash = predecessor.rows[0]?.content_hash;
      if (!Buffer.isBuffer(predecessorHash) || predecessorHash.length !== 32) {
        throw new Error(`${memoryId}: supersession_predecessor_hash_missing`);
      }
      predecessorLiveContentHash = predecessorHash.toString('hex');
      const retainedEdge = await client.query(
        `SELECT id, prior_memory_id::text, trigger_type, metadata
           FROM supersession_events
          WHERE company_id = $1 AND post_memory_id = $2::uuid
          LIMIT 1`,
        [memory.company_id, memory.id]
      );
      if (retainedEdge.rows[0]
        && retainedEdge.rows[0].prior_memory_id !== memory.supersedes_id) {
        throw new Error(`${memoryId}: supersession_edge_conflict`);
      }
      let edge;
      if (retainedEdge.rows[0]) {
        edge = retainedEdge.rows[0];
        supersessionEventId = Number(edge.id);
      } else {
        const repairMetadata = {
          relation: 'supersedes',
          attestation: 'portable_binding_v3',
          historical_origin_signature_claimed: false,
        };
        const inserted = await client.query(
          `INSERT INTO supersession_events
             (company_id, prior_memory_id, post_memory_id, trigger_type, metadata)
           VALUES ($1, $2::uuid, $3::uuid, 'retained_upgrade', $4::jsonb)
           RETURNING id`,
          [
            memory.company_id,
            memory.supersedes_id,
            memory.id,
            JSON.stringify(repairMetadata),
          ]
        );
        supersessionEventId = Number(inserted.rows[0].id);
        edge = { id: supersessionEventId, trigger_type: 'retained_upgrade', metadata: repairMetadata };
      }
      const lineage = await commitHousekeeperSupersession({
        client,
        companyId: memory.company_id,
        key: memory.key,
        childId: memory.id,
        parentId: memory.supersedes_id,
        childLiveContentHash: memory.content_hash,
        parentLiveContentHash: predecessorHash,
        supersessionEventId,
        triggerType: edge.trigger_type,
        metadata: edge.metadata,
        correction: edge.trigger_type === 'correction',
        attestationReason: 'retained_memory_portable_upgrade',
      });
      lineageMutationHash = Buffer.from(lineage.mutationHash).toString('hex');
    }

    const provenance = await client.query(
      `SELECT p.*,
              p.memory_id::text AS memory_id,
              p.agent_id AS provenance_agent_id,
              p.content_hash AS prov_content_hash,
              p.live_content_hash AS snapshot_live_content_hash,
              p.created_at AS provenance_created_at,
              m.company_id AS live_company_id,
              m.agent_id AS live_agent_id,
              m.key AS live_key,
              m.value AS live_value,
              m.scope AS live_scope,
              m.memory_type AS live_memory_type,
              m.clearance_level AS live_clearance_level,
              m.data_class AS live_data_class,
              m.source AS live_source,
              m.content_hash AS live_content_hash,
              m.supersedes_id,
              EXISTS (SELECT 1 FROM aimos_memories successor
                       WHERE successor.company_id=m.company_id
                         AND successor.key=m.key
                         AND successor.supersedes_id=m.id) AS has_successor,
              ai.pubkey AS signer_pubkey,
              ai.cert AS signer_cert,
              ai.device_fp AS signer_device_fp,
              ai.valid_until AS signer_valid_until,
              master.master_pubkey,
              master.fingerprint AS master_fingerprint,
              rev.master_fingerprint AS revocation_master_fingerprint,
              rev.target_cert_hash AS revocation_target_cert_hash,
              rev.prior_identity_hash AS revocation_prior_identity_hash,
              rev.signed_body AS revocation_signed_body,
              rev.content_hash AS revocation_content_hash,
              rev.mutation_hash AS revocation_mutation_hash,
              rev.ts_signed AS revocation_ts_signed,
              rev.nonce AS revocation_nonce,
              rev.sig AS revocation_sig
         FROM aimos_memory_provenance p
         JOIN aimos_memories m ON m.id=p.memory_id
         LEFT JOIN agent_identity ai
           ON ai.agent_id=p.agent_id AND ai.valid_from=p.agent_valid_from
         LEFT JOIN aimos_master_identity master ON master.id=1
         LEFT JOIN aimos_agent_revocation_events rev
           ON rev.agent_id=ai.agent_id AND rev.agent_valid_from=ai.valid_from
        WHERE p.memory_id = $1`,
      [memoryId]
    );
    const retainedRows = orderProvenanceRowsByTopology(provenance.rows);
    const saveRows = retainedRows.filter((row) => row.event_type === 'SAVE');
    const originalSave = saveRows.length === 1 && verifyRecallEvidenceRow(saveRows[0]).valid
      ? saveRows[0]
      : null;
    let authorityRow = originalSave;
    let originEvidenceState = originalSave ? 'original_save_verified' : 'retrospectively_attested';
    let predecessorNodeCount = retainedRows.length;
    let predecessorMutationHash = retainedRows.length
      ? Buffer.from(retainedRows.at(-1).mutation_hash).toString('hex')
      : null;

    if (!originalSave) {
      const retainedRoot = retainedProvenanceMerkleRoot(retainedRows).toString('hex');
      const attestationSigned = await signAsHousekeeper({
        event_type: 'RETAINED_ATTEST',
        memory_id: memory.id,
        company_id: memory.company_id,
        subject_agent_id: memory.agent_id,
        key: memory.key,
        live_content_hash: memory.content_hash.toString('hex'),
        attestation_reason: 'retained_memory_portable_upgrade',
        historical_origin_signature_claimed: false,
        observed_memory_originated_at: new Date(memory.created_at).toISOString(),
        retained_provenance_merkle_root: retainedRoot,
        retained_provenance_node_count: retainedRows.length,
        attested_predecessor_mutation_hash: predecessorMutationHash,
        supersedes_id: memory.supersedes_id || null,
        supersession_event_id: supersessionEventId,
        predecessor_live_content_hash: predecessorLiveContentHash,
        lineage_mutation_hash: lineageMutationHash,
      });
      const attestation = await memoryProvenanceLedger.commitProvenance({
        memoryId: memory.id,
        body: attestationSigned.body,
        agentId: attestationSigned.agentId,
        validFromIso: attestationSigned.validFromIso,
        certString: attestationSigned.certString,
        signedTs: attestationSigned.signedTs,
        nonce: attestationSigned.nonce,
        sigBytes: attestationSigned.sigBytes,
        identityTier: attestationSigned.identityTier,
        requestSigForm: attestationSigned.sigForm,
        eventType: 'RETAINED_ATTEST',
        bodyJson: attestationSigned.body,
        liveContentHash: memory.content_hash,
        bindingSchemaVersion: 2,
        client,
      });
      if (!attestation.ok) throw new Error(`${memoryId}: ${attestation.reason}`);
      authorityRow = {
        event_type: 'RETAINED_ATTEST',
        prov_content_hash: attestation.contentHash,
        mutation_hash: attestation.mutationHash,
        sig: attestationSigned.sigBytes,
        provenance_agent_id: attestationSigned.agentId,
        agent_valid_from: attestationSigned.validFromIso,
      };
      predecessorNodeCount += 1;
      predecessorMutationHash = Buffer.from(attestation.mutationHash).toString('hex');
    }

    const signed = await signAsHousekeeper({
      event_type: 'BIND',
      binding_schema_version: 3,
      memory_id: memory.id,
      company_id: memory.company_id,
      subject_agent_id: memory.agent_id,
      key: memory.key,
      live_content_hash: memory.content_hash.toString('hex'),
      attestation_reason: 'retained_memory_portable_upgrade',
      origin_evidence_state: originEvidenceState,
      historical_origin_signature_claimed: false,
      attested_predecessor_mutation_hash: predecessorMutationHash,
      attested_predecessor_node_count: predecessorNodeCount,
      supersedes_id: memory.supersedes_id || null,
      supersession_event_id: supersessionEventId,
      predecessor_live_content_hash: predecessorLiveContentHash,
      lineage_mutation_hash: lineageMutationHash,
      authority_event_type: authorityRow.event_type,
      authority_content_hash: Buffer.from(authorityRow.prov_content_hash).toString('hex'),
      authority_mutation_hash: Buffer.from(authorityRow.mutation_hash).toString('hex'),
      authority_signature_hash: createHash('sha256').update(Buffer.from(authorityRow.sig)).digest('hex'),
      authority_signer_agent_id: authorityRow.provenance_agent_id,
      authority_signer_valid_from: new Date(authorityRow.agent_valid_from).toISOString(),
    });
    const binding = await memoryProvenanceLedger.commitProvenance({
      memoryId: memory.id,
      body: signed.body,
      agentId: signed.agentId,
      validFromIso: signed.validFromIso,
      certString: signed.certString,
      signedTs: signed.signedTs,
      nonce: signed.nonce,
      sigBytes: signed.sigBytes,
      identityTier: signed.identityTier,
      requestSigForm: signed.sigForm,
      eventType: 'BIND',
      bodyJson: signed.body,
      liveContentHash: memory.content_hash,
      bindingSchemaVersion: 3,
      client,
    });
    if (!binding.ok) throw new Error(`${memoryId}: ${binding.reason}`);
    await client.query('COMMIT');
    return {
      memory_id: memoryId,
      status: 'bound',
      origin_evidence_state: originEvidenceState,
      lineage_mutation_hash: lineageMutationHash,
      binding_content_hash: Buffer.from(binding.contentHash).toString('hex'),
      binding_mutation_hash: Buffer.from(binding.mutationHash).toString('hex'),
    };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
}

try {
  const before = await census();
  if (!live) {
    console.log(JSON.stringify({ database, mode: 'DRY_RUN', before }, null, 2));
  } else {
    const targets = await query(
      `SELECT m.id::text
         FROM aimos_memories m
        WHERE NOT EXISTS (
          SELECT 1 FROM aimos_memory_provenance p
           WHERE p.memory_id = m.id
             AND p.event_type = 'BIND'
             AND p.binding_schema_version = 3
        )
        ORDER BY m.created_at, m.id`
    );
    const proofs = [];
    for (const target of targets.rows) proofs.push(await attestMemory(target.id));
    const after = await census();
    const proofRoot = createHash('sha256').update(canonicalJson(proofs)).digest('hex');
    console.log(JSON.stringify({
      database,
      mode: 'LIVE',
      before,
      after,
      bound: proofs.filter((proof) => proof.status === 'bound').length,
      proof_root_sha256: proofRoot,
      proofs,
    }, null, 2));
  }
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
