// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: LIVE — commitGovernorMutation is called by STDP, Hebbian consensus
// and SPICED inside the owning restricted weight transaction.
// It signs with the `housekeeper` system operational identity
// (NOT a user-enrollable agent) and commits a REWEIGHT row to the live
// aimos_memory_provenance ledger. The owning transaction treats a missing
// certificate or failed receipt as an error and rolls the mutation back.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * governor-provenance.js — shared cryptographic ledger commit for governors
 *
 * STDP and Oja commit REWEIGHT rows to
 * the existing `aimos_memory_provenance` ledger (migration 018 + 021,
 * fully wired at Phase 4). This module encapsulates the sign + commit
 * flow so the governors stay focused on their math, not on crypto plumbing.
 *
 * Signing identity: `housekeeper` — the non-user-enrollable system operational
 * identity provisioned at deployment.
 * The housekeeper signs all server-side commits to aimos_memory_provenance
 * that are NOT user-initiated /save. This module + governor-config-ledger.js
 * and governor configuration import from housekeeper-signer.js —
 * single source of truth for the identity.
 *
 * REWEIGHT vs SAVE discrimination:
 *   . body.event_type = 'REWEIGHT' (Ed25519 signature-covered, tamper-evident)
 *   . The migration 022 `event_type` column is a denormalized copy for
 *     DB-level filtering. commitProvenance persists event_type + body_json
 *     in-transaction.
 *
 * Fail-closed behavior:
 *   The owning restricted transaction treats any unsuccessful return as an
 *   exception and rolls the retrieval-weight mutation back.
 *
 * Mutation hash form (memory-provenance.js:74):
 *   genesis  : sha256(content_hash || nonce || String(ts))
 *   mutation : sha256(content_hash || prev_mutation_hash || nonce || String(ts))
 *
 * Signature (agent-identity.js:277):
 *   sig = Ed25519_sign(JCS(body) || "\n" || nonce || "\n" || ts, privkey)
 *
 * Source: HOM Security Wiring Plan MASTER §10–§11 (Phase 4 grounding)
 */

import { createHash } from 'node:crypto';
import { memoryProvenanceLedger } from '../security/memory-provenance.js';
import {
  signAsHousekeeper,
  signCognitiveTransitionAsHousekeeper,
  HOUSEKEEPER_SIGNER_CONSTANTS,
} from '../security/housekeeper-signer.js';
import { contentHash } from '../security/identity-chain.js';
import { logEvent } from '../observe/event-ledger.js';
import { cognitiveAncestryBinding, cognitiveProjectionHash } from '../security/protocol/mutmem-protocol.js';

const COMPANY = 'hom';

export const GOVERNOR_PROVENANCE_CONSTANTS = Object.freeze({
  EVENT_TYPE_REWEIGHT: 'REWEIGHT',
  IDENTITY_TIER: HOUSEKEEPER_SIGNER_CONSTANTS.IDENTITY_TIER_MASTER_SIGNED
});

/**
 * Commit a governor mutation to the cryptographic ledger.
 *
 * @param {object} args
 * @param {string} args.memoryId — UUID string
 * @param {number} args.oldWeight — pre-mutation retrieval_weight
 * @param {number} args.newWeight — post-mutation retrieval_weight
 * @param {number} args.judgeValence — tanh valence in [-1, 1]
 * @param {string} args.governorFlag — 'COHEN_GROSSBERG_GOVERNOR' | 'OJA_NORMALIZATION_GOVERNOR'
 * @param {string} args.reason — 'energy_dampen' | 'oja_decomposition' | ...
 * @param {object} [args.extra] — additional body fields (e.g., delta_v, fixed_point)
 * @returns {Promise<{ ok: true, mutationHash: Buffer } | { ok: false, reason: string }>}
 */
export async function commitGovernorMutation({
  memoryId,
  oldWeight,
  newWeight,
  judgeValence,
  governorFlag,
  reason,
  extra = {},
  client = null
} = {}) {
  const { EVENT_TYPE_REWEIGHT, IDENTITY_TIER } = GOVERNOR_PROVENANCE_CONSTANTS;

  if (typeof memoryId !== 'string' || memoryId.length === 0) {
    return { ok: false, reason: 'malformed_input' };
  }
  if (typeof governorFlag !== 'string' || governorFlag.length === 0) {
    return { ok: false, reason: 'malformed_input' };
  }

  if (!client || typeof client.query !== 'function') return { ok: false, reason: 'cognitive_transaction_required' };
  // Same lock order as the existing weight/provenance owners. Both heads stay
  // stable until their owning transaction commits or rolls back.
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
    [`cognitive-reweight:${COMPANY}:${memoryId}`]);
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
    [`memory-provenance:${memoryId}`]);
  const nativeHead=await memoryProvenanceLedger.getLatestMutationHash(memoryId,client);
  const heads=(await client.query(`SELECT h.projection_hash FROM aimos_cognitive_weight_projections h
    WHERE h.company_id=$1 AND h.memory_id=$2 AND NOT EXISTS (
      SELECT 1 FROM aimos_cognitive_weight_projections s WHERE s.memory_id=h.memory_id
        AND s.prev_projection_hash=h.projection_hash) LIMIT 2`,[COMPANY,memoryId])).rows;
  if(heads.length>1) throw new Error('cognitive_projection_multiple_heads');
  const previousProjectionHash=heads[0]?.projection_hash || null;
  const ancestryBinding=cognitiveAncestryBinding({nativePredecessorKind:nativeHead.predecessorKind,
    nativePredecessorHash:nativeHead.prevMutationHash,nativePredecessorId:nativeHead.predecessorId,previousProjectionHash});

  const body = {
    event_type: EVENT_TYPE_REWEIGHT,
    company_id: COMPANY,
    memory_id: memoryId,
    old_weight: Number(oldWeight),
    new_weight: Number(newWeight),
    judge_valence: Number(judgeValence),
    governor_flag: governorFlag,
    reason,
    ...extra,
    ancestry_binding: ancestryBinding
    // ts_signed is injected by signAsHousekeeper BEFORE signing — sig covers
    // the same body that gets persisted (verifyPayloadSig invariant).
  };

  // The caller owns rollback and its post-transaction failure record. Opening
  // another event transaction here could wait on our own held stream lock.
  const signed = await signAsHousekeeper(body);

  const result = await memoryProvenanceLedger.commitProvenance({
    memoryId,
    body: signed.body,                     // body with ts_signed populated
    agentId: signed.agentId,                // 'housekeeper'
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    eventType: EVENT_TYPE_REWEIGHT,
    bodyJson: signed.body,
    client
  });

  if (!result?.ok) {
    throw new Error(`governor_provenance_rejected:${result?.reason || 'commit_failed'}`);
  }

  // Preserve the provenance content hash for the caller's receipt, then sign
  // a distinct fixed-width transition preimage. The latter binds tenant,
  // memory, integer-milliscaled old/new weights, and this exact provenance
  // mutation hash; the database reconstructs and verifies those same bytes.
  const contentHashBuf = contentHash(signed.body);
  const transitionProof = signCognitiveTransitionAsHousekeeper({
    companyId: COMPANY,
    memoryId,
    oldWeight,
    newWeight,
    provenanceMutationHash: result.mutationHash,
  });
  if ((result.prevMutationHash?.toString('hex') || null)
      !== ancestryBinding.native_predecessor.commitment_hex) throw new Error('cognitive_native_head_changed');
  const projectionHash=cognitiveProjectionHash({memoryId,oldWeightMilli:Math.round(oldWeight*1000),
    newWeightMilli:Math.round(newWeight*1000),provenanceMutationHash:result.mutationHash,previousHash:previousProjectionHash});
  const signerFingerprint=createHash('sha256').update(signed.certString).digest('hex');
  const ancestryReceipt=await logEvent(COMPANY,'housekeeper','cognitive_ancestry_bound',result.mutationHash.toString('hex'),{
    schema:'hom.aimos.cognitive-ancestry-bridge/v1',company_id:COMPANY,memory_id:memoryId,
    native_mutation_hash:result.mutationHash.toString('hex'),
    projection_hash:projectionHash.toString('hex'),ancestry_binding:ancestryBinding,
    old_weight_milli:Math.round(oldWeight*1000),new_weight_milli:Math.round(newWeight*1000),
    signer_agent_id:signed.agentId,signer_valid_from:signed.validFromIso,
    cert_fingerprint:signerFingerprint,
    attestation_kind:'atomic_transition',historical_origin_claimed:false,
    reasoning:'The existing Housekeeper transaction binds the typed native predecessor and projection predecessor to this exact signed REWEIGHT and its derived projection; it grants no additional operation authority.',
  },null,{client,returnReceipt:true,exclusiveOperationKey:true,signerConstraint:{agent_id:signed.agentId,
    valid_from:signed.validFromIso,cert_fingerprint:signerFingerprint,
    identity_tier:signed.identityTier}});

  return {
    ok: true,
    mutationHash: result.mutationHash,
    prevMutationHash: result.prevMutationHash,
    isGenesis: result.isGenesis,
    contentHash: contentHashBuf,
    transitionHash: transitionProof.transitionHash,
    transitionSig: transitionProof.transitionSig,
    ancestryEventId: ancestryReceipt.event_id,
  };
}

export default { commitGovernorMutation, GOVERNOR_PROVENANCE_CONSTANTS };
