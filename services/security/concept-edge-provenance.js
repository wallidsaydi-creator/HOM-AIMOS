/**
 * concept-edge-provenance.js — signed append-only Concept graph projection
 *
 * The existing concept_edges schema has no receipt foreign key and grants no
 * restricted runtime INSERT. CR7 therefore retired the runtime mutation owner
 * rather than preserve a broad-pool bypass. This module retains only the pure,
 * portable historical receipt contract and verifier.
 */

import { createHash } from 'node:crypto';

import {
  canonicalJson,
  verifyStoredPayloadSig,
} from './agent-identity.js';
import { eventMutationHash } from './protocol/mutmem-protocol.js';

export const CONCEPT_EDGE_PROVENANCE_SCHEMA = 'hom-aimos/concept-edge-provenance/v1';
export const CONCEPT_EDGE_OPERATION = 'concept_edge_appended';
export const CONCEPT_EDGE_ENFORCEMENT = 'detectable_code_level_no_projection_foreign_key';

const EDGE_IDENTITY_DOMAIN = Buffer.from('HOM-AIMOS-CONCEPT-EDGE-v1\0', 'utf8');
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_EDGE_TYPES = new Set([
  'NEXT',
  'DERIVED_FROM',
  'DERIVED_FROM_FACT',
  'HAS_CONCEPT',
  'ABOUT_CONCEPT',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function invalid(reason) {
  return Object.freeze({ valid: false, reason });
}

export function normalizeConceptEdge(edge = {}) {
  const companyId = String(edge.company_id || '').trim();
  const sourceId = String(edge.source_id || '').trim().toLowerCase();
  const targetId = String(edge.target_id || '').trim().toLowerCase();
  const edgeType = String(edge.edge_type || '').trim().toUpperCase();
  const rawWeight = edge.weight ?? edge.weight_q9 ?? 1;
  const weight = Number(rawWeight);

  if (!companyId) throw new Error('concept_edge_company_required');
  if (!UUID_PATTERN.test(sourceId)) throw new Error('concept_edge_source_uuid_invalid');
  if (!UUID_PATTERN.test(targetId)) throw new Error('concept_edge_target_uuid_invalid');
  if (sourceId === targetId) throw new Error('concept_edge_self_edge_forbidden');
  if (!ALLOWED_EDGE_TYPES.has(edgeType)) throw new Error('concept_edge_type_invalid');
  if (!Number.isFinite(weight) || weight <= 0 || weight > 1_000_000) {
    throw new Error('concept_edge_weight_invalid');
  }

  return Object.freeze({
    schema: CONCEPT_EDGE_PROVENANCE_SCHEMA,
    company_id: companyId,
    source_id: sourceId,
    target_id: targetId,
    edge_type: edgeType,
    weight_q9: weight.toFixed(9),
  });
}

export function conceptEdgeIdentityHash(edge) {
  const normalized = normalizeConceptEdge(edge);
  return sha256(Buffer.concat([
    EDGE_IDENTITY_DOMAIN,
    Buffer.from(canonicalJson(normalized), 'utf8'),
  ])).toString('hex');
}

export function conceptEdgeEventMetadata(edge) {
  const normalized = normalizeConceptEdge(edge);
  const identity = conceptEdgeIdentityHash(normalized);
  return Object.freeze({
    schema: CONCEPT_EDGE_PROVENANCE_SCHEMA,
    edge_identity_sha256: identity,
    edge: normalized,
    projection_table: 'concept_edges',
    enforcement: CONCEPT_EDGE_ENFORCEMENT,
    canonical_memory_changed: false,
    retention_changed: false,
    reasoning: 'The native Concept graph writer appended one deterministic edge projection and its housekeeper-signed evidence atomically.',
    source_knowledge: 'GAAMA graph construction adapted to the HOM-AIMOS signed event ledger',
  });
}

export function verifyConceptEdgeReceipt(edge, receipt = {}, signerPubkey = '') {
  try {
    const normalized = normalizeConceptEdge(edge);
    const identity = conceptEdgeIdentityHash(normalized);
    const body = receipt.signed_body;
    if (!body || receipt.proof_required !== true || Number(receipt.ledger_version) !== 1) {
      return invalid('concept_edge_receipt_version');
    }
    if (
      body.operation !== CONCEPT_EDGE_OPERATION
      || body.key !== identity
      || canonicalJson(body.metadata) !== canonicalJson(conceptEdgeEventMetadata(normalized))
    ) {
      return invalid('concept_edge_receipt_binding');
    }

    const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
    if (contentHash.toString('hex') !== String(receipt.content_hash || '')) {
      return invalid('concept_edge_receipt_content_hash');
    }
    const predecessor = Buffer.from(String(receipt.prev_mutation_hash || ''), 'hex');
    if (predecessor.length !== 32) return invalid('concept_edge_receipt_predecessor');
    const mutationHash = eventMutationHash(
      predecessor,
      contentHash,
      String(receipt.nonce || ''),
      Number(receipt.ts_signed),
    );
    if (mutationHash.toString('hex') !== String(receipt.mutation_hash || '')) {
      return invalid('concept_edge_receipt_mutation_hash');
    }
    const signature = verifyStoredPayloadSig(
      signerPubkey,
      body,
      String(receipt.nonce || ''),
      Number(receipt.ts_signed),
      String(receipt.signature || ''),
    );
    return signature.valid
      ? Object.freeze({ valid: true, reason: null, edge_identity_sha256: identity })
      : invalid(`concept_edge_receipt_${signature.reason}`);
  } catch {
    return invalid('concept_edge_receipt_malformed');
  }
}
