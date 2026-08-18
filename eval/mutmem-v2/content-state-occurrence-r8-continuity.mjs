/**
 * R8 authority-free class-map and continuity kernel.
 *
 * Sources: RFC 6962 domain-separated Merkle trees; Crosby/Wallach append-only
 * tamper-evident logs. This module owns no database, filesystem, network,
 * signer, policy, mutation, classification, or environment authority.
 */

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

export const R8_CONTINUITY_CONTRACT = Object.freeze({
  artifact_schema: 'hom.aimos.content-state-occurrence-r8-continuity/v1',
  event_schema: 'hom.aimos.content-state-occurrence-continuity-event/v1',
  occurrence_leaf_source: 'aimos.retained-provenance-leaf/v1',
  time_complexity: 'O(memories_plus_occurrences_plus_evidence_plus_topology)',
  space_complexity: 'O(memories_plus_occurrences)',
  canonical_mutation_authority: false,
  deletion_authority: false,
});

const DOMAINS = Object.freeze({
  provenanceNode: Buffer.from('aimos.retained-provenance-node/v1\0', 'utf8'),
  provenanceEmpty: Buffer.from('aimos.retained-provenance-empty/v1\0', 'utf8'),
  partitionLeaf: Buffer.from('hom.aimos.class-map-partition-leaf/v1\0', 'utf8'),
  partitionNode: Buffer.from('hom.aimos.class-map-partition-node/v1\0', 'utf8'),
  partitionEmpty: Buffer.from('hom.aimos.class-map-partition-empty/v1\0', 'utf8'),
  evidenceLeaf: Buffer.from('hom.aimos.class-map-evidence-leaf/v1\0', 'utf8'),
  evidenceNode: Buffer.from('hom.aimos.class-map-evidence-node/v1\0', 'utf8'),
  evidenceEmpty: Buffer.from('hom.aimos.class-map-evidence-empty/v1\0', 'utf8'),
  topologyLeaf: Buffer.from('hom.aimos.class-map-topology-leaf/v1\0', 'utf8'),
  topologyNode: Buffer.from('hom.aimos.class-map-topology-node/v1\0', 'utf8'),
  topologyEmpty: Buffer.from('hom.aimos.class-map-topology-empty/v1\0', 'utf8'),
  decision: Buffer.from('hom.aimos.class-map-continuity-decision/v1\0', 'utf8'),
});
const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fail(code) {
  throw new Error(`r8_continuity:${code}`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function domainLeaf(domain, value) {
  return sha256(Buffer.concat([domain, Buffer.from(canonicalJson(value), 'utf8')]));
}

function merkleRootFromHashes(hashes, nodeDomain, emptyDomain) {
  if (!Array.isArray(hashes) || hashes.some((hash) => !Buffer.isBuffer(hash) || hash.length !== 32)) {
    fail('merkle_leaf_invalid');
  }
  if (!hashes.length) return sha256(emptyDomain);
  let level = hashes.map((hash) => Buffer.from(hash));
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] || left;
      next.push(sha256(Buffer.concat([nodeDomain, left, right])));
    }
    level = next;
  }
  return level[0];
}

export function retainedProvenanceRootFromLeafHashes(leafHashes = []) {
  return merkleRootFromHashes(
    leafHashes.map((value) => {
      const normalized = String(value || '').toLowerCase();
      if (!HEX32.test(normalized)) fail('provenance_leaf_hash_invalid');
      return Buffer.from(normalized, 'hex');
    }),
    DOMAINS.provenanceNode,
    DOMAINS.provenanceEmpty,
  ).toString('hex');
}

function normalizeMemory(record = {}) {
  const normalized = {
    memory_id: String(record.memory_id || '').toLowerCase(),
    company_id: String(record.company_id || ''),
    live_content_hash: String(record.live_content_hash || '').toLowerCase(),
    principal_id: String(record.principal_id || ''),
    supersedes_id: record.supersedes_id == null ? null : String(record.supersedes_id).toLowerCase(),
    topology_commitment: String(record.topology_commitment || '').toLowerCase(),
    evidence_scope_commitment: String(record.evidence_scope_commitment || '').toLowerCase(),
  };
  if (!UUID.test(normalized.memory_id) || !normalized.company_id
      || !HEX32.test(normalized.live_content_hash) || !normalized.principal_id
      || (normalized.supersedes_id != null && !UUID.test(normalized.supersedes_id))
      || !HEX32.test(normalized.topology_commitment)
      || !HEX32.test(normalized.evidence_scope_commitment)) {
    fail('memory_record_invalid');
  }
  return Object.freeze(normalized);
}

function normalizeOccurrence(record = {}) {
  const normalized = {
    occurrence_ref: String(record.occurrence_ref || '').toLowerCase(),
    memory_id: String(record.memory_id || '').toLowerCase(),
    live_content_hash: String(record.live_content_hash || '').toLowerCase(),
    provenance_leaf_hash: String(record.provenance_leaf_hash || '').toLowerCase(),
    event_type: String(record.event_type || '').toUpperCase(),
    signed_time: Number(record.signed_time),
    signature_form_version: Number(record.signature_form_version),
  };
  if (!HEX32.test(normalized.occurrence_ref) || !UUID.test(normalized.memory_id)
      || !HEX32.test(normalized.live_content_hash)
      || !HEX32.test(normalized.provenance_leaf_hash)
      || !normalized.event_type || !Number.isSafeInteger(normalized.signed_time)
      || normalized.signed_time <= 0 || !Number.isSafeInteger(normalized.signature_form_version)
      || normalized.signature_form_version < 1) {
    fail('occurrence_record_invalid');
  }
  return Object.freeze(normalized);
}

export function buildR8ClassMap({ companyId, memories = [], occurrences = [] } = {}) {
  const company = String(companyId || '');
  if (!company || !Array.isArray(memories) || !Array.isArray(occurrences)) fail('input_invalid');
  const normalizedMemories = memories.map(normalizeMemory)
    .sort((left, right) => left.memory_id.localeCompare(right.memory_id));
  const memoryById = new Map();
  for (const memory of normalizedMemories) {
    if (memory.company_id !== company || memoryById.has(memory.memory_id)) fail('memory_identity_invalid');
    memoryById.set(memory.memory_id, memory);
  }
  const normalizedOccurrences = occurrences.map(normalizeOccurrence)
    .sort((left, right) => left.occurrence_ref.localeCompare(right.occurrence_ref));
  const occurrenceRefs = new Set();
  const occurrenceCountByMemory = new Map();
  for (const occurrence of normalizedOccurrences) {
    const memory = memoryById.get(occurrence.memory_id);
    if (!memory || memory.live_content_hash !== occurrence.live_content_hash
        || occurrenceRefs.has(occurrence.occurrence_ref)) {
      fail('occurrence_membership_invalid');
    }
    occurrenceRefs.add(occurrence.occurrence_ref);
    occurrenceCountByMemory.set(
      occurrence.memory_id,
      (occurrenceCountByMemory.get(occurrence.memory_id) || 0) + 1,
    );
  }
  if (normalizedMemories.some((memory) => !occurrenceCountByMemory.has(memory.memory_id))) {
    fail('memory_without_occurrence');
  }

  const groups = new Map();
  for (const memory of normalizedMemories) {
    if (!groups.has(memory.live_content_hash)) groups.set(memory.live_content_hash, []);
    groups.get(memory.live_content_hash).push(memory);
  }
  const occurrencesByState = new Map();
  for (const occurrence of normalizedOccurrences) {
    if (!occurrencesByState.has(occurrence.live_content_hash)) {
      occurrencesByState.set(occurrence.live_content_hash, []);
    }
    occurrencesByState.get(occurrence.live_content_hash).push(occurrence.occurrence_ref);
  }
  const partitions = [...groups.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([contentHash, members]) => Object.freeze({
      schema: 'hom.aimos.class-map-partition/v1',
      company_id: company,
      live_content_hash: contentHash,
      memory_ids: members.map((member) => member.memory_id).sort(),
      principal_ids: [...new Set(members.map((member) => member.principal_id))].sort(),
      occurrence_refs: [...(occurrencesByState.get(contentHash) || [])].sort(),
      evidence_scope_commitments: members
        .map((member) => member.evidence_scope_commitment).sort(),
      topology_commitments: members.map((member) => member.topology_commitment).sort(),
    }));
  const partitionOccurrenceRefs = partitions.flatMap((partition) => partition.occurrence_refs);
  if (partitionOccurrenceRefs.length !== normalizedOccurrences.length
      || new Set(partitionOccurrenceRefs).size !== normalizedOccurrences.length
      || partitionOccurrenceRefs.some((ref) => !occurrenceRefs.has(ref))) {
    fail('partition_completeness_invalid');
  }

  const occurrenceRoot = retainedProvenanceRootFromLeafHashes(
    normalizedOccurrences.map((record) => record.provenance_leaf_hash),
  );
  const partitionRoot = merkleRootFromHashes(
    partitions.map((partition) => domainLeaf(DOMAINS.partitionLeaf, partition)),
    DOMAINS.partitionNode,
    DOMAINS.partitionEmpty,
  ).toString('hex');
  const evidenceRoot = merkleRootFromHashes(
    normalizedMemories.map((memory) => domainLeaf(DOMAINS.evidenceLeaf, {
      memory_id: memory.memory_id,
      live_content_hash: memory.live_content_hash,
      evidence_scope_commitment: memory.evidence_scope_commitment,
    })),
    DOMAINS.evidenceNode,
    DOMAINS.evidenceEmpty,
  ).toString('hex');
  const topologyRoot = merkleRootFromHashes(
    normalizedMemories.map((memory) => domainLeaf(DOMAINS.topologyLeaf, {
      memory_id: memory.memory_id,
      live_content_hash: memory.live_content_hash,
      supersedes_id: memory.supersedes_id,
      topology_commitment: memory.topology_commitment,
    })),
    DOMAINS.topologyNode,
    DOMAINS.topologyEmpty,
  ).toString('hex');
  const repeated = partitions.filter((partition) => partition.memory_ids.length > 1);
  return Object.freeze({
    memories: Object.freeze(normalizedMemories),
    occurrences: Object.freeze(normalizedOccurrences),
    partitions: Object.freeze(partitions),
    summary: Object.freeze({
      memory_count: normalizedMemories.length,
      occurrence_count: normalizedOccurrences.length,
      content_state_count: partitions.length,
      repeated_group_count: repeated.length,
      repeated_row_count: repeated.reduce((sum, partition) => sum + partition.memory_ids.length, 0),
      excess_row_count: repeated.reduce((sum, partition) => sum + partition.memory_ids.length - 1, 0),
      occurrence_root: occurrenceRoot,
      partition_root: partitionRoot,
      evidence_scope_root: evidenceRoot,
      topology_root: topologyRoot,
    }),
  });
}

export function continuityDecisionHash(body = {}) {
  if (!body || body.schema !== R8_CONTINUITY_CONTRACT.event_schema
      || !Number.isSafeInteger(body.sequence) || body.sequence < 1
      || !HEX32.test(String(body.occurrence_root || ''))
      || !HEX32.test(String(body.partition_root || ''))
      || !HEX32.test(String(body.evidence_scope_root || ''))
      || !HEX32.test(String(body.topology_root || ''))
      || !HEX32.test(String(body.source_closure_sha256 || ''))
      || !HEX32.test(String(body.external_checkpoint_sha256 || ''))) {
    fail('continuity_body_invalid');
  }
  if (body.sequence === 1) {
    if (body.predecessor_event_id != null || body.predecessor_decision_sha256 != null) {
      fail('continuity_genesis_invalid');
    }
  } else if (!UUID.test(String(body.predecessor_event_id || ''))
      || !HEX32.test(String(body.predecessor_decision_sha256 || ''))) {
    fail('continuity_predecessor_invalid');
  }
  return sha256(Buffer.concat([
    DOMAINS.decision,
    Buffer.from(canonicalJson(body), 'utf8'),
  ])).toString('hex');
}
