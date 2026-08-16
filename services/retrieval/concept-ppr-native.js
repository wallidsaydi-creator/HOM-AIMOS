/**
 * concept-ppr-native.js — persistent, source-bound Concept/PPR retrieval gear
 *
 * Paper authority: HippoRAG (arXiv:2405.14831, NeurIPS 2024).
 * Paper-shaped path:
 *   retained passage -> phrase/entity nodes + relation/synonym edges;
 *   query entities -> nearest graph nodes -> specificity-weighted PPR;
 *   phrase probabilities -> phrase-to-passage lift -> ranked passages.
 * Native adaptations:
 *   - existing source-grounded entity anchors and semantic triples replace an
 *     ambient OpenIE service;
 *   - synonym candidates use bounded deterministic LSH buckets before the
 *     paper's cosine >= 0.8 rule, preventing an O(V^2) build;
 *   - every immutable node/edge/build is source/root-bound to one signed event;
 *   - a master-signed composite policy selects the exact readable graph root.
 *
 * The gear has no enable/shadow/enforce mode. It does not delete, classify,
 * disclose, or mutate memories; its passage candidates remain subject to the
 * canonical provenance, Canary, epistemic, SABER-evidence, and Aladdin gates.
 */

import { createHash, randomUUID } from 'node:crypto';

import { query, withTransaction } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { getEmbedding } from '../core/embeddings.js';
import { canonicalJson } from '../security/agent-identity.js';
import { computeLiveRowContentHash } from '../security/memory-provenance.js';
import { logEvent, readVerifiedEventById } from '../observe/event-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';
import {
  CONCEPT_PPR_RETRIEVAL_POLICY_VERSION,
  validateConceptPprRetrievalPolicy,
} from '../security/system-config-ledger.js';
import { extractQueryEntityAnchors, normalizeEntityAnchor } from './query-entity-anchors.js';
import { cosineSimilarity, merkleRootHex } from './quim-index.js';

const COMPANY = AIMOS_COMPANY_ID;
export const CONCEPT_GRAPH_BUILD_SCHEMA = 'hom-aimos/concept-ppr-build/v1';
export const CONCEPT_GRAPH_ALGORITHM_VERSION = 'hipporag/native-source-bound-ppr/v1';
export const CONCEPT_GRAPH_EMBEDDING_MODEL = 'Xenova/all-mpnet-base-v2';
export const CONCEPT_PPR_DAMPING = 0.5;
export const CONCEPT_PPR_ITERATIONS = 20;
export const CONCEPT_SYNONYM_THRESHOLD = 0.8;
export const CONCEPT_MAX_SYNONYMS_PER_NODE = 8;

const BUILD_EVENT_OPERATION = 'concept_ppr_build_committed';
const MAX_BUILD_CONCEPTS = 100_000;
const MAX_BUILD_RELATION_EDGES = 1_000_000;
const SYNONYM_SIGNATURE_BITS = 8;
const SHA256_RE = /^[0-9a-f]{64}$/;

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
  return sha256(value).toString('hex');
}

function assertEmbedding(vector, code = 'concept_embedding_invalid') {
  if (!Array.isArray(vector) || vector.length !== 768 || vector.some((value) => !Number.isFinite(Number(value)))) {
    throw new Error(code);
  }
  if (vector._degraded === true) throw new Error('concept_degraded_embedding_forbidden');
  return vector.map(Number);
}

function uuidFromHash(hex) {
  const bytes = Buffer.from(hex, 'hex').subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const value = bytes.toString('hex');
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

function normalizeRelation(value) {
  return String(value || 'RELATED_TO')
    .normalize('NFKC')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 128) || 'RELATED_TO';
}

function nodeIdentity(node) {
  return sha256Hex(Buffer.concat([
    Buffer.from('HOM-AIMOS-CONCEPT-NODE-v1\0', 'utf8'),
    Buffer.from(canonicalJson({
      normalized_label: node.normalized_label,
      entity_type: node.entity_type,
      embedding: node.embedding,
      passage_degree: node.passage_degree,
      specificity_q9: node.specificity.toFixed(9),
    }), 'utf8'),
  ]));
}

function passageEdgeIdentity(edge) {
  return sha256Hex(Buffer.concat([
    Buffer.from('HOM-AIMOS-CONCEPT-PASSAGE-EDGE-v1\0', 'utf8'),
    Buffer.from(canonicalJson({
      node_identity_sha256: edge.node_identity_sha256,
      memory_id: edge.memory_id,
      source_content_sha256: edge.source_content_sha256,
      weight_q9: edge.weight.toFixed(9),
    }), 'utf8'),
  ]));
}

function relationEdgeIdentity(edge) {
  return sha256Hex(Buffer.concat([
    Buffer.from('HOM-AIMOS-CONCEPT-RELATION-EDGE-v1\0', 'utf8'),
    Buffer.from(canonicalJson({
      source_node_identity_sha256: edge.source_node_identity_sha256,
      target_node_identity_sha256: edge.target_node_identity_sha256,
      relation_type: edge.relation_type,
      weight_q9: edge.weight.toFixed(9),
      source_memory_id: edge.source_memory_id,
      source_content_sha256: edge.source_content_sha256,
    }), 'utf8'),
  ]));
}

function verifyMemorySourceRow(row) {
  if (!Buffer.isBuffer(row.content_hash) || row.content_hash.length !== 32) {
    throw new Error(`concept_source_content_hash_missing:${row.id}`);
  }
  const computed = computeLiveRowContentHash(row);
  if (!computed.equals(row.content_hash)) throw new Error(`concept_source_content_hash_invalid:${row.id}`);
}

function corpusLeaf(row) {
  return sha256(Buffer.concat([
    Buffer.from('HOM-AIMOS-CONCEPT-CORPUS-LEAF-v1\0', 'utf8'),
    Buffer.from(canonicalJson({
      memory_id: String(row.id),
      content_sha256: Buffer.from(row.content_hash).toString('hex'),
    }), 'utf8'),
  ]));
}

function synonymBucket(embedding) {
  let value = 0;
  for (let index = 0; index < SYNONYM_SIGNATURE_BITS; index++) {
    if (Number(embedding[index]) >= 0) value |= (1 << index);
  }
  return value;
}

function normalizeTriple(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const subject = normalizeEntityAnchor(raw.subject ?? raw.source ?? raw.from);
  const object = normalizeEntityAnchor(raw.object ?? raw.target ?? raw.to);
  if (!subject || !object || subject === object) return null;
  return { subject, object, relation_type: normalizeRelation(raw.predicate ?? raw.relation ?? raw.edge_type) };
}

function triplesFrom(value) {
  if (!value) return [];
  let parsed = value;
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed); } catch { return []; }
  }
  const rows = Array.isArray(parsed) ? parsed : Array.isArray(parsed.triples) ? parsed.triples : [];
  return rows.map(normalizeTriple).filter(Boolean);
}

function buildSynonymEdges(nodes) {
  const buckets = new Map();
  for (const node of nodes) {
    const bucket = synonymBucket(node.embedding);
    if (!buckets.has(bucket)) buckets.set(bucket, []);
    buckets.get(bucket).push(node);
  }
  const selections = new Map(nodes.map((node) => [node.normalized_label, []]));
  for (const bucketNodes of buckets.values()) {
    for (let leftIndex = 0; leftIndex < bucketNodes.length; leftIndex++) {
      for (let rightIndex = leftIndex + 1; rightIndex < bucketNodes.length; rightIndex++) {
        const left = bucketNodes[leftIndex];
        const right = bucketNodes[rightIndex];
        const similarity = cosineSimilarity(left.embedding, right.embedding);
        if (similarity < CONCEPT_SYNONYM_THRESHOLD) continue;
        selections.get(left.normalized_label).push({ node: right, similarity });
        selections.get(right.normalized_label).push({ node: left, similarity });
      }
    }
  }
  const deduplicated = new Map();
  for (const node of nodes) {
    const selected = selections.get(node.normalized_label)
      .sort((left, right) => right.similarity - left.similarity
        || left.node.normalized_label.localeCompare(right.node.normalized_label))
      .slice(0, CONCEPT_MAX_SYNONYMS_PER_NODE);
    for (const candidate of selected) {
      const labels = [node.normalized_label, candidate.node.normalized_label].sort();
      const key = labels.join('\0');
      const existing = deduplicated.get(key);
      if (!existing || candidate.similarity > existing.weight) {
        deduplicated.set(key, {
          source_label: labels[0],
          target_label: labels[1],
          relation_type: 'SYNONYM_SIMILARITY',
          weight: candidate.similarity,
          source_memory_id: null,
          source_content_sha256: null,
        });
      }
    }
  }
  return [...deduplicated.values()];
}

function powerIteration({ nodeIds, edges, seedWeights, damping, iterations }) {
  const teleportTotal = [...seedWeights.values()].reduce((total, weight) => total + weight, 0) || 1;
  const teleport = new Map(nodeIds.map((nodeId) => [nodeId, (seedWeights.get(nodeId) || 0) / teleportTotal]));
  const adjacency = new Map(nodeIds.map((nodeId) => [nodeId, []]));
  for (const edge of edges) {
    if (!adjacency.has(edge.source) || !adjacency.has(edge.target)) continue;
    adjacency.get(edge.source).push({ node: edge.target, weight: edge.weight });
    if (edge.relation_type === 'SYNONYM_SIMILARITY') {
      adjacency.get(edge.target).push({ node: edge.source, weight: edge.weight });
    }
  }
  let scores = new Map(teleport);
  for (let iteration = 0; iteration < iterations; iteration++) {
    const next = new Map(nodeIds.map((nodeId) => [nodeId, (1 - damping) * teleport.get(nodeId)]));
    let danglingMass = 0;
    for (const nodeId of nodeIds) {
      const score = scores.get(nodeId) || 0;
      const neighbors = adjacency.get(nodeId) || [];
      const totalWeight = neighbors.reduce((total, edge) => total + edge.weight, 0);
      if (totalWeight <= 0) {
        danglingMass += score;
        continue;
      }
      for (const neighbor of neighbors) {
        next.set(neighbor.node, (next.get(neighbor.node) || 0) + damping * score * neighbor.weight / totalWeight);
      }
    }
    if (danglingMass > 0) {
      for (const nodeId of nodeIds) {
        next.set(nodeId, (next.get(nodeId) || 0) + damping * danglingMass * teleport.get(nodeId));
      }
    }
    scores = next;
  }
  return scores;
}

export function runPersonalizedPageRank(input) {
  return powerIteration(input);
}

async function insertNodes(client, nodes, buildId, eventId, company) {
  for (let offset = 0; offset < nodes.length; offset += 100) {
    const batch = nodes.slice(offset, offset + 100);
    const params = [];
    const values = [];
    for (const node of batch) {
      const base = params.length;
      params.push(
        node.node_id, company, buildId, node.canonical_label, node.normalized_label,
        node.entity_type, JSON.stringify(node.embedding), node.passage_degree,
        node.specificity, Buffer.from(node.node_identity_sha256, 'hex'), eventId,
      );
      values.push(`($${base + 1}::uuid,$${base + 2},$${base + 3}::uuid,$${base + 4},$${base + 5},$${base + 6},$${base + 7}::vector,$${base + 8},$${base + 9},$${base + 10},$${base + 11}::uuid)`);
    }
    await client.query(
      `INSERT INTO public.concept_graph_nodes
         (node_id, company_id, build_id, canonical_label, normalized_label,
          entity_type, embedding, passage_degree, specificity,
          node_identity_sha256, authority_event_id)
       VALUES ${values.join(',')}`,
      params,
    );
  }
}

async function insertPassageEdges(client, edges, buildId, eventId, company) {
  for (let offset = 0; offset < edges.length; offset += 200) {
    const batch = edges.slice(offset, offset + 200);
    const params = [];
    const values = [];
    for (const edge of batch) {
      const base = params.length;
      params.push(
        company, buildId, edge.concept_node_id, edge.memory_id, edge.weight,
        Buffer.from(edge.source_content_sha256, 'hex'), Buffer.from(edge.edge_identity_sha256, 'hex'), eventId,
      );
      values.push(`($${base + 1},$${base + 2}::uuid,$${base + 3}::uuid,$${base + 4}::uuid,$${base + 5},$${base + 6},$${base + 7},$${base + 8}::uuid)`);
    }
    await client.query(
      `INSERT INTO public.concept_passage_edges
         (company_id, build_id, concept_node_id, memory_id, weight,
          source_content_sha256, edge_identity_sha256, authority_event_id)
       VALUES ${values.join(',')}`,
      params,
    );
  }
}

async function insertRelationEdges(client, edges, buildId, eventId, company) {
  for (let offset = 0; offset < edges.length; offset += 150) {
    const batch = edges.slice(offset, offset + 150);
    const params = [];
    const values = [];
    for (const edge of batch) {
      const base = params.length;
      params.push(
        company, buildId, edge.source_concept_node_id, edge.target_concept_node_id,
        edge.relation_type, edge.weight, edge.source_memory_id,
        edge.source_content_sha256 ? Buffer.from(edge.source_content_sha256, 'hex') : null,
        Buffer.from(edge.edge_identity_sha256, 'hex'), eventId,
      );
      values.push(`($${base + 1},$${base + 2}::uuid,$${base + 3}::uuid,$${base + 4}::uuid,$${base + 5},$${base + 6},$${base + 7}::uuid,$${base + 8},$${base + 9},$${base + 10}::uuid)`);
    }
    await client.query(
      `INSERT INTO public.concept_relation_edges
         (company_id, build_id, source_concept_node_id, target_concept_node_id,
          relation_type, weight, source_memory_id, source_content_sha256,
          edge_identity_sha256, authority_event_id)
       VALUES ${values.join(',')}`,
      params,
    );
  }
}

/** Build one immutable phrase graph and phrase-to-passage projection. */
export async function buildConceptPprGraph(companyId = COMPANY, options = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('concept_company_required');
  const embeddingFn = options.embeddingFn || getEmbedding;
  const sourceResult = await query(
    `SELECT m.id, m.key, m.value, m.scope, m.memory_type, m.clearance_level,
            m.data_class, m.source, m.content_hash, m.semantic_triples, m.created_at,
            e.entity, e.entity_type
       FROM public.aimos_memories m
       JOIN public.entity_memory_edges e
         ON e.company_id = m.company_id AND e.memory_id = m.id
      WHERE m.company_id = $1
        AND COALESCE(m.node_type, 'episode') <> 'concept'
      ORDER BY m.created_at, m.id, lower(e.entity), e.id`,
    [company],
  );
  if (sourceResult.rows.length === 0) throw new Error('concept_source_population_empty');

  const memoryById = new Map();
  const entityMap = new Map();
  for (const row of sourceResult.rows) {
    if (!memoryById.has(String(row.id))) {
      verifyMemorySourceRow(row);
      memoryById.set(String(row.id), row);
    }
    const label = normalizeEntityAnchor(row.entity);
    if (!label) continue;
    if (!entityMap.has(label)) entityMap.set(label, {
      canonical_label: String(row.entity).trim(),
      normalized_label: label,
      entity_type: String(row.entity_type || 'unknown').trim().toLowerCase(),
      memory_ids: new Set(),
    });
    entityMap.get(label).memory_ids.add(String(row.id));
  }
  if (entityMap.size === 0) throw new Error('concept_entity_population_empty');
  if (entityMap.size > MAX_BUILD_CONCEPTS) throw new Error('concept_build_node_scale_bound_exceeded');

  const buildId = randomUUID();
  const nodes = [];
  for (const entity of [...entityMap.values()].sort((a, b) => a.normalized_label.localeCompare(b.normalized_label))) {
    const embedding = assertEmbedding(await embeddingFn(entity.canonical_label));
    const node = {
      ...entity,
      embedding,
      passage_degree: entity.memory_ids.size,
      specificity: 1 / entity.memory_ids.size,
    };
    node.node_identity_sha256 = nodeIdentity(node);
    node.node_id = uuidFromHash(sha256Hex(Buffer.from(`${buildId}\0${node.node_identity_sha256}`, 'utf8')));
    nodes.push(node);
  }
  const nodeByLabel = new Map(nodes.map((node) => [node.normalized_label, node]));
  const passageEdges = [];
  for (const node of nodes) {
    for (const memoryId of [...node.memory_ids].sort()) {
      const memory = memoryById.get(memoryId);
      const edge = {
        node_identity_sha256: node.node_identity_sha256,
        concept_node_id: node.node_id,
        memory_id: memoryId,
        source_content_sha256: Buffer.from(memory.content_hash).toString('hex'),
        weight: 1,
      };
      edge.edge_identity_sha256 = passageEdgeIdentity(edge);
      passageEdges.push(edge);
    }
  }

  const relationCandidates = new Map();
  for (const memory of memoryById.values()) {
    const sourceContentSha256 = Buffer.from(memory.content_hash).toString('hex');
    for (const triple of triplesFrom(memory.semantic_triples)) {
      const sourceNode = nodeByLabel.get(triple.subject);
      const targetNode = nodeByLabel.get(triple.object);
      if (!sourceNode || !targetNode) continue;
      const key = `${sourceNode.normalized_label}\0${triple.relation_type}\0${targetNode.normalized_label}\0${memory.id}`;
      relationCandidates.set(key, {
        source_label: sourceNode.normalized_label,
        target_label: targetNode.normalized_label,
        relation_type: triple.relation_type,
        weight: 1,
        source_memory_id: String(memory.id),
        source_content_sha256: sourceContentSha256,
      });
    }
  }
  for (const synonym of buildSynonymEdges(nodes)) {
    relationCandidates.set(`synonym\0${synonym.source_label}\0${synonym.target_label}`, synonym);
  }
  if (relationCandidates.size > MAX_BUILD_RELATION_EDGES) throw new Error('concept_build_edge_scale_bound_exceeded');
  const relationEdges = [...relationCandidates.values()].map((candidate) => {
    const sourceNode = nodeByLabel.get(candidate.source_label);
    const targetNode = nodeByLabel.get(candidate.target_label);
    const edge = {
      ...candidate,
      source_concept_node_id: sourceNode.node_id,
      target_concept_node_id: targetNode.node_id,
      source_node_identity_sha256: sourceNode.node_identity_sha256,
      target_node_identity_sha256: targetNode.node_identity_sha256,
    };
    edge.edge_identity_sha256 = relationEdgeIdentity(edge);
    return edge;
  }).sort((a, b) => a.edge_identity_sha256.localeCompare(b.edge_identity_sha256));

  const corpusRoot = merkleRootHex([...memoryById.values()].map(corpusLeaf));
  const graphRoot = merkleRootHex([
    ...nodes.map((node) => Buffer.from(node.node_identity_sha256, 'hex')),
    ...passageEdges.map((edge) => Buffer.from(edge.edge_identity_sha256, 'hex')),
    ...relationEdges.map((edge) => Buffer.from(edge.edge_identity_sha256, 'hex')),
  ]);
  const metadata = Object.freeze({
    schema: CONCEPT_GRAPH_BUILD_SCHEMA,
    build_id: buildId,
    algorithm_version: CONCEPT_GRAPH_ALGORITHM_VERSION,
    embedding_model: CONCEPT_GRAPH_EMBEDDING_MODEL,
    corpus_root_sha256: corpusRoot,
    graph_root_sha256: graphRoot,
    memory_count: memoryById.size,
    concept_count: nodes.length,
    passage_edge_count: passageEdges.length,
    relation_edge_count: relationEdges.length,
    ppr_damping: '1/2',
    ppr_iterations: CONCEPT_PPR_ITERATIONS,
    synonym_threshold_q6: Math.round(CONCEPT_SYNONYM_THRESHOLD * 1_000_000),
    max_synonyms_per_node: CONCEPT_MAX_SYNONYMS_PER_NODE,
    canonical_memory_changed: false,
    retention_changed: false,
    automatic_policy_activation: false,
    reasoning: 'Housekeeper committed one immutable source-grounded phrase graph and phrase-to-passage projection; activation remains a separate master-signed build selection.',
    source_knowledge: 'HippoRAG arXiv:2405.14831 with declared bounded LSH and retained AIMOS entity-edge adaptations',
  });
  const receipt = await withTransaction(async (client) => {
    const event = await logEvent(company, 'concept-ppr', BUILD_EVENT_OPERATION, graphRoot, metadata, null, {
      client,
      returnReceipt: true,
      exclusiveOperationKey: true,
    });
    await client.query(
      `INSERT INTO public.concept_graph_builds
         (build_id, company_id, schema_version, algorithm_version, embedding_model,
          corpus_root_sha256, graph_root_sha256, memory_count, concept_count,
          passage_edge_count, relation_edge_count, authority_event_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        buildId, company, CONCEPT_GRAPH_BUILD_SCHEMA, CONCEPT_GRAPH_ALGORITHM_VERSION,
        CONCEPT_GRAPH_EMBEDDING_MODEL, Buffer.from(corpusRoot, 'hex'), Buffer.from(graphRoot, 'hex'),
        memoryById.size, nodes.length, passageEdges.length, relationEdges.length, event.event_id,
      ],
    );
    await insertNodes(client, nodes, buildId, event.event_id, company);
    await insertPassageEdges(client, passageEdges, buildId, event.event_id, company);
    await insertRelationEdges(client, relationEdges, buildId, event.event_id, company);
    return event;
  }, { restricted: true, client_id: company, agent_id: 'housekeeper' });

  return Object.freeze({
    success: true,
    build_id: buildId,
    corpus_root_sha256: corpusRoot,
    graph_root_sha256: graphRoot,
    memory_count: memoryById.size,
    concept_count: nodes.length,
    passage_edge_count: passageEdges.length,
    relation_edge_count: relationEdges.length,
    authority_event_id: receipt.event_id,
    authority_event_mutation_hash: receipt.mutation_hash,
    policy: {
      version: CONCEPT_PPR_RETRIEVAL_POLICY_VERSION,
      build_id: buildId,
      corpus_root_sha256: corpusRoot,
      graph_root_sha256: graphRoot,
      damping: '1/2',
      iterations: CONCEPT_PPR_ITERATIONS,
      entity_seed_limit: 5,
      passage_limit: 20,
      synonym_threshold_q6: Math.round(CONCEPT_SYNONYM_THRESHOLD * 1_000_000),
      max_synonyms_per_node: CONCEPT_MAX_SYNONYMS_PER_NODE,
      max_ppr_nodes: nodes.length,
      max_ppr_edges: relationEdges.length,
    },
  });
}

export function readConceptPprPolicy() {
  const entry = systemConfigStore.readVerifiedConfig('CONCEPT_PPR_RETRIEVAL_POLICY');
  if (!entry?.value || !SHA256_RE.test(String(entry.mutation_hash || ''))) return null;
  const validated = validateConceptPprRetrievalPolicy(entry.value);
  return validated.ok
    ? Object.freeze({ policy: validated.policy, mutation_hash: entry.mutation_hash })
    : null;
}

async function verifySelectedBuild(company, selected) {
  const result = await query(
    `SELECT build_id, corpus_root_sha256, graph_root_sha256, concept_count,
            passage_edge_count, relation_edge_count, authority_event_id
       FROM public.concept_graph_builds
      WHERE company_id=$1 AND build_id=$2::uuid
      LIMIT 2`,
    [company, selected.policy.build_id],
  );
  if (result.rowCount !== 1) throw new Error('concept_selected_build_missing_or_ambiguous');
  const build = result.rows[0];
  const corpusRoot = Buffer.from(build.corpus_root_sha256).toString('hex');
  const graphRoot = Buffer.from(build.graph_root_sha256).toString('hex');
  if (
    corpusRoot !== selected.policy.corpus_root_sha256
    || graphRoot !== selected.policy.graph_root_sha256
    || Number(build.concept_count) > selected.policy.max_ppr_nodes
    || Number(build.relation_edge_count) > selected.policy.max_ppr_edges
  ) throw new Error('concept_selected_build_policy_binding_invalid');
  const event = await readVerifiedEventById(build.authority_event_id, company);
  if (
    event.operation !== BUILD_EVENT_OPERATION
    || event.key !== graphRoot
    || event.metadata?.build_id !== selected.policy.build_id
    || event.metadata?.corpus_root_sha256 !== corpusRoot
    || event.metadata?.graph_root_sha256 !== graphRoot
  ) throw new Error('concept_selected_build_event_binding_invalid');
  return build;
}

async function mapQueryAnchorsToNodes(queryText, company, buildId, policy) {
  let anchors = extractQueryEntityAnchors(queryText, policy.entity_seed_limit);
  if (anchors.length === 0) anchors = [{ name: String(queryText || '').trim().toLowerCase(), type: 'query' }];
  const best = new Map();
  for (const anchor of anchors.slice(0, policy.entity_seed_limit)) {
    const embedding = assertEmbedding(await getEmbedding(anchor.name), 'concept_query_embedding_invalid');
    const match = await query(
      `SELECT node_id, normalized_label, specificity,
              1 - (embedding <=> $3::vector) AS similarity
         FROM public.concept_graph_nodes
        WHERE company_id=$1 AND build_id=$2::uuid
        ORDER BY embedding <=> $3::vector, node_identity_sha256
        LIMIT 1`,
      [company, buildId, JSON.stringify(embedding)],
    );
    if (match.rowCount !== 1) continue;
    const row = match.rows[0];
    const similarity = Math.max(0, Math.min(1, Number(row.similarity || 0)));
    const weight = similarity * similarity * Number(row.specificity || 0);
    const prior = best.get(String(row.node_id)) || 0;
    if (weight > prior) best.set(String(row.node_id), weight);
  }
  return best;
}

/** Query-time specificity-weighted PPR and phrase-to-passage lift. */
export async function conceptPprLookup(queryText, companyId = COMPANY, limit = 10) {
  const selected = readConceptPprPolicy();
  if (!selected) throw new Error('concept_ppr_signed_build_policy_missing');
  const company = String(companyId || '').trim();
  const build = await verifySelectedBuild(company, selected);
  const seedWeights = await mapQueryAnchorsToNodes(queryText, company, build.build_id, selected.policy);
  if (seedWeights.size === 0) return [];
  const [nodesResult, edgesResult] = await Promise.all([
    query(
      `SELECT node_id FROM public.concept_graph_nodes
        WHERE company_id=$1 AND build_id=$2::uuid
        ORDER BY node_identity_sha256`,
      [company, build.build_id],
    ),
    query(
      `SELECT source_concept_node_id AS source, target_concept_node_id AS target,
              relation_type, weight
         FROM public.concept_relation_edges
        WHERE company_id=$1 AND build_id=$2::uuid
        ORDER BY edge_identity_sha256`,
      [company, build.build_id],
    ),
  ]);
  if (nodesResult.rowCount > selected.policy.max_ppr_nodes
      || edgesResult.rowCount > selected.policy.max_ppr_edges) {
    throw new Error('concept_ppr_runtime_scale_bound_exceeded');
  }
  const scores = powerIteration({
    nodeIds: nodesResult.rows.map((row) => String(row.node_id)),
    edges: edgesResult.rows.map((row) => ({
      source: String(row.source),
      target: String(row.target),
      relation_type: row.relation_type,
      weight: Number(row.weight),
    })),
    seedWeights,
    damping: CONCEPT_PPR_DAMPING,
    iterations: selected.policy.iterations,
  });
  const activeConcepts = [...scores.entries()]
    .filter(([, score]) => score > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (activeConcepts.length === 0) return [];
  const conceptIds = activeConcepts.map(([nodeId]) => nodeId);
  const scoreValues = activeConcepts.map(([, score]) => score);
  const passages = await query(
    `SELECT edge.memory_id AS id,
            SUM(score.value * edge.weight)::float8 AS ppr_score,
            COUNT(*)::int AS concept_hits
       FROM unnest($3::uuid[], $4::float8[]) AS score(node_id, value)
       JOIN public.concept_passage_edges edge
         ON edge.company_id=$1 AND edge.build_id=$2::uuid
        AND edge.concept_node_id=score.node_id
      GROUP BY edge.memory_id
      ORDER BY ppr_score DESC, edge.memory_id
      LIMIT $5`,
    [company, build.build_id, conceptIds, scoreValues, Math.min(Number(limit || 10), selected.policy.passage_limit)],
  );
  return passages.rows.map((row) => ({
    id: row.id,
    score: Number(row.ppr_score || 0),
    ppr: Number(row.ppr_score || 0),
    cosine: 0,
    concept_hits: Number(row.concept_hits || 0),
    source: 'concept_graph_ppr',
    build_id: selected.policy.build_id,
    build_root_sha256: selected.policy.graph_root_sha256,
    policy_mutation_hash: selected.mutation_hash,
  }));
}

export async function getConceptPprStats(companyId = COMPANY) {
  const selected = readConceptPprPolicy();
  if (!selected) return { activeBuild: null, concepts: 0, passageEdges: 0, relationEdges: 0 };
  const result = await query(
    `SELECT concept_count, passage_edge_count, relation_edge_count
       FROM public.concept_graph_builds
      WHERE company_id=$1 AND build_id=$2::uuid`,
    [companyId, selected.policy.build_id],
  );
  const row = result.rows[0] || {};
  return {
    activeBuild: selected.policy.build_id,
    graphRootSha256: selected.policy.graph_root_sha256,
    concepts: Number(row.concept_count || 0),
    passageEdges: Number(row.passage_edge_count || 0),
    relationEdges: Number(row.relation_edge_count || 0),
  };
}

export default {
  buildConceptPprGraph,
  conceptPprLookup,
  runPersonalizedPageRank,
  readConceptPprPolicy,
  getConceptPprStats,
};
