/**
 * quim-index.js — native, signed QuIM inverted-question retrieval gear
 *
 * Paper authority: QuIM-RAG (arXiv:2501.02702, 2025).
 * Paper mapping:
 *   chunk -> hypothetical questions -> embedding -> prototype quantization;
 *   query -> nearest prototype -> top-3 question matches -> source passages.
 * Native adaptations:
 *   - deterministic source-grounded question templates replace the paper's
 *     provider-specific GPT/manual-review lane;
 *   - deterministic bounded-load codebook fitting makes bucket work explicit;
 *   - every immutable build and row is hash-bound to retained source content
 *     and one housekeeper-signed build event;
 *   - one master-signed composite policy selects the exact readable build.
 *
 * This is a permanent additive retrieval gear. It has no enable/shadow/enforce
 * mode and no deletion, classification, disclosure, or memory-mutation power.
 *
 * SERVICE CONNECTIONS:
 * 1. <- native-recall-pipeline.js (query-time contribution)
 * 2. <- scripts/ceremony/build-native-derived-retrieval.mjs (offline build)
 * 3. -> aimos_memories + quim_index_builds/prototypes/index
 * 4. -> housekeeper-signed aimos_events build receipt
 */

import { createHash, randomUUID } from 'node:crypto';

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { getEmbedding } from '../core/embeddings.js';
import { withTransaction, query } from '../../db/connection.js';
import { canonicalJson } from '../security/agent-identity.js';
import { computeLiveRowContentHash } from '../security/memory-provenance.js';
import { readVerifiedEventById, logEvent } from '../observe/event-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';
import {
  QUIM_RETRIEVAL_POLICY_VERSION,
  validateQuimRetrievalPolicy,
} from '../security/system-config-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
export const QUIM_BUILD_SCHEMA = 'hom-aimos/quim-index-build/v1';
export const QUIM_ALGORITHM_VERSION = 'quim-rag/native-bounded-codebook/v1';
export const QUIM_QUESTION_GENERATOR = 'source-grounded-deterministic-templates/v1';
export const QUIM_EMBEDDING_MODEL = 'Xenova/all-mpnet-base-v2';
export const QUIM_TOP_QUESTIONS = 3;

const QUESTION_COUNT_PER_CHUNK = 5;
const CHUNK_TOKEN_BOUND = 1_000;
const CHUNK_OVERLAP_CHARACTERS = 200;
const TARGET_BUCKET_SIZE = 256;
const MAX_PROTOTYPES = 128;
const KMEANS_SAMPLE_LIMIT = 2_048;
const KMEANS_ITERATIONS = 4;
const MAX_BUILD_QUESTIONS = 50_000;
const BUILD_EVENT_OPERATION = 'quim_index_build_committed';
const SHA256_RE = /^[0-9a-f]{64}$/;

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
  return sha256(value).toString('hex');
}

function hashLeaf(domain, value) {
  return sha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from(value)]));
}

export function merkleRootHex(leaves = []) {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    return sha256(Buffer.from('HOM-AIMOS-EMPTY-MERKLE-v1\0', 'utf8')).toString('hex');
  }
  let level = leaves.map((leaf) => Buffer.isBuffer(leaf) ? Buffer.from(leaf) : Buffer.from(String(leaf), 'hex'));
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] || left;
      next.push(sha256(Buffer.concat([Buffer.from([0x01]), left, right])));
    }
    level = next;
  }
  return level[0].toString('hex');
}

function parseVector(value) {
  if (Array.isArray(value)) return value.map(Number);
  if (typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(Number) : [];
  } catch {
    return [];
  }
}

function assertEmbedding(vector, code = 'quim_embedding_invalid') {
  if (!Array.isArray(vector) || vector.length !== 768 || vector.some((value) => !Number.isFinite(Number(value)))) {
    throw new Error(code);
  }
  if (vector._degraded === true) throw new Error('quim_degraded_embedding_forbidden');
  return vector.map(Number);
}

export function cosineSimilarity(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length || left.length === 0) return 0;
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  for (let index = 0; index < left.length; index++) {
    const a = Number(left[index]);
    const b = Number(right[index]);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return 0;
    dot += a * b;
    leftNorm += a * a;
    rightNorm += b * b;
  }
  const denominator = Math.sqrt(leftNorm) * Math.sqrt(rightNorm);
  return denominator === 0 ? 0 : dot / denominator;
}

/**
 * Deterministic approximate token chunks with the paper's 1,000-token bound
 * and 200-character overlap. Exact tokenizer identity is declared as a native
 * adaptation rather than falsely claiming TikToken parity.
 */
export function chunkText(text, maxTokens = CHUNK_TOKEN_BOUND, overlapCharacters = CHUNK_OVERLAP_CHARACTERS) {
  const source = String(text || '').trim();
  if (!source) return [];
  const tokens = [...source.matchAll(/\S+/g)].map((match) => ({
    value: match[0],
    start: match.index,
    end: match.index + match[0].length,
  }));
  if (tokens.length <= maxTokens) return [source];

  const chunks = [];
  let startToken = 0;
  while (startToken < tokens.length) {
    const endToken = Math.min(tokens.length, startToken + maxTokens);
    const startCharacter = tokens[startToken].start;
    const endCharacter = tokens[endToken - 1].end;
    chunks.push(source.slice(startCharacter, endCharacter));
    if (endToken === tokens.length) break;

    const overlapBoundary = Math.max(startCharacter + 1, endCharacter - overlapCharacters);
    let nextStart = endToken;
    while (nextStart > startToken + 1 && tokens[nextStart - 1].start >= overlapBoundary) nextStart--;
    startToken = nextStart;
  }
  return chunks;
}

function uniqueTerms(text, pattern, limit) {
  const seen = new Set();
  const values = [];
  for (const match of String(text || '').matchAll(pattern)) {
    const value = String(match[1] || '').trim();
    const normalized = value.toLowerCase();
    if (!value || seen.has(normalized)) continue;
    seen.add(normalized);
    values.push(value);
    if (values.length >= limit) break;
  }
  return values;
}

/** Source-grounded deterministic alternative to the paper's provider/manual lane. */
export function generateHypotheticalQuestions(text, count = QUESTION_COUNT_PER_CHUNK) {
  const source = String(text || '').trim();
  if (source.length < 20 || count < 1) return [];
  const entities = uniqueTerms(source, /\b([A-Z][\p{L}\p{N}_-]+(?:\s+[A-Z][\p{L}\p{N}_-]+){0,3})\b/gu, 12);
  const terms = uniqueTerms(
    source.toLowerCase(),
    /\b([\p{L}][\p{L}\p{N}_-]{5,})\b/gu,
    16,
  ).filter((term) => !new Set(['should', 'would', 'could', 'therefore', 'because', 'between', 'through']).has(term));
  const candidates = [];
  for (const entity of entities) {
    candidates.push(`What is ${entity}?`, `How does ${entity} work?`, `Why is ${entity} relevant?`);
  }
  for (const term of terms) {
    candidates.push(`What does ${term} mean in this context?`, `How is ${term} used?`);
  }
  candidates.push('What is the principal claim in this passage?', 'Which evidence supports the principal claim?');
  return [...new Set(candidates)].slice(0, count);
}

export function choosePrototypeCount(questionCount) {
  const count = Number(questionCount);
  if (!Number.isSafeInteger(count) || count < 1) throw new Error('quim_question_count_invalid');
  return Math.max(1, Math.min(MAX_PROTOTYPES, Math.ceil(count / TARGET_BUCKET_SIZE)));
}

function deterministicSample(rows, limit = KMEANS_SAMPLE_LIMIT) {
  if (rows.length <= limit) return rows;
  return [...rows]
    .sort((left, right) => left.question_sha256.localeCompare(right.question_sha256))
    .filter((_, index) => index % Math.ceil(rows.length / limit) === 0)
    .slice(0, limit);
}

export function fitDeterministicCodebook(rows, prototypeCount, iterations = KMEANS_ITERATIONS) {
  if (!Array.isArray(rows) || rows.length < prototypeCount || prototypeCount < 1) {
    throw new Error('quim_codebook_population_invalid');
  }
  const sample = deterministicSample(rows);
  const ordered = [...sample].sort((a, b) => a.question_sha256.localeCompare(b.question_sha256));
  let centroids = Array.from({ length: prototypeCount }, (_, index) => {
    const selected = ordered[Math.floor(index * ordered.length / prototypeCount)];
    return [...selected.embedding];
  });

  for (let iteration = 0; iteration < iterations; iteration++) {
    const sums = Array.from({ length: prototypeCount }, () => new Float64Array(768));
    const counts = new Uint32Array(prototypeCount);
    for (const row of ordered) {
      let best = 0;
      let bestSimilarity = Number.NEGATIVE_INFINITY;
      for (let index = 0; index < centroids.length; index++) {
        const similarity = cosineSimilarity(row.embedding, centroids[index]);
        if (similarity > bestSimilarity) {
          bestSimilarity = similarity;
          best = index;
        }
      }
      counts[best]++;
      for (let dimension = 0; dimension < 768; dimension++) sums[best][dimension] += row.embedding[dimension];
    }
    centroids = centroids.map((centroid, index) => {
      if (counts[index] === 0) return centroid;
      const next = Array.from(sums[index], (value) => value / counts[index]);
      const norm = Math.sqrt(next.reduce((total, value) => total + value * value, 0));
      return norm > 0 ? next.map((value) => value / norm) : centroid;
    });
  }
  return centroids;
}

/**
 * Assign all rows to their closest centroid under a deterministic capacity
 * bound. Capacity is a scale guard, not relevance math: it prevents one hot
 * prototype from turning query-time work back into a corpus scan.
 */
export function assignBoundedPrototypeBuckets(rows, centroids) {
  const capacity = Math.ceil(rows.length / centroids.length * 1.5);
  const counts = new Uint32Array(centroids.length);
  const assigned = [];
  for (const row of [...rows].sort((a, b) => a.question_sha256.localeCompare(b.question_sha256))) {
    const ranked = centroids
      .map((centroid, index) => ({ index, similarity: cosineSimilarity(row.embedding, centroid) }))
      .sort((a, b) => b.similarity - a.similarity || a.index - b.index);
    const selected = ranked.find((candidate) => counts[candidate.index] < capacity) || ranked[0];
    counts[selected.index]++;
    assigned.push({ ...row, prototype_id: selected.index });
  }
  return { rows: assigned, counts: Array.from(counts), maxBucketSize: Math.max(...counts) };
}

function memoryLeaf(row) {
  return hashLeaf('HOM-AIMOS-QUIM-CORPUS-LEAF-v1\0', canonicalJson({
    memory_id: String(row.id),
    content_sha256: Buffer.from(row.content_hash).toString('hex'),
  }));
}

function questionIdentity(row) {
  return sha256Hex(Buffer.concat([
    Buffer.from('HOM-AIMOS-QUIM-ROW-v1\0', 'utf8'),
    Buffer.from(canonicalJson({
      memory_id: row.memory_id,
      source_content_sha256: row.source_content_sha256,
      chunk_ordinal: row.chunk_ordinal,
      question_ordinal: row.question_ordinal,
      question_sha256: row.question_sha256,
      prototype_id: row.prototype_id,
    }), 'utf8'),
  ]));
}

function prototypeIdentity(prototypeId, centroid, memberCount) {
  return sha256Hex(Buffer.concat([
    Buffer.from('HOM-AIMOS-QUIM-PROTOTYPE-v1\0', 'utf8'),
    Buffer.from(canonicalJson({ prototype_id: prototypeId, centroid, member_count: memberCount }), 'utf8'),
  ]));
}

function verifyMemorySourceRow(row) {
  if (!Buffer.isBuffer(row.content_hash) || row.content_hash.length !== 32) {
    throw new Error(`quim_source_content_hash_missing:${row.id}`);
  }
  const computed = computeLiveRowContentHash(row);
  if (!computed.equals(row.content_hash)) throw new Error(`quim_source_content_hash_invalid:${row.id}`);
}

async function insertQuestionRows(client, rows, buildId, authorityEventId, centroids) {
  const batchSize = 100;
  for (let offset = 0; offset < rows.length; offset += batchSize) {
    const batch = rows.slice(offset, offset + batchSize);
    const values = [];
    const parameters = [];
    for (const row of batch) {
      const base = parameters.length;
      parameters.push(
        row.company_id, row.prototype_id, centroids[row.prototype_id],
        row.question_text, row.embedding, row.memory_id, row.chunk_preview,
        buildId, JSON.stringify(row.embedding), Buffer.from(row.question_sha256, 'hex'),
        Buffer.from(row.source_content_sha256, 'hex'), Buffer.from(row.row_identity_sha256, 'hex'),
        row.chunk_ordinal, row.question_ordinal, authorityEventId,
      );
      values.push(`($${base + 1},$${base + 2},$${base + 3}::float8[],$${base + 4},$${base + 5}::float8[],$${base + 6}::uuid,$${base + 7},$${base + 8}::uuid,$${base + 9}::vector,$${base + 10},$${base + 11},$${base + 12},$${base + 13},$${base + 14},$${base + 15}::uuid)`);
    }
    await client.query(
      `INSERT INTO public.quim_index
         (company_id, prototype_id, prototype_embedding, question_text,
          question_embedding, chunk_id, chunk_preview, build_id,
          question_embedding_vector, question_sha256, source_content_sha256,
          row_identity_sha256, chunk_ordinal, question_ordinal, authority_event_id)
       VALUES ${values.join(',')}`,
      parameters,
    );
  }
}

/** Build one immutable, signed QuIM projection over the retained corpus. */
export async function buildQuimIndex(companyId = COMPANY, options = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('quim_company_required');
  const memoryLimit = Math.max(1, Math.min(Number(options.limit || 100_000), 100_000));
  const questionGenerator = options.questionGenerator || generateHypotheticalQuestions;
  const embeddingFn = options.embeddingFn || getEmbedding;
  const source = await query(
    `SELECT id, key, value, scope, memory_type, clearance_level, data_class, source,
            content_hash, created_at
       FROM public.aimos_memories
      WHERE company_id = $1
        AND COALESCE(node_type, 'episode') <> 'concept'
      ORDER BY created_at, id
      LIMIT $2`,
    [company, memoryLimit],
  );
  if (source.rows.length === 0) throw new Error('quim_source_population_empty');

  const memoryLeaves = [];
  const questions = [];
  let chunkCount = 0;
  for (const memory of source.rows) {
    verifyMemorySourceRow(memory);
    memoryLeaves.push(memoryLeaf(memory));
    const sourceContentSha256 = Buffer.from(memory.content_hash).toString('hex');
    const chunks = chunkText(memory.value);
    for (let chunkOrdinal = 0; chunkOrdinal < chunks.length; chunkOrdinal++) {
      const chunk = chunks[chunkOrdinal];
      chunkCount++;
      const generated = await Promise.resolve(questionGenerator(chunk, QUESTION_COUNT_PER_CHUNK));
      for (let questionOrdinal = 0; questionOrdinal < generated.length; questionOrdinal++) {
        if (questions.length >= MAX_BUILD_QUESTIONS) throw new Error('quim_build_question_scale_bound_exceeded');
        const questionText = String(generated[questionOrdinal] || '').trim();
        if (!questionText) continue;
        const embedding = assertEmbedding(await embeddingFn(questionText));
        questions.push({
          company_id: company,
          memory_id: String(memory.id),
          source_content_sha256: sourceContentSha256,
          chunk_ordinal: chunkOrdinal,
          question_ordinal: questionOrdinal,
          question_text: questionText,
          question_sha256: sha256Hex(Buffer.from(questionText, 'utf8')),
          chunk_preview: chunk.slice(0, 200),
          embedding,
        });
      }
    }
  }
  if (questions.length === 0) throw new Error('quim_question_population_empty');

  const prototypeCount = choosePrototypeCount(questions.length);
  const centroids = fitDeterministicCodebook(questions, prototypeCount);
  const assigned = assignBoundedPrototypeBuckets(questions, centroids);
  const committedRows = assigned.rows.map((row) => {
    const normalized = { ...row };
    normalized.row_identity_sha256 = questionIdentity(normalized);
    return normalized;
  });
  const prototypeRows = centroids.map((centroid, prototypeId) => ({
    prototype_id: prototypeId,
    centroid,
    member_count: assigned.counts[prototypeId],
    prototype_identity_sha256: prototypeIdentity(prototypeId, centroid, assigned.counts[prototypeId]),
  }));
  const corpusRoot = merkleRootHex(memoryLeaves);
  const indexRoot = merkleRootHex([
    ...prototypeRows.map((row) => Buffer.from(row.prototype_identity_sha256, 'hex')),
    ...committedRows.map((row) => Buffer.from(row.row_identity_sha256, 'hex')),
  ]);
  const buildId = randomUUID();
  const metadata = Object.freeze({
    schema: QUIM_BUILD_SCHEMA,
    build_id: buildId,
    algorithm_version: QUIM_ALGORITHM_VERSION,
    question_generator: QUIM_QUESTION_GENERATOR,
    embedding_model: QUIM_EMBEDDING_MODEL,
    corpus_root_sha256: corpusRoot,
    index_root_sha256: indexRoot,
    memory_count: source.rows.length,
    chunk_count: chunkCount,
    question_count: committedRows.length,
    prototype_count: prototypeRows.length,
    max_bucket_size: assigned.maxBucketSize,
    canonical_memory_changed: false,
    retention_changed: false,
    automatic_policy_activation: false,
    reasoning: 'Housekeeper committed one immutable source-bound QuIM derived-index build; activation remains a separate master-signed build selection.',
    source_knowledge: 'QuIM-RAG arXiv:2501.02702 with declared deterministic and bounded-load AIMOS adaptations',
  });

  const result = await withTransaction(async (client) => {
    const receipt = await logEvent(company, 'quim-index', BUILD_EVENT_OPERATION, indexRoot, metadata, null, {
      client,
      returnReceipt: true,
      exclusiveOperationKey: true,
    });
    await client.query(
      `INSERT INTO public.quim_index_builds
         (build_id, company_id, schema_version, algorithm_version, question_generator,
          embedding_model, corpus_root_sha256, index_root_sha256, memory_count,
          chunk_count, question_count, prototype_count, max_bucket_size, authority_event_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [
        buildId, company, QUIM_BUILD_SCHEMA, QUIM_ALGORITHM_VERSION, QUIM_QUESTION_GENERATOR,
        QUIM_EMBEDDING_MODEL, Buffer.from(corpusRoot, 'hex'), Buffer.from(indexRoot, 'hex'),
        source.rows.length, chunkCount, committedRows.length, prototypeRows.length,
        assigned.maxBucketSize, receipt.event_id,
      ],
    );
    for (const prototype of prototypeRows) {
      await client.query(
        `INSERT INTO public.quim_prototypes
           (company_id, prototype_id, centroid, member_count, build_id,
            centroid_vector, prototype_identity_sha256, authority_event_id)
         VALUES ($1,$2,$3::float8[],$4,$5::uuid,$6::vector,$7,$8::uuid)`,
        [
          company, prototype.prototype_id, prototype.centroid, prototype.member_count,
          buildId, JSON.stringify(prototype.centroid), Buffer.from(prototype.prototype_identity_sha256, 'hex'),
          receipt.event_id,
        ],
      );
    }
    await insertQuestionRows(client, committedRows, buildId, receipt.event_id, centroids);
    return receipt;
  }, { restricted: true, client_id: company, agent_id: 'housekeeper' });

  return Object.freeze({
    success: true,
    build_id: buildId,
    corpus_root_sha256: corpusRoot,
    index_root_sha256: indexRoot,
    memory_count: source.rows.length,
    chunk_count: chunkCount,
    question_count: committedRows.length,
    prototype_count: prototypeRows.length,
    max_bucket_size: assigned.maxBucketSize,
    authority_event_id: result.event_id,
    authority_event_mutation_hash: result.mutation_hash,
    policy: {
      version: QUIM_RETRIEVAL_POLICY_VERSION,
      build_id: buildId,
      corpus_root_sha256: corpusRoot,
      index_root_sha256: indexRoot,
      prototype_count: prototypeRows.length,
      top_questions: QUIM_TOP_QUESTIONS,
      max_bucket_scan: assigned.maxBucketSize,
    },
  });
}

export function readQuimPolicy() {
  const entry = systemConfigStore.readVerifiedConfig('QUIM_RETRIEVAL_POLICY');
  if (!entry?.value || !SHA256_RE.test(String(entry.mutation_hash || ''))) return null;
  const validated = validateQuimRetrievalPolicy(entry.value);
  return validated.ok
    ? Object.freeze({ policy: validated.policy, mutation_hash: entry.mutation_hash })
    : null;
}

async function verifySelectedBuild(company, selected) {
  const result = await query(
    `SELECT build_id, corpus_root_sha256, index_root_sha256, prototype_count,
            max_bucket_size, authority_event_id
       FROM public.quim_index_builds
      WHERE company_id = $1 AND build_id = $2::uuid
      LIMIT 2`,
    [company, selected.policy.build_id],
  );
  if (result.rowCount !== 1) throw new Error('quim_selected_build_missing_or_ambiguous');
  const build = result.rows[0];
  const corpusRoot = Buffer.from(build.corpus_root_sha256).toString('hex');
  const indexRoot = Buffer.from(build.index_root_sha256).toString('hex');
  if (
    corpusRoot !== selected.policy.corpus_root_sha256
    || indexRoot !== selected.policy.index_root_sha256
    || Number(build.prototype_count) !== selected.policy.prototype_count
    || Number(build.max_bucket_size) > selected.policy.max_bucket_scan
  ) throw new Error('quim_selected_build_policy_binding_invalid');
  const event = await readVerifiedEventById(build.authority_event_id, company);
  if (
    event.operation !== BUILD_EVENT_OPERATION
    || event.key !== indexRoot
    || event.metadata?.build_id !== selected.policy.build_id
    || event.metadata?.corpus_root_sha256 !== corpusRoot
    || event.metadata?.index_root_sha256 !== indexRoot
  ) throw new Error('quim_selected_build_event_binding_invalid');
  return build;
}

/** Query-time paper-shaped QuIM contribution. */
export async function quimLookup(queryText, companyId = COMPANY, limit = 10) {
  const selected = readQuimPolicy();
  if (!selected) throw new Error('quim_signed_build_policy_missing');
  const company = String(companyId || '').trim();
  const build = await verifySelectedBuild(company, selected);
  const queryEmbedding = assertEmbedding(await getEmbedding(String(queryText || '')), 'quim_query_embedding_invalid');
  const nearest = await query(
    `SELECT prototype_id
       FROM public.quim_prototypes
      WHERE company_id = $1 AND build_id = $2::uuid
      ORDER BY centroid_vector <=> $3::vector, prototype_id
      LIMIT 1`,
    [company, build.build_id, JSON.stringify(queryEmbedding)],
  );
  if (nearest.rowCount !== 1) throw new Error('quim_selected_build_prototypes_missing');
  const matches = await query(
    `SELECT chunk_id AS id, question_text,
            1 - (question_embedding_vector <=> $4::vector) AS score,
            chunk_preview, row_identity_sha256
       FROM public.quim_index
      WHERE company_id = $1 AND build_id = $2::uuid AND prototype_id = $3
      ORDER BY question_embedding_vector <=> $4::vector, row_identity_sha256
      LIMIT $5`,
    [
      company, build.build_id, nearest.rows[0].prototype_id,
      JSON.stringify(queryEmbedding), Math.min(QUIM_TOP_QUESTIONS, selected.policy.max_bucket_scan),
    ],
  );
  const byPassage = new Map();
  for (const row of matches.rows) {
    const score = Math.max(0, Math.min(1, Number(row.score || 0)));
    const existing = byPassage.get(String(row.id));
    if (!existing || score > existing.score) {
      byPassage.set(String(row.id), {
        id: row.id,
        score,
        question: row.question_text,
        preview: row.chunk_preview,
        source: 'quim',
        build_id: selected.policy.build_id,
        build_root_sha256: selected.policy.index_root_sha256,
        policy_mutation_hash: selected.mutation_hash,
        row_identity_sha256: Buffer.from(row.row_identity_sha256).toString('hex'),
      });
    }
  }
  return [...byPassage.values()]
    .sort((left, right) => right.score - left.score || String(left.id).localeCompare(String(right.id)))
    .slice(0, Math.max(1, Number(limit || 10)));
}

export async function getQuimStats(companyId = COMPANY) {
  const selected = readQuimPolicy();
  if (!selected) return { activeBuild: null, indexEntries: 0, prototypes: 0 };
  const [indexCount, prototypeCount] = await Promise.all([
    query('SELECT COUNT(*) AS count FROM public.quim_index WHERE company_id=$1 AND build_id=$2::uuid', [companyId, selected.policy.build_id]),
    query('SELECT COUNT(*) AS count FROM public.quim_prototypes WHERE company_id=$1 AND build_id=$2::uuid', [companyId, selected.policy.build_id]),
  ]);
  return {
    activeBuild: selected.policy.build_id,
    indexRootSha256: selected.policy.index_root_sha256,
    indexEntries: Number(indexCount.rows[0]?.count || 0),
    prototypes: Number(prototypeCount.rows[0]?.count || 0),
  };
}

export default {
  buildQuimIndex,
  quimLookup,
  generateHypotheticalQuestions,
  chunkText,
  choosePrototypeCount,
  fitDeterministicCodebook,
  assignBoundedPrototypeBuckets,
  getQuimStats,
};
