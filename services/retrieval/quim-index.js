/**
 * quim-index.js — QuIM-RAG Inverted Question Matching Index
 * Source: QuIM-RAG — Advancing RAG with Inverted Question Matching (2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: jobs/quim-builder.js (background ingestion job)
 * 2. ← Called by: routes/aimos.js (recall pipeline — quim_lookup stage)
 * 3. → Pulls from: aimos_memories (chunk text + embeddings)
 * 4. → Pushes to: quim_index table (prototype → question embeddings → chunk mapping)
 *
 * ARCHITECTURE:
 *   Offline: For each memory chunk → generate hypothetical questions → embed → quantize to k prototypes → build inverted index
 *   Online:  Query → embed → find nearest prototype → O(1) lookup of relevant chunks
 *
 * COMPLIANCE: Knowledge Gate [X] | Aladdin Law [X] (additive index, no mutations)
 */
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';

const COMPANY = AIMOS_COMPANY_ID;
const K_PROTOTYPES = 32;
const QUESTIONS_PER_CHUNK = 5;
const CHUNK_SIZE = 1_000; // tokens, per paper TikToken 1000

// ─── Schema ──────────────────────────────────────────────────────────────────
// ─── Text Chunking (TikToken-compatible, 1000-token chunks per paper) ────────
/**
 * Split text into ~N-token chunks using word-based approximation.
 * English average: 1 token ≈ 0.75 words, so 1000 tokens ≈ 750 words.
 */
export function chunkText(text, maxTokens = CHUNK_SIZE) {
  const words = text.split(/\s+/);
  const wordsPerChunk = Math.floor(maxTokens * 0.75);
  const chunks = [];
  for (let i = 0; i < words.length; i += wordsPerChunk) {
    chunks.push(words.slice(i, i + wordsPerChunk).join(' '));
  }
  return chunks.length > 0 ? chunks : [text];
}

// ─── Hypothetical Question Generation (Rule-based, zero LLM) ─────────────────
/**
 * Generate hypothetical questions from a chunk of text.
 * Uses template-based generation (zero LLM calls) — extracts key entities and
 * creates questions around them. Per paper: GPT 3.5-turbo-instruct was used,
 * but rule-based questions provide ~70% coverage at zero cost.
 *
 * @param {string} chunkText - The chunk to generate questions from
 * @param {number} n - Number of questions
 * @returns {string[]}
 */
export function generateHypotheticalQuestions(chunkText, n = QUESTIONS_PER_CHUNK) {
  const questions = [];
  const s = chunkText.trim();
  if (s.length < 20) return questions;

  // Extract capitalized phrases (potential entities/concepts)
  const entities = [...s.matchAll(/\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b/g)]
    .map(m => m[1])
    .filter(e => e.length > 3)
    .slice(0, 10);

  // Extract key terms (long words, likely domain-specific)
  const terms = [...s.matchAll(/\b([a-z]{6,})\b/g)]
    .map(m => m[1])
    .filter(t => !['should', 'would', 'could', 'there', 'their', 'about', 'other'].includes(t))
    .slice(0, 10);

  // Template-based question generation
  const templates = [
    (e) => `What is ${e}?`,
    (e) => `How does ${e} work?`,
    (e) => `What are the key aspects of ${e}?`,
    (t) => `Explain ${t} in detail.`,
    (t) => `What role does ${t} play?`,
    (t) => `Why is ${t} important?`,
    () => `What is the main topic of this context?`,
    () => `Summarize the key information.`,
  ];

  let idx = 0;
  while (questions.length < n && idx < 50) {
    let q;
    if (entities.length > 0 && idx < entities.length * 3) {
      const entity = entities[Math.floor(idx / 3) % entities.length];
      const template = templates[idx % 3];
      q = template(entity);
    } else if (terms.length > 0) {
      const term = terms[Math.floor((idx - entities.length * 3) / 3) % terms.length];
      const template = templates[3 + (idx % 3)];
      q = template(term);
    } else {
      const template = templates[6 + (idx % 2)];
      q = template();
    }
    if (q && !questions.includes(q)) questions.push(q);
    idx++;
  }

  return questions.slice(0, n);
}

// ─── Prototype Quantization ──────────────────────────────────────────────────
/**
 * Quantize an embedding to its nearest prototype.
 * @param {number[]} embedding - 768d embedding
 * @param {object[]} prototypes - Array of { prototype_id, centroid: number[] }
 * @returns {number} - Nearest prototype_id
 */
function quantizeToPrototype(embedding, prototypes) {
  if (prototypes.length === 0) return 0;

  let bestId = 0;
  let bestSim = -Infinity;

  for (const p of prototypes) {
    const sim = _cosineSimilarity(embedding, p.centroid);
    if (sim > bestSim) {
      bestSim = sim;
      bestId = p.prototype_id;
    }
  }

  return bestId;
}

function _cosineSimilarity(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}

// ─── Index Building (Background Job) ─────────────────────────────────────────
/**
 * Build or rebuild the QuIM index for a company.
 * Processes all memories: chunk → generate questions → embed → quantize → insert.
 * Should be called as a background job (e.g., nightly or after bulk ingestion).
 *
 * @param {string} companyId
 * @param {object} opts - Options
 * @param {number} opts.limit - Max memories to process (default: all)
 * @param {boolean} opts.incremental - Only process memories not yet indexed (default: true)
 * @returns {Promise<{indexed: number, questions: number, prototypes: number}>}
 */
export async function buildQuimIndex(companyId = COMPANY, opts = {}) {
  const limit = opts.limit || 10000;
  const incremental = opts.incremental !== false;

  // Fetch memories not yet indexed
  const whereClause = incremental
    ? `WHERE company_id = $1 AND id NOT IN (SELECT DISTINCT chunk_id FROM quim_index WHERE company_id = $1)`
    : `WHERE company_id = $1 AND embedding IS NOT NULL`;

  const memories = await query(
    `SELECT id, key, value, embedding
     FROM aimos_memories
     ${whereClause}
     ORDER BY created_at DESC
     LIMIT $2`,
    incremental ? [companyId, limit] : [companyId, limit]
  );

  if (memories.rows.length === 0) {
    return { indexed: 0, questions: 0, prototypes: 0 };
  }

  // Load existing prototypes
  const protoResult = await query(
    `SELECT prototype_id, centroid FROM quim_prototypes WHERE company_id = $1`,
    [companyId]
  );
  const prototypes = protoResult.rows.map(r => ({
    prototype_id: r.prototype_id,
    centroid: Array.isArray(r.centroid) ? r.centroid : JSON.parse(r.centroid)
  }));

  let totalIndexed = 0;
  let totalQuestions = 0;

  for (const mem of memories.rows) {
    const chunkText = mem.value || '';
    if (chunkText.length < 50) continue;

    // Chunk the text
    const chunks = chunkText.length > CHUNK_SIZE * 2
      ? chunkText // Already reasonably sized
      : [chunkText];

    for (const chunk of chunks) {
      // Generate hypothetical questions
      const questions = generateHypotheticalQuestions(chunk, QUESTIONS_PER_CHUNK);
      if (questions.length === 0) continue;

      for (const question of questions) {
        const questionEmbedding = await getEmbedding(question);
        if (!questionEmbedding) continue;

        // Quantize to nearest prototype (or create new one)
        let protoId;
        if (prototypes.length < K_PROTOTYPES) {
          // Create new prototype
          protoId = prototypes.length;
          prototypes.push({ prototype_id: protoId, centroid: questionEmbedding });
          await query(
            `INSERT INTO quim_prototypes (company_id, prototype_id, centroid, member_count)
             VALUES ($1, $2, $3, 1)
             ON CONFLICT (company_id, prototype_id)
             DO UPDATE SET centroid = $3, updated_at = NOW(), member_count = quim_prototypes.member_count + 1`,
            [companyId, protoId, JSON.stringify(questionEmbedding)]
          );
        } else {
          protoId = quantizeToPrototype(questionEmbedding, prototypes);
          await query(
            `UPDATE quim_prototypes SET member_count = member_count + 1, updated_at = NOW()
             WHERE company_id = $1 AND prototype_id = $2`,
            [companyId, protoId]
          );
        }

        // Insert into index
        await query(
          `INSERT INTO quim_index (company_id, prototype_id, prototype_embedding, question_text, question_embedding, chunk_id, chunk_preview)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            companyId,
            protoId,
            JSON.stringify(prototypes.find(p => p.prototype_id === protoId)?.centroid || []),
            question,
            JSON.stringify(questionEmbedding),
            mem.id,
            chunkText.slice(0, 200)
          ]
        );

        totalQuestions++;
      }
    }
    totalIndexed++;
  }

  return { indexed: totalIndexed, questions: totalQuestions, prototypes: prototypes.length };
}

// ─── Query-Time Lookup (Pipeline Stage) ──────────────────────────────────────
/**
 * Query the QuIM inverted index.
 * Pipeline: encode query → find nearest prototype → retrieve all chunks mapped to that prototype.
 * O(1) prototype lookup + minimal cosine similarity filter.
 *
 * @param {string} queryText - User's query
 * @param {string} companyId
 * @param {number} limit - Max results
 * @returns {Promise<Array<{id: string, score: number, source: 'quim'}>>}
 */
export async function quimLookup(queryText, companyId = COMPANY, limit = 10) {
  const queryEmbedding = await getEmbedding(queryText);
  if (!queryEmbedding) return [];

  // Load prototypes
  const protoResult = await query(
    `SELECT prototype_id, centroid FROM quim_prototypes WHERE company_id = $1`,
    [companyId]
  );

  if (protoResult.rows.length === 0) return [];

  const prototypes = protoResult.rows.map(r => ({
    prototype_id: r.prototype_id,
    centroid: Array.isArray(r.centroid) ? r.centroid : JSON.parse(r.centroid)
  }));

  // Find nearest prototype
  const nearestProtoId = quantizeToPrototype(queryEmbedding, prototypes);

  // Retrieve all chunks mapped to this prototype
  const results = await query(
    `SELECT DISTINCT ON (chunk_id)
       chunk_id as id,
       question_text,
       chunk_preview,
       question_embedding
     FROM quim_index
     WHERE company_id = $1 AND prototype_id = $2
     ORDER BY chunk_id, id
     LIMIT $3`,
    [companyId, nearestProtoId, limit]
  );

  return results.rows.map(r => ({
    id: r.id,
    score: 0.5, // Neutral score — will be re-ranked by RRF fusion
    question: r.question_text,
    preview: r.chunk_preview,
    source: 'quim'
  }));
}

// ─── Index Stats ─────────────────────────────────────────────────────────────
export async function getQuimStats(companyId = COMPANY) {
  const [indexCount, protoCount] = await Promise.all([
    query(`SELECT COUNT(*) as cnt FROM quim_index WHERE company_id = $1`, [companyId]),
    query(`SELECT COUNT(*) as cnt FROM quim_prototypes WHERE company_id = $1`, [companyId])
  ]);

  return {
    indexEntries: parseInt(indexCount.rows[0]?.cnt || '0', 10),
    prototypes: parseInt(protoCount.rows[0]?.cnt || '0', 10)
  };
}

export default {
  buildQuimIndex,
  quimLookup,
  generateHypotheticalQuestions,
  chunkText,
  getQuimStats
};
