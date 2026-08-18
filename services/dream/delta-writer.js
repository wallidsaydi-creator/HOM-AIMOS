/**
 * delta-writer.js — Delta-Only Memory Write Pipeline (P0-B3-5)
 *
 * Three-role pipeline that prevents "context collapse":
 * - Generator: executes task, flags helpful/harmful memories
 * - Reflector: produces candidate delta bullets (new insights, corrections)
 * - Curator: deterministic merge into memory store (no LLM call)
 *
 * Never pass full memory to LLM for rewriting. Only deltas.
 *
 * Source: ACE — Agentic Context Engineering (Stanford/SambaNova, ICLR 2026)
 * Result: +10.6% on agent benchmarks, 86.9% reduction in adaptation latency.
 *
 * Near-duplicates are rejected deterministically; accepted ACE bullets are
 * stored verbatim as immutable procedural memories.
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 11)
// → Calls: services/db/connection.js (delta upsert)
// Pipeline: DREAM_PIPELINE
// Position: delta pipeline
// ─────────────────────────────────────────────────────────────────────────────

import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { persistMemory } from '../write/persist-memory.js';
import { applyRewardSignal } from '../learning/stdp-kernel.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

const COMPANY = AIMOS_COMPANY_ID;
const DEDUP_THRESHOLD = 0.92; // cosine similarity threshold for deduplication

/**
 * @typedef {Object} DeltaBullet
 * @property {string} id - unique bullet ID (e.g., "shr-00009", "ts-00003")
 * @property {'strategy'|'code_snippet'|'troubleshoot'|'pitfall'|'insight'|'correction'} category
 * @property {string} content - the actual insight, max ~100 tokens
 * @property {number} helpful_count - times flagged as helpful
 * @property {number} harmful_count - times flagged as harmful
 * @property {string} created_at
 * @property {string} last_used
 */

let _bulletCounter = 0;

/**
 * Generate a unique bullet ID.
 * @param {'strategy'|'code_snippet'|'troubleshoot'|'pitfall'|'insight'|'correction'} category
 */
function generateBulletId(category) {
  _bulletCounter++;
  const prefix = {
    strategy: 'str', code_snippet: 'code', troubleshoot: 'ts',
    pitfall: 'pit', insight: 'ins', correction: 'cor'
  }[category] || 'blt';
  return `${prefix}-${String(_bulletCounter).padStart(5, '0')}`;
}

/**
 * Generator phase: flag which existing memories were helpful or harmful during execution.
 *
 * @param {string[]} usedMemoryIds - memory IDs that were retrieved and used
 * @param {{ helpful: string[], harmful: string[] }} flags - which were helpful vs harmful
 * @param {string} companyId
 */
export async function flagMemoryUsage(usedMemoryIds, flags, companyId = COMPANY) {
  const { helpful = [], harmful = [] } = flags;
  const validate = (entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || typeof entry.memory_id !== 'string' || !entry.outcome_evidence) {
      throw new Error('delta_writer_signed_occurrence_evidence_required');
    }
    return entry;
  };
  const helpfulEvidence = helpful.map(validate);
  const harmfulEvidence = harmful.map(validate);

  // Outcome evidence is a signed, bounded cognitive mutation. It never uses
  // age-based decay and never edits content in place.
  await Promise.all(helpfulEvidence.map((entry) => applyRewardSignal(
    entry.memory_id,
    1,
    { outcomeEvidence: entry.outcome_evidence },
  )));
  await Promise.all(harmfulEvidence.map((entry) => applyRewardSignal(
    entry.memory_id,
    -1,
    { outcomeEvidence: entry.outcome_evidence },
  )));

  return { helpfulFlagged: helpfulEvidence.length, harmfulFlagged: harmfulEvidence.length };
}

/**
 * Parse LLM reflector output into structured delta bullets.
 *
 * @param {string} llmOutput - raw LLM output containing bullet candidates
 * @returns {DeltaBullet[]}
 */
export function parseLLMDeltas(llmOutput) {
  const bullets = [];
  const lines = String(llmOutput || '').split('\n').filter(Boolean);

  for (const line of lines) {
    // Try to parse structured output: [CATEGORY] content
    const match = line.match(/^\[?(strategy|code_snippet|troubleshoot|pitfall|insight|correction)\]?\s*[:\-–]\s*(.+)/i);
    if (match) {
      const category = match[1].toLowerCase().replace(/\s+/g, '_');
      const content = match[2].trim().slice(0, 500);
      if (content.length >= 10) {
        bullets.push({
          id: generateBulletId(category),
          category,
          content,
          helpful_count: 0,
          harmful_count: 0,
          created_at: new Date().toISOString(),
          last_used: new Date().toISOString()
        });
      }
    }
  }

  return bullets;
}

/**
 * Curator phase: deterministic merge of delta bullets into Aimos.
 * No LLM call. Rules-based: append new, update counters on existing, dedup by embedding.
 *
 * @param {DeltaBullet[]} deltas - candidate delta bullets
 * @param {string} companyId
 * @returns {Promise<{ added: number, updated: number, deduped: number }>}
 */
export async function curatorMerge(deltas, companyId = COMPANY) {
  let added = 0, updated = 0, deduped = 0;

  for (const delta of deltas) {
    const embedding = await getEmbedding(delta.content);

    // Check for near-duplicates by embedding similarity
    if (embedding && !embedding._degraded) {
      const dupCheck = await query(
        `SELECT id, key, 1 - (embedding <=> $1::vector) as similarity
         FROM aimos_memories
         WHERE company_id = $2 AND embedding IS NOT NULL
           AND memory_type = 'procedural'
         ORDER BY embedding <=> $1::vector ASC
         LIMIT 1`,
        [JSON.stringify(embedding), companyId]
      );

      if (dupCheck.rows.length > 0 && parseFloat(dupCheck.rows[0].similarity) > DEDUP_THRESHOLD) {
        // ACE curator semantics: a semantic duplicate is rejected, not used to
        // rewrite or compress the retained procedural memory.
        deduped++;
        continue;
      }
    }

    // No duplicate — insert the exact structured ACE delta bullet.
    const key = `delta:${delta.category}:${delta.id}`;
    const value = JSON.stringify({
      category: delta.category,
      content: delta.content,
      helpful_count: delta.helpful_count,
      harmful_count: delta.harmful_count
    });

    const saveResult = await persistMemory({
      company_id: companyId,
      agent_id: 'delta-writer',
      mutation_authority: 'housekeeper',
      key,
      value,
      scope: 'system',
      memory_type: 'procedural',
      clearance_level: 5,
      source: 'delta-writer',
    });
    if (!saveResult.rejected) added++;
  }

  return { added, updated, deduped };
}

/**
 * Full delta-only write pipeline: flag → reflect → curate.
 *
 * @param {{ usedMemoryIds: string[], helpful: string[], harmful: string[] }} generatorOutput
 * @param {string} reflectorOutput - LLM-generated delta bullets
 * @param {string} companyId
 */
export async function runDeltaPipeline(generatorOutput, reflectorOutput, companyId = COMPANY) {
  // Phase 1: Generator flags
  const flags = await flagMemoryUsage(
    generatorOutput.usedMemoryIds || [],
    { helpful: generatorOutput.helpful || [], harmful: generatorOutput.harmful || [] },
    companyId
  );

  // Phase 2: Reflector parse
  const deltas = parseLLMDeltas(reflectorOutput);

  // Phase 3: Curator merge
  const mergeResult = await curatorMerge(deltas, companyId);

  return { ...flags, ...mergeResult, deltasGenerated: deltas.length };
}
