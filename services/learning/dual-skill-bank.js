/**
 * dual-skill-bank.js — Dual-Granularity Skill System (P0-B3-2)
 * Source: D2Skill (Chinese Acad. Sciences, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (Pre-run skill injection)
 * 2. → Pulls from: aimos_memories (SQL + pgvector for skill recall)
 * 3. → Pushes to: aimos_memories (Saves hindsight utility scores)
 * 4. ↔ Interacts with: epistemic-vigilance.js (Skill deposit gate)
 *
 * LOGIC GUIDE: Two-tier skill retrieval: Task Skills (guidance) and 
 * Step Skills (corrections). Uses UCB exploration to discover new paths.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';

const COMPANY = AIMOS_COMPANY_ID;
const BETA_TASK = 0.3;   // EMA smoothing for task-level utility
const BETA_STEP = 0.2;   // EMA smoothing for step-level utility
const ALPHA = 0.6;       // similarity vs utility+exploration weight
const ETA = 0.5;         // exploration bonus coefficient
const SIM_THRESHOLD = 0.75; // minimum cosine similarity for retrieval
const PROTECTION_PERIOD_HOURS = 48; // protect new skills from eviction

// ─── SCHEMA ───────────────────────────────────────────────────────────────
let _schemaEnsured = false;
async function ensureSchema() {
  if (_schemaEnsured) return;
  const result = await query(
    `SELECT ARRAY(
       SELECT required.column_name
         FROM unnest(ARRAY[
           'id','company_id','skill_type','principle','when_to_apply',
           'retrieval_key','retrieval_embedding','utility','retrieval_count',
           'success_count','failure_count','created_at','updated_at','is_active'
         ]) AS required(column_name)
        WHERE NOT EXISTS (
          SELECT 1 FROM information_schema.columns actual
           WHERE actual.table_schema = current_schema()
             AND actual.table_name = 'skill_bank'
             AND actual.column_name = required.column_name
        )
     ) AS missing_columns`,
  );
  if (result.rows[0]?.missing_columns?.length) {
    const error = new Error(`MIGRATION_SCHEMA_MISSING:skill_bank:${result.rows[0].missing_columns.join(',')}`);
    error.code = 'MIGRATION_SCHEMA_MISSING';
    throw error;
  }
  _schemaEnsured = true;
}

/**
 * Generate a skill ID.
 */
function genId(type) {
  return `${type}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Deposit a new skill into the bank.
 *
 * @param {'task'|'step'} skillType
 * @param {string} principle - what to do
 * @param {string} whenToApply - trigger condition
 * @param {string} retrievalKey - text used for embedding-based retrieval
 * @param {string} companyId
 * @returns {Promise<string>} skill ID
 */
export async function depositSkill(skillType, principle, whenToApply, retrievalKey, companyId = COMPANY) {
  await ensureSchema();
  const id = genId(skillType);
  const embedding = await getEmbedding(retrievalKey);

  await query(
    `INSERT INTO skill_bank (id, company_id, skill_type, principle, when_to_apply, retrieval_key, retrieval_embedding, utility)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 0.5)`,
    [id, companyId, skillType, principle, whenToApply, retrievalKey, embedding ? JSON.stringify(embedding) : null]
  );

  return id;
}

/**
 * Two-stage skill retrieval with UCB exploration bonus.
 *
 * Stage 1: cosine similarity filter (top-m above threshold)
 * Stage 2: UCB-scored reranking: score = α*sim + (1-α)*(u + η*√(log(1+N)/1+n))
 *
 * @param {string} queryText - current task or observation
 * @param {'task'|'step'} skillType
 * @param {number} topK - number to return
 * @param {string} companyId
 */
export async function retrieveSkills(queryText, skillType, topK = 3, companyId = COMPANY) {
  await ensureSchema();
  const embedding = await getEmbedding(queryText);
  if (!embedding || embedding._degraded) return [];

  // Stage 1: cosine similarity filter
  const candidates = await query(
    `SELECT id, principle, when_to_apply, retrieval_key, utility, retrieval_count,
            1 - (retrieval_embedding <=> $1::vector) as similarity
     FROM skill_bank
     WHERE company_id = $2 AND skill_type = $3
       AND retrieval_embedding IS NOT NULL
     ORDER BY retrieval_embedding <=> $1::vector ASC
     LIMIT 20`,
    [JSON.stringify(embedding), companyId, skillType]
  );

  // Get total retrieval count for UCB
  const totalResult = await query(
    `SELECT COALESCE(SUM(retrieval_count), 1) as total FROM skill_bank
     WHERE company_id = $1 AND skill_type = $2`,
    [companyId, skillType]
  );
  const totalRetrievals = parseInt(totalResult.rows[0]?.total || '1', 10);

  // Stage 2: UCB-scored reranking
  const scored = candidates.rows
    .filter(r => parseFloat(r.similarity) >= SIM_THRESHOLD)
    .map(r => {
      const sim = parseFloat(r.similarity);
      const u = parseFloat(r.utility);
      const n = parseInt(r.retrieval_count, 10);
      const exploration = ETA * Math.sqrt(Math.log(1 + totalRetrievals) / (1 + n));
      const score = ALPHA * sim + (1 - ALPHA) * (u + exploration);

      return { ...r, similarity: sim, utility: u, exploration, score };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, topK);

  // Increment retrieval counts (fire-and-forget)
  for (const skill of scored) {
    query(
      `UPDATE skill_bank SET retrieval_count = retrieval_count + 1, updated_at = NOW() WHERE id = $1`,
      [skill.id]
    ).catch(() => {});
  }

  return scored;
}

/**
 * Update skill utility using hindsight signal (EMA).
 *
 * For task skills: credit = success_rate_with_skill - success_rate_without
 * For step skills: credit = trajectory_outcome - baseline_success_rate
 *
 * @param {string} skillId
 * @param {number} credit - hindsight signal (-1 to 1)
 * @param {'task'|'step'} skillType
 */
export async function updateUtility(skillId, credit, skillType = 'task') {
  await ensureSchema();
  const beta = skillType === 'task' ? BETA_TASK : BETA_STEP;

  const current = await query(
    `SELECT utility FROM skill_bank WHERE id = $1`,
    [skillId]
  );
  if (current.rows.length === 0) return;

  const currentUtility = parseFloat(current.rows[0].utility);
  const newUtility = Math.max(0, Math.min(1, (1 - beta) * currentUtility + beta * credit));

  const successDelta = credit > 0 ? 1 : 0;
  const failureDelta = credit < 0 ? 1 : 0;

  await query(
    `UPDATE skill_bank SET utility = $1, success_count = success_count + $2,
     failure_count = failure_count + $3, updated_at = NOW() WHERE id = $4`,
    [newUtility, successDelta, failureDelta, skillId]
  );
}

/**
 * Get skill bank statistics.
 */
export async function getSkillBankStats(companyId = COMPANY) {
  await ensureSchema();
  const result = await query(
    `SELECT skill_type, COUNT(*) as count, AVG(utility) as avg_utility,
            SUM(retrieval_count) as total_retrievals
     FROM skill_bank WHERE company_id = $1
     GROUP BY skill_type`,
    [companyId]
  );
  const stats = { task: { count: 0, avgUtility: 0, totalRetrievals: 0 }, step: { count: 0, avgUtility: 0, totalRetrievals: 0 } };
  for (const r of result.rows) {
    stats[r.skill_type] = {
      count: parseInt(r.count, 10),
      avgUtility: parseFloat(r.avg_utility || 0),
      totalRetrievals: parseInt(r.total_retrievals || 0, 10)
    };
  }
  return stats;
}
