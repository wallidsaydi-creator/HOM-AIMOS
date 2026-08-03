/**
 * skill-consolidation.js — Skill Clustering and Abstraction
 * Source: Complementary Learning Systems (McClelland & Kumaran)
 * Additive TEM authority: Learning Hierarchical Procedural Memory for LLM
 * Agents through Bayesian Selection and Contrastive Refinement (MACLA)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: nightly-dream.js (Step 10)
 * 2. → Pulls from: aimos_memories (Provisional skills)
 * 3. ↔ Interacts with: services/core/embeddings.js (Clustering similarity)
 * 4. ↔ Interacts with: services/shared/native-llm.js (LLM abstraction)
 * 5. → Pushes to: aimos_memories (Additive abstraction summaries)
 *
 * LOGIC GUIDE: Clusters similar skills (sim > 0.85). Extracts shared 
 * abstractions via LLM. Promotes provisional skills to stable after validation.
 * MACLA alignment is limited to procedural-memory visibility and reuse
 * diagnostics; this file's clustering threshold remains governed by its
 * existing CLS/embedding-distance design.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 10)
// → Calls: services/core/embeddings.js (skill cluster similarity)
// → Calls: services/shared/native-llm.js (abstraction extraction)
// Pipeline: DREAM_PIPELINE
// Position: skill clustering + abstraction
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { runProvider } from '../core/providers.js';
import { logEvent } from '../observe/event-ledger.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;

// Embedding similarity threshold for clustering (pgvector cosine distance < 0.15 ≈ similarity > 0.85)
const CLUSTER_DISTANCE_THRESHOLD = 0.15;

// Validation count required to promote a provisional skill to stable
const PROMOTION_VALIDATION_COUNT = 3;

/**
 * Cluster skills with embedding similarity above the threshold.
 * Uses pgvector self-join to find pairs, then groups into clusters.
 *
 * @param {string} [companyId]
 * @returns {Promise<Array<{clusterId: string, skillIds: string[], centerKey: string}>>}
 */
export async function clusterSimilarSkills(companyId) {
  const cid = companyId || COMPANY;

  let rows;
  try {
    // Self-join via pgvector: find skill pairs within distance threshold
    const result = await query(
      `SELECT a.id AS id_a, b.id AS id_b,
              a.key AS key_a, b.key AS key_b,
              (a.embedding <=> b.embedding) AS distance
       FROM aimos_memories a
       JOIN aimos_memories b ON a.company_id = b.company_id
         AND a.id < b.id
       WHERE a.company_id = $1
         AND a.memory_type IN ('procedural', 'skill')
         AND b.memory_type IN ('procedural', 'skill')
         AND a.embedding IS NOT NULL
         AND b.embedding IS NOT NULL
         AND (a.embedding <=> b.embedding) < $2
       ORDER BY distance ASC
       LIMIT 1000`,
      [cid, CLUSTER_DISTANCE_THRESHOLD]
    );
    rows = result.rows;
  } catch (err) {
    console.error('[skill-consolidation] clusterSimilarSkills DB error:', err.message);
    return [];
  }

  if (!rows.length) return [];

  // Union-Find clustering
  const parent = new Map();
  function find(x) {
    if (!parent.has(x)) parent.set(x, x);
    if (parent.get(x) !== x) parent.set(x, find(parent.get(x)));
    return parent.get(x);
  }
  function union(x, y) {
    parent.set(find(x), find(y));
  }

  for (const row of rows) {
    union(row.id_a, row.id_b);
  }

  // Collect all involved IDs with their keys
  const idToKey = new Map();
  for (const row of rows) {
    idToKey.set(row.id_a, row.key_a);
    idToKey.set(row.id_b, row.key_b);
  }

  // Group by root
  const clusterMap = new Map();
  for (const [id] of idToKey) {
    const root = find(id);
    if (!clusterMap.has(root)) clusterMap.set(root, []);
    clusterMap.get(root).push(id);
  }

  return Array.from(clusterMap.entries())
    .filter(([, members]) => members.length >= 2)
    .map(([root, members]) => ({
      clusterId: root,
      skillIds: members,
      centerKey: idToKey.get(root) || root,
    }));
}

/**
 * Extract the shared abstraction from a cluster of similar skills.
 * Creates a new additive summary memory — originals are never modified.
 *
 * @param {Object} skillCluster - From clusterSimilarSkills output
 * @param {string[]} skillCluster.skillIds - IDs of clustered skills
 * @param {string} skillCluster.clusterId
 * @param {string} [companyId]
 * @returns {Promise<{abstractionKey: string, abstractionValue: string, saved: boolean}>}
 */
export async function extractAbstraction(skillCluster, companyId) {
  const cid = companyId || COMPANY;

  if (!Array.isArray(skillCluster?.skillIds) || skillCluster.skillIds.length < 2) {
    return { abstractionKey: null, abstractionValue: null, saved: false };
  }

  // Fetch skill values for LLM analysis
  let skillRows;
  try {
    const result = await query(
      `SELECT key, value FROM aimos_memories
       WHERE id = ANY($1) AND company_id = $2`,
      [skillCluster.skillIds, cid]
    );
    skillRows = result.rows;
  } catch (err) {
    console.error('[skill-consolidation] extractAbstraction fetch error:', err.message);
    return { abstractionKey: null, abstractionValue: null, saved: false };
  }

  const skillSummaries = skillRows
    .map((r) => `Key: ${r.key}\nValue: ${String(r.value || '').slice(0, 300)}`)
    .join('\n---\n');

  const prompt = `You are a skill abstraction engine. Find the shared generalised pattern from these similar skills.

SKILLS IN CLUSTER:
${skillSummaries.slice(0, 3000)}

Return ONLY a JSON object — no markdown, no explanation.
Output:
{
  "abstraction_name": "<concise name for the shared skill>",
  "shared_pattern": "<generalised principle that covers all cluster members>",
  "applicability": "<when to apply this abstraction>",
  "confidence": 0.0-1.0
}`;

  let raw = '';
  try {
    raw = await runProvider({ prompt });
  } catch (err) {
    console.error('[skill-consolidation] extractAbstraction LLM call failed:', err.message);
    return { abstractionKey: null, abstractionValue: null, saved: false };
  }

  let abstraction;
  try {
    const stripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    abstraction = JSON.parse(stripped);
  } catch {
    return { abstractionKey: null, abstractionValue: null, saved: false };
  }

  const abstractionKey = `skill_abstraction:cluster_${skillCluster.clusterId.slice(0, 20)}`;
  const abstractionValue = JSON.stringify({
    ...abstraction,
    source_skill_ids: skillCluster.skillIds,
    cluster_size: skillCluster.skillIds.length,
    generated_at: new Date().toISOString(),
  });

  try {
    const saveResult = await persistMemory({
      company_id: cid,
      agent_id: 'skill-consolidation',
      mutation_authority: 'housekeeper',
      key: abstractionKey,
      value: abstractionValue,
      scope: 'global',
      memory_type: 'procedural',
      clearance_level: 3,
      source: 'skill-consolidation',
    });

    await logEvent(cid, 'skill-consolidation', 'abstraction_extracted', abstractionKey, {
      reasoning: `Extracted abstraction from ${skillCluster.skillIds.length} similar skills. Pattern: ${abstraction?.shared_pattern?.slice(0, 100) || 'n/a'}`,
      clusterSize: skillCluster.skillIds.length,
      confidence: abstraction?.confidence,
    });

    return { abstractionKey, abstractionValue, saved: !saveResult.rejected };
  } catch (err) {
    console.error('[skill-consolidation] extractAbstraction save error:', err.message);
    return { abstractionKey, abstractionValue, saved: false };
  }
}

/**
 * Detect contradictions within a skill cluster.
 * Returns pairs of skills with opposing conclusions.
 *
 * @param {Object} skillCluster - From clusterSimilarSkills
 * @param {string} [companyId]
 * @returns {Promise<Array<{skillIdA: string, skillIdB: string, contradiction: string}>>}
 */
export async function detectSkillContradictions(skillCluster, companyId) {
  const cid = companyId || COMPANY;

  if (!Array.isArray(skillCluster?.skillIds) || skillCluster.skillIds.length < 2) {
    return [];
  }

  let skillRows;
  try {
    const result = await query(
      `SELECT id, key, value FROM aimos_memories
       WHERE id = ANY($1) AND company_id = $2`,
      [skillCluster.skillIds, cid]
    );
    skillRows = result.rows;
  } catch (err) {
    console.error('[skill-consolidation] detectSkillContradictions fetch error:', err.message);
    return [];
  }

  const summaries = skillRows
    .map((r) => `ID: ${r.id}\nKey: ${r.key}\nValue: ${String(r.value || '').slice(0, 250)}`)
    .join('\n---\n');

  const prompt = `You are a contradiction detector. Find skills with opposing conclusions.

SKILLS:
${summaries.slice(0, 3000)}

Return ONLY a JSON array of contradictions. If none found, return [].
Output format:
[{"skillIdA": "<id>", "skillIdB": "<id>", "contradiction": "<what they disagree on>"}]`;

  let raw = '';
  try {
    raw = await runProvider({ prompt });
  } catch (err) {
    console.error('[skill-consolidation] detectSkillContradictions LLM call failed:', err.message);
    return [];
  }

  try {
    const stripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    const arrayMatch = stripped.match(/\[[\s\S]*\]/);
    if (!arrayMatch) return [];
    const parsed = JSON.parse(arrayMatch[0]);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * Promote a provisional skill to stable status once validated 3+ times.
 * Checks the validation_count in the skill's value or metadata.
 *
 * @param {string} skillId - UUID of the skill to evaluate for promotion
 * @param {string} [companyId]
 * @returns {Promise<{promoted: boolean, validationCount: number, reason: string}>}
 */
export async function promoteProvisionalSkill(skillId, companyId) {
  const cid = companyId || COMPANY;

  let row;
  try {
    const result = await query(
      `SELECT projected.id, projected.key, projected.value, projected.memory_type,
              projected.scope, projected.clearance_level, projected.data_class
         FROM aimos_memories requested
         JOIN LATERAL (
           SELECT version.id, version.key, version.value, version.memory_type,
                  version.scope, version.clearance_level, version.data_class
             FROM aimos_memories version
           WHERE version.company_id = requested.company_id
              AND version.key = requested.key
              AND NOT EXISTS (
                SELECT 1
                  FROM aimos_memories successor
                 WHERE successor.company_id = version.company_id
                   AND successor.key = version.key
                   AND successor.supersedes_id = version.id
              )
            -- Append-only projection: the current version is the newest write
            -- for this key (created_at DESC), not an id ordinal. Among no-successor
            -- heads there is normally exactly one; LIMIT 2 still surfaces a branch.
            ORDER BY version.created_at DESC NULLS LAST
            LIMIT 2
         ) projected ON TRUE
        WHERE requested.id = $1 AND requested.company_id = $2`,
      [skillId, cid]
    );
    if (!result.rows.length) {
      return { promoted: false, validationCount: 0, reason: 'skill_not_found' };
    }
    if (result.rows.length !== 1) {
      return { promoted: false, validationCount: 0, reason: 'skill_topology_invalid' };
    }
    row = result.rows[0];
  } catch (err) {
    console.error('[skill-consolidation] promoteProvisionalSkill fetch error:', err.message);
    return { promoted: false, validationCount: 0, reason: `db_error: ${err.message}` };
  }

  // Parse validation count from value JSONB
  let valueObj = {};
  try {
    const parsed = typeof row.value === 'string' ? JSON.parse(row.value) : row.value;
    valueObj = parsed && typeof parsed === 'object' ? parsed : {};
  } catch { valueObj = {}; }

  const validationCount = parseInt(valueObj.validation_count || 0, 10);

  if (validationCount < PROMOTION_VALIDATION_COUNT) {
    return {
      promoted: false,
      validationCount,
      reason: `insufficient_validations (${validationCount}/${PROMOTION_VALIDATION_COUNT})`,
    };
  }

  if (valueObj.stability === 'stable') {
    return { promoted: false, validationCount, reason: 'already_stable' };
  }

  // Promote: set a stable flag in value
  valueObj.stability = 'stable';
  valueObj.promoted_at = new Date().toISOString();

  try {
    const saved = await persistMemory({
      company_id: cid,
      agent_id: 'skill-consolidation',
      mutation_authority: 'housekeeper',
      key: row.key,
      value: JSON.stringify(valueObj),
      scope: row.scope || 'system',
      memory_type: row.memory_type,
      clearance_level: Number(row.clearance_level || 5),
      data_class: row.data_class || 'internal',
      source: 'skill-consolidation',
      supersedes_id: row.id,
    });
    if (!saved?.id || saved.rejected) {
      throw new Error(saved?.reason || 'promotion_persistence_failed');
    }

    await logEvent(cid, 'skill-consolidation', 'skill_promoted', row.key, {
      reasoning: `Skill promoted to stable after ${validationCount} validations`,
      skillId,
      validationCount,
    });

    return { promoted: true, validationCount, reason: 'promoted_to_stable' };
  } catch (err) {
    console.error('[skill-consolidation] promoteProvisionalSkill save error:', err.message);
    return { promoted: false, validationCount, reason: `save_error: ${err.message}` };
  }
}

/**
 * Identify skills that have been superseded by newer, more specific skills.
 * Flags them as redundant — they remain in DB, just marked advisory.
 *
 * @param {string} [companyId]
 * @returns {Promise<Array<{skillId: string, key: string, supersededBy: string|null, reason: string}>>}
 */
export async function flagRedundantSkills(companyId) {
  const cid = companyId || COMPANY;

  let rows;
  try {
    const result = await query(
      `SELECT id, key, value, supersedes_id, updated_at
       FROM aimos_memories
       WHERE company_id = $1
         AND memory_type IN ('procedural', 'skill')
         AND (supersedes_id IS NOT NULL
              OR key LIKE 'skill_abstraction:%')
       ORDER BY updated_at DESC
       LIMIT 200`,
      [cid]
    );
    rows = result.rows;
  } catch (err) {
    console.error('[skill-consolidation] flagRedundantSkills DB error:', err.message);
    return [];
  }

  return rows.map((row) => ({
    skillId: row.id,
    key: row.key,
    supersededBy: row.supersedes_id || null,
    reason: row.supersedes_id
      ? `superseded_by_${row.supersedes_id}`
      : 'abstraction_exists_for_pattern',
  }));
}
