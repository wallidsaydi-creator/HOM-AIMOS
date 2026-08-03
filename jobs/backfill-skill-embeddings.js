// Backfill procedural_skills that are missing embeddings.
// Run: node jobs/backfill-skill-embeddings.js


import { query } from '../db/connection.js';
import { getEmbedding } from '../services/core/embeddings.js';

export async function backfillSkillEmbeddings() {
  const result = await query(
    `SELECT id, skill_name, trigger_pattern, expected_outcome, tags
     FROM procedural_skills
     WHERE skill_embedding IS NULL`
  );

  if (!result.rows.length) {
    console.log('[backfill] All skills already have embeddings');
    return { backfilled: 0, failed: 0, total: 0 };
  }

  console.log(`[backfill] Found ${result.rows.length} skills without embeddings`);
  let success = 0;
  let failed = 0;

  for (const skill of result.rows) {
    const desc = `${skill.skill_name}: ${skill.trigger_pattern || 'general'} task. ${skill.expected_outcome || ''}`.trim();
    try {
      const embedding = await getEmbedding(desc);
      if (embedding) {
        await query(
          `UPDATE procedural_skills SET skill_embedding = $1::vector WHERE id = $2`,
          [JSON.stringify(embedding), skill.id]
        );
        success++;
        console.log(`  + ${skill.skill_name}`);
      }
    } catch (err) {
      failed++;
      console.warn(`  x ${skill.skill_name}: ${err.message}`);
    }
  }

  console.log(`[backfill] Done: ${success} embedded, ${failed} failed out of ${result.rows.length}`);
  return { backfilled: success, failed, total: result.rows.length };
}

// Direct invocation
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  backfillSkillEmbeddings()
    .then(r => { console.log(JSON.stringify(r)); process.exit(0); })
    .catch(err => { console.error(err); process.exit(1); });
}
