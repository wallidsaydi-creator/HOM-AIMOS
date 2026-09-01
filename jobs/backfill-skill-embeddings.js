// Backfill procedural_skills that are missing embeddings.
// Run: node jobs/backfill-skill-embeddings.js


import { query } from '../db/connection.js';

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

  console.log(`[backfill] ${result.rows.length} retained legacy skills require canonical procedural-memory re-save`);
  return {
    backfilled: 0,
    failed: 0,
    total: result.rows.length,
    mutation_performed: false,
    disposition: 'LEGACY_READ_ONLY_REQUIRES_CANONICAL_RESAVE',
  };
}

// Direct invocation
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  backfillSkillEmbeddings()
    .then(r => { console.log(JSON.stringify(r)); process.exit(0); })
    .catch(err => { console.error(err); process.exit(1); });
}
