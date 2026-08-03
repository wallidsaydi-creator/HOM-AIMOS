// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: delta-writer.js, aimos.js, spiced-consolidator.js
// → Calls: db (connection.js)
// Pipeline: DREAM | Position: Consolidation (dream cycle)
// Sources: MemGPT (memory conflict detection), HippoRAG (entity deduplication)
// ─────────────────────────────────────────────────────────────────────────────
import { query } from '../../db/connection.js';

function toVectorLiteral(embedding) {
  if (!Array.isArray(embedding) || embedding.length === 0) {
    throw new Error('embedding must be a non-empty array');
  }
  return `[${embedding.map((value) => Number(value)).join(',')}]`;
}

export async function checkConflict(company_id, key, value, embedding) {
  try {
    const result = await query(
      `SELECT id, key, value, (embedding <=> $1::vector) as similarity
       FROM aimos_memories
       WHERE company_id = $2
       ORDER BY (embedding <=> $1::vector) ASC
       LIMIT 1`,
      [toVectorLiteral(embedding), company_id]
    );
    
    if (result.rows.length === 0) return null;
    
    const existing = result.rows[0];
    const similarity = parseFloat(existing.similarity);
    
    if (similarity < 0.03 && existing.key === key) {
      return { id: existing.id, type: 'duplicate' };
    }
    
    if (similarity < 0.1) {
      return { id: existing.id, type: 'update' };
    }
    
    return null;
  } catch (error) {
    console.error('[Curator] Error:', error);
    return null;
  }
}
