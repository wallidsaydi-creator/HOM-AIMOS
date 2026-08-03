// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — not yet wired into a live pipeline
// Purpose: SHA-256 keyed cache for schema transformation results; avoids
//          redundant computation on identical input/output schema pairs (P2-B3-1)
// Wire into: ingestion-orchestrator.js or mnemonic-encoder.js (SAVE pipeline)
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSFORMATION CACHE (transformation-cache.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-1: Caches schema transformation results to avoid redundant computation.
// Uses SHA-256 hashing to create deterministic cache keys from input/output schemas.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { createHash } from 'crypto';

const COMPANY = AIMOS_COMPANY_ID;

/**
 * Compute SHA-256 hash of a schema object.
 *
 * @param {Object} schema - The schema to hash
 * @returns {string} - SHA-256 hex digest
 */
export function computeSchemaHash(schema) {
  const normalized = JSON.stringify(schema, Object.keys(schema).sort());
  return createHash('sha256').update(normalized).digest('hex');
}

/**
 * Retrieve a cached transformation result by schema hashes.
 *
 * @param {string} inputSchemaHash - SHA-256 hash of input schema
 * @param {string} outputSchemaHash - SHA-256 hash of output schema
 * @returns {Promise<Object|null>} - Cached result or null if not found
 */
export async function getCachedTransformation(inputSchemaHash, outputSchemaHash) {
  try {
    const cacheKey = createHash('sha256')
      .update(`${inputSchemaHash}:${outputSchemaHash}`)
      .digest('hex');

    const result = await query(
      `SELECT result FROM transformation_cache
       WHERE company_id = $1
         AND cache_key = $2`,
      [COMPANY, cacheKey]
    );

    if (result.rows.length === 0) {
      return null;
    }

    // Record hit
    await query(
      `UPDATE transformation_cache
       SET hit_count = hit_count + 1, last_hit_at = NOW()
       WHERE company_id = $1
         AND cache_key = $2`,
      [COMPANY, cacheKey]
    ).catch(() => {}); // Silent fail on update

    return result.rows[0].result;
  } catch (err) {
    console.error('[transformation-cache] getCachedTransformation error:', err.message);
    return null;
  }
}

/**
 * Store a transformation result in the cache.
 *
 * @param {string} inputSchemaHash - SHA-256 hash of input schema
 * @param {string} outputSchemaHash - SHA-256 hash of output schema
 * @param {Object} result - The transformation result to cache
 * @returns {Promise<boolean>} - true on success
 */
export async function cacheTransformation(inputSchemaHash, outputSchemaHash, result) {
  try {
    const cacheKey = createHash('sha256')
      .update(`${inputSchemaHash}:${outputSchemaHash}`)
      .digest('hex');

    await query(
      `INSERT INTO transformation_cache (
         cache_key,
         company_id,
         input_schema_hash,
         output_schema_hash,
         result,
         hit_count,
         created_at,
         last_hit_at
       )
       VALUES ($1, $2, $3, $4, $5::jsonb, 1, NOW(), NOW())
       ON CONFLICT (company_id, cache_key) DO UPDATE
       SET result = $5::jsonb,
           hit_count = 1,
           input_schema_hash = $3,
           output_schema_hash = $4,
           last_hit_at = NOW()`,
      [cacheKey, COMPANY, inputSchemaHash, outputSchemaHash, JSON.stringify(result)]
    );

    return true;
  } catch (err) {
    console.error('[transformation-cache] cacheTransformation error:', err.message);
    return false;
  }
}

/**
 * Get cache statistics (hits, misses, total entries).
 *
 * @returns {Promise<{hits: number, misses: number, entries: number}>}
 */
export async function getCacheStats() {
  try {
    const result = await query(
      `SELECT
        COALESCE(SUM(hit_count), 0) as total_hits,
        COUNT(*) as total_entries
       FROM transformation_cache
       WHERE company_id = $1`,
      [COMPANY]
    );

    const row = result.rows[0] || { total_hits: 0, total_entries: 0 };
    const hits = parseInt(row.total_hits, 10) || 0;
    const entries = parseInt(row.total_entries, 10) || 0;

    return {
      hits,
      misses: Math.max(0, entries - hits),
      entries
    };
  } catch (err) {
    console.error('[transformation-cache] getCacheStats error:', err.message);
    return { hits: 0, misses: 0, entries: 0 };
  }
}
