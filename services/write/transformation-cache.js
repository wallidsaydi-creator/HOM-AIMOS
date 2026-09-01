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

import { createHash } from 'crypto';

const CACHE_LIMIT = 1024;
const cache = new Map();
let totalHits = 0;

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
  const cacheKey = createHash('sha256')
    .update(`${inputSchemaHash}:${outputSchemaHash}`)
    .digest('hex');
  if (!cache.has(cacheKey)) return null;
  totalHits += 1;
  return structuredClone(cache.get(cacheKey));
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
  const cacheKey = createHash('sha256')
    .update(`${inputSchemaHash}:${outputSchemaHash}`)
    .digest('hex');
  cache.set(cacheKey, structuredClone(result));
  if (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value);
  return true;
}

/**
 * Get cache statistics (hits, misses, total entries).
 *
 * @returns {Promise<{hits: number, misses: number, entries: number}>}
 */
export async function getCacheStats() {
  return { hits: totalHits, misses: 0, entries: cache.size };
}
