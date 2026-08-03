-- 030-aimos-memories-content-hash.sql
-- Phase 9a — live-row integrity hash for /recall sig verification.
--
-- Adds content_hash to aimos_memories: sha256(canonicalJson({key, value, scope,
-- memory_type, clearance_level, data_class, source})) computed at save time
-- from the canonical field subset. The /recall choke-point (Phase 8 +
-- Phase 9) recomputes this hash from the live row's fields and compares to
-- the stored content_hash. If they differ, the live row was tampered
-- (someone UPDATEd value/key/scope/etc. without recomputing the hash).
--
-- This closes the Phase 8 gap: Phase 8's verifyRecallMemories only checked
-- provenance self-consistency (mutation_hash recompute), which does NOT
-- detect tampering of aimos_memories.value. Phase 9a adds the live-row
-- integrity check: recompute content_hash from the live fields, compare to
-- the stored content_hash. Mismatch → the row is rejected under enforce
-- (SECURITY_ENFORCE_RECALL_SIG_VERIFY) or logged under shadow.
--
-- Phase 9b (follow-up) will add live_content_hash to aimos_memory_provenance
-- as an append-only snapshot of this hash at save time, to catch the
-- sophisticated attacker who tampers value AND recomputes the stored hash.
-- The provenance row is append-only (Aladdin Law — no UPDATE, no DELETE),
-- so the snapshot can't be modified after save. Phase 9a alone catches the
-- primary attack (direct DB UPDATE of value without hash recompute).
--
-- Canonical field subset (the fields that define the memory's CONTENT +
-- CLASSIFICATION, not its lifecycle state):
--   key, value, scope, memory_type, clearance_level, data_class, source
--
-- Excluded fields (legitimately change over time):
--   created_at, updated_at, access_count, last_accessed_at, credit_score,
--   memory_tier, decay_weight, retrieval_weight, embedding, search_vector,
--   is_active, medallion_layer, freshness_state, last_verified_at,
--   verified_by, verification_basis, semantic_triples, surprise_at_save,
--   compression_ratio, quant_idx, residual_vector, valid_from, valid_until
--
-- H10 (no legacy aliases): N/A — new column, no alias removed.
-- H8 (no parallel edits): solo migration, sequential after 029.
-- Idempotent: DO/IF NOT EXISTS guard on the column add.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name   = 'aimos_memories'
       AND column_name  = 'content_hash'
  ) THEN
    ALTER TABLE aimos_memories
      ADD COLUMN content_hash bytea;

    COMMENT ON COLUMN aimos_memories.content_hash IS
      'Phase 9a live-row integrity hash = sha256(canonicalJson({key, value, scope, memory_type, clearance_level, data_class, source})). Computed at save time from the canonical field subset. /recall verify recomputes from the live row + compares. Mismatch → the row was tampered (value/key/scope/etc. changed without recomputing the hash). NULL for rows written before migration 030 — backfill via scripts/backfill-live-content-hash.js.';
  END IF;
END
$body$;

-- Visibility: confirm the column exists post-migration.
SELECT 'content_hash_column' AS metric, column_name AS value
  FROM information_schema.columns
 WHERE table_name = 'aimos_memories' AND column_name = 'content_hash'
UNION ALL
SELECT 'rows_with_content_hash', count(*)::text
  FROM aimos_memories WHERE content_hash IS NOT NULL
UNION ALL
SELECT 'rows_needing_backfill', count(*)::text
  FROM aimos_memories WHERE content_hash IS NULL;