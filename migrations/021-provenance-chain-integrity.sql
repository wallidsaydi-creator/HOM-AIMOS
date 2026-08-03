-- 021-provenance-chain-integrity.sql
-- Phase 4 Step 4 — Chain integrity constraints for aimos_memory_provenance.
--
-- The provenance ledger (018) is a linked-list per memory_id via
-- prev_mutation_hash. The 018 schema enforces UNIQUE(memory_id,
-- mutation_hash) — prevents two rows with the same mutation_hash — but
-- does NOT enforce the linked-list shape. Two invariants that 018 left
-- implicit are made explicit here:
--
--   (1) ONE GENESIS PER memory_id — exactly one row with
--       prev_mutation_hash IS NULL. The 020 backfill achieved this state
--       (verified: memories_with_provenance=19041, dup_genesis_rows=0).
--       This partial unique index locks the invariant in so that a buggy
--       P-live path or a concurrent-writer race cannot create a second
--       genesis row for a memory that already has one.
--
--   (2) NO FORK-RACE — within a memory_id, each prev_mutation_hash can be
--       claimed by at most one row. Without this, two concurrent writers
--       could both SELECT the latest row's mutation_hash and both INSERT
--       with that prev_link — producing a branching tree instead of a
--       linked list. The unique constraint converts that race into a
--       constraint violation the caller can retry.
--
--   (3) CONSISTENCY — is_genesis must agree with prev_mutation_hash:
--       genesis ⟺ prev IS NULL. Locks in the invariant across all row
--       types (P-anchor / P-real / P-live). Catches a class of bug where
--       a row claims is_genesis=true but provides a non-null prev.
--
-- H10 (no legacy aliases): N/A — additive indexes/constraints only, no
--     columns added or removed.
-- H8 (no parallel edits): solo migration, sequential after 020.
-- Idempotent: CREATE UNIQUE INDEX IF NOT EXISTS + DO/IF NOT EXISTS for
--             the CHECK constraint.

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_provenance_one_genesis
  ON aimos_memory_provenance (memory_id)
  WHERE prev_mutation_hash IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_provenance_next_unique
  ON aimos_memory_provenance (memory_id, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'aimos_memory_provenance_genesis_consistent'
      AND conrelid = 'aimos_memory_provenance'::regclass
  ) THEN
    ALTER TABLE aimos_memory_provenance
      ADD CONSTRAINT aimos_memory_provenance_genesis_consistent
      CHECK (
        (is_genesis = true  AND prev_mutation_hash IS NULL)
     OR (is_genesis = false AND prev_mutation_hash IS NOT NULL)
      );
  END IF;
END
$body$;

-- Verification query (run after applying; should both return 0).
-- SELECT 'existing_double_genesis', count(*)::text FROM (
--   SELECT memory_id FROM aimos_memory_provenance
--    WHERE prev_mutation_hash IS NULL GROUP BY memory_id HAVING count(*) > 1
-- ) d;
-- SELECT 'existing_fork_races', count(*)::text FROM (
--   SELECT memory_id, prev_mutation_hash FROM aimos_memory_provenance
--    WHERE prev_mutation_hash IS NOT NULL
--    GROUP BY memory_id, prev_mutation_hash HAVING count(*) > 1
-- ) d;
