-- 031-provenance-live-content-hash-snapshot.sql
-- Phase 9b — append-only live_content_hash snapshot on aimos_memory_provenance.
--
-- Adds live_content_hash bytea to aimos_memory_provenance. This is the
-- append-only SNAPSHOT of aimos_memories.content_hash at save time. Because
-- the provenance table is INSERT-only (Aladdin Law — no UPDATE, no DELETE),
-- the snapshot cannot be modified after save. Phase 9a's check 2a catches
-- the lazy attacker (UPDATE value without recompute); Phase 9b's check 2b
-- catches the sophisticated attacker (UPDATE value AND recompute the stored
-- content_hash on aimos_memories). The verify path compares:
--
--   aimos_memories.content_hash         (live, mutable — recomputed on UPDATE)
--   aimos_memory_provenance.live_content_hash  (snapshot at save time, append-only)
--
-- Mismatch → the live row was tampered AND the attacker recomputed the live
-- hash — flagged as `live_row_tampered_sophisticated`.
--
-- NULL for rows where the snapshot is N/A:
--   . backfilled rows (pre-migration 030 — no content_hash on aimos_memories)
--   . REWEIGHT events (canonical subset {key, value, scope, memory_type,
--     clearance_level, data_class, source} unchanged by REWEIGHT — the live
--     content_hash on aimos_memories does NOT change, so the snapshot is
--     the same as the prior row's snapshot; passing NULL avoids redundancy)
--   . governor mutations (same reasoning as REWEIGHT)
--
-- Check 2b only fires when BOTH the live row has content_hash AND the latest
-- provenance row has live_content_hash. Otherwise: N/A (not rejected).
--
-- H10 (no legacy aliases): N/A — new column, no alias removed.
-- H8 (no parallel edits): solo migration, sequential after 030.
-- Idempotent: DO/IF NOT EXISTS guard on the column add.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name   = 'aimos_memory_provenance'
       AND column_name  = 'live_content_hash'
  ) THEN
    ALTER TABLE aimos_memory_provenance
      ADD COLUMN live_content_hash bytea;

    COMMENT ON COLUMN aimos_memory_provenance.live_content_hash IS
      'Phase 9b append-only snapshot of aimos_memories.content_hash at save time. NULL for backfilled rows (pre-migration 030), REWEIGHT events, and governor mutations (canonical subset unchanged). /recall verify check 2b compares aimos_memories.content_hash (live, mutable) to this snapshot (append-only). Mismatch → live_row_tampered_sophisticated. Backfill via scripts/backfill-live-content-hash-snapshot.js.';
  END IF;
END
$body$;

-- Visibility: confirm the column exists post-migration.
SELECT 'live_content_hash_column' AS metric, column_name AS value
  FROM information_schema.columns
 WHERE table_name = 'aimos_memory_provenance' AND column_name = 'live_content_hash'
UNION ALL
SELECT 'rows_with_snapshot', count(*)::text
  FROM aimos_memory_provenance WHERE live_content_hash IS NOT NULL
UNION ALL
SELECT 'rows_needing_backfill', count(*)::text
  FROM aimos_memory_provenance WHERE live_content_hash IS NULL;