-- 016-aimos-save-envelope-nonce-unique.sql
-- Phase 2.2 DB backstop (per the HOM Security Wiring Plan § 2.2).
--
-- The in-memory nonce-window.js enforces per-process freshness. This
-- constraint supplies the cross-process durable backstop: a replay attempt
-- from a DIFFERENT process (whose in-memory window never saw the original
-- nonce) is now rejected by the DB itself, not just by per-process cache.
--
-- Nonces are 256-bit entropy (per agent-identity.js randomNonce), so a unique
-- constraint across the full table lifetime is bounded by the legitimate save
-- rate, not by replay attempts. Storage cost is trivial.
--
-- Single transactional DO block does two things atomically:
--   1. Pre-flight dup check: abort cleanly if duplicate nonces already exist.
--      Live DB has 0 dupes today (verified before this migration). The
--      string_agg() per-aggregate ORDER BY is the universally-portable PG
--      >=9.0 form; subquery ORDER BY is NOT a reliable input-ordering signal
--      past the aggregation boundary.
--   2. Idempotent ALTER: skip the ADD CONSTRAINT if it already exists, so
--      manual-psql re-application (e.g., after operator wipes
--      schema_migrations but keeps the constraint) is a no-op rather than
--      an error.

DO $body$
DECLARE
  dup_count int;
  dup_nonces text;
BEGIN
  SELECT count(*)::int,
         string_agg(nonce, ', ' ORDER BY d.min_created_at DESC)
    INTO dup_count, dup_nonces
  FROM (
    SELECT nonce, min(created_at) AS min_created_at
    FROM aimos_save_envelope
    GROUP BY nonce
    HAVING count(*) > 1
  ) d;
  IF dup_count > 0 THEN
    RAISE EXCEPTION
      'cannot add UNIQUE nonce: % duplicate nonce group(s) exist. sample: % -- resolve with DELETE FROM aimos_save_envelope WHERE nonce IN (...) AND rerun',
      dup_count, dup_nonces;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'aimos_save_envelope_nonce_unique'
      AND conrelid = 'aimos_save_envelope'::regclass
  ) THEN
    ALTER TABLE aimos_save_envelope
      ADD CONSTRAINT aimos_save_envelope_nonce_unique UNIQUE (nonce);
  END IF;
END
$body$;
