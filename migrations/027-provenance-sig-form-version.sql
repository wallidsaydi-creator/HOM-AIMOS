-- 027-provenance-sig-form-version.sql
-- Phase 4 Step 4 — sig canonical form versioning for the backfill ceremony.
--
-- Adds sig_form_version to aimos_memory_provenance so the verify path can
-- branch on which canonical form an Ed25519 sig was produced over:
--
--   v1 (default) — canonicalJson(body) || '\n' || nonce || '\n' || String(ts_signed)
--                  3-field form. Used by the 43 P-real rows (sig imported
--                  from aimos_save_envelope at backfill time, 020) and by
--                  all P-live rows written by commitProvenance before this
--                  migration landed.
--
--   v2           — canonicalJson(body) || '\n' || nonce || '\n' ||
--                  String(ts_signed) || '\n' || String(memory_originated_at_unix)
--                  4-field form. Folds memory_originated_at into the sig
--                  preimage so the event's origin time is cryptographically
--                  bound rather than merely stored as mutable metadata.
--
--                  Written by:
--                    (a) the backfill ceremony (scripts/backfill-ledger-reviewer.mjs)
--                        for the 18,998 P-anchor re-attestation rows
--                    (b) commitProvenance going forward, for all new live
--                        provenance rows
--
-- The 43 P-real rows + 18 non-genesis envelope rows stay at v1 (their sigs
-- are historical attestations at original ts_signed; re-signing would
-- collapse the "signed at origin" / "notarized at T" boundary). The verify path branches on
-- this column: v1 → 3-field canonical form, v2 → 4-field.
--
-- content_hash itself is UNCHANGED (still sha256(canonicalJson(body)) via
-- RFC 8785 JCS per identity-chain.js#contentHash). The v2 change is in the
-- SIG canonical form + the mutation_hash formula (which gains a 5th field,
-- String(memory_originated_at_unix)). Cross-ledger reference on
-- content_hash is preserved — P-anchor, P-real, and ceremony rows for the
-- same memory_id all share the same content_hash bytes.
--
-- H10 (no legacy aliases): N/A — new column, no alias removed.
-- H8 (no parallel edits): solo migration, sequential after 026.
-- Idempotent: DO/IF NOT EXISTS guard on the column add.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name   = 'aimos_memory_provenance'
       AND column_name  = 'sig_form_version'
  ) THEN
    ALTER TABLE aimos_memory_provenance
      ADD COLUMN sig_form_version smallint NOT NULL DEFAULT 1;

    COMMENT ON COLUMN aimos_memory_provenance.sig_form_version IS
      'Sig canonical form version. v1=3-field (canonicalJson(body)||nonce||ts_signed) — historical P-real + pre-migration P-live. v2=4-field (canonicalJson(body)||nonce||ts_signed||String(memory_originated_at_unix)) — backfill ceremony rows + post-migration P-live. Verify path branches on this column.';
  END IF;
END
$body$;

-- Visibility: confirm the column + the row-class distribution post-migration.
SELECT 'sig_form_version_column' AS metric, column_name AS value
  FROM information_schema.columns
 WHERE table_name = 'aimos_memory_provenance' AND column_name = 'sig_form_version'
UNION ALL
SELECT 'v1_rows_default', count(*)::text
  FROM aimos_memory_provenance WHERE sig_form_version = 1;
