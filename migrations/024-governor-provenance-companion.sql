-- 024-governor-provenance-companion.sql
-- Aimos-2 / Paper 2 fallback path — companion table for governor body
-- persistence until H8-coordinated commitProvenance extension lands.
--
-- The main ledger `aimos_memory_provenance` is INSERT-only (Aladdin
-- compliant — no UPDATE/DELETE path). Migration 022 added `event_type`
-- and `body_json` columns directly to the ledger, but populating those
-- columns in-transaction requires extending `commitProvenance` in
-- `services/security/memory-provenance.js` — and that file is the security
-- agent's territory (H8: no parallel edits across overlapping files).
--
-- Until the H8-coordinated extension lands, the governor writes
-- event_type + body_json to this COMPANION table in a separate transaction
-- AFTER commitProvenance succeeds. The audit joins the companion table to
-- the main ledger on (memory_id, mutation_hash) to recover the governor
-- mutation body for signature verification post-hoc.
--
-- Why a companion table (not an UPDATE on the main ledger)?
--   . The main ledger is INSERT-only by design (Aladdin). An UPDATE on the
--     new columns would violate the append-only invariant.
--   . The companion table is a SEPARATE table — the ledger stays clean.
--   . When the H8 extension lands, commitProvenance populates the columns
--     in-transaction and the companion table becomes redundant. A future
--     migration can drop it (H10 schedule: N = 024, N+1 = drop in 025+).
--
-- H8 (no parallel edits): solo migration; does NOT touch
--     memory-provenance.js. The companion writer lives in
--     services/governance/governor-provenance.js (my file).
-- H10 (no legacy aliases): N/A — new table. When the H8 extension lands
--     and the companion is no longer populated, a future migration drops
--     it (with a backfill of event_type/body_json from the companion into
--     the main ledger for any rows written in fallback mode).
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'aimos_memory_provenance_governor_body'
  ) THEN
    CREATE TABLE aimos_memory_provenance_governor_body (
      id              bigserial   PRIMARY KEY,
      memory_id       uuid        NOT NULL,
      mutation_hash   bytea       NOT NULL,
      event_type      text        NOT NULL,
      body_json       jsonb       NOT NULL,
      written_at      timestamptz NOT NULL DEFAULT now()
    );
    COMMENT ON TABLE  aimos_memory_provenance_governor_body IS
      'Companion to aimos_memory_provenance for governor mutation bodies. Fallback path until H8-coordinated commitProvenance extension populates event_type + body_json on the main ledger in-transaction.';
    COMMENT ON COLUMN aimos_memory_provenance_governor_body.mutation_hash IS
      'FK reference (logical, not enforced) to aimos_memory_provenance.mutation_hash. The audit joins on (memory_id, mutation_hash).';
    COMMENT ON COLUMN aimos_memory_provenance_governor_body.event_type IS
      'REWEIGHT for governor mutations. Mirrors body_json->>''event_type'' (signature-covered).';
    COMMENT ON COLUMN aimos_memory_provenance_governor_body.body_json IS
      'Full governor mutation body. Used for signature verification post-hoc (the main ledger only persists content_hash).';
  END IF;
END
$body$;

CREATE INDEX IF NOT EXISTS idx_governor_body_memory_mutation
  ON aimos_memory_provenance_governor_body (memory_id, mutation_hash);

CREATE INDEX IF NOT EXISTS idx_governor_body_event_type
  ON aimos_memory_provenance_governor_body (event_type);

-- Verification query (run after applying):
-- SELECT event_type, count(*) FROM aimos_memory_provenance_governor_body GROUP BY event_type;
--   -> 0 initially. Populated on the first governor mutation after restart.

-- Drift audit (fallback mode): the companion row's event_type must match
-- the body_json->>'event_type' (signature-covered). Run after the governor
-- has written rows:
--   SELECT count(*) AS drift
--     FROM aimos_memory_provenance_governor_body
--    WHERE event_type != body_json->>'event_type';
--   -> Expected: 0 (drift-free).