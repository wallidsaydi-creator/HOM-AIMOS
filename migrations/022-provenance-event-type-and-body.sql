-- 022-provenance-event-type-and-body.sql
-- Aimos-2 / Paper 2 extension (per HOM-Security-Wiring-Plan-MASTER §11.1):
-- "the event_type (SAVE|CONSOLIDATE|REWEIGHT) extension and meta-ledger is
--  Aimos-2 / Paper 2 territory (plasticity ON, mutation ledger). Keep it
--  out of Aimos-1."
--
-- Adds two columns to aimos_memory_provenance so Paper 1 (SAVE) and
-- Paper 2 (REWEIGHT) claims are DB-separable at audit scale without parsing
-- every body, and so governor mutation bodies — which are NOT reconstructable
-- from aimos_memories (a REWEIGHT is a mutation record, not memory content)
-- — are persisted for signature verification post-hoc.
--
-- (a) event_type text NOT NULL DEFAULT 'SAVE'
--     Indexed. Discriminates SAVE (Paper 1, existing /save path) from
--     REWEIGHT (Paper 2, governor mutations). The body-level event_type
--     is Ed25519 signature-covered (tamper-evident); this column is a
--     denormalized copy persisted at INSERT time for DB-level filtering.
--     The commitProvenance extension persists both in the same INSERT
--     transaction — no drift (audit: event_type_column ==
--     body_json->>'event_type').
--
-- (b) body_json jsonb
--     Persists the full provenance body. Existing rows (backfilled P-anchor
--     and P-real) get body_json=NULL — their bodies are reconstructable from
--     aimos_memories. New rows from the governor path get body_json
--     populated. Required for REWEIGHT rows because the governor mutation
--     body is not reconstructable from any other table.
--
-- H10 (no legacy aliases): N/A — additive columns only, no columns removed.
-- H8 (no parallel edits): solo migration. The commitProvenance extension
--     that populates these columns is H8-coordinated with the security agent
--     separately (memory-provenance.js is the security agent's file).
-- Idempotent: ADD COLUMN IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.

ALTER TABLE aimos_memory_provenance
  ADD COLUMN IF NOT EXISTS event_type text NOT NULL DEFAULT 'SAVE';

ALTER TABLE aimos_memory_provenance
  ADD COLUMN IF NOT EXISTS body_json jsonb;

COMMENT ON COLUMN aimos_memory_provenance.event_type IS
  'Discriminator: SAVE (Paper 1, /save path) vs REWEIGHT (Paper 2, governor mutation). Denormalized copy of body.event_type (signature-covered). Indexed for DB-level audit.';
COMMENT ON COLUMN aimos_memory_provenance.body_json IS
  'Full provenance body. NULL for backfilled rows (reconstructable from aimos_memories). Populated for governor mutations (REWEIGHT bodies not reconstructable elsewhere).';

CREATE INDEX IF NOT EXISTS aimos_memory_provenance_event_type_idx
  ON aimos_memory_provenance (event_type);

-- Partial index for Paper 2 audit: only REWEIGHT rows, by memory + time.
CREATE INDEX IF NOT EXISTS aimos_memory_provenance_reweight_memory_time_idx
  ON aimos_memory_provenance (memory_id, created_at)
  WHERE event_type = 'REWEIGHT';

-- Verification queries (run after applying):
-- SELECT event_type, count(*) FROM aimos_memory_provenance GROUP BY event_type;
--   -> Existing rows: all 'SAVE' (default). Governor rows (future): 'REWEIGHT'.
-- SELECT count(*) FROM aimos_memory_provenance WHERE body_json IS NULL;
--   -> Existing rows: all NULL (backfilled). Governor rows: populated.