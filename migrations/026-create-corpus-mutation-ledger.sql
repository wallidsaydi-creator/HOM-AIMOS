-- 026-create-corpus-mutation-ledger.sql
-- Aimos-2 / Paper 2 — append-only corpus mutation ledger.
--
-- Purpose: when the corpus itself must be mutated (e.g. re-classifying
-- pre-enforce shadow-mode canary leaks from scope=public to scope=quarantine),
-- the mutation must be a cert-enveloped, hash-chained, replay-protected
-- ledger row — NOT a raw SQL UPDATE. The "no mutation without cert envelope"
-- rule applies to the corpus as much as to any other state. A raw UPDATE
-- would defeat the mutation ledger on itself as an implementation: the
-- cleanup would be invisible to the audit plane, unsigned, unchained.
--
-- Each row is one signed corpus mutation event:
--   (action, target_memory_ids, signed by housekeeper, hash-chained
--    on action via prev_mutation_hash, replay-protected via nonce)
--
-- The latest row per action is the chain head. Mutating = appending a signed
-- row (NEVER UPDATE/DELETE — Aladdin). The housekeeper system identity
-- signs every row — NOT tied to any enrolled agent (survives rotation/
-- revocation). Same identity that signs governor REWEIGHT mutations and
-- governor config flag toggles.
--
-- The actual UPDATE on aimos_memories is applied in the SAME transaction
-- as the ledger INSERT — both commit atomically, or both roll back. The
-- ledger records WHAT was mutated; the UPDATE applies it. Together they
-- are the cert-enveloped corpus mutation.
--
-- Chain shape (mirrors 025 keyed on action instead of config_key):
--   . ONE GENESIS PER action — partial unique index.
--   . NO FORK-RACE on prev link — partial unique index.
--   . CONSISTENCY is_genesis ⟺ prev IS NULL (CHECK).
--   . NONCE UNIQUENESS — replay protection.
--   . mutation_hash = sha256(content_hash || prev_mutation_hash || nonce || ts)
--
-- H10 (no legacy aliases): N/A — new table.
-- H8 (no parallel edits): solo migration, sequential after 025.
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS +
--             DO/IF NOT EXISTS for the CHECK constraint.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'aimos_corpus_mutation_ledger'
  ) THEN
    CREATE TABLE aimos_corpus_mutation_ledger (
      corpus_mutation_id  bigserial    PRIMARY KEY,
      action              text         NOT NULL,
      target_memory_ids   uuid[]       NOT NULL,
      cert_fingerprint    text         NOT NULL,
      content_hash        bytea        NOT NULL,
      mutation_hash       bytea        NOT NULL,
      prev_mutation_hash  bytea,
      ts_signed           bigint       NOT NULL,
      nonce               text         NOT NULL,
      sig                 bytea        NOT NULL,
      is_genesis          boolean      NOT NULL DEFAULT false,
      body_json           jsonb,
      rows_affected       integer      NOT NULL DEFAULT 0,
      created_at          timestamptz  NOT NULL DEFAULT now()
    );
    COMMENT ON TABLE  aimos_corpus_mutation_ledger IS 'Append-only corpus mutation ledger. Records cert-enveloped mutations to the corpus (e.g. quarantine leaked canaries). Each row is one signed mutation event; the actual UPDATE on aimos_memories is applied in the same transaction. Signed by the housekeeper system identity (NOT an enrolled agent).';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.action              IS 'Mutation action identifier — e.g. quarantine_leaked_canaries. Validated against an allowlist in the commit path.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.target_memory_ids   IS 'Array of aimos_memories.id (uuid) rows targeted by this mutation. The commit path verifies these rows exist + are active before signing.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.cert_fingerprint    IS 'sha256(cert_string) — which housekeeper cert signed this mutation.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.content_hash        IS 'sha256(canonicalJson(body)) — same form as aimos_save_envelope and aimos_governor_config content_hash.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.mutation_hash       IS 'sha256(content_hash || prev_mutation_hash || nonce || String(ts_signed)) (genesis drops prev). Chain link.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.prev_mutation_hash  IS 'Previous row mutation_hash for this action. NULL for the genesis row.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.ts_signed          IS 'Unix seconds (integer) when the mutation was signed.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.nonce              IS 'Random base64url nonce (replay protection). Unique across the table.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.sig                IS '64-byte raw Ed25519 over canonicalJson(body) || "\n" || nonce || "\n" || String(ts_signed).';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.is_genesis         IS 'TRUE for the first row in an action chain. CHECK constraint locks is_genesis ⟺ prev_mutation_hash IS NULL.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.body_json           IS 'Full signed body for auditability — action, target_memory_ids, reason, operator, prev_rows_affected.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.rows_affected       IS 'Count of aimos_memories rows actually UPDATEd in the same transaction. Must equal target_memory_ids length if the commit succeeded.';
    COMMENT ON COLUMN aimos_corpus_mutation_ledger.created_at          IS 'When the row was inserted (DB time).';
  END IF;
END
$body$;

-- One genesis per action
CREATE UNIQUE INDEX IF NOT EXISTS aimos_corpus_mutation_ledger_one_genesis
  ON aimos_corpus_mutation_ledger (action)
  WHERE prev_mutation_hash IS NULL;

-- No fork-race on prev link
CREATE UNIQUE INDEX IF NOT EXISTS aimos_corpus_mutation_ledger_next_unique
  ON aimos_corpus_mutation_ledger (action, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

-- Nonce uniqueness (replay protection)
CREATE UNIQUE INDEX IF NOT EXISTS aimos_corpus_mutation_ledger_nonce_unique
  ON aimos_corpus_mutation_ledger (nonce);

-- Latest-row lookup per action
CREATE INDEX IF NOT EXISTS aimos_corpus_mutation_ledger_action_created
  ON aimos_corpus_mutation_ledger (action, created_at DESC, corpus_mutation_id DESC);

-- Consistency: is_genesis ⟺ prev IS NULL (mirrors 025)
DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'aimos_corpus_mutation_ledger_genesis_consistent'
      AND conrelid = 'aimos_corpus_mutation_ledger'::regclass
  ) THEN
    ALTER TABLE aimos_corpus_mutation_ledger
      ADD CONSTRAINT aimos_corpus_mutation_ledger_genesis_consistent
      CHECK (
        (is_genesis = true  AND prev_mutation_hash IS NULL)
     OR (is_genesis = false AND prev_mutation_hash IS NOT NULL)
      );
  END IF;
END
$body$;

-- Verification queries (run after applying):
-- SELECT action, is_genesis, ts_signed, rows_affected
--   FROM aimos_corpus_mutation_ledger ORDER BY action, created_at;
--   -> 0 rows initially. Begins populating on the first quarantine-leaked-canaries.js
--      invocation.
-- SELECT 'double_genesis', count(*) FROM (
--   SELECT action FROM aimos_corpus_mutation_ledger
--    WHERE prev_mutation_hash IS NULL GROUP BY action HAVING count(*) > 1
-- ) d;
--   -> 0 (one-genesis invariant holds).