-- 025-create-governor-config-ledger.sql
-- Aimos-2 / Paper 2 — append-only governor config ledger.
--
-- Replaces `process.env.X === 'ON'` reads for governor flags with a
-- signed, hash-chained, replay-protected toggle record. The HOM
-- architecture is "Three Orthogonal Guarantees" (existence/health/
-- validity) built on a crypto ledger + cert envelope; env vars are
-- silently editable, unsigned, unchained, and invisible to the ledger —
-- exactly the drift the architecture is designed to prevent. Governor
-- toggles must live in the same audit plane as the mutations they gate.
--
-- Each row is one toggle event:
--   (config_key, enabled, signed by housekeeper, hash-chained on
--    config_key via prev_mutation_hash, replay-protected via nonce)
--
-- The latest row per config_key is the live flag state. Toggling =
-- appending a signed row (NEVER UPDATE/DELETE — Aladdin). The
-- `housekeeper` system identity (already enrolled, master-signed,
-- privkey at ~/.aimos/agents/housekeeper.key) signs every row.
--
-- Chain shape (mirrors migration 018 + 021, keyed on config_key instead
-- of memory_id):
--   . ONE GENESIS PER config_key — partial unique index locks the
--     invariant; a buggy toggle path or concurrent-writer race cannot
--     create a second genesis row for a key that already has one.
--   . NO FORK-RACE — within a config_key, each prev_mutation_hash can
--     be claimed by at most one row. Two concurrent toggles racing the
--     same prev link convert to a 23505 the CLI retries.
--   . CONSISTENCY — is_genesis ⟺ prev_mutation_hash IS NULL.
--   . NONCE UNIQUENESS — replay protection, mirrors
--     aimos_save_envelope_nonce_unique (migration 016).
--
-- H10 (no legacy aliases): N/A — new table.
-- H8 (no parallel edits): solo migration, sequential after 024.
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS +
--             DO/IF NOT EXISTS for the CHECK constraint.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'aimos_governor_config'
  ) THEN
    CREATE TABLE aimos_governor_config (
      config_id           bigserial    PRIMARY KEY,
      config_key          text         NOT NULL,
      enabled             boolean      NOT NULL,
      cert_fingerprint    text         NOT NULL,
      content_hash        bytea        NOT NULL,
      mutation_hash       bytea        NOT NULL,
      prev_mutation_hash  bytea,
      ts_signed           bigint       NOT NULL,
      nonce               text         NOT NULL,
      sig                 bytea        NOT NULL,
      is_genesis          boolean      NOT NULL DEFAULT false,
      body_json           jsonb,
      created_at          timestamptz  NOT NULL DEFAULT now()
    );
    COMMENT ON TABLE  aimos_governor_config IS 'Append-only governor config ledger. Replaces process.env for governor flag toggles. Each row is one signed toggle event; the latest row per config_key is the live flag state. Signed by the housekeeper system identity (NOT an enrolled agent).';
    COMMENT ON COLUMN aimos_governor_config.config_key         IS 'Governor flag identifier — e.g. COHEN_GROSSBERG_GOVERNOR, OJA_NORMALIZATION_GOVERNOR. Validated against an allowlist in the commit path.';
    COMMENT ON COLUMN aimos_governor_config.enabled             IS 'The toggle payload. TRUE = governor fires; FALSE = governor shadow-first. The latest row per config_key is the live state.';
    COMMENT ON COLUMN aimos_governor_config.cert_fingerprint   IS 'sha256(cert_string) — which housekeeper cert signed this toggle (survives cert rotation; audit matches the cert valid at ts_signed).';
    COMMENT ON COLUMN aimos_governor_config.content_hash       IS 'sha256(canonicalJson(body)) — same form as aimos_save_envelope and aimos_memory_provenance content_hash.';
    COMMENT ON COLUMN aimos_governor_config.mutation_hash      IS 'sha256(content_hash || prev_mutation_hash || nonce || String(ts_signed)) (genesis drops prev). Chain link.';
    COMMENT ON COLUMN aimos_governor_config.prev_mutation_hash IS 'Previous row mutation_hash for this config_key. NULL for the genesis row.';
    COMMENT ON COLUMN aimos_governor_config.ts_signed         IS 'Unix seconds (integer) when the toggle was signed. Matches the signPayload ts convention.';
    COMMENT ON COLUMN aimos_governor_config.nonce              IS 'Random base64url nonce (replay protection). Unique across the table.';
    COMMENT ON COLUMN aimos_governor_config.sig               IS '64-byte raw Ed25519 over canonicalJson(body) || "\n" || nonce || "\n" || String(ts_signed).';
    COMMENT ON COLUMN aimos_governor_config.is_genesis        IS 'TRUE for the first row in a config_key chain. CHECK constraint locks is_genesis ⟺ prev_mutation_hash IS NULL.';
    COMMENT ON COLUMN aimos_governor_config.body_json         IS 'Full signed body for auditability — reason, operator, prev_state. NULL only if the commit path was unable to capture it (recoverable from sig + content_hash).';
    COMMENT ON COLUMN aimos_governor_config.created_at        IS 'When the row was inserted (DB time, distinct from ts_signed which is the signer time).';
  END IF;
END
$body$;

-- One genesis per config_key
CREATE UNIQUE INDEX IF NOT EXISTS aimos_governor_config_one_genesis
  ON aimos_governor_config (config_key)
  WHERE prev_mutation_hash IS NULL;

-- No fork-race on prev link
CREATE UNIQUE INDEX IF NOT EXISTS aimos_governor_config_next_unique
  ON aimos_governor_config (config_key, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

-- Nonce uniqueness (replay protection, mirrors migration 016)
CREATE UNIQUE INDEX IF NOT EXISTS aimos_governor_config_nonce_unique
  ON aimos_governor_config (nonce);

-- Latest-row lookup (the readFlag reader ORDER BY created_at DESC, config_id DESC)
CREATE INDEX IF NOT EXISTS aimos_governor_config_key_created
  ON aimos_governor_config (config_key, created_at DESC, config_id DESC);

-- Consistency: is_genesis ⟺ prev IS NULL (mirrors 021:43-58)
DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'aimos_governor_config_genesis_consistent'
      AND conrelid = 'aimos_governor_config'::regclass
  ) THEN
    ALTER TABLE aimos_governor_config
      ADD CONSTRAINT aimos_governor_config_genesis_consistent
      CHECK (
        (is_genesis = true  AND prev_mutation_hash IS NULL)
     OR (is_genesis = false AND prev_mutation_hash IS NOT NULL)
      );
  END IF;
END
$body$;

-- Verification queries (run after applying):
-- SELECT config_key, enabled, is_genesis, ts_signed
--   FROM aimos_governor_config ORDER BY config_key, created_at;
--   -> 0 rows initially. Begins populating on the first toggle-governor-flag.js
--      invocation.
-- SELECT 'double_genesis', count(*) FROM (
--   SELECT config_key FROM aimos_governor_config
--    WHERE prev_mutation_hash IS NULL GROUP BY config_key HAVING count(*) > 1
-- ) d;
--   -> 0 (one-genesis invariant holds).