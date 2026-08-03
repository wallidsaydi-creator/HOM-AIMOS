








































DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'aimos_system_config'
  ) THEN
    CREATE TABLE aimos_system_config (
      config_id           bigserial    PRIMARY KEY,
      config_key          text         NOT NULL,
      value_text          text         NOT NULL,
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

    COMMENT ON COLUMN aimos_system_config.config_key         IS 'System config identifier — e.g. OPERATOR_AGENT_ID, EXECUTIVE_AGENT_ALIASES. Validated against an allowlist in the commit path.';
    COMMENT ON COLUMN aimos_system_config.value_text          IS 'The delegation payload (string-valued). For OPERATOR_AGENT_ID, the designated agent_id. The latest row per config_key is the live state.';
    COMMENT ON COLUMN aimos_system_config.cert_fingerprint   IS 'sha256(cert_string) — which master cert signed this delegation. The master cert is stored in aimos_master_identity; this fingerprint survives cert rotation.';
    COMMENT ON COLUMN aimos_system_config.content_hash       IS 'sha256(canonicalJson(body)) — same form as aimos_save_envelope, aimos_memory_provenance, aimos_governor_config content_hash.';
    COMMENT ON COLUMN aimos_system_config.mutation_hash      IS 'sha256(content_hash || prev_mutation_hash || nonce || String(ts_signed)) (genesis drops prev). Chain link.';
    COMMENT ON COLUMN aimos_system_config.prev_mutation_hash IS 'Previous row mutation_hash for this config_key. NULL for the genesis row.';
    COMMENT ON COLUMN aimos_system_config.ts_signed         IS 'Unix seconds (integer) when the delegation was signed. Matches the signPayload ts convention.';
    COMMENT ON COLUMN aimos_system_config.nonce              IS 'Random base64url nonce (replay protection). Unique across the table.';

    COMMENT ON COLUMN aimos_system_config.is_genesis        IS 'TRUE for the first row in a config_key chain. CHECK constraint locks is_genesis ⟺ prev_mutation_hash IS NULL.';
    COMMENT ON COLUMN aimos_system_config.body_json         IS 'Full signed body for auditability — reason, operator, prev_value. NULL only if the commit path was unable to capture it.';
    COMMENT ON COLUMN aimos_system_config.created_at        IS 'When the row was inserted (DB time, distinct from ts_signed which is the signer time).';
  END IF;
END
$body$;

-- One genesis per config_key
CREATE UNIQUE INDEX IF NOT EXISTS aimos_system_config_one_genesis
  ON aimos_system_config (config_key)
  WHERE prev_mutation_hash IS NULL;

-- No fork-race on prev link
CREATE UNIQUE INDEX IF NOT EXISTS aimos_system_config_next_unique
  ON aimos_system_config (config_key, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

-- Nonce uniqueness (replay protection, mirrors migration 016 + 025)
CREATE UNIQUE INDEX IF NOT EXISTS aimos_system_config_nonce_unique
  ON aimos_system_config (nonce);

-- Latest-row lookup (the readConfigString reader ORDER BY created_at DESC, config_id DESC)
CREATE INDEX IF NOT EXISTS aimos_system_config_key_created
  ON aimos_system_config (config_key, created_at DESC, config_id DESC);

-- Consistency: is_genesis ⟺ prev IS NULL (mirrors 021:43-58 + 025:95-110)
DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'aimos_system_config_genesis_consistent'
      AND conrelid = 'aimos_system_config'::regclass
  ) THEN
    ALTER TABLE aimos_system_config
      ADD CONSTRAINT aimos_system_config_genesis_consistent
      CHECK (
        (is_genesis = true  AND prev_mutation_hash IS NULL)
     OR (is_genesis = false AND prev_mutation_hash IS NOT NULL)
      );
  END IF;
END
$body$;

-- Verification queries (run after applying):
-- SELECT config_key, value_text, is_genesis, ts_signed
--   FROM aimos_system_config ORDER BY config_key, created_at;
--   -> 0 rows initially. Begins populating on the first set-system-config.js
--      invocation.
-- SELECT 'double_genesis', count(*) FROM (
--   SELECT config_key FROM aimos_system_config
--    WHERE prev_mutation_hash IS NULL GROUP BY config_key HAVING count(*) > 1
-- ) d;
--   -> 0 (one-genesis invariant holds).