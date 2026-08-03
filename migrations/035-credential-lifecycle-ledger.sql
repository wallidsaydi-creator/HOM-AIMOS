














































CREATE TABLE IF NOT EXISTS aimos_credential_lifecycle (
  provenance_id        uuid         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  service_name         text         NOT NULL,
  slot_id              text         NOT NULL,
  event_type           text         NOT NULL CHECK (event_type IN ('STORE','ROTATE','REVOKE','VERIFY')),
  agent_id             text         NOT NULL,
  identity_tier        text         NOT NULL,
  body_json            jsonb        NOT NULL,
  content_hash         bytea        NOT NULL,
  mutation_hash        bytea        NOT NULL,
  prev_mutation_hash   bytea,
  ts_signed           bigint       NOT NULL,
  nonce                text         NOT NULL,
  sig                  bytea        NOT NULL,
  is_genesis           boolean      NOT NULL DEFAULT false,
  created_at           timestamptz  NOT NULL DEFAULT now()
);




COMMENT ON COLUMN aimos_credential_lifecycle.service_name IS
  'Logical service name (e.g. brave, stripe, x_bearer, supabase_service_role). Stable across rotations.';

COMMENT ON COLUMN aimos_credential_lifecycle.slot_id IS
  'Keychain slot identifier (e.g. com.hom.credentials.brave). Stable across rotations — a rotation writes a new row with the same slot_id but a new credential_hash. The chain is keyed on slot_id.';

COMMENT ON COLUMN aimos_credential_lifecycle.event_type IS
  'STORE = new credential placed in keychain slot. ROTATE = old credential superseded by new (old row gets revoked_at via supersession, new STORE row with rotated_from = prev provenance_id). REVOKE = credential marked invalid without replacement (leak response). VERIFY = agent confirmed credential still works (API call succeeded or explicit health-check).';

COMMENT ON COLUMN aimos_credential_lifecycle.body_json IS
  'Signed body. Contains: event_type, service, slot_id, credential_hash (sha256 hex of plaintext), valid_from, valid_until (null for STORE, set on REVOKE), rotated_from (null for STORE, prev provenance_id for ROTATE), reason. The plaintext credential is NEVER in this column.';

-- Chain-link integrity (mirrors 021-provenance-chain-integrity.sql):
--   one-genesis per slot_id  →  UNIQUE INDEX on (slot_id) WHERE is_genesis
--   next-unique per (slot_id, prev_mutation_hash)  →  prevents fork races
--   per-(slot_id, mutation_hash) uniqueness  →  prevents duplicate rows

CREATE UNIQUE INDEX IF NOT EXISTS aimos_credential_lifecycle_one_genesis
  ON aimos_credential_lifecycle (slot_id)
  WHERE is_genesis = true;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_credential_lifecycle_next_unique
  ON aimos_credential_lifecycle (slot_id, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_credential_lifecycle_slot_mutation_unique'
  ) THEN
    ALTER TABLE aimos_credential_lifecycle
      ADD CONSTRAINT aimos_credential_lifecycle_slot_mutation_unique
      UNIQUE (slot_id, mutation_hash);
  END IF;
END
$body$;

-- Auditor query indexes: rotate-by-slot, verify-by-slot, leak-revocation-ordering.
CREATE INDEX IF NOT EXISTS aimos_credential_lifecycle_slot_ts_idx
  ON aimos_credential_lifecycle (slot_id, ts_signed DESC);

CREATE INDEX IF NOT EXISTS aimos_credential_lifecycle_service_event_idx
  ON aimos_credential_lifecycle (service_name, event_type, ts_signed DESC);

-- Visibility: confirm the table exists post-migration.
SELECT 'aimos_credential_lifecycle_table' AS metric,
       count(*)::text AS value
  FROM information_schema.tables
 WHERE table_name = 'aimos_credential_lifecycle'
UNION ALL
SELECT 'rows_pre_backfill', count(*)::text
  FROM aimos_credential_lifecycle;
