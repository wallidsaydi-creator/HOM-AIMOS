-- In-place cryptographic event ledger. Historical rows remain byte-for-byte
-- unchanged with ledger_version NULL (legacy_unattested). Every runtime row
-- appended after this migration carries a complete signed proof.

ALTER TABLE public.aimos_events
  ADD COLUMN IF NOT EXISTS proof_required boolean,
  ADD COLUMN IF NOT EXISTS ledger_version smallint,
  ADD COLUMN IF NOT EXISTS ledger_seq bigint,
  ADD COLUMN IF NOT EXISTS signer_agent_id text,
  ADD COLUMN IF NOT EXISTS signer_valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS cert_fingerprint text,
  ADD COLUMN IF NOT EXISTS identity_tier text,
  ADD COLUMN IF NOT EXISTS authority_kind text,
  ADD COLUMN IF NOT EXISTS signed_body jsonb,
  ADD COLUMN IF NOT EXISTS content_hash bytea,
  ADD COLUMN IF NOT EXISTS mutation_hash bytea,
  ADD COLUMN IF NOT EXISTS prev_mutation_hash bytea,
  ADD COLUMN IF NOT EXISTS ts_signed bigint,
  ADD COLUMN IF NOT EXISTS nonce text,
  ADD COLUMN IF NOT EXISTS sig bytea;

-- Rows that existed before this migration retain NULL and are explicitly
-- legacy/unattested. Every later insert gets TRUE by default. The restricted
-- runtime role is deliberately not granted INSERT on this column, so it cannot
-- manufacture a new legacy row by omitting the proof fields.
ALTER TABLE public.aimos_events
  ALTER COLUMN proof_required SET DEFAULT true;

DO $event_proof_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_events_cryptographic_proof_complete'
       AND conrelid = 'public.aimos_events'::regclass
  ) THEN
    ALTER TABLE public.aimos_events
      ADD CONSTRAINT aimos_events_cryptographic_proof_complete CHECK (
        (proof_required IS NULL
          AND ledger_version IS NULL
          AND ledger_seq IS NULL
          AND signer_agent_id IS NULL
          AND signer_valid_from IS NULL
          AND cert_fingerprint IS NULL
          AND identity_tier IS NULL
          AND authority_kind IS NULL
          AND signed_body IS NULL
          AND content_hash IS NULL
          AND mutation_hash IS NULL
          AND prev_mutation_hash IS NULL
          AND ts_signed IS NULL
          AND nonce IS NULL
          AND sig IS NULL)
        OR
        (proof_required IS TRUE
          AND ledger_version = 1
          AND ledger_seq > 0
          AND signer_agent_id IS NOT NULL
          AND signer_valid_from IS NOT NULL
          AND cert_fingerprint ~ '^[0-9a-f]{64}$'
          AND identity_tier IN ('T1', 'T1_SYSTEM_SELF')
          AND authority_kind IN ('housekeeper_autonomous', 'housekeeper_observation_of_verified_request')
          AND signed_body IS NOT NULL
          AND octet_length(content_hash) = 32
          AND octet_length(mutation_hash) = 32
          AND octet_length(prev_mutation_hash) = 32
          AND ts_signed > 0
          AND length(nonce) > 0
          AND octet_length(sig) = 64)
      );
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_events_signer_epoch_fkey'
       AND conrelid = 'public.aimos_events'::regclass
  ) THEN
    ALTER TABLE public.aimos_events
      ADD CONSTRAINT aimos_events_signer_epoch_fkey
      FOREIGN KEY (signer_agent_id, signer_valid_from)
      REFERENCES public.agent_identity(agent_id, valid_from);
  END IF;
END
$event_proof_constraints$;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_events_ledger_sequence_unique
  ON public.aimos_events (company_id, signer_agent_id, signer_valid_from, ledger_seq)
  WHERE ledger_version = 1;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_events_ledger_successor_unique
  ON public.aimos_events (company_id, signer_agent_id, signer_valid_from, prev_mutation_hash)
  WHERE ledger_version = 1;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_events_ledger_mutation_unique
  ON public.aimos_events (mutation_hash)
  WHERE ledger_version = 1;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_events_ledger_nonce_unique
  ON public.aimos_events (signer_agent_id, signer_valid_from, nonce)
  WHERE ledger_version = 1;

DROP RULE IF EXISTS block_event_delete ON public.aimos_events;

DO $event_ledger_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_events FROM agent_runtime;
    GRANT SELECT ON public.aimos_events TO agent_runtime;
    GRANT INSERT (
      id, ts, company_id, agent_id, operation, key, metadata, parent_event_id,
      ledger_version, ledger_seq, signer_agent_id, signer_valid_from,
      cert_fingerprint, identity_tier, authority_kind, signed_body,
      content_hash, mutation_hash, prev_mutation_hash, ts_signed, nonce, sig
    ) ON public.aimos_events TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_events FROM aimos_app;
  END IF;
END
$event_ledger_acl$;

COMMENT ON COLUMN public.aimos_events.ledger_version IS
  'NULL=retained historical unattested row; 1=housekeeper-signed append-only event proof.';

COMMENT ON COLUMN public.aimos_events.proof_required IS
  'NULL only for rows retained from before migration 051; TRUE by default for every later insert and unavailable to agent_runtime INSERT.';
