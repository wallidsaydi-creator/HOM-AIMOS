-- Make every new valence observation cert-bound and restrict the table to the
-- native housekeeper transaction. Historical rows remain retained and are
-- explicitly distinguishable by proof_required IS NULL.

ALTER TABLE public.memory_valence_ledger
  ADD COLUMN IF NOT EXISTS proof_required boolean,
  ADD COLUMN IF NOT EXISTS signer_agent_id text,
  ADD COLUMN IF NOT EXISTS signer_valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS cert_fingerprint text,
  ADD COLUMN IF NOT EXISTS identity_tier text;

ALTER TABLE public.memory_valence_ledger
  ALTER COLUMN proof_required SET DEFAULT true;

DO $valence_constraints$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'memory_valence_ledger_memory_id_fkey'
       AND conrelid = 'public.memory_valence_ledger'::regclass
  ) THEN
    ALTER TABLE public.memory_valence_ledger
      DROP CONSTRAINT memory_valence_ledger_memory_id_fkey;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'memory_valence_ledger_memory_id_retained_fkey'
       AND conrelid = 'public.memory_valence_ledger'::regclass
  ) THEN
    ALTER TABLE public.memory_valence_ledger
      ADD CONSTRAINT memory_valence_ledger_memory_id_retained_fkey
      FOREIGN KEY (memory_id) REFERENCES public.aimos_memories(id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'memory_valence_ledger_signer_epoch_fkey'
       AND conrelid = 'public.memory_valence_ledger'::regclass
  ) THEN
    ALTER TABLE public.memory_valence_ledger
      ADD CONSTRAINT memory_valence_ledger_signer_epoch_fkey
      FOREIGN KEY (signer_agent_id, signer_valid_from)
      REFERENCES public.agent_identity(agent_id, valid_from);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'memory_valence_ledger_proof_complete'
       AND conrelid = 'public.memory_valence_ledger'::regclass
  ) THEN
    ALTER TABLE public.memory_valence_ledger
      ADD CONSTRAINT memory_valence_ledger_proof_complete CHECK (
        (proof_required IS NULL
          AND signer_agent_id IS NULL
          AND signer_valid_from IS NULL
          AND cert_fingerprint IS NULL
          AND identity_tier IS NULL)
        OR
        (proof_required IS TRUE
          AND body_json IS NOT NULL
          AND octet_length(content_hash) = 32
          AND octet_length(row_hash) = 32
          AND ts_signed > 0
          AND length(nonce) > 0
          AND octet_length(sig) = 64
          AND signer_agent_id = 'housekeeper'
          AND signer_valid_from IS NOT NULL
          AND cert_fingerprint ~ '^[0-9a-f]{64}$'
          AND identity_tier IN ('T1', 'T1_SYSTEM_SELF'))
      ) NOT VALID;
  END IF;
END
$valence_constraints$;

DO $valence_acl$
BEGIN
  REVOKE ALL ON public.memory_valence_ledger FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.memory_valence_ledger FROM agent_runtime;
    GRANT SELECT ON public.memory_valence_ledger TO agent_runtime;
    GRANT INSERT (
      memory_id, company_id, reward_sign, context_hash, body_json,
      content_hash, prev_hash, row_hash, ts_signed, nonce, sig,
      signer_agent_id, signer_valid_from, cert_fingerprint, identity_tier
    ) ON public.memory_valence_ledger TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.memory_valence_ledger FROM aimos_app;
  END IF;
END
$valence_acl$;

COMMENT ON COLUMN public.memory_valence_ledger.proof_required IS
  'NULL only for retained pre-062 rows; TRUE by default for every new cert-bound observation.';

COMMENT ON TABLE public.memory_valence_ledger IS
  'Append-only, cert-bound outcome evidence. All retained signs contribute age-neutrally to bidirectional cognitive weight mutation.';
