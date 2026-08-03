-- Retained credential events created before the signer-id body binding remain
-- byte-for-byte valid Ed25519 proofs. Classify them as proof schema v1 without
-- rewriting signed bytes; every post-cutover event is v2 by default.

ALTER TABLE public.aimos_credential_lifecycle
  ADD COLUMN IF NOT EXISTS proof_version smallint;

UPDATE public.aimos_credential_lifecycle
   SET proof_version = 1
 WHERE proof_version IS NULL;

ALTER TABLE public.aimos_credential_lifecycle
  ALTER COLUMN proof_version SET DEFAULT 2,
  ALTER COLUMN proof_version SET NOT NULL;

DO $credential_proof_version_constraint$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_credential_lifecycle_proof_version_check'
       AND conrelid = 'public.aimos_credential_lifecycle'::regclass
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT aimos_credential_lifecycle_proof_version_check CHECK (
        (proof_version = 1 AND body_json->>'signer_agent_id' IS NULL)
        OR
        (proof_version = 2 AND body_json->>'signer_agent_id' = agent_id)
      );
  END IF;
END
$credential_proof_version_constraint$;

COMMENT ON COLUMN public.aimos_credential_lifecycle.proof_version IS
  '1=retained original signed body without signer_agent_id; 2=current signed body with exact signer binding. Classification is outside signed bytes and never rewrites them.';
