-- 046-credential-epoch-and-append-only-acl.sql
-- Bind every credential lifecycle event to the signing identity epoch and
-- certificate fingerprint, then close the remaining legacy-role UPDATE path.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE public.aimos_credential_lifecycle
  ADD COLUMN IF NOT EXISTS agent_valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS cert_fingerprint text;

WITH matched AS (
  SELECT DISTINCT ON (c.provenance_id)
         c.provenance_id,
         a.valid_from,
         a.cert
    FROM public.aimos_credential_lifecycle c
    JOIN public.agent_identity a
      ON a.agent_id = c.agent_id
     AND a.valid_from <= to_timestamp(c.ts_signed)
   WHERE c.agent_valid_from IS NULL
      OR c.cert_fingerprint IS NULL
   ORDER BY c.provenance_id, a.valid_from DESC
)
UPDATE public.aimos_credential_lifecycle c
   SET agent_valid_from = matched.valid_from,
       cert_fingerprint = encode(digest(matched.cert, 'sha256'), 'hex')
  FROM matched
 WHERE c.provenance_id = matched.provenance_id;

DO $credential_epoch_gate$
DECLARE
  orphan_count bigint;
BEGIN
  SELECT count(*) INTO orphan_count
    FROM public.aimos_credential_lifecycle
   WHERE agent_valid_from IS NULL
      OR cert_fingerprint IS NULL
      OR cert_fingerprint !~ '^[0-9a-f]{64}$';
  IF orphan_count > 0 THEN
    RAISE EXCEPTION
      '046 ABORT: % credential lifecycle rows cannot be bound to a signing identity epoch/certificate',
      orphan_count;
  END IF;
END
$credential_epoch_gate$;

ALTER TABLE public.aimos_credential_lifecycle
  ALTER COLUMN agent_valid_from SET NOT NULL,
  ALTER COLUMN cert_fingerprint SET NOT NULL;

DO $credential_epoch_fk$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_credential_lifecycle'::regclass
       AND conname = 'fk_credential_lifecycle_agent_epoch'
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT fk_credential_lifecycle_agent_epoch
      FOREIGN KEY (agent_id, agent_valid_from)
      REFERENCES public.agent_identity(agent_id, valid_from);
  END IF;
END
$credential_epoch_fk$;

DO $append_only_roles$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_memories FROM agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_memory_provenance FROM agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_save_envelope FROM agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_credential_lifecycle FROM agent_runtime;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_memories FROM aimos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_memory_provenance FROM aimos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_save_envelope FROM aimos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_credential_lifecycle FROM aimos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.supersession_events FROM aimos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.memory_cross_refs FROM aimos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.entity_memory_edges FROM aimos_app;
  END IF;
END
$append_only_roles$;

COMMENT ON COLUMN public.aimos_credential_lifecycle.agent_valid_from IS
  'Signing identity epoch; composite-FK bound to agent_identity.';
COMMENT ON COLUMN public.aimos_credential_lifecycle.cert_fingerprint IS
  'Lowercase SHA-256 hex of the certificate envelope used for this signed lifecycle event.';
