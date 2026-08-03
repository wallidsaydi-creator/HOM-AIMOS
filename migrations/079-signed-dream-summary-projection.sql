-- Dream hierarchy rows are retained derived cognition. Every post-cutover row
-- binds its complete canonical snapshot hash to a housekeeper-signed event in
-- the same restricted transaction. Historical rows remain byte-for-byte intact.

ALTER TABLE public.dream_summary_layers
  ADD COLUMN IF NOT EXISTS content_hash bytea,
  ADD COLUMN IF NOT EXISTS authority_event_id uuid;

DO $signed_dream_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'dream_summary_layers_content_hash_shape'
       AND conrelid = 'public.dream_summary_layers'::regclass
  ) THEN
    ALTER TABLE public.dream_summary_layers
      ADD CONSTRAINT dream_summary_layers_content_hash_shape
      CHECK (octet_length(content_hash) = 32)
      NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'dream_summary_layers_authority_required'
       AND conrelid = 'public.dream_summary_layers'::regclass
  ) THEN
    ALTER TABLE public.dream_summary_layers
      ADD CONSTRAINT dream_summary_layers_authority_required
      CHECK (authority_event_id IS NOT NULL)
      NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'dream_summary_layers_authority_event_fkey'
       AND conrelid = 'public.dream_summary_layers'::regclass
  ) THEN
    ALTER TABLE public.dream_summary_layers
      ADD CONSTRAINT dream_summary_layers_authority_event_fkey
      FOREIGN KEY (authority_event_id)
      REFERENCES public.aimos_events(id)
      ON DELETE RESTRICT
      NOT VALID;
  END IF;
END
$signed_dream_constraints$;

DO $signed_dream_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    GRANT SELECT, INSERT ON public.dream_summary_layers TO agent_runtime;
    GRANT USAGE, SELECT ON SEQUENCE public.dream_summary_layers_id_seq TO agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.dream_summary_layers FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.dream_summary_layers FROM aimos_app;
  END IF;
END
$signed_dream_acl$;

COMMENT ON COLUMN public.dream_summary_layers.content_hash IS
  'SHA-256 of the complete canonical dream-layer snapshot at insertion time; NULL is retained historical pre-cutover evidence only.';

COMMENT ON COLUMN public.dream_summary_layers.authority_event_id IS
  'Housekeeper-signed append-only event committed atomically with this retained dream projection row.';
