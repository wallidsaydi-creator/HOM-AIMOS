-- Graph edges are a mutable cognitive projection, but every insert or update
-- must be authorized by an append-only housekeeper-signed event committed in
-- the same transaction. Historical edges remain retained and are not rewritten.

ALTER TABLE public.memory_cross_refs
  ADD COLUMN IF NOT EXISTS authority_event_id uuid;

DO $signed_cross_ref_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'memory_cross_refs_authority_event_fkey'
       AND conrelid = 'public.memory_cross_refs'::regclass
  ) THEN
    ALTER TABLE public.memory_cross_refs
      ADD CONSTRAINT memory_cross_refs_authority_event_fkey
      FOREIGN KEY (authority_event_id)
      REFERENCES public.aimos_events(id)
      ON DELETE RESTRICT
      NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'memory_cross_refs_signed_projection_required'
       AND conrelid = 'public.memory_cross_refs'::regclass
  ) THEN
    ALTER TABLE public.memory_cross_refs
      ADD CONSTRAINT memory_cross_refs_signed_projection_required
      CHECK (authority_event_id IS NOT NULL)
      NOT VALID;
  END IF;
END
$signed_cross_ref_constraints$;

DO $signed_cross_ref_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON public.memory_cross_refs FROM agent_runtime;
    GRANT UPDATE (similarity, edge_strength, edge_type, authority_event_id)
      ON public.memory_cross_refs TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.memory_cross_refs FROM aimos_app;
  END IF;
END
$signed_cross_ref_acl$;

COMMENT ON COLUMN public.memory_cross_refs.authority_event_id IS
  'Append-only signed aimos_events proof for the atomic graph projection transition; NULL is retained historical pre-cutover evidence only.';
