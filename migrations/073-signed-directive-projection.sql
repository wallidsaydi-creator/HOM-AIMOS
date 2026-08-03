-- Directive tables remain query-efficient projections, but every creation,
-- claim, and terminal transition must point to its retained housekeeper-signed
-- event in the canonical event ledger.

ALTER TABLE public.aimos_directives
  ADD COLUMN IF NOT EXISTS authority_event_id uuid,
  ADD COLUMN IF NOT EXISTS last_event_id uuid;

ALTER TABLE public.directive_claims
  ADD COLUMN IF NOT EXISTS last_event_id uuid;

DO $directive_constraints$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_directives_authority_event_fkey') THEN
    ALTER TABLE public.aimos_directives ADD CONSTRAINT aimos_directives_authority_event_fkey
      FOREIGN KEY (authority_event_id) REFERENCES public.aimos_events(id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_directives_last_event_fkey') THEN
    ALTER TABLE public.aimos_directives ADD CONSTRAINT aimos_directives_last_event_fkey
      FOREIGN KEY (last_event_id) REFERENCES public.aimos_events(id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'directive_claims_last_event_fkey') THEN
    ALTER TABLE public.directive_claims ADD CONSTRAINT directive_claims_last_event_fkey
      FOREIGN KEY (last_event_id) REFERENCES public.aimos_events(id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_directives_signed_projection_required') THEN
    ALTER TABLE public.aimos_directives ADD CONSTRAINT aimos_directives_signed_projection_required
      CHECK (authority_event_id IS NOT NULL AND last_event_id IS NOT NULL) NOT VALID;
  END IF;
END
$directive_constraints$;

DO $directive_acl$
BEGIN
  REVOKE ALL ON public.aimos_directives, public.directive_claims FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    GRANT SELECT ON public.aimos_directives, public.directive_claims TO agent_runtime;
    GRANT INSERT (id, company_id, agent_id, goal, status, priority, clearance_level, authority_event_id, last_event_id)
      ON public.aimos_directives TO agent_runtime;
    GRANT UPDATE (status, result, updated_at, last_event_id) ON public.aimos_directives TO agent_runtime;
    GRANT INSERT (directive_id, company_id, claimed_by, run_id, lease_until, status, created_at, updated_at, last_event_id)
      ON public.directive_claims TO agent_runtime;
    GRANT UPDATE (company_id, claimed_by, run_id, lease_until, status, updated_at, last_event_id)
      ON public.directive_claims TO agent_runtime;
    REVOKE DELETE, TRUNCATE ON public.aimos_directives, public.directive_claims FROM agent_runtime;
  END IF;
END
$directive_acl$;
