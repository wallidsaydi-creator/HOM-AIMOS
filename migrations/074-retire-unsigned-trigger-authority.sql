-- Unsigned mutable triggers were a parallel autonomous executor with plaintext
-- secret reads and deactivation semantics. Housekeeper-owned signed scheduler
-- events are the sole autonomous execution authority. Retain trigger history.

REVOKE ALL ON public.trigger_rules FROM PUBLIC;

DO $retire_trigger_authority$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.trigger_rules FROM agent_runtime;
    GRANT SELECT ON public.trigger_rules TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.trigger_rules FROM aimos_app;
  END IF;
END
$retire_trigger_authority$;

COMMENT ON TABLE public.trigger_rules IS
  'RETIRED retained historical rules. Never autonomous execution authority; housekeeper signed scheduler events are canonical.';
