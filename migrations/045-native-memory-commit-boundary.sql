-- Native memory commit boundary.
--
-- The application owner is services/write/persist-memory.js. This migration
-- removes the parallel SECURITY DEFINER writer, prevents supersession forks,
-- and grants the restricted runtime role only the statements used by the
-- canonical memory/provenance/envelope/credential transaction.

REVOKE ALL PRIVILEGES ON FUNCTION public.secure_aimos_save(
  text, text, text, text, text, text, text, bytea
) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.secure_aimos_save(
  text, text, text, text, text, text, text, bytea
) FROM agent_runtime;
DROP FUNCTION public.secure_aimos_save(
  text, text, text, text, text, text, text, bytea
);

-- Existing canonical data was preflighted before this migration: no predecessor
-- had more than one successor. The index makes that invariant durable.
CREATE UNIQUE INDEX IF NOT EXISTS aimos_memories_one_successor_per_predecessor
  ON public.aimos_memories (supersedes_id)
  WHERE supersedes_id IS NOT NULL;

DO $native_commit_roles$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    GRANT USAGE ON SCHEMA public TO agent_runtime;

    GRANT SELECT, INSERT ON public.aimos_memories TO agent_runtime;
    GRANT SELECT, INSERT ON public.aimos_memory_provenance TO agent_runtime;
    GRANT SELECT, INSERT ON public.aimos_save_envelope TO agent_runtime;
    GRANT SELECT, INSERT ON public.memory_cross_refs TO agent_runtime;
    GRANT SELECT, INSERT ON public.entity_memory_edges TO agent_runtime;
    GRANT SELECT, INSERT ON public.supersession_events TO agent_runtime;
    GRANT SELECT, INSERT ON public.aimos_credential_lifecycle TO agent_runtime;
    GRANT SELECT ON public.agent_identity TO agent_runtime;
    GRANT UPDATE (chain_head) ON public.agent_identity TO agent_runtime;

    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agent_runtime;

    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_memories FROM agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_memory_provenance FROM agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_save_envelope FROM agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_credential_lifecycle FROM agent_runtime;
    REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM agent_runtime;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE DELETE, TRUNCATE ON TABLES FROM agent_runtime;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM aimos_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE DELETE, TRUNCATE ON TABLES FROM aimos_app;
  END IF;
END
$native_commit_roles$;

COMMENT ON INDEX public.aimos_memories_one_successor_per_predecessor IS
  'Append-only supersession is linear: one retained predecessor may have at most one direct successor.';
