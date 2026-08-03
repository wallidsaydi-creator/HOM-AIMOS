-- backend/migrations/002-client-isolation-rls.sql
-- Client Isolation via Row-Level Security
-- Every query MUST set: SELECT set_config('app.current_client_id', 'client_xxx', false);
-- When no session var is set, current_setting returns NULL (missing_ok=true),
-- which means the policy evaluates to NULL = falsy, blocking all rows.
-- The 'hom' default is applied at the app layer, not here.
--
-- SUPERUSER NOTE: Postgres superusers bypass RLS even with FORCE ROW LEVEL SECURITY.
-- FORCE RLS applies only to non-superuser table owners and regular roles.
-- The application MUST connect as the 'aimos_app' non-superuser role for RLS
-- to be enforced at runtime.
--
-- Run once to create the aimos_app role:
--   CREATE ROLE aimos_app LOGIN PASSWORD 'aimos_app_local';
--   GRANT ALL ON ALL TABLES IN SCHEMA public TO aimos_app;
--   GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO aimos_app;
--   GRANT USAGE ON SCHEMA public TO aimos_app;

-- ─── Enable RLS on core tables ───────────────────────────────────────────────
ALTER TABLE aimos_memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE aimos_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_memory_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE dream_summary_layers ENABLE ROW LEVEL SECURITY;
ALTER TABLE recommendation_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE procedural_skills ENABLE ROW LEVEL SECURITY;

-- ─── FORCE RLS so the table owner (non-superuser) is also subject to policies ─
-- Without FORCE, the table owner bypasses RLS, breaking isolation.
-- Note: superusers always bypass RLS regardless; use aimos_app role in production.
ALTER TABLE aimos_memories FORCE ROW LEVEL SECURITY;
ALTER TABLE aimos_events FORCE ROW LEVEL SECURITY;
ALTER TABLE entity_memory_edges FORCE ROW LEVEL SECURITY;
ALTER TABLE dream_summary_layers FORCE ROW LEVEL SECURITY;
ALTER TABLE recommendation_log FORCE ROW LEVEL SECURITY;
ALTER TABLE procedural_skills FORCE ROW LEVEL SECURITY;

-- ─── RLS Policies ─────────────────────────────────────────────────────────────
-- Each policy allows SELECT/INSERT/UPDATE/DELETE only for rows where
-- company_id matches the session variable app.current_client_id.
-- missing_ok=true prevents errors when the variable is not set (returns NULL,
-- which blocks all rows — safe default deny).
--
-- IDEMPOTENT: DROP IF EXISTS before CREATE to allow re-applying migration.

DROP POLICY IF EXISTS client_isolation_memories ON aimos_memories;
DROP POLICY IF EXISTS client_isolation_events ON aimos_events;
DROP POLICY IF EXISTS client_isolation_edges ON entity_memory_edges;
DROP POLICY IF EXISTS client_isolation_dreams ON dream_summary_layers;
DROP POLICY IF EXISTS client_isolation_recommendations ON recommendation_log;
DROP POLICY IF EXISTS client_isolation_skills ON procedural_skills;

-- Memories: only see your own client's data
CREATE POLICY client_isolation_memories ON aimos_memories
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

-- Events: only see your own client's events
CREATE POLICY client_isolation_events ON aimos_events
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

-- Entity edges: only see your own client's knowledge graph
CREATE POLICY client_isolation_edges ON entity_memory_edges
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

-- Dream layers: only see your own client's dream summaries
CREATE POLICY client_isolation_dreams ON dream_summary_layers
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

-- Recommendations: only see your own client's recommendation log
CREATE POLICY client_isolation_recommendations ON recommendation_log
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

-- Skills: only see your own client's procedural skills
CREATE POLICY client_isolation_skills ON procedural_skills
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

-- ─── Application role setup (idempotent) ─────────────────────────────────────
-- Create aimos_app if it doesn't exist. Used by all application connections.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    CREATE ROLE aimos_app LOGIN PASSWORD 'aimos_app_local';
  END IF;
END
$$;

GRANT ALL ON ALL TABLES IN SCHEMA public TO aimos_app;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO aimos_app;
GRANT USAGE ON SCHEMA public TO aimos_app;
-- Grant execute on all functions (needed for pgvector operations)
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO aimos_app;
