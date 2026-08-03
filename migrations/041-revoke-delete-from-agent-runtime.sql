-- 041-revoke-delete-from-agent-runtime.sql
-- R3 Step 7 — Enforce the no-delete (Aladdin) law where it actually binds:
-- at the database privilege layer, not in a JS string scan.
--
-- The old `vandalismCheck` in db/connection.js case-folds the query text and
-- looks for the substring 'DELETE FROM'. That is not a security control: it is
-- bypassed by `DELETE\nFROM`, `delete  from`, `DELETE /*x*/ FROM`, or any verb
-- assembled dynamically, and it false-positives on innocent string literals. It
-- has been demoted to a developer-convenience fast-fail (see the rewritten
-- comment + error message in db/connection.js). The REAL enforcement is here.
--
-- agent_runtime is the restricted role the guarded write path (secureQuery /
-- agentPool) connects as. Revoking DELETE from it means Postgres itself refuses a
-- delete on that connection — whitespace-obfuscated, comment-injected, or
-- dynamically assembled, it makes no difference. REVOKE binds the role, not the
-- spelling of the statement.
--
-- Scope note: this binds ONLY non-superusers. The superuser `pool` (reserved for
-- migrations / boot / maintenance) can still delete; that is intentional and is
-- why agent-initiated writes are meant to travel on agentPool. See the POOL
-- DECISION block at the top of db/connection.js.
--
-- H8 (no parallel edits): solo migration, sequential.
-- Idempotent: REVOKE of an absent privilege is a no-op; guarded on role existence
-- so a fresh DB that has not yet created agent_runtime does not error.

DO $r3_041_revoke_delete$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    -- Existing tables: pull DELETE off every table in the public schema.
    EXECUTE 'REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM agent_runtime';
    -- Future tables: any table created hereafter by the migration owner inherits
    -- no DELETE grant for agent_runtime.
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE DELETE ON TABLES FROM agent_runtime';
  ELSE
    RAISE NOTICE 'R3-041: role agent_runtime does not exist yet; skipping REVOKE DELETE (will apply on re-run after role creation).';
  END IF;
END
$r3_041_revoke_delete$;
