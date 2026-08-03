-- ─── Phase 2 PR-B (cont.): strip aimos_app's blanket DML on system_envelopes ──
-- Migration 017 created the aimos_app_ro + aimos_flag_signer roles and GRANTed
-- them the minimum privileges they need (SELECT / INSERT+UPDATE). But 017 only
-- REVOKEd from PUBLIC — it did NOT touch the blanket
--   GRANT ALL ON ALL TABLES IN SCHEMA public TO aimos_app
-- issued by migration 002:92. That left aimos_app with INSERT/UPDATE/DELETE on
-- system_envelopes, which is the flag-forgery exploit path 017's own header
-- (lines 16-19) flagged as a "release blocker, separate from this fix."
--
-- This migration closes that gap. After it runs:
--   aimos_app        → no privileges on system_envelopes (SELECT denied too —
--                       aimos_app is not the read path; the server connects as
--                       `operator` via DATABASE_URL, not as aimos_app)
--   aimos_app_ro     → SELECT only (read path for envelope-reader.js readFlag)
--   aimos_flag_signer→ INSERT, UPDATE only (write path for pr-b-flip-commit)
--
-- Aladdin-clean: REVOKE removes a privilege; it does not delete rows or alter
-- data. Idempotent: REVOKE on an ungranted privilege is a no-op in PG ≥ 9.
--
-- Applied after 017. Tracked in schema_migrations via migrations/run.js.
-- ─────────────────────────────────────────────────────────────────────────────

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON system_envelopes FROM aimos_app;

-- Verification (run after; expect 0 rows for INSERT/UPDATE/DELETE/TRUNCATE):
-- SELECT privilege_type FROM information_schema.role_table_grants
--   WHERE table_name = 'system_envelopes' AND grantee = 'aimos_app';