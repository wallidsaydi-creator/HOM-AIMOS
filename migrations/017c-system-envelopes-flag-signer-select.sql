-- ─── Phase 2 PR-B (cont.): grant SELECT to aimos_flag_signer for upsert ───
-- Migration 017 GRANTed INSERT + UPDATE to aimos_flag_signer but NOT SELECT.
-- pr-b-flip-commit.mjs uses INSERT ... ON CONFLICT (name) DO UPDATE — PG needs
-- SELECT on the conflict arbiter column to decide insert-vs-update. Without
-- SELECT, the upsert fails with "permission denied for table system_envelopes"
-- even though INSERT + UPDATE are granted.
--
-- This migration adds SELECT to aimos_flag_signer. The role is still minimal:
--   SELECT + INSERT + UPDATE (no DELETE, no TRUNCATE, no REFERENCES, no TRIGGER).
-- The flag-forgery exploit path (DELETE rows / TRUNCATE / insert forged rows
-- outside the signed-packet ceremony) remains closed — only the signed-packet
-- commit path can upsert, and only via the SET LOCAL ROLE escalation in
-- pr-b-flip-commit.mjs.
--
-- Aladdin-clean: GRANT adds a privilege; it does not delete rows or alter data.
-- Idempotent: GRANT on an already-granted privilege is a no-op in PG ≥ 9.
--
-- Applied after 017b. Tracked in schema_migrations via migrations/run.js.
-- ─────────────────────────────────────────────────────────────────────────────

GRANT SELECT ON system_envelopes TO aimos_flag_signer;

-- Verification (run after; expect INSERT, UPDATE, SELECT):
-- SELECT privilege_type FROM information_schema.role_table_grants
--   WHERE table_name = 'system_envelopes' AND grantee = 'aimos_flag_signer';