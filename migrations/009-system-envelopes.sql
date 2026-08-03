-- ─── Phase 2 PR-A: system_envelopes table ──────────────────────────────────────
-- Purpose: the Ed25519-attested runtime-flag table referenced by
--          services/security/envelope-reader.js. Each row is a fresh signed
--          payload, nonce-bound, with unix_ts <= 300s to prevent replay.
-- Schema sources: envelope-reader.js (L5-L13 inline comment) + readFlag() flow.
--
-- IMPORTANT: This table is owned by the standard application DB role (the same
-- role that envelope-reader.js uses via its default pool.query path; it does
-- NOT use reviewer_runtime / secureQuery). Operator tooling that writes new
-- envelope rows during a flag-flip MUST match the master key index for sig
-- verification on read.
--
-- Phase 0 / pre-PR-A: this migration may not yet be applied to production.
-- envelope-reader.js fail-open defaults (NOT_FOUND/42P01 -> returns caller
-- defaultValue) mean default-OFF remains a no-op until a signed row exists.
--
-- Aladdin-clean: append-only. No UPDATE of value/name after creation. Operators
-- INSERT a fresh row when they want to change a flag; envelope-reader.js reads
-- the freshest row via the (name, updated_at DESC) index below.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS system_envelopes (
  name        TEXT PRIMARY KEY,
  value       BOOLEAN NOT NULL,
  nonce       TEXT NOT NULL,
  unix_ts     BIGINT NOT NULL,
  sig         TEXT NOT NULL,
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS system_envelopes_updated_at_idx
  ON system_envelopes (name, updated_at DESC);
