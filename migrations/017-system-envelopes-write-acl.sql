-- ─── Phase 2 PR-B: system_envelopes write-ACL ─────────────────────────────────
-- Closes the write-AUTH path that makes BUG-01/02 reachable. With only BUG-01
-- in place, any DB principal with table-level write on system_envelopes can
-- still forge flag state; this migration narrows that authority to a single
-- dedicated role and forces every writer to produce a fresh Ed25519
-- signature (rejected by readFlag's post-BUG-01 verification path).
--
-- Role model (NOLOGIN group roles; memberships assigned out-of-band):
--   aimos_app_ro        — SELECT on system_envelopes only.
--                          Used for readFlag/system_envelopes readers.
--   aimos_flag_signer   — INSERT, UPDATE on system_envelopes only.
--                          Used by the signed-flag refresher (300s cadence).
--                          Every INSERT/UPDATE must carry a fresh signature;
--                          post-BUG-01 readFlag rejects out-of-band writes.
--
-- IMPORTANT: this migration MUST be applied as a role that owns the table and
-- has CREATEROLE. Do NOT run it under the hardcoded reviewer_runtime identity in
-- db/connection.js — that is a release blocker, separate from this fix. The
-- intent is publisher-only: the refresher is the sole writer.
--
-- Aladdin-clean: GRANT creates new authoritative writers; nothing deletes
-- existing rows. REVOKE FROM PUBLIC strips default PUBLIC grant (Postgres ≥ 14
-- already has none, but the REVOKE statement is idempotent and explicit).
-- Idempotent: every role CREATE is guarded; every GRANT/REVOKE is naturally
-- idempotent at the privilege level (Postgres records the resulting ACL).
-- ─────────────────────────────────────────────────────────────────────────────

DO $acl$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app_ro') THEN
    CREATE ROLE aimos_app_ro NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_flag_signer') THEN
    CREATE ROLE aimos_flag_signer NOLOGIN;
  END IF;
END
$acl$;

-- Strip any default PUBLIC privilege on the table (idempotent: REVOKE on
-- an ungranted privilege is a no-op rather than an error in PG ≥ 9).
REVOKE ALL PRIVILEGES ON system_envelopes FROM PUBLIC;

-- Read path: aimos_app_ro is the only read-side principal group.
GRANT SELECT ON system_envelopes TO aimos_app_ro;

-- Write path: only the signed-flag refresher role may INSERT or UPDATE.
-- DELETE is intentionally denied: flag rows are append-only (signed refresh
-- produces new rows; the table PK is `name` so updates are in-place anyway).
GRANT INSERT, UPDATE ON system_envelopes TO aimos_flag_signer;
