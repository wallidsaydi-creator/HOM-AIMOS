-- 054-keychain-only-integration-tokens.sql
-- OAuth/provider token plaintext belongs only in versioned Keychain slots.
-- The identity vault retains non-secret references, hashes, provider metadata,
-- validity, and append-only credential lifecycle evidence.

BEGIN;

DO $body$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM integration_tokens
     WHERE access_token IS NOT NULL OR refresh_token IS NOT NULL
  ) THEN
    RAISE EXCEPTION
      'integration_tokens contains plaintext credentials; run the approved Keychain migration ceremony before migration 054';
  END IF;
END
$body$;

ALTER TABLE integration_tokens
  ADD COLUMN IF NOT EXISTS access_token_slot text,
  ADD COLUMN IF NOT EXISTS access_token_hash text,
  ADD COLUMN IF NOT EXISTS refresh_token_slot text,
  ADD COLUMN IF NOT EXISTS refresh_token_hash text;

ALTER TABLE integration_tokens
  DROP COLUMN access_token,
  DROP COLUMN refresh_token;

ALTER TABLE integration_tokens
  ADD CONSTRAINT integration_tokens_access_reference_complete
  CHECK (
    (access_token_slot IS NULL AND access_token_hash IS NULL)
    OR
    (access_token_slot IS NOT NULL AND access_token_hash ~ '^[0-9a-f]{64}$')
  ),
  ADD CONSTRAINT integration_tokens_refresh_reference_complete
  CHECK (
    (refresh_token_slot IS NULL AND refresh_token_hash IS NULL)
    OR
    (refresh_token_slot IS NOT NULL AND refresh_token_hash ~ '^[0-9a-f]{64}$')
  );

REVOKE UPDATE, DELETE, TRUNCATE ON integration_tokens FROM PUBLIC, aimos_app, agent_runtime;
GRANT SELECT ON integration_tokens TO agent_runtime;

COMMIT;
