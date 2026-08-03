-- 055-retire-unsigned-integration-settings.sql
-- Integration availability is derived from verified Keychain credential
-- references. An unsigned mutable enable flag is not an authority plane.

BEGIN;

DO $body$
BEGIN
  IF EXISTS (SELECT 1 FROM integration_settings) THEN
    RAISE EXCEPTION
      'integration_settings contains unsigned state; reconcile provider connectivity before migration 055';
  END IF;
END
$body$;

DROP TABLE integration_settings;

COMMIT;
