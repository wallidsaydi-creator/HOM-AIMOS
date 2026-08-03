-- 048-master-keychain-locator.sql
-- Persist the non-secret Keychain locator chosen during master enrollment so
-- every native enrollment surface opens the same encrypted master key.

ALTER TABLE public.aimos_master_identity
  ADD COLUMN IF NOT EXISTS keychain_service text,
  ADD COLUMN IF NOT EXISTS keychain_account text;

COMMENT ON COLUMN public.aimos_master_identity.keychain_service IS
  'Non-secret macOS Keychain service locator for the encrypted master private key.';
COMMENT ON COLUMN public.aimos_master_identity.keychain_account IS
  'Non-secret macOS Keychain account locator chosen in the master enrollment ceremony.';
