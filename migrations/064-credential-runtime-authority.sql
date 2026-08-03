-- Restrict credential lifecycle and OAuth reference projections to their
-- native, cryptographically verified runtime owners.

ALTER TABLE public.integration_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.integration_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS integration_tokens_company_isolation ON public.integration_tokens;
CREATE POLICY integration_tokens_company_isolation ON public.integration_tokens
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

REVOKE ALL ON public.integration_tokens FROM PUBLIC;
REVOKE ALL ON public.aimos_credential_lifecycle FROM PUBLIC;

DO $credential_runtime_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.integration_tokens FROM agent_runtime;
    GRANT SELECT ON public.integration_tokens TO agent_runtime;
    GRANT INSERT (
      id, company_id, provider, access_token_slot, access_token_hash,
      refresh_token_slot, refresh_token_hash, expires_at, metadata,
      auth_type, cluster_id, created_at, updated_at
    ) ON public.integration_tokens TO agent_runtime;

    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_credential_lifecycle FROM agent_runtime;
    GRANT SELECT ON public.aimos_credential_lifecycle TO agent_runtime;
    GRANT INSERT (
      service_name, slot_id, event_type, agent_id, agent_valid_from,
      cert_fingerprint, identity_tier, body_json, content_hash,
      mutation_hash, prev_mutation_hash, ts_signed, nonce, sig, is_genesis
    ) ON public.aimos_credential_lifecycle TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.integration_tokens FROM aimos_app;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_credential_lifecycle FROM aimos_app;
  END IF;
END
$credential_runtime_acl$;

COMMENT ON TABLE public.integration_tokens IS
  'Append-only OAuth reference projection. Plaintext remains in versioned Keychain slots; materialization requires a fully verified credential lifecycle chain.';
