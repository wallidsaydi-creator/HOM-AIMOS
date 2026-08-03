-- The retained integration_tokens table is legacy observation history only.
-- Runtime OAuth truth is the verified credential lifecycle + versioned
-- Keychain pair. No row is deleted and whole-brain purge remains the sole
-- maintenance mechanism capable of removing the retained database.

BEGIN;

REVOKE ALL ON public.integration_tokens FROM PUBLIC;

DO $retire_integration_token_authority$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE ALL ON public.integration_tokens FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE ALL ON public.integration_tokens FROM aimos_app;
  END IF;
END
$retire_integration_token_authority$;

COMMENT ON TABLE public.integration_tokens IS
  'Retained legacy OAuth projection. Non-authoritative and inaccessible to runtime roles; live truth is the signed aimos_credential_lifecycle plus versioned Keychain.';

DO $credential_authority_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_identity_vault_body_complete'
       AND conrelid = 'public.aimos_credential_lifecycle'::regclass
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT aimos_identity_vault_body_complete CHECK (
        NOT (body_json ? 'identity_vault')
        OR COALESCE((
          event_type IN ('STORE', 'ROTATE')
          AND jsonb_typeof(body_json->'identity_vault') = 'object'
          AND body_json->'identity_vault'->>'namespace' = 'identity_vault'
          AND length(body_json->'identity_vault'->>'company_id') > 0
          AND body_json->'identity_vault'->>'provider' ~ '^[a-z0-9][a-z0-9_-]{0,63}$'
          AND body_json->'identity_vault'->>'credential_kind' IN ('access', 'refresh')
          AND service_name = concat(
            'oauth_',
            body_json->'identity_vault'->>'provider',
            '_',
            body_json->'identity_vault'->>'credential_kind',
            '_token'
          )
          AND jsonb_typeof(body_json->'identity_vault'->'metadata') = 'object'
          AND length(body_json->'identity_vault'->>'auth_type') > 0
          AND length(body_json->'identity_vault'->>'cluster_id') > 0
          AND length(body_json->'identity_vault'->>'initiating_subject_agent_id') > 0
          AND jsonb_typeof(body_json->'identity_vault'->'credential_use_evidence') = 'array'
        ), false)
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_credential_use_exact_authority_complete'
       AND conrelid = 'public.aimos_credential_lifecycle'::regclass
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT aimos_credential_use_exact_authority_complete CHECK (
        event_type <> 'USE_RESERVED'
        OR COALESCE((
          body_json->>'autonomous_action_event_id' IS NOT NULL
          AND body_json->>'autonomous_action_mutation_hash' ~ '^[0-9a-f]{64}$'
          AND body_json->>'authority_kind' IN (
            'housekeeper_autonomous',
            'housekeeper_observation_of_verified_request'
          )
          AND (
            (
              body_json->>'authority_kind' = 'housekeeper_autonomous'
              AND body_json->>'request_receipt_id' IS NULL
              AND body_json->>'request_receipt_mutation_hash' IS NULL
              AND body_json->>'request_admission_event_id' IS NULL
              AND body_json->>'request_admission_mutation_hash' IS NULL
            )
            OR
            (
              body_json->>'authority_kind' = 'housekeeper_observation_of_verified_request'
              AND body_json->>'request_receipt_id' IS NOT NULL
              AND body_json->>'request_receipt_mutation_hash' ~ '^[0-9a-f]{64}$'
              AND body_json->>'request_admission_event_id' IS NOT NULL
              AND body_json->>'request_admission_mutation_hash' ~ '^[0-9a-f]{64}$'
            )
          )
        ), false)
      ) NOT VALID;
  END IF;
END
$credential_authority_constraints$;

COMMIT;
