-- Credential consumption is part of the native lifecycle ledger. Every
-- external boundary reserves an exact verified credential version before use
-- and appends one retained completion/failure event afterward. No plaintext,
-- credential-bearing URL, request body, or response body enters this table.

ALTER TABLE public.aimos_credential_lifecycle
  DROP CONSTRAINT IF EXISTS aimos_credential_lifecycle_event_type_check;

ALTER TABLE public.aimos_credential_lifecycle
  ADD CONSTRAINT aimos_credential_lifecycle_event_type_check
  CHECK (event_type IN (
    'STORE','ROTATE','REVOKE','VERIFY',
    'USE_RESERVED','USE_COMPLETED','USE_FAILED'
  ));

DO $credential_use_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_credential_use_body_complete'
       AND conrelid = 'public.aimos_credential_lifecycle'::regclass
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT aimos_credential_use_body_complete CHECK (
        event_type NOT IN ('USE_RESERVED','USE_COMPLETED','USE_FAILED')
        OR (
          body_json->>'use_id' IS NOT NULL
          AND body_json->>'credential_hash' ~ '^[0-9a-f]{64}$'
          AND body_json->>'signer_agent_id' = agent_id
          AND body_json->>'service' = service_name
          AND body_json->>'slot_id' = slot_id
          AND body_json->>'event_type' = event_type
          AND (
            (event_type = 'USE_RESERVED'
              AND body_json->>'operation' IS NOT NULL
              AND body_json->>'endpoint' IS NOT NULL
              AND position('?' in body_json->>'endpoint') = 0
              AND body_json->>'request_hash' ~ '^[0-9a-f]{64}$'
              AND body_json->>'effective_provenance_id' IS NOT NULL
              AND body_json->>'effective_mutation_hash' ~ '^[0-9a-f]{64}$')
            OR
            (event_type IN ('USE_COMPLETED','USE_FAILED')
              AND body_json->>'reservation_provenance_id' IS NOT NULL
              AND body_json->>'reservation_mutation_hash' ~ '^[0-9a-f]{64}$'
              AND body_json->>'outcome_hash' ~ '^[0-9a-f]{64}$')
          )
        )
      );
  END IF;
END
$credential_use_constraints$;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_credential_use_reservation_unique
  ON public.aimos_credential_lifecycle (slot_id, (body_json->>'use_id'))
  WHERE event_type = 'USE_RESERVED';

CREATE UNIQUE INDEX IF NOT EXISTS aimos_credential_use_terminal_unique
  ON public.aimos_credential_lifecycle (slot_id, (body_json->>'use_id'))
  WHERE event_type IN ('USE_COMPLETED','USE_FAILED');

COMMENT ON TABLE public.aimos_credential_lifecycle IS
  'Append-only signed credential lifecycle and use ledger: STORE/ROTATE/REVOKE/VERIFY plus USE_RESERVED followed by exactly one USE_COMPLETED or USE_FAILED. Plaintext is Keychain-only.';
