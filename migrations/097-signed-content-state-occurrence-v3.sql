-- 097-signed-content-state-occurrence-v3.sql
--
-- R7 activates the successor occurrence form for authorized exact-state save
-- reassertions. Existing v1/v2 provenance bytes remain unchanged. The new
-- partial constraints apply only to sig_form_version=3 and do not introduce a
-- global content-hash uniqueness rule, memory deletion, or ranking authority.

DO $occurrence_v3_constraint$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_memory_provenance_occurrence_v3_shape'
       AND conrelid = 'public.aimos_memory_provenance'::regclass
  ) THEN
    ALTER TABLE public.aimos_memory_provenance
    ADD CONSTRAINT aimos_memory_provenance_occurrence_v3_shape
    CHECK (
    sig_form_version <> 3 OR (
      event_type IN ('SAVE_REASSERT', 'INTERNAL_SAVE_REASSERT')
      AND agent_valid_from IS NOT NULL
      AND octet_length(content_hash) = 32
      AND octet_length(mutation_hash) = 32
      AND octet_length(prev_mutation_hash) = 32
      AND octet_length(live_content_hash) = 32
      AND octet_length(sig) = 64
      AND nonce ~ '^(?:[0-9a-f]{2}){16,32}$'
      AND jsonb_typeof(body_json) = 'object'
      AND body_json->>'schema' = 'hom.aimos.memory-occurrence/v3'
      AND body_json->>'occurrence_event_id' = provenance_id::text
      AND body_json->>'memory_id' = memory_id::text
      AND body_json->>'event_type' = event_type
      AND body_json->>'company_id' <> ''
      AND body_json->>'agent_id' = agent_id
      AND (body_json->>'signer_valid_from_unix_ms')::bigint
          = trunc(extract(epoch FROM agent_valid_from) * 1000)::bigint
      AND body_json->>'cert_fingerprint_hex' = cert_fingerprint
      AND body_json->>'identity_tier' = identity_tier
      AND (body_json->>'sig_form_version')::smallint = 3
      AND body_json->>'nonce_hex' = nonce
      AND (body_json->>'ts_signed_unix_seconds')::bigint = ts_signed
      AND body_json->>'occurrence_commitment' = encode(mutation_hash, 'hex')
      AND body_json->>'live_content_hash_hex' = encode(live_content_hash, 'hex')
      AND body_json->>'request_body_hash_hex' = encode(content_hash, 'hex')
      AND (body_json->>'predecessor_present')::integer = 1
      AND body_json->>'predecessor_commitment_hex' = encode(prev_mutation_hash, 'hex')
      AND (
        (
          event_type = 'SAVE_REASSERT'
          AND body_json->>'signed_method' <> ''
          AND body_json->>'signed_path' <> ''
          AND (body_json->>'request_receipt_present')::integer = 1
          AND body_json->>'request_receipt_mutation_hash_hex' ~ '^[0-9a-f]{64}$'
          AND (body_json->>'authorization_event_present')::integer = 1
          AND body_json->>'authorization_event_id' ~
            '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        )
        OR
        (
          event_type = 'INTERNAL_SAVE_REASSERT'
          AND body_json->>'signed_method' = ''
          AND body_json->>'signed_path' = ''
          AND (body_json->>'request_receipt_present')::integer = 0
          AND body_json->>'request_receipt_mutation_hash_hex' = ''
          AND (body_json->>'authorization_event_present')::integer = 0
          AND body_json->>'authorization_event_id' = ''
        )
      )
    )
    );
  END IF;
END
$occurrence_v3_constraint$;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS aimos_memory_provenance_occurrence_v3_commitment_unique
  ON public.aimos_memory_provenance (mutation_hash)
  WHERE sig_form_version = 3;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS aimos_memory_provenance_occurrence_v3_nonce_unique
  ON public.aimos_memory_provenance (agent_id, agent_valid_from, nonce)
  WHERE sig_form_version = 3;

CREATE INDEX CONCURRENTLY IF NOT EXISTS aimos_memories_content_state_principal_lookup
  ON public.aimos_memories (company_id, content_hash, agent_id, id)
  WHERE content_hash IS NOT NULL;

COMMENT ON CONSTRAINT aimos_memory_provenance_occurrence_v3_shape
  ON public.aimos_memory_provenance IS
  'R7 exact-state occurrence contract: v3 rows bind event id, content state, predecessor occurrence, signer epoch, request receipt, authorization event, and detached Ed25519 commitment.';
