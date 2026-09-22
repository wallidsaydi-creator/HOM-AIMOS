-- 100-origin-family-ledger-and-writers.sql
--
-- OB-2: one database-local, append-only authority for the three frozen OB-1
-- object families. The portable object hash remains independent of PostgreSQL;
-- this migration adds a native no-fork envelope bound to the current database,
-- master, Housekeeper epoch, signer profile, and predecessor.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pgsodium;

CREATE TABLE public.aimos_origin_family_profiles (
  profile_sha256 bytea PRIMARY KEY,
  schema_id text NOT NULL UNIQUE,
  profile_version integer NOT NULL,
  body_json jsonb NOT NULL,
  body_bytes bytea NOT NULL,
  installed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT aimos_origin_family_profile_hash_len CHECK (octet_length(profile_sha256) = 32),
  CONSTRAINT aimos_origin_family_profile_version CHECK (profile_version = 1)
);

CREATE TABLE public.aimos_origin_family_definitions (
  profile_sha256 bytea NOT NULL,
  family_id text NOT NULL,
  parent_id text,
  confidentiality_floor text NOT NULL,
  action_policy text NOT NULL,
  PRIMARY KEY (profile_sha256, family_id),
  CONSTRAINT aimos_origin_family_definition_profile_fk
    FOREIGN KEY (profile_sha256) REFERENCES public.aimos_origin_family_profiles(profile_sha256)
    ON DELETE RESTRICT,
  CONSTRAINT aimos_origin_family_parent_fk
    FOREIGN KEY (profile_sha256, parent_id)
    REFERENCES public.aimos_origin_family_definitions(profile_sha256, family_id)
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT aimos_origin_family_confidentiality CHECK (
    confidentiality_floor IN ('public', 'internal', 'confidential', 'restricted')
  ),
  CONSTRAINT aimos_origin_family_action_policy CHECK (
    action_policy IN (
      'inform_only', 'exact_origin_verdict', 'exact_user_or_provider',
      'exact_configuration_owner', 'inherit_parents', 'deny_action'
    )
  )
);

CREATE TABLE public.aimos_origin_ledger_entries (
  ledger_hash bytea PRIMARY KEY,
  company_id text NOT NULL,
  object_schema text NOT NULL,
  object_sha256 bytea NOT NULL UNIQUE,
  prev_ledger_hash bytea,
  database_context_sha256 bytea NOT NULL,
  authority_profile_sha256 bytea NOT NULL,
  signer_agent_id text NOT NULL,
  signer_valid_from timestamptz NOT NULL,
  signer_cert_fingerprint text NOT NULL,
  signed_at timestamptz NOT NULL,
  ledger_signature bytea NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT aimos_origin_ledger_object_schema CHECK (
    object_schema IN (
      'hom.aimos.memory-origin-binding/v1',
      'hom.aimos.origin-elevation/v1',
      'hom.aimos.action-origin-verdict/v1'
    )
  ),
  CONSTRAINT aimos_origin_ledger_hash_lengths CHECK (
    octet_length(ledger_hash) = 32
    AND octet_length(object_sha256) = 32
    AND (prev_ledger_hash IS NULL OR octet_length(prev_ledger_hash) = 32)
    AND octet_length(database_context_sha256) = 32
    AND octet_length(authority_profile_sha256) = 32
    AND octet_length(ledger_signature) = 64
  ),
  CONSTRAINT aimos_origin_ledger_signer_fingerprint CHECK (
    signer_cert_fingerprint ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT aimos_origin_ledger_signer_epoch_fk
    FOREIGN KEY (signer_agent_id, signer_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from) ON DELETE RESTRICT,
  CONSTRAINT aimos_origin_ledger_predecessor_fk
    FOREIGN KEY (prev_ledger_hash)
    REFERENCES public.aimos_origin_ledger_entries(ledger_hash) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT aimos_origin_ledger_profile_fk
    FOREIGN KEY (authority_profile_sha256)
    REFERENCES public.aimos_origin_family_profiles(profile_sha256) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX aimos_origin_ledger_one_genesis
  ON public.aimos_origin_ledger_entries(company_id)
  WHERE prev_ledger_hash IS NULL;
CREATE UNIQUE INDEX aimos_origin_ledger_one_successor
  ON public.aimos_origin_ledger_entries(company_id, prev_ledger_hash)
  WHERE prev_ledger_hash IS NOT NULL;
CREATE INDEX aimos_origin_ledger_company_commit
  ON public.aimos_origin_ledger_entries(company_id, committed_at, ledger_hash);

CREATE TABLE public.aimos_memory_origin_bindings (
  binding_sha256 bytea PRIMARY KEY,
  ledger_hash bytea NOT NULL UNIQUE,
  company_id text NOT NULL,
  memory_id uuid NOT NULL,
  occurrence_id uuid NOT NULL UNIQUE,
  content_sha256 bytea NOT NULL,
  actor_agent_id text NOT NULL,
  actor_valid_from timestamptz NOT NULL,
  actor_cert_fingerprint text NOT NULL,
  request_receipt_id uuid NOT NULL,
  request_mutation_sha256 bytea NOT NULL,
  ingress_channel text NOT NULL,
  channel_identity_sha256 bytea NOT NULL,
  parent_origin_sha256s bytea[] NOT NULL DEFAULT '{}',
  family_profile_sha256 bytea NOT NULL,
  family_ids text[] NOT NULL,
  classification_authority text NOT NULL,
  classification_evidence_sha256 bytea NOT NULL,
  classification_event_id uuid NOT NULL,
  confidentiality text NOT NULL,
  integrity text NOT NULL,
  action_class text NOT NULL,
  action_scope text NOT NULL,
  session_id text,
  tool_action_event_id uuid,
  originated_at timestamptz NOT NULL,
  body_json jsonb NOT NULL,
  body_bytes bytea NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT aimos_memory_origin_ledger_fk FOREIGN KEY (ledger_hash)
    REFERENCES public.aimos_origin_ledger_entries(ledger_hash) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_memory_fk FOREIGN KEY (memory_id)
    REFERENCES public.aimos_memories(id) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_occurrence_fk FOREIGN KEY (occurrence_id)
    REFERENCES public.aimos_memory_provenance(provenance_id) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_actor_fk FOREIGN KEY (actor_agent_id, actor_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_request_fk FOREIGN KEY (request_receipt_id)
    REFERENCES public.aimos_request_receipts(request_receipt_id) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_profile_fk FOREIGN KEY (family_profile_sha256)
    REFERENCES public.aimos_origin_family_profiles(profile_sha256) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_classification_event_fk FOREIGN KEY (classification_event_id)
    REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_tool_event_fk FOREIGN KEY (tool_action_event_id)
    REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_origin_hash_lengths CHECK (
    octet_length(binding_sha256) = 32
    AND octet_length(content_sha256) = 32
    AND octet_length(request_mutation_sha256) = 32
    AND octet_length(channel_identity_sha256) = 32
    AND octet_length(family_profile_sha256) = 32
    AND octet_length(classification_evidence_sha256) = 32
  ),
  CONSTRAINT aimos_memory_origin_actor_fingerprint CHECK (
    actor_cert_fingerprint ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT aimos_memory_origin_ingress CHECK (
    ingress_channel IN (
      'untrusted_external', 'agent_self', 'authenticated_agent',
      'housekeeper_system', 'authenticated_tool', 'authenticated_user',
      'system_internal'
    )
  ),
  CONSTRAINT aimos_memory_origin_classification_authority CHECK (
    classification_authority IN (
      'deterministic_route_schema', 'deterministic_field_schema',
      'authenticated_tool_schema', 'system_producer_schema',
      'trusted_monitor_classifier', 'legacy_successor_review'
    )
  ),
  CONSTRAINT aimos_memory_origin_confidentiality CHECK (
    confidentiality IN ('public', 'internal', 'confidential', 'restricted')
  ),
  CONSTRAINT aimos_memory_origin_integrity CHECK (integrity IN ('untrusted', 'agent', 'trusted')),
  CONSTRAINT aimos_memory_origin_action_class CHECK (action_class IN ('none', 'inform', 'act'))
);

CREATE TABLE public.aimos_origin_elevations (
  elevation_sha256 bytea PRIMARY KEY,
  ledger_hash bytea NOT NULL UNIQUE,
  company_id text NOT NULL,
  elevation_id uuid NOT NULL UNIQUE,
  value_sha256 bytea NOT NULL,
  family_id text NOT NULL,
  action_scope text NOT NULL,
  risk_class text NOT NULL,
  base_origin_sha256s bytea[] NOT NULL,
  corroborators jsonb NOT NULL,
  threshold integer NOT NULL,
  user_authorization_sha256 bytea,
  authorization_event_id uuid,
  maximum_uses integer NOT NULL,
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  originated_at timestamptz NOT NULL,
  body_json jsonb NOT NULL,
  body_bytes bytea NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT aimos_origin_elevation_ledger_fk FOREIGN KEY (ledger_hash)
    REFERENCES public.aimos_origin_ledger_entries(ledger_hash) ON DELETE RESTRICT,
  CONSTRAINT aimos_origin_elevation_authorization_event_fk FOREIGN KEY (authorization_event_id)
    REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  CONSTRAINT aimos_origin_elevation_hash_lengths CHECK (
    octet_length(elevation_sha256) = 32
    AND octet_length(value_sha256) = 32
    AND (user_authorization_sha256 IS NULL OR octet_length(user_authorization_sha256) = 32)
  ),
  CONSTRAINT aimos_origin_elevation_risk CHECK (
    risk_class IN ('non_consequential', 'consequential', 'high_impact')
  ),
  CONSTRAINT aimos_origin_elevation_one_use CHECK (maximum_uses = 1),
  CONSTRAINT aimos_origin_elevation_time CHECK (valid_until > valid_from AND originated_at <= valid_until)
);

CREATE TABLE public.aimos_action_origin_verdicts (
  verdict_sha256 bytea PRIMARY KEY,
  ledger_hash bytea NOT NULL UNIQUE,
  company_id text NOT NULL,
  verdict_id uuid NOT NULL UNIQUE,
  actor_agent_id text NOT NULL,
  actor_valid_from timestamptz NOT NULL,
  actor_cert_fingerprint text NOT NULL,
  tool_name text NOT NULL,
  action_scope text NOT NULL,
  risk_class text NOT NULL,
  arguments_sha256 bytea NOT NULL,
  security_values jsonb NOT NULL,
  family_ids text[] NOT NULL,
  input_origin_sha256s bytea[] NOT NULL,
  untrusted_influence boolean NOT NULL,
  elevation_sha256 bytea,
  user_authorization_sha256 bytea,
  authorization_event_id uuid,
  decision text NOT NULL,
  failure_code text,
  previous_verdict_sha256 bytea,
  originated_at timestamptz NOT NULL,
  body_json jsonb NOT NULL,
  body_bytes bytea NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT aimos_action_origin_verdict_ledger_fk FOREIGN KEY (ledger_hash)
    REFERENCES public.aimos_origin_ledger_entries(ledger_hash) ON DELETE RESTRICT,
  CONSTRAINT aimos_action_origin_verdict_actor_fk FOREIGN KEY (actor_agent_id, actor_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from) ON DELETE RESTRICT,
  CONSTRAINT aimos_action_origin_verdict_elevation_fk FOREIGN KEY (elevation_sha256)
    REFERENCES public.aimos_origin_elevations(elevation_sha256) ON DELETE RESTRICT,
  CONSTRAINT aimos_action_origin_verdict_authorization_event_fk FOREIGN KEY (authorization_event_id)
    REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  CONSTRAINT aimos_action_origin_verdict_predecessor_fk FOREIGN KEY (previous_verdict_sha256)
    REFERENCES public.aimos_action_origin_verdicts(verdict_sha256) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT aimos_action_origin_verdict_hash_lengths CHECK (
    octet_length(verdict_sha256) = 32
    AND octet_length(arguments_sha256) = 32
    AND (elevation_sha256 IS NULL OR octet_length(elevation_sha256) = 32)
    AND (user_authorization_sha256 IS NULL OR octet_length(user_authorization_sha256) = 32)
    AND (previous_verdict_sha256 IS NULL OR octet_length(previous_verdict_sha256) = 32)
  ),
  CONSTRAINT aimos_action_origin_verdict_actor_fingerprint CHECK (
    actor_cert_fingerprint ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT aimos_action_origin_verdict_decision CHECK (
    decision IN ('ALLOW', 'DENY', 'INDETERMINATE')
  ),
  CONSTRAINT aimos_action_origin_verdict_semantics CHECK (
    (decision = 'ALLOW' AND failure_code IS NULL)
    OR (decision <> 'ALLOW' AND failure_code IS NOT NULL)
  )
);

CREATE UNIQUE INDEX aimos_action_origin_one_genesis
  ON public.aimos_action_origin_verdicts(company_id, actor_agent_id, actor_valid_from, tool_name, action_scope)
  WHERE previous_verdict_sha256 IS NULL;
CREATE UNIQUE INDEX aimos_action_origin_one_successor
  ON public.aimos_action_origin_verdicts(company_id, previous_verdict_sha256)
  WHERE previous_verdict_sha256 IS NOT NULL;

-- PostgreSQL jsonb is used only after the supplied UTF-8 bytes have been proven
-- equal to this deterministic serializer. OB-1 values are safe integers and
-- bounded-depth JSON, so this recursion has no floating-point ambiguity.
CREATE FUNCTION public.ob2_canonical_json(p_value jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
DECLARE
  v_type text := jsonb_typeof(p_value);
  v_result text;
BEGIN
  IF v_type = 'object' THEN
    SELECT '{' || COALESCE(string_agg(to_json(key)::text || ':' || public.ob2_canonical_json(value), ',' ORDER BY convert_to(key, 'UTF8')), '') || '}'
      INTO v_result FROM jsonb_each(p_value);
    RETURN v_result;
  ELSIF v_type = 'array' THEN
    SELECT '[' || COALESCE(string_agg(public.ob2_canonical_json(value), ',' ORDER BY ordinal), '') || ']'
      INTO v_result FROM jsonb_array_elements(p_value) WITH ORDINALITY AS item(value, ordinal);
    RETURN v_result;
  END IF;
  RETURN p_value::text;
END
$function$;

CREATE FUNCTION public.ob2_exact_json_keys(p_value jsonb, p_expected text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $function$
  SELECT jsonb_typeof(p_value) = 'object'
     AND ARRAY(SELECT key FROM jsonb_object_keys(p_value) key ORDER BY convert_to(key, 'UTF8'))
         = ARRAY(SELECT key FROM unnest(p_expected) key ORDER BY convert_to(key, 'UTF8'));
$function$;

CREATE FUNCTION public.ob2_raw_ed25519_pubkey(p_agent_id text, p_valid_from timestamptz)
RETURNS bytea
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
  SELECT substring(
    decode(rpad(translate(identity.pubkey, '-_', '+/'),
      (length(translate(identity.pubkey, '-_', '+/')) + 3) / 4 * 4, '='), 'base64')
    FROM 13 FOR 32)
  FROM public.agent_identity identity
  WHERE identity.agent_id = p_agent_id AND identity.valid_from = p_valid_from
  LIMIT 1;
$function$;

CREATE FUNCTION public.ob2_origin_database_context_hash(
  p_company_id text,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_database text := current_database();
  v_master text;
  v_signer_count integer;
  v_database_bytes bytea;
  v_company_bytes bytea;
BEGIN
  SELECT fingerprint INTO STRICT v_master FROM public.aimos_master_identity WHERE id = 1;
  IF v_master !~ '^[0-9a-f]{64}$' OR p_signer_cert_fingerprint !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'origin_database_identity_invalid';
  END IF;
  SELECT count(*)::integer INTO v_signer_count
    FROM public.agent_identity identity
   WHERE identity.agent_id = 'housekeeper'
     AND identity.valid_from = p_signer_valid_from
     AND identity.revoked_at IS NULL
     AND identity.valid_from <= clock_timestamp()
     AND identity.valid_until > clock_timestamp()
     AND identity.is_system_role IS TRUE
     AND encode(digest(convert_to(identity.cert, 'UTF8'), 'sha256'), 'hex') = p_signer_cert_fingerprint;
  IF v_signer_count <> 1 THEN RAISE EXCEPTION 'origin_signer_epoch_invalid'; END IF;
  v_database_bytes := convert_to(v_database, 'UTF8');
  v_company_bytes := convert_to(p_company_id, 'UTF8');
  RETURN digest(
    convert_to('hom.aimos.database-origin-context/v1', 'UTF8') || decode('00', 'hex')
    || int4send(octet_length(v_database_bytes)) || v_database_bytes
    || int4send(octet_length(v_company_bytes)) || v_company_bytes
    || decode(v_master, 'hex')
    || decode(p_signer_cert_fingerprint, 'hex')
    || int8send(trunc(extract(epoch FROM p_signer_valid_from) * 1000)::bigint),
    'sha256'
  );
END
$function$;

CREATE FUNCTION public.ob2_origin_ledger_envelope_hash(
  p_object_schema text,
  p_object_sha256 bytea,
  p_prev_ledger_hash bytea,
  p_database_context_sha256 bytea,
  p_authority_profile_sha256 bytea,
  p_signer_agent_id text,
  p_signer_valid_from timestamptz,
  p_signed_at timestamptz
) RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_schema bytea := convert_to(p_object_schema, 'UTF8');
  v_signer bytea := convert_to(p_signer_agent_id, 'UTF8');
BEGIN
  IF octet_length(p_object_sha256) <> 32
     OR (p_prev_ledger_hash IS NOT NULL AND octet_length(p_prev_ledger_hash) <> 32)
     OR octet_length(p_database_context_sha256) <> 32
     OR octet_length(p_authority_profile_sha256) <> 32 THEN
    RAISE EXCEPTION 'origin_ledger_hash_input_invalid';
  END IF;
  RETURN digest(
    convert_to('hom.aimos.origin-ledger-envelope/v1', 'UTF8') || decode('00', 'hex')
    || int4send(octet_length(v_schema)) || v_schema
    || p_object_sha256 || COALESCE(p_prev_ledger_hash, decode(repeat('00', 32), 'hex'))
    || p_database_context_sha256 || p_authority_profile_sha256
    || int4send(octet_length(v_signer)) || v_signer
    || int8send(trunc(extract(epoch FROM p_signer_valid_from) * 1000)::bigint)
    || int8send(trunc(extract(epoch FROM p_signed_at) * 1000)::bigint),
    'sha256'
  );
END
$function$;

CREATE FUNCTION public.ob2_verify_origin_object(
  p_schema text,
  p_body jsonb,
  p_body_bytes bytea,
  p_object_sha256 bytea
) RETURNS void
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_canonical bytea;
BEGIN
  IF p_body->>'schema' IS DISTINCT FROM p_schema THEN RAISE EXCEPTION 'origin_schema_invalid'; END IF;
  v_canonical := convert_to(public.ob2_canonical_json(p_body), 'UTF8');
  IF p_body_bytes <> v_canonical
     OR convert_from(p_body_bytes, 'UTF8')::jsonb <> p_body THEN
    RAISE EXCEPTION 'origin_canonical_bytes_invalid';
  END IF;
  IF digest(convert_to(p_schema, 'UTF8') || decode('00', 'hex')
       || int4send(octet_length(p_body_bytes)) || p_body_bytes, 'sha256') <> p_object_sha256 THEN
    RAISE EXCEPTION 'origin_object_hash_invalid';
  END IF;
END
$function$;

CREATE FUNCTION public.ob2_verify_signed_event(p_event_id uuid, p_company_id text)
RETURNS public.aimos_events
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_event public.aimos_events%ROWTYPE;
  v_pub bytea;
  v_message bytea;
  v_content bytea;
  v_mutation bytea;
BEGIN
  SELECT * INTO v_event FROM public.aimos_events
   WHERE id = p_event_id AND company_id = p_company_id AND proof_required IS TRUE;
  IF NOT FOUND OR v_event.ledger_version <> 1 OR v_event.signed_body IS NULL THEN
    RAISE EXCEPTION 'origin_signed_event_invalid';
  END IF;
  v_content := digest(convert_to(public.ob2_canonical_json(v_event.signed_body), 'UTF8'), 'sha256');
  v_mutation := digest(
    convert_to('AIMOS-EVENT-LINK-v1', 'UTF8') || decode('00', 'hex')
    || v_event.prev_mutation_hash || v_content
    || convert_to(v_event.nonce, 'UTF8') || convert_to(v_event.ts_signed::text, 'UTF8'), 'sha256');
  v_pub := public.ob2_raw_ed25519_pubkey(v_event.signer_agent_id, v_event.signer_valid_from);
  v_message := convert_to(public.ob2_canonical_json(v_event.signed_body)
    || E'\n' || v_event.nonce || E'\n' || v_event.ts_signed::text, 'UTF8');
  IF v_content <> v_event.content_hash OR v_mutation <> v_event.mutation_hash
     OR v_pub IS NULL OR octet_length(v_pub) <> 32
     OR NOT pgsodium.crypto_sign_verify_detached(v_event.sig, v_message, v_pub) THEN
    RAISE EXCEPTION 'origin_signed_event_invalid';
  END IF;
  RETURN v_event;
END
$function$;

CREATE FUNCTION public.ob2_read_origin_ledger_state(p_company_id text)
RETURNS TABLE(
  prev_ledger_hash bytea,
  database_context_sha256 bytea,
  authority_profile_sha256 bytea,
  signer_agent_id text,
  signer_valid_from timestamptz,
  signer_cert_fingerprint text
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_head_count integer;
BEGIN
  IF p_company_id IS NULL OR p_company_id = '' THEN RAISE EXCEPTION 'origin_company_scope_required'; END IF;
  SELECT identity.valid_from,
         encode(digest(convert_to(identity.cert, 'UTF8'), 'sha256'), 'hex')
    INTO signer_valid_from, signer_cert_fingerprint
    FROM public.agent_identity identity
   WHERE identity.agent_id = 'housekeeper' AND identity.revoked_at IS NULL
     AND identity.valid_from <= clock_timestamp() AND identity.valid_until > clock_timestamp()
     AND identity.is_system_role IS TRUE
   ORDER BY identity.valid_from DESC LIMIT 1;
  IF signer_valid_from IS NULL THEN RAISE EXCEPTION 'origin_signer_epoch_invalid'; END IF;
  signer_agent_id := 'housekeeper';
  authority_profile_sha256 := decode('14001dd244e7e3276eb27c145f00abe41ec121908c65a2cf1eef571b922037b3', 'hex');
  SELECT count(*)::integer, (array_agg(entry.ledger_hash))[1]
    INTO v_head_count, prev_ledger_hash
    FROM public.aimos_origin_ledger_entries entry
   WHERE entry.company_id = p_company_id
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_origin_ledger_entries successor
        WHERE successor.company_id = entry.company_id
          AND successor.prev_ledger_hash = entry.ledger_hash
     );
  IF v_head_count > 1 THEN RAISE EXCEPTION 'origin_ledger_existing_fork'; END IF;
  database_context_sha256 := public.ob2_origin_database_context_hash(
    p_company_id, signer_valid_from, signer_cert_fingerprint);
  RETURN NEXT;
END
$function$;

CREATE FUNCTION public.ob2_commit_origin_ledger_entry(
  p_company_id text,
  p_object_schema text,
  p_object_sha256 bytea,
  p_prev_ledger_hash bytea,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text,
  p_authority_profile_sha256 bytea,
  p_signed_at timestamptz,
  p_ledger_signature bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_scope text := current_setting('app.current_client_id', true);
  v_state record;
  v_ledger_hash bytea;
  v_pub bytea;
BEGIN
  IF v_scope IS NULL OR v_scope = '' OR v_scope <> p_company_id THEN
    RAISE EXCEPTION 'origin_company_scope_invalid';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('origin-ledger:' || p_company_id, 0));
  SELECT * INTO v_state FROM public.ob2_read_origin_ledger_state(p_company_id);
  IF v_state.prev_ledger_hash IS DISTINCT FROM p_prev_ledger_hash THEN
    RAISE EXCEPTION 'origin_ledger_predecessor_invalid';
  END IF;
  IF v_state.signer_valid_from <> p_signer_valid_from
     OR v_state.signer_cert_fingerprint <> p_signer_cert_fingerprint
     OR v_state.authority_profile_sha256 <> p_authority_profile_sha256 THEN
    RAISE EXCEPTION 'origin_signer_profile_invalid';
  END IF;
  IF p_signed_at < p_signer_valid_from OR p_signed_at > clock_timestamp() + interval '5 seconds' THEN
    RAISE EXCEPTION 'origin_signed_time_invalid';
  END IF;
  v_ledger_hash := public.ob2_origin_ledger_envelope_hash(
    p_object_schema, p_object_sha256, p_prev_ledger_hash,
    v_state.database_context_sha256, p_authority_profile_sha256,
    'housekeeper', p_signer_valid_from, p_signed_at);
  v_pub := public.ob2_raw_ed25519_pubkey('housekeeper', p_signer_valid_from);
  IF v_pub IS NULL OR octet_length(v_pub) <> 32 OR octet_length(p_ledger_signature) <> 64
     OR NOT pgsodium.crypto_sign_verify_detached(p_ledger_signature, v_ledger_hash, v_pub) THEN
    RAISE EXCEPTION 'origin_ledger_signature_invalid';
  END IF;
  INSERT INTO public.aimos_origin_ledger_entries (
    ledger_hash, company_id, object_schema, object_sha256, prev_ledger_hash,
    database_context_sha256, authority_profile_sha256, signer_agent_id,
    signer_valid_from, signer_cert_fingerprint, signed_at, ledger_signature
  ) VALUES (
    v_ledger_hash, p_company_id, p_object_schema, p_object_sha256,
    p_prev_ledger_hash, v_state.database_context_sha256,
    p_authority_profile_sha256, 'housekeeper', p_signer_valid_from,
    p_signer_cert_fingerprint, p_signed_at, p_ledger_signature
  );
  RETURN v_ledger_hash;
END
$function$;

-- The three typed public writers are added below after the immutable profile.

INSERT INTO public.aimos_origin_family_profiles (
  profile_sha256, schema_id, profile_version, body_json, body_bytes
) VALUES (
  decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),
  'hom.aimos.origin-family-profile/v1', 1,
  '{"action_class_order":["none","inform","act"],"canonicalization":"hom-aimos/canonical-json/v1-safe-integers","classification_authorities":["deterministic_route_schema","deterministic_field_schema","authenticated_tool_schema","system_producer_schema","trusted_monitor_classifier","legacy_successor_review"],"confidentiality_order":["public","internal","confidential","restricted"],"families":[{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input","parent_id":null},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input.executable_instruction","parent_id":"action_input"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input.external_destination","parent_id":"action_input"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"confidential","id":"action_input.financial_value","parent_id":"action_input"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input.resource_target","parent_id":"action_input"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived","parent_id":null},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.housekeeper_derivation","parent_id":"derived"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.reflection","parent_id":"derived"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.summary","parent_id":"derived"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.tool_result","parent_id":"derived"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity","parent_id":null},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity.ownership_assertion","parent_id":"identity"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity.principal_assertion","parent_id":"identity"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity.role_assertion","parent_id":"identity"},{"action_policy":"inform_only","confidentiality_floor":"public","id":"information","parent_id":null},{"action_policy":"inform_only","confidentiality_floor":"public","id":"information.event","parent_id":"information"},{"action_policy":"inform_only","confidentiality_floor":"public","id":"information.fact","parent_id":"information"},{"action_policy":"inform_only","confidentiality_floor":"internal","id":"information.preference","parent_id":"information"},{"action_policy":"inform_only","confidentiality_floor":"internal","id":"information.relationship","parent_id":"information"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret","parent_id":null},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.access_token","parent_id":"secret"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.credential","parent_id":"secret"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.personal_data","parent_id":"secret"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.private_key","parent_id":"secret"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control","parent_id":null},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.authorization_directive","parent_id":"system_control"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.memory_directive","parent_id":"system_control"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.model_configuration","parent_id":"system_control"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.security_policy","parent_id":"system_control"},{"action_policy":"deny_action","confidentiality_floor":"restricted","id":"unknown_protected","parent_id":null}],"family_action_policies":["inform_only","exact_origin_verdict","exact_user_or_provider","exact_configuration_owner","inherit_parents","deny_action"],"family_order":"utf8_lexicographic_ascending","hash":"sha256","ingress_channels":["untrusted_external","agent_self","authenticated_agent","housekeeper_system","authenticated_tool","authenticated_user","system_internal"],"integrity_order":["untrusted","agent","trusted"],"maximum_corroborator_count":16,"maximum_family_count":64,"maximum_parent_count":64,"risk_class_order":["non_consequential","consequential","high_impact"],"schema":"hom.aimos.origin-family-profile/v1","signature":"ed25519","version":1}'::jsonb,
  convert_to('{"action_class_order":["none","inform","act"],"canonicalization":"hom-aimos/canonical-json/v1-safe-integers","classification_authorities":["deterministic_route_schema","deterministic_field_schema","authenticated_tool_schema","system_producer_schema","trusted_monitor_classifier","legacy_successor_review"],"confidentiality_order":["public","internal","confidential","restricted"],"families":[{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input","parent_id":null},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input.executable_instruction","parent_id":"action_input"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input.external_destination","parent_id":"action_input"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"confidential","id":"action_input.financial_value","parent_id":"action_input"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"action_input.resource_target","parent_id":"action_input"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived","parent_id":null},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.housekeeper_derivation","parent_id":"derived"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.reflection","parent_id":"derived"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.summary","parent_id":"derived"},{"action_policy":"inherit_parents","confidentiality_floor":"internal","id":"derived.tool_result","parent_id":"derived"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity","parent_id":null},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity.ownership_assertion","parent_id":"identity"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity.principal_assertion","parent_id":"identity"},{"action_policy":"exact_origin_verdict","confidentiality_floor":"internal","id":"identity.role_assertion","parent_id":"identity"},{"action_policy":"inform_only","confidentiality_floor":"public","id":"information","parent_id":null},{"action_policy":"inform_only","confidentiality_floor":"public","id":"information.event","parent_id":"information"},{"action_policy":"inform_only","confidentiality_floor":"public","id":"information.fact","parent_id":"information"},{"action_policy":"inform_only","confidentiality_floor":"internal","id":"information.preference","parent_id":"information"},{"action_policy":"inform_only","confidentiality_floor":"internal","id":"information.relationship","parent_id":"information"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret","parent_id":null},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.access_token","parent_id":"secret"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.credential","parent_id":"secret"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.personal_data","parent_id":"secret"},{"action_policy":"exact_user_or_provider","confidentiality_floor":"restricted","id":"secret.private_key","parent_id":"secret"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control","parent_id":null},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.authorization_directive","parent_id":"system_control"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.memory_directive","parent_id":"system_control"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.model_configuration","parent_id":"system_control"},{"action_policy":"exact_configuration_owner","confidentiality_floor":"restricted","id":"system_control.security_policy","parent_id":"system_control"},{"action_policy":"deny_action","confidentiality_floor":"restricted","id":"unknown_protected","parent_id":null}],"family_action_policies":["inform_only","exact_origin_verdict","exact_user_or_provider","exact_configuration_owner","inherit_parents","deny_action"],"family_order":"utf8_lexicographic_ascending","hash":"sha256","ingress_channels":["untrusted_external","agent_self","authenticated_agent","housekeeper_system","authenticated_tool","authenticated_user","system_internal"],"integrity_order":["untrusted","agent","trusted"],"maximum_corroborator_count":16,"maximum_family_count":64,"maximum_parent_count":64,"risk_class_order":["non_consequential","consequential","high_impact"],"schema":"hom.aimos.origin-family-profile/v1","signature":"ed25519","version":1}','UTF8')
), (
  decode('14001dd244e7e3276eb27c145f00abe41ec121908c65a2cf1eef571b922037b3','hex'),
  'hom.aimos.origin-ledger-authority-profile/v1', 1,
  '{"canonicalization":"hom-aimos/canonical-json/v1-safe-integers","custody":"application_local_encrypted_file","database_verification":"pgsodium.crypto_sign_verify_detached","hash":"sha256","schema":"hom.aimos.origin-ledger-authority-profile/v1","signature":"ed25519","signer":"housekeeper","signing_input":"hom.aimos.origin-ledger-envelope/v1","version":1}'::jsonb,
  convert_to('{"canonicalization":"hom-aimos/canonical-json/v1-safe-integers","custody":"application_local_encrypted_file","database_verification":"pgsodium.crypto_sign_verify_detached","hash":"sha256","schema":"hom.aimos.origin-ledger-authority-profile/v1","signature":"ed25519","signer":"housekeeper","signing_input":"hom.aimos.origin-ledger-envelope/v1","version":1}','UTF8')
);

INSERT INTO public.aimos_origin_family_definitions
  (profile_sha256, family_id, parent_id, confidentiality_floor, action_policy)
VALUES
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'action_input',NULL,'internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'action_input.executable_instruction','action_input','internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'action_input.external_destination','action_input','internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'action_input.financial_value','action_input','confidential','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'action_input.resource_target','action_input','internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'derived',NULL,'internal','inherit_parents'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'derived.housekeeper_derivation','derived','internal','inherit_parents'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'derived.reflection','derived','internal','inherit_parents'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'derived.summary','derived','internal','inherit_parents'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'derived.tool_result','derived','internal','inherit_parents'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'identity',NULL,'internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'identity.ownership_assertion','identity','internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'identity.principal_assertion','identity','internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'identity.role_assertion','identity','internal','exact_origin_verdict'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'information',NULL,'public','inform_only'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'information.event','information','public','inform_only'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'information.fact','information','public','inform_only'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'information.preference','information','internal','inform_only'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'information.relationship','information','internal','inform_only'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'secret',NULL,'restricted','exact_user_or_provider'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'secret.access_token','secret','restricted','exact_user_or_provider'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'secret.credential','secret','restricted','exact_user_or_provider'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'secret.personal_data','secret','restricted','exact_user_or_provider'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'secret.private_key','secret','restricted','exact_user_or_provider'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'system_control',NULL,'restricted','exact_configuration_owner'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'system_control.authorization_directive','system_control','restricted','exact_configuration_owner'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'system_control.memory_directive','system_control','restricted','exact_configuration_owner'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'system_control.model_configuration','system_control','restricted','exact_configuration_owner'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'system_control.security_policy','system_control','restricted','exact_configuration_owner'),
  (decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex'),'unknown_protected',NULL,'restricted','deny_action');

-- Runtime visibility is company-scoped. There is no write policy because all
-- mutation is exclusively through the typed SECURITY DEFINER functions.
ALTER TABLE public.aimos_origin_ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_origin_ledger_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_memory_origin_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_memory_origin_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_origin_elevations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_origin_elevations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_action_origin_verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_action_origin_verdicts FORCE ROW LEVEL SECURITY;

CREATE POLICY aimos_origin_ledger_company_read ON public.aimos_origin_ledger_entries
  FOR SELECT USING (company_id = current_setting('app.current_client_id', true));
CREATE POLICY aimos_memory_origin_company_read ON public.aimos_memory_origin_bindings
  FOR SELECT USING (company_id = current_setting('app.current_client_id', true));
CREATE POLICY aimos_origin_elevation_company_read ON public.aimos_origin_elevations
  FOR SELECT USING (company_id = current_setting('app.current_client_id', true));
CREATE POLICY aimos_action_origin_verdict_company_read ON public.aimos_action_origin_verdicts
  FOR SELECT USING (company_id = current_setting('app.current_client_id', true));

REVOKE ALL ON public.aimos_origin_family_profiles,
  public.aimos_origin_family_definitions, public.aimos_origin_ledger_entries,
  public.aimos_memory_origin_bindings, public.aimos_origin_elevations,
  public.aimos_action_origin_verdicts FROM PUBLIC, agent_runtime, aimos_app;
GRANT SELECT ON public.aimos_origin_family_profiles,
  public.aimos_origin_family_definitions, public.aimos_origin_ledger_entries,
  public.aimos_memory_origin_bindings, public.aimos_origin_elevations,
  public.aimos_action_origin_verdicts TO agent_runtime;

REVOKE ALL ON FUNCTION public.ob2_canonical_json(jsonb),
  public.ob2_exact_json_keys(jsonb,text[]),
  public.ob2_raw_ed25519_pubkey(text,timestamptz),
  public.ob2_origin_database_context_hash(text,timestamptz,text),
  public.ob2_origin_ledger_envelope_hash(text,bytea,bytea,bytea,bytea,text,timestamptz,timestamptz),
  public.ob2_verify_origin_object(text,jsonb,bytea,bytea),
  public.ob2_verify_signed_event(uuid,text),
  public.ob2_commit_origin_ledger_entry(text,text,bytea,bytea,timestamptz,text,bytea,timestamptz,bytea)
  FROM PUBLIC, agent_runtime, aimos_app;
REVOKE ALL ON FUNCTION public.ob2_read_origin_ledger_state(text) FROM PUBLIC, aimos_app;
GRANT EXECUTE ON FUNCTION public.ob2_read_origin_ledger_state(text) TO agent_runtime;

COMMENT ON TABLE public.aimos_origin_ledger_entries IS
  'OB-2 database-bound, Housekeeper-signed, no-fork authority envelopes for the three portable OB-1 object families.';
