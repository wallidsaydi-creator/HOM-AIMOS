-- 109-origin-trust-registry-and-elevation-v2.sql
-- OB-5: provider-agnostic trusted-source observations and actor/request-bound
-- single-use corroboration elevations. Housekeeper verifies sources but never
-- counts as a corroborator.

ALTER TABLE public.aimos_origin_elevations
  ADD COLUMN IF NOT EXISTS elevation_schema text NOT NULL DEFAULT 'hom.aimos.origin-elevation/v1',
  ADD COLUMN IF NOT EXISTS actor_agent_id text,
  ADD COLUMN IF NOT EXISTS actor_valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS actor_cert_fingerprint text,
  ADD COLUMN IF NOT EXISTS request_receipt_mutation_sha256 bytea,
  ADD COLUMN IF NOT EXISTS action_id text,
  ADD COLUMN IF NOT EXISTS arguments_sha256 bytea,
  ADD COLUMN IF NOT EXISTS registry_sha256 bytea;

DO $ob5_elevation_v2_constraints$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='aimos_origin_elevation_schema_check') THEN
    ALTER TABLE public.aimos_origin_elevations ADD CONSTRAINT aimos_origin_elevation_schema_check
      CHECK (elevation_schema IN ('hom.aimos.origin-elevation/v1','hom.aimos.origin-elevation/v2'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='aimos_origin_elevation_v2_complete') THEN
    ALTER TABLE public.aimos_origin_elevations ADD CONSTRAINT aimos_origin_elevation_v2_complete CHECK (
      elevation_schema <> 'hom.aimos.origin-elevation/v2' OR (
        actor_agent_id IS NOT NULL AND actor_valid_from IS NOT NULL
        AND actor_cert_fingerprint ~ '^[0-9a-f]{64}$'
        AND octet_length(request_receipt_mutation_sha256)=32
        AND action_id ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'
        AND octet_length(arguments_sha256)=32 AND octet_length(registry_sha256)=32
        AND user_authorization_sha256 IS NULL AND authorization_event_id IS NULL
      )
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='aimos_origin_elevation_v2_actor_fk') THEN
    ALTER TABLE public.aimos_origin_elevations ADD CONSTRAINT aimos_origin_elevation_v2_actor_fk
      FOREIGN KEY (actor_agent_id,actor_valid_from)
      REFERENCES public.agent_identity(agent_id,valid_from) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='aimos_origin_elevation_v2_request_fk') THEN
    ALTER TABLE public.aimos_origin_elevations ADD CONSTRAINT aimos_origin_elevation_v2_request_fk
      FOREIGN KEY (request_receipt_mutation_sha256)
      REFERENCES public.aimos_request_receipts(mutation_hash) ON DELETE RESTRICT;
  END IF;
END
$ob5_elevation_v2_constraints$;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_origin_elevation_v2_request_action_unique
  ON public.aimos_origin_elevations
  (company_id,actor_agent_id,actor_valid_from,request_receipt_mutation_sha256,action_id);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_origin_elevation_v2_registry_action_unique
  ON public.aimos_origin_elevations (company_id,registry_sha256,action_id);

CREATE OR REPLACE FUNCTION public.ob5_verify_corroboration_license_v2(
  p_entry jsonb,
  p_company text,
  p_actor jsonb,
  p_request_receipt_mutation_sha256 bytea,
  p_action_id text,
  p_arguments_sha256 bytea,
  p_value_sha256 bytea,
  p_family_id text,
  p_action_scope text,
  p_risk_class text,
  p_base_origin_sha256s bytea[],
  p_valid_until timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path=pg_catalog,public
AS $function$
DECLARE
  v_license public.aimos_events%ROWTYPE;
  v_observation public.aimos_events%ROWTYPE;
  v_activation public.aimos_events%ROWTYPE;
  v_effect_start public.aimos_events%ROWTYPE;
  v_effect_terminal public.aimos_events%ROWTYPE;
  v_authority jsonb;
  v_registry jsonb;
BEGIN
  IF NOT public.ob2_exact_json_keys(p_entry,ARRAY[
    'principal_id','valid_from','administrative_domain_sha256',
    'upstream_source_sha256','license_sha256'
  ]) OR p_entry->>'principal_id'='housekeeper'
     OR p_entry->>'administrative_domain_sha256' !~ '^[0-9a-f]{64}$'
     OR p_entry->>'upstream_source_sha256' !~ '^[0-9a-f]{64}$'
     OR p_entry->>'license_sha256' !~ '^[0-9a-f]{64}$'
  THEN RAISE EXCEPTION 'origin_elevation_corroborator_license_invalid'; END IF;

  SELECT * INTO v_license FROM public.aimos_events
   WHERE company_id=p_company
     AND mutation_hash=decode(p_entry->>'license_sha256','hex')
     AND operation='origin_corroboration_licensed';
  IF NOT FOUND THEN RAISE EXCEPTION 'origin_elevation_corroborator_license_invalid'; END IF;
  v_license := public.ob2_verify_signed_event(v_license.id,p_company);
  IF v_license.signer_agent_id<>'housekeeper'
     OR v_license.authority_kind<>'housekeeper_autonomous'
     OR v_license.signed_body->>'actor_agent_id' IS NOT NULL
     OR v_license.metadata->>'schema'<>'hom.aimos.origin-corroboration-license/v2'
     OR v_license.metadata->>'principal_id'<>p_entry->>'principal_id'
     OR (v_license.metadata->>'principal_valid_from')::timestamptz
        <> (p_entry->>'valid_from')::timestamptz
     OR v_license.metadata->>'administrative_domain_sha256'
        <>p_entry->>'administrative_domain_sha256'
     OR v_license.metadata->>'upstream_source_sha256'
        <>p_entry->>'upstream_source_sha256'
     OR v_license.metadata->'actor'<>p_actor
     OR decode(v_license.metadata->>'request_receipt_mutation_sha256','hex')
        <>p_request_receipt_mutation_sha256
     OR v_license.metadata->>'action_id'<>p_action_id
     OR decode(v_license.metadata->>'arguments_sha256','hex')<>p_arguments_sha256
     OR decode(v_license.metadata->>'value_sha256','hex')<>p_value_sha256
     OR v_license.metadata->>'family_id'<>p_family_id
     OR v_license.metadata->>'action_scope'<>p_action_scope
     OR v_license.metadata->>'risk_class'<>p_risk_class
     OR public.ob2_json_hash_array(v_license.metadata->'base_origin_sha256s')
        <>p_base_origin_sha256s
     OR (v_license.metadata->>'maximum_uses')::integer<>1
     OR (v_license.metadata->>'valid_until')::timestamptz<p_valid_until
     OR v_license.metadata->>'action_authority'<>'exact_single_use_elevation_input_only'
  THEN RAISE EXCEPTION 'origin_elevation_corroborator_license_invalid'; END IF;

  v_observation := public.ob2_verify_signed_event(
    (v_license.metadata->>'source_observation_event_id')::uuid,p_company);
  IF v_observation.id<>v_license.parent_event_id
     OR encode(v_observation.mutation_hash,'hex')
        <>v_license.metadata->>'source_observation_mutation_sha256'
     OR v_observation.operation<>'origin_source_observed'
     OR v_observation.signer_agent_id<>'housekeeper'
     OR v_observation.authority_kind<>'housekeeper_autonomous'
     OR v_observation.metadata->>'schema'<>'hom.aimos.origin-source-observation/v1'
     OR v_observation.metadata->>'principal_id'<>p_entry->>'principal_id'
     OR v_observation.metadata->>'administrative_domain_sha256'
        <>p_entry->>'administrative_domain_sha256'
     OR v_observation.metadata->>'upstream_source_sha256'
        <>p_entry->>'upstream_source_sha256'
     OR v_observation.metadata->>'claim_sha256'<>v_license.metadata->>'claim_sha256'
     OR v_observation.metadata->>'config_mutation_sha256'
        <>v_license.metadata->>'config_mutation_sha256'
     OR v_observation.metadata->>'registry_sha256'<>v_license.metadata->>'registry_sha256'
     OR v_observation.metadata->>'action_id'<>p_action_id
     OR v_observation.metadata->>'evidence_marker_sha256' !~ '^[0-9a-f]{64}$'
     OR v_observation.metadata->>'document_sha256' !~ '^[0-9a-f]{64}$'
     OR v_observation.metadata->>'tls_peer_certificate_sha256' !~ '^[0-9a-f]{64}$'
     OR v_observation.metadata->>'tls_peer_spki_sha256' !~ '^[0-9a-f]{64}$'
     OR v_observation.metadata->>'material_effect_start_mutation_sha256' !~ '^[0-9a-f]{64}$'
     OR v_observation.metadata->>'material_effect_terminal_mutation_sha256' !~ '^[0-9a-f]{64}$'
     OR (v_observation.metadata->>'trust_established_for_exact_claim_only')::boolean IS NOT TRUE
     OR (v_observation.metadata->>'action_authority')::boolean IS NOT FALSE
  THEN RAISE EXCEPTION 'origin_elevation_source_observation_invalid'; END IF;

  v_effect_start := public.ob2_verify_signed_event(
    (v_observation.metadata->>'material_effect_start_event_id')::uuid,p_company);
  v_effect_terminal := public.ob2_verify_signed_event(
    (v_observation.metadata->>'material_effect_terminal_event_id')::uuid,p_company);
  IF v_effect_start.operation<>'material_effect_started'
     OR encode(v_effect_start.mutation_hash,'hex')
        <>v_observation.metadata->>'material_effect_start_mutation_sha256'
     OR v_effect_start.metadata->>'effect_kind'<>'external'
     OR v_effect_start.metadata->>'effect_operation'<>'origin_source_fetch'
     OR v_effect_terminal.operation<>'material_effect_terminal'
     OR v_effect_terminal.parent_event_id<>v_effect_start.id
     OR encode(v_effect_terminal.mutation_hash,'hex')
        <>v_observation.metadata->>'material_effect_terminal_mutation_sha256'
     OR v_effect_terminal.metadata->>'start_event_id'<>v_effect_start.id::text
     OR v_effect_terminal.metadata->>'start_mutation_hash'
        <>encode(v_effect_start.mutation_hash,'hex')
     OR v_effect_terminal.metadata->>'disposition'<>'SUCCEEDED'
     OR v_effect_terminal.metadata->>'result_class'<>'origin_source_verified'
  THEN RAISE EXCEPTION 'origin_elevation_source_effect_invalid'; END IF;

  v_activation := public.ob2_verify_signed_event(v_observation.parent_event_id,p_company);
  IF v_activation.operation<>'origin_trust_registry_activated'
     OR v_activation.signer_agent_id<>'housekeeper'
     OR v_activation.authority_kind<>'housekeeper_autonomous'
     OR v_activation.metadata->>'schema'<>'hom.aimos.origin-trust-registry-activation/v1'
     OR v_activation.metadata->>'config_key'<>'ORIGIN_TRUST_REGISTRY'
     OR v_activation.metadata->>'config_mutation_sha256'
        <>v_observation.metadata->>'config_mutation_sha256'
     OR v_activation.metadata->>'registry_sha256'
        <>v_observation.metadata->>'registry_sha256'
     OR (v_activation.metadata->>'provider_agnostic')::boolean IS NOT TRUE
     OR (v_activation.metadata->>'action_authority')::boolean IS NOT FALSE
  THEN RAISE EXCEPTION 'origin_elevation_registry_activation_invalid'; END IF;

  v_registry := v_activation.metadata->'registry';
  IF v_registry->>'registry_sha256'<>v_activation.metadata->>'registry_sha256'
     OR v_registry#>>'{action,action_id}'<>p_action_id
     OR decode(v_registry#>>'{action,arguments_sha256}','hex')<>p_arguments_sha256
     OR decode(v_registry#>>'{action,value_sha256}','hex')<>p_value_sha256
     OR v_registry#>>'{action,primary_family_id}'<>p_family_id
     OR v_registry#>>'{action,action_scope}'<>p_action_scope
     OR v_registry#>>'{action,risk_class}'<>p_risk_class
     OR v_registry#>>'{claim,claim_sha256}'<>v_observation.metadata->>'claim_sha256'
  THEN RAISE EXCEPTION 'origin_elevation_registry_binding_invalid'; END IF;

  SELECT authority INTO v_authority
    FROM jsonb_array_elements(v_registry->'authorities') authority
   WHERE authority->>'authority_id'=v_observation.metadata->>'authority_id';
  IF v_authority IS NULL
     OR v_authority->>'principal_id'<>p_entry->>'principal_id'
     OR (v_authority->>'valid_from')::timestamptz<>(p_entry->>'valid_from')::timestamptz
     OR v_authority->>'administrative_domain_sha256'
        <>p_entry->>'administrative_domain_sha256'
     OR v_authority->>'upstream_source_sha256'<>p_entry->>'upstream_source_sha256'
     OR v_authority->>'evidence_marker_sha256'
        <>v_observation.metadata->>'evidence_marker_sha256'
     OR encode(digest(convert_to(v_authority->>'url','UTF8'),'sha256'),'hex')
        <>v_observation.metadata->>'source_url_sha256'
  THEN RAISE EXCEPTION 'origin_elevation_registry_authority_invalid'; END IF;
END
$function$;

CREATE OR REPLACE FUNCTION public.commit_origin_elevation_v2(
  p_body jsonb,
  p_body_bytes bytea,
  p_elevation_sha256 bytea,
  p_authorization_event_id uuid,
  p_prev_ledger_hash bytea,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text,
  p_authority_profile_sha256 bytea,
  p_signed_at timestamptz,
  p_ledger_signature bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public
AS $function$
DECLARE
  c_schema constant text := 'hom.aimos.origin-elevation/v2';
  c_family_profile constant bytea := decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex');
  v_company text;
  v_elevation_id uuid;
  v_actor text;
  v_actor_valid_from timestamptz;
  v_actor_fingerprint text;
  v_request bytea;
  v_action_id text;
  v_arguments bytea;
  v_value bytea;
  v_family text;
  v_origins bytea[];
  v_corroborators jsonb;
  v_threshold integer;
  v_valid_from timestamptz;
  v_valid_until timestamptz;
  v_created_at timestamptz;
  v_registry bytea;
  v_ledger_hash bytea;
  v_count integer;
  v_distinct_principals integer;
  v_distinct_domains integer;
  v_distinct_upstream integer;
  v_entry jsonb;
  v_receipt public.aimos_request_receipts%ROWTYPE;
BEGIN
  IF p_authorization_event_id IS NOT NULL THEN
    RAISE EXCEPTION 'origin_elevation_v2_authorization_event_forbidden';
  END IF;
  PERFORM public.ob2_verify_origin_object(c_schema,p_body,p_body_bytes,p_elevation_sha256);
  IF NOT public.ob2_exact_json_keys(p_body,ARRAY[
    'schema','company_id','elevation_id','actor','request_receipt_mutation_sha256',
    'action_id','arguments_sha256','value_sha256','family_id','action_scope',
    'risk_class','base_origin_sha256s','corroborators','threshold','maximum_uses',
    'valid_from','valid_until','created_at'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'actor',ARRAY[
    'agent_id','valid_from','cert_fingerprint_sha256'
  ]) THEN RAISE EXCEPTION 'origin_elevation_v2_shape_invalid'; END IF;
  BEGIN
    v_company:=p_body->>'company_id';
    v_elevation_id:=(p_body->>'elevation_id')::uuid;
    v_actor:=p_body#>>'{actor,agent_id}';
    v_actor_valid_from:=(p_body#>>'{actor,valid_from}')::timestamptz;
    v_actor_fingerprint:=p_body#>>'{actor,cert_fingerprint_sha256}';
    v_request:=decode(p_body->>'request_receipt_mutation_sha256','hex');
    v_action_id:=p_body->>'action_id';
    v_arguments:=decode(p_body->>'arguments_sha256','hex');
    v_value:=decode(p_body->>'value_sha256','hex');
    v_family:=p_body->>'family_id';
    v_origins:=public.ob2_json_hash_array(p_body->'base_origin_sha256s');
    v_corroborators:=p_body->'corroborators';
    v_threshold:=(p_body->>'threshold')::integer;
    v_valid_from:=(p_body->>'valid_from')::timestamptz;
    v_valid_until:=(p_body->>'valid_until')::timestamptz;
    v_created_at:=(p_body->>'created_at')::timestamptz;
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'origin_elevation_v2_field_invalid'; END;

  IF octet_length(v_request)<>32 OR octet_length(v_arguments)<>32
     OR octet_length(v_value)<>32 OR v_actor_fingerprint !~ '^[0-9a-f]{64}$'
     OR v_action_id !~ '^[a-z0-9][a-z0-9._:-]{0,127}$'
     OR cardinality(v_origins)<1 OR cardinality(v_origins)>64
     OR v_origins<>ARRAY(SELECT value FROM unnest(v_origins) value ORDER BY encode(value,'hex'))
     OR cardinality(ARRAY(SELECT DISTINCT value FROM unnest(v_origins) value))<>cardinality(v_origins)
     OR (p_body->>'maximum_uses')::integer<>1
     OR v_valid_until<=v_valid_from OR v_created_at>v_valid_until
     OR v_valid_until>v_created_at+interval '5 minutes'
  THEN RAISE EXCEPTION 'origin_elevation_v2_field_invalid'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.aimos_origin_family_definitions
    WHERE profile_sha256=c_family_profile AND family_id=v_family) THEN
    RAISE EXCEPTION 'origin_elevation_family_invalid';
  END IF;
  PERFORM public.ob2_validate_corroborators(v_corroborators,v_threshold,NULL::bytea);
  SELECT count(*)::integer,count(DISTINCT entry->>'principal_id')::integer,
         count(DISTINCT entry->>'administrative_domain_sha256')::integer,
         count(DISTINCT entry->>'upstream_source_sha256')::integer
    INTO v_count,v_distinct_principals,v_distinct_domains,v_distinct_upstream
    FROM jsonb_array_elements(v_corroborators) entry;
  IF v_count<>v_distinct_principals OR v_count<>v_distinct_domains
     OR v_count<>v_distinct_upstream OR v_count<v_threshold
  THEN RAISE EXCEPTION 'origin_elevation_authority_invalid'; END IF;

  SELECT * INTO v_receipt FROM public.aimos_request_receipts
   WHERE company_id=v_company AND mutation_hash=v_request;
  IF NOT FOUND OR v_receipt.actor_agent_id<>v_actor
     OR v_receipt.actor_valid_from<>v_actor_valid_from
     OR v_receipt.cert_fingerprint<>v_actor_fingerprint
  THEN RAISE EXCEPTION 'origin_elevation_request_invalid'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.agent_identity identity
    WHERE identity.agent_id=v_actor AND identity.valid_from=v_actor_valid_from
      AND identity.valid_from<=v_created_at AND identity.valid_until>v_created_at
      AND encode(digest(convert_to(identity.cert,'UTF8'),'sha256'),'hex')=v_actor_fingerprint
      AND NOT EXISTS (SELECT 1 FROM public.aimos_agent_revocation_events revoked
        WHERE revoked.agent_id=identity.agent_id AND revoked.agent_valid_from=identity.valid_from
          AND revoked.ts_signed<=extract(epoch FROM v_created_at)))
  THEN RAISE EXCEPTION 'origin_elevation_actor_invalid'; END IF;
  SELECT count(*)::integer INTO v_count FROM unnest(v_origins) origin
    JOIN public.aimos_memory_origin_bindings binding ON binding.binding_sha256=origin
   WHERE binding.company_id=v_company;
  IF v_count<>cardinality(v_origins) THEN RAISE EXCEPTION 'origin_elevation_base_invalid'; END IF;

  FOR v_entry IN SELECT value FROM jsonb_array_elements(v_corroborators) LOOP
    PERFORM public.ob5_verify_corroboration_license_v2(
      v_entry,v_company,p_body->'actor',v_request,v_action_id,v_arguments,
      v_value,v_family,p_body->>'action_scope',p_body->>'risk_class',
      v_origins,v_valid_until);
  END LOOP;
  SELECT decode((v_license.metadata->>'registry_sha256'),'hex') INTO v_registry
    FROM public.aimos_events v_license
   WHERE v_license.company_id=v_company
     AND v_license.mutation_hash=decode(v_corroborators->0->>'license_sha256','hex');
  IF octet_length(v_registry)<>32 THEN RAISE EXCEPTION 'origin_elevation_registry_invalid'; END IF;
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(v_corroborators) next_entry
      JOIN public.aimos_events license
        ON license.company_id=v_company
       AND license.mutation_hash=decode(next_entry->>'license_sha256','hex')
     WHERE license.metadata->>'registry_sha256'<>encode(v_registry,'hex')
  ) THEN RAISE EXCEPTION 'origin_elevation_registry_mixed'; END IF;
  IF EXISTS (SELECT 1 FROM public.aimos_origin_elevations prior,
      jsonb_array_elements(prior.corroborators) prior_entry,
      jsonb_array_elements(v_corroborators) next_entry
    WHERE prior.company_id=v_company
      AND prior_entry->>'license_sha256'=next_entry->>'license_sha256')
  THEN RAISE EXCEPTION 'origin_elevation_license_replayed'; END IF;

  v_ledger_hash:=public.ob2_commit_origin_ledger_entry(
    v_company,c_schema,p_elevation_sha256,p_prev_ledger_hash,
    p_signer_valid_from,p_signer_cert_fingerprint,p_authority_profile_sha256,
    p_signed_at,p_ledger_signature);
  INSERT INTO public.aimos_origin_elevations(
    elevation_sha256,ledger_hash,company_id,elevation_id,value_sha256,
    family_id,action_scope,risk_class,base_origin_sha256s,corroborators,
    threshold,user_authorization_sha256,authorization_event_id,maximum_uses,
    valid_from,valid_until,originated_at,body_json,body_bytes,elevation_schema,
    actor_agent_id,actor_valid_from,actor_cert_fingerprint,
    request_receipt_mutation_sha256,action_id,arguments_sha256,registry_sha256
  ) VALUES (
    p_elevation_sha256,v_ledger_hash,v_company,v_elevation_id,v_value,
    v_family,p_body->>'action_scope',p_body->>'risk_class',v_origins,v_corroborators,
    v_threshold,NULL,NULL,1,v_valid_from,v_valid_until,v_created_at,p_body,p_body_bytes,
    c_schema,v_actor,v_actor_valid_from,v_actor_fingerprint,v_request,v_action_id,
    v_arguments,v_registry
  );
  RETURN v_ledger_hash;
END
$function$;

CREATE OR REPLACE FUNCTION public.ob5_verify_elevation_for_verdict_v2(
  p_elevation bytea,
  p_company text,
  p_actor text,
  p_actor_valid_from timestamptz,
  p_actor_fingerprint text,
  p_request_receipt_mutation_sha256 bytea,
  p_arguments_sha256 bytea,
  p_value_sha256 bytea,
  p_family_id text,
  p_action_scope text,
  p_risk_class text,
  p_memory_origins bytea[],
  p_created_at timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path=pg_catalog,public
AS $function$
DECLARE
  v_elevation public.aimos_origin_elevations%ROWTYPE;
  v_entry jsonb;
BEGIN
  SELECT * INTO v_elevation FROM public.aimos_origin_elevations
   WHERE elevation_sha256=p_elevation AND company_id=p_company FOR UPDATE;
  IF NOT FOUND OR v_elevation.elevation_schema<>'hom.aimos.origin-elevation/v2'
     OR v_elevation.actor_agent_id<>p_actor
     OR v_elevation.actor_valid_from<>p_actor_valid_from
     OR v_elevation.actor_cert_fingerprint<>p_actor_fingerprint
     OR v_elevation.request_receipt_mutation_sha256<>p_request_receipt_mutation_sha256
     OR v_elevation.arguments_sha256<>p_arguments_sha256
     OR v_elevation.value_sha256<>p_value_sha256
     OR v_elevation.family_id<>p_family_id
     OR v_elevation.action_scope<>p_action_scope
     OR v_elevation.risk_class<>p_risk_class
     OR v_elevation.base_origin_sha256s<>p_memory_origins
     OR p_created_at<v_elevation.valid_from OR p_created_at>=v_elevation.valid_until
     OR EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts prior
       WHERE prior.elevation_sha256=p_elevation)
  THEN RAISE EXCEPTION 'origin_verdict_elevation_invalid'; END IF;
  FOR v_entry IN SELECT value FROM jsonb_array_elements(v_elevation.corroborators) LOOP
    PERFORM public.ob5_verify_corroboration_license_v2(
      v_entry,p_company,jsonb_build_object(
        'agent_id',p_actor,'valid_from',to_char(p_actor_valid_from AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'cert_fingerprint_sha256',p_actor_fingerprint),
      p_request_receipt_mutation_sha256,v_elevation.action_id,p_arguments_sha256,
      p_value_sha256,p_family_id,p_action_scope,p_risk_class,p_memory_origins,
      v_elevation.valid_until);
  END LOOP;
END
$function$;

REVOKE ALL ON FUNCTION public.ob5_verify_corroboration_license_v2(
  jsonb,text,jsonb,bytea,text,bytea,bytea,text,text,text,bytea[],timestamptz
) FROM PUBLIC,aimos_app,agent_runtime;
REVOKE ALL ON FUNCTION public.ob5_verify_elevation_for_verdict_v2(
  bytea,text,text,timestamptz,text,bytea,bytea,bytea,text,text,text,bytea[],timestamptz
) FROM PUBLIC,aimos_app,agent_runtime;
REVOKE ALL ON FUNCTION public.commit_origin_elevation_v2(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) FROM PUBLIC,aimos_app;
REVOKE EXECUTE ON FUNCTION public.commit_origin_elevation_v1(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) FROM agent_runtime;
GRANT EXECUTE ON FUNCTION public.commit_origin_elevation_v2(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) TO agent_runtime;

CREATE OR REPLACE FUNCTION public.commit_action_origin_verdict_v1(
  p_body jsonb,
  p_body_bytes bytea,
  p_verdict_sha256 bytea,
  p_authorization_event_id uuid,
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
  c_schema constant text := 'hom.aimos.action-origin-verdict/v1';
  c_family_profile constant bytea := decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex');
  c_input_schema constant text := 'hom.aimos.consequential-action-input/v1';
  c_authorization_schema constant text := 'hom.aimos.consequential-action-authorization/v1';
  v_company text;
  v_verdict_id uuid;
  v_actor text;
  v_actor_valid_from timestamptz;
  v_actor_fingerprint text;
  v_families text[];
  v_origins bytea[];
  v_elevation bytea;
  v_user_auth bytea;
  v_previous bytea;
  v_decision text;
  v_failure text;
  v_input_event public.aimos_events%ROWTYPE;
  v_input_event_id uuid;
  v_auth_event public.aimos_events%ROWTYPE;
  v_claim_event public.aimos_events%ROWTYPE;
  v_elevation_row public.aimos_origin_elevations%ROWTYPE;
  v_license_event public.aimos_events%ROWTYPE;
  v_ledger_hash bytea;
  v_value_hash bytea;
  v_value_families text[];
  v_memory_origins bytea[];
  v_entry jsonb;
  v_count integer;
  v_distinct_principals integer;
  v_created_at timestamptz;
BEGIN
  PERFORM public.ob2_verify_origin_object(c_schema, p_body, p_body_bytes, p_verdict_sha256);
  IF NOT public.ob2_exact_json_keys(p_body, ARRAY[
    'schema','company_id','verdict_id','actor','tool_name','action_scope','risk_class',
    'arguments_sha256','security_values','family_ids','input_origin_sha256s',
    'untrusted_influence','elevation_sha256','user_authorization_sha256','decision',
    'failure_code','previous_verdict_sha256','created_at'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'actor', ARRAY[
    'agent_id','valid_from','cert_fingerprint_sha256'
  ]) THEN RAISE EXCEPTION 'origin_verdict_shape_invalid'; END IF;
  BEGIN
    v_company := p_body->>'company_id';
    v_verdict_id := (p_body->>'verdict_id')::uuid;
    v_actor := p_body#>>'{actor,agent_id}';
    v_actor_valid_from := (p_body#>>'{actor,valid_from}')::timestamptz;
    v_actor_fingerprint := p_body#>>'{actor,cert_fingerprint_sha256}';
    v_families := public.ob2_json_text_array(p_body->'family_ids');
    v_origins := public.ob2_json_hash_array(p_body->'input_origin_sha256s');
    v_elevation := CASE WHEN p_body->>'elevation_sha256' IS NULL THEN NULL
      ELSE decode(p_body->>'elevation_sha256','hex') END;
    v_user_auth := CASE WHEN p_body->>'user_authorization_sha256' IS NULL THEN NULL
      ELSE decode(p_body->>'user_authorization_sha256','hex') END;
    v_previous := CASE WHEN p_body->>'previous_verdict_sha256' IS NULL THEN NULL
      ELSE decode(p_body->>'previous_verdict_sha256','hex') END;
    v_decision := p_body->>'decision';
    v_failure := p_body->>'failure_code';
    v_created_at := (p_body->>'created_at')::timestamptz;
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'origin_verdict_field_invalid'; END;

  PERFORM public.ob2_validate_family_set(c_family_profile, v_families);
  IF v_actor_fingerprint !~ '^[0-9a-f]{64}$'
     OR p_body->>'arguments_sha256' !~ '^[0-9a-f]{64}$'
     OR cardinality(v_origins) <> 1
     OR (v_decision = 'ALLOW' AND v_failure IS NOT NULL)
     OR (v_decision <> 'ALLOW' AND v_failure IS NULL)
     OR v_decision NOT IN ('ALLOW','DENY','INDETERMINATE')
     OR v_failure IS NOT NULL AND v_failure NOT IN (
       'origin_missing','origin_invalid','family_missing','family_policy_unsatisfied',
       'input_attribution_indeterminate','untrusted_influence_unlicensed',
       'corroboration_insufficient','corroboration_not_independent',
       'user_authorization_missing','user_authorization_invalid',
       'user_authorization_replayed','action_substitution','scope_invalid',
       'identity_epoch_invalid','evidence_expired_or_revoked')
     OR v_elevation IS NOT NULL AND v_user_auth IS NOT NULL
     OR v_decision <> 'ALLOW' AND (v_elevation IS NOT NULL OR v_user_auth IS NOT NULL)
     OR v_decision = 'ALLOW' AND (p_body->>'untrusted_influence')::boolean
        AND v_elevation IS NULL AND v_user_auth IS NULL
     OR v_decision = 'ALLOW' AND NOT (p_body->>'untrusted_influence')::boolean
        AND (v_elevation IS NOT NULL OR v_user_auth IS NOT NULL) THEN
    RAISE EXCEPTION 'origin_verdict_semantics_invalid';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.agent_identity identity
     WHERE identity.agent_id=v_actor AND identity.valid_from=v_actor_valid_from
       AND identity.valid_from<=v_created_at AND identity.valid_until>v_created_at
       AND NOT EXISTS (
         SELECT 1 FROM public.aimos_agent_revocation_events revoked
          WHERE revoked.agent_id=identity.agent_id
            AND revoked.agent_valid_from=identity.valid_from
            AND revoked.ts_signed<=extract(epoch FROM v_created_at))
       AND encode(digest(convert_to(identity.cert,'UTF8'),'sha256'),'hex')=v_actor_fingerprint
  ) THEN RAISE EXCEPTION 'origin_verdict_actor_invalid'; END IF;

  SELECT id INTO v_input_event_id
    FROM public.aimos_events
   WHERE company_id=v_company AND mutation_hash=v_origins[1]
     AND operation='origin_action_input_observed';
  IF NOT FOUND THEN RAISE EXCEPTION 'origin_verdict_input_invalid'; END IF;
  v_input_event := public.ob2_verify_signed_event(v_input_event_id, v_company);
  IF v_input_event.operation <> 'origin_action_input_observed'
     OR v_input_event.metadata->>'schema' <> c_input_schema
     OR v_input_event.metadata->>'tool' <> p_body->>'tool_name'
     OR v_input_event.metadata->>'action_scope' <> p_body->>'action_scope'
     OR v_input_event.metadata->>'risk_class' <> p_body->>'risk_class'
     OR v_input_event.metadata->>'arguments_sha256' <> p_body->>'arguments_sha256'
     OR v_input_event.metadata->>'security_value_sha256'
        <> p_body#>>'{security_values,0,value_sha256}'
     OR v_input_event.metadata->'security_value_family_ids' <> p_body->'family_ids'
     OR (v_input_event.metadata->>'untrusted_influence')::boolean
        <> (p_body->>'untrusted_influence')::boolean
     OR v_input_event.metadata->>'actor_agent_id' <> v_actor
     OR (v_input_event.metadata->>'actor_valid_from')::timestamptz <> v_actor_valid_from
     OR v_input_event.signed_body->>'actor_agent_id' <> v_actor
     OR (v_input_event.signed_body->>'actor_valid_from')::timestamptz <> v_actor_valid_from
     OR NOT (v_input_event.authority_kind='housekeeper_observation_of_verified_request'
       OR v_actor='housekeeper' AND v_input_event.authority_kind='housekeeper_autonomous')
     OR v_input_event.metadata->>'native_input_snapshot_sha256'
        <> v_input_event.metadata#>>'{native_input_snapshot,input_sha256}'
     OR v_input_event.metadata->>'native_input_snapshot_sha256'
        <> encode(digest(convert_to(public.ob2_canonical_json(
          (v_input_event.metadata->'native_input_snapshot') - 'input_sha256'), 'UTF8'),'sha256'),'hex')
  THEN RAISE EXCEPTION 'origin_verdict_input_binding_invalid'; END IF;

  IF jsonb_typeof(p_body->'security_values') <> 'array'
     OR jsonb_array_length(p_body->'security_values') <> 1 THEN
    RAISE EXCEPTION 'origin_verdict_security_values_invalid';
  END IF;
  PERFORM public.ob2_validate_security_values(
    p_body->'security_values', c_family_profile, v_families);
  v_value_hash := decode(p_body#>>'{security_values,0,value_sha256}','hex');
  SELECT ARRAY(
    SELECT distinct_family.family FROM (
      SELECT DISTINCT family
        FROM jsonb_array_elements(p_body->'security_values') value,
             jsonb_array_elements_text(value->'family_ids') family
    ) distinct_family ORDER BY convert_to(distinct_family.family,'UTF8')
  ) INTO v_value_families;
  IF v_value_families <> v_families THEN
    RAISE EXCEPTION 'origin_verdict_security_values_invalid';
  END IF;

  SELECT COALESCE(array_agg(decode(origin_hash,'hex') ORDER BY origin_hash),ARRAY[]::bytea[])
    INTO v_memory_origins
    FROM (
      SELECT DISTINCT origin_hash
        FROM jsonb_array_elements(v_input_event.metadata->'input_memory_origins') memory,
             jsonb_array_elements_text(memory->'origin_sha256s') origin_hash
    ) origins;

  IF v_elevation IS NOT NULL THEN
    PERFORM public.ob5_verify_elevation_for_verdict_v2(
      v_elevation,v_company,v_actor,v_actor_valid_from,v_actor_fingerprint,
      decode(v_input_event.metadata->>'request_receipt_mutation_sha256','hex'),
      decode(p_body->>'arguments_sha256','hex'),v_value_hash,
      v_input_event.metadata->>'security_value_primary_family_id',
      p_body->>'action_scope',p_body->>'risk_class',v_memory_origins,v_created_at
    );
  END IF;

  IF v_user_auth IS NULL AND p_authorization_event_id IS NOT NULL
     OR v_user_auth IS NOT NULL AND p_authorization_event_id IS NULL THEN
    RAISE EXCEPTION 'origin_verdict_authorization_invalid';
  END IF;
  IF p_authorization_event_id IS NOT NULL THEN
    v_auth_event := public.ob2_verify_signed_event(p_authorization_event_id,v_company);
    IF v_auth_event.mutation_hash <> v_user_auth
       OR v_auth_event.operation <> 'origin_action_authorized'
       OR v_auth_event.metadata->>'schema' <> c_authorization_schema
       OR v_auth_event.signed_body->>'actor_agent_id' <> v_actor
       OR (v_auth_event.signed_body->>'actor_valid_from')::timestamptz <> v_actor_valid_from
       OR v_auth_event.metadata->>'tool' <> p_body->>'tool_name'
       OR v_auth_event.metadata->>'action_scope' <> p_body->>'action_scope'
       OR v_auth_event.metadata->>'risk_class' <> p_body->>'risk_class'
       OR v_auth_event.metadata->>'arguments_sha256' <> p_body->>'arguments_sha256'
       OR v_auth_event.metadata->>'security_value_sha256' <> encode(v_value_hash,'hex')
       OR v_auth_event.metadata->>'input_origin_sha256' <> encode(v_origins[1],'hex')
       OR v_auth_event.metadata->>'prior_action_commitment_sha256' <> encode(v_origins[1],'hex')
       OR (v_auth_event.metadata->>'maximum_uses')::integer <> 1
       OR v_created_at < to_timestamp(v_auth_event.ts_signed)
       OR v_created_at >= (v_auth_event.metadata->>'valid_until')::timestamptz
       OR (v_auth_event.metadata->>'valid_until')::timestamptz
          > to_timestamp(v_auth_event.ts_signed) + interval '5 minutes'
       OR v_auth_event.parent_event_id::text
          <> v_auth_event.metadata->>'approval_claim_event_id'
       OR v_auth_event.key <> v_auth_event.parent_event_id::text
       OR EXISTS (
         SELECT 1 FROM public.aimos_action_origin_verdicts prior
          WHERE prior.user_authorization_sha256=v_user_auth)
    THEN RAISE EXCEPTION 'origin_verdict_authorization_invalid'; END IF;
    v_claim_event := public.ob2_verify_signed_event(v_auth_event.parent_event_id,v_company);
    IF v_claim_event.operation <> 'tool_approval_execution_claimed'
       OR encode(v_claim_event.mutation_hash,'hex')
          <> v_auth_event.metadata->>'approval_claim_mutation_sha256'
       OR v_claim_event.metadata->>'tool' <> p_body->>'tool_name'
       OR v_claim_event.metadata->>'args_sha256' <> p_body->>'arguments_sha256'
       OR v_claim_event.agent_id <> v_auth_event.agent_id
    THEN RAISE EXCEPTION 'origin_verdict_authorization_invalid'; END IF;
  END IF;

  IF v_previous IS NULL THEN
    IF EXISTS (
      SELECT 1 FROM public.aimos_action_origin_verdicts prior
       WHERE prior.company_id=v_company AND prior.actor_agent_id=v_actor
         AND prior.actor_valid_from=v_actor_valid_from
         AND prior.tool_name=p_body->>'tool_name'
         AND prior.action_scope=p_body->>'action_scope'
    ) THEN RAISE EXCEPTION 'origin_verdict_predecessor_invalid'; END IF;
  ELSIF NOT EXISTS (
    SELECT 1 FROM public.aimos_action_origin_verdicts prior
     WHERE prior.verdict_sha256=v_previous AND prior.company_id=v_company
       AND prior.actor_agent_id=v_actor AND prior.actor_valid_from=v_actor_valid_from
       AND prior.tool_name=p_body->>'tool_name'
       AND prior.action_scope=p_body->>'action_scope'
       AND NOT EXISTS (
         SELECT 1 FROM public.aimos_action_origin_verdicts successor
          WHERE successor.previous_verdict_sha256=prior.verdict_sha256)
  ) THEN RAISE EXCEPTION 'origin_verdict_predecessor_invalid'; END IF;

  v_ledger_hash := public.ob2_commit_origin_ledger_entry(
    v_company,c_schema,p_verdict_sha256,p_prev_ledger_hash,
    p_signer_valid_from,p_signer_cert_fingerprint,
    p_authority_profile_sha256,p_signed_at,p_ledger_signature);
  INSERT INTO public.aimos_action_origin_verdicts (
    verdict_sha256,ledger_hash,company_id,verdict_id,actor_agent_id,
    actor_valid_from,actor_cert_fingerprint,tool_name,action_scope,risk_class,
    arguments_sha256,security_values,family_ids,input_origin_sha256s,
    untrusted_influence,elevation_sha256,user_authorization_sha256,
    authorization_event_id,decision,failure_code,previous_verdict_sha256,
    originated_at,body_json,body_bytes
  ) VALUES (
    p_verdict_sha256,v_ledger_hash,v_company,v_verdict_id,v_actor,
    v_actor_valid_from,v_actor_fingerprint,p_body->>'tool_name',
    p_body->>'action_scope',p_body->>'risk_class',decode(p_body->>'arguments_sha256','hex'),
    p_body->'security_values',v_families,v_origins,
    (p_body->>'untrusted_influence')::boolean,v_elevation,v_user_auth,
    p_authorization_event_id,v_decision,v_failure,v_previous,
    v_created_at,p_body,p_body_bytes
  );
  RETURN v_ledger_hash;
END
$function$;

REVOKE ALL ON FUNCTION public.commit_action_origin_verdict_v1(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) FROM PUBLIC, aimos_app;
GRANT EXECUTE ON FUNCTION public.commit_action_origin_verdict_v1(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) TO agent_runtime;
