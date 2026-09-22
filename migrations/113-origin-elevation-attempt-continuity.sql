-- 113-origin-elevation-attempt-continuity.sql
-- OB-5: permit a fresh corroboration attempt only after every prior attempt for
-- the exact registry/action has expired unused. One consumed attempt closes the
-- action permanently. The writer serializes this rule before ledger commit.

DROP INDEX public.aimos_origin_elevation_v2_registry_action_unique;
CREATE INDEX aimos_origin_elevation_v2_registry_action_lookup
  ON public.aimos_origin_elevations (company_id,registry_sha256,action_id,valid_until);

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

  PERFORM pg_advisory_xact_lock(hashtextextended(
    'origin-registry-action:' || v_company || ':' || encode(v_registry,'hex') || ':' || v_action_id,0));
  IF EXISTS (SELECT 1 FROM public.aimos_origin_elevations prior
      JOIN public.aimos_action_origin_verdicts verdict
        ON verdict.elevation_sha256=prior.elevation_sha256
    WHERE prior.company_id=v_company AND prior.registry_sha256=v_registry
      AND prior.action_id=v_action_id)
  THEN RAISE EXCEPTION 'origin_elevation_action_already_consumed'; END IF;
  IF EXISTS (SELECT 1 FROM public.aimos_origin_elevations prior
    WHERE prior.company_id=v_company AND prior.registry_sha256=v_registry
      AND prior.action_id=v_action_id AND prior.valid_until>v_created_at)
  THEN RAISE EXCEPTION 'origin_elevation_action_attempt_pending'; END IF;

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
     OR EXISTS (SELECT 1 FROM public.aimos_origin_elevations sibling
       JOIN public.aimos_action_origin_verdicts prior
         ON prior.elevation_sha256=sibling.elevation_sha256
       WHERE sibling.company_id=v_elevation.company_id
         AND sibling.registry_sha256=v_elevation.registry_sha256
         AND sibling.action_id=v_elevation.action_id
         AND sibling.elevation_sha256<>v_elevation.elevation_sha256)
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
    PERFORM public.ob5_verify_source_effect_projection_v1(v_entry,p_company);
  END LOOP;
END
$function$;

REVOKE ALL ON FUNCTION public.commit_origin_elevation_v2(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) FROM PUBLIC,aimos_app;
GRANT EXECUTE ON FUNCTION public.commit_origin_elevation_v2(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) TO agent_runtime;
REVOKE ALL ON FUNCTION public.ob5_verify_elevation_for_verdict_v2(
  bytea,text,text,timestamptz,text,bytea,bytea,bytea,text,text,text,bytea[],timestamptz
) FROM PUBLIC,aimos_app,agent_runtime;
