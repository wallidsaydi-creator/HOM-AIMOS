-- 107-origin-elevation-license-binding.sql
-- OB-5: an origin elevation is usable authority only when every corroborator
-- license is a verified signed event over the exact value, family, action,
-- complete base-origin set and validity window. Principal, administrative
-- domain and upstream-source independence are all required independently.

CREATE OR REPLACE FUNCTION public.commit_origin_elevation_v1(
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
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_schema constant text := 'hom.aimos.origin-elevation/v1';
  c_family_profile constant bytea := decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex');
  c_license_schema constant text := 'hom.aimos.origin-corroboration-license/v1';
  c_user_schema constant text := 'hom.aimos.origin-elevation-authorization/v1';
  v_company text;
  v_elevation_id uuid;
  v_value bytea;
  v_family text;
  v_origins bytea[];
  v_corroborators jsonb;
  v_threshold integer;
  v_user_auth bytea;
  v_event public.aimos_events%ROWTYPE;
  v_license public.aimos_events%ROWTYPE;
  v_entry jsonb;
  v_ledger_hash bytea;
  v_count integer;
  v_distinct_principals integer;
  v_distinct_domains integer;
  v_distinct_upstream integer;
BEGIN
  PERFORM public.ob2_verify_origin_object(c_schema,p_body,p_body_bytes,p_elevation_sha256);
  IF NOT public.ob2_exact_json_keys(p_body,ARRAY[
    'schema','company_id','elevation_id','value_sha256','family_id','action_scope',
    'risk_class','base_origin_sha256s','corroborators','threshold',
    'user_authorization_sha256','maximum_uses','valid_from','valid_until','created_at'
  ]) THEN RAISE EXCEPTION 'origin_elevation_shape_invalid'; END IF;
  BEGIN
    v_company := p_body->>'company_id';
    v_elevation_id := (p_body->>'elevation_id')::uuid;
    v_value := decode(p_body->>'value_sha256','hex');
    v_family := p_body->>'family_id';
    v_origins := public.ob2_json_hash_array(p_body->'base_origin_sha256s');
    v_corroborators := p_body->'corroborators';
    v_threshold := (p_body->>'threshold')::integer;
    v_user_auth := CASE WHEN p_body->>'user_authorization_sha256' IS NULL THEN NULL
      ELSE decode(p_body->>'user_authorization_sha256','hex') END;
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'origin_elevation_field_invalid'; END;
  IF octet_length(v_value) <> 32 OR cardinality(v_origins) < 1 OR cardinality(v_origins) > 64
     OR v_origins <> ARRAY(SELECT value FROM unnest(v_origins) value ORDER BY encode(value,'hex'))
     OR cardinality(ARRAY(SELECT DISTINCT value FROM unnest(v_origins) value)) <> cardinality(v_origins)
     OR (p_body->>'maximum_uses')::integer <> 1
     OR (p_body->>'valid_until')::timestamptz <= (p_body->>'valid_from')::timestamptz
     OR (p_body->>'created_at')::timestamptz > (p_body->>'valid_until')::timestamptz THEN
    RAISE EXCEPTION 'origin_elevation_field_invalid';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.aimos_origin_family_definitions
    WHERE profile_sha256=c_family_profile AND family_id=v_family) THEN
    RAISE EXCEPTION 'origin_elevation_family_invalid';
  END IF;
  PERFORM public.ob2_validate_corroborators(v_corroborators,v_threshold,v_user_auth);
  SELECT count(*)::integer INTO v_count FROM unnest(v_origins) origin
    JOIN public.aimos_memory_origin_bindings binding ON binding.binding_sha256=origin
   WHERE binding.company_id=v_company;
  IF v_count <> cardinality(v_origins) THEN RAISE EXCEPTION 'origin_elevation_base_invalid'; END IF;

  SELECT count(*)::integer,
         count(DISTINCT entry->>'principal_id')::integer,
         count(DISTINCT entry->>'administrative_domain_sha256')::integer,
         count(DISTINCT entry->>'upstream_source_sha256')::integer
    INTO v_count,v_distinct_principals,v_distinct_domains,v_distinct_upstream
    FROM jsonb_array_elements(v_corroborators) entry
   WHERE public.ob2_exact_json_keys(entry,ARRAY[
     'principal_id','valid_from','administrative_domain_sha256','upstream_source_sha256','license_sha256'
   ]) AND entry->>'principal_id' <> ''
     AND entry->>'administrative_domain_sha256' ~ '^[0-9a-f]{64}$'
     AND entry->>'upstream_source_sha256' ~ '^[0-9a-f]{64}$'
     AND entry->>'license_sha256' ~ '^[0-9a-f]{64}$';
  IF v_count <> jsonb_array_length(v_corroborators)
     OR v_count <> v_distinct_principals
     OR v_count <> v_distinct_domains OR v_count <> v_distinct_upstream
     OR v_threshold < 2 OR v_threshold > 16
     OR (v_user_auth IS NULL AND v_count < v_threshold) THEN
    RAISE EXCEPTION 'origin_elevation_authority_invalid';
  END IF;

  IF v_user_auth IS NULL AND p_authorization_event_id IS NOT NULL
     OR v_user_auth IS NOT NULL AND p_authorization_event_id IS NULL THEN
    RAISE EXCEPTION 'origin_elevation_authorization_binding_invalid';
  END IF;
  IF v_user_auth IS NULL THEN
    FOR v_entry IN SELECT value FROM jsonb_array_elements(v_corroborators) LOOP
      SELECT * INTO v_license FROM public.aimos_events
       WHERE company_id=v_company
         AND mutation_hash=decode(v_entry->>'license_sha256','hex')
         AND operation='origin_corroboration_licensed';
      IF NOT FOUND THEN RAISE EXCEPTION 'origin_elevation_corroborator_license_invalid'; END IF;
      v_license := public.ob2_verify_signed_event(v_license.id,v_company);
      IF v_license.metadata->>'schema' <> c_license_schema
         OR v_license.authority_kind <> 'housekeeper_observation_of_verified_request'
         OR v_license.signed_body->>'actor_agent_id' <> v_entry->>'principal_id'
         OR (v_license.signed_body->>'actor_valid_from')::timestamptz
            <> (v_entry->>'valid_from')::timestamptz
         OR v_license.metadata->>'value_sha256' <> encode(v_value,'hex')
         OR v_license.metadata->>'family_id' <> v_family
         OR v_license.metadata->>'action_scope' <> p_body->>'action_scope'
         OR v_license.metadata->>'risk_class' <> p_body->>'risk_class'
         OR v_license.metadata->'base_origin_sha256s' <> p_body->'base_origin_sha256s'
         OR v_license.metadata->>'administrative_domain_sha256'
            <> v_entry->>'administrative_domain_sha256'
         OR v_license.metadata->>'upstream_source_sha256'
            <> v_entry->>'upstream_source_sha256'
         OR (v_license.metadata->>'maximum_uses')::integer <> 1
         OR (v_license.metadata->>'valid_until')::timestamptz
            < (p_body->>'valid_until')::timestamptz
         OR EXISTS (
           SELECT 1 FROM public.aimos_origin_elevations prior,
                jsonb_array_elements(prior.corroborators) prior_entry
            WHERE prior.company_id=v_company
              AND prior_entry->>'license_sha256'=v_entry->>'license_sha256')
      THEN RAISE EXCEPTION 'origin_elevation_corroborator_license_invalid'; END IF;
    END LOOP;
  ELSE
    v_event := public.ob2_verify_signed_event(p_authorization_event_id,v_company);
    IF v_event.mutation_hash <> v_user_auth
       OR v_event.operation <> 'origin_elevation_authorized'
       OR v_event.metadata->>'schema' <> c_user_schema
       OR v_event.metadata->>'value_sha256' <> encode(v_value,'hex')
       OR v_event.metadata->>'family_id' <> v_family
       OR v_event.metadata->>'action_scope' <> p_body->>'action_scope'
       OR v_event.metadata->>'risk_class' <> p_body->>'risk_class'
       OR v_event.metadata->'base_origin_sha256s' <> p_body->'base_origin_sha256s'
       OR (v_event.metadata->>'maximum_uses')::integer <> 1
       OR (v_event.metadata->>'valid_until')::timestamptz
          < (p_body->>'valid_until')::timestamptz
       OR EXISTS (SELECT 1 FROM public.aimos_origin_elevations prior
         WHERE prior.user_authorization_sha256=v_user_auth)
    THEN RAISE EXCEPTION 'origin_elevation_authorization_binding_invalid'; END IF;
  END IF;

  v_ledger_hash := public.ob2_commit_origin_ledger_entry(
    v_company,c_schema,p_elevation_sha256,p_prev_ledger_hash,
    p_signer_valid_from,p_signer_cert_fingerprint,
    p_authority_profile_sha256,p_signed_at,p_ledger_signature);
  INSERT INTO public.aimos_origin_elevations (
    elevation_sha256,ledger_hash,company_id,elevation_id,value_sha256,
    family_id,action_scope,risk_class,base_origin_sha256s,corroborators,
    threshold,user_authorization_sha256,authorization_event_id,maximum_uses,
    valid_from,valid_until,originated_at,body_json,body_bytes
  ) VALUES (
    p_elevation_sha256,v_ledger_hash,v_company,v_elevation_id,v_value,
    v_family,p_body->>'action_scope',p_body->>'risk_class',v_origins,
    v_corroborators,v_threshold,v_user_auth,p_authorization_event_id,1,
    (p_body->>'valid_from')::timestamptz,(p_body->>'valid_until')::timestamptz,
    (p_body->>'created_at')::timestamptz,p_body,p_body_bytes);
  RETURN v_ledger_hash;
END
$function$;

REVOKE ALL ON FUNCTION public.commit_origin_elevation_v1(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) FROM PUBLIC,aimos_app;
GRANT EXECUTE ON FUNCTION public.commit_origin_elevation_v1(
  jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea
) TO agent_runtime;
