-- 106-consequential-action-verdict-binding.sql
-- OB-5: make the existing action-verdict writer independently bind the exact
-- typed value projection, complete signed input observation, elevation or
-- fresh single-use authorization, and no-fork verdict head.

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
    SELECT * INTO v_elevation_row
      FROM public.aimos_origin_elevations elevation
     WHERE elevation.elevation_sha256=v_elevation
       AND elevation.company_id=v_company
     FOR UPDATE;
    IF NOT FOUND OR v_elevation_row.value_sha256 <> v_value_hash
       OR v_elevation_row.action_scope <> p_body->>'action_scope'
       OR v_elevation_row.risk_class <> p_body->>'risk_class'
       OR v_elevation_row.family_id
          <> v_input_event.metadata->>'security_value_primary_family_id'
       OR v_elevation_row.base_origin_sha256s <> v_memory_origins
       OR v_created_at < v_elevation_row.valid_from
       OR v_created_at >= v_elevation_row.valid_until
       OR EXISTS (
         SELECT 1 FROM public.aimos_action_origin_verdicts prior
          WHERE prior.elevation_sha256=v_elevation)
    THEN RAISE EXCEPTION 'origin_verdict_elevation_invalid'; END IF;

    SELECT count(DISTINCT entry->>'principal_id')::integer
      INTO v_distinct_principals
      FROM jsonb_array_elements(v_elevation_row.corroborators) entry;
    IF v_distinct_principals <> jsonb_array_length(v_elevation_row.corroborators)
       OR v_distinct_principals < v_elevation_row.threshold THEN
      RAISE EXCEPTION 'origin_verdict_elevation_invalid';
    END IF;
    FOR v_entry IN SELECT value FROM jsonb_array_elements(v_elevation_row.corroborators) LOOP
      SELECT * INTO v_license_event
        FROM public.aimos_events
       WHERE company_id=v_company
         AND mutation_hash=decode(v_entry->>'license_sha256','hex')
         AND operation='origin_corroboration_licensed';
      IF NOT FOUND THEN RAISE EXCEPTION 'origin_verdict_corroborator_license_invalid'; END IF;
      v_license_event := public.ob2_verify_signed_event(v_license_event.id,v_company);
      IF v_license_event.signed_body->>'actor_agent_id' <> v_entry->>'principal_id'
         OR (v_license_event.signed_body->>'actor_valid_from')::timestamptz
            <> (v_entry->>'valid_from')::timestamptz
         OR v_license_event.authority_kind <> 'housekeeper_observation_of_verified_request'
         OR v_license_event.metadata->>'value_sha256' <> encode(v_value_hash,'hex')
         OR v_license_event.metadata->>'family_id' <> v_elevation_row.family_id
         OR v_license_event.metadata->>'action_scope' <> v_elevation_row.action_scope
         OR v_license_event.metadata->>'risk_class' <> v_elevation_row.risk_class
         OR v_license_event.metadata->>'administrative_domain_sha256'
            <> v_entry->>'administrative_domain_sha256'
         OR v_license_event.metadata->>'upstream_source_sha256'
            <> v_entry->>'upstream_source_sha256'
      THEN RAISE EXCEPTION 'origin_verdict_corroborator_license_invalid'; END IF;
    END LOOP;
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
