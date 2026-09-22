-- 102-origin-action-verdict-family-order-fix.sql
-- Correct the executable DISTINCT/ORDER BY projection in the already constrained
-- OB-2 verdict writer. No table, privilege, signature, or predicate is relaxed.

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
  v_event public.aimos_events%ROWTYPE;
  v_ledger_hash bytea;
  v_count integer;
  v_value_families text[];
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
    v_elevation := CASE WHEN p_body->>'elevation_sha256' IS NULL THEN NULL ELSE decode(p_body->>'elevation_sha256','hex') END;
    v_user_auth := CASE WHEN p_body->>'user_authorization_sha256' IS NULL THEN NULL ELSE decode(p_body->>'user_authorization_sha256','hex') END;
    v_previous := CASE WHEN p_body->>'previous_verdict_sha256' IS NULL THEN NULL ELSE decode(p_body->>'previous_verdict_sha256','hex') END;
    v_decision := p_body->>'decision';
    v_failure := p_body->>'failure_code';
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'origin_verdict_field_invalid'; END;
  PERFORM public.ob2_validate_family_set(c_family_profile, v_families);
  IF v_actor_fingerprint !~ '^[0-9a-f]{64}$' OR p_body->>'arguments_sha256' !~ '^[0-9a-f]{64}$'
     OR cardinality(v_origins) < 1 OR cardinality(v_origins) > 64
     OR v_origins <> ARRAY(SELECT value FROM unnest(v_origins) value ORDER BY encode(value,'hex'))
     OR cardinality(ARRAY(SELECT DISTINCT value FROM unnest(v_origins) value)) <> cardinality(v_origins)
     OR (v_decision = 'ALLOW' AND v_failure IS NOT NULL)
     OR (v_decision <> 'ALLOW' AND v_failure IS NULL)
     OR (v_decision = 'ALLOW' AND (p_body->>'untrusted_influence')::boolean
         AND v_elevation IS NULL AND v_user_auth IS NULL) THEN
    RAISE EXCEPTION 'origin_verdict_semantics_invalid';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.agent_identity identity
    WHERE identity.agent_id = v_actor AND identity.valid_from = v_actor_valid_from
      AND identity.revoked_at IS NULL
      AND encode(digest(convert_to(identity.cert,'UTF8'),'sha256'),'hex') = v_actor_fingerprint) THEN
    RAISE EXCEPTION 'origin_verdict_actor_invalid';
  END IF;
  SELECT count(*)::integer INTO v_count FROM unnest(v_origins) origin
    JOIN public.aimos_memory_origin_bindings binding ON binding.binding_sha256 = origin
   WHERE binding.company_id = v_company;
  IF v_count <> cardinality(v_origins) THEN RAISE EXCEPTION 'origin_verdict_input_invalid'; END IF;
  IF jsonb_typeof(p_body->'security_values') <> 'array'
     OR jsonb_array_length(p_body->'security_values') < 1
     OR jsonb_array_length(p_body->'security_values') > 64 THEN
    RAISE EXCEPTION 'origin_verdict_security_values_invalid';
  END IF;
  SELECT ARRAY(
    SELECT distinct_value.family
      FROM (
        SELECT DISTINCT family
          FROM jsonb_array_elements(p_body->'security_values') value,
               jsonb_array_elements_text(value->'family_ids') family
      ) distinct_value
     ORDER BY convert_to(distinct_value.family,'UTF8')
  ) INTO v_value_families;
  IF v_value_families <> v_families OR EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_body->'security_values') value
     WHERE NOT public.ob2_exact_json_keys(value, ARRAY['value_sha256','family_ids'])
        OR value->>'value_sha256' !~ '^[0-9a-f]{64}$'
  ) THEN RAISE EXCEPTION 'origin_verdict_security_values_invalid'; END IF;
  IF v_elevation IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.aimos_origin_elevations elevation
     WHERE elevation.elevation_sha256 = v_elevation AND elevation.company_id = v_company
       AND elevation.action_scope = p_body->>'action_scope'
       AND elevation.family_id = ANY(v_families)
       AND (p_body->>'created_at')::timestamptz BETWEEN elevation.valid_from AND elevation.valid_until
  ) THEN RAISE EXCEPTION 'origin_verdict_elevation_invalid'; END IF;
  IF v_user_auth IS NULL AND p_authorization_event_id IS NOT NULL
     OR v_user_auth IS NOT NULL AND p_authorization_event_id IS NULL THEN
    RAISE EXCEPTION 'origin_verdict_authorization_invalid';
  END IF;
  IF p_authorization_event_id IS NOT NULL THEN
    v_event := public.ob2_verify_signed_event(p_authorization_event_id, v_company);
    IF v_event.mutation_hash <> v_user_auth OR v_event.operation <> 'origin_action_authorized' THEN
      RAISE EXCEPTION 'origin_verdict_authorization_invalid';
    END IF;
  END IF;
  IF v_previous IS NULL THEN
    IF EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts prior
      WHERE prior.company_id = v_company AND prior.actor_agent_id = v_actor
        AND prior.actor_valid_from = v_actor_valid_from
        AND prior.tool_name = p_body->>'tool_name' AND prior.action_scope = p_body->>'action_scope') THEN
      RAISE EXCEPTION 'origin_verdict_predecessor_invalid';
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts prior
    WHERE prior.verdict_sha256 = v_previous AND prior.company_id = v_company
      AND prior.actor_agent_id = v_actor AND prior.actor_valid_from = v_actor_valid_from
      AND prior.tool_name = p_body->>'tool_name' AND prior.action_scope = p_body->>'action_scope'
      AND NOT EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts successor
        WHERE successor.previous_verdict_sha256 = prior.verdict_sha256)) THEN
    RAISE EXCEPTION 'origin_verdict_predecessor_invalid';
  END IF;
  v_ledger_hash := public.ob2_commit_origin_ledger_entry(
    v_company, c_schema, p_verdict_sha256, p_prev_ledger_hash,
    p_signer_valid_from, p_signer_cert_fingerprint,
    p_authority_profile_sha256, p_signed_at, p_ledger_signature);
  INSERT INTO public.aimos_action_origin_verdicts (
    verdict_sha256, ledger_hash, company_id, verdict_id, actor_agent_id,
    actor_valid_from, actor_cert_fingerprint, tool_name, action_scope, risk_class,
    arguments_sha256, security_values, family_ids, input_origin_sha256s,
    untrusted_influence, elevation_sha256, user_authorization_sha256,
    authorization_event_id, decision, failure_code, previous_verdict_sha256,
    originated_at, body_json, body_bytes
  ) VALUES (
    p_verdict_sha256, v_ledger_hash, v_company, v_verdict_id, v_actor,
    v_actor_valid_from, v_actor_fingerprint, p_body->>'tool_name',
    p_body->>'action_scope', p_body->>'risk_class', decode(p_body->>'arguments_sha256','hex'),
    p_body->'security_values', v_families, v_origins,
    (p_body->>'untrusted_influence')::boolean, v_elevation, v_user_auth,
    p_authorization_event_id, v_decision, v_failure, v_previous,
    (p_body->>'created_at')::timestamptz, p_body, p_body_bytes
  );
  RETURN v_ledger_hash;
END
$function$;

