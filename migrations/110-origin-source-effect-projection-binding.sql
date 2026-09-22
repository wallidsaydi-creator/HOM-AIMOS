-- 110-origin-source-effect-projection-binding.sql
-- OB-5 successor: bind the source observation's exact document/TLS projection
-- to the already signed material-effect start and terminal hashes. Migration
-- 109 is retained byte-for-byte after live application.

CREATE OR REPLACE FUNCTION public.ob5_verify_source_effect_projection_v1(
  p_entry jsonb,
  p_company text
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
  v_expected_target bytea;
  v_expected_input bytea;
  v_expected_result bytea;
BEGIN
  IF NOT public.ob2_exact_json_keys(p_entry,ARRAY[
    'principal_id','valid_from','administrative_domain_sha256',
    'upstream_source_sha256','license_sha256'
  ]) OR p_entry->>'license_sha256' !~ '^[0-9a-f]{64}$'
  THEN RAISE EXCEPTION 'origin_source_effect_projection_entry_invalid'; END IF;

  SELECT * INTO v_license FROM public.aimos_events
   WHERE company_id=p_company
     AND mutation_hash=decode(p_entry->>'license_sha256','hex')
     AND operation='origin_corroboration_licensed';
  IF NOT FOUND THEN RAISE EXCEPTION 'origin_source_effect_projection_license_invalid'; END IF;
  v_license := public.ob2_verify_signed_event(v_license.id,p_company);
  v_observation := public.ob2_verify_signed_event(
    (v_license.metadata->>'source_observation_event_id')::uuid,p_company);
  v_activation := public.ob2_verify_signed_event(v_observation.parent_event_id,p_company);
  v_effect_start := public.ob2_verify_signed_event(
    (v_observation.metadata->>'material_effect_start_event_id')::uuid,p_company);
  v_effect_terminal := public.ob2_verify_signed_event(
    (v_observation.metadata->>'material_effect_terminal_event_id')::uuid,p_company);
  v_registry := v_activation.metadata->'registry';

  SELECT authority INTO v_authority
    FROM jsonb_array_elements(v_registry->'authorities') authority
   WHERE authority->>'authority_id'=v_observation.metadata->>'authority_id';
  IF v_authority IS NULL
     OR v_authority->>'principal_id'<>p_entry->>'principal_id'
  THEN RAISE EXCEPTION 'origin_source_effect_projection_authority_invalid'; END IF;

  v_expected_target := digest(
    convert_to('HOM-AIMOS-MATERIAL-EFFECT-TARGET-v1','UTF8')
    || decode('00','hex') || convert_to('external','UTF8')
    || decode('00','hex') || convert_to(v_authority->>'url','UTF8'),
    'sha256');
  v_expected_input := digest(convert_to(public.ob2_canonical_json(
    jsonb_build_object(
      'registry_sha256',v_observation.metadata->>'registry_sha256',
      'action_id',v_observation.metadata->>'action_id',
      'authority_id',v_observation.metadata->>'authority_id',
      'claim_sha256',v_observation.metadata->>'claim_sha256',
      'evidence_marker_sha256',v_observation.metadata->>'evidence_marker_sha256',
      'max_bytes',(v_authority->>'max_bytes')::integer
    )), 'UTF8'),'sha256');
  v_expected_result := digest(convert_to(public.ob2_canonical_json(
    jsonb_build_object(
      'document_sha256',v_observation.metadata->>'document_sha256',
      'document_bytes',(v_observation.metadata->>'document_bytes')::integer,
      'tls_peer_certificate_sha256',v_observation.metadata->>'tls_peer_certificate_sha256',
      'tls_peer_spki_sha256',v_observation.metadata->>'tls_peer_spki_sha256',
      'evidence_marker_sha256',v_observation.metadata->>'evidence_marker_sha256'
    )), 'UTF8'),'sha256');

  IF v_effect_start.operation<>'material_effect_started'
     OR v_effect_start.metadata->>'effect_kind'<>'external'
     OR v_effect_start.metadata->>'effect_operation'<>'origin_source_fetch'
     OR decode(v_effect_start.metadata->>'target_sha256','hex')<>v_expected_target
     OR decode(v_effect_start.metadata->>'input_sha256','hex')<>v_expected_input
     OR v_effect_terminal.operation<>'material_effect_terminal'
     OR v_effect_terminal.parent_event_id<>v_effect_start.id
     OR v_effect_terminal.metadata->>'start_event_id'<>v_effect_start.id::text
     OR v_effect_terminal.metadata->>'start_mutation_hash'
        <>encode(v_effect_start.mutation_hash,'hex')
     OR v_effect_terminal.metadata->>'target_sha256'
        <>v_effect_start.metadata->>'target_sha256'
     OR v_effect_terminal.metadata->>'input_sha256'
        <>v_effect_start.metadata->>'input_sha256'
     OR v_effect_terminal.metadata->>'disposition'<>'SUCCEEDED'
     OR v_effect_terminal.metadata->>'result_class'<>'origin_source_verified'
     OR decode(v_effect_terminal.metadata->>'result_sha256','hex')<>v_expected_result
  THEN RAISE EXCEPTION 'origin_source_effect_projection_binding_invalid'; END IF;
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
    PERFORM public.ob5_verify_source_effect_projection_v1(v_entry,p_company);
  END LOOP;
END
$function$;

REVOKE ALL ON FUNCTION public.ob5_verify_source_effect_projection_v1(jsonb,text)
  FROM PUBLIC,aimos_app,agent_runtime;
REVOKE ALL ON FUNCTION public.ob5_verify_elevation_for_verdict_v2(
  bytea,text,text,timestamptz,text,bytea,bytea,bytea,text,text,text,bytea[],timestamptz
) FROM PUBLIC,aimos_app,agent_runtime;
