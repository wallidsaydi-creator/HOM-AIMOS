-- 114-origin-elevation-exact-selector.sql
-- OB-5: agent_runtime may read elevation rows but must never receive table
-- UPDATE. Consequential-action selection requires a row lock, so this exact
-- database-local selector owns only the bounded FOR UPDATE operation and
-- returns only the matching commitment. The verdict writer independently
-- re-verifies the complete elevation before consuming it.

CREATE OR REPLACE FUNCTION public.select_origin_elevation_v2_for_action(
  p_company text,
  p_value_sha256 bytea,
  p_family_id text,
  p_action_scope text,
  p_risk_class text,
  p_base_origin_sha256s bytea[],
  p_actor_agent_id text,
  p_actor_valid_from timestamptz,
  p_actor_cert_fingerprint text,
  p_request_receipt_mutation_sha256 bytea,
  p_arguments_sha256 bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path=pg_catalog,public
AS $function$
DECLARE
  v_elevation bytea;
BEGIN
  IF p_company IS NULL OR p_company=''
     OR octet_length(p_value_sha256)<>32
     OR p_family_id IS NULL OR p_family_id=''
     OR p_action_scope IS NULL OR p_action_scope=''
     OR p_risk_class IS NULL OR p_risk_class=''
     OR cardinality(p_base_origin_sha256s)<1
     OR cardinality(p_base_origin_sha256s)>64
     OR EXISTS (SELECT 1 FROM unnest(p_base_origin_sha256s) value
                WHERE octet_length(value)<>32)
     OR p_base_origin_sha256s<>ARRAY(
          SELECT value FROM unnest(p_base_origin_sha256s) value
          ORDER BY encode(value,'hex'))
     OR cardinality(ARRAY(
          SELECT DISTINCT value FROM unnest(p_base_origin_sha256s) value))
        <>cardinality(p_base_origin_sha256s)
     OR p_actor_agent_id IS NULL OR p_actor_agent_id=''
     OR p_actor_valid_from IS NULL
     OR p_actor_cert_fingerprint !~ '^[0-9a-f]{64}$'
     OR octet_length(p_request_receipt_mutation_sha256)<>32
     OR octet_length(p_arguments_sha256)<>32
  THEN RAISE EXCEPTION 'origin_elevation_selector_input_invalid'; END IF;

  SELECT elevation.elevation_sha256 INTO v_elevation
    FROM public.aimos_origin_elevations elevation
   WHERE elevation.company_id=p_company
     AND elevation.elevation_schema='hom.aimos.origin-elevation/v2'
     AND elevation.actor_agent_id=p_actor_agent_id
     AND elevation.actor_valid_from=p_actor_valid_from
     AND elevation.actor_cert_fingerprint=p_actor_cert_fingerprint
     AND elevation.request_receipt_mutation_sha256=p_request_receipt_mutation_sha256
     AND elevation.arguments_sha256=p_arguments_sha256
     AND elevation.value_sha256=p_value_sha256
     AND elevation.family_id=p_family_id
     AND elevation.action_scope=p_action_scope
     AND elevation.risk_class=p_risk_class
     AND elevation.base_origin_sha256s=p_base_origin_sha256s
     AND elevation.user_authorization_sha256 IS NULL
     AND elevation.valid_from<=clock_timestamp()
     AND elevation.valid_until>clock_timestamp()
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_action_origin_verdicts consumed
        WHERE consumed.elevation_sha256=elevation.elevation_sha256)
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_origin_elevations sibling
       JOIN public.aimos_action_origin_verdicts consumed
         ON consumed.elevation_sha256=sibling.elevation_sha256
        WHERE sibling.company_id=elevation.company_id
          AND sibling.registry_sha256=elevation.registry_sha256
          AND sibling.action_id=elevation.action_id)
   ORDER BY elevation.valid_until,elevation.elevation_sha256
   FOR UPDATE OF elevation SKIP LOCKED
   LIMIT 1;
  RETURN v_elevation;
END
$function$;

REVOKE ALL ON FUNCTION public.select_origin_elevation_v2_for_action(
  text,bytea,text,text,text,bytea[],text,timestamptz,text,bytea,bytea
) FROM PUBLIC,aimos_app;
GRANT EXECUTE ON FUNCTION public.select_origin_elevation_v2_for_action(
  text,bytea,text,text,text,bytea[],text,timestamptz,text,bytea,bytea
) TO agent_runtime;
