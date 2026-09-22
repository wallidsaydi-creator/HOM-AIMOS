-- 112-origin-corroborator-key-precedence.sql
-- OB-5 successor: make JSON extraction precedence explicit in the existing
-- three-axis corroborator verifier. Migration 103 remains byte-immutable.

CREATE OR REPLACE FUNCTION public.ob2_validate_corroborators(
  p_corroborators jsonb,
  p_threshold integer,
  p_user_authorization_sha256 bytea
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_entry jsonb;
  v_count integer := 0;
  v_prior text := NULL;
  v_key text;
  v_domains text[] := '{}';
  v_upstream text[] := '{}';
BEGIN
  IF jsonb_typeof(p_corroborators) <> 'array' OR jsonb_array_length(p_corroborators) > 16
     OR p_threshold < 2 OR p_threshold > 16 THEN
    RAISE EXCEPTION 'origin_elevation_corroborators_invalid';
  END IF;
  FOR v_entry IN SELECT value FROM jsonb_array_elements(p_corroborators)
    WITH ORDINALITY item(value,ordinal) ORDER BY ordinal LOOP
    IF NOT public.ob2_exact_json_keys(v_entry, ARRAY[
      'principal_id','valid_from','administrative_domain_sha256','upstream_source_sha256','license_sha256'
    ]) OR v_entry->>'administrative_domain_sha256' !~ '^[0-9a-f]{64}$'
       OR v_entry->>'upstream_source_sha256' !~ '^[0-9a-f]{64}$'
       OR v_entry->>'license_sha256' !~ '^[0-9a-f]{64}$' THEN
      RAISE EXCEPTION 'origin_elevation_corroborators_invalid';
    END IF;
    PERFORM (v_entry->>'valid_from')::timestamptz;
    v_key := (v_entry->>'administrative_domain_sha256') || ':'
      || (v_entry->>'upstream_source_sha256') || ':' || (v_entry->>'principal_id')
      || ':' || (v_entry->>'valid_from');
    IF v_prior IS NOT NULL AND convert_to(v_prior,'UTF8') >= convert_to(v_key,'UTF8') THEN
      RAISE EXCEPTION 'origin_elevation_corroborator_order_invalid';
    END IF;
    IF (v_entry->>'administrative_domain_sha256') = ANY(v_domains)
       OR (v_entry->>'upstream_source_sha256') = ANY(v_upstream) THEN
      RAISE EXCEPTION 'origin_elevation_corroborator_independence_invalid';
    END IF;
    v_prior := v_key;
    v_domains := array_append(v_domains,v_entry->>'administrative_domain_sha256');
    v_upstream := array_append(v_upstream,v_entry->>'upstream_source_sha256');
    v_count := v_count + 1;
  END LOOP;
  IF p_user_authorization_sha256 IS NULL AND v_count < p_threshold THEN
    RAISE EXCEPTION 'origin_elevation_authority_invalid';
  END IF;
END
$function$;

REVOKE ALL ON FUNCTION public.ob2_validate_corroborators(jsonb,integer,bytea)
  FROM PUBLIC,agent_runtime,aimos_app;
