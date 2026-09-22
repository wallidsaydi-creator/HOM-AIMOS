-- 105-origin-security-family-byte-order.sql
-- Make the database aggregate-family union use the frozen UTF-8 byte order,
-- independent of database locale/collation.

CREATE OR REPLACE FUNCTION public.ob2_validate_security_values(
  p_values jsonb,
  p_profile_sha256 bytea,
  p_aggregate_families text[]
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_entry jsonb;
  v_hash text;
  v_prior text := NULL;
  v_families text[];
  v_union text[];
BEGIN
  IF jsonb_typeof(p_values) <> 'array' OR jsonb_array_length(p_values) < 1
     OR jsonb_array_length(p_values) > 64 THEN
    RAISE EXCEPTION 'origin_verdict_security_values_invalid';
  END IF;
  FOR v_entry IN SELECT value FROM jsonb_array_elements(p_values) WITH ORDINALITY item(value,ordinal) ORDER BY ordinal LOOP
    IF NOT public.ob2_exact_json_keys(v_entry,ARRAY['value_sha256','family_ids'])
       OR v_entry->>'value_sha256' !~ '^[0-9a-f]{64}$' THEN
      RAISE EXCEPTION 'origin_verdict_security_values_invalid';
    END IF;
    v_hash := v_entry->>'value_sha256';
    IF v_prior IS NOT NULL AND convert_to(v_prior,'UTF8') >= convert_to(v_hash,'UTF8') THEN
      RAISE EXCEPTION 'origin_verdict_security_value_order_invalid';
    END IF;
    v_families := public.ob2_json_text_array(v_entry->'family_ids');
    PERFORM public.ob2_validate_family_set(p_profile_sha256,v_families);
    v_prior := v_hash;
  END LOOP;
  SELECT ARRAY(
    SELECT distinct_family.family
      FROM (
        SELECT DISTINCT family
          FROM jsonb_array_elements(p_values) value,
               jsonb_array_elements_text(value->'family_ids') family
      ) distinct_family
     ORDER BY convert_to(distinct_family.family,'UTF8')
  ) INTO v_union;
  IF v_union <> p_aggregate_families THEN
    RAISE EXCEPTION 'origin_verdict_security_value_family_invalid';
  END IF;
END
$function$;

