-- AUD-018 explicit exact-wire profile. New definitions only; no data rewrite,
-- historical serializer replacement, role grant, or request-body retention.
-- Object-specific authority checks remain mandatory in constrained writers.
CREATE OR REPLACE FUNCTION public.signed_json_shape_v1(p_value json, p_depth integer)
RETURNS void LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $function$
DECLARE item record; kind text := json_typeof(p_value); decoded text;
BEGIN
  IF p_depth > 32 THEN RAISE EXCEPTION 'signed_json_wire_invalid'; END IF;
  IF kind='object' THEN
    FOR item IN SELECT key,value FROM json_each(p_value) LOOP
      -- json_each decodes property names; PostgreSQL rejects NUL/lone surrogates.
      PERFORM public.signed_json_shape_v1(item.value,p_depth+1);
    END LOOP;
  ELSIF kind='array' THEN
    FOR item IN SELECT value FROM json_array_elements(p_value) LOOP
      PERFORM public.signed_json_shape_v1(item.value,p_depth+1);
    END LOOP;
  ELSIF kind='string' THEN
    decoded := p_value #>> '{}';
  END IF;
END
$function$;

CREATE OR REPLACE FUNCTION public.signed_json_bytes_commitment_v1(p_schema text,p_wire bytea)
RETURNS bytea LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $function$
DECLARE source text; schema_bytes bytea;
BEGIN
  IF p_schema IS NULL OR p_schema COLLATE "C" !~ '^[a-z][a-z0-9._/-]*/v[1-9][0-9]*$'
     OR octet_length(p_schema)>200 THEN RAISE EXCEPTION 'signed_json_schema_invalid'; END IF;
  IF p_wire IS NULL OR octet_length(p_wire)<1 OR octet_length(p_wire)>67108864 THEN
    RAISE EXCEPTION 'signed_json_size_invalid'; END IF;
  BEGIN
    source := convert_from(p_wire,'UTF8');
    IF source IS NOT JSON WITH UNIQUE KEYS THEN RAISE EXCEPTION 'signed_json_wire_invalid'; END IF;
    PERFORM public.signed_json_shape_v1(source::json,0);
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'signed_json_wire_invalid';
  END;
  schema_bytes := convert_to(p_schema,'UTF8');
  RETURN digest(convert_to('hom.aimos.signed-json-bytes/v1','UTF8')||decode('00','hex')
    ||int4send(octet_length(schema_bytes))||schema_bytes||int4send(octet_length(p_wire))||p_wire,'sha256');
END
$function$;
REVOKE ALL ON FUNCTION public.signed_json_shape_v1(json,integer) FROM PUBLIC,agent_runtime,aimos_app;
REVOKE ALL ON FUNCTION public.signed_json_bytes_commitment_v1(text,bytea) FROM PUBLIC,agent_runtime,aimos_app;
