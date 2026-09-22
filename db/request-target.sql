-- Current native request form 5. No historical row or signature is rewritten.
CREATE OR REPLACE FUNCTION public.request_target_valid_v5(p_target text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER IMMUTABLE
SET search_path=pg_catalog,public AS $function$
DECLARE duplicate_key boolean;
BEGIN
  IF p_target IS NULL OR p_target NOT LIKE '/%' OR p_target LIKE '//%'
    OR p_target ~ '[^!-~]|[#\\]' OR p_target ~ '%(?![0-9A-Fa-f]{2})' THEN RETURN false; END IF;
  IF strpos(p_target,'?')=0 THEN RETURN true; END IF;
  WITH fields AS (
    SELECT field,ordinal FROM regexp_split_to_table(substr(p_target,strpos(p_target,'?')+1),'&')
      WITH ORDINALITY AS f(field,ordinal) WHERE field<>''
  ), keys AS (
    SELECT ordinal,convert_from(decode(coalesce(string_agg(CASE
      WHEN token[1] IS NULL THEN ''
      WHEN left(token[1],1)='%' THEN substr(token[1],2)
      ELSE encode(convert_to(CASE WHEN token[1]='+' THEN ' ' ELSE token[1] END,'UTF8'),'hex')
      END,'' ORDER BY part),''),'hex'),'UTF8') AS decoded_key
    FROM fields LEFT JOIN LATERAL regexp_matches(split_part(field,'=',1),'(%[0-9A-Fa-f]{2}|.)','g')
      WITH ORDINALITY AS m(token,part) ON true GROUP BY ordinal
  ) SELECT EXISTS(SELECT 1 FROM keys GROUP BY convert_to(decoded_key,'UTF8') HAVING count(*)>1) INTO duplicate_key;
  RETURN NOT duplicate_key;
EXCEPTION WHEN OTHERS THEN RETURN false;
END
$function$;
REVOKE ALL ON FUNCTION public.request_target_valid_v5(text) FROM PUBLIC,agent_runtime,aimos_app;

CREATE OR REPLACE FUNCTION public.request_signature_message_v5(p_wire bytea,p_method text,p_target text,p_claims jsonb,p_nonce text,p_ts bigint)
RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER IMMUTABLE
SET search_path=pg_catalog,public AS $function$
DECLARE msg bytea; field bytea; previous_claim text; device_claim text;
BEGIN
  IF p_wire IS NULL OR p_method IS NULL OR upper(p_method) !~ '^[A-Z]+$'
    OR public.request_target_valid_v5(p_target) IS NOT TRUE OR p_nonce IS NULL OR p_nonce=''
    OR p_ts IS NULL OR p_ts<=0 OR p_ts>9007199254740991
    OR jsonb_typeof(p_claims) IS DISTINCT FROM 'object'
    OR (p_claims ?& ARRAY['prev_chain_hash','device_fp']) IS NOT TRUE
    OR p_claims-ARRAY['prev_chain_hash','device_fp'] IS DISTINCT FROM '{}'::jsonb THEN
    RAISE EXCEPTION 'origin_native_request_context_invalid'; END IF;
  previous_claim:=p_claims->>'prev_chain_hash'; device_claim:=p_claims->>'device_fp';
  IF (p_claims->'prev_chain_hash'<>'null'::jsonb AND jsonb_typeof(p_claims->'prev_chain_hash')<>'string')
    OR (previous_claim IS NOT NULL AND (previous_claim !~ '^[A-Za-z0-9_-]{43}$'
      OR right(previous_claim,1) !~ '^[AEIMQUYcgkosw048]$'))
    OR (p_claims->'device_fp'<>'null'::jsonb AND jsonb_typeof(p_claims->'device_fp')<>'string')
    OR (device_claim IS NOT NULL AND (device_claim='' OR previous_claim IS NULL)) THEN
    RAISE EXCEPTION 'origin_native_request_claims_invalid'; END IF;
  msg:=convert_to('hom.aimos.request-envelope/v5','UTF8')||decode('00','hex');
  FOREACH field IN ARRAY ARRAY[p_wire,convert_to(upper(p_method),'UTF8'),convert_to(p_target,'UTF8'),
    convert_to(public.ob2_canonical_json(p_claims),'UTF8'),convert_to(p_nonce,'UTF8'),convert_to(p_ts::text,'UTF8')]
  LOOP msg:=msg||int4send(octet_length(field))||field; END LOOP;
  RETURN msg;
END
$function$;
REVOKE ALL ON FUNCTION public.request_signature_message_v5(bytea,text,text,jsonb,text,bigint) FROM PUBLIC,agent_runtime,aimos_app;

ALTER TABLE public.aimos_request_receipts DROP CONSTRAINT IF EXISTS aimos_request_receipts_request_sig_form_check;
ALTER TABLE public.aimos_request_receipts ADD CONSTRAINT aimos_request_receipts_request_sig_form_check CHECK (request_sig_form IN (3,4,5));
ALTER TABLE public.aimos_request_receipts DROP CONSTRAINT IF EXISTS aimos_request_receipts_form5_claims;
ALTER TABLE public.aimos_request_receipts ADD CONSTRAINT aimos_request_receipts_form5_claims CHECK (request_sig_form<>5 OR (
  jsonb_typeof(signed_claims)='object' AND signed_claims ?& ARRAY['prev_chain_hash','device_fp']
  AND signed_claims-ARRAY['prev_chain_hash','device_fp']='{}'::jsonb
  AND signed_claims_hash IS NOT NULL) IS TRUE);

DO $request_target_constraints$
DECLARE relation_name text; constraint_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY['aimos_memory_provenance','aimos_save_envelope','aimos_authorization_events','aimos_memory_lineage']
  LOOP
    constraint_name:=CASE WHEN relation_name='aimos_memory_lineage' THEN 'aimos_memory_lineage_request_context_valid'
      ELSE relation_name||'_request_signature_context_valid' END;
    EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT IF EXISTS %I',relation_name,constraint_name);
    EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (
      (request_sig_form=1 AND signed_method IS NULL AND signed_path IS NULL AND signed_claims IS NULL)
      OR (request_sig_form=3 AND signed_method IS NOT NULL AND signed_path IS NOT NULL AND signed_claims IS NULL)
      OR (request_sig_form=4 AND signed_method IS NOT NULL AND signed_path IS NOT NULL
        AND jsonb_typeof(signed_claims)=''object'' AND jsonb_typeof(signed_claims->''prev_chain_hash'')=''string'')
      OR (request_sig_form=5 AND signed_method IS NOT NULL AND signed_path IS NOT NULL
        AND jsonb_typeof(signed_claims)=''object'' AND signed_claims ?& ARRAY[''prev_chain_hash'',''device_fp'']
        AND signed_claims-ARRAY[''prev_chain_hash'',''device_fp'']=''{}''::jsonb) IS TRUE)',relation_name,constraint_name);
  END LOOP;
END
$request_target_constraints$;
