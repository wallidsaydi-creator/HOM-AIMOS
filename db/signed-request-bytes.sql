-- Native, transient form-3/4 request-byte verification. The receipt stays
-- hash-only. No new signer, route, signature preimage or request-body storage.
CREATE OR REPLACE FUNCTION public.ob2_verify_signed_request_bytes(p_receipt_id uuid,p_request_json json)
RETURNS public.aimos_request_receipts LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,public AS $function$
DECLARE r public.aimos_request_receipts%ROWTYPE; i public.agent_identity%ROWTYPE;
  wire bytea; msg bytea; pub bytea; claims bytea; claims_hash bytea; expected bytea;
BEGIN
  SELECT * INTO r FROM public.aimos_request_receipts WHERE request_receipt_id=p_receipt_id;
  IF NOT FOUND OR p_request_json IS NULL OR json_typeof(p_request_json) NOT IN ('object','array')
    OR (p_request_json::text IS JSON WITH UNIQUE KEYS) IS NOT TRUE THEN
    RAISE EXCEPTION 'origin_native_request_body_invalid'; END IF;
  wire:=convert_to(p_request_json::text,'UTF8');
  IF octet_length(wire)>1048576 OR digest(wire,'sha256') IS DISTINCT FROM r.request_hash THEN
    RAISE EXCEPTION 'origin_native_request_body_invalid'; END IF;
  SELECT * INTO i FROM public.agent_identity WHERE agent_id=r.actor_agent_id AND valid_from=r.actor_valid_from;
  IF NOT FOUND OR i.revoked_at IS NOT NULL
    OR to_timestamp(r.ts_signed)<i.valid_from OR to_timestamp(r.ts_signed)>=i.valid_until
    OR encode(digest(convert_to(i.cert,'UTF8'),'sha256'),'hex') IS DISTINCT FROM r.cert_fingerprint
    OR EXISTS(SELECT 1 FROM public.aimos_agent_revocation_events x WHERE x.agent_id=i.agent_id
      AND x.agent_valid_from=i.valid_from AND x.ts_signed<=r.ts_signed) THEN
    RAISE EXCEPTION 'origin_native_request_identity_invalid'; END IF;
  msg:=wire||convert_to(E'\n'||upper(r.signed_method)||E'\n'||split_part(r.signed_path,'?',1)||E'\n','UTF8');
  IF r.request_sig_form=5 AND r.signed_claims IS NOT NULL THEN
    claims:=convert_to(public.ob2_canonical_json(r.signed_claims),'UTF8');
    claims_hash:=digest(claims,'sha256');
    IF claims_hash IS DISTINCT FROM r.signed_claims_hash THEN RAISE EXCEPTION 'origin_native_request_claims_invalid'; END IF;
    msg:=public.request_signature_message_v5(wire,r.signed_method,r.signed_path,r.signed_claims,r.nonce,r.ts_signed);
  ELSIF r.request_sig_form=4 AND r.signed_claims IS NOT NULL THEN
    claims:=convert_to(public.ob2_canonical_json(r.signed_claims),'UTF8');
    claims_hash:=digest(claims,'sha256'); msg:=msg||claims||decode('0a','hex');
    IF claims_hash IS DISTINCT FROM r.signed_claims_hash THEN RAISE EXCEPTION 'origin_native_request_claims_invalid'; END IF;
  ELSIF r.request_sig_form=3 AND r.signed_claims IS NULL AND r.signed_claims_hash IS NULL THEN
    claims_hash:=decode(repeat('00',32),'hex');
  ELSE RAISE EXCEPTION 'origin_native_request_form_invalid'; END IF;
  IF r.request_sig_form<>5 THEN msg:=msg||convert_to(r.nonce||E'\n'||r.ts_signed::text,'UTF8'); END IF;
  pub:=public.ob2_raw_ed25519_pubkey(i.agent_id,i.valid_from);
  expected:=digest(convert_to('aimos-request-receipt-v1','UTF8')||decode('00','hex')
    ||coalesce(r.prev_mutation_hash,decode(repeat('00',32),'hex'))||r.request_hash||claims_hash||r.sig
    ||convert_to(r.signed_method||r.signed_path||r.nonce||r.ts_signed::text,'UTF8'),'sha256');
  IF pub IS NULL OR octet_length(pub)<>32 OR pgsodium.crypto_sign_verify_detached(r.sig,msg,pub) IS NOT TRUE
    OR expected IS DISTINCT FROM r.mutation_hash OR (r.prev_mutation_hash IS NULL) IS DISTINCT FROM r.is_genesis
    OR (r.prev_mutation_hash IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.aimos_request_receipts prev
      WHERE prev.company_id=r.company_id AND prev.actor_agent_id=r.actor_agent_id
        AND prev.actor_valid_from=r.actor_valid_from AND prev.mutation_hash=r.prev_mutation_hash)) THEN
    RAISE EXCEPTION 'origin_native_request_signature_invalid'; END IF;
  RETURN r;
END
$function$;
REVOKE ALL ON FUNCTION public.ob2_verify_signed_request_bytes(uuid,json) FROM PUBLIC,agent_runtime,aimos_app;
