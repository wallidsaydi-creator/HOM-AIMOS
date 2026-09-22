-- 108-operator-action-authorization-verifier.sql
-- Independently verify the master-signed, exact, single-use operator proof
-- before an ALLOW verdict carrying user_authorization_sha256 can be inserted.

CREATE OR REPLACE FUNCTION public.ob5_verify_operator_action_authorization()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_schema constant text := 'hom.aimos.operator-action-authorization/v1';
  v_auth public.aimos_events%ROWTYPE;
  v_claim public.aimos_events%ROWTYPE;
  v_reserved public.aimos_events%ROWTYPE;
  v_approved public.aimos_events%ROWTYPE;
  v_requested public.aimos_events%ROWTYPE;
  v_proof jsonb;
  v_body jsonb;
  v_master_pub text;
  v_master_fingerprint text;
  v_raw_pub bytea;
  v_sig bytea;
  v_message bytea;
  v_proof_hash bytea;
  v_content_hash bytea;
  v_created_at timestamptz;
  v_valid_until timestamptz;
BEGIN
  IF NEW.user_authorization_sha256 IS NULL THEN RETURN NEW; END IF;
  IF NEW.authorization_event_id IS NULL OR NEW.decision <> 'ALLOW' THEN
    RAISE EXCEPTION 'operator_action_authorization_invalid';
  END IF;
  v_auth := public.ob2_verify_signed_event(NEW.authorization_event_id,NEW.company_id);
  v_proof := v_auth.metadata->'operator_proof';
  v_body := v_proof->'body';
  IF v_auth.operation <> 'origin_action_authorized'
     OR v_auth.mutation_hash <> NEW.user_authorization_sha256
     OR v_auth.metadata->>'operator_proof_sha256' <> v_proof->>'proof_sha256'
     OR NOT public.ob2_exact_json_keys(v_proof,ARRAY[
       'body','ts_signed','nonce','sig','content_sha256','proof_sha256'
     ]) OR NOT public.ob2_exact_json_keys(v_body,ARRAY[
       'schema','proof_id','company_id','subject_agent_id','subject_valid_from',
       'subject_cert_fingerprint_sha256','approval_request_id',
       'approval_request_mutation_sha256','tool_name','action_scope','risk_class',
       'arguments_sha256','security_value_sha256','maximum_uses','created_at',
       'valid_until','master_fingerprint'
     ]) OR v_body->>'schema' <> c_schema THEN
    RAISE EXCEPTION 'operator_action_authorization_invalid';
  END IF;
  BEGIN
    v_created_at := (v_body->>'created_at')::timestamptz;
    v_valid_until := (v_body->>'valid_until')::timestamptz;
    v_sig := decode(rpad(translate(v_proof->>'sig','-_','+/'),
      (length(translate(v_proof->>'sig','-_','+/'))+3)/4*4,'='),'base64');
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'operator_action_authorization_invalid'; END;
  SELECT master_pubkey,fingerprint INTO v_master_pub,v_master_fingerprint
    FROM public.aimos_master_identity WHERE id=1;
  v_raw_pub := substring(decode(rpad(translate(v_master_pub,'-_','+/'),
    (length(translate(v_master_pub,'-_','+/'))+3)/4*4,'='),'base64') FROM 13 FOR 32);
  v_content_hash := digest(convert_to(public.ob2_canonical_json(v_body),'UTF8'),'sha256');
  v_proof_hash := digest(convert_to(public.ob2_canonical_json(v_proof-'proof_sha256'),'UTF8'),'sha256');
  v_message := convert_to(public.ob2_canonical_json(v_body) || E'\n'
    || (v_proof->>'nonce') || E'\n' || (v_proof->>'ts_signed'),'UTF8');
  IF octet_length(v_raw_pub) <> 32 OR octet_length(v_sig) <> 64
     OR encode(v_content_hash,'hex') <> v_proof->>'content_sha256'
     OR encode(v_proof_hash,'hex') <> v_proof->>'proof_sha256'
     OR v_body->>'master_fingerprint' <> v_master_fingerprint
     OR NOT pgsodium.crypto_sign_verify_detached(v_sig,v_message,v_raw_pub)
     OR (v_proof->>'ts_signed')::bigint <> trunc(extract(epoch FROM v_created_at))::bigint
     OR v_valid_until <= v_created_at
     OR v_valid_until > v_created_at + interval '5 minutes'
     OR NEW.originated_at < v_created_at OR NEW.originated_at >= v_valid_until
     OR (v_body->>'maximum_uses')::integer <> 1
     OR v_body->>'company_id' <> NEW.company_id
     OR v_body->>'subject_agent_id' <> NEW.actor_agent_id
     OR (v_body->>'subject_valid_from')::timestamptz <> NEW.actor_valid_from
     OR v_body->>'subject_cert_fingerprint_sha256' <> NEW.actor_cert_fingerprint
     OR v_body->>'tool_name' <> NEW.tool_name
     OR v_body->>'action_scope' <> NEW.action_scope
     OR v_body->>'risk_class' <> NEW.risk_class
     OR v_body->>'arguments_sha256' <> encode(NEW.arguments_sha256,'hex')
     OR v_body->>'security_value_sha256'
        <> NEW.security_values#>>'{0,value_sha256}' THEN
    RAISE EXCEPTION 'operator_action_authorization_invalid';
  END IF;

  v_claim := public.ob2_verify_signed_event(v_auth.parent_event_id,NEW.company_id);
  v_reserved := public.ob2_verify_signed_event(v_claim.parent_event_id,NEW.company_id);
  v_approved := public.ob2_verify_signed_event(v_reserved.parent_event_id,NEW.company_id);
  v_requested := public.ob2_verify_signed_event(v_approved.parent_event_id,NEW.company_id);
  IF v_claim.operation <> 'tool_approval_execution_claimed'
     OR v_reserved.operation <> 'tool_approval_execution_reserved'
     OR v_approved.operation <> 'tool_approval_approved'
     OR v_requested.operation <> 'tool_approval_requested'
     OR v_body->>'approval_request_id' <> v_requested.id::text
     OR v_body->>'approval_request_mutation_sha256' <> encode(v_requested.mutation_hash,'hex')
     OR v_requested.metadata->>'tool' <> NEW.tool_name
     OR v_requested.metadata->>'args_sha256' <> encode(NEW.arguments_sha256,'hex')
     OR v_requested.metadata->>'agent_id' <> NEW.actor_agent_id
     OR v_approved.metadata->>'operator_proof_sha256' <> v_proof->>'proof_sha256'
     OR v_approved.metadata->'operator_proof' <> v_proof
     OR v_reserved.metadata->>'operator_proof_sha256' <> v_proof->>'proof_sha256'
     OR v_claim.metadata->>'operator_proof_sha256' <> v_proof->>'proof_sha256'
     OR EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts prior
       WHERE prior.user_authorization_sha256=NEW.user_authorization_sha256)
  THEN RAISE EXCEPTION 'operator_action_authorization_invalid'; END IF;
  RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS ob5_verify_operator_action_authorization
  ON public.aimos_action_origin_verdicts;
CREATE TRIGGER ob5_verify_operator_action_authorization
BEFORE INSERT ON public.aimos_action_origin_verdicts
FOR EACH ROW EXECUTE FUNCTION public.ob5_verify_operator_action_authorization();

REVOKE ALL ON FUNCTION public.ob5_verify_operator_action_authorization()
  FROM PUBLIC,agent_runtime,aimos_app;
