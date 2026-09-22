-- 104-origin-event-local-timestamp-parity.sql
-- aimos_events.ts is timestamp-without-time-zone and stores the session-local
-- rendering of ts_signed; compare the exact local projection, not UTC epoch.

CREATE OR REPLACE FUNCTION public.ob2_verify_signed_event(p_event_id uuid, p_company_id text)
RETURNS public.aimos_events
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_event public.aimos_events%ROWTYPE;
  v_identity record;
  v_pub bytea;
  v_message bytea;
  v_content bytea;
  v_mutation bytea;
BEGIN
  SELECT * INTO v_event FROM public.aimos_events
   WHERE id = p_event_id AND company_id = p_company_id AND proof_required IS TRUE;
  IF NOT FOUND OR v_event.ledger_version <> 1 OR v_event.signed_body IS NULL
     OR v_event.signer_agent_id <> 'housekeeper' THEN
    RAISE EXCEPTION 'origin_signed_event_invalid';
  END IF;
  SELECT identity.pubkey, identity.cert, identity.valid_until, identity.revoked_at
    INTO v_identity FROM public.agent_identity identity
   WHERE identity.agent_id = v_event.signer_agent_id
     AND identity.valid_from = v_event.signer_valid_from;
  IF NOT FOUND OR v_identity.revoked_at IS NOT NULL
     OR v_event.ts_signed < trunc(extract(epoch FROM v_event.signer_valid_from))::bigint
     OR v_event.ts_signed >= trunc(extract(epoch FROM v_identity.valid_until))::bigint
     OR encode(digest(convert_to(v_identity.cert,'UTF8'),'sha256'),'hex') <> v_event.cert_fingerprint THEN
    RAISE EXCEPTION 'origin_signed_event_identity_invalid';
  END IF;
  IF v_event.signed_body->>'event_id' <> v_event.id::text
     OR v_event.signed_body->>'company_id' <> v_event.company_id
     OR v_event.signed_body->>'subject_agent_id' <> v_event.agent_id
     OR v_event.signed_body->>'signer_agent_id' <> v_event.signer_agent_id
     OR (v_event.signed_body->>'signer_valid_from')::timestamptz <> v_event.signer_valid_from
     OR v_event.signed_body->>'cert_fingerprint' <> v_event.cert_fingerprint
     OR v_event.signed_body->>'identity_tier' <> v_event.identity_tier
     OR v_event.signed_body->>'authority_kind' <> v_event.authority_kind
     OR v_event.signed_body->>'operation' <> v_event.operation
     OR v_event.signed_body->>'key' IS DISTINCT FROM v_event.key
     OR v_event.signed_body->'metadata' <> v_event.metadata
     OR v_event.signed_body->>'parent_event_id' IS DISTINCT FROM v_event.parent_event_id::text
     OR (v_event.signed_body->>'ledger_seq')::bigint <> v_event.ledger_seq
     OR v_event.signed_body->>'prev_mutation_hash' <> encode(v_event.prev_mutation_hash,'hex')
     OR (v_event.signed_body->>'ts_signed')::bigint <> v_event.ts_signed
     OR v_event.ts <> (to_timestamp(v_event.ts_signed) AT TIME ZONE current_setting('TimeZone')) THEN
    RAISE EXCEPTION 'origin_signed_event_relational_mismatch';
  END IF;
  IF v_event.ledger_seq > 1 AND NOT EXISTS (
    SELECT 1 FROM public.aimos_events predecessor
     WHERE predecessor.company_id = v_event.company_id
       AND predecessor.signer_agent_id = v_event.signer_agent_id
       AND predecessor.signer_valid_from = v_event.signer_valid_from
       AND predecessor.ledger_seq = v_event.ledger_seq - 1
       AND predecessor.mutation_hash = v_event.prev_mutation_hash
  ) THEN RAISE EXCEPTION 'origin_signed_event_predecessor_invalid'; END IF;
  v_content := digest(convert_to(public.ob2_canonical_json(v_event.signed_body), 'UTF8'), 'sha256');
  v_mutation := digest(
    convert_to('AIMOS-EVENT-LINK-v1', 'UTF8') || decode('00', 'hex')
    || v_event.prev_mutation_hash || v_content
    || convert_to(v_event.nonce, 'UTF8') || convert_to(v_event.ts_signed::text, 'UTF8'), 'sha256');
  v_pub := public.ob2_raw_ed25519_pubkey(v_event.signer_agent_id, v_event.signer_valid_from);
  v_message := convert_to(public.ob2_canonical_json(v_event.signed_body)
    || E'\n' || v_event.nonce || E'\n' || v_event.ts_signed::text, 'UTF8');
  IF v_content <> v_event.content_hash OR v_mutation <> v_event.mutation_hash
     OR v_pub IS NULL OR octet_length(v_pub) <> 32
     OR NOT pgsodium.crypto_sign_verify_detached(v_event.sig, v_message, v_pub) THEN
    RAISE EXCEPTION 'origin_signed_event_invalid';
  END IF;
  RETURN v_event;
END
$function$;

