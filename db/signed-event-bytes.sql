-- AUD-018 candidate: versioned event payload in the existing v1 linkage ledger.
-- Apply only after signed-json-bytes.sql; no historical row/body rewrite.
ALTER TABLE public.aimos_events ADD COLUMN IF NOT EXISTS signed_body_bytes bytea;
DO $payload_constraint$
BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.aimos_events'::regclass
  AND conname='aimos_events_exact_payload_pair') THEN
ALTER TABLE public.aimos_events ADD CONSTRAINT aimos_events_exact_payload_pair CHECK (
  CASE WHEN signed_body IS NULL THEN signed_body_bytes IS NULL
    WHEN signed_body ? 'payload_schema' THEN
      signed_body->>'payload_schema'='hom.aimos.event/v2' AND signed_body_bytes IS NOT NULL
    ELSE signed_body_bytes IS NULL END);
END IF;
END
$payload_constraint$;

CREATE OR REPLACE FUNCTION public.ob2_verify_signed_event(p_event_id uuid,p_company_id text)
RETURNS public.aimos_events LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,public AS $function$
DECLARE e public.aimos_events%ROWTYPE; identity public.agent_identity%ROWTYPE;
  b jsonb; content bytea; mutation bytea; message bytea; pub bytea;
BEGIN
  SELECT * INTO e FROM public.aimos_events WHERE id=p_event_id AND company_id=p_company_id AND proof_required IS TRUE;
  IF NOT FOUND OR e.ledger_version<>1 OR e.signed_body IS NULL OR e.signer_agent_id<>'housekeeper' THEN
    RAISE EXCEPTION 'origin_signed_event_invalid'; END IF;
  -- Payload versioning must preserve the existing identity and linkage guards.
  SELECT * INTO identity FROM public.agent_identity WHERE agent_id=e.signer_agent_id AND valid_from=e.signer_valid_from;
  IF NOT FOUND OR identity.revoked_at IS NOT NULL
    OR e.ts_signed<trunc(extract(epoch FROM e.signer_valid_from))::bigint
    OR e.ts_signed>=trunc(extract(epoch FROM identity.valid_until))::bigint
    OR encode(digest(convert_to(identity.cert,'UTF8'),'sha256'),'hex') IS DISTINCT FROM e.cert_fingerprint
    OR EXISTS(SELECT 1 FROM public.aimos_agent_revocation_events r WHERE r.agent_id=e.signer_agent_id
      AND r.agent_valid_from=e.signer_valid_from AND r.ts_signed<=e.ts_signed) THEN
    RAISE EXCEPTION 'origin_signed_event_identity_invalid'; END IF;
  IF e.ledger_seq<1 OR e.ledger_seq>9007199254740991 THEN RAISE EXCEPTION 'origin_signed_event_predecessor_invalid'; END IF;
  IF e.ledger_seq=1 THEN
    IF e.prev_mutation_hash IS DISTINCT FROM digest(convert_to('aimos-event-genesis/v1','UTF8')||decode('00','hex')
      ||convert_to(e.company_id,'UTF8')||decode('00','hex')||convert_to(e.signer_agent_id,'UTF8')||decode('00','hex')
      ||convert_to(to_char(e.signer_valid_from AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'UTF8'),'sha256') THEN
      RAISE EXCEPTION 'origin_signed_event_predecessor_invalid'; END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.aimos_events p WHERE p.company_id=e.company_id
    AND p.signer_agent_id=e.signer_agent_id AND p.signer_valid_from=e.signer_valid_from
    AND p.ledger_version=e.ledger_version AND p.ledger_seq=e.ledger_seq-1 AND p.mutation_hash=e.prev_mutation_hash) THEN
    RAISE EXCEPTION 'origin_signed_event_predecessor_invalid';
  END IF;
  b := e.signed_body;
  IF b ? 'payload_schema' THEN
    IF b->>'payload_schema' IS DISTINCT FROM 'hom.aimos.event/v2' OR e.signed_body_bytes IS NULL THEN
      RAISE EXCEPTION 'origin_signed_event_invalid'; END IF;
    content := public.signed_json_bytes_commitment_v1('hom.aimos.event/v2',e.signed_body_bytes);
    IF convert_from(e.signed_body_bytes,'UTF8')::jsonb IS DISTINCT FROM b
      OR b->'nonce' IS DISTINCT FROM to_jsonb(e.nonce)
      OR b->'event_id' IS DISTINCT FROM to_jsonb(e.id::text)
      OR b->'company_id' IS DISTINCT FROM to_jsonb(e.company_id)
      OR b->'subject_agent_id' IS DISTINCT FROM coalesce(to_jsonb(e.agent_id),'null'::jsonb)
      OR b->'signer_agent_id' IS DISTINCT FROM to_jsonb(e.signer_agent_id)
      OR jsonb_typeof(b->'signer_valid_from') IS DISTINCT FROM 'string'
      OR (b->>'signer_valid_from')::timestamptz IS DISTINCT FROM e.signer_valid_from
      OR b->'cert_fingerprint' IS DISTINCT FROM to_jsonb(e.cert_fingerprint)
      OR b->'identity_tier' IS DISTINCT FROM to_jsonb(e.identity_tier)
      OR b->'authority_kind' IS DISTINCT FROM to_jsonb(e.authority_kind)
      OR b->'operation' IS DISTINCT FROM to_jsonb(e.operation)
      OR b->'key' IS DISTINCT FROM coalesce(to_jsonb(e.key),'null'::jsonb)
      OR b->'metadata' IS DISTINCT FROM e.metadata
      OR b->'parent_event_id' IS DISTINCT FROM coalesce(to_jsonb(e.parent_event_id::text),'null'::jsonb)
      OR b->'ledger_version' IS DISTINCT FROM to_jsonb(e.ledger_version)
      OR b->'ledger_seq' IS DISTINCT FROM to_jsonb(e.ledger_seq)
      OR b->>'prev_mutation_hash' IS DISTINCT FROM encode(e.prev_mutation_hash,'hex')
      OR b->'ts_signed' IS DISTINCT FROM to_jsonb(e.ts_signed)
      OR e.ts IS DISTINCT FROM to_timestamp(e.ts_signed) THEN
      RAISE EXCEPTION 'origin_signed_event_payload_binding_invalid'; END IF;
    message := content;
  ELSE
    IF e.signed_body_bytes IS NOT NULL THEN RAISE EXCEPTION 'origin_signed_event_invalid'; END IF;
    -- Preserve historical reconstruction and signature preimage verbatim.
    content := digest(convert_to(public.ob2_canonical_json(b),'UTF8'),'sha256');
    message := convert_to(public.ob2_canonical_json(b)||E'\n'||e.nonce||E'\n'||e.ts_signed::text,'UTF8');
  END IF;
  -- Both payload profiles bind the same denormalized event fields.
  IF b->>'event_id' IS DISTINCT FROM e.id::text OR b->>'company_id' IS DISTINCT FROM e.company_id
    OR b->>'subject_agent_id' IS DISTINCT FROM e.agent_id OR b->>'signer_agent_id' IS DISTINCT FROM e.signer_agent_id
    OR (b->>'signer_valid_from')::timestamptz IS DISTINCT FROM e.signer_valid_from
    OR b->>'cert_fingerprint' IS DISTINCT FROM e.cert_fingerprint OR b->>'identity_tier' IS DISTINCT FROM e.identity_tier
    OR b->>'authority_kind' IS DISTINCT FROM e.authority_kind OR b->>'operation' IS DISTINCT FROM e.operation
    OR b->>'key' IS DISTINCT FROM e.key OR b->'metadata' IS DISTINCT FROM e.metadata
    OR b->>'parent_event_id' IS DISTINCT FROM e.parent_event_id::text
    OR (b->>'ledger_seq')::bigint IS DISTINCT FROM e.ledger_seq
    OR b->>'prev_mutation_hash' IS DISTINCT FROM encode(e.prev_mutation_hash,'hex')
    OR (b->>'ts_signed')::bigint IS DISTINCT FROM e.ts_signed OR e.ts IS DISTINCT FROM to_timestamp(e.ts_signed) THEN
    RAISE EXCEPTION 'origin_signed_event_relational_mismatch'; END IF;
  mutation := digest(convert_to('AIMOS-EVENT-LINK-v1','UTF8')||decode('00','hex')
    ||e.prev_mutation_hash||content||convert_to(e.nonce,'UTF8')||convert_to(e.ts_signed::text,'UTF8'),'sha256');
  pub := public.ob2_raw_ed25519_pubkey(e.signer_agent_id,e.signer_valid_from);
  IF content IS DISTINCT FROM e.content_hash OR mutation IS DISTINCT FROM e.mutation_hash
    OR pub IS NULL OR octet_length(pub)<>32
    OR pgsodium.crypto_sign_verify_detached(e.sig,message,pub) IS NOT TRUE THEN
    RAISE EXCEPTION 'origin_signed_event_invalid'; END IF;
  RETURN e;
END
$function$;

CREATE OR REPLACE FUNCTION public.require_signed_event_bytes_v1()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $function$
BEGIN
  IF NEW.signed_body ? 'payload_schema' THEN PERFORM public.ob2_verify_signed_event(NEW.id,NEW.company_id); END IF;
  RETURN NULL;
END
$function$;
CREATE OR REPLACE TRIGGER aimos_events_exact_payload_verified AFTER INSERT ON public.aimos_events
FOR EACH ROW EXECUTE FUNCTION public.require_signed_event_bytes_v1();
REVOKE ALL ON FUNCTION public.require_signed_event_bytes_v1() FROM PUBLIC,agent_runtime,aimos_app;
-- Extend only the existing runtime column ACL; no table-level INSERT/UPDATE,
-- helper EXECUTE, server-owner role, or other principal grant.
GRANT SELECT(signed_body_bytes),INSERT(signed_body_bytes) ON public.aimos_events TO agent_runtime;
-- Preserve application reads/maintenance; event schema authority is not runtime authority.
REVOKE TRIGGER,REFERENCES ON public.aimos_events FROM aimos_app;
