-- Native OB-2 database definitions. Apply transactionally to the existing
-- canonical database; no data copy, new identity, or migration replay.
-- v1 signed bytes remain immutable. v2 represents the existing native request
-- OR Housekeeper/tool action, instead of inventing an HTTP receipt for actions.
SET LOCAL lock_timeout = '10s';
ALTER TABLE public.aimos_origin_ledger_entries
  DROP CONSTRAINT IF EXISTS aimos_origin_ledger_object_schema;
ALTER TABLE public.aimos_origin_ledger_entries ADD CONSTRAINT aimos_origin_ledger_object_schema
  CHECK (object_schema IN ('hom.aimos.memory-origin-binding/v1','hom.aimos.memory-origin-binding/v2','hom.aimos.memory-origin-binding/v3',
    'hom.aimos.origin-elevation/v1','hom.aimos.origin-elevation/v2','hom.aimos.action-origin-verdict/v1'));
ALTER TABLE public.aimos_memory_origin_bindings
  ALTER COLUMN request_receipt_id DROP NOT NULL,
  ALTER COLUMN request_mutation_sha256 DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS operation_authority jsonb,
  ADD COLUMN IF NOT EXISTS action_authority_event_id uuid REFERENCES public.aimos_events(id);

CREATE INDEX IF NOT EXISTS aimos_memory_origin_company_memory
  ON public.aimos_memory_origin_bindings(company_id,memory_id);

CREATE OR REPLACE FUNCTION public.ob2_occurrence_reference(p public.aimos_memory_provenance, company text)
RETURNS bytea LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $function$
DECLARE fields bytea[]; enc bytea; n integer;
BEGIN
  IF p.sig_form_version=3 THEN RETURN p.mutation_hash; END IF;
  fields := ARRAY[convert_to(company,'UTF8'),uuid_send(p.memory_id),uuid_send(p.provenance_id),p.mutation_hash,
    convert_to(p.agent_id,'UTF8'),int8send((extract(epoch FROM p.agent_valid_from)*1000)::bigint),
    decode(p.cert_fingerprint,'hex'),convert_to(upper(p.event_type),'UTF8'),int2send(p.sig_form_version::smallint)];
  enc := convert_to('hom.aimos.memory-occurrence-ref/legacy-v1','UTF8')||decode('00','hex');
  FOR n IN 1..9 LOOP enc := enc||int2send(n::smallint)||int4send(octet_length(fields[n]))||fields[n]; END LOOP;
  RETURN digest(enc,'sha256');
END
$function$;
REVOKE ALL ON FUNCTION public.ob2_occurrence_reference(public.aimos_memory_provenance,text) FROM PUBLIC,agent_runtime,aimos_app;

-- Retire the JSONB-only handoff: it discarded the already-signed serialization.
-- JSON retains the native canonical text; no request plaintext is stored here.
DROP FUNCTION IF EXISTS public.ob2_verify_native_save_authority(uuid,jsonb,jsonb,text);
CREATE OR REPLACE FUNCTION public.ob2_verify_native_save_authority(
  p_occurrence uuid, p_authority jsonb, p_request_json json, p_session text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $function$
DECLARE
  o public.aimos_memory_provenance%ROWTYPE;
  m public.aimos_memories%ROWTYPE;
  r public.aimos_request_receipts%ROWTYPE;
  e public.aimos_events%ROWTYPE;
  i public.agent_identity%ROWTYPE;
  b jsonb; a jsonb := p_authority - 'authority_sha256';
  kind text := p_authority->>'kind';
  pub bytea; msg bytea; enc bytea; fields bytea[]; part bytea; n integer;
  expected bytea; request_hash bytea; claims_hash bytea; effective_body jsonb;
  saved_record jsonb; input_source public.aimos_memories%ROWTYPE;
  expected_key text;
  p_request_body jsonb := p_request_json::jsonb;
  request_bytes bytea;
BEGIN
  IF public.ob2_exact_json_keys(p_authority,ARRAY['schema','kind','company_id','actor','signer',
      'subject_agent_id','evidence','authority_sha256']) IS NOT TRUE
    OR p_authority->>'schema' IS DISTINCT FROM 'hom.aimos.origin-operation-authority/v2'
    OR kind IS NULL OR kind NOT IN ('verified_request','verified_housekeeper_action','verified_tool_action')
    OR p_authority->>'company_id' IS DISTINCT FROM current_setting('app.current_client_id',true)
    OR public.ob2_exact_json_keys(p_authority->'actor',ARRAY['agent_id','valid_from','cert_fingerprint_sha256']) IS NOT TRUE
    OR public.ob2_exact_json_keys(p_authority->'signer',ARRAY['agent_id','valid_from','cert_fingerprint_sha256']) IS NOT TRUE THEN
    RAISE EXCEPTION 'origin_native_authority_shape_invalid';
  END IF;
  enc := convert_to(public.ob2_canonical_json(a),'UTF8');
  IF encode(digest(convert_to('hom.aimos.origin-operation-authority/v2','UTF8')||decode('00','hex')
      ||int4send(octet_length(enc))||enc,'sha256'),'hex') IS DISTINCT FROM p_authority->>'authority_sha256' THEN
    RAISE EXCEPTION 'origin_native_authority_hash_invalid';
  END IF;
  SELECT * INTO o FROM public.aimos_memory_provenance WHERE provenance_id=p_occurrence;
  SELECT * INTO m FROM public.aimos_memories WHERE id=o.memory_id FOR SHARE;
  IF o.provenance_id IS NULL OR m.id IS NULL OR m.company_id IS DISTINCT FROM p_authority->>'company_id'
    OR m.agent_id IS DISTINCT FROM p_authority->>'subject_agent_id'
    OR o.live_content_hash IS DISTINCT FROM m.content_hash
    OR o.event_type NOT IN ('SAVE','SAVE_REASSERT','INTERNAL_SAVE_REASSERT') THEN
    RAISE EXCEPTION 'origin_native_occurrence_invalid';
  END IF;
  expected := digest(convert_to(public.ob2_canonical_json(jsonb_build_object(
    'key',coalesce(m.key,''),'value',coalesce(m.value,''),'scope',coalesce(m.scope,''),'memory_type',coalesce(m.memory_type,''),
    'clearance_level',coalesce(m.clearance_level::text,''),'data_class',coalesce(m.data_class,''),'source',coalesce(m.source,''))),'UTF8'),'sha256');
  IF expected IS DISTINCT FROM m.content_hash THEN RAISE EXCEPTION 'origin_live_content_hash_invalid'; END IF;
  SELECT * INTO i FROM public.agent_identity WHERE agent_id=p_authority#>>'{actor,agent_id}'
    AND valid_from=(p_authority#>>'{actor,valid_from}')::timestamptz FOR SHARE;
  IF i.agent_id IS NULL OR i.revoked_at IS NOT NULL OR i.valid_from>clock_timestamp() OR i.valid_until<=clock_timestamp()
    OR encode(digest(convert_to(i.cert,'UTF8'),'sha256'),'hex') IS DISTINCT FROM p_authority#>>'{actor,cert_fingerprint_sha256}'
    OR EXISTS(SELECT 1 FROM public.aimos_agent_revocation_events x
      WHERE x.agent_id=i.agent_id AND x.agent_valid_from=i.valid_from) THEN
    RAISE EXCEPTION 'origin_native_actor_epoch_invalid';
  END IF;
  IF kind='verified_request' THEN
    IF public.ob2_exact_json_keys(p_authority->'evidence',ARRAY['receipt_id','mutation_sha256','request_sha256',
       'signature_form','signed_method','signed_path','signed_at']) IS NOT TRUE
      OR p_authority->'signer' IS DISTINCT FROM p_authority->'actor'
      OR p_authority->>'subject_agent_id' IS DISTINCT FROM i.agent_id THEN
      RAISE EXCEPTION 'origin_native_request_shape_invalid';
    END IF;
    SELECT * INTO r FROM public.aimos_request_receipts
      WHERE request_receipt_id=(p_authority#>>'{evidence,receipt_id}')::uuid;
    IF r.request_receipt_id IS NULL OR r.company_id IS DISTINCT FROM m.company_id
      OR r.actor_agent_id IS DISTINCT FROM i.agent_id OR r.actor_valid_from IS DISTINCT FROM i.valid_from
      OR r.cert_fingerprint IS DISTINCT FROM p_authority#>>'{actor,cert_fingerprint_sha256}'
      OR encode(r.mutation_hash,'hex') IS DISTINCT FROM p_authority#>>'{evidence,mutation_sha256}'
      OR encode(r.request_hash,'hex') IS DISTINCT FROM p_authority#>>'{evidence,request_sha256}'
      OR r.request_sig_form IS DISTINCT FROM (p_authority#>>'{evidence,signature_form}')::integer
      OR r.signed_method IS DISTINCT FROM p_authority#>>'{evidence,signed_method}'
      OR r.signed_path IS DISTINCT FROM p_authority#>>'{evidence,signed_path}'
      OR to_timestamp(r.ts_signed) IS DISTINCT FROM (p_authority#>>'{evidence,signed_at}')::timestamptz
      OR to_timestamp(r.ts_signed)<i.valid_from OR to_timestamp(r.ts_signed)>=i.valid_until
      OR p_request_body IS NULL THEN RAISE EXCEPTION 'origin_native_request_mismatch'; END IF;
    effective_body := p_request_body;
    r := public.ob2_verify_signed_request_bytes(r.request_receipt_id,p_request_json);
    request_hash := r.request_hash;
  ELSE
    IF p_request_body IS NOT NULL OR p_authority#>>'{signer,agent_id}' IS DISTINCT FROM 'housekeeper' THEN
      RAISE EXCEPTION 'origin_native_action_shape_invalid'; END IF;
    e := public.ob2_verify_signed_event((p_authority#>>'{evidence,event_id}')::uuid,m.company_id);
    IF encode(e.mutation_hash,'hex') IS DISTINCT FROM p_authority#>>'{evidence,mutation_sha256}'
      OR e.signer_valid_from IS DISTINCT FROM (p_authority#>>'{signer,valid_from}')::timestamptz
      OR e.cert_fingerprint IS DISTINCT FROM p_authority#>>'{signer,cert_fingerprint_sha256}'
      OR to_timestamp(e.ts_signed) IS DISTINCT FROM (p_authority#>>'{evidence,signed_at}')::timestamptz THEN
      RAISE EXCEPTION 'origin_native_action_mismatch'; END IF;
    IF kind='verified_housekeeper_action' THEN
      IF public.ob2_exact_json_keys(p_authority->'evidence',ARRAY['event_id','mutation_sha256','action_sha256','action_context_sha256','signed_at']) IS NOT TRUE
        OR p_authority->'actor' IS DISTINCT FROM p_authority->'signer'
        OR e.agent_id IS DISTINCT FROM m.agent_id OR e.operation IS DISTINCT FROM 'canonical_save_action_started'
        OR e.metadata->>'schema' IS DISTINCT FROM 'hom.aimos.canonical-save-action-start/v2'
        OR e.metadata->>'action_sha256' IS DISTINCT FROM p_authority#>>'{evidence,action_sha256}'
        OR e.metadata->>'action_context_sha256' IS DISTINCT FROM p_authority#>>'{evidence,action_context_sha256}' THEN
        RAISE EXCEPTION 'origin_native_housekeeper_action_invalid'; END IF;
    ELSE
      IF public.ob2_exact_json_keys(p_authority->'evidence',ARRAY['event_id','mutation_sha256','tool','args_sha256','runtime_agent_id','purpose_authorization_sha256','signed_at']) IS NOT TRUE
        OR e.operation IS DISTINCT FROM 'tool_execution_started'
        OR e.metadata->'dispatch_allowed' = 'false'::jsonb
        OR e.metadata->>'schema' IS DISTINCT FROM 'aimos.tool-action/v1'
        OR e.key IS DISTINCT FROM 'aimos_save_commit'
        OR e.key IS DISTINCT FROM p_authority#>>'{evidence,tool}'
        OR e.agent_id IS DISTINCT FROM p_authority#>>'{evidence,runtime_agent_id}'
        OR e.metadata->>'actor_agent_id' IS DISTINCT FROM i.agent_id
        OR (e.metadata->>'actor_valid_from')::timestamptz IS DISTINCT FROM i.valid_from
        OR e.metadata->>'args_sha256' IS DISTINCT FROM p_authority#>>'{evidence,args_sha256}'
        OR e.metadata->>'purpose_authorization_sha256' IS DISTINCT FROM p_authority#>>'{evidence,purpose_authorization_sha256}' THEN
        RAISE EXCEPTION 'origin_native_tool_action_invalid'; END IF;
    END IF;
  END IF;
  IF kind='verified_request' AND split_part(r.signed_path,'?',1) IN ('/aimos/compaction/save','/aimos/compaction/post') THEN
    saved_record:=m.value::jsonb;
    IF p_request_body->>'agent_id' IS NOT NULL AND p_request_body->>'agent_id' IS DISTINCT FROM i.agent_id
      OR p_request_body->>'company_id' IS NOT NULL AND p_request_body->>'company_id' IS DISTINCT FROM m.company_id
      OR saved_record->>'agent_id' IS DISTINCT FROM i.agent_id
      OR saved_record->>'session_id' IS DISTINCT FROM p_session THEN
      RAISE EXCEPTION 'origin_compaction_request_identity_invalid'; END IF;
    IF split_part(r.signed_path,'?',1)='/aimos/compaction/save' THEN
      IF saved_record->>'schema' IS DISTINCT FROM 'hom.aimos.compaction-record/v1'
        OR saved_record->>'kind' IS DISTINCT FROM 'compaction_save'
        OR saved_record->>'project_id' IS DISTINCT FROM p_request_body->>'project_id'
        OR saved_record->>'session_id' IS DISTINCT FROM p_request_body->>'session_id'
        OR saved_record->>'workspace_path' IS DISTINCT FROM p_request_body->>'workspace_path'
        OR saved_record#>>'{time_window,valid_from}' IS DISTINCT FROM p_request_body->>'valid_from'
        OR saved_record#>>'{time_window,valid_until}' IS DISTINCT FROM p_request_body->>'valid_until'
        OR saved_record->'evidence' IS DISTINCT FROM jsonb_build_object('turns',p_request_body->'turns',
          'tool_events',p_request_body->'tool_events','files',p_request_body->'files','services',p_request_body->'services','tests',p_request_body->'tests')
        OR saved_record->'decisions' IS DISTINCT FROM p_request_body->'decisions'
        OR saved_record->'open_questions' IS DISTINCT FROM p_request_body->'open_questions'
        OR saved_record#>'{confidence,raw}' IS DISTINCT FROM p_request_body->'confidence'
        OR saved_record->'source_memory_ids' IS DISTINCT FROM coalesce(p_request_body->'source_memory_ids','[]')
        OR saved_record->'continuity' IS DISTINCT FROM jsonb_build_object(
          'current_objective',p_request_body->'current_objective','current_state',p_request_body->'current_state',
          'current_phase',p_request_body->'current_phase','next_actions',coalesce(p_request_body->'next_actions','[]')) THEN
        RAISE EXCEPTION 'origin_compaction_signed_detail_mismatch'; END IF;
      expected_key:=left('compaction:'||left(regexp_replace(regexp_replace(p_request_body->>'project_id','[^a-zA-Z0-9_:-]','_','g'),'_+','_','g'),80)
        ||':'||left(regexp_replace(regexp_replace(p_request_body->>'session_id','[^a-zA-Z0-9_:-]','_','g'),'_+','_','g'),80)
        ||':'||to_char((p_request_body->>'valid_from')::timestamptz AT TIME ZONE 'UTC','YYYYMMDD_HH24MISSMS"Z"'),255);
      IF m.key IS DISTINCT FROM expected_key THEN RAISE EXCEPTION 'origin_compaction_signed_key_mismatch'; END IF;
    ELSE
      IF saved_record->>'schema' IS DISTINCT FROM 'hom.aimos.post-compaction-record/v1'
        OR saved_record->>'kind' IS DISTINCT FROM 'post_compaction_summary_save' THEN
        RAISE EXCEPTION 'origin_compaction_handoff_shape_invalid'; END IF;
      SELECT * INTO input_source FROM public.aimos_memories
        WHERE id=(saved_record#>>'{source,memory_id}')::uuid AND company_id=m.company_id;
      IF input_source.id IS NULL
        OR (p_request_body->>'compaction_memory_id' IS NOT NULL
          AND p_request_body->>'compaction_memory_id' IS DISTINCT FROM input_source.id::text)
        OR (p_request_body->>'compaction_key' IS NOT NULL
          AND p_request_body->>'compaction_key' IS DISTINCT FROM input_source.key)
        OR (p_request_body->>'compaction_memory_id' IS NULL AND (p_request_body->>'compaction_key' IS NULL
          OR EXISTS(SELECT 1 FROM public.aimos_memories successor WHERE successor.company_id=m.company_id
            AND successor.key=input_source.key AND successor.supersedes_id=input_source.id))) THEN
        RAISE EXCEPTION 'origin_compaction_handoff_source_substitution'; END IF;
    END IF;
  END IF;
  b := o.body_json;
  pub := public.ob2_raw_ed25519_pubkey(o.agent_id,o.agent_valid_from);
  IF NOT EXISTS(SELECT 1 FROM public.agent_identity signer WHERE signer.agent_id=o.agent_id
    AND signer.valid_from=o.agent_valid_from AND signer.valid_from<=to_timestamp(o.ts_signed)
    AND signer.valid_until>to_timestamp(o.ts_signed) AND signer.revoked_at IS NULL
    AND encode(digest(convert_to(signer.cert,'UTF8'),'sha256'),'hex')=o.cert_fingerprint
    AND NOT EXISTS(SELECT 1 FROM public.aimos_agent_revocation_events revoked
      WHERE revoked.agent_id=signer.agent_id AND revoked.agent_valid_from=signer.valid_from)) THEN
    RAISE EXCEPTION 'origin_native_occurrence_signer_invalid'; END IF;
  IF o.sig_form_version=3 THEN
    IF NOT EXISTS(SELECT 1 FROM public.aimos_memory_provenance predecessor WHERE predecessor.memory_id=o.memory_id
      AND predecessor.provenance_id<>o.provenance_id
      AND public.ob2_occurrence_reference(predecessor,m.company_id)=o.prev_mutation_hash) THEN
      RAISE EXCEPTION 'origin_native_occurrence_predecessor_invalid'; END IF;
    IF b->>'schema' IS DISTINCT FROM 'hom.aimos.memory-occurrence/v3' OR o.agent_id IS DISTINCT FROM 'housekeeper'
      OR b->>'company_id' IS DISTINCT FROM m.company_id OR (b->>'occurrence_event_id')::uuid IS DISTINCT FROM o.provenance_id
      OR (b->>'memory_id')::uuid IS DISTINCT FROM m.id OR b->>'event_type' IS DISTINCT FROM o.event_type
      OR b->>'agent_id' IS DISTINCT FROM o.agent_id OR b->>'cert_fingerprint_hex' IS DISTINCT FROM o.cert_fingerprint
      OR b->>'live_content_hash_hex' IS DISTINCT FROM encode(m.content_hash,'hex')
      OR (b->>'signer_valid_from_unix_ms')::bigint IS DISTINCT FROM (extract(epoch FROM o.agent_valid_from)*1000)::bigint
      OR (b->>'ts_signed_unix_seconds')::bigint IS DISTINCT FROM o.ts_signed
      OR b->>'nonce_hex' IS DISTINCT FROM o.nonce OR b->>'identity_tier' IS DISTINCT FROM o.identity_tier
      OR b->>'predecessor_commitment_hex' IS DISTINCT FROM encode(o.prev_mutation_hash,'hex')
      OR (b->>'predecessor_present')::integer IS DISTINCT FROM 1 THEN
      RAISE EXCEPTION 'origin_native_reassertion_parity_invalid'; END IF;
    IF kind='verified_request' THEN
      IF b->>'event_type' IS DISTINCT FROM 'SAVE_REASSERT'
        OR (b->>'request_receipt_present')::integer IS DISTINCT FROM 1
        OR b->>'request_receipt_mutation_hash_hex' IS DISTINCT FROM encode(r.mutation_hash,'hex')
        OR b->>'signed_method' IS DISTINCT FROM r.signed_method OR b->>'signed_path' IS DISTINCT FROM r.signed_path
        OR (b->>'authorization_event_present')::integer IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'origin_native_reassertion_request_invalid'; END IF;
      e := public.ob2_verify_signed_event((b->>'authorization_event_id')::uuid,m.company_id);
      IF e.operation IS DISTINCT FROM 'request_admission_verified' OR e.agent_id IS DISTINCT FROM r.actor_agent_id
        OR e.metadata->>'request_receipt_mutation_hash' IS DISTINCT FROM encode(r.mutation_hash,'hex')
        OR e.metadata->>'request_hash' IS DISTINCT FROM encode(r.request_hash,'hex') THEN
        RAISE EXCEPTION 'origin_native_reassertion_admission_invalid'; END IF;
    ELSE
      effective_body := jsonb_build_object('event_type','INTERNAL_SAVE_REASSERT','company_id',m.company_id,
        'subject_agent_id',m.agent_id,'memory_id',m.id,'key',m.key,'value',m.value,'scope',m.scope,
        'clearance_level',m.clearance_level,'memory_type',m.memory_type,'source',m.source,'session_id',p_session,
        'authority_kind',kind,'action_event_id',e.id,'action_mutation_sha256',encode(e.mutation_hash,'hex'));
      request_hash := digest(convert_to(public.ob2_canonical_json(effective_body),'UTF8'),'sha256');
      IF b->>'event_type' IS DISTINCT FROM 'INTERNAL_SAVE_REASSERT'
        OR (b->>'request_receipt_present')::integer IS DISTINCT FROM 0
        OR (b->>'authorization_event_present')::integer IS DISTINCT FROM 0
        OR b->>'signed_method' IS DISTINCT FROM '' OR b->>'signed_path' IS DISTINCT FROM '' THEN
        RAISE EXCEPTION 'origin_native_reassertion_action_invalid'; END IF;
    END IF;
    IF b->>'request_body_hash_hex' IS DISTINCT FROM encode(request_hash,'hex')
      OR o.content_hash IS DISTINCT FROM request_hash THEN RAISE EXCEPTION 'origin_native_reassertion_body_invalid'; END IF;
    fields := ARRAY[convert_to(b->>'company_id','UTF8'),uuid_send((b->>'occurrence_event_id')::uuid),
      uuid_send((b->>'memory_id')::uuid),convert_to(b->>'event_type','UTF8'),decode(b->>'live_content_hash_hex','hex'),
      decode(lpad(to_hex((b->>'predecessor_present')::integer),2,'0'),'hex'),decode(b->>'predecessor_commitment_hex','hex'),
      convert_to(b->>'agent_id','UTF8'),int8send((b->>'signer_valid_from_unix_ms')::bigint),decode(b->>'cert_fingerprint_hex','hex'),
      convert_to(b->>'identity_tier','UTF8'),int2send((b->>'sig_form_version')::smallint),decode(b->>'nonce_hex','hex'),
      int8send((b->>'ts_signed_unix_seconds')::bigint),convert_to(b->>'signed_method','UTF8'),convert_to(b->>'signed_path','UTF8'),
      decode(b->>'request_body_hash_hex','hex'),decode(lpad(to_hex((b->>'request_receipt_present')::integer),2,'0'),'hex'),
      decode(b->>'request_receipt_mutation_hash_hex','hex'),decode(lpad(to_hex((b->>'authorization_event_present')::integer),2,'0'),'hex'),
      CASE WHEN b->>'authorization_event_id'='' THEN ''::bytea ELSE uuid_send((b->>'authorization_event_id')::uuid) END];
    enc := convert_to('hom.aimos.memory-occurrence/v3','UTF8')||decode('00','hex');
    FOR n IN 1..21 LOOP
      part := fields[n]; IF part IS NULL THEN RAISE EXCEPTION 'origin_native_reassertion_field_missing'; END IF;
      enc := enc||int2send(n::smallint)||int4send(octet_length(part))||part;
    END LOOP;
    expected := digest(enc,'sha256');
    msg := convert_to('hom.aimos.memory-occurrence-signature/v3','UTF8')||decode('00','hex')||expected;
    IF expected IS DISTINCT FROM o.mutation_hash OR encode(expected,'hex') IS DISTINCT FROM b->>'occurrence_commitment'
      OR pgsodium.crypto_sign_verify_detached(o.sig,msg,pub) IS NOT TRUE THEN
      RAISE EXCEPTION 'origin_native_reassertion_signature_invalid'; END IF;
  ELSIF o.sig_form_version=1 AND o.event_type='SAVE' THEN
    IF digest(o.content_hash||coalesce(o.prev_mutation_hash,''::bytea)||convert_to(o.nonce||o.ts_signed::text,'UTF8'),'sha256')
      IS DISTINCT FROM o.mutation_hash THEN RAISE EXCEPTION 'origin_native_save_chain_invalid'; END IF;
    IF kind='verified_request' THEN
      -- The request signature and receipt were verified above over their exact
      -- native bytes. Bind the occurrence to that proof, without a second
      -- JSONB reserialization of the same request.
      IF o.agent_id IS DISTINCT FROM r.actor_agent_id OR o.agent_valid_from IS DISTINCT FROM r.actor_valid_from
        OR o.sig IS DISTINCT FROM r.sig OR o.content_hash IS DISTINCT FROM r.request_hash
        OR o.body_json IS DISTINCT FROM effective_body OR o.nonce IS DISTINCT FROM r.nonce
        OR o.ts_signed IS DISTINCT FROM r.ts_signed OR o.request_sig_form IS DISTINCT FROM r.request_sig_form
        OR o.signed_method IS DISTINCT FROM r.signed_method OR o.signed_path IS DISTINCT FROM r.signed_path
        OR o.signed_claims IS DISTINCT FROM r.signed_claims THEN
        RAISE EXCEPTION 'origin_request_signature_invalid'; END IF;
    ELSE
      IF o.agent_id IS DISTINCT FROM 'housekeeper' OR o.agent_valid_from IS DISTINCT FROM e.signer_valid_from
        OR b->>'memory_id' IS DISTINCT FROM m.id::text OR b->>'subject_agent_id' IS DISTINCT FROM m.agent_id
        OR b->>'company_id' IS DISTINCT FROM m.company_id
        OR b->>'key' IS DISTINCT FROM m.key OR b->>'value' IS DISTINCT FROM m.value
        OR b->>'scope' IS DISTINCT FROM m.scope OR b->>'memory_type' IS DISTINCT FROM m.memory_type
        OR b->>'source' IS DISTINCT FROM m.source OR b->>'session_id' IS DISTINCT FROM p_session
        OR (b->>'clearance_level')::integer IS DISTINCT FROM m.clearance_level
        OR (kind='verified_housekeeper_action' AND (b->>'housekeeper_action_event_id' IS DISTINCT FROM e.id::text
          OR b->>'housekeeper_action_mutation_hash' IS DISTINCT FROM encode(e.mutation_hash,'hex')
          OR b->>'housekeeper_action_sha256' IS DISTINCT FROM e.metadata->>'action_sha256'
          OR b->>'housekeeper_action_context_sha256' IS DISTINCT FROM e.metadata->>'action_context_sha256'))
        OR (kind='verified_tool_action' AND (b->>'tool_action_event_id' IS DISTINCT FROM e.id::text
          OR b->>'tool_action_mutation_hash' IS DISTINCT FROM encode(e.mutation_hash,'hex')
          OR b->>'tool_action_args_sha256' IS DISTINCT FROM e.metadata->>'args_sha256')) THEN
        RAISE EXCEPTION 'origin_native_save_action_parity_invalid'; END IF;
      enc := convert_to(public.ob2_canonical_json(b),'UTF8');
      msg := enc||convert_to(E'\n'||o.nonce||E'\n'||o.ts_signed::text,'UTF8');
      IF digest(enc,'sha256') IS DISTINCT FROM o.content_hash
        OR pgsodium.crypto_sign_verify_detached(o.sig,msg,pub) IS NOT TRUE THEN
        RAISE EXCEPTION 'origin_native_save_action_signature_invalid'; END IF;
    END IF;
  ELSE RAISE EXCEPTION 'origin_native_occurrence_form_invalid'; END IF;
END
$function$;
REVOKE ALL ON FUNCTION public.ob2_verify_native_save_authority(uuid,jsonb,json,text) FROM PUBLIC,agent_runtime,aimos_app;

-- Native input-set projection. It reads retained session/compaction facts and
-- returns IDs only. It has no signing, mutation, classification or grant power.
CREATE OR REPLACE FUNCTION public.ob3_native_save_input_ids(company text, subject text, value text, session text, declared jsonb DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $function$
DECLARE r jsonb; source public.aimos_memories%ROWTYPE; item jsonb; stored jsonb; turn_map jsonb;
  ids uuid[] := '{}'; actual uuid[]; supplied uuid[]; producer text := NULL; n integer; prefix text;
BEGIN
  IF company IS DISTINCT FROM current_setting('app.current_client_id',true) THEN
    RAISE EXCEPTION 'origin_input_company_invalid'; END IF;
  BEGIN r:=value::jsonb; EXCEPTION WHEN invalid_text_representation THEN r:='{}'; END;
  IF jsonb_typeof(r) IS DISTINCT FROM 'object' THEN r:='{}'; END IF;
  IF r->>'schema' IN ('aimos.session-exchange/v1','aimos.session-exchange/v2') THEN
    producer:='session_exchange';
    IF jsonb_typeof(r->'source_memory_ids') IS DISTINCT FROM 'array'
      OR jsonb_array_length(r->'source_memory_ids') NOT IN (1,2)
      OR jsonb_typeof(r->'source_content_sha256') IS DISTINCT FROM 'array'
      OR jsonb_array_length(r->'source_content_sha256')<>jsonb_array_length(r->'source_memory_ids') THEN
      RAISE EXCEPTION 'origin_session_input_shape_invalid'; END IF;
    SELECT array_agg(v::uuid ORDER BY ord) INTO ids
      FROM jsonb_array_elements_text(r->'source_memory_ids') WITH ORDINALITY x(v,ord);
    IF cardinality(ids)<>cardinality(ARRAY(SELECT DISTINCT unnest(ids))) THEN
      RAISE EXCEPTION 'origin_session_input_duplicate'; END IF;
    FOR n IN 1..cardinality(ids) LOOP
      SELECT * INTO source FROM public.aimos_memories WHERE id=ids[n] AND company_id=company;
      IF source.id IS NULL THEN RAISE EXCEPTION 'origin_input_memory_missing'; END IF;
      stored:=source.value::jsonb;
      IF stored->>'schema' IS DISTINCT FROM 'aimos.session-turn/v1'
        OR stored->>'session_id' IS DISTINCT FROM r->>'session_id'
        OR encode(digest(convert_to(stored->>'content','UTF8'),'sha256'),'hex') IS DISTINCT FROM r#>>ARRAY['source_content_sha256',(n-1)::text] THEN
        RAISE EXCEPTION 'origin_session_input_content_invalid'; END IF;
      IF r->>'schema'='aimos.session-exchange/v1' THEN
        IF stored->>'role' IS DISTINCT FROM (CASE n WHEN 1 THEN 'user' ELSE 'assistant' END)
          OR stored->>'content' IS DISTINCT FROM r->>(CASE n WHEN 1 THEN 'user' ELSE 'assistant' END)
          OR (stored->>'sequence')::bigint IS DISTINCT FROM (r->>(CASE n WHEN 1 THEN 'user_sequence' ELSE 'assistant_sequence' END))::bigint THEN
          RAISE EXCEPTION 'origin_session_input_content_invalid'; END IF;
      ELSE
        item:=r#>ARRAY['turns',(n-1)::text];
        IF item IS DISTINCT FROM (stored-'schema'-'session_id'-'turn_id_sha256'
          -CASE WHEN stored->>'source_ref' IS NULL THEN 'source_ref' ELSE '_absent' END) THEN
          RAISE EXCEPTION 'origin_session_input_content_invalid'; END IF;
      END IF;
    END LOOP;
  ELSIF r->>'schema'='aimos.session-finalization/v1' THEN
    producer:='session_finalization'; prefix:='sess:'||(r->>'session_id')||':';
    IF jsonb_typeof(r->'turns') IS DISTINCT FROM 'array' OR jsonb_typeof(r->'exchanges') IS DISTINCT FROM 'array'
      OR (r->>'turn_count')::integer IS DISTINCT FROM jsonb_array_length(r->'turns')
      OR (r->>'exchange_count')::integer IS DISTINCT FROM jsonb_array_length(r->'exchanges') THEN
      RAISE EXCEPTION 'origin_session_input_shape_invalid'; END IF;
    SELECT coalesce(array_agg(m.id ORDER BY m.id),'{}') INTO actual FROM public.aimos_memories m
      WHERE m.company_id=company AND left(m.key,length(prefix))=prefix
        AND (substring(m.key FROM length(prefix)+1) LIKE 'turn:%'
          OR substring(m.key FROM length(prefix)+1) LIKE 'exchange:%');
    SELECT coalesce(array_agg(DISTINCT id ORDER BY id),'{}') INTO supplied FROM (
      SELECT (x->>'memory_id')::uuid AS id FROM jsonb_array_elements(r->'turns') x
      UNION ALL SELECT (x->>'memory_id')::uuid FROM jsonb_array_elements(r->'exchanges') x
      UNION ALL SELECT x::uuid FROM jsonb_array_elements_text(coalesce(r->'retained_retry_copy_memory_ids','[]')) x
    ) members;
    IF actual IS DISTINCT FROM supplied OR cardinality(actual)=0 THEN
      RAISE EXCEPTION 'origin_session_input_membership_invalid'; END IF;
    FOR item IN SELECT x FROM jsonb_array_elements((r->'turns')||(r->'exchanges')) x LOOP
      SELECT * INTO source FROM public.aimos_memories WHERE id=(item->>'memory_id')::uuid AND company_id=company;
      IF item->>'live_content_hash' IS DISTINCT FROM encode(source.content_hash,'hex') THEN
        RAISE EXCEPTION 'origin_session_input_content_invalid'; END IF;
    END LOOP;
    ids:=actual;
  ELSIF r->>'schema'='hom.aimos.compaction-record/v1' AND r->>'kind'='compaction_save' THEN
    producer:='compaction_full'; prefix:='sess:'||(r->>'session_id')||':turn:';
    IF jsonb_typeof(r#>'{evidence,turns}') IS DISTINCT FROM 'array'
      OR jsonb_array_length(r#>'{evidence,turns}')=0
      OR jsonb_typeof(r->'source_memory_ids') IS DISTINCT FROM 'array' THEN
      RAISE EXCEPTION 'origin_compaction_input_shape_invalid'; END IF;
    SELECT coalesce(array_agg(DISTINCT id ORDER BY id),'{}') INTO ids FROM (
      SELECT v::uuid AS id FROM jsonb_array_elements_text(r->'source_memory_ids') v
      UNION ALL SELECT (x->>'memory_id')::uuid FROM jsonb_array_elements(r#>'{evidence,turns}') x
        WHERE x->>'memory_id' IS NOT NULL
    ) declared;
    SELECT coalesce(jsonb_object_agg(x->>'memory_id',x),'{}') INTO turn_map
      FROM jsonb_array_elements(r#>'{evidence,turns}') x WHERE x->>'memory_id' IS NOT NULL;
    IF (SELECT count(*) FROM jsonb_array_elements(r#>'{evidence,turns}') x WHERE x->>'memory_id' IS NOT NULL)
      <> (SELECT count(*) FROM jsonb_object_keys(turn_map)) THEN RAISE EXCEPTION 'origin_compaction_input_duplicate'; END IF;
    FOR source IN SELECT m.* FROM public.aimos_memories m WHERE m.company_id=company
      AND left(m.key,length(prefix))=prefix ORDER BY m.key LOOP
      stored:=source.value::jsonb;
      item:=turn_map->source.id::text;
      IF item IS NULL OR (item-'memory_id') IS DISTINCT FROM stored THEN
        RAISE EXCEPTION 'origin_compaction_session_detail_missing'; END IF;
      ids:=array_append(ids,source.id);
    END LOOP;
    FOR source IN SELECT m.* FROM public.aimos_memories m WHERE m.company_id=company
      AND m.id=ANY(ids) AND turn_map ? m.id::text LOOP
      IF ((turn_map->(source.id::text))-'memory_id') IS DISTINCT FROM source.value::jsonb THEN
        RAISE EXCEPTION 'origin_compaction_session_detail_missing'; END IF;
    END LOOP;
  ELSIF r->>'schema'='hom.aimos.post-compaction-record/v1' AND r->>'kind'='post_compaction_summary_save' THEN
    producer:='compaction_handoff'; ids:=ARRAY[(r#>>'{source,memory_id}')::uuid];
    SELECT * INTO source FROM public.aimos_memories WHERE id=ids[1] AND company_id=company;
    IF source.id IS NULL OR source.value::jsonb->>'kind' IS DISTINCT FROM 'compaction_save'
      OR r#>>'{source,full_compaction_key}' IS DISTINCT FROM source.key
      OR r#>>'{source,full_compaction_content_hash}' IS DISTINCT FROM encode(source.content_hash,'hex')
      OR r->>'session_id' IS DISTINCT FROM source.value::jsonb->>'session_id'
      OR r->>'project_id' IS DISTINCT FROM source.value::jsonb->>'project_id' THEN
      RAISE EXCEPTION 'origin_compaction_source_invalid'; END IF;
  ELSE
    IF declared IS NULL THEN RETURN NULL; END IF;
    producer:='declared_inputs';
  END IF;
  IF producer<>'declared_inputs' AND (r->>'session_id' IS DISTINCT FROM session OR session IS NULL OR session='') THEN
    RAISE EXCEPTION 'origin_input_session_mismatch'; END IF;
  IF declared IS NOT NULL THEN
    IF jsonb_typeof(declared) IS DISTINCT FROM 'array' OR jsonb_array_length(declared)>16384 THEN
      RAISE EXCEPTION 'origin_declared_input_set_invalid'; END IF;
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(declared) x WHERE jsonb_typeof(x)<>'string'
      OR (x#>>'{}') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$') THEN
      RAISE EXCEPTION 'origin_declared_input_set_invalid'; END IF;
    SELECT coalesce(array_agg(x::uuid),'{}') INTO supplied FROM jsonb_array_elements_text(declared) x;
    IF cardinality(supplied)<>cardinality(ARRAY(SELECT DISTINCT unnest(supplied))) THEN
      RAISE EXCEPTION 'origin_declared_input_set_invalid'; END IF;
    ids:=ids||supplied;
  END IF;
  SELECT coalesce(array_agg(DISTINCT id ORDER BY id),'{}') INTO ids FROM unnest(ids) id;
  IF array_position(ids,NULL) IS NOT NULL OR cardinality(ids)>16384 THEN
    RAISE EXCEPTION 'origin_input_count_invalid'; END IF;
  IF EXISTS(SELECT 1 FROM unnest(ids) i LEFT JOIN public.aimos_memories m ON m.id=i
      WHERE m.id IS NULL OR m.company_id IS DISTINCT FROM company
        OR (m.cube_scope='private' AND m.agent_id IS DISTINCT FROM subject)
        OR NOT coalesce(m.scope IN ('global','executive','system')
          -- Historical project-scoped rows remain readable only by their
          -- original subject here. This does not enable project-scoped SAVE.
          OR (m.scope IN ('private','agent','project',subject) AND m.agent_id=subject)
          OR ((m.scope='quarantine' OR m.memory_type='quarantine')
            AND (m.agent_id=subject OR subject='housekeeper')),false)) THEN
    RAISE EXCEPTION 'origin_input_memory_not_authorized'; END IF;
  RETURN jsonb_build_object('producer',producer,'memory_ids',to_jsonb(ids));
END
$function$;
REVOKE ALL ON FUNCTION public.ob3_native_save_input_ids(text,text,text,text,jsonb) FROM PUBLIC,aimos_app;
GRANT EXECUTE ON FUNCTION public.ob3_native_save_input_ids(text,text,text,text,jsonb) TO agent_runtime;

DROP FUNCTION IF EXISTS public.commit_memory_origin_binding_v2(jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea,jsonb);
CREATE OR REPLACE FUNCTION public.commit_memory_origin_binding_v2(
  p_body jsonb,
  p_body_bytes bytea,
  p_binding_sha256 bytea,
  p_classification_event_id uuid,
  p_prev_ledger_hash bytea,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text,
  p_authority_profile_sha256 bytea,
  p_signed_at timestamptz,
  p_ledger_signature bytea,
  p_request_json json
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_schema text := p_body->>'schema';
  p_request_body jsonb := p_request_json::jsonb;
  c_family_profile constant bytea := decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex');
  v_company text;
  v_memory_id uuid;
  v_occurrence_id uuid;
  v_content bytea;
  v_actor text;
  v_actor_valid_from timestamptz;
  v_actor_fingerprint text;
  v_receipt_id uuid;
  v_request_mutation bytea;
  v_ingress text;
  v_channel_identity bytea;
  v_parents bytea[];
  v_families text[];
  v_confidentiality text;
  v_integrity text;
  v_action text;
  v_scope text;
  v_event public.aimos_events%ROWTYPE;
  v_memory record;
  v_occurrence record;
  v_receipt record;
  v_identity record;
  v_ledger_hash bytea;
  v_missing integer;
  v_floor integer;
  v_parent_floor integer;
  v_parent_integrity integer;
  v_parent_action integer;
  v_native_inputs jsonb;
  v_input jsonb;
  v_input_memory public.aimos_memories%ROWTYPE;
  v_input_binding public.aimos_memory_origin_bindings%ROWTYPE;
  v_input_ids uuid[];
  v_input_hash bytea;
  v_input_bytes bytea;
  v_input_origin text;
  v_declared_inputs jsonb;
  v_intent jsonb;
  v_call_count integer;
  v_snapshot jsonb;
  v_snapshot_body jsonb;
  v_result_ref jsonb;
  v_result jsonb;
  v_result_body jsonb;
  v_result_event public.aimos_events%ROWTYPE;
  v_result_start public.aimos_events%ROWTYPE;
  v_result_families text[];
  v_result_bytes bytea;
BEGIN
  IF p_body IS NULL OR p_body_bytes IS NULL OR p_binding_sha256 IS NULL OR p_classification_event_id IS NULL
    OR p_signer_valid_from IS NULL OR p_signer_cert_fingerprint IS NULL OR p_authority_profile_sha256 IS NULL
    OR p_signed_at IS NULL OR p_ledger_signature IS NULL OR octet_length(p_body_bytes)>1048576
    OR c_schema IS NULL OR c_schema NOT IN ('hom.aimos.memory-origin-binding/v2','hom.aimos.memory-origin-binding/v3')
    THEN RAISE EXCEPTION 'origin_memory_field_invalid'; END IF;
  PERFORM public.ob2_verify_origin_object(c_schema, p_body, p_body_bytes, p_binding_sha256);
  IF (NOT public.ob2_exact_json_keys(p_body, ARRAY[
    'schema','company_id','memory_id','occurrence_id','content_sha256','actor','request',
    'operation_authority','origin','parents','classification','confidentiality','integrity','action_class',
    'scope','session_id','tool_action_event_id','created_at'
  ] || CASE WHEN c_schema='hom.aimos.memory-origin-binding/v3' THEN ARRAY['derivation'] ELSE '{}'::text[] END)
  OR NOT public.ob2_exact_json_keys(p_body->'actor', ARRAY[
    'agent_id','valid_from','cert_fingerprint_sha256'
  ]) OR (p_body->'request' <> 'null'::jsonb AND NOT public.ob2_exact_json_keys(p_body->'request', ARRAY[
    'receipt_id','mutation_sha256'
  ])) OR NOT public.ob2_exact_json_keys(p_body->'origin', ARRAY[
    'ingress_channel','channel_identity_sha256'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'parents', ARRAY['origin_sha256s'])
     OR NOT public.ob2_exact_json_keys(p_body->'classification', ARRAY[
       'profile_sha256','family_ids','authority','evidence_sha256'
     ])) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_memory_shape_invalid';
  END IF;

  BEGIN
    v_company := p_body->>'company_id';
    v_memory_id := (p_body->>'memory_id')::uuid;
    v_occurrence_id := (p_body->>'occurrence_id')::uuid;
    v_content := decode(p_body->>'content_sha256','hex');
    v_actor := p_body#>>'{actor,agent_id}';
    v_actor_valid_from := (p_body#>>'{actor,valid_from}')::timestamptz;
    v_actor_fingerprint := p_body#>>'{actor,cert_fingerprint_sha256}';
    v_receipt_id := (p_body#>>'{request,receipt_id}')::uuid;
    v_request_mutation := decode(p_body#>>'{request,mutation_sha256}','hex');
    v_ingress := p_body#>>'{origin,ingress_channel}';
    v_channel_identity := decode(p_body#>>'{origin,channel_identity_sha256}','hex');
    v_parents := public.ob2_json_hash_array(p_body#>'{parents,origin_sha256s}');
    v_families := public.ob2_json_text_array(p_body#>'{classification,family_ids}');
    v_confidentiality := p_body->>'confidentiality';
    v_integrity := p_body->>'integrity';
    v_action := p_body->>'action_class';
    v_scope := p_body->>'scope';
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'origin_memory_field_invalid';
  END;
  IF (octet_length(v_content) <> 32 OR (v_request_mutation IS NOT NULL AND octet_length(v_request_mutation) <> 32)
     OR octet_length(v_channel_identity) <> 32
     OR p_body#>>'{classification,profile_sha256}' <> encode(c_family_profile,'hex')
     OR p_body#>>'{classification,evidence_sha256}' !~ '^[0-9a-f]{64}$'
     OR v_actor_fingerprint !~ '^[0-9a-f]{64}$'
     OR v_scope IS NULL OR v_scope = '') IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_memory_field_invalid';
  END IF;
  IF (v_parents <> ARRAY(
       SELECT value FROM unnest(v_parents) value ORDER BY encode(value,'hex')
     ) OR cardinality(ARRAY(SELECT DISTINCT value FROM unnest(v_parents) value)) <> cardinality(v_parents)
     OR cardinality(v_parents) > 64) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_parent_set_invalid';
  END IF;
  PERFORM public.ob2_validate_family_set(c_family_profile, v_families);

  SELECT memory.content_hash, memory.company_id, memory.scope, memory.data_class, memory.supersedes_id,
         memory.value,memory.agent_id,memory.clearance_level,memory.memory_type,memory.key
    INTO v_memory FROM public.aimos_memories memory
   WHERE memory.id = v_memory_id FOR SHARE;
  IF (NOT FOUND OR v_memory.company_id <> v_company OR v_memory.content_hash <> v_content
     OR v_memory.scope <> v_scope OR v_memory.data_class <> v_confidentiality) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_memory_relational_mismatch';
  END IF;
  -- A legacy predecessor may not yet have an origin object. Its retained
  -- confidentiality still cannot be lowered by appending a version. This is
  -- a storage-label floor, not a fabricated family or historical origin claim.
  IF EXISTS (SELECT 1 FROM public.aimos_memories predecessor
    WHERE predecessor.id=v_memory.supersedes_id
      AND (predecessor.company_id IS DISTINCT FROM v_company
        OR array_position(ARRAY['public','internal','confidential','restricted'],predecessor.data_class)
          > array_position(ARRAY['public','internal','confidential','restricted'],v_confidentiality))) THEN
    RAISE EXCEPTION 'origin_version_confidentiality_downgrade';
  END IF;

  IF (p_body->'actor' IS DISTINCT FROM p_body#>'{operation_authority,actor}'
    OR p_body->>'company_id' IS DISTINCT FROM p_body#>>'{operation_authority,company_id}'
    OR (p_body#>>'{operation_authority,kind}'='verified_request' AND
      p_body->'request' IS DISTINCT FROM jsonb_build_object(
        'receipt_id',p_body#>>'{operation_authority,evidence,receipt_id}',
        'mutation_sha256',p_body#>>'{operation_authority,evidence,mutation_sha256}'))
    OR (p_body#>>'{operation_authority,kind}'<>'verified_request' AND p_body->'request' IS DISTINCT FROM 'null'::jsonb)) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_native_binding_authority_mismatch';
  END IF;
  PERFORM public.ob2_verify_native_save_authority(
    v_occurrence_id,p_body->'operation_authority',p_request_json,p_body->>'session_id');
  IF NOT EXISTS(SELECT 1 FROM public.aimos_memory_provenance p
    WHERE p.provenance_id=v_occurrence_id AND p.memory_id=v_memory_id
      AND p.live_content_hash=v_content) THEN RAISE EXCEPTION 'origin_occurrence_relational_mismatch'; END IF;


  v_event := public.ob2_verify_signed_event(p_classification_event_id, v_company);

  IF (v_event.operation IS DISTINCT FROM 'origin_family_classified'
    OR v_event.signer_agent_id IS DISTINCT FROM 'housekeeper'
    OR v_event.mutation_hash IS DISTINCT FROM decode(p_body#>>'{classification,evidence_sha256}','hex')
    OR v_event.metadata->>'schema' IS DISTINCT FROM 'hom.aimos.origin-classification-evidence/v2'
    OR v_event.metadata->'binding' IS DISTINCT FROM ((p_body-'created_at') #- '{classification,evidence_sha256}')
    OR (p_body->>'created_at')::timestamptz IS DISTINCT FROM to_timestamp(v_event.ts_signed)) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_classification_evidence_invalid';
  END IF;
  IF (v_ingress IS DISTINCT FROM CASE
      WHEN p_body#>>'{operation_authority,kind}'='verified_tool_action' THEN 'authenticated_tool'
      WHEN p_body#>>'{operation_authority,kind}'='verified_request' AND v_actor<>'housekeeper' THEN 'authenticated_agent'
      ELSE 'housekeeper_system' END
    OR v_channel_identity IS DISTINCT FROM decode(v_actor_fingerprint,'hex')
    OR p_body->>'tool_action_event_id' IS DISTINCT FROM CASE
      WHEN p_body#>>'{operation_authority,kind}'='verified_tool_action'
      THEN p_body#>>'{operation_authority,evidence,event_id}' ELSE NULL END
    OR v_integrity NOT IN ('untrusted','agent')
    OR v_action NOT IN ('none','inform')
    OR p_body#>>'{classification,authority}' IS DISTINCT FROM 'deterministic_field_schema') IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_native_classification_scope_invalid';
  END IF;


  IF (v_ingress IN ('authenticated_agent','agent_self') AND encode(v_channel_identity,'hex') <> v_actor_fingerprint) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_channel_identity_invalid';
  ELSIF v_ingress = 'housekeeper_system' AND encode(v_channel_identity,'hex') <> p_signer_cert_fingerprint THEN
    RAISE EXCEPTION 'origin_channel_identity_invalid';
  END IF;
  IF (v_integrity = 'trusted' AND v_ingress NOT IN ('authenticated_tool','authenticated_user','system_internal')) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_integrity_elevation';
  END IF;
  IF ((v_action = 'act' AND v_integrity <> 'trusted') OR (v_action = 'inform' AND v_integrity = 'untrusted')) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_action_class_elevation';
  END IF;
  IF v_action<>'none' AND EXISTS (
    SELECT 1 FROM public.aimos_origin_family_definitions definition
     WHERE definition.profile_sha256=c_family_profile AND definition.family_id=ANY(v_families)
       AND definition.action_policy NOT IN ('inform_only','inherit_parents')
  ) THEN RAISE EXCEPTION 'origin_family_action_elevation'; END IF;
  SELECT max(array_position(ARRAY['public','internal','confidential','restricted'], definition.confidentiality_floor))
    INTO v_floor FROM public.aimos_origin_family_definitions definition
   WHERE definition.profile_sha256 = c_family_profile AND definition.family_id = ANY(v_families);
  IF (array_position(ARRAY['public','internal','confidential','restricted'], v_confidentiality) < v_floor) IS NOT FALSE THEN
    RAISE EXCEPTION 'origin_confidentiality_floor_invalid';
  END IF;

  -- Resolve declared input membership from the already-verified operation,
  -- never from the caller-supplied output classification or derivation list.
  IF p_body#>>'{operation_authority,kind}'='verified_request' THEN
    v_intent:=p_request_body;
    IF split_part(p_body#>>'{operation_authority,evidence,signed_path}','?',1)='/aimos/mcp/tools/call' THEN
      IF v_intent->>'name'<>'aimos_save' THEN RAISE EXCEPTION 'origin_declared_input_intent_ambiguous'; END IF;
      v_intent:=v_intent->'arguments';
    ELSIF split_part(p_body#>>'{operation_authority,evidence,signed_path}','?',1)='/mcp' THEN
      SELECT count(*),(array_agg(args))[1] INTO v_call_count,v_intent FROM (
        SELECT CASE WHEN jsonb_typeof(x#>'{params,arguments}')='string'
          THEN (x#>>'{params,arguments}')::jsonb ELSE x#>'{params,arguments}' END AS args
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p_request_body)='array'
          THEN p_request_body ELSE jsonb_build_array(p_request_body) END) x
        WHERE x->>'method'='tools/call' AND x#>>'{params,name}'='aimos_save'
      ) calls WHERE args->>'key'=v_memory.key;
      IF v_call_count<>1 THEN RAISE EXCEPTION 'origin_declared_input_intent_ambiguous'; END IF;
    END IF;
    IF jsonb_typeof(v_intent)='string' THEN v_intent:=(v_intent#>>'{}')::jsonb; END IF;
    v_declared_inputs:=v_intent->'source_memory_ids';
  ELSE
    v_event:=public.ob2_verify_signed_event((p_body#>>'{operation_authority,evidence,event_id}')::uuid,v_company);
    v_declared_inputs:=v_event.metadata->'source_memory_ids';
    v_snapshot:=v_event.metadata->'native_input_snapshot';
  END IF;
  -- The native producer's signed operation supplies this snapshot. Never
  -- accept trust labels or result references from the public SAVE request.
  IF v_snapshot IS NOT NULL THEN
    v_snapshot_body:=v_snapshot-'input_sha256';
    IF public.ob2_exact_json_keys(v_snapshot_body,ARRAY['schema','memory_ids','tool_results','context_inputs','context_receipts']) IS NOT TRUE
      OR v_snapshot->>'schema' IS DISTINCT FROM 'hom.aimos.tool-input-snapshot/v2'
      OR v_snapshot->>'input_sha256' IS DISTINCT FROM encode(digest(convert_to(public.ob2_canonical_json(v_snapshot_body),'UTF8'),'sha256'),'hex')
      OR jsonb_typeof(v_snapshot->'memory_ids') IS DISTINCT FROM 'array'
      OR jsonb_typeof(v_snapshot->'context_inputs') IS DISTINCT FROM 'array'
      OR jsonb_typeof(v_snapshot->'tool_results') IS DISTINCT FROM 'array'
      OR v_declared_inputs IS NULL OR NOT v_declared_inputs @> (v_snapshot->'memory_ids')
      OR NOT 'derived'=ANY(v_families) THEN RAISE EXCEPTION 'origin_native_snapshot_invalid'; END IF;
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(v_snapshot->'context_inputs') i WHERE i->>'kind' IN ('file','record'))
      AND (v_confidentiality<>'restricted' OR v_integrity<>'untrusted' OR v_action<>'none'
        OR NOT 'unknown_protected'=ANY(v_families)) THEN RAISE EXCEPTION 'origin_opaque_context_elevated'; END IF;
    FOR v_result_ref IN SELECT x FROM jsonb_array_elements(v_snapshot->'tool_results') x LOOP
      v_result_event:=public.ob2_verify_signed_event((v_result_ref->>'terminal_event_id')::uuid,v_company);
      v_result:=v_result_event.metadata->'result_origin';
      v_result_body:=v_result-'classification_sha256';
      v_result_bytes:=convert_to(public.ob2_canonical_json(v_result_body),'UTF8');
      IF (v_result->>'schema' IS DISTINCT FROM 'hom.aimos.native-result-origin/v1'
        OR v_result_event.operation NOT IN ('tool_execution_terminal','model_context_completed')
        OR v_result_event.signer_agent_id IS DISTINCT FROM 'housekeeper'
        OR v_result->>'classification_sha256' IS DISTINCT FROM v_result_ref->>'classification_sha256'
        OR v_result->>'classification_sha256' IS DISTINCT FROM encode(digest(convert_to('hom.aimos.native-result-origin/v1','UTF8')
          ||decode('00','hex')||int4send(octet_length(v_result_bytes))||v_result_bytes,'sha256'),'hex')
        OR encode(v_result_event.mutation_hash,'hex') IS DISTINCT FROM v_result_ref->>'terminal_mutation_sha256'
        OR v_result->>'company_id' IS DISTINCT FROM v_company
        OR v_result->>'family_profile_sha256' IS DISTINCT FROM encode(c_family_profile,'hex')
        OR v_result->'independent_authority' IS DISTINCT FROM 'false'::jsonb
        OR v_result->>'action_event_id' IS DISTINCT FROM v_result_ref->>'action_event_id'
        OR v_result_event.parent_event_id::text IS DISTINCT FROM v_result->>'action_event_id'
        OR v_result->>'result_sha256' IS DISTINCT FROM v_result_ref->>'result_sha256'
        OR v_result->>'disclosed_result_sha256' IS DISTINCT FROM v_result_ref->>'disclosed_result_sha256'
        OR v_result->>'input_snapshot_sha256' IS DISTINCT FROM v_result#>>'{input_snapshot,input_sha256}'
        OR v_result->>'input_snapshot_sha256' IS DISTINCT FROM encode(digest(convert_to(public.ob2_canonical_json(
          (v_result->'input_snapshot')-'input_sha256'),'UTF8'),'sha256'),'hex')
        OR jsonb_typeof(v_result->'family_ids') IS DISTINCT FROM 'array'
        OR jsonb_typeof(v_result->'private_subject_ids') IS DISTINCT FROM 'array'
        OR (v_result->>'clearance_floor')::integer NOT BETWEEN 1 AND 12
        OR v_result->>'confidentiality' NOT IN ('public','internal','confidential','restricted')
        OR v_result->>'integrity' NOT IN ('untrusted','agent','trusted')
        OR v_result->>'action_class' NOT IN ('none','inform')) IS NOT FALSE
        THEN RAISE EXCEPTION 'origin_native_result_binding_invalid'; END IF;
      v_result_start:=public.ob2_verify_signed_event((v_result->>'action_event_id')::uuid,v_company);
      IF v_result_event.operation='tool_execution_terminal' AND v_result_start.metadata ? 'dispatch_allowed' THEN
        IF (public.ob2_exact_json_keys(v_result->'execution',ARRAY['disposition','tool_invoked']) IS NOT TRUE
          OR v_result#>>'{execution,disposition}' NOT IN ('SUCCEEDED','DENIED','FAILED','INDETERMINATE')
          OR jsonb_typeof(v_result#>'{execution,tool_invoked}') IS DISTINCT FROM 'boolean'
          OR v_result#>>'{execution,disposition}' IS DISTINCT FROM v_result_event.metadata->>'disposition'
          OR v_result_event.metadata->>'outcome_sha256' IS DISTINCT FROM v_result->>'result_sha256'
          OR (v_result_start.metadata->'dispatch_allowed'='false'::jsonb AND
            (v_result#>'{execution,tool_invoked}' IS DISTINCT FROM 'false'::jsonb
              OR v_result#>>'{execution,disposition}' IS DISTINCT FROM 'DENIED'))
          OR (v_result#>>'{execution,disposition}'='SUCCEEDED'
            AND v_result#>'{execution,tool_invoked}' IS DISTINCT FROM 'true'::jsonb)) IS NOT FALSE
          THEN RAISE EXCEPTION 'origin_native_result_execution_invalid'; END IF;
      END IF;
      IF (encode(v_result_start.mutation_hash,'hex') IS DISTINCT FROM v_result_ref->>'action_mutation_sha256'
        OR v_result_start.signer_agent_id IS DISTINCT FROM 'housekeeper'
        OR v_result_start.agent_id IS DISTINCT FROM v_result_event.agent_id
        OR v_result->'native_profile_sha256' IS DISTINCT FROM coalesce(v_result_start.metadata->'native_tool_profile_sha256','null'::jsonb)
        OR (v_result_event.operation='tool_execution_terminal' AND (
          v_result_start.operation<>'tool_execution_started'
          OR v_result_event.metadata->>'tool_action_event_id' IS DISTINCT FROM v_result_start.id::text
          OR (CASE WHEN v_result#>'{execution,tool_invoked}'='false'::jsonb THEN
              v_result#>>'{source,owner}' IS DISTINCT FROM 'services/orchestration/tool-registry.js#executeTool'
              OR v_result#>>'{source,kind}' IS DISTINCT FROM 'native_derivation'
              OR v_result#>>'{source,namespace}' IS DISTINCT FROM 'hom.aimos.tool_decision'
            ELSE v_result#>>'{source,owner}' IS DISTINCT FROM v_result_start.metadata#>>'{native_tool_profile,owner}'
              OR v_result#>>'{source,kind}' IS DISTINCT FROM v_result_start.metadata#>>'{native_tool_profile,source_kind}'
              OR v_result#>>'{source,namespace}' IS DISTINCT FROM v_result_start.metadata#>>'{native_tool_profile,source_namespace}' END)
          OR v_result_ref->>'tool' IS DISTINCT FROM v_result_start.metadata#>>'{native_tool_profile,tool}'
          OR v_result->>'native_profile_sha256' IS DISTINCT FROM encode(digest(convert_to(public.ob2_canonical_json(
            v_result_start.metadata->'native_tool_profile'),'UTF8'),'sha256'),'hex')
          OR (v_result_event.metadata->>'disposition'='SUCCEEDED'
            AND v_result_event.metadata->>'outcome_sha256' IS DISTINCT FROM v_result->>'result_sha256')))
        OR (v_result_event.operation='model_context_completed' AND (
          v_result_start.operation<>'tool_context_prepared' OR v_result_ref->>'result_kind' IS DISTINCT FROM 'model'
          OR v_result_ref->'tool' IS DISTINCT FROM 'null'::jsonb
          OR v_result#>>'{source,owner}' IS DISTINCT FROM 'services/orchestration/agent-tools.js#runByModel'
          OR v_result_event.metadata->>'outcome_sha256' IS DISTINCT FROM v_result->>'result_sha256'))) IS NOT FALSE
        THEN RAISE EXCEPTION 'origin_native_result_owner_invalid'; END IF;
      SELECT coalesce(array_agg(f),'{}') INTO v_result_families FROM jsonb_array_elements_text(v_result->'family_ids') f;
      IF (NOT v_result_families <@ v_families
        OR array_position(ARRAY['public','internal','confidential','restricted'],v_confidentiality)
          <array_position(ARRAY['public','internal','confidential','restricted'],v_result->>'confidentiality')
        OR array_position(ARRAY['untrusted','agent','trusted'],v_integrity)
          >array_position(ARRAY['untrusted','agent','trusted'],v_result->>'integrity')
        OR array_position(ARRAY['none','inform','act'],v_action)
          >array_position(ARRAY['none','inform','act'],v_result->>'action_class')
        OR v_memory.clearance_level<(v_result->>'clearance_floor')::integer
        OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(v_result->'private_subject_ids') subject
          WHERE subject IS DISTINCT FROM v_memory.agent_id
            OR (v_memory.clearance_level>2 AND v_memory.scope NOT IN ('private','agent',v_memory.agent_id)))) IS NOT FALSE
        THEN RAISE EXCEPTION 'origin_native_result_label_weakening'; END IF;
    END LOOP;
  END IF;
  -- The authorized subject owns the resulting memory. Housekeeper may sign
  -- that subject's SAVE; signer identity must not replace private ownership.
  v_native_inputs:=public.ob3_native_save_input_ids(v_company,v_memory.agent_id,v_memory.value,p_body->>'session_id',v_declared_inputs);
  IF v_native_inputs IS NULL THEN
    IF c_schema='hom.aimos.memory-origin-binding/v3' THEN RAISE EXCEPTION 'origin_input_producer_invalid'; END IF;
  ELSE
    IF c_schema<>'hom.aimos.memory-origin-binding/v3'
      OR public.ob2_exact_json_keys(p_body->'derivation',ARRAY['schema','producer','input_count','inputs_sha256','inputs']) IS NOT TRUE
      OR p_body#>>'{derivation,schema}' IS DISTINCT FROM 'hom.aimos.origin-input-manifest/v1'
      OR p_body#>>'{derivation,producer}' IS DISTINCT FROM v_native_inputs->>'producer'
      OR jsonb_typeof(p_body#>'{derivation,inputs}') IS DISTINCT FROM 'array'
      OR (p_body#>>'{derivation,input_count}')::integer IS DISTINCT FROM jsonb_array_length(p_body#>'{derivation,inputs}') THEN
      RAISE EXCEPTION 'origin_input_manifest_invalid'; END IF;
    SELECT coalesce(array_agg((x->>'memory_id')::uuid ORDER BY ord),'{}') INTO v_input_ids
      FROM jsonb_array_elements(p_body#>'{derivation,inputs}') WITH ORDINALITY a(x,ord);
    IF to_jsonb(v_input_ids) IS DISTINCT FROM v_native_inputs->'memory_ids'
      OR v_memory_id=ANY(v_input_ids) THEN RAISE EXCEPTION 'origin_input_membership_invalid'; END IF;
    IF NOT 'derived'=ANY(v_families) OR (v_native_inputs->>'producer'='compaction_handoff'
      AND NOT 'derived.summary'=ANY(v_families)) THEN RAISE EXCEPTION 'origin_input_family_invalid'; END IF;
    v_input_bytes:=convert_to(public.ob2_canonical_json(p_body#>'{derivation,inputs}'),'UTF8');
    v_input_hash:=digest(convert_to('hom.aimos.origin-input-manifest/v1','UTF8')||decode('00','hex')
      ||int4send(octet_length(v_input_bytes))||v_input_bytes,'sha256');
    IF encode(v_input_hash,'hex') IS DISTINCT FROM p_body#>>'{derivation,inputs_sha256}' THEN
      RAISE EXCEPTION 'origin_input_root_invalid'; END IF;
    FOR v_input IN SELECT x FROM jsonb_array_elements(p_body#>'{derivation,inputs}') x LOOP
      IF public.ob2_exact_json_keys(v_input,ARRAY['memory_id','content_sha256','origin_sha256s','legacy_unbound']) IS NOT TRUE
        OR jsonb_typeof(v_input->'origin_sha256s') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'origin_input_member_invalid'; END IF;
      SELECT * INTO v_input_memory FROM public.aimos_memories WHERE id=(v_input->>'memory_id')::uuid;
      IF v_input->>'content_sha256' IS DISTINCT FROM encode(v_input_memory.content_hash,'hex')
        OR array_position(ARRAY['public','internal','confidential','restricted'],v_confidentiality)
          <array_position(ARRAY['public','internal','confidential','restricted'],v_input_memory.data_class) THEN
        RAISE EXCEPTION 'origin_input_content_or_confidentiality_invalid'; END IF;
      IF v_memory.clearance_level<v_input_memory.clearance_level THEN RAISE EXCEPTION 'origin_input_clearance_downgrade'; END IF;
      IF (v_input_memory.cube_scope='private'
        OR v_input_memory.scope IN ('private','agent',v_input_memory.agent_id))
        AND (v_input_memory.agent_id IS DISTINCT FROM v_memory.agent_id
          OR (v_memory.clearance_level>2 AND (v_scope NOT IN ('private','agent',v_memory.agent_id)
            OR v_scope='quarantine' OR v_memory.memory_type='quarantine'))) THEN
        RAISE EXCEPTION 'origin_input_scope_broadening'; END IF;
      PERFORM pg_advisory_xact_lock(hashtextextended('origin-ledger:'||v_company,0));
      WITH relevant AS MATERIALIZED (
        SELECT binding_sha256,parent_origin_sha256s FROM public.aimos_memory_origin_bindings
          WHERE company_id=v_company AND memory_id=v_input_memory.id
      ), consumed AS (SELECT unnest(parent_origin_sha256s) AS binding_sha256 FROM relevant)
      SELECT coalesce(jsonb_agg(encode(b.binding_sha256,'hex') ORDER BY b.binding_sha256),'[]') INTO v_native_inputs
        FROM relevant b LEFT JOIN consumed USING(binding_sha256) WHERE consumed.binding_sha256 IS NULL;
      IF v_input->'origin_sha256s' IS DISTINCT FROM v_native_inputs
        OR v_input->'legacy_unbound' IS DISTINCT FROM to_jsonb(v_native_inputs='[]'::jsonb) THEN
        RAISE EXCEPTION 'origin_input_binding_missing_or_stale'; END IF;
      IF v_native_inputs='[]'::jsonb THEN
        IF v_integrity<>'untrusted' OR v_action<>'none' OR v_confidentiality<>'restricted'
          OR NOT 'unknown_protected'=ANY(v_families) THEN RAISE EXCEPTION 'origin_legacy_input_elevated'; END IF;
      END IF;
      FOR v_input_origin IN SELECT jsonb_array_elements_text(v_native_inputs) LOOP
        SELECT * INTO v_input_binding FROM public.aimos_memory_origin_bindings WHERE binding_sha256=decode(v_input_origin,'hex');
        IF NOT v_input_binding.family_ids <@ v_families
          OR array_position(ARRAY['public','internal','confidential','restricted'],v_confidentiality)
            <array_position(ARRAY['public','internal','confidential','restricted'],v_input_binding.confidentiality)
          OR array_position(ARRAY['untrusted','agent','trusted'],v_integrity)
            >array_position(ARRAY['untrusted','agent','trusted'],v_input_binding.integrity)
          OR array_position(ARRAY['none','inform','act'],v_action)
            >array_position(ARRAY['none','inform','act'],v_input_binding.action_class) THEN
          RAISE EXCEPTION 'origin_input_label_weakening'; END IF;
      END LOOP;
    END LOOP;
  END IF;

  -- OB-3: version and exact-reassertion dependencies are database facts. A
  -- caller-supplied empty or stale parent list cannot restart family authority.
  -- Same lock as the native origin owner and the no-fork ledger append.
  PERFORM pg_advisory_xact_lock(hashtextextended('origin-ledger:'||v_company,0));
  IF EXISTS (
    WITH relevant AS MATERIALIZED (
      SELECT memory_id,binding_sha256,parent_origin_sha256s
        FROM public.aimos_memory_origin_bindings
       WHERE company_id=v_company AND memory_id=ANY(ARRAY[v_memory_id,v_memory.supersedes_id])
    ), consumed AS (
      SELECT memory_id,unnest(parent_origin_sha256s) AS binding_sha256 FROM relevant
    )
    SELECT 1 FROM relevant required
     LEFT JOIN consumed USING (memory_id,binding_sha256)
     WHERE consumed.binding_sha256 IS NULL
       AND NOT required.binding_sha256=ANY(v_parents)
  ) THEN RAISE EXCEPTION 'origin_required_version_parent_missing'; END IF;

  SELECT count(*)::integer INTO v_missing
    FROM unnest(v_parents) parent(hash)
    LEFT JOIN public.aimos_memory_origin_bindings binding ON binding.binding_sha256 = parent.hash
   WHERE binding.binding_sha256 IS NULL OR binding.company_id <> v_company;
  IF (v_missing <> 0) IS NOT FALSE THEN RAISE EXCEPTION 'origin_parent_binding_invalid'; END IF;
  IF (cardinality(v_parents) > 0) IS NOT FALSE THEN
    SELECT max(array_position(ARRAY['public','internal','confidential','restricted'], parent.confidentiality)),
           min(array_position(ARRAY['untrusted','agent','trusted'], parent.integrity)),
           min(array_position(ARRAY['none','inform','act'], parent.action_class))
      INTO v_parent_floor, v_parent_integrity, v_parent_action
      FROM public.aimos_memory_origin_bindings parent WHERE parent.binding_sha256 = ANY(v_parents);
    IF (array_position(ARRAY['public','internal','confidential','restricted'], v_confidentiality) < v_parent_floor
       OR array_position(ARRAY['untrusted','agent','trusted'], v_integrity) > v_parent_integrity
       OR array_position(ARRAY['none','inform','act'], v_action) > v_parent_action) IS NOT FALSE THEN
      RAISE EXCEPTION 'origin_parent_lattice_invalid';
    END IF;
    SELECT count(*)::integer INTO v_missing FROM (
      SELECT DISTINCT unnest(parent.family_ids) family_id
        FROM public.aimos_memory_origin_bindings parent WHERE parent.binding_sha256 = ANY(v_parents)
    ) inherited WHERE NOT inherited.family_id = ANY(v_families);
    IF (v_missing <> 0) IS NOT FALSE THEN RAISE EXCEPTION 'origin_parent_family_invalid'; END IF;
  END IF;

  v_ledger_hash := public.ob2_commit_origin_ledger_entry(
    v_company, c_schema, p_binding_sha256, p_prev_ledger_hash,
    p_signer_valid_from, p_signer_cert_fingerprint,
    p_authority_profile_sha256, p_signed_at, p_ledger_signature);
  INSERT INTO public.aimos_memory_origin_bindings (
    binding_sha256, ledger_hash, company_id, memory_id, occurrence_id,
    content_sha256, actor_agent_id, actor_valid_from, actor_cert_fingerprint,
    request_receipt_id, request_mutation_sha256, ingress_channel,
    channel_identity_sha256, parent_origin_sha256s, family_profile_sha256,
    family_ids, classification_authority, classification_evidence_sha256,
    classification_event_id, confidentiality, integrity, action_class,
    action_scope, session_id, tool_action_event_id, originated_at,
    body_json, body_bytes, operation_authority, action_authority_event_id
  ) VALUES (
    p_binding_sha256, v_ledger_hash, v_company, v_memory_id, v_occurrence_id,
    v_content, v_actor, v_actor_valid_from, v_actor_fingerprint, v_receipt_id,
    v_request_mutation, v_ingress, v_channel_identity, v_parents,
    c_family_profile, v_families, p_body#>>'{classification,authority}',
    decode(p_body#>>'{classification,evidence_sha256}','hex'), p_classification_event_id,
    v_confidentiality, v_integrity, v_action, v_scope, p_body->>'session_id',
    NULLIF(p_body->>'tool_action_event_id','')::uuid, (p_body->>'created_at')::timestamptz,
    p_body, p_body_bytes, p_body->'operation_authority',
    NULLIF(p_body#>>'{operation_authority,evidence,event_id}','')::uuid
  );
  RETURN v_ledger_hash;
END
$function$;
REVOKE ALL ON FUNCTION public.commit_memory_origin_binding_v2(jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea,json) FROM PUBLIC,aimos_app;
GRANT EXECUTE ON FUNCTION public.commit_memory_origin_binding_v2(jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea,json) TO agent_runtime;
DROP FUNCTION IF EXISTS public.ob3_native_save_input_ids(text,text,text,text);

-- Deferred, database-local atomicity: every new SAVE occurrence must have one
-- origin and a signed SUCCESS terminal in the same transaction. Existing rows
-- are retained unchanged; this is not a retroactive backfill of origin claims.
CREATE OR REPLACE FUNCTION public.ob2_require_atomic_save_origin()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $function$
DECLARE occurrence uuid; binding public.aimos_memory_origin_bindings%ROWTYPE;
  event_id uuid; terminal public.aimos_events%ROWTYPE; transaction_id xid;
BEGIN
  IF TG_TABLE_NAME='aimos_memories' THEN
    SELECT p.provenance_id INTO occurrence FROM public.aimos_memory_provenance p
      WHERE p.memory_id=NEW.id AND p.event_type='SAVE' AND p.is_genesis IS TRUE;
    IF occurrence IS NULL THEN RAISE EXCEPTION 'origin_atomic_memory_occurrence_missing'; END IF;
  ELSIF TG_TABLE_NAME='aimos_memory_provenance' THEN
    IF NEW.event_type NOT IN ('SAVE','SAVE_REASSERT','INTERNAL_SAVE_REASSERT') THEN RETURN NEW; END IF;
    occurrence := NEW.provenance_id;
  ELSE occurrence := NEW.occurrence_id; END IF;
  SELECT * INTO binding FROM public.aimos_memory_origin_bindings WHERE occurrence_id=occurrence;
  IF NOT FOUND THEN RAISE EXCEPTION 'origin_atomic_binding_missing'; END IF;
  SELECT p.xmin INTO transaction_id FROM public.aimos_memory_provenance p
    JOIN public.aimos_memory_origin_bindings b ON b.occurrence_id=p.provenance_id AND b.xmin=p.xmin
    JOIN public.aimos_origin_ledger_entries l ON l.ledger_hash=b.ledger_hash AND l.xmin=b.xmin
    JOIN public.aimos_events c ON c.id=b.classification_event_id AND c.xmin=b.xmin
    WHERE p.provenance_id=occurrence;
  IF transaction_id IS NULL THEN RAISE EXCEPTION 'origin_atomic_transaction_mismatch'; END IF;
  SELECT e.id INTO event_id FROM public.aimos_events e
    WHERE e.xmin=transaction_id AND e.company_id=binding.company_id
      AND e.operation='canonical_save_terminal' AND e.metadata->>'outcome'='SUCCESS'
      AND e.metadata->>'schema'='hom.aimos.canonical-save-terminal/v1'
      AND e.metadata->'stages' @> jsonb_build_array(jsonb_build_object(
        'stage','TERMINAL','status','SUCCESS','evidence',jsonb_build_object(
          'origin_bindings',jsonb_build_array(jsonb_build_object(
            'memory_id',binding.memory_id,'occurrence_id',binding.occurrence_id,
            'binding_sha256',encode(binding.binding_sha256,'hex'),
            'ledger_hash',encode(binding.ledger_hash,'hex')))))) LIMIT 1;
  IF event_id IS NULL THEN RAISE EXCEPTION 'origin_atomic_save_terminal_missing'; END IF;
  terminal := public.ob2_verify_signed_event(event_id,binding.company_id);
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.ob2_require_atomic_save_origin() FROM PUBLIC,agent_runtime,aimos_app;
DROP TRIGGER IF EXISTS ob2_atomic_save_origin ON public.aimos_memory_provenance;
CREATE CONSTRAINT TRIGGER ob2_atomic_save_origin AFTER INSERT ON public.aimos_memory_provenance
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.ob2_require_atomic_save_origin();
DROP TRIGGER IF EXISTS ob2_atomic_origin_save ON public.aimos_memory_origin_bindings;
CREATE CONSTRAINT TRIGGER ob2_atomic_origin_save AFTER INSERT ON public.aimos_memory_origin_bindings
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.ob2_require_atomic_save_origin();
DROP TRIGGER IF EXISTS ob2_atomic_memory_origin ON public.aimos_memories;
CREATE CONSTRAINT TRIGGER ob2_atomic_memory_origin AFTER INSERT ON public.aimos_memories
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.ob2_require_atomic_save_origin();

-- Retained attestation is a typed successor, not a second current native BIND.
-- Keep the existing unique v3 index and retain uniqueness of native v4 BINDs.
DROP INDEX IF EXISTS public.aimos_memory_provenance_one_current_portable_binding;
CREATE UNIQUE INDEX aimos_memory_provenance_one_current_portable_binding
  ON public.aimos_memory_provenance(memory_id)
  WHERE event_type='BIND' AND binding_schema_version=4;
CREATE OR REPLACE FUNCTION public.ob2_require_retained_binding_successor()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $function$
DECLARE native public.aimos_memory_provenance%ROWTYPE;
  review public.aimos_memory_provenance%ROWTYPE;
  witness public.aimos_memory_provenance%ROWTYPE;
  node public.aimos_memory_provenance%ROWTYPE; pub bytea; msg bytea;
BEGIN
  IF NEW.event_type<>'BIND' OR NEW.binding_schema_version NOT IN (3,4) THEN RETURN NEW; END IF;
  SELECT * INTO native FROM public.aimos_memory_provenance
    WHERE memory_id=NEW.memory_id AND event_type='BIND' AND binding_schema_version=4;
  SELECT * INTO review FROM public.aimos_memory_provenance
    WHERE memory_id=NEW.memory_id AND event_type='BIND' AND binding_schema_version=3;
  IF native.provenance_id IS NULL OR review.provenance_id IS NULL THEN RETURN NEW; END IF;
  SELECT * INTO witness FROM public.aimos_memory_provenance
    WHERE memory_id=NEW.memory_id AND event_type='RETAINED_ATTEST' AND mutation_hash=review.prev_mutation_hash;
  IF witness.provenance_id IS NULL
    OR review.body_json->>'attestation_reason' IS DISTINCT FROM 'retained_memory_portable_upgrade'
    OR witness.body_json->>'attestation_reason' IS DISTINCT FROM 'retained_memory_portable_upgrade'
    OR witness.body_json->'historical_origin_signature_claimed' IS DISTINCT FROM 'false'::jsonb
    OR review.body_json->'historical_origin_signature_claimed' IS DISTINCT FROM 'false'::jsonb
    OR witness.body_json->>'attested_predecessor_mutation_hash' IS DISTINCT FROM encode(witness.prev_mutation_hash,'hex')
    OR review.body_json->>'attested_predecessor_mutation_hash' IS DISTINCT FROM encode(witness.mutation_hash,'hex')
    OR review.body_json->>'authority_event_type' IS DISTINCT FROM 'RETAINED_ATTEST'
    OR review.body_json->>'authority_mutation_hash' IS DISTINCT FROM encode(witness.mutation_hash,'hex')
    OR review.body_json->>'authority_content_hash' IS DISTINCT FROM encode(witness.content_hash,'hex')
    OR review.body_json->>'authority_signature_hash' IS DISTINCT FROM encode(digest(witness.sig,'sha256'),'hex')
    OR review.body_json->>'authority_signer_agent_id' IS DISTINCT FROM 'housekeeper'
    OR (review.body_json->>'authority_signer_valid_from')::timestamptz IS DISTINCT FROM witness.agent_valid_from
    OR review.agent_valid_from IS DISTINCT FROM witness.agent_valid_from
    OR review.cert_fingerprint IS DISTINCT FROM witness.cert_fingerprint
    OR review.live_content_hash IS DISTINCT FROM native.live_content_hash
    OR witness.live_content_hash IS DISTINCT FROM native.live_content_hash
    OR (review.body_json->>'attested_predecessor_node_count')::integer
      IS DISTINCT FROM (witness.body_json->>'retained_provenance_node_count')::integer+1 THEN
    RAISE EXCEPTION 'retained_binding_successor_invalid'; END IF;
  FOR node IN SELECT * FROM public.aimos_memory_provenance
    WHERE provenance_id IN (review.provenance_id,witness.provenance_id) LOOP
    IF node.agent_id IS DISTINCT FROM 'housekeeper' OR node.sig_form_version IS DISTINCT FROM 1
      OR node.request_sig_form IS DISTINCT FROM 1 OR node.sig IS NULL
      OR node.body_json->>'memory_id' IS DISTINCT FROM node.memory_id::text
      OR node.body_json->>'event_type' IS DISTINCT FROM node.event_type
      OR digest(convert_to(public.ob2_canonical_json(node.body_json),'UTF8'),'sha256') IS DISTINCT FROM node.content_hash
      OR digest(node.content_hash||node.prev_mutation_hash||convert_to(node.nonce||node.ts_signed::text,'UTF8'),'sha256')
        IS DISTINCT FROM node.mutation_hash
      OR NOT EXISTS(SELECT 1 FROM public.agent_identity i WHERE i.agent_id=node.agent_id
        AND i.valid_from=node.agent_valid_from AND i.valid_until>to_timestamp(node.ts_signed)
        AND i.valid_from<=to_timestamp(node.ts_signed) AND i.revoked_at IS NULL
        AND encode(digest(convert_to(i.cert,'UTF8'),'sha256'),'hex')=node.cert_fingerprint
        AND NOT EXISTS(SELECT 1 FROM public.aimos_agent_revocation_events r
          WHERE r.agent_id=i.agent_id AND r.agent_valid_from=i.valid_from)) THEN
      RAISE EXCEPTION 'retained_binding_successor_signature_invalid'; END IF;
    pub := public.ob2_raw_ed25519_pubkey(node.agent_id,node.agent_valid_from);
    msg := convert_to(public.ob2_canonical_json(node.body_json)||E'\n'||node.nonce||E'\n'||node.ts_signed::text,'UTF8');
    IF pgsodium.crypto_sign_verify_detached(node.sig,msg,pub) IS NOT TRUE THEN
      RAISE EXCEPTION 'retained_binding_successor_signature_invalid'; END IF;
  END LOOP;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION public.ob2_require_retained_binding_successor() FROM PUBLIC,agent_runtime,aimos_app;
DROP TRIGGER IF EXISTS ob2_retained_binding_successor ON public.aimos_memory_provenance;
CREATE CONSTRAINT TRIGGER ob2_retained_binding_successor AFTER INSERT ON public.aimos_memory_provenance
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.ob2_require_retained_binding_successor();
