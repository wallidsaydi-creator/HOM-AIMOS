-- Current native AUD-007 definitions; historical numbered SQL is unchanged.
-- One existing Housekeeper event ledger; no new table or runtime privilege.
CREATE OR REPLACE FUNCTION public.verify_cognitive_ancestry_bridge_v1(
  p_memory_id uuid,p_native_hash bytea,p_previous_projection bytea,p_projection_hash bytea
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,public AS $function$
DECLARE p public.aimos_memory_provenance%ROWTYPE; e public.aimos_events%ROWTYPE;
  parent public.aimos_memory_provenance%ROWTYPE; ids uuid[]; company text;
  b jsonb; n jsonb; h jsonb; content bytea; mutation bytea; pub bytea;
  identity public.agent_identity%ROWTYPE; parent_commitment bytea;
BEGIN
  company:=current_setting('app.current_client_id',true);
  IF company IS NULL OR company='' THEN RETURN NULL; END IF;
  SELECT provenance.* INTO p FROM public.aimos_memory_provenance provenance
    JOIN public.aimos_memories memory ON memory.id=provenance.memory_id
    WHERE provenance.memory_id=p_memory_id AND provenance.mutation_hash=p_native_hash AND memory.company_id=company;
  IF NOT FOUND OR p.event_type<>'REWEIGHT' OR p.agent_id<>'housekeeper' THEN RETURN NULL; END IF;
  b:=p.body_json->'ancestry_binding';n:=b->'native_predecessor';h:=b->'projection_predecessor';
  IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR jsonb_typeof(n) IS DISTINCT FROM 'object'
    OR jsonb_typeof(h) IS DISTINCT FROM 'object' THEN RETURN NULL; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(b))<>3
    OR (SELECT count(*) FROM jsonb_object_keys(n))<>3 OR (SELECT count(*) FROM jsonb_object_keys(h))<>2
    OR b->>'schema' IS DISTINCT FROM 'hom.aimos.cognitive-ancestry-binding/v1'
    OR n->'commitment_hex' IS DISTINCT FROM coalesce(to_jsonb(encode(p.prev_mutation_hash,'hex')),'null'::jsonb)
    OR h IS DISTINCT FROM jsonb_build_object('kind',CASE WHEN p_previous_projection IS NULL THEN 'genesis' ELSE 'projection_hash' END,
      'commitment_hex',encode(p_previous_projection,'hex')) THEN RETURN NULL; END IF;
  IF p.prev_mutation_hash IS NULL THEN
    IF n->>'kind' IS DISTINCT FROM 'genesis' OR n->'provenance_id' IS DISTINCT FROM 'null'::jsonb THEN RETURN NULL; END IF;
  ELSE
    IF coalesce(n->>'kind','') NOT IN ('mutation_hash','occurrence_ref') OR jsonb_typeof(n->'provenance_id') IS DISTINCT FROM 'string'
      OR n->>'provenance_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RETURN NULL; END IF;
    SELECT * INTO parent FROM public.aimos_memory_provenance
      WHERE provenance_id=(n->>'provenance_id')::uuid AND memory_id=p_memory_id;
    IF NOT FOUND OR parent.provenance_id=p.provenance_id THEN RETURN NULL; END IF;
    parent_commitment:=CASE n->>'kind' WHEN 'mutation_hash' THEN parent.mutation_hash
      ELSE public.ob2_occurrence_reference(parent,company) END;
    IF parent_commitment IS DISTINCT FROM p.prev_mutation_hash THEN RETURN NULL; END IF;
  END IF;
  SELECT array_agg(id) INTO ids FROM (SELECT id FROM public.aimos_events
    WHERE company_id=company AND operation='cognitive_ancestry_bound' AND key=encode(p_native_hash,'hex') LIMIT 2) candidates;
  IF cardinality(ids) IS DISTINCT FROM 1 THEN RETURN NULL; END IF;
  SELECT * INTO e FROM public.aimos_events WHERE id=ids[1];
  IF e.proof_required IS DISTINCT FROM true OR e.ledger_version<>1
    OR e.signer_agent_id IS DISTINCT FROM 'housekeeper' OR e.agent_id IS DISTINCT FROM 'housekeeper'
    OR e.authority_kind IS DISTINCT FROM 'housekeeper_autonomous' OR e.signer_valid_from IS DISTINCT FROM p.agent_valid_from
    OR e.cert_fingerprint IS DISTINCT FROM p.cert_fingerprint OR e.ts_signed<p.ts_signed
    OR e.signed_body_bytes IS NULL OR e.signed_body->>'payload_schema' IS DISTINCT FROM 'hom.aimos.event/v2'
    OR convert_from(e.signed_body_bytes,'UTF8')::jsonb IS DISTINCT FROM e.signed_body
    OR e.signed_body->'metadata' IS DISTINCT FROM e.metadata
    OR e.signed_body->>'company_id' IS DISTINCT FROM company
    OR e.signed_body->>'event_id' IS DISTINCT FROM e.id::text
    OR e.signed_body->>'operation' IS DISTINCT FROM e.operation OR e.signed_body->>'key' IS DISTINCT FROM e.key
    OR e.signed_body->>'signer_agent_id' IS DISTINCT FROM e.signer_agent_id
    OR e.signed_body->>'subject_agent_id' IS DISTINCT FROM e.agent_id
    OR e.signed_body->>'authority_kind' IS DISTINCT FROM e.authority_kind
    OR e.signed_body->'actor_agent_id' IS DISTINCT FROM 'null'::jsonb
    OR e.signed_body->'actor_valid_from' IS DISTINCT FROM 'null'::jsonb
    OR e.signed_body->'request_envelope_digest' IS DISTINCT FROM 'null'::jsonb
    OR e.signed_body->'nonce' IS DISTINCT FROM to_jsonb(e.nonce)
    OR e.signed_body->'ts_signed' IS DISTINCT FROM to_jsonb(e.ts_signed)
    OR e.signed_body->'ledger_version' IS DISTINCT FROM to_jsonb(e.ledger_version)
    OR e.signed_body->'ledger_seq' IS DISTINCT FROM to_jsonb(e.ledger_seq)
    OR e.signed_body->>'prev_mutation_hash' IS DISTINCT FROM encode(e.prev_mutation_hash,'hex')
    OR e.signed_body->>'identity_tier' IS DISTINCT FROM e.identity_tier
    OR e.ledger_seq<1 OR e.ledger_seq>9007199254740991
    OR e.ts IS DISTINCT FROM to_timestamp(e.ts_signed)
    OR e.signed_body->>'signer_valid_from' IS DISTINCT FROM to_char(p.agent_valid_from AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    OR e.signed_body->>'cert_fingerprint' IS DISTINCT FROM p.cert_fingerprint
    OR e.metadata->>'schema' IS DISTINCT FROM 'hom.aimos.cognitive-ancestry-bridge/v1'
    OR e.metadata->>'company_id' IS DISTINCT FROM company OR e.metadata->>'memory_id' IS DISTINCT FROM p_memory_id::text
    OR e.metadata->>'native_mutation_hash' IS DISTINCT FROM encode(p_native_hash,'hex')
    OR e.metadata->>'projection_hash' IS DISTINCT FROM encode(p_projection_hash,'hex')
    OR e.metadata->'ancestry_binding' IS DISTINCT FROM b
    OR e.metadata->'old_weight_milli' IS DISTINCT FROM to_jsonb(round((p.body_json->>'old_weight')::double precision*1000)::bigint)
    OR e.metadata->'new_weight_milli' IS DISTINCT FROM to_jsonb(round((p.body_json->>'new_weight')::double precision*1000)::bigint)
    OR e.metadata->>'signer_agent_id' IS DISTINCT FROM p.agent_id
    OR e.metadata->>'signer_valid_from' IS DISTINCT FROM to_char(p.agent_valid_from AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    OR e.metadata->>'cert_fingerprint' IS DISTINCT FROM p.cert_fingerprint
    OR e.metadata->>'attestation_kind' IS DISTINCT FROM 'atomic_transition'
    OR e.metadata->'historical_origin_claimed' IS DISTINCT FROM 'false'::jsonb THEN RETURN NULL; END IF;
  SELECT * INTO identity FROM public.agent_identity WHERE agent_id=e.signer_agent_id AND valid_from=e.signer_valid_from;
  IF NOT FOUND OR e.ts_signed<extract(epoch FROM identity.valid_from) OR e.ts_signed>=extract(epoch FROM identity.valid_until)
    OR encode(digest(convert_to(identity.cert,'UTF8'),'sha256'),'hex') IS DISTINCT FROM e.cert_fingerprint
    OR (identity.revoked_at IS NOT NULL AND identity.revoked_at<=to_timestamp(e.ts_signed))
    OR EXISTS(SELECT 1 FROM public.aimos_agent_revocation_events r WHERE r.agent_id=e.signer_agent_id
      AND r.agent_valid_from=e.signer_valid_from AND r.ts_signed<=e.ts_signed) THEN RETURN NULL; END IF;
  content:=public.signed_json_bytes_commitment_v1('hom.aimos.event/v2',e.signed_body_bytes);
  mutation:=digest(convert_to('AIMOS-EVENT-LINK-v1','UTF8')||decode('00','hex')||e.prev_mutation_hash
    ||content||convert_to(e.nonce,'UTF8')||convert_to(e.ts_signed::text,'UTF8'),'sha256');
  pub:=public.cwc_raw_ed25519_pubkey(e.signer_agent_id,e.signer_valid_from);
  IF content IS DISTINCT FROM e.content_hash OR mutation IS DISTINCT FROM e.mutation_hash
    OR pgsodium.crypto_sign_verify_detached(e.sig,content,pub) IS NOT TRUE THEN RETURN NULL; END IF;
  RETURN e.id;
END
$function$;
REVOKE ALL ON FUNCTION public.verify_cognitive_ancestry_bridge_v1(uuid,bytea,bytea,bytea) FROM PUBLIC,agent_runtime,aimos_app;

CREATE OR REPLACE FUNCTION public.apply_signed_cognitive_reweight(
  p_memory_id uuid,
  p_old_weight double precision,
  p_new_weight double precision,
  p_provenance_mutation_hash bytea,
  p_transition_sig bytea
) RETURNS real
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  v_current_weight real;
  v_current_milli int;
  v_old_milli int;
  v_new_milli int;
  v_body jsonb;
  v_ancestry_event_id uuid;
  v_current_xid text;
  v_agent_vf timestamptz;
  v_agent_until timestamptz;
  v_signed_ts bigint;
  v_revocation_ts bigint;
  v_prov_cert_fingerprint text;
  v_identity_cert_fingerprint text;
  v_raw_pub bytea;
  v_prev_hash bytea;
  v_head_milli int;
  v_proj_hash bytea;
  v_transition_hash bytea;
  v_applied real;
  v_body_old_milli integer;
  v_body_new_milli integer;
  v_baseline_ok boolean;
  v_baseline_milli integer;
  v_baseline_observed real;
  c_chain_prefix bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_transition_prefix bytea := '\x61696d6f732e636f676e69746976652d7472616e736974696f6e2f763200'::bytea;
  c_zero32 bytea := decode(repeat('00', 32), 'hex');
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN RAISE EXCEPTION 'cognitive_company_scope_required'; END IF;
  IF current_setting('app.current_agent_id', true) <> 'housekeeper' THEN RAISE EXCEPTION 'cognitive_housekeeper_scope_required'; END IF;
  IF p_memory_id IS NULL OR p_provenance_mutation_hash IS NULL
     OR octet_length(p_provenance_mutation_hash) <> 32 THEN RAISE EXCEPTION 'cognitive_transition_identity_malformed'; END IF;
  IF p_old_weight IS NULL OR p_new_weight IS NULL
     OR p_old_weight < 0.1 OR p_old_weight > 3.0
     OR p_new_weight < 0.1 OR p_new_weight > 3.0 THEN RAISE EXCEPTION 'cognitive_weight_out_of_bounds'; END IF;
  v_old_milli := round(p_old_weight * 1000)::int;
  v_new_milli := round(p_new_weight * 1000)::int;
  IF v_old_milli < 100 OR v_old_milli > 3000 OR v_new_milli < 100 OR v_new_milli > 3000 THEN RAISE EXCEPTION 'cognitive_weight_out_of_bounds'; END IF;
  IF v_new_milli = v_old_milli THEN RAISE EXCEPTION 'cognitive_noop_reweight'; END IF;
  IF p_transition_sig IS NULL OR octet_length(p_transition_sig) <> 64 THEN RAISE EXCEPTION 'cognitive_transition_sig_malformed'; END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('cognitive-reweight:' || v_company_id || ':' || p_memory_id::text, 0));
  SELECT m.retrieval_weight INTO v_current_weight
    FROM public.aimos_memories m
   WHERE m.id = p_memory_id AND m.company_id = v_company_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'cognitive_memory_not_found'; END IF;

  SELECT p.body_json, p.agent_valid_from, p.ts_signed, p.cert_fingerprint
    INTO v_body, v_agent_vf, v_signed_ts, v_prov_cert_fingerprint
    FROM public.aimos_memory_provenance p
   WHERE p.memory_id = p_memory_id
     AND p.mutation_hash = p_provenance_mutation_hash
     AND p.event_type = 'REWEIGHT'
     AND p.binding_schema_version = 2
     AND p.agent_id = 'housekeeper'
     AND p.agent_valid_from IS NOT NULL
     AND p.ts_signed IS NOT NULL
     AND p.nonce IS NOT NULL
     AND p.content_hash IS NOT NULL
     AND p.cert_fingerprint IS NOT NULL
     AND p.backfilled = false
     AND p.sig IS NOT NULL AND octet_length(p.sig) = 64
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_memory_provenance successor
        WHERE successor.memory_id = p.memory_id
          AND successor.prev_mutation_hash = p.mutation_hash
     );
  IF NOT FOUND OR v_body IS NULL THEN RAISE EXCEPTION 'signed_cognitive_provenance_required'; END IF;
  SELECT i.valid_until, rev.ts_signed, encode(digest(i.cert, 'sha256'), 'hex')
    INTO v_agent_until, v_revocation_ts, v_identity_cert_fingerprint
    FROM public.agent_identity i
    LEFT JOIN public.aimos_agent_revocation_events rev
      ON rev.agent_id = i.agent_id AND rev.agent_valid_from = i.valid_from
   WHERE i.agent_id = 'housekeeper' AND i.valid_from = v_agent_vf
   FOR UPDATE OF i;
  IF NOT FOUND OR to_timestamp(v_signed_ts) < v_agent_vf OR to_timestamp(v_signed_ts) >= v_agent_until
     OR clock_timestamp() < v_agent_vf
     OR clock_timestamp() >= v_agent_until
     OR v_identity_cert_fingerprint IS DISTINCT FROM v_prov_cert_fingerprint
     OR v_revocation_ts IS NOT NULL THEN
    RAISE EXCEPTION 'cognitive_housekeeper_epoch_invalid';
  END IF;

  v_body_old_milli := CASE WHEN jsonb_typeof(v_body->'old_weight') = 'number' THEN round((v_body->>'old_weight')::double precision * 1000)::int ELSE NULL END;
  v_body_new_milli := CASE WHEN jsonb_typeof(v_body->'new_weight') = 'number' THEN round((v_body->>'new_weight')::double precision * 1000)::int ELSE NULL END;
  IF v_body->>'event_type' IS DISTINCT FROM 'REWEIGHT'
     OR v_body->>'company_id' IS DISTINCT FROM v_company_id
     OR v_body->>'memory_id' IS DISTINCT FROM p_memory_id::text OR v_body_old_milli IS NULL
     OR v_body_new_milli IS NULL OR v_body_old_milli <> v_old_milli
     OR v_body_new_milli <> v_new_milli THEN RAISE EXCEPTION 'signed_cognitive_transition_mismatch'; END IF;

  v_transition_hash := digest(
    c_transition_prefix || int4send(octet_length(convert_to(v_company_id, 'UTF8')))
    || convert_to(v_company_id, 'UTF8') || uuid_send(p_memory_id)
    || int8send(v_old_milli::int8) || int8send(v_new_milli::int8)
    || p_provenance_mutation_hash, 'sha256');
  v_raw_pub := public.cwc_raw_ed25519_pubkey('housekeeper', v_agent_vf);
  IF v_raw_pub IS NULL OR octet_length(v_raw_pub) <> 32
     OR NOT pgsodium.crypto_sign_verify_detached(p_transition_sig, v_transition_hash, v_raw_pub) THEN
    RAISE EXCEPTION 'cognitive_transition_sig_invalid';
  END IF;

  SELECT h.projection_hash, h.new_weight_milli INTO v_prev_hash, v_head_milli
    FROM public.aimos_cognitive_weight_projections h
   WHERE h.memory_id = p_memory_id AND h.company_id = v_company_id
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_cognitive_weight_projections c
        WHERE c.memory_id = h.memory_id AND c.prev_projection_hash = h.projection_hash
     );
  IF v_prev_hash IS NULL THEN
    SELECT b.ok, b.weight_milli INTO v_baseline_ok, v_baseline_milli
      FROM public.verify_cognitive_weight_baseline(p_memory_id) b
     WHERE b.reason IS DISTINCT FROM 'baseline_missing';
    IF FOUND THEN
      SELECT b.observed_weight INTO v_baseline_observed
        FROM public.aimos_cognitive_weight_baselines b
       WHERE b.company_id = v_company_id AND b.memory_id = p_memory_id;
      IF v_baseline_ok IS DISTINCT FROM true
         OR v_old_milli <> v_baseline_milli
         OR float4send(v_current_weight) <> float4send(v_baseline_observed) THEN
        RAISE EXCEPTION 'cognitive_baseline_mismatch';
      END IF;
    ELSE
      v_current_milli := round(v_current_weight::double precision * 1000)::int;
      IF float4send(v_current_weight) <> float4send(1.0::real) THEN
        RAISE EXCEPTION 'cognitive_initial_weight_attestation_required';
      END IF;
      IF v_old_milli <> v_current_milli THEN RAISE EXCEPTION 'cognitive_old_weight_mismatch'; END IF;
    END IF;
  ELSIF v_old_milli <> v_head_milli THEN
    RAISE EXCEPTION 'cognitive_chain_discontinuity';
  ELSIF float4send(v_current_weight)
        <> float4send((v_head_milli::double precision / 1000.0)::real) THEN
    RAISE EXCEPTION 'cognitive_live_weight_chain_head_mismatch';
  END IF;

  v_proj_hash := digest(
    c_chain_prefix || uuid_send(p_memory_id)
    || int8send(v_old_milli::int8) || int8send(v_new_milli::int8)
    || p_provenance_mutation_hash || COALESCE(v_prev_hash, c_zero32), 'sha256');
  v_ancestry_event_id:=public.verify_cognitive_ancestry_bridge_v1(p_memory_id,p_provenance_mutation_hash,v_prev_hash,v_proj_hash);
  IF v_ancestry_event_id IS NULL THEN RAISE EXCEPTION 'cognitive_ancestry_bridge_required'; END IF;
  v_current_xid:=mod(pg_current_xact_id()::text::numeric,4294967296)::text;
  IF NOT EXISTS(SELECT 1 FROM public.aimos_events e WHERE e.id=v_ancestry_event_id AND e.xmin::text=v_current_xid)
    OR NOT EXISTS(SELECT 1 FROM public.aimos_memory_provenance p WHERE p.memory_id=p_memory_id
      AND p.mutation_hash=p_provenance_mutation_hash AND p.xmin::text=v_current_xid) THEN
    RAISE EXCEPTION 'cognitive_ancestry_not_atomic'; END IF;
  INSERT INTO public.aimos_cognitive_weight_projections
    (company_id, memory_id, provenance_mutation_hash,
     old_weight, new_weight, old_weight_milli, new_weight_milli,
     prev_projection_hash, projection_hash, content_hash_sig,
     transition_hash, transition_sig)
  VALUES
    (v_company_id, p_memory_id, p_provenance_mutation_hash,
     (v_old_milli / 1000.0)::real, (v_new_milli / 1000.0)::real,
     v_old_milli, v_new_milli, v_prev_hash, v_proj_hash, NULL,
     v_transition_hash, p_transition_sig);
  UPDATE public.aimos_memories SET retrieval_weight = (v_new_milli / 1000.0)::real
   WHERE id = p_memory_id AND company_id = v_company_id
  RETURNING retrieval_weight INTO v_applied;
  RETURN v_applied;
END
$function$;

CREATE OR REPLACE FUNCTION public.verify_cognitive_weight_chain(p_memory_id uuid)
RETURNS TABLE(ok boolean, chain_length integer, terminal_weight real,
              sigs_verified integer, break_at bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  c_chain_prefix bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_transition_prefix bytea := '\x61696d6f732e636f676e69746976652d7472616e736974696f6e2f763200'::bytea;
  c_zero32 bytea := decode(repeat('00', 32), 'hex');
  r record;
  v_prev_hash bytea := NULL;
  v_prev_new_milli int := NULL;
  v_first_old_milli int := NULL;
  v_expected bytea;
  v_transition bytea;
  v_provenance bytea;
  v_len integer := 0;
  v_sigs integer := 0;
  v_total integer;
  v_break bytea := NULL;
  v_reason text := NULL;
  v_terminal_milli integer := NULL;
  v_live real;
  v_raw_pub bytea;
  v_body_old_milli integer;
  v_body_new_milli integer;
  v_identity_until timestamptz;
  v_revocation_ts bigint;
  v_identity_cert_fingerprint text;
  v_baseline_count integer;
  v_baseline_ok boolean;
  v_baseline_milli integer;
  v_baseline_observed real;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN RAISE EXCEPTION 'cognitive_company_scope_required'; END IF;
  SELECT retrieval_weight INTO v_live FROM public.aimos_memories
   WHERE id = p_memory_id AND company_id = v_company_id;
  IF NOT FOUND THEN RETURN QUERY SELECT false,0,NULL::real,0,c_zero32,'memory_not_found'::text; RETURN; END IF;
  SELECT count(*) INTO v_total FROM public.aimos_cognitive_weight_projections
   WHERE memory_id = p_memory_id AND company_id = v_company_id;
  SELECT count(*) INTO v_baseline_count FROM public.aimos_cognitive_weight_baselines
   WHERE memory_id = p_memory_id AND company_id = v_company_id;
  IF v_total = 0 THEN
    IF v_baseline_count = 1 THEN
      SELECT b.ok, b.weight_milli INTO v_baseline_ok, v_baseline_milli
        FROM public.verify_cognitive_weight_baseline(p_memory_id) b;
      IF v_baseline_ok IS DISTINCT FROM true THEN
        RETURN QUERY SELECT false,0,v_live,0,c_zero32,'baseline_invalid'::text; RETURN;
      END IF;
      SELECT observed_weight INTO v_baseline_observed
        FROM public.aimos_cognitive_weight_baselines
       WHERE company_id = v_company_id AND memory_id = p_memory_id;
      IF float4send(v_live) <> float4send(v_baseline_observed) THEN
        RETURN QUERY SELECT false,0,v_live,0,c_zero32,'baseline_terminal_weight_mismatch'::text; RETURN;
      END IF;
      RETURN QUERY SELECT true,0,v_live,0,NULL::bytea,NULL::text; RETURN;
    END IF;
    IF float4send(v_live) <> float4send(1.0::real) THEN
      RETURN QUERY SELECT false,0,v_live,0,c_zero32,'unattested_initial_weight'::text; RETURN;
    END IF;
    RETURN QUERY SELECT true,0,v_live,0,NULL::bytea,NULL::text; RETURN;
  END IF;

  FOR r IN
    WITH RECURSIVE walk AS (
      SELECT p.company_id,p.projection_hash,p.prev_projection_hash,
             p.provenance_mutation_hash,p.old_weight,p.new_weight,
             p.old_weight_milli,p.new_weight_milli,p.transition_hash,p.transition_sig,1 AS ord
        FROM public.aimos_cognitive_weight_projections p
       WHERE p.memory_id=p_memory_id AND p.company_id=v_company_id AND p.prev_projection_hash IS NULL
      UNION ALL
      SELECT p.company_id,p.projection_hash,p.prev_projection_hash,
             p.provenance_mutation_hash,p.old_weight,p.new_weight,
             p.old_weight_milli,p.new_weight_milli,p.transition_hash,p.transition_sig,w.ord+1
        FROM public.aimos_cognitive_weight_projections p
        JOIN walk w ON p.memory_id=p_memory_id AND p.company_id=v_company_id
                   AND p.prev_projection_hash=w.projection_hash
    )
    SELECT w.*,pr.event_type,pr.binding_schema_version,pr.agent_id,pr.backfilled,
           pr.body_json,pr.content_hash,pr.prev_mutation_hash AS provenance_prev_hash,
           pr.nonce,pr.ts_signed,pr.agent_valid_from,pr.cert_fingerprint
      FROM walk w LEFT JOIN public.aimos_memory_provenance pr
        ON pr.memory_id=p_memory_id AND pr.mutation_hash=w.provenance_mutation_hash
     ORDER BY w.ord
  LOOP
    v_len := v_len + 1;
    IF v_first_old_milli IS NULL THEN v_first_old_milli := r.old_weight_milli; END IF;
    v_body_old_milli := CASE WHEN jsonb_typeof(r.body_json->'old_weight')='number' THEN round((r.body_json->>'old_weight')::double precision*1000)::int ELSE NULL END;
    v_body_new_milli := CASE WHEN jsonb_typeof(r.body_json->'new_weight')='number' THEN round((r.body_json->>'new_weight')::double precision*1000)::int ELSE NULL END;
    IF r.company_id IS DISTINCT FROM v_company_id
       OR r.event_type IS DISTINCT FROM 'REWEIGHT'
       OR r.binding_schema_version IS DISTINCT FROM 2
       OR r.agent_id IS DISTINCT FROM 'housekeeper'
       OR r.backfilled IS DISTINCT FROM false OR r.body_json IS NULL
       OR r.content_hash IS NULL OR r.nonce IS NULL OR r.ts_signed IS NULL OR r.agent_valid_from IS NULL
       OR r.body_json->>'company_id' IS DISTINCT FROM v_company_id
       OR r.body_json->>'memory_id' IS DISTINCT FROM p_memory_id::text
       OR v_body_old_milli IS NULL OR v_body_new_milli IS NULL
       OR v_body_old_milli<>r.old_weight_milli OR v_body_new_milli<>r.new_weight_milli
       OR float4send(r.old_weight)<>float4send((r.old_weight_milli::double precision/1000.0)::real)
       OR float4send(r.new_weight)<>float4send((r.new_weight_milli::double precision/1000.0)::real) THEN
      v_break:=r.projection_hash; v_reason:='provenance_binding_invalid'; EXIT;
    END IF;
    SELECT i.valid_until,rev.ts_signed,encode(digest(i.cert,'sha256'),'hex')
      INTO v_identity_until,v_revocation_ts,v_identity_cert_fingerprint
      FROM public.agent_identity i LEFT JOIN public.aimos_agent_revocation_events rev
        ON rev.agent_id=i.agent_id AND rev.agent_valid_from=i.valid_from
     WHERE i.agent_id='housekeeper' AND i.valid_from=r.agent_valid_from;
    IF NOT FOUND OR to_timestamp(r.ts_signed)<r.agent_valid_from OR to_timestamp(r.ts_signed)>=v_identity_until
       OR v_identity_cert_fingerprint IS DISTINCT FROM r.cert_fingerprint
       OR (v_revocation_ts IS NOT NULL AND v_revocation_ts<=r.ts_signed) THEN
      v_break:=r.projection_hash; v_reason:='provenance_identity_epoch_invalid'; EXIT;
    END IF;
    IF v_prev_new_milli IS NOT NULL AND r.old_weight_milli<>v_prev_new_milli THEN v_break:=r.projection_hash;v_reason:='continuity_break';EXIT; END IF;
    v_provenance:=digest(r.content_hash||COALESCE(r.provenance_prev_hash,''::bytea)||convert_to(r.nonce,'UTF8')||convert_to((r.ts_signed::bigint)::text,'UTF8'),'sha256');
    IF v_provenance<>r.provenance_mutation_hash THEN v_break:=r.projection_hash;v_reason:='provenance_hash_invalid';EXIT; END IF;
    v_expected:=digest(c_chain_prefix||uuid_send(p_memory_id)||int8send(r.old_weight_milli::int8)||int8send(r.new_weight_milli::int8)||r.provenance_mutation_hash||COALESCE(v_prev_hash,c_zero32),'sha256');
    IF v_expected<>r.projection_hash THEN v_break:=r.projection_hash;v_reason:='hash_mismatch';EXIT; END IF;
    v_transition:=digest(c_transition_prefix||int4send(octet_length(convert_to(v_company_id,'UTF8')))||convert_to(v_company_id,'UTF8')||uuid_send(p_memory_id)||int8send(r.old_weight_milli::int8)||int8send(r.new_weight_milli::int8)||r.provenance_mutation_hash,'sha256');
    IF v_transition<>r.transition_hash THEN v_break:=r.projection_hash;v_reason:='transition_hash_invalid';EXIT; END IF;
    v_raw_pub:=public.cwc_raw_ed25519_pubkey('housekeeper',r.agent_valid_from);
    IF v_raw_pub IS NULL OR octet_length(v_raw_pub)<>32 OR r.transition_sig IS NULL
       OR octet_length(r.transition_sig)<>64
       OR NOT pgsodium.crypto_sign_verify_detached(r.transition_sig,v_transition,v_raw_pub) THEN
      v_break:=r.projection_hash;v_reason:='signature_invalid';EXIT;
    END IF;
    IF r.body_json ? 'ancestry_binding' AND public.verify_cognitive_ancestry_bridge_v1(
      p_memory_id,r.provenance_mutation_hash,v_prev_hash,r.projection_hash) IS NULL THEN
      v_break:=r.projection_hash;v_reason:='ancestry_bridge_invalid';EXIT;
    END IF;
    v_sigs:=v_sigs+1;v_prev_hash:=r.projection_hash;v_prev_new_milli:=r.new_weight_milli;v_terminal_milli:=r.new_weight_milli;
  END LOOP;
  IF v_break IS NULL AND v_len<>v_total THEN v_break:=c_zero32;v_reason:='unreachable_rows'; END IF;
  IF v_break IS NULL AND v_baseline_count=1 THEN
    SELECT b.ok,b.weight_milli INTO v_baseline_ok,v_baseline_milli FROM public.verify_cognitive_weight_baseline(p_memory_id) b;
    IF v_baseline_ok IS DISTINCT FROM true OR v_first_old_milli<>v_baseline_milli THEN v_break:=c_zero32;v_reason:='baseline_chain_anchor_invalid'; END IF;
  ELSIF v_break IS NULL AND v_first_old_milli<>1000 THEN
    v_break:=c_zero32;v_reason:='default_chain_anchor_invalid';
  END IF;
  IF v_break IS NULL AND v_terminal_milli IS NOT NULL
     AND float4send(v_live)<>float4send((v_terminal_milli::double precision/1000.0)::real) THEN v_break:=c_zero32;v_reason:='terminal_weight_mismatch'; END IF;
  ok:=(v_break IS NULL);chain_length:=v_len;terminal_weight:=v_live;sigs_verified:=v_sigs;break_at:=v_break;reason:=v_reason;RETURN NEXT;
END
$function$;
