-- 103-origin-writer-independent-crypto-parity.sql
-- OB-2 independent database parity: verify complete signed-event row equality,
-- the admitted request/occurrence Ed25519 proof, corroborator order, and every
-- security-value family set before any typed row is appended.

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
     OR trunc(extract(epoch FROM v_event.ts))::bigint <> v_event.ts_signed THEN
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

CREATE FUNCTION public.ob2_verify_request_occurrence_authority(
  p_occurrence_id uuid,
  p_request_receipt_id uuid,
  p_company_id text,
  p_actor_agent_id text,
  p_actor_valid_from timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_row record;
  v_pub bytea;
  v_claims text;
  v_message text;
  v_claims_hash bytea;
  v_expected_mutation bytea;
BEGIN
  SELECT occurrence.body_json, occurrence.content_hash AS occurrence_content_hash,
         occurrence.sig AS occurrence_sig, occurrence.agent_id AS occurrence_agent,
         occurrence.agent_valid_from AS occurrence_valid_from,
         receipt.*, identity.pubkey, identity.cert, identity.valid_until, identity.revoked_at
    INTO v_row
    FROM public.aimos_memory_provenance occurrence
    JOIN public.aimos_request_receipts receipt
      ON receipt.request_receipt_id = p_request_receipt_id
    JOIN public.agent_identity identity
      ON identity.agent_id = receipt.actor_agent_id
     AND identity.valid_from = receipt.actor_valid_from
   WHERE occurrence.provenance_id = p_occurrence_id;
  IF NOT FOUND OR v_row.company_id <> p_company_id
     OR v_row.actor_agent_id <> p_actor_agent_id
     OR v_row.actor_valid_from <> p_actor_valid_from
     OR v_row.occurrence_agent <> p_actor_agent_id
     OR v_row.occurrence_valid_from <> p_actor_valid_from
     OR v_row.occurrence_sig <> v_row.sig
     OR v_row.occurrence_content_hash <> v_row.request_hash
     OR v_row.revoked_at IS NOT NULL
     OR v_row.ts_signed < trunc(extract(epoch FROM p_actor_valid_from))::bigint
     OR v_row.ts_signed >= trunc(extract(epoch FROM v_row.valid_until))::bigint
     OR encode(digest(convert_to(v_row.cert,'UTF8'),'sha256'),'hex') <> v_row.cert_fingerprint
     OR digest(convert_to(public.ob2_canonical_json(v_row.body_json),'UTF8'),'sha256') <> v_row.request_hash THEN
    RAISE EXCEPTION 'origin_request_signature_invalid';
  END IF;
  v_pub := public.ob2_raw_ed25519_pubkey(p_actor_agent_id, p_actor_valid_from);
  IF v_row.request_sig_form = 4 THEN
    IF v_row.signed_claims IS NULL THEN RAISE EXCEPTION 'origin_request_signature_invalid'; END IF;
    v_claims := public.ob2_canonical_json(v_row.signed_claims);
    v_message := public.ob2_canonical_json(v_row.body_json) || E'\n'
      || upper(v_row.signed_method) || E'\n' || split_part(v_row.signed_path,'?',1) || E'\n'
      || v_claims || E'\n' || v_row.nonce || E'\n' || v_row.ts_signed::text;
    v_claims_hash := digest(convert_to(v_claims,'UTF8'),'sha256');
  ELSIF v_row.request_sig_form = 3 THEN
    v_message := public.ob2_canonical_json(v_row.body_json) || E'\n'
      || upper(v_row.signed_method) || E'\n' || split_part(v_row.signed_path,'?',1) || E'\n'
      || v_row.nonce || E'\n' || v_row.ts_signed::text;
    v_claims_hash := decode(repeat('00',32),'hex');
  ELSE RAISE EXCEPTION 'origin_request_signature_invalid'; END IF;
  v_expected_mutation := digest(
    convert_to('aimos-request-receipt-v1','UTF8') || decode('00','hex')
    || COALESCE(v_row.prev_mutation_hash,decode(repeat('00',32),'hex'))
    || v_row.request_hash || v_claims_hash || v_row.sig
    || convert_to(v_row.signed_method,'UTF8') || convert_to(v_row.signed_path,'UTF8')
    || convert_to(v_row.nonce,'UTF8') || convert_to(v_row.ts_signed::text,'UTF8'), 'sha256');
  IF v_pub IS NULL OR octet_length(v_pub) <> 32
     OR v_expected_mutation <> v_row.mutation_hash
     OR NOT pgsodium.crypto_sign_verify_detached(v_row.sig,convert_to(v_message,'UTF8'),v_pub)
     OR (v_row.prev_mutation_hash IS NULL) <> v_row.is_genesis
     OR (v_row.prev_mutation_hash IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM public.aimos_request_receipts predecessor
        WHERE predecessor.company_id=v_row.company_id
          AND predecessor.actor_agent_id=v_row.actor_agent_id
          AND predecessor.actor_valid_from=v_row.actor_valid_from
          AND predecessor.mutation_hash=v_row.prev_mutation_hash
     )) THEN RAISE EXCEPTION 'origin_request_signature_invalid'; END IF;
END
$function$;

CREATE FUNCTION public.ob2_validate_corroborators(
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
  FOR v_entry IN SELECT value FROM jsonb_array_elements(p_corroborators) WITH ORDINALITY item(value,ordinal) ORDER BY ordinal LOOP
    IF NOT public.ob2_exact_json_keys(v_entry, ARRAY[
      'principal_id','valid_from','administrative_domain_sha256','upstream_source_sha256','license_sha256'
    ]) OR v_entry->>'administrative_domain_sha256' !~ '^[0-9a-f]{64}$'
       OR v_entry->>'upstream_source_sha256' !~ '^[0-9a-f]{64}$'
       OR v_entry->>'license_sha256' !~ '^[0-9a-f]{64}$' THEN
      RAISE EXCEPTION 'origin_elevation_corroborators_invalid';
    END IF;
    PERFORM (v_entry->>'valid_from')::timestamptz;
    v_key := v_entry->>'administrative_domain_sha256' || ':'
      || v_entry->>'upstream_source_sha256' || ':' || v_entry->>'principal_id'
      || ':' || v_entry->>'valid_from';
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

CREATE FUNCTION public.ob2_validate_security_values(
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
  SELECT ARRAY(SELECT DISTINCT family FROM jsonb_array_elements(p_values) value,
    jsonb_array_elements_text(value->'family_ids') family ORDER BY family)
    INTO v_union;
  IF v_union <> p_aggregate_families THEN
    RAISE EXCEPTION 'origin_verdict_security_value_family_invalid';
  END IF;
END
$function$;

-- The corrected typed function definitions follow in this same migration.


CREATE OR REPLACE FUNCTION public.commit_memory_origin_binding_v1(
  p_body jsonb,
  p_body_bytes bytea,
  p_binding_sha256 bytea,
  p_classification_event_id uuid,
  p_prev_ledger_hash bytea,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text,
  p_authority_profile_sha256 bytea,
  p_signed_at timestamptz,
  p_ledger_signature bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_schema constant text := 'hom.aimos.memory-origin-binding/v1';
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
BEGIN
  PERFORM public.ob2_verify_origin_object(c_schema, p_body, p_body_bytes, p_binding_sha256);
  IF NOT public.ob2_exact_json_keys(p_body, ARRAY[
    'schema','company_id','memory_id','occurrence_id','content_sha256','actor','request',
    'origin','parents','classification','confidentiality','integrity','action_class',
    'scope','session_id','tool_action_event_id','created_at'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'actor', ARRAY[
    'agent_id','valid_from','cert_fingerprint_sha256'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'request', ARRAY[
    'receipt_id','mutation_sha256'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'origin', ARRAY[
    'ingress_channel','channel_identity_sha256'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'parents', ARRAY['origin_sha256s'])
     OR NOT public.ob2_exact_json_keys(p_body->'classification', ARRAY[
       'profile_sha256','family_ids','authority','evidence_sha256'
     ]) THEN
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
  IF octet_length(v_content) <> 32 OR octet_length(v_request_mutation) <> 32
     OR octet_length(v_channel_identity) <> 32
     OR p_body#>>'{classification,profile_sha256}' <> encode(c_family_profile,'hex')
     OR p_body#>>'{classification,evidence_sha256}' !~ '^[0-9a-f]{64}$'
     OR v_actor_fingerprint !~ '^[0-9a-f]{64}$'
     OR v_scope IS NULL OR v_scope = '' THEN
    RAISE EXCEPTION 'origin_memory_field_invalid';
  END IF;
  IF v_parents <> ARRAY(
       SELECT value FROM unnest(v_parents) value ORDER BY encode(value,'hex')
     ) OR cardinality(ARRAY(SELECT DISTINCT value FROM unnest(v_parents) value)) <> cardinality(v_parents)
     OR cardinality(v_parents) > 64 THEN
    RAISE EXCEPTION 'origin_parent_set_invalid';
  END IF;
  PERFORM public.ob2_validate_family_set(c_family_profile, v_families);

  SELECT memory.content_hash, memory.company_id, memory.scope, memory.data_class
    INTO v_memory FROM public.aimos_memories memory
   WHERE memory.id = v_memory_id FOR SHARE;
  IF NOT FOUND OR v_memory.company_id <> v_company OR v_memory.content_hash <> v_content
     OR v_memory.scope <> v_scope OR v_memory.data_class <> v_confidentiality THEN
    RAISE EXCEPTION 'origin_memory_relational_mismatch';
  END IF;
  SELECT provenance.memory_id, provenance.live_content_hash, provenance.agent_id,
         provenance.agent_valid_from, provenance.cert_fingerprint, provenance.sig,
         provenance.content_hash, provenance.body_json, provenance.request_sig_form,
         provenance.signed_method, provenance.signed_path, provenance.signed_claims,
         provenance.nonce, provenance.ts_signed
    INTO v_occurrence FROM public.aimos_memory_provenance provenance
   WHERE provenance.provenance_id = v_occurrence_id AND provenance.event_type IN ('SAVE','SAVE_REASSERT');
  IF NOT FOUND OR v_occurrence.memory_id <> v_memory_id OR v_occurrence.live_content_hash <> v_content THEN
    RAISE EXCEPTION 'origin_occurrence_relational_mismatch';
  END IF;
  SELECT receipt.*, identity.pubkey, identity.cert
    INTO v_receipt FROM public.aimos_request_receipts receipt
    JOIN public.agent_identity identity
      ON identity.agent_id = receipt.actor_agent_id AND identity.valid_from = receipt.actor_valid_from
   WHERE receipt.request_receipt_id = v_receipt_id;
  IF NOT FOUND OR v_receipt.company_id <> v_company OR v_receipt.actor_agent_id <> v_actor
     OR v_receipt.actor_valid_from <> v_actor_valid_from OR v_receipt.mutation_hash <> v_request_mutation
     OR v_receipt.cert_fingerprint <> v_actor_fingerprint
     OR encode(digest(convert_to(v_receipt.cert,'UTF8'),'sha256'),'hex') <> v_actor_fingerprint
     OR v_occurrence.agent_id <> v_actor OR v_occurrence.agent_valid_from <> v_actor_valid_from
     OR v_occurrence.cert_fingerprint <> v_actor_fingerprint OR v_occurrence.sig <> v_receipt.sig
     OR v_occurrence.content_hash <> v_receipt.request_hash THEN
    RAISE EXCEPTION 'origin_request_actor_relational_mismatch';
  END IF;
  PERFORM public.ob2_verify_request_occurrence_authority(
    v_occurrence_id, v_receipt_id, v_company, v_actor, v_actor_valid_from);


  v_event := public.ob2_verify_signed_event(p_classification_event_id, v_company);
  IF v_event.operation <> 'origin_family_classified'
     OR v_event.signer_agent_id <> 'housekeeper'
     OR v_event.mutation_hash <> decode(p_body#>>'{classification,evidence_sha256}','hex')
     OR v_event.metadata->>'schema' <> 'hom.aimos.origin-classification-evidence/v1'
     OR v_event.metadata->>'memory_id' <> v_memory_id::text
     OR v_event.metadata->>'content_sha256' <> encode(v_content,'hex')
     OR v_event.metadata->>'actor_agent_id' <> v_actor
     OR v_event.metadata->>'family_profile_sha256' <> encode(c_family_profile,'hex')
     OR v_event.metadata->'family_ids' <> p_body#>'{classification,family_ids}'
     OR v_event.metadata->>'classification_authority' <> p_body#>>'{classification,authority}'
     OR v_event.metadata->>'ingress_channel' <> v_ingress
     OR v_event.metadata->>'channel_identity_sha256' <> encode(v_channel_identity,'hex')
     OR v_event.metadata->>'confidentiality' <> v_confidentiality
     OR v_event.metadata->>'integrity' <> v_integrity
     OR v_event.metadata->>'action_class' <> v_action
     OR v_event.metadata->>'action_scope' <> v_scope
     OR v_event.metadata->>'session_id' IS DISTINCT FROM p_body->>'session_id'
     OR v_event.metadata->>'tool_action_event_id' IS DISTINCT FROM p_body->>'tool_action_event_id'
     OR (p_body->>'created_at')::timestamptz <> v_event.ts::timestamptz THEN
    RAISE EXCEPTION 'origin_classification_evidence_invalid';
  END IF;

  IF v_ingress IN ('authenticated_agent','agent_self') AND encode(v_channel_identity,'hex') <> v_actor_fingerprint THEN
    RAISE EXCEPTION 'origin_channel_identity_invalid';
  ELSIF v_ingress = 'housekeeper_system' AND encode(v_channel_identity,'hex') <> p_signer_cert_fingerprint THEN
    RAISE EXCEPTION 'origin_channel_identity_invalid';
  END IF;
  IF v_integrity = 'trusted' AND v_ingress NOT IN ('authenticated_tool','authenticated_user','system_internal') THEN
    RAISE EXCEPTION 'origin_integrity_elevation';
  END IF;
  IF (v_action = 'act' AND v_integrity <> 'trusted') OR (v_action = 'inform' AND v_integrity = 'untrusted') THEN
    RAISE EXCEPTION 'origin_action_class_elevation';
  END IF;
  SELECT max(array_position(ARRAY['public','internal','confidential','restricted'], definition.confidentiality_floor))
    INTO v_floor FROM public.aimos_origin_family_definitions definition
   WHERE definition.profile_sha256 = c_family_profile AND definition.family_id = ANY(v_families);
  IF array_position(ARRAY['public','internal','confidential','restricted'], v_confidentiality) < v_floor THEN
    RAISE EXCEPTION 'origin_confidentiality_floor_invalid';
  END IF;

  SELECT count(*)::integer INTO v_missing
    FROM unnest(v_parents) parent(hash)
    LEFT JOIN public.aimos_memory_origin_bindings binding ON binding.binding_sha256 = parent.hash
   WHERE binding.binding_sha256 IS NULL OR binding.company_id <> v_company;
  IF v_missing <> 0 THEN RAISE EXCEPTION 'origin_parent_binding_invalid'; END IF;
  IF cardinality(v_parents) > 0 THEN
    SELECT max(array_position(ARRAY['public','internal','confidential','restricted'], parent.confidentiality)),
           min(array_position(ARRAY['untrusted','agent','trusted'], parent.integrity)),
           min(array_position(ARRAY['none','inform','act'], parent.action_class))
      INTO v_parent_floor, v_parent_integrity, v_parent_action
      FROM public.aimos_memory_origin_bindings parent WHERE parent.binding_sha256 = ANY(v_parents);
    IF array_position(ARRAY['public','internal','confidential','restricted'], v_confidentiality) < v_parent_floor
       OR array_position(ARRAY['untrusted','agent','trusted'], v_integrity) > v_parent_integrity
       OR array_position(ARRAY['none','inform','act'], v_action) > v_parent_action THEN
      RAISE EXCEPTION 'origin_parent_lattice_invalid';
    END IF;
    SELECT count(*)::integer INTO v_missing FROM (
      SELECT DISTINCT unnest(parent.family_ids) family_id
        FROM public.aimos_memory_origin_bindings parent WHERE parent.binding_sha256 = ANY(v_parents)
    ) inherited WHERE NOT inherited.family_id = ANY(v_families);
    IF v_missing <> 0 THEN RAISE EXCEPTION 'origin_parent_family_invalid'; END IF;
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
    body_json, body_bytes
  ) VALUES (
    p_binding_sha256, v_ledger_hash, v_company, v_memory_id, v_occurrence_id,
    v_content, v_actor, v_actor_valid_from, v_actor_fingerprint, v_receipt_id,
    v_request_mutation, v_ingress, v_channel_identity, v_parents,
    c_family_profile, v_families, p_body#>>'{classification,authority}',
    decode(p_body#>>'{classification,evidence_sha256}','hex'), p_classification_event_id,
    v_confidentiality, v_integrity, v_action, v_scope, p_body->>'session_id',
    NULLIF(p_body->>'tool_action_event_id','')::uuid, (p_body->>'created_at')::timestamptz,
    p_body, p_body_bytes
  );
  RETURN v_ledger_hash;
END
$function$;

CREATE OR REPLACE FUNCTION public.commit_origin_elevation_v1(
  p_body jsonb,
  p_body_bytes bytea,
  p_elevation_sha256 bytea,
  p_authorization_event_id uuid,
  p_prev_ledger_hash bytea,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text,
  p_authority_profile_sha256 bytea,
  p_signed_at timestamptz,
  p_ledger_signature bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_schema constant text := 'hom.aimos.origin-elevation/v1';
  c_family_profile constant bytea := decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex');
  v_company text;
  v_elevation_id uuid;
  v_value bytea;
  v_family text;
  v_origins bytea[];
  v_corroborators jsonb;
  v_threshold integer;
  v_user_auth bytea;
  v_event public.aimos_events%ROWTYPE;
  v_ledger_hash bytea;
  v_count integer;
  v_distinct_domains integer;
  v_distinct_upstream integer;
BEGIN
  PERFORM public.ob2_verify_origin_object(c_schema, p_body, p_body_bytes, p_elevation_sha256);
  IF NOT public.ob2_exact_json_keys(p_body, ARRAY[
    'schema','company_id','elevation_id','value_sha256','family_id','action_scope',
    'risk_class','base_origin_sha256s','corroborators','threshold',
    'user_authorization_sha256','maximum_uses','valid_from','valid_until','created_at'
  ]) THEN RAISE EXCEPTION 'origin_elevation_shape_invalid'; END IF;
  BEGIN
    v_company := p_body->>'company_id';
    v_elevation_id := (p_body->>'elevation_id')::uuid;
    v_value := decode(p_body->>'value_sha256','hex');
    v_family := p_body->>'family_id';
    v_origins := public.ob2_json_hash_array(p_body->'base_origin_sha256s');
    v_corroborators := p_body->'corroborators';
    v_threshold := (p_body->>'threshold')::integer;
    v_user_auth := CASE WHEN p_body->>'user_authorization_sha256' IS NULL THEN NULL
      ELSE decode(p_body->>'user_authorization_sha256','hex') END;
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'origin_elevation_field_invalid'; END;
  IF octet_length(v_value) <> 32 OR cardinality(v_origins) < 1 OR cardinality(v_origins) > 64
     OR v_origins <> ARRAY(SELECT value FROM unnest(v_origins) value ORDER BY encode(value,'hex'))
     OR cardinality(ARRAY(SELECT DISTINCT value FROM unnest(v_origins) value)) <> cardinality(v_origins)
     OR (p_body->>'maximum_uses')::integer <> 1
     OR (p_body->>'valid_until')::timestamptz <= (p_body->>'valid_from')::timestamptz
     OR (p_body->>'created_at')::timestamptz > (p_body->>'valid_until')::timestamptz THEN
    RAISE EXCEPTION 'origin_elevation_field_invalid';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.aimos_origin_family_definitions
    WHERE profile_sha256 = c_family_profile AND family_id = v_family) THEN
    RAISE EXCEPTION 'origin_elevation_family_invalid';
  END IF;
  PERFORM public.ob2_validate_corroborators(v_corroborators,v_threshold,v_user_auth);
  SELECT count(*)::integer INTO v_count FROM unnest(v_origins) origin
    JOIN public.aimos_memory_origin_bindings binding ON binding.binding_sha256 = origin
   WHERE binding.company_id = v_company;
  IF v_count <> cardinality(v_origins) THEN RAISE EXCEPTION 'origin_elevation_base_invalid'; END IF;
  IF jsonb_typeof(v_corroborators) <> 'array' OR jsonb_array_length(v_corroborators) > 16 THEN
    RAISE EXCEPTION 'origin_elevation_corroborators_invalid';
  END IF;
  SELECT count(*)::integer,
         count(DISTINCT entry->>'administrative_domain_sha256')::integer,
         count(DISTINCT entry->>'upstream_source_sha256')::integer
    INTO v_count, v_distinct_domains, v_distinct_upstream
    FROM jsonb_array_elements(v_corroborators) entry
   WHERE public.ob2_exact_json_keys(entry, ARRAY[
     'principal_id','valid_from','administrative_domain_sha256','upstream_source_sha256','license_sha256'
   ]) AND entry->>'administrative_domain_sha256' ~ '^[0-9a-f]{64}$'
     AND entry->>'upstream_source_sha256' ~ '^[0-9a-f]{64}$'
     AND entry->>'license_sha256' ~ '^[0-9a-f]{64}$';
  IF v_count <> jsonb_array_length(v_corroborators)
     OR v_count <> v_distinct_domains OR v_count <> v_distinct_upstream
     OR v_threshold < 2 OR v_threshold > 16
     OR (v_user_auth IS NULL AND v_count < v_threshold) THEN
    RAISE EXCEPTION 'origin_elevation_authority_invalid';
  END IF;
  IF v_user_auth IS NULL AND p_authorization_event_id IS NOT NULL
     OR v_user_auth IS NOT NULL AND p_authorization_event_id IS NULL THEN
    RAISE EXCEPTION 'origin_elevation_authorization_binding_invalid';
  END IF;
  IF p_authorization_event_id IS NOT NULL THEN
    v_event := public.ob2_verify_signed_event(p_authorization_event_id, v_company);
    IF v_event.mutation_hash <> v_user_auth OR v_event.operation <> 'origin_elevation_authorized' THEN
      RAISE EXCEPTION 'origin_elevation_authorization_binding_invalid';
    END IF;
  END IF;
  v_ledger_hash := public.ob2_commit_origin_ledger_entry(
    v_company, c_schema, p_elevation_sha256, p_prev_ledger_hash,
    p_signer_valid_from, p_signer_cert_fingerprint,
    p_authority_profile_sha256, p_signed_at, p_ledger_signature);
  INSERT INTO public.aimos_origin_elevations (
    elevation_sha256, ledger_hash, company_id, elevation_id, value_sha256,
    family_id, action_scope, risk_class, base_origin_sha256s, corroborators,
    threshold, user_authorization_sha256, authorization_event_id, maximum_uses,
    valid_from, valid_until, originated_at, body_json, body_bytes
  ) VALUES (
    p_elevation_sha256, v_ledger_hash, v_company, v_elevation_id, v_value,
    v_family, p_body->>'action_scope', p_body->>'risk_class', v_origins,
    v_corroborators, v_threshold, v_user_auth, p_authorization_event_id, 1,
    (p_body->>'valid_from')::timestamptz, (p_body->>'valid_until')::timestamptz,
    (p_body->>'created_at')::timestamptz, p_body, p_body_bytes
  );
  RETURN v_ledger_hash;
END
$function$;

CREATE OR REPLACE FUNCTION public.commit_action_origin_verdict_v1(
  p_body jsonb,
  p_body_bytes bytea,
  p_verdict_sha256 bytea,
  p_authorization_event_id uuid,
  p_prev_ledger_hash bytea,
  p_signer_valid_from timestamptz,
  p_signer_cert_fingerprint text,
  p_authority_profile_sha256 bytea,
  p_signed_at timestamptz,
  p_ledger_signature bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_schema constant text := 'hom.aimos.action-origin-verdict/v1';
  c_family_profile constant bytea := decode('49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24','hex');
  v_company text;
  v_verdict_id uuid;
  v_actor text;
  v_actor_valid_from timestamptz;
  v_actor_fingerprint text;
  v_families text[];
  v_origins bytea[];
  v_elevation bytea;
  v_user_auth bytea;
  v_previous bytea;
  v_decision text;
  v_failure text;
  v_event public.aimos_events%ROWTYPE;
  v_ledger_hash bytea;
  v_count integer;
  v_value_families text[];
BEGIN
  PERFORM public.ob2_verify_origin_object(c_schema, p_body, p_body_bytes, p_verdict_sha256);
  IF NOT public.ob2_exact_json_keys(p_body, ARRAY[
    'schema','company_id','verdict_id','actor','tool_name','action_scope','risk_class',
    'arguments_sha256','security_values','family_ids','input_origin_sha256s',
    'untrusted_influence','elevation_sha256','user_authorization_sha256','decision',
    'failure_code','previous_verdict_sha256','created_at'
  ]) OR NOT public.ob2_exact_json_keys(p_body->'actor', ARRAY[
    'agent_id','valid_from','cert_fingerprint_sha256'
  ]) THEN RAISE EXCEPTION 'origin_verdict_shape_invalid'; END IF;
  BEGIN
    v_company := p_body->>'company_id';
    v_verdict_id := (p_body->>'verdict_id')::uuid;
    v_actor := p_body#>>'{actor,agent_id}';
    v_actor_valid_from := (p_body#>>'{actor,valid_from}')::timestamptz;
    v_actor_fingerprint := p_body#>>'{actor,cert_fingerprint_sha256}';
    v_families := public.ob2_json_text_array(p_body->'family_ids');
    v_origins := public.ob2_json_hash_array(p_body->'input_origin_sha256s');
    v_elevation := CASE WHEN p_body->>'elevation_sha256' IS NULL THEN NULL ELSE decode(p_body->>'elevation_sha256','hex') END;
    v_user_auth := CASE WHEN p_body->>'user_authorization_sha256' IS NULL THEN NULL ELSE decode(p_body->>'user_authorization_sha256','hex') END;
    v_previous := CASE WHEN p_body->>'previous_verdict_sha256' IS NULL THEN NULL ELSE decode(p_body->>'previous_verdict_sha256','hex') END;
    v_decision := p_body->>'decision';
    v_failure := p_body->>'failure_code';
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'origin_verdict_field_invalid'; END;
  PERFORM public.ob2_validate_family_set(c_family_profile, v_families);
  IF v_actor_fingerprint !~ '^[0-9a-f]{64}$' OR p_body->>'arguments_sha256' !~ '^[0-9a-f]{64}$'
     OR cardinality(v_origins) < 1 OR cardinality(v_origins) > 64
     OR v_origins <> ARRAY(SELECT value FROM unnest(v_origins) value ORDER BY encode(value,'hex'))
     OR cardinality(ARRAY(SELECT DISTINCT value FROM unnest(v_origins) value)) <> cardinality(v_origins)
     OR (v_decision = 'ALLOW' AND v_failure IS NOT NULL)
     OR (v_decision <> 'ALLOW' AND v_failure IS NULL)
     OR (v_decision = 'ALLOW' AND (p_body->>'untrusted_influence')::boolean
         AND v_elevation IS NULL AND v_user_auth IS NULL) THEN
    RAISE EXCEPTION 'origin_verdict_semantics_invalid';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.agent_identity identity
    WHERE identity.agent_id = v_actor AND identity.valid_from = v_actor_valid_from
      AND identity.revoked_at IS NULL
      AND encode(digest(convert_to(identity.cert,'UTF8'),'sha256'),'hex') = v_actor_fingerprint) THEN
    RAISE EXCEPTION 'origin_verdict_actor_invalid';
  END IF;
  SELECT count(*)::integer INTO v_count FROM unnest(v_origins) origin
    JOIN public.aimos_memory_origin_bindings binding ON binding.binding_sha256 = origin
   WHERE binding.company_id = v_company;
  IF v_count <> cardinality(v_origins) THEN RAISE EXCEPTION 'origin_verdict_input_invalid'; END IF;
  IF jsonb_typeof(p_body->'security_values') <> 'array'
     OR jsonb_array_length(p_body->'security_values') < 1
     OR jsonb_array_length(p_body->'security_values') > 64 THEN
    RAISE EXCEPTION 'origin_verdict_security_values_invalid';
  END IF;
  PERFORM public.ob2_validate_security_values(
    p_body->'security_values',c_family_profile,v_families);
  SELECT ARRAY(
    SELECT distinct_value.family
      FROM (
        SELECT DISTINCT family
          FROM jsonb_array_elements(p_body->'security_values') value,
               jsonb_array_elements_text(value->'family_ids') family
      ) distinct_value
     ORDER BY convert_to(distinct_value.family,'UTF8')
  ) INTO v_value_families;
  IF v_value_families <> v_families OR EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_body->'security_values') value
     WHERE NOT public.ob2_exact_json_keys(value, ARRAY['value_sha256','family_ids'])
        OR value->>'value_sha256' !~ '^[0-9a-f]{64}$'
  ) THEN RAISE EXCEPTION 'origin_verdict_security_values_invalid'; END IF;
  IF v_elevation IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.aimos_origin_elevations elevation
     WHERE elevation.elevation_sha256 = v_elevation AND elevation.company_id = v_company
       AND elevation.action_scope = p_body->>'action_scope'
       AND elevation.family_id = ANY(v_families)
       AND (p_body->>'created_at')::timestamptz BETWEEN elevation.valid_from AND elevation.valid_until
  ) THEN RAISE EXCEPTION 'origin_verdict_elevation_invalid'; END IF;
  IF v_user_auth IS NULL AND p_authorization_event_id IS NOT NULL
     OR v_user_auth IS NOT NULL AND p_authorization_event_id IS NULL THEN
    RAISE EXCEPTION 'origin_verdict_authorization_invalid';
  END IF;
  IF p_authorization_event_id IS NOT NULL THEN
    v_event := public.ob2_verify_signed_event(p_authorization_event_id, v_company);
    IF v_event.mutation_hash <> v_user_auth OR v_event.operation <> 'origin_action_authorized' THEN
      RAISE EXCEPTION 'origin_verdict_authorization_invalid';
    END IF;
  END IF;
  IF v_previous IS NULL THEN
    IF EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts prior
      WHERE prior.company_id = v_company AND prior.actor_agent_id = v_actor
        AND prior.actor_valid_from = v_actor_valid_from
        AND prior.tool_name = p_body->>'tool_name' AND prior.action_scope = p_body->>'action_scope') THEN
      RAISE EXCEPTION 'origin_verdict_predecessor_invalid';
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts prior
    WHERE prior.verdict_sha256 = v_previous AND prior.company_id = v_company
      AND prior.actor_agent_id = v_actor AND prior.actor_valid_from = v_actor_valid_from
      AND prior.tool_name = p_body->>'tool_name' AND prior.action_scope = p_body->>'action_scope'
      AND NOT EXISTS (SELECT 1 FROM public.aimos_action_origin_verdicts successor
        WHERE successor.previous_verdict_sha256 = prior.verdict_sha256)) THEN
    RAISE EXCEPTION 'origin_verdict_predecessor_invalid';
  END IF;
  v_ledger_hash := public.ob2_commit_origin_ledger_entry(
    v_company, c_schema, p_verdict_sha256, p_prev_ledger_hash,
    p_signer_valid_from, p_signer_cert_fingerprint,
    p_authority_profile_sha256, p_signed_at, p_ledger_signature);
  INSERT INTO public.aimos_action_origin_verdicts (
    verdict_sha256, ledger_hash, company_id, verdict_id, actor_agent_id,
    actor_valid_from, actor_cert_fingerprint, tool_name, action_scope, risk_class,
    arguments_sha256, security_values, family_ids, input_origin_sha256s,
    untrusted_influence, elevation_sha256, user_authorization_sha256,
    authorization_event_id, decision, failure_code, previous_verdict_sha256,
    originated_at, body_json, body_bytes
  ) VALUES (
    p_verdict_sha256, v_ledger_hash, v_company, v_verdict_id, v_actor,
    v_actor_valid_from, v_actor_fingerprint, p_body->>'tool_name',
    p_body->>'action_scope', p_body->>'risk_class', decode(p_body->>'arguments_sha256','hex'),
    p_body->'security_values', v_families, v_origins,
    (p_body->>'untrusted_influence')::boolean, v_elevation, v_user_auth,
    p_authorization_event_id, v_decision, v_failure, v_previous,
    (p_body->>'created_at')::timestamptz, p_body, p_body_bytes
  );
  RETURN v_ledger_hash;
END
$function$;

REVOKE ALL ON FUNCTION public.ob2_verify_request_occurrence_authority(uuid,uuid,text,text,timestamptz), public.ob2_validate_corroborators(jsonb,integer,bytea), public.ob2_validate_security_values(jsonb,bytea,text[]) FROM PUBLIC, agent_runtime, aimos_app;
