-- Certified cognitive trajectory v2 correction.
--
-- 084 proved that a provenance content hash was signed, but did not bind the
-- detached signature directly to the projection's tenant/memory/old/new tuple.
-- It also recreated the SECURITY DEFINER writer without restoring its EXECUTE
-- ACL. This forward-only migration closes both defects.

ALTER TABLE public.aimos_cognitive_weight_projections
  ADD COLUMN IF NOT EXISTS transition_hash bytea,
  ADD COLUMN IF NOT EXISTS transition_sig bytea;

-- No canonical deployment has applied 080-084 yet. If another deployment has
-- already created v1 projection rows, it must run an explicit retained
-- re-attestation ceremony; silently certifying them as v2 would be dishonest.
DO $cwc_v2_upgrade_gate$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.aimos_cognitive_weight_projections
     WHERE transition_hash IS NULL OR transition_sig IS NULL
  ) THEN
    RAISE EXCEPTION 'CWC-085 ABORT: pre-v2 cognitive rows require explicit transition re-attestation';
  END IF;
END
$cwc_v2_upgrade_gate$;

ALTER TABLE public.aimos_cognitive_weight_projections
  ALTER COLUMN transition_hash SET NOT NULL,
  ALTER COLUMN transition_sig SET NOT NULL;

ALTER TABLE public.aimos_cognitive_weight_projections
  ADD CONSTRAINT aimos_cwc_transition_hash_length
  CHECK (octet_length(transition_hash) = 32);

ALTER TABLE public.aimos_cognitive_weight_projections
  ADD CONSTRAINT aimos_cwc_transition_sig_length
  CHECK (octet_length(transition_sig) = 64);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_cwc_transition_hash_unique
  ON public.aimos_cognitive_weight_projections (transition_hash);

-- PostgreSQL does not permit renaming p_content_sig from migration 084 via
-- CREATE OR REPLACE. Replace the exact signature inside this migration's
-- transaction; no compatibility overload remains.
DROP FUNCTION public.apply_signed_cognitive_reweight(
  uuid, double precision, double precision, bytea, bytea
);

CREATE FUNCTION public.apply_signed_cognitive_reweight(
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
  v_company_id       text;
  v_current_weight   real;
  v_current_milli    int;
  v_old_milli        int;
  v_new_milli        int;
  v_body             jsonb;
  v_agent_vf         timestamptz;
  v_raw_pub          bytea;
  v_prev_hash        bytea;
  v_head_milli       int;
  v_proj_hash        bytea;
  v_transition_hash  bytea;
  v_applied          real;
  v_body_old_milli   integer;
  v_body_new_milli   integer;
  c_chain_prefix     bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_transition_prefix bytea := '\x61696d6f732e636f676e69746976652d7472616e736974696f6e2f763200'::bytea;
  c_zero32           bytea := decode(repeat('00', 32), 'hex');
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;
  IF current_setting('app.current_agent_id', true) <> 'housekeeper' THEN
    RAISE EXCEPTION 'cognitive_housekeeper_scope_required';
  END IF;

  IF p_memory_id IS NULL
     OR p_provenance_mutation_hash IS NULL
     OR octet_length(p_provenance_mutation_hash) <> 32 THEN
    RAISE EXCEPTION 'cognitive_transition_identity_malformed';
  END IF;
  IF p_old_weight IS NULL OR p_new_weight IS NULL
     OR p_old_weight < 0.1 OR p_old_weight > 3.0
     OR p_new_weight < 0.1 OR p_new_weight > 3.0 THEN
    RAISE EXCEPTION 'cognitive_weight_out_of_bounds';
  END IF;
  v_old_milli := round(p_old_weight * 1000)::int;
  v_new_milli := round(p_new_weight * 1000)::int;
  IF v_old_milli < 100 OR v_old_milli > 3000
     OR v_new_milli < 100 OR v_new_milli > 3000 THEN
    RAISE EXCEPTION 'cognitive_weight_out_of_bounds';
  END IF;
  IF v_new_milli = v_old_milli THEN
    RAISE EXCEPTION 'cognitive_noop_reweight';
  END IF;
  IF p_transition_sig IS NULL OR octet_length(p_transition_sig) <> 64 THEN
    RAISE EXCEPTION 'cognitive_transition_sig_malformed';
  END IF;

  -- Serialize the complete read/sign/apply protocol without granting the
  -- runtime role direct UPDATE merely to use SELECT FOR UPDATE. Native callers
  -- take this same key before reading the old weight; re-acquisition inside one
  -- transaction is safe and makes direct function calls follow the same order.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'cognitive-reweight:' || v_company_id || ':' || p_memory_id::text,
    0
  ));

  SELECT m.retrieval_weight
    INTO v_current_weight
    FROM public.aimos_memories m
   WHERE m.id = p_memory_id AND m.company_id = v_company_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'cognitive_memory_not_found'; END IF;

  SELECT p.body_json, p.agent_valid_from
    INTO v_body, v_agent_vf
    FROM public.aimos_memory_provenance p
   WHERE p.memory_id = p_memory_id
     AND p.mutation_hash = p_provenance_mutation_hash
     AND p.event_type = 'REWEIGHT'
     AND p.binding_schema_version = 2
     AND p.agent_id = 'housekeeper'
     AND p.backfilled = false
     AND p.sig IS NOT NULL
     AND octet_length(p.sig) = 64
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_memory_provenance successor
        WHERE successor.memory_id = p.memory_id
          AND successor.prev_mutation_hash = p.mutation_hash
     );
  IF NOT FOUND OR v_body IS NULL THEN
    RAISE EXCEPTION 'signed_cognitive_provenance_required';
  END IF;
  v_body_old_milli := CASE
    WHEN jsonb_typeof(v_body->'old_weight') = 'number'
    THEN round((v_body->>'old_weight')::double precision * 1000)::int
    ELSE NULL
  END;
  v_body_new_milli := CASE
    WHEN jsonb_typeof(v_body->'new_weight') = 'number'
    THEN round((v_body->>'new_weight')::double precision * 1000)::int
    ELSE NULL
  END;
  IF v_body->>'event_type' <> 'REWEIGHT'
     OR v_body->>'company_id' <> v_company_id
     OR v_body->>'memory_id' <> p_memory_id::text
     OR v_body_old_milli IS NULL
     OR v_body_new_milli IS NULL
     OR v_body_old_milli <> v_old_milli
     OR v_body_new_milli <> v_new_milli THEN
    RAISE EXCEPTION 'signed_cognitive_transition_mismatch';
  END IF;

  v_transition_hash := digest(
    c_transition_prefix
    || int4send(octet_length(convert_to(v_company_id, 'UTF8')))
    || convert_to(v_company_id, 'UTF8')
    || uuid_send(p_memory_id)
    || int8send(v_old_milli::int8)
    || int8send(v_new_milli::int8)
    || p_provenance_mutation_hash,
    'sha256');
  v_raw_pub := public.cwc_raw_ed25519_pubkey('housekeeper', v_agent_vf);
  IF v_raw_pub IS NULL OR octet_length(v_raw_pub) <> 32 THEN
    RAISE EXCEPTION 'cognitive_housekeeper_pubkey_unavailable';
  END IF;
  IF NOT pgsodium.crypto_sign_verify_detached(p_transition_sig, v_transition_hash, v_raw_pub) THEN
    RAISE EXCEPTION 'cognitive_transition_sig_invalid';
  END IF;

  SELECT h.projection_hash, h.new_weight_milli
    INTO v_prev_hash, v_head_milli
    FROM public.aimos_cognitive_weight_projections h
   WHERE h.memory_id = p_memory_id
     AND h.company_id = v_company_id
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_cognitive_weight_projections c
        WHERE c.memory_id = h.memory_id
          AND c.prev_projection_hash = h.projection_hash
     );

  IF v_prev_hash IS NULL THEN
    v_current_milli := round(v_current_weight::double precision * 1000)::int;
    IF v_old_milli <> v_current_milli THEN RAISE EXCEPTION 'cognitive_old_weight_mismatch'; END IF;
  ELSIF v_old_milli <> v_head_milli THEN
    RAISE EXCEPTION 'cognitive_chain_discontinuity';
  END IF;

  v_proj_hash := digest(
    c_chain_prefix || uuid_send(p_memory_id)
    || int8send(v_old_milli::int8) || int8send(v_new_milli::int8)
    || p_provenance_mutation_hash || COALESCE(v_prev_hash, c_zero32),
    'sha256');

  INSERT INTO public.aimos_cognitive_weight_projections
    (company_id, memory_id, provenance_mutation_hash,
     old_weight, new_weight, old_weight_milli, new_weight_milli,
     prev_projection_hash, projection_hash, content_hash_sig,
     transition_hash, transition_sig)
  VALUES
    (v_company_id, p_memory_id, p_provenance_mutation_hash,
     p_old_weight, p_new_weight, v_old_milli, v_new_milli,
     v_prev_hash, v_proj_hash, NULL,
     v_transition_hash, p_transition_sig);

  UPDATE public.aimos_memories
     SET retrieval_weight = (v_new_milli / 1000.0)::real
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
  v_company_id        text;
  c_chain_prefix      bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_transition_prefix bytea := '\x61696d6f732e636f676e69746976652d7472616e736974696f6e2f763200'::bytea;
  c_zero32            bytea := decode(repeat('00', 32), 'hex');
  r                   record;
  v_prev_hash         bytea := NULL;
  v_prev_new_milli    int := NULL;
  v_expected          bytea;
  v_transition        bytea;
  v_provenance        bytea;
  v_len               integer := 0;
  v_sigs              integer := 0;
  v_total             integer;
  v_break             bytea := NULL;
  v_reason            text := NULL;
  v_terminal_milli    integer := NULL;
  v_live              real;
  v_raw_pub           bytea;
  v_body_old_milli    integer;
  v_body_new_milli    integer;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;

  SELECT retrieval_weight INTO v_live
    FROM public.aimos_memories
   WHERE id = p_memory_id AND company_id = v_company_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 0, NULL::real, 0, c_zero32, 'memory_not_found'::text;
    RETURN;
  END IF;

  SELECT count(*) INTO v_total
    FROM public.aimos_cognitive_weight_projections
   WHERE memory_id = p_memory_id AND company_id = v_company_id;

  FOR r IN
    WITH RECURSIVE walk AS (
      SELECT p.company_id, p.projection_hash, p.prev_projection_hash,
             p.provenance_mutation_hash, p.old_weight_milli, p.new_weight_milli,
             p.transition_hash, p.transition_sig, 1 AS ord
        FROM public.aimos_cognitive_weight_projections p
       WHERE p.memory_id = p_memory_id
         AND p.company_id = v_company_id
         AND p.prev_projection_hash IS NULL
      UNION ALL
      SELECT p.company_id, p.projection_hash, p.prev_projection_hash,
             p.provenance_mutation_hash, p.old_weight_milli, p.new_weight_milli,
             p.transition_hash, p.transition_sig, w.ord + 1
        FROM public.aimos_cognitive_weight_projections p
        JOIN walk w ON p.memory_id = p_memory_id
                   AND p.company_id = v_company_id
                   AND p.prev_projection_hash = w.projection_hash
    )
    SELECT w.*, pr.event_type, pr.binding_schema_version, pr.agent_id,
           pr.backfilled, pr.body_json, pr.content_hash,
           pr.prev_mutation_hash AS provenance_prev_hash,
           pr.nonce, pr.ts_signed, pr.agent_valid_from
      FROM walk w
      LEFT JOIN public.aimos_memory_provenance pr
        ON pr.memory_id = p_memory_id
       AND pr.mutation_hash = w.provenance_mutation_hash
     ORDER BY w.ord
  LOOP
    v_len := v_len + 1;
    v_body_old_milli := CASE
      WHEN jsonb_typeof(r.body_json->'old_weight') = 'number'
      THEN round((r.body_json->>'old_weight')::double precision * 1000)::int
      ELSE NULL
    END;
    v_body_new_milli := CASE
      WHEN jsonb_typeof(r.body_json->'new_weight') = 'number'
      THEN round((r.body_json->>'new_weight')::double precision * 1000)::int
      ELSE NULL
    END;
    IF r.company_id <> v_company_id
       OR r.event_type <> 'REWEIGHT'
       OR r.binding_schema_version <> 2
       OR r.agent_id <> 'housekeeper'
       OR r.backfilled IS DISTINCT FROM false
       OR r.body_json IS NULL
       OR r.content_hash IS NULL
       OR r.nonce IS NULL
       OR r.ts_signed IS NULL
       OR r.agent_valid_from IS NULL
       OR r.body_json->>'company_id' <> v_company_id
       OR r.body_json->>'memory_id' <> p_memory_id::text
       OR v_body_old_milli IS NULL
       OR v_body_new_milli IS NULL
       OR v_body_old_milli <> r.old_weight_milli
       OR v_body_new_milli <> r.new_weight_milli THEN
      v_break := r.projection_hash; v_reason := 'provenance_binding_invalid'; EXIT;
    END IF;
    IF v_prev_new_milli IS NOT NULL AND r.old_weight_milli <> v_prev_new_milli THEN
      v_break := r.projection_hash; v_reason := 'continuity_break'; EXIT;
    END IF;

    v_provenance := digest(
      r.content_hash
      || COALESCE(r.provenance_prev_hash, ''::bytea)
      || convert_to(r.nonce, 'UTF8')
      || convert_to((r.ts_signed::bigint)::text, 'UTF8'),
      'sha256');
    IF v_provenance <> r.provenance_mutation_hash THEN
      v_break := r.projection_hash; v_reason := 'provenance_hash_invalid'; EXIT;
    END IF;

    v_expected := digest(
      c_chain_prefix || uuid_send(p_memory_id)
      || int8send(r.old_weight_milli::int8) || int8send(r.new_weight_milli::int8)
      || r.provenance_mutation_hash || COALESCE(v_prev_hash, c_zero32),
      'sha256');
    IF v_expected <> r.projection_hash THEN
      v_break := r.projection_hash; v_reason := 'hash_mismatch'; EXIT;
    END IF;

    IF r.transition_sig IS NULL OR octet_length(r.transition_sig) <> 64 THEN
      v_break := r.projection_hash; v_reason := 'signature_missing'; EXIT;
    END IF;
    v_transition := digest(
      c_transition_prefix
      || int4send(octet_length(convert_to(v_company_id, 'UTF8')))
      || convert_to(v_company_id, 'UTF8')
      || uuid_send(p_memory_id)
      || int8send(r.old_weight_milli::int8)
      || int8send(r.new_weight_milli::int8)
      || r.provenance_mutation_hash,
      'sha256');
    IF v_transition <> r.transition_hash THEN
      v_break := r.projection_hash; v_reason := 'transition_hash_invalid'; EXIT;
    END IF;
    v_raw_pub := public.cwc_raw_ed25519_pubkey('housekeeper', r.agent_valid_from);
    IF v_raw_pub IS NULL OR octet_length(v_raw_pub) <> 32
       OR NOT pgsodium.crypto_sign_verify_detached(r.transition_sig, v_transition, v_raw_pub) THEN
      v_break := r.projection_hash; v_reason := 'signature_invalid'; EXIT;
    END IF;
    v_sigs := v_sigs + 1;
    v_prev_hash := r.projection_hash;
    v_prev_new_milli := r.new_weight_milli;
    v_terminal_milli := r.new_weight_milli;
  END LOOP;

  IF v_break IS NULL AND v_len <> v_total THEN
    v_break := c_zero32; v_reason := 'unreachable_rows';
  END IF;
  IF v_break IS NULL AND v_terminal_milli IS NOT NULL
     AND round(v_live::double precision * 1000)::int <> v_terminal_milli THEN
    v_break := c_zero32; v_reason := 'terminal_weight_mismatch';
  END IF;

  ok := (v_break IS NULL);
  chain_length := v_len;
  terminal_weight := v_live;
  sigs_verified := v_sigs;
  break_at := v_break;
  reason := v_reason;
  RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION public.verify_all_cognitive_weight_chains()
RETURNS TABLE(memory_id uuid, ok boolean, chain_length integer,
              sigs_verified integer, break_at bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  m uuid;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;
  FOR m IN
    SELECT DISTINCT p.memory_id
      FROM public.aimos_cognitive_weight_projections p
     WHERE p.company_id = v_company_id
  LOOP
    RETURN QUERY
      SELECT m, v.ok, v.chain_length, v.sigs_verified, v.break_at, v.reason
        FROM public.verify_cognitive_weight_chain(m) v;
  END LOOP;
END
$function$;

REVOKE ALL ON FUNCTION public.apply_signed_cognitive_reweight(
  uuid, double precision, double precision, bytea, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.verify_cognitive_weight_chain(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.verify_all_cognitive_weight_chains() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.cwc_raw_ed25519_pubkey(text, timestamptz) FROM PUBLIC;

DO $cwc_v2_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    -- Migration 080 granted INSERT so the SECURITY DEFINER function could
    -- append. That grant was unnecessary: the function executes as its owner
    -- and direct INSERT lets the runtime forge/consume retained projections.
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE
      ON public.aimos_cognitive_weight_projections FROM agent_runtime;
    GRANT EXECUTE ON FUNCTION public.apply_signed_cognitive_reweight(
      uuid, double precision, double precision, bytea, bytea
    ) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.verify_cognitive_weight_chain(uuid) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.verify_all_cognitive_weight_chains() TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE ALL ON FUNCTION public.apply_signed_cognitive_reweight(
      uuid, double precision, double precision, bytea, bytea
    ) FROM aimos_app;
    REVOKE ALL ON FUNCTION public.verify_cognitive_weight_chain(uuid) FROM aimos_app;
    REVOKE ALL ON FUNCTION public.verify_all_cognitive_weight_chains() FROM aimos_app;
    REVOKE ALL ON FUNCTION public.cwc_raw_ed25519_pubkey(text, timestamptz) FROM aimos_app;
  END IF;
END
$cwc_v2_acl$;

COMMENT ON COLUMN public.aimos_cognitive_weight_projections.transition_hash IS
  'SHA-256 of domain || company-length || company || memory UUID || old/new integer millis || provenance mutation hash.';
COMMENT ON COLUMN public.aimos_cognitive_weight_projections.transition_sig IS
  'Housekeeper Ed25519 signature over transition_hash; binds the exact certified projection rather than an unrelated provenance body.';
