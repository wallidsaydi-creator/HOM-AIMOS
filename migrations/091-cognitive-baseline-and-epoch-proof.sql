-- Certified cognitive trajectory v3 correction.
--
-- Historical non-default retrieval weights predate the certified transition
-- chain. They are retained as observed state, not rewritten or represented as
-- fabricated REWEIGHT history. This migration adds one honest signed baseline
-- per such memory, requires exact active signer epochs, derives display weights
-- from integer millis, and makes corpus verification enumerate every memory.

CREATE TABLE IF NOT EXISTS public.aimos_cognitive_weight_baselines (
  baseline_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id text NOT NULL,
  memory_id uuid NOT NULL UNIQUE,
  event_id uuid NOT NULL UNIQUE,
  event_mutation_hash bytea NOT NULL CHECK (octet_length(event_mutation_hash) = 32),
  observed_weight real NOT NULL CHECK (observed_weight BETWEEN 0.1 AND 3.0),
  observed_weight_float4 bytea NOT NULL CHECK (octet_length(observed_weight_float4) = 4),
  retrieval_weight_milli integer NOT NULL
    CHECK (retrieval_weight_milli BETWEEN 100 AND 3000),
  live_content_hash bytea NOT NULL CHECK (octet_length(live_content_hash) = 32),
  observed_ts bigint NOT NULL CHECK (observed_ts > 0),
  attestation_reason text NOT NULL
    CHECK (attestation_reason = 'retained_nondefault_weight_baseline'),
  historical_origin_claimed boolean NOT NULL DEFAULT false
    CHECK (historical_origin_claimed = false),
  signer_agent_id text NOT NULL CHECK (signer_agent_id = 'housekeeper'),
  signer_valid_from timestamptz NOT NULL,
  cert_fingerprint text NOT NULL CHECK (cert_fingerprint ~ '^[0-9a-f]{64}$'),
  baseline_hash bytea NOT NULL UNIQUE CHECK (octet_length(baseline_hash) = 32),
  baseline_sig bytea NOT NULL CHECK (octet_length(baseline_sig) = 64),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (memory_id) REFERENCES public.aimos_memories(id) ON DELETE RESTRICT,
  FOREIGN KEY (event_id) REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  FOREIGN KEY (signer_agent_id, signer_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from) ON DELETE RESTRICT
);

ALTER TABLE public.aimos_cognitive_weight_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_cognitive_weight_baselines FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aimos_cognitive_weight_baseline_company_isolation
  ON public.aimos_cognitive_weight_baselines;
CREATE POLICY aimos_cognitive_weight_baseline_company_isolation
  ON public.aimos_cognitive_weight_baselines
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

CREATE OR REPLACE FUNCTION public.cognitive_weight_baseline_hash(
  p_company_id text,
  p_memory_id uuid,
  p_event_id uuid,
  p_event_mutation_hash bytea,
  p_live_content_hash bytea,
  p_observed_weight real,
  p_weight_milli integer,
  p_observed_ts bigint,
  p_signer_valid_from timestamptz,
  p_cert_fingerprint bytea
) RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $function$
  SELECT digest(
    '\x61696d6f732e636f676e69746976652d626173656c696e652f763100'::bytea
    || int4send(octet_length(convert_to(p_company_id, 'UTF8')))
    || convert_to(p_company_id, 'UTF8')
    || uuid_send(p_memory_id)
    || uuid_send(p_event_id)
    || p_event_mutation_hash
    || p_live_content_hash
    || float4send(p_observed_weight)
    || int8send(p_weight_milli::bigint)
    || int8send(p_observed_ts)
    || int8send(extract(epoch FROM p_signer_valid_from)::bigint)
    || p_cert_fingerprint,
    'sha256'
  );
$function$;

-- Epoch lookup is exact. Migration 084's NULL-means-latest behavior is retired.
CREATE OR REPLACE FUNCTION public.cwc_raw_ed25519_pubkey(
  p_agent_id text,
  p_valid_from timestamptz
) RETURNS bytea
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT substring(
           decode(
             rpad(translate(i.pubkey, '-_', '+/'),
                  (length(translate(i.pubkey, '-_', '+/')) + 3) / 4 * 4, '='),
             'base64')
           FROM 13 FOR 32)
    FROM public.agent_identity i
   WHERE p_valid_from IS NOT NULL
     AND i.agent_id = p_agent_id
     AND i.valid_from = p_valid_from
   LIMIT 1;
$function$;

CREATE OR REPLACE FUNCTION public.verify_cognitive_weight_baseline(p_memory_id uuid)
RETURNS TABLE(ok boolean, weight_milli integer, baseline_hash bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  r record;
  v_expected bytea;
  v_raw_pub bytea;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;

  SELECT b.*, m.content_hash AS current_content_hash,
         e.operation AS event_operation, e.key AS event_key,
         e.signer_agent_id AS event_signer_agent_id,
         e.signer_valid_from AS event_signer_valid_from,
         e.mutation_hash AS stored_event_mutation_hash,
         e.ts_signed AS event_ts_signed,
         e.metadata AS event_metadata, e.proof_required AS event_proof_required,
         encode(digest(i.cert, 'sha256'), 'hex') AS identity_cert_fingerprint,
         i.valid_until, rev.ts_signed AS revocation_ts_signed
    INTO r
    FROM public.aimos_cognitive_weight_baselines b
    JOIN public.aimos_memories m
      ON m.id = b.memory_id AND m.company_id = b.company_id
    JOIN public.agent_identity i
      ON i.agent_id = b.signer_agent_id
     AND i.valid_from = b.signer_valid_from
    JOIN public.aimos_events e
      ON e.id = b.event_id AND e.company_id = b.company_id
    LEFT JOIN public.aimos_agent_revocation_events rev
      ON rev.agent_id = i.agent_id
     AND rev.agent_valid_from = i.valid_from
   WHERE b.company_id = v_company_id
     AND b.memory_id = p_memory_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, NULL::integer, NULL::bytea, 'baseline_missing'::text;
    RETURN;
  END IF;
  IF r.attestation_reason <> 'retained_nondefault_weight_baseline'
     OR r.historical_origin_claimed IS DISTINCT FROM false
     OR r.observed_weight_float4 <> float4send(r.observed_weight)
     OR float4send(r.observed_weight) = float4send(1.0::real)
     OR round(r.observed_weight::double precision * 1000)::integer
          <> r.retrieval_weight_milli
     OR r.live_content_hash IS DISTINCT FROM r.current_content_hash
     OR r.event_operation IS DISTINCT FROM 'cognitive_initial_weight_attested'
     OR r.event_key IS DISTINCT FROM r.memory_id::text
     OR r.event_signer_agent_id IS DISTINCT FROM r.signer_agent_id
     OR r.event_signer_valid_from IS DISTINCT FROM r.signer_valid_from
     OR r.stored_event_mutation_hash IS DISTINCT FROM r.event_mutation_hash
     OR r.event_proof_required IS DISTINCT FROM true
     OR r.event_metadata->>'schema' IS DISTINCT FROM 'hom.aimos.cognitive-initial-weight/v1'
     OR r.event_metadata->>'observed_weight_float4' IS DISTINCT FROM encode(r.observed_weight_float4, 'hex')
     OR r.event_metadata->>'weight_milli' IS DISTINCT FROM r.retrieval_weight_milli::text
     OR r.event_metadata->>'observed_ts' IS DISTINCT FROM r.observed_ts::text
     OR r.event_metadata->>'memory_content_hash' IS DISTINCT FROM encode(r.live_content_hash, 'hex')
     OR r.event_metadata->>'historical_origin_claimed' IS DISTINCT FROM 'false'
     OR r.event_metadata->>'canonical_memory_mutation' IS DISTINCT FROM 'false'
     OR r.event_ts_signed IS NULL
     OR abs(r.event_ts_signed - r.observed_ts) > 5
     OR r.identity_cert_fingerprint IS DISTINCT FROM r.cert_fingerprint
     OR to_timestamp(r.observed_ts) < r.signer_valid_from
     OR to_timestamp(r.observed_ts) >= r.valid_until
     OR (r.revocation_ts_signed IS NOT NULL AND r.revocation_ts_signed <= r.observed_ts) THEN
    RETURN QUERY SELECT false, r.retrieval_weight_milli, r.baseline_hash,
                        'baseline_identity_or_content_invalid'::text;
    RETURN;
  END IF;
  v_expected := public.cognitive_weight_baseline_hash(
    r.company_id, r.memory_id, r.event_id, r.event_mutation_hash,
    r.live_content_hash, r.observed_weight, r.retrieval_weight_milli,
    r.observed_ts, r.signer_valid_from, decode(r.cert_fingerprint, 'hex')
  );
  v_raw_pub := public.cwc_raw_ed25519_pubkey(r.signer_agent_id, r.signer_valid_from);
  IF v_expected IS DISTINCT FROM r.baseline_hash THEN
    RETURN QUERY SELECT false, r.retrieval_weight_milli, r.baseline_hash,
                        'baseline_hash_invalid'::text;
    RETURN;
  END IF;
  IF v_raw_pub IS NULL OR octet_length(v_raw_pub) <> 32
     OR NOT pgsodium.crypto_sign_verify_detached(r.baseline_sig, v_expected, v_raw_pub) THEN
    RETURN QUERY SELECT false, r.retrieval_weight_milli, r.baseline_hash,
                        'baseline_signature_invalid'::text;
    RETURN;
  END IF;
  RETURN QUERY SELECT true, r.retrieval_weight_milli, r.baseline_hash, NULL::text;
END
$function$;

CREATE OR REPLACE FUNCTION public.commit_cognitive_weight_baseline(
  p_memory_id uuid,
  p_event_id uuid,
  p_event_mutation_hash bytea,
  p_live_content_hash bytea,
  p_observed_weight real,
  p_weight_milli integer,
  p_observed_ts bigint,
  p_signer_valid_from timestamptz,
  p_cert_fingerprint text,
  p_baseline_sig bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  v_live_weight real;
  v_stored_content_hash bytea;
  v_valid_until timestamptz;
  v_revocation_ts bigint;
  v_hash bytea;
  v_raw_pub bytea;
  v_identity_cert_fingerprint text;
  v_event record;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;
  IF current_setting('app.current_agent_id', true) <> 'housekeeper' THEN
    RAISE EXCEPTION 'cognitive_housekeeper_scope_required';
  END IF;
  IF p_memory_id IS NULL OR p_event_id IS NULL
     OR p_event_mutation_hash IS NULL OR octet_length(p_event_mutation_hash) <> 32
     OR p_live_content_hash IS NULL
     OR octet_length(p_live_content_hash) <> 32
     OR p_observed_weight IS NULL OR p_observed_weight < 0.1 OR p_observed_weight > 3.0
     OR round(p_observed_weight::double precision * 1000)::integer <> p_weight_milli
     OR p_weight_milli < 100 OR p_weight_milli > 3000
     OR p_observed_ts <= 0 OR p_signer_valid_from IS NULL
     OR p_cert_fingerprint IS NULL
     OR p_cert_fingerprint !~ '^[0-9a-f]{64}$'
     OR p_baseline_sig IS NULL OR octet_length(p_baseline_sig) <> 64 THEN
    RAISE EXCEPTION 'cognitive_baseline_input_invalid';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    'cognitive-reweight:' || v_company_id || ':' || p_memory_id::text, 0
  ));
  SELECT m.retrieval_weight, m.content_hash
    INTO v_live_weight, v_stored_content_hash
    FROM public.aimos_memories m
   WHERE m.id = p_memory_id AND m.company_id = v_company_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'cognitive_memory_not_found'; END IF;
  IF float4send(v_live_weight) <> float4send(p_observed_weight)
     OR round(v_live_weight::double precision * 1000)::integer <> p_weight_milli
     OR v_stored_content_hash IS DISTINCT FROM p_live_content_hash THEN
    RAISE EXCEPTION 'cognitive_baseline_live_state_mismatch';
  END IF;
  IF float4send(v_live_weight) = float4send(1.0::real) THEN
    RAISE EXCEPTION 'cognitive_default_weight_baseline_forbidden';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.aimos_cognitive_weight_projections
     WHERE company_id = v_company_id AND memory_id = p_memory_id
  ) THEN
    RAISE EXCEPTION 'cognitive_baseline_after_transition_forbidden';
  END IF;

  SELECT i.valid_until, rev.ts_signed, encode(digest(i.cert, 'sha256'), 'hex')
    INTO v_valid_until, v_revocation_ts, v_identity_cert_fingerprint
    FROM public.agent_identity i
    LEFT JOIN public.aimos_agent_revocation_events rev
      ON rev.agent_id = i.agent_id AND rev.agent_valid_from = i.valid_from
   WHERE i.agent_id = 'housekeeper' AND i.valid_from = p_signer_valid_from
   FOR UPDATE OF i;
  IF NOT FOUND
     OR to_timestamp(p_observed_ts) < p_signer_valid_from
     OR to_timestamp(p_observed_ts) >= v_valid_until
     OR clock_timestamp() < p_signer_valid_from
     OR clock_timestamp() >= v_valid_until
     OR v_revocation_ts IS NOT NULL THEN
    RAISE EXCEPTION 'cognitive_baseline_signer_epoch_invalid';
  END IF;
  IF v_identity_cert_fingerprint IS DISTINCT FROM p_cert_fingerprint THEN
    RAISE EXCEPTION 'cognitive_baseline_cert_fingerprint_invalid';
  END IF;

  SELECT e.operation, e.key, e.signer_agent_id, e.signer_valid_from,
         e.mutation_hash, e.metadata, e.proof_required, e.ts_signed
    INTO v_event
    FROM public.aimos_events e
   WHERE e.id = p_event_id AND e.company_id = v_company_id;
  IF NOT FOUND OR v_event.operation IS DISTINCT FROM 'cognitive_initial_weight_attested'
     OR v_event.key IS DISTINCT FROM p_memory_id::text
     OR v_event.signer_agent_id IS DISTINCT FROM 'housekeeper'
     OR v_event.signer_valid_from IS DISTINCT FROM p_signer_valid_from
     OR v_event.mutation_hash IS DISTINCT FROM p_event_mutation_hash
     OR v_event.proof_required IS DISTINCT FROM true
     OR v_event.metadata->>'schema' IS DISTINCT FROM 'hom.aimos.cognitive-initial-weight/v1'
     OR v_event.metadata->>'observed_weight_float4' IS DISTINCT FROM encode(float4send(p_observed_weight), 'hex')
     OR v_event.metadata->>'weight_milli' IS DISTINCT FROM p_weight_milli::text
     OR v_event.metadata->>'observed_ts' IS DISTINCT FROM p_observed_ts::text
     OR v_event.metadata->>'memory_content_hash' IS DISTINCT FROM encode(p_live_content_hash, 'hex')
     OR v_event.metadata->>'historical_origin_claimed' IS DISTINCT FROM 'false'
     OR v_event.metadata->>'canonical_memory_mutation' IS DISTINCT FROM 'false'
     OR v_event.ts_signed IS NULL
     OR abs(v_event.ts_signed - p_observed_ts) > 5 THEN
    RAISE EXCEPTION 'cognitive_baseline_event_invalid';
  END IF;

  v_hash := public.cognitive_weight_baseline_hash(
    v_company_id, p_memory_id, p_event_id, p_event_mutation_hash,
    p_live_content_hash, p_observed_weight, p_weight_milli,
    p_observed_ts, p_signer_valid_from, decode(p_cert_fingerprint, 'hex')
  );
  v_raw_pub := public.cwc_raw_ed25519_pubkey('housekeeper', p_signer_valid_from);
  IF v_raw_pub IS NULL OR octet_length(v_raw_pub) <> 32
     OR NOT pgsodium.crypto_sign_verify_detached(p_baseline_sig, v_hash, v_raw_pub) THEN
    RAISE EXCEPTION 'cognitive_baseline_signature_invalid';
  END IF;

  INSERT INTO public.aimos_cognitive_weight_baselines
    (company_id, memory_id, event_id, event_mutation_hash,
     observed_weight, observed_weight_float4, retrieval_weight_milli, live_content_hash,
     observed_ts, attestation_reason, historical_origin_claimed,
     signer_agent_id, signer_valid_from, cert_fingerprint, baseline_hash, baseline_sig)
  VALUES
    (v_company_id, p_memory_id, p_event_id, p_event_mutation_hash,
     p_observed_weight, float4send(p_observed_weight), p_weight_milli, p_live_content_hash,
     p_observed_ts, 'retained_nondefault_weight_baseline', false,
     'housekeeper', p_signer_valid_from, p_cert_fingerprint, v_hash, p_baseline_sig)
  ON CONFLICT (memory_id) DO NOTHING;

  IF NOT EXISTS (
    SELECT 1 FROM public.aimos_cognitive_weight_baselines b
     WHERE b.company_id = v_company_id
       AND b.memory_id = p_memory_id
       AND b.event_id = p_event_id
       AND b.event_mutation_hash = p_event_mutation_hash
       AND float4send(b.observed_weight) = float4send(p_observed_weight)
       AND b.retrieval_weight_milli = p_weight_milli
       AND b.live_content_hash = p_live_content_hash
       AND b.observed_ts = p_observed_ts
       AND b.signer_valid_from = p_signer_valid_from
       AND b.cert_fingerprint = p_cert_fingerprint
       AND b.baseline_hash = v_hash
       AND b.baseline_sig = p_baseline_sig
  ) THEN
    RAISE EXCEPTION 'cognitive_baseline_conflict';
  END IF;

  RETURN v_hash;
END
$function$;

ALTER TABLE public.aimos_cognitive_weight_projections
  ADD CONSTRAINT aimos_cwc_old_display_derived
  CHECK (float4send(old_weight) = float4send((old_weight_milli::double precision / 1000.0)::real));
ALTER TABLE public.aimos_cognitive_weight_projections
  ADD CONSTRAINT aimos_cwc_new_display_derived
  CHECK (float4send(new_weight) = float4send((new_weight_milli::double precision / 1000.0)::real));

-- Replace the writer with exact signer-epoch and baseline checks. The signature
-- is unchanged; no compatibility overload or parallel writer is introduced.
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

-- The per-memory verifier from 085 remains the transition verifier. This
-- forward definition adds honest empty-chain/baseline handling and signer epoch
-- checks without changing its public result shape.
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

DROP FUNCTION public.verify_all_cognitive_weight_chains();
CREATE FUNCTION public.verify_all_cognitive_weight_chains()
RETURNS TABLE(memory_id uuid, ok boolean, chain_length integer,
              sigs_verified integer, certification_status text,
              break_at bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  m record;
BEGIN
  v_company_id:=current_setting('app.current_client_id',true);
  IF v_company_id IS NULL OR v_company_id='' THEN RAISE EXCEPTION 'cognitive_company_scope_required'; END IF;
  FOR m IN
    SELECT mem.id,
           EXISTS(SELECT 1 FROM public.aimos_cognitive_weight_projections p WHERE p.company_id=mem.company_id AND p.memory_id=mem.id) AS has_chain,
           EXISTS(SELECT 1 FROM public.aimos_cognitive_weight_baselines b WHERE b.company_id=mem.company_id AND b.memory_id=mem.id) AS has_baseline
      FROM public.aimos_memories mem
     WHERE mem.company_id=v_company_id
     ORDER BY mem.id
  LOOP
    RETURN QUERY
      SELECT m.id,v.ok,v.chain_length,v.sigs_verified,
             CASE WHEN m.has_chain THEN 'certified_chain'
                  WHEN m.has_baseline THEN 'signed_initial_weight'
                  WHEN v.ok THEN 'default_empty_chain'
                  ELSE 'unattested_initial_weight' END,
             v.break_at,v.reason
        FROM public.verify_cognitive_weight_chain(m.id) v;
  END LOOP;
END
$function$;

REVOKE ALL ON public.aimos_cognitive_weight_baselines FROM PUBLIC;
REVOKE ALL ON FUNCTION public.cognitive_weight_baseline_hash(text,uuid,uuid,bytea,bytea,real,integer,bigint,timestamptz,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.commit_cognitive_weight_baseline(uuid,uuid,bytea,bytea,real,integer,bigint,timestamptz,text,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.verify_cognitive_weight_baseline(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.apply_signed_cognitive_reweight(uuid,double precision,double precision,bytea,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.verify_cognitive_weight_chain(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.verify_all_cognitive_weight_chains() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.cwc_raw_ed25519_pubkey(text,timestamptz) FROM PUBLIC;

DO $cwc_v3_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_runtime') THEN
    REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON public.aimos_cognitive_weight_baselines FROM agent_runtime;
    GRANT SELECT ON public.aimos_cognitive_weight_baselines TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.cognitive_weight_baseline_hash(text,uuid,uuid,bytea,bytea,real,integer,bigint,timestamptz,bytea) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.commit_cognitive_weight_baseline(uuid,uuid,bytea,bytea,real,integer,bigint,timestamptz,text,bytea) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.verify_cognitive_weight_baseline(uuid) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.apply_signed_cognitive_reweight(uuid,double precision,double precision,bytea,bytea) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.verify_cognitive_weight_chain(uuid) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.verify_all_cognitive_weight_chains() TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='aimos_app') THEN
    REVOKE ALL ON public.aimos_cognitive_weight_baselines FROM aimos_app;
    REVOKE ALL ON FUNCTION public.commit_cognitive_weight_baseline(uuid,uuid,bytea,bytea,real,integer,bigint,timestamptz,text,bytea) FROM aimos_app;
    REVOKE ALL ON FUNCTION public.verify_cognitive_weight_baseline(uuid) FROM aimos_app;
    REVOKE ALL ON FUNCTION public.verify_all_cognitive_weight_chains() FROM aimos_app;
  END IF;
END
$cwc_v3_acl$;

COMMENT ON TABLE public.aimos_cognitive_weight_baselines IS
  'One append-only housekeeper-signed observation of a retained pre-chain non-default weight. It proves state at observation time and never claims original REWEIGHT history.';
COMMENT ON FUNCTION public.verify_all_cognitive_weight_chains() IS
  'Enumerates every memory in the current company and distinguishes certified chains, default empty chains, signed retained baselines, and unattested non-default initial states.';
