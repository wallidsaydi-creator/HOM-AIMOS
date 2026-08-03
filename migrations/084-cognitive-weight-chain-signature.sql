-- 084-cognitive-weight-chain-signature.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Option 3 — Certified Cognitive-Weight Trajectory, Phase 3b (Layer 2, in-DB
-- Ed25519). Normative spec: docs/security/cognitive-weight-chain-SPEC.md §7, §11.
--
-- Makes the SIGNATURE layer verifiable in pure SQL. The housekeeper signs the
-- 32-byte content_hash of each REWEIGHT node (a SQL-reconstructible value — no
-- fragile JSON-canonicalization), and pgsodium verifies it IN the database:
--   pgsodium.crypto_sign_verify_detached(content_hash_sig, content_hash, raw_pubkey)
-- Proven: AIMOS's base64url-DER-SPKI pubkey → raw 32 bytes in SQL, and a Node
-- Ed25519 detached signature over a 32-byte hash verifies `t` in-DB.
--
-- PREREQUISITE: pgsodium extension (build via scripts/db/build-pgsodium.sh, then
-- CREATE EXTENSION). This migration fails loudly if pgsodium is absent — signature
-- verification is not silently skipped.
--
-- The unsigned 4-arg reweight is DROPPED so no caller can bypass signing.

CREATE EXTENSION IF NOT EXISTS pgsodium;

-- pgsodium installs a ddl_command_end event trigger for its column-masking KMS
-- feature — which we do NOT use (only crypto_sign_verify_detached). Left enabled,
-- it aborts every subsequent DDL statement referencing the GUC
-- `pgsodium.enable_event_trigger`, which only exists when pgsodium is in
-- shared_preload_libraries (the heavyweight setup we intentionally avoid).
-- Disable it here, before this migration's own DDL. Verify functions are
-- unaffected. Must run immediately after CREATE EXTENSION.
DO $cwc_sodium_trg$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'pgsodium_trg_mask_update') THEN
    ALTER EVENT TRIGGER pgsodium_trg_mask_update DISABLE;
  END IF;
END
$cwc_sodium_trg$;

-- ─── 1. store the housekeeper's detached signature over content_hash ──────────
ALTER TABLE public.aimos_cognitive_weight_projections
  ADD COLUMN IF NOT EXISTS content_hash_sig bytea;   -- NULL only on pre-084 legacy rows

-- ─── 2. raw 32-byte Ed25519 pubkey for an identity epoch. agent_identity stores
--        base64url(DER SPKI); the raw key is the last 32 of the 44 DER bytes. ──
CREATE OR REPLACE FUNCTION public.cwc_raw_ed25519_pubkey(p_agent_id text, p_valid_from timestamptz)
RETURNS bytea
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
   WHERE i.agent_id = p_agent_id
     AND (p_valid_from IS NULL OR i.valid_from = p_valid_from)
   ORDER BY i.valid_from DESC
   LIMIT 1;
$function$;

-- ─── 3. reweight: same as 082 + verify the content-hash signature in-DB and
--        store it. New 5-arg signature; the unsigned 4-arg form is dropped. ────
DROP FUNCTION IF EXISTS public.apply_signed_cognitive_reweight(uuid, double precision, double precision, bytea);

CREATE FUNCTION public.apply_signed_cognitive_reweight(
  p_memory_id uuid,
  p_old_weight double precision,
  p_new_weight double precision,
  p_provenance_mutation_hash bytea,
  p_content_sig bytea
) RETURNS real
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id    text;
  v_current_weight real;
  v_current_milli int;
  v_old_milli     int;
  v_new_milli     int;
  v_body          jsonb;
  v_content_hash  bytea;
  v_agent_vf      timestamptz;
  v_raw_pub       bytea;
  v_prev_hash     bytea;
  v_head_milli    int;
  v_proj_hash     bytea;
  v_applied       real;
  c_prefix        bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_zero32        bytea := decode(repeat('00', 32), 'hex');
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;
  IF current_setting('app.current_agent_id', true) <> 'housekeeper' THEN
    RAISE EXCEPTION 'cognitive_housekeeper_scope_required';
  END IF;

  IF p_old_weight < 0.1 OR p_old_weight > 3.0
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

  SELECT m.retrieval_weight INTO v_current_weight
    FROM public.aimos_memories m
   WHERE m.id = p_memory_id AND m.company_id = v_company_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cognitive_memory_not_found';
  END IF;

  -- terminal signed REWEIGHT node; capture content_hash + epoch for the sig check
  SELECT p.body_json, p.content_hash, p.agent_valid_from
    INTO v_body, v_content_hash, v_agent_vf
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
  IF v_body->>'event_type' <> 'REWEIGHT'
     OR v_body->>'memory_id' <> p_memory_id::text
     OR abs((v_body->>'old_weight')::double precision - p_old_weight) > 0.000001
     OR abs((v_body->>'new_weight')::double precision - p_new_weight) > 0.000001 THEN
    RAISE EXCEPTION 'signed_cognitive_transition_mismatch';
  END IF;

  -- ── verify the housekeeper's Ed25519 signature over content_hash IN-DB ─────
  IF octet_length(p_content_sig) <> 64 THEN
    RAISE EXCEPTION 'cognitive_content_sig_malformed';
  END IF;
  v_raw_pub := public.cwc_raw_ed25519_pubkey('housekeeper', v_agent_vf);
  IF v_raw_pub IS NULL OR octet_length(v_raw_pub) <> 32 THEN
    RAISE EXCEPTION 'cognitive_housekeeper_pubkey_unavailable';
  END IF;
  IF NOT pgsodium.crypto_sign_verify_detached(p_content_sig, v_content_hash, v_raw_pub) THEN
    RAISE EXCEPTION 'cognitive_content_sig_invalid';
  END IF;

  SELECT h.projection_hash, h.new_weight_milli INTO v_prev_hash, v_head_milli
    FROM public.aimos_cognitive_weight_projections h
   WHERE h.memory_id = p_memory_id
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_cognitive_weight_projections c
        WHERE c.memory_id = h.memory_id AND c.prev_projection_hash = h.projection_hash);

  IF v_prev_hash IS NULL THEN
    v_current_milli := round(v_current_weight::double precision * 1000)::int;
    IF v_old_milli <> v_current_milli THEN RAISE EXCEPTION 'cognitive_old_weight_mismatch'; END IF;
  ELSE
    IF v_old_milli <> v_head_milli THEN RAISE EXCEPTION 'cognitive_chain_discontinuity'; END IF;
  END IF;

  v_proj_hash := digest(
    c_prefix || uuid_send(p_memory_id)
    || int8send(v_old_milli::int8) || int8send(v_new_milli::int8)
    || p_provenance_mutation_hash || COALESCE(v_prev_hash, c_zero32),
    'sha256');

  INSERT INTO public.aimos_cognitive_weight_projections
    (company_id, memory_id, provenance_mutation_hash,
     old_weight, new_weight, old_weight_milli, new_weight_milli,
     prev_projection_hash, projection_hash, content_hash_sig)
  VALUES
    (v_company_id, p_memory_id, p_provenance_mutation_hash,
     p_old_weight, p_new_weight, v_old_milli, v_new_milli,
     v_prev_hash, v_proj_hash, p_content_sig);

  UPDATE public.aimos_memories
     SET retrieval_weight = (v_new_milli / 1000.0)::real
   WHERE id = p_memory_id AND company_id = v_company_id
  RETURNING retrieval_weight INTO v_applied;
  RETURN v_applied;
END
$function$;

COMMENT ON FUNCTION public.apply_signed_cognitive_reweight(uuid, double precision, double precision, bytea, bytea) IS
  'Sole writer of retrieval_weight. Verifies the housekeeper Ed25519 signature over content_hash IN-DB (pgsodium), appends a tamper-evident hash-chain link (SPEC §7.1). Bidirectional; exact-integer continuity.';

-- ─── 4. verifier: recompute the hash chain AND re-verify each Ed25519 signature
--        in pure SQL (SPEC §7.2/§11). Both layers, one call, any moment. ──────
DROP FUNCTION IF EXISTS public.verify_cognitive_weight_chain(uuid);
CREATE FUNCTION public.verify_cognitive_weight_chain(p_memory_id uuid)
RETURNS TABLE(ok boolean, chain_length integer, terminal_weight real,
              sigs_verified integer, break_at bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_prefix         bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_zero32         bytea := decode(repeat('00', 32), 'hex');
  r                record;
  v_prev_hash      bytea := NULL;
  v_prev_new_milli int   := NULL;
  v_expected       bytea;
  v_len            integer := 0;
  v_sigs           integer := 0;
  v_total          integer;
  v_break          bytea := NULL;
  v_reason         text  := NULL;
  v_terminal_milli integer := NULL;
  v_live           real;
  v_raw_pub        bytea;
BEGIN
  SELECT count(*) INTO v_total
    FROM public.aimos_cognitive_weight_projections WHERE memory_id = p_memory_id;

  FOR r IN
    WITH RECURSIVE walk AS (
      SELECT p.projection_hash, p.prev_projection_hash, p.provenance_mutation_hash,
             p.old_weight_milli, p.new_weight_milli, p.content_hash_sig, 1 AS ord
        FROM public.aimos_cognitive_weight_projections p
       WHERE p.memory_id = p_memory_id AND p.prev_projection_hash IS NULL
      UNION ALL
      SELECT p.projection_hash, p.prev_projection_hash, p.provenance_mutation_hash,
             p.old_weight_milli, p.new_weight_milli, p.content_hash_sig, w.ord + 1
        FROM public.aimos_cognitive_weight_projections p
        JOIN walk w ON p.memory_id = p_memory_id
                   AND p.prev_projection_hash = w.projection_hash
    )
    SELECT w.*, pr.content_hash, pr.agent_valid_from
      FROM walk w
      LEFT JOIN public.aimos_memory_provenance pr
        ON pr.memory_id = p_memory_id AND pr.mutation_hash = w.provenance_mutation_hash
     ORDER BY w.ord
  LOOP
    v_len := v_len + 1;
    IF v_prev_new_milli IS NOT NULL AND r.old_weight_milli <> v_prev_new_milli THEN
      v_break := r.projection_hash; v_reason := 'continuity_break'; EXIT;
    END IF;
    v_expected := digest(
      c_prefix || uuid_send(p_memory_id)
      || int8send(r.old_weight_milli::int8) || int8send(r.new_weight_milli::int8)
      || r.provenance_mutation_hash || COALESCE(v_prev_hash, c_zero32),
      'sha256');
    IF v_expected <> r.projection_hash THEN
      v_break := r.projection_hash; v_reason := 'hash_mismatch'; EXIT;
    END IF;
    -- Layer 2: verify the housekeeper Ed25519 signature over content_hash
    IF r.content_hash_sig IS NOT NULL THEN
      v_raw_pub := public.cwc_raw_ed25519_pubkey('housekeeper', r.agent_valid_from);
      IF r.content_hash IS NULL OR v_raw_pub IS NULL
         OR NOT pgsodium.crypto_sign_verify_detached(r.content_hash_sig, r.content_hash, v_raw_pub) THEN
        v_break := r.projection_hash; v_reason := 'signature_invalid'; EXIT;
      END IF;
      v_sigs := v_sigs + 1;
    END IF;
    v_prev_hash := r.projection_hash;
    v_prev_new_milli := r.new_weight_milli;
    v_terminal_milli := r.new_weight_milli;
  END LOOP;

  IF v_break IS NULL AND v_len <> v_total THEN
    v_break := c_zero32; v_reason := 'unreachable_rows';
  END IF;

  SELECT retrieval_weight INTO v_live FROM public.aimos_memories WHERE id = p_memory_id;
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

DROP FUNCTION IF EXISTS public.verify_all_cognitive_weight_chains();
CREATE FUNCTION public.verify_all_cognitive_weight_chains()
RETURNS TABLE(memory_id uuid, ok boolean, chain_length integer, sigs_verified integer, break_at bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE m uuid;
BEGIN
  FOR m IN SELECT DISTINCT p.memory_id FROM public.aimos_cognitive_weight_projections p LOOP
    RETURN QUERY
      SELECT m, v.ok, v.chain_length, v.sigs_verified, v.break_at, v.reason
        FROM public.verify_cognitive_weight_chain(m) v;
  END LOOP;
END
$function$;
