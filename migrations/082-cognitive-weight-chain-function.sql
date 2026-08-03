-- 082-cognitive-weight-chain-function.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Option 3 — Certified Cognitive-Weight Trajectory, Phase 2 (the sole writer).
-- Normative spec: docs/security/cognitive-weight-chain-SPEC.md §7.1.
--
-- Supersedes migration 080's apply_signed_cognitive_reweight (CREATE OR REPLACE,
-- SAME double-precision signature so existing callers are unchanged). Adds the
-- tamper-evident HASH CHAIN and switches continuity from a float epsilon to EXACT
-- INTEGER millis. Still no monotone check — weight is bidirectional (good→bad→good).
--
-- The function is the SOLE writer of retrieval_weight and the SOLE inserter of a
-- projection row; it derives prev_hash from the DB head and computes projection_hash
-- in-DB via pgcrypto, so NO caller can forge the chain linkage.
--
-- Quantization authority lives here: the signed body binds the double weights (the
-- signature is unchanged), and the chain hashes the derived integer millis
-- q = round(w*1000) ∈ [100,3000] (SPEC §9 — you cannot hash a float).

CREATE OR REPLACE FUNCTION public.apply_signed_cognitive_reweight(
  p_memory_id uuid,
  p_old_weight double precision,
  p_new_weight double precision,
  p_provenance_mutation_hash bytea
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
  v_prev_hash     bytea;      -- NULL ⇒ this transition is genesis
  v_head_milli    int;
  v_proj_hash     bytea;
  v_applied       real;
  -- SPEC §4 domain-separation prefix 'aimos.cwc/v1' || 0x00 (13 bytes)
  c_prefix        bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_zero32        bytea := decode(repeat('00', 32), 'hex');
BEGIN
  -- ── scope (unchanged) ──────────────────────────────────────────────────────
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;
  IF current_setting('app.current_agent_id', true) <> 'housekeeper' THEN
    RAISE EXCEPTION 'cognitive_housekeeper_scope_required';
  END IF;

  -- ── quantize + bounds (SPEC I1). The signed body still binds the doubles. ──
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
  -- Every chain link is a real transition (SPEC §7.1): no self-equal step.
  IF v_new_milli = v_old_milli THEN
    RAISE EXCEPTION 'cognitive_noop_reweight';
  END IF;

  -- ── lock the memory; serializes concurrent reweights of the same memory ────
  SELECT m.retrieval_weight
    INTO v_current_weight
    FROM public.aimos_memories m
   WHERE m.id = p_memory_id
     AND m.company_id = v_company_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cognitive_memory_not_found';
  END IF;

  -- ── verify the terminal signed REWEIGHT provenance node (σ_i) (unchanged) ──
  SELECT p.body_json
    INTO v_body
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

  -- ── chain head: the memory's terminal projection (no successor). NULL ⇒ the
  --     memory has no chain yet, so THIS is its genesis transition. ───────────
  SELECT h.projection_hash, h.new_weight_milli
    INTO v_prev_hash, v_head_milli
    FROM public.aimos_cognitive_weight_projections h
   WHERE h.memory_id = p_memory_id
     AND NOT EXISTS (
       SELECT 1 FROM public.aimos_cognitive_weight_projections c
        WHERE c.memory_id = h.memory_id
          AND c.prev_projection_hash = h.projection_hash
     );

  -- ── continuity (SPEC I2), EXACT integer, never float ──────────────────────
  IF v_prev_hash IS NULL THEN
    -- genesis: old must equal the memory's live weight (quantized)
    v_current_milli := round(v_current_weight::double precision * 1000)::int;
    IF v_old_milli <> v_current_milli THEN
      RAISE EXCEPTION 'cognitive_old_weight_mismatch';
    END IF;
  ELSE
    -- successor: old must equal the chain head's new
    IF v_old_milli <> v_head_milli THEN
      RAISE EXCEPTION 'cognitive_chain_discontinuity';
    END IF;
  END IF;

  -- ── compute the projection hash in-DB (SPEC §4/§5); caller cannot forge it ─
  v_proj_hash := digest(
    c_prefix
    || uuid_send(p_memory_id)
    || int8send(v_old_milli::int8)
    || int8send(v_new_milli::int8)
    || p_provenance_mutation_hash
    || COALESCE(v_prev_hash, c_zero32),
    'sha256');

  -- ── append the transition (INSERT only; UPDATE/DELETE revoked in 081) ──────
  INSERT INTO public.aimos_cognitive_weight_projections
    (company_id, memory_id, provenance_mutation_hash,
     old_weight, new_weight, old_weight_milli, new_weight_milli,
     prev_projection_hash, projection_hash)
  VALUES
    (v_company_id, p_memory_id, p_provenance_mutation_hash,
     p_old_weight, p_new_weight, v_old_milli, v_new_milli,
     v_prev_hash, v_proj_hash);

  -- ── apply the canonical weight (derived from the milli) ────────────────────
  UPDATE public.aimos_memories
     SET retrieval_weight = (v_new_milli / 1000.0)::real
   WHERE id = p_memory_id
     AND company_id = v_company_id
  RETURNING retrieval_weight INTO v_applied;

  RETURN v_applied;
END
$function$;

COMMENT ON FUNCTION public.apply_signed_cognitive_reweight(uuid, double precision, double precision, bytea) IS
  'Sole writer of retrieval_weight. Bidirectional (no monotone check); exact-integer continuity; appends a tamper-evident hash-chain link (SPEC §7.1). Chain hash computed in-DB — callers cannot forge linkage.';
