-- 083-cognitive-weight-chain-verifier.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Option 3 — Certified Cognitive-Weight Trajectory, Phase 3a (in-DB verifier).
-- Normative spec: docs/security/cognitive-weight-chain-SPEC.md §7.2, §11.
--
-- Pure-SQL, LIVE verification of the weight-transition hash chain — tap it any
-- moment with `SELECT * FROM verify_cognitive_weight_chain('<memory-id>')`. No
-- external script, no service, no secret. Layer 1 (SHA-256 chain, pgcrypto).
-- Layer 2 (Ed25519 signature, pgsodium) is added separately once the signature
-- form is settled — see the SPEC's signature-layer note.
--
-- Walks the chain from genesis, recomputes every h_i (SPEC §5) and compares it to
-- the stored projection_hash, checks continuity (SPEC I2), reachability (no
-- orphan rows), and terminal fidelity (SPEC I3: last new == live retrieval_weight).
-- O(k) time, streaming. An empty chain (memory never reweighted) verifies ok.

CREATE OR REPLACE FUNCTION public.verify_cognitive_weight_chain(p_memory_id uuid)
RETURNS TABLE(ok boolean, chain_length integer, terminal_weight real, break_at bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  c_prefix         bytea := '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea;
  c_zero32         bytea := decode(repeat('00', 32), 'hex');
  r                record;
  v_prev_hash      bytea := NULL;   -- predecessor's stored projection_hash
  v_prev_new_milli int   := NULL;
  v_expected       bytea;
  v_len            integer := 0;
  v_total          integer;
  v_break          bytea := NULL;
  v_reason         text  := NULL;
  v_terminal_milli integer := NULL;
  v_live           real;
BEGIN
  SELECT count(*) INTO v_total
    FROM public.aimos_cognitive_weight_projections WHERE memory_id = p_memory_id;

  FOR r IN
    WITH RECURSIVE walk AS (
      SELECT p.projection_hash, p.prev_projection_hash, p.provenance_mutation_hash,
             p.old_weight_milli, p.new_weight_milli, 1 AS ord
        FROM public.aimos_cognitive_weight_projections p
       WHERE p.memory_id = p_memory_id AND p.prev_projection_hash IS NULL
      UNION ALL
      SELECT p.projection_hash, p.prev_projection_hash, p.provenance_mutation_hash,
             p.old_weight_milli, p.new_weight_milli, w.ord + 1
        FROM public.aimos_cognitive_weight_projections p
        JOIN walk w ON p.memory_id = p_memory_id
                   AND p.prev_projection_hash = w.projection_hash
    )
    SELECT * FROM walk ORDER BY ord
  LOOP
    v_len := v_len + 1;
    -- continuity (SPEC I2)
    IF v_prev_new_milli IS NOT NULL AND r.old_weight_milli <> v_prev_new_milli THEN
      v_break := r.projection_hash; v_reason := 'continuity_break'; EXIT;
    END IF;
    -- recompute the chain hash (SPEC §5) and compare to what is stored
    v_expected := digest(
      c_prefix || uuid_send(p_memory_id)
      || int8send(r.old_weight_milli::int8) || int8send(r.new_weight_milli::int8)
      || r.provenance_mutation_hash || COALESCE(v_prev_hash, c_zero32),
      'sha256');
    IF v_expected <> r.projection_hash THEN
      v_break := r.projection_hash; v_reason := 'hash_mismatch'; EXIT;
    END IF;
    v_prev_hash      := r.projection_hash;
    v_prev_new_milli := r.new_weight_milli;
    v_terminal_milli := r.new_weight_milli;
  END LOOP;

  -- reachability: every projection row must be on the walk from genesis (SPEC I5)
  IF v_break IS NULL AND v_len <> v_total THEN
    v_break := c_zero32; v_reason := 'unreachable_rows';
  END IF;

  -- terminal fidelity (SPEC I3): last new == live weight (quantized), when a chain exists
  SELECT retrieval_weight INTO v_live FROM public.aimos_memories WHERE id = p_memory_id;
  IF v_break IS NULL AND v_terminal_milli IS NOT NULL
     AND round(v_live::double precision * 1000)::int <> v_terminal_milli THEN
    v_break := c_zero32; v_reason := 'terminal_weight_mismatch';
  END IF;

  ok             := (v_break IS NULL);
  chain_length   := v_len;
  terminal_weight:= v_live;
  break_at       := v_break;
  reason         := v_reason;
  RETURN NEXT;
END
$function$;

-- Corpus-wide verifier for the ceremony / CI — one row per memory that has a chain.
CREATE OR REPLACE FUNCTION public.verify_all_cognitive_weight_chains()
RETURNS TABLE(memory_id uuid, ok boolean, chain_length integer, break_at bytea, reason text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE m uuid;
BEGIN
  FOR m IN
    SELECT DISTINCT p.memory_id FROM public.aimos_cognitive_weight_projections p
  LOOP
    RETURN QUERY
      SELECT m, v.ok, v.chain_length, v.break_at, v.reason
        FROM public.verify_cognitive_weight_chain(m) v;
  END LOOP;
END
$function$;

COMMENT ON FUNCTION public.verify_cognitive_weight_chain(uuid) IS
  'Live, pure-SQL verification of a memory''s weight hash-chain (SPEC §7.2): recomputes every h_i, checks continuity, reachability, and terminal fidelity. Tap any time.';
