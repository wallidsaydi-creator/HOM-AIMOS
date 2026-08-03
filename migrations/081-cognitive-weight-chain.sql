-- 081-cognitive-weight-chain.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Option 3 — Certified Cognitive-Weight Trajectory, Phase 1 (schema).
-- Normative spec: docs/security/cognitive-weight-chain-SPEC.md
--
-- Turns aimos_cognitive_weight_projections (created in 080) into an append-only,
-- tamper-evident HASH CHAIN of every weight transition. Weight movement stays
-- BIDIRECTIONAL (good→bad→good); the database guarantees Existence, Bounds,
-- Signature, and Chained order — NOT monotonicity.
--
-- Canonical hash (SPEC §4/§5), all-bytea, fixed-width, domain-separated:
--   h_i = sha256( 'aimos.cwc/v1' || 0x00 || uuid_send(m)
--                 || int8send(q_{i-1}) || int8send(q_i)
--                 || σ_i || h_{i-1} )     h_{-1} = 32 zero bytes
-- Canonical weight is the INTEGER milli q ∈ [100,3000]; the real column is a
-- derived display and is never on the hash path (SPEC §9 — you cannot hash a
-- float). Verified in-DB == Python reference: 7e3ea6b5…966d73f7.
--
-- H10 (schema forward-only): additive; no legacy alias removed.
-- Idempotent: guarded so a manual re-run is a no-op.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─── 1. Columns (nullable first — the table may already hold 080-era rows) ────
ALTER TABLE public.aimos_cognitive_weight_projections
  ADD COLUMN IF NOT EXISTS old_weight_milli     integer,
  ADD COLUMN IF NOT EXISTS new_weight_milli     integer,
  ADD COLUMN IF NOT EXISTS prev_projection_hash bytea,
  ADD COLUMN IF NOT EXISTS projection_hash      bytea;

-- ─── 2a. Backfill canonical millis from the stored reals (round-trip exact for
--          q∈[100,3000]; SPEC §9). No-op on a fresh/empty table. ──────────────
UPDATE public.aimos_cognitive_weight_projections
   SET old_weight_milli = round(old_weight * 1000)::int,
       new_weight_milli = round(new_weight * 1000)::int
 WHERE old_weight_milli IS NULL OR new_weight_milli IS NULL;

-- ─── 2b. Backfill the chain in per-memory applied_at order. The hash of row n
--          depends on row n-1, so this is a recursive walk from each genesis.
--          The preimage uses the SAME millis just stored (2a), so h matches the
--          canonical columns exactly. No-op on empty. ─────────────────────────
WITH RECURSIVE ordered AS (
  SELECT projection_id, memory_id, provenance_mutation_hash,
         old_weight_milli, new_weight_milli,
         row_number() OVER (PARTITION BY memory_id
                            ORDER BY applied_at, projection_id) AS rn
    FROM public.aimos_cognitive_weight_projections
),
chain AS (
  -- genesis (rn = 1): prev_hash = NULL, preimage prev = 32 zero bytes
  SELECT o.projection_id, o.memory_id, o.rn,
         NULL::bytea AS prev_hash,
         digest(
           '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea
           || uuid_send(o.memory_id)
           || int8send(o.old_weight_milli::int8)
           || int8send(o.new_weight_milli::int8)
           || o.provenance_mutation_hash
           || decode(repeat('00', 32), 'hex'),
           'sha256') AS proj_hash
    FROM ordered o
   WHERE o.rn = 1
  UNION ALL
  -- successor: prev_hash = predecessor's proj_hash
  SELECT o.projection_id, o.memory_id, o.rn,
         c.proj_hash AS prev_hash,
         digest(
           '\x61696d6f732e6377632f7631'::bytea || '\x00'::bytea
           || uuid_send(o.memory_id)
           || int8send(o.old_weight_milli::int8)
           || int8send(o.new_weight_milli::int8)
           || o.provenance_mutation_hash
           || c.proj_hash,
           'sha256') AS proj_hash
    FROM ordered o
    JOIN chain c ON c.memory_id = o.memory_id AND o.rn = c.rn + 1
)
UPDATE public.aimos_cognitive_weight_projections p
   SET prev_projection_hash = ch.prev_hash,
       projection_hash      = ch.proj_hash
  FROM chain ch
 WHERE p.projection_id = ch.projection_id
   AND p.projection_hash IS NULL;

-- ─── 3. Continuity gate (SPEC I2). Abort loudly rather than chain over dirty
--          legacy data. Vacuous-true on an empty table (correct: empty chain is
--          valid). Any non-genesis row whose old ≠ predecessor's new is an
--          incident to investigate before constraining. ─────────────────────
DO $cwc_continuity$
DECLARE
  broken bigint;
BEGIN
  WITH ordered AS (
    SELECT memory_id, old_weight_milli, new_weight_milli,
           row_number() OVER (PARTITION BY memory_id
                              ORDER BY applied_at, projection_id) AS rn
      FROM public.aimos_cognitive_weight_projections
  )
  SELECT count(*) INTO broken
    FROM ordered cur
    JOIN ordered prev
      ON prev.memory_id = cur.memory_id AND prev.rn = cur.rn - 1
   WHERE cur.old_weight_milli <> prev.new_weight_milli;
  IF broken > 0 THEN
    RAISE EXCEPTION
      'CWC-081 ABORT: % projection rows violate weight continuity (old != predecessor new). Investigate as an incident before chaining.', broken;
  END IF;
END
$cwc_continuity$;

-- ─── 4. Lock the canonical columns down. ─────────────────────────────────────
ALTER TABLE public.aimos_cognitive_weight_projections
  ALTER COLUMN old_weight_milli SET NOT NULL,
  ALTER COLUMN new_weight_milli SET NOT NULL,
  ALTER COLUMN projection_hash  SET NOT NULL;

DO $cwc_bound$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_cwc_milli_bound'
       AND conrelid = 'public.aimos_cognitive_weight_projections'::regclass
  ) THEN
    ALTER TABLE public.aimos_cognitive_weight_projections
      ADD CONSTRAINT aimos_cwc_milli_bound
      CHECK (old_weight_milli BETWEEN 100 AND 3000
         AND new_weight_milli BETWEEN 100 AND 3000);
  END IF;
END
$cwc_bound$;

-- ─── 5. Chain shape: unique hashes, one genesis per memory, no fork (SPEC I5).
--          Together these force a simple path (total order). ─────────────────
CREATE UNIQUE INDEX IF NOT EXISTS aimos_cwc_projection_hash_unique
  ON public.aimos_cognitive_weight_projections (projection_hash);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_cwc_one_genesis
  ON public.aimos_cognitive_weight_projections (memory_id)
  WHERE prev_projection_hash IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_cwc_no_fork
  ON public.aimos_cognitive_weight_projections (memory_id, prev_projection_hash);

-- Fast terminal-head lookup (the reweight function reads the current chain head).
CREATE INDEX IF NOT EXISTS aimos_cwc_head
  ON public.aimos_cognitive_weight_projections (memory_id, applied_at DESC);

-- ─── 6. Append-only at the DB (SPEC I6). Only the SECURITY DEFINER reweight
--          function inserts; nobody updates, deletes, or truncates. ──────────
DO $cwc_acl$
BEGIN
  REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_cognitive_weight_projections FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_cognitive_weight_projections FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_cognitive_weight_projections FROM aimos_app;
  END IF;
END
$cwc_acl$;

COMMENT ON COLUMN public.aimos_cognitive_weight_projections.projection_hash IS
  'SPEC §5 chain hash h_i = sha256(prefix||uuid||be64(old_milli)||be64(new_milli)||sigma||prev_hash). Canonical, externally verifiable.';
COMMENT ON COLUMN public.aimos_cognitive_weight_projections.new_weight_milli IS
  'Canonical quantized weight q_i in [100,3000]; retrieval_weight (real) is q_i/1000 derived. Only millis are hashed.';
