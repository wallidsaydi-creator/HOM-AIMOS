-- 093-signed-memory-origin-time.sql
--
-- Twin-prime Paper 2, TP-G0: establish a native, cryptographically bound
-- cardinal time coordinate before any arithmetic feature can affect recall.
-- New native SAVE transactions append a schema-v4 BIND node whose signed body
-- contains the database-issued memory creation time quantized to Unix
-- milliseconds. The same value is retained in memory_originated_at and the
-- constraint below prevents projection/body drift.
--
-- This does not claim an external-world event time. It attests the database
-- insertion time observed by the housekeeper inside the canonical transaction.
-- Historical schema-v1/v2/v3 rows remain valid and are never rewritten.
--
-- Mathematical and systems authority:
--   - GPY/Maynard/Polymath8b as bounded-gap background only; no fixed radius
--     or unproved prime conjecture is introduced by this migration.
--   - Haber & Stornetta / Crosby & Wallach: signed, append-only commitments
--     must bind the exact datum later consumed by the verifier.

ALTER TABLE public.aimos_memory_provenance
  DROP CONSTRAINT IF EXISTS aimos_memory_provenance_binding_schema_version;

ALTER TABLE public.aimos_memory_provenance
  ADD CONSTRAINT aimos_memory_provenance_binding_schema_version
  CHECK (binding_schema_version IN (1, 2, 3, 4));

ALTER TABLE public.aimos_memory_provenance
  ADD CONSTRAINT aimos_memory_provenance_v4_is_origin_bound_bind
  CHECK (
    binding_schema_version <> 4 OR (
      event_type = 'BIND'
      AND memory_originated_at IS NOT NULL
      AND jsonb_typeof(body_json) = 'object'
      AND jsonb_typeof(body_json->'memory_originated_at_unix_ms') = 'number'
      AND trunc(extract(epoch FROM memory_originated_at) * 1000)::bigint
          = (body_json->>'memory_originated_at_unix_ms')::bigint
    )
  );

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_provenance_one_current_portable_binding
  ON public.aimos_memory_provenance (memory_id)
  WHERE event_type = 'BIND' AND binding_schema_version IN (3, 4);

COMMENT ON CONSTRAINT aimos_memory_provenance_v4_is_origin_bound_bind
  ON public.aimos_memory_provenance IS
  'Schema v4 is a housekeeper-signed native BIND whose body commits the database-issued memory origin time at millisecond precision; it is not an external event-time claim.';

