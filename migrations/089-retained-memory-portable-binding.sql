-- 089-retained-memory-portable-binding.sql
--
-- Native append-only upgrade boundary for memories retained before the
-- portable SAVE -> BIND protocol existed. Version 3 BIND rows are current
-- housekeeper attestations: they sign the exact retained predecessor head,
-- current live-content hash, and exact supersession edge. They do not rewrite
-- legacy rows or claim that an unverifiable historical signature was valid at
-- origin.
--
-- Paper authority:
--   Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging"
--   (signed commitments must fix a consistent retained history).
--   Koisser & Sadeghi, "Accountability of Things: Large-Scale Tamper-Evident
--   Logging for Smart Devices" (receipts attest inclusion/existence; they do
--   not manufacture event-origin authenticity).

ALTER TABLE public.aimos_memory_provenance
  DROP CONSTRAINT IF EXISTS aimos_memory_provenance_binding_schema_version;

ALTER TABLE public.aimos_memory_provenance
  ADD CONSTRAINT aimos_memory_provenance_binding_schema_version
  CHECK (binding_schema_version IN (1, 2, 3));

ALTER TABLE public.aimos_memory_provenance
  ADD CONSTRAINT aimos_memory_provenance_v3_is_bind
  CHECK (binding_schema_version <> 3 OR event_type = 'BIND');

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_provenance_one_portable_upgrade
  ON public.aimos_memory_provenance (memory_id)
  WHERE event_type = 'BIND' AND binding_schema_version = 3;

COMMENT ON CONSTRAINT aimos_memory_provenance_v3_is_bind
  ON public.aimos_memory_provenance IS
  'Schema v3 is a housekeeper-signed portable binding over the retained predecessor head, live row, and exact supersession edge; it is not a fabricated historical SAVE signature.';
