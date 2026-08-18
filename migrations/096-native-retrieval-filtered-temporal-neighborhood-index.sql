-- 096-native-retrieval-filtered-temporal-neighborhood-index.sql
--
-- Scale-correct access path for bounded temporal-neighborhood gears when a
-- signed recall envelope narrows the retained corpus by exact source and
-- memory type. Migration 094 supplies the unfiltered company/time path; this
-- index supplies the filtered path observed by the MutMem V2 Gate50 corpus.
--
-- The column order follows equality predicates first and temporal order next:
--   company_id = ? AND source = ? AND memory_type = ?
--   ORDER BY created_at, id LIMIT 1
-- This keeps each prior/following lookup logarithmic plus the bounded result,
-- instead of scanning the company corpus once for every frontier member.
--
-- This additive read-path index creates no authority, changes no memory,
-- removes no retained evidence, and does not alter ranking mathematics.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aimos_memories_company_source_type_created_id
  ON public.aimos_memories(company_id, source, memory_type, created_at, id);

COMMENT ON INDEX public.idx_aimos_memories_company_source_type_created_id IS
  'Supports bounded source/type-scoped temporal-neighborhood retrieval; no authority, memory mutation, retention, or ranking semantics.';
