-- 094-native-retrieval-temporal-neighborhood-index.sql
--
-- Native retrieval scale bound for temporal-neighborhood gears, including
-- MAGMA.  The retrieval owner asks for the immediately preceding/following
-- eligible memories for each bounded frontier node.  Without this index the
-- database may scan and sort the company corpus once per frontier, making a
-- syntactically bounded LIMIT behave as O(f*n) work at scale.
--
-- The index is read-path infrastructure only. It creates no authority, changes
-- no memory, removes no evidence, and does not alter Aladdin eligibility.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aimos_memories_company_created_id
  ON public.aimos_memories(company_id, created_at, id);

COMMENT ON INDEX public.idx_aimos_memories_company_created_id IS
  'Supports bounded native temporal-neighborhood retrieval by company and origin-time order; no retention or ranking authority.';
