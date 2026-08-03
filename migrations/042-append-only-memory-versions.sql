-- Aladdin Law: same-key saves create immutable linked versions; they never
-- overwrite the prior row. The old unique index was the schema pressure that
-- forced destructive ON CONFLICT updates in the canonical save lane.

DROP INDEX IF EXISTS public.idx_aimos_memories_company_key;

CREATE INDEX IF NOT EXISTS idx_aimos_memories_company_key_created
  ON public.aimos_memories (company_id, key, created_at DESC);
