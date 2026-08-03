-- 059-aladdin-retention-constraints.sql
--
-- Canonical memory lifecycle state is retained historical metadata, never
-- recall authority. These NOT VALID constraints reject new forbidden states
-- without rewriting or deleting any legacy row. Existing rows remain fully
-- addressable while forward writes are permanently long-term and active.

ALTER TABLE aimos_memories
  ADD CONSTRAINT aimos_memories_aladdin_active
    CHECK (is_active IS TRUE) NOT VALID,
  ADD CONSTRAINT aimos_memories_aladdin_no_expiry
    CHECK (expires_at IS NULL) NOT VALID,
  ADD CONSTRAINT aimos_memories_aladdin_neutral_legacy_decay
    CHECK (decay_weight = 1.0) NOT VALID,
  ADD CONSTRAINT aimos_memories_aladdin_long_term
    CHECK (memory_tier = 'long-term') NOT VALID;

CREATE INDEX IF NOT EXISTS idx_memories_retrieval_weight_retained
  ON aimos_memories (company_id, retrieval_weight DESC);

CREATE INDEX IF NOT EXISTS idx_memories_skill_type_retained
  ON aimos_memories (company_id, memory_type);

CREATE INDEX IF NOT EXISTS idx_procedural_skills_retained
  ON aimos_memories (company_id, memory_type, created_at)
  WHERE memory_type = 'procedural';
