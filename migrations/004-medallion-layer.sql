-- Medallion architecture: Bronze/Silver/Gold layer separation
-- Bronze = raw/unvalidated, Silver = validated/enriched, Gold = curated/production-ready
ALTER TABLE aimos_memories ADD COLUMN IF NOT EXISTS medallion_layer TEXT DEFAULT 'bronze'
  CHECK (medallion_layer IN ('bronze', 'silver', 'gold'));

CREATE INDEX IF NOT EXISTS idx_memories_medallion ON aimos_memories(medallion_layer);
CREATE INDEX IF NOT EXISTS idx_memories_company_medallion ON aimos_memories(company_id, medallion_layer);

-- Backfill existing memories to appropriate layers
UPDATE aimos_memories SET medallion_layer = 'gold'
  WHERE memory_type IN ('milestone', 'product', 'identity', 'procedural', 'crew_identity', 'dream_summary', 'self_improvement', 'infrastructure')
  AND medallion_layer = 'bronze';

UPDATE aimos_memories SET medallion_layer = 'silver'
  WHERE memory_type IN ('session', 'directive', 'heartbeat', 'intel', 'test')
  AND medallion_layer = 'bronze';
-- All others remain 'bronze' (raw/episodic)
