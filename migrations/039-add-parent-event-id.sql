ALTER TABLE aimos_events ADD COLUMN IF NOT EXISTS parent_event_id UUID;
CREATE INDEX IF NOT EXISTS idx_aimos_events_parent ON aimos_events (parent_event_id) WHERE parent_event_id IS NOT NULL;
