-- Migration 013: Dormancy hot-path aimos_events index
-- Supports set-based recall_count aggregation in services/temporal/dormancy-manager.js.
-- Shape required by Phase 5: aimos_events(company_id, key, operation)

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aimos_events_company_key_operation
  ON aimos_events(company_id, key, operation);
