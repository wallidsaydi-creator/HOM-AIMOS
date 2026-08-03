-- Migration 014: Dormancy hot-path source cross-reference index
-- Supports set-based cross_ref_count aggregation in services/temporal/dormancy-manager.js.
-- Shape required by Phase 5: memory_cross_refs(company_id, source_memory_id)

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_memory_cross_refs_company_source
  ON memory_cross_refs(company_id, source_memory_id);
