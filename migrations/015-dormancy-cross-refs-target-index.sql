-- Migration 015: Dormancy hot-path target cross-reference index
-- Supports set-based cross_ref_count aggregation in services/temporal/dormancy-manager.js.
-- Shape required by Phase 5: memory_cross_refs(company_id, target_memory_id)

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_memory_cross_refs_company_target
  ON memory_cross_refs(company_id, target_memory_id);
