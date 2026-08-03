-- Migration 010: similarity_statistics table
-- Source: services/retrieval/similarity-stats.js ensureTable()
-- Pipeline: extracted from lazy runtime DDL into versioned migration

CREATE TABLE IF NOT EXISTS similarity_statistics (
  company_id TEXT PRIMARY KEY,
  window_mean FLOAT NOT NULL DEFAULT 0.0,
  window_std FLOAT NOT NULL DEFAULT 1.0,
  sample_count INTEGER NOT NULL DEFAULT 0,
  running_sum FLOAT NOT NULL DEFAULT 0,
  running_sum_sq FLOAT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);