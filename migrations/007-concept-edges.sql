-- Migration 007: concept_edges table and indexes
-- Source: services/core/concept-graph.js ensureSchema()
-- Pipeline: extracted from lazy runtime DDL into versioned migration

-- Add node_type column to aimos_memories if not present
ALTER TABLE aimos_memories ADD COLUMN IF NOT EXISTS node_type TEXT DEFAULT 'episode';

-- Concept edges table for cross-referencing memory relationships
CREATE TABLE IF NOT EXISTS concept_edges (
  id SERIAL PRIMARY KEY,
  company_id TEXT NOT NULL,
  source_id UUID NOT NULL,
  target_id UUID NOT NULL,
  edge_type TEXT NOT NULL CHECK (edge_type IN ('NEXT', 'DERIVED_FROM', 'DERIVED_FROM_FACT', 'HAS_CONCEPT', 'ABOUT_CONCEPT')),
  weight FLOAT DEFAULT 1.0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_concept_edges_source ON concept_edges (company_id, source_id);
CREATE INDEX IF NOT EXISTS idx_concept_edges_target ON concept_edges (company_id, target_id);