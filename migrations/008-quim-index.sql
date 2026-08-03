-- Migration 008: quim_index and quim_prototypes tables and indexes
-- Source: services/retrieval/quim-index.js ensureSchema()
-- Pipeline: extracted from lazy runtime DDL into versioned migration

-- QuIM inverted question index for fast prototype-to-question lookup
CREATE TABLE IF NOT EXISTS quim_index (
  id SERIAL PRIMARY KEY,
  company_id TEXT NOT NULL,
  prototype_id INTEGER NOT NULL,
  prototype_embedding FLOAT8[],
  question_text TEXT,
  question_embedding FLOAT8[],
  chunk_id UUID NOT NULL REFERENCES aimos_memories(id) ON DELETE CASCADE,
  chunk_preview TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_quim_company_proto ON quim_index(company_id, prototype_id);
CREATE INDEX IF NOT EXISTS idx_quim_chunk ON quim_index(company_id, chunk_id);

-- Prototype centroids for nearest-prototype lookup
CREATE TABLE IF NOT EXISTS quim_prototypes (
  id SERIAL PRIMARY KEY,
  company_id TEXT NOT NULL,
  prototype_id INTEGER NOT NULL,
  centroid FLOAT8[],
  member_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(company_id, prototype_id)
);