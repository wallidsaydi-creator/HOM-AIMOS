-- Migration 011: HNSW embedding index
-- Source: services/retrieval/hnsw-optimizer.js ensureHnswIndex()
-- Pipeline: extracted from lazy runtime DDL into versioned migration
-- Note: CONCURRENTLY does not lock the table for writes; safe for live DBs

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aimos_memories_embedding_hnsw
  ON aimos_memories USING hnsw (embedding vector_cosine_ops)
  WITH (m = 32, ef_construction = 200);