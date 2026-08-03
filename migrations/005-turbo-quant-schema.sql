-- 005-turbo-quant-schema.sql
-- Goal: Native Cognitive Compression (Phase I: TurboQuant)
-- Alignment: DA-SSDP (weight preservation) + MemGPT (infinite archival scaling)

-- 1. Add quantization columns
ALTER TABLE aimos_memories ADD COLUMN IF NOT EXISTS quant_idx INTEGER;
ALTER TABLE aimos_memories ADD COLUMN IF NOT EXISTS residual_vector vector(768);

-- 2. Create index for high-speed centroid filtering (L2 Retrieval first-pass)
-- B-Tree is optimal for integer index filtering
CREATE INDEX IF NOT EXISTS idx_memories_quant_idx ON aimos_memories(company_id, quant_idx) WHERE quant_idx IS NOT NULL;

-- 3. Create a dedicated table for the Codebook (Centroids)
-- This allows per-company isolated manifolds as per Sovereignty Check
CREATE TABLE IF NOT EXISTS aimos_codebook (
    id SERIAL PRIMARY KEY,
    company_id TEXT NOT NULL,
    quant_idx INTEGER NOT NULL,
    centroid vector(768) NOT NULL,
    access_count BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(company_id, quant_idx)
);

CREATE INDEX IF NOT EXISTS idx_codebook_lookup ON aimos_codebook(company_id, quant_idx);

-- 4. Comment for provenance
COMMENT ON COLUMN aimos_memories.quant_idx IS 'ITQ3 S / TurboQuant centroid index for first-pass retrieval';
COMMENT ON COLUMN aimos_memories.residual_vector IS 'QJL-corrected residual for precision re-ranking';
