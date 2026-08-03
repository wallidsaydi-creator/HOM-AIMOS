-- Quantum Brain Schema Migration
-- Phase 2B: Tesseract + Quantum State Vectors
-- Date: 2026-03-21
-- Idempotent: safe to run multiple times

-- ─── 1. PCA BASIS TABLE ─────────────────────────────────────────────
-- Living basis: recomputed by nightly dream, one active per company.
CREATE TABLE IF NOT EXISTS pca_basis (
    id SERIAL PRIMARY KEY,
    company_id TEXT NOT NULL,
    eigenvectors BYTEA NOT NULL,
    eigenvalues DOUBLE PRECISION[] NOT NULL,
    mean_vector BYTEA NOT NULL,
    total_variance DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_count INTEGER NOT NULL,
    max_meaningful_d INTEGER NOT NULL DEFAULT 20,
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    drift_from_previous DOUBLE PRECISION,
    CONSTRAINT pca_basis_company_unique UNIQUE (company_id)
);

-- ─── 2. QUANTUM STATE VECTORS TABLE ─────────────────────────────────
-- Separate table: variable dimension, lazy loading per dimension level.
-- Only load the dimension you need for this query.
CREATE TABLE IF NOT EXISTS memory_quantum_states (
    memory_id UUID NOT NULL REFERENCES aimos_memories(id) ON DELETE CASCADE,
    company_id TEXT NOT NULL,
    dimension INTEGER NOT NULL,
    state_vector BYTEA NOT NULL,
    basis_id INTEGER REFERENCES pca_basis(id),
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (memory_id, dimension)
);

CREATE INDEX IF NOT EXISTS idx_quantum_states_company_dim
    ON memory_quantum_states(company_id, dimension);

-- ─── 3. TESSERACT SCOPE COLUMN ──────────────────────────────────────
-- Each memory belongs to: shared interior, private agent cube, or propagated.
ALTER TABLE aimos_memories
    ADD COLUMN IF NOT EXISTS cube_scope TEXT DEFAULT 'shared';

-- Add check constraint only if not exists (idempotent)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'aimos_memories_cube_scope_check'
    ) THEN
        ALTER TABLE aimos_memories
            ADD CONSTRAINT aimos_memories_cube_scope_check
            CHECK (cube_scope IN ('shared', 'private', 'propagated'));
    END IF;
END $$;

-- ─── 4. CAUSAL CHAIN COLUMNS ────────────────────────────────────────
-- 4th dimension: temporal links between memories without overwriting.
ALTER TABLE aimos_memories
    ADD COLUMN IF NOT EXISTS parent_memory_id UUID;

ALTER TABLE aimos_memories
    ADD COLUMN IF NOT EXISTS propagated_from_agent TEXT;

-- ─── 5. SCALE PARAMETERS TABLE ──────────────────────────────────────
-- Per-dimension mean/std for arctan(z-score) scaling to [0, π].
-- Arctan mapping spreads Gaussian PCA values uniformly across phase range.
-- Stored alongside PCA basis, recomputed together.
CREATE TABLE IF NOT EXISTS quantum_scale_params (
    id SERIAL PRIMARY KEY,
    company_id TEXT NOT NULL,
    dimension INTEGER NOT NULL,
    means DOUBLE PRECISION[] NOT NULL,
    stds DOUBLE PRECISION[] NOT NULL,
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    basis_id INTEGER REFERENCES pca_basis(id),
    CONSTRAINT scale_params_company_dim_unique UNIQUE (company_id, dimension)
);

-- ─── 6. INDEXES FOR QUANTUM RECALL ──────────────────────────────────
-- Cube scope index for tesseract queries
CREATE INDEX IF NOT EXISTS idx_memories_cube_scope
    ON aimos_memories(company_id, cube_scope)
    WHERE is_active = true;

-- Agent + cube scope for agent-scoped recall
CREATE INDEX IF NOT EXISTS idx_memories_agent_cube
    ON aimos_memories(company_id, agent_id, cube_scope)
    WHERE is_active = true;

-- Parent memory for causal chain traversal
CREATE INDEX IF NOT EXISTS idx_memories_parent
    ON aimos_memories(parent_memory_id)
    WHERE parent_memory_id IS NOT NULL;
