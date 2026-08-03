-- HyperBrain autonomous self-mutation archive
-- Date: 2026-03-26
-- Idempotent migration for cycle/archive/version tables

CREATE TABLE IF NOT EXISTS improvement_cycles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id TEXT NOT NULL,
    trigger_signal TEXT NOT NULL,
    objective TEXT NOT NULL,
    declared_workset JSONB NOT NULL DEFAULT '{}'::jsonb,
    resolved_workset JSONB NOT NULL DEFAULT '{}'::jsonb,
    parent_cycle_id UUID REFERENCES improvement_cycles(id) ON DELETE SET NULL,
    benchmark_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    benchmark_slice TEXT,
    status TEXT NOT NULL DEFAULT 'planned'
      CHECK (status IN ('planned', 'executing', 'evaluated', 'active', 'rolled_back', 'failed', 'blocked')),
    verdict TEXT NOT NULL DEFAULT 'pending'
      CHECK (verdict IN ('pending', 'pass', 'fail', 'blocked')),
    active_artifact_id UUID,
    rollback_snapshot_path TEXT,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT 'meta-improvement',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_improvement_cycles_company_created
  ON improvement_cycles(company_id, created_at DESC);

CREATE TABLE IF NOT EXISTS mutation_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_id UUID NOT NULL REFERENCES improvement_cycles(id) ON DELETE CASCADE,
    company_id TEXT NOT NULL,
    parent_artifact_id UUID REFERENCES mutation_artifacts(id) ON DELETE SET NULL,
    artifact_kind TEXT NOT NULL DEFAULT 'candidate',
    status TEXT NOT NULL DEFAULT 'draft'
      CHECK (status IN ('draft', 'evaluated', 'passed', 'failed', 'active', 'rolled_back', 'blocked')),
    operations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    affected_paths TEXT[] NOT NULL DEFAULT '{}',
    rationale TEXT,
    measured_deltas JSONB NOT NULL DEFAULT '{}'::jsonb,
    transfer_tags TEXT[] NOT NULL DEFAULT '{}',
    evaluation_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    snapshot_before_path TEXT,
    snapshot_after_path TEXT,
    snapshot_restore_path TEXT,
    created_by TEXT NOT NULL DEFAULT 'meta-improvement',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mutation_artifacts_cycle_created
  ON mutation_artifacts(cycle_id, created_at DESC);

CREATE TABLE IF NOT EXISTS meta_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id TEXT NOT NULL,
    cycle_id UUID REFERENCES improvement_cycles(id) ON DELETE SET NULL,
    artifact_id UUID REFERENCES mutation_artifacts(id) ON DELETE SET NULL,
    surface_type TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    version_label TEXT NOT NULL,
    config_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    mutation_strategy JSONB NOT NULL DEFAULT '{}'::jsonb,
    lineage JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_by TEXT NOT NULL DEFAULT 'meta-improvement',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT meta_versions_unique UNIQUE (company_id, surface_type, scope_key, version_label)
);
CREATE INDEX IF NOT EXISTS idx_meta_versions_surface_scope
  ON meta_versions(company_id, surface_type, scope_key, is_active DESC, created_at DESC);
