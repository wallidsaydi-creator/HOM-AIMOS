-- Migration 009: skill_bank table and index
-- Source: services/learning/dual-skill-bank.js ensureSchema()
-- Pipeline: extracted from lazy runtime DDL into versioned migration

CREATE TABLE IF NOT EXISTS skill_bank (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  skill_type TEXT NOT NULL CHECK (skill_type IN ('task', 'step')),
  principle TEXT NOT NULL,
  when_to_apply TEXT NOT NULL,
  retrieval_key TEXT NOT NULL,
  retrieval_embedding vector(768),
  utility FLOAT NOT NULL DEFAULT 0.5,
  retrieval_count INTEGER NOT NULL DEFAULT 0,
  success_count INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  is_active BOOLEAN DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_skill_bank_type ON skill_bank (company_id, skill_type, is_active);