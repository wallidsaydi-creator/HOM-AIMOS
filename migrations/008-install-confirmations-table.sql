-- 008-install-confirmations-table.sql
-- Phase 7: install-gate two-step confirmation state.
-- Append-only by convention (status field is supersession metadata; row content
-- is immutable after creation; no DELETE).

CREATE TABLE IF NOT EXISTS install_confirmations (
  token TEXT PRIMARY KEY,
  next_token TEXT NULL,
  step INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'pending',
  install_classes TEXT[] NOT NULL,
  summary JSONB NOT NULL,
  pending_save JSONB NOT NULL,
  pending_envelope JSONB NULL,
  agent_id TEXT NOT NULL,
  identity_tier TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  step1_confirmed_at TIMESTAMPTZ NULL,
  step2_confirmed_at TIMESTAMPTZ NULL,
  master_sig_required BOOLEAN NOT NULL DEFAULT FALSE,
  CHECK (status IN ('pending','confirmed_step1','installed','rejected','expired'))
);

CREATE INDEX IF NOT EXISTS idx_install_confirmations_expires
  ON install_confirmations (expires_at);

CREATE INDEX IF NOT EXISTS idx_install_confirmations_status
  ON install_confirmations (status);

CREATE INDEX IF NOT EXISTS idx_install_confirmations_next_token
  ON install_confirmations (next_token) WHERE next_token IS NOT NULL;
