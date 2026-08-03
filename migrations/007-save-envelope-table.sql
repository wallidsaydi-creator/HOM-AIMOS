







CREATE TABLE IF NOT EXISTS aimos_save_envelope (
  memory_id UUID PRIMARY KEY REFERENCES aimos_memories(id),
  agent_id TEXT NOT NULL,
  agent_valid_from TIMESTAMPTZ NOT NULL,
  cert_fingerprint TEXT NOT NULL,         -- sha256 hex of full cert envelope
  content_hash BYTEA NOT NULL,            -- 32-byte SHA-256 of canonical body
  chain_hash BYTEA NOT NULL,              -- 32-byte chain link hash
  prev_chain_hash BYTEA NOT NULL,         -- 32-byte; genesis on first save
  ts_signed BIGINT NOT NULL,              -- unix seconds from client signature
  nonce TEXT NOT NULL,                    -- base64url, paired with (agent_id) is replay-protected
  sig BYTEA NOT NULL,                     -- raw 64-byte Ed25519 signature
  identity_tier TEXT NOT NULL CHECK (identity_tier IN ('T2', 'T3')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (agent_id, agent_valid_from)
    REFERENCES agent_identity(agent_id, valid_from)
);

-- Forensic / chain-audit access patterns:
--   - "show me all chained saves for reviewer on this enrollment, in order"
--   - "given a memory_id, what enrollment + chain position?"
CREATE INDEX IF NOT EXISTS idx_save_envelope_agent
  ON aimos_save_envelope (agent_id, agent_valid_from, created_at);

CREATE INDEX IF NOT EXISTS idx_save_envelope_chain
  ON aimos_save_envelope (agent_id, agent_valid_from, chain_hash);
