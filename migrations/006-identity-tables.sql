






-- ─── MASTER IDENTITY ─────────────────────────────────────────────────────────
-- Single-row table. CHECK (id = 1) enforces uniqueness without sequence drift.
-- master_pubkey is base64url DER SPKI Ed25519 public key.
-- fingerprint is sha256 hex of the DER bytes (for human-readable display).
-- revocation_cert_hash is the sha256 of a pre-issued offline revocation
-- envelope (Phase 2 generates and stores hash; the envelope itself stays
-- offline). NULL until master is enrolled.

CREATE TABLE IF NOT EXISTS aimos_master_identity (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  master_pubkey TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revocation_cert_hash TEXT NULL
);

-- ─── AGENT IDENTITY ──────────────────────────────────────────────────────────
-- One row per enrollment. Composite PK (agent_id, valid_from) makes rotation
-- explicit: rotating reviewer produces a second row with a later valid_from while
-- the prior row remains canonical. revoked_at is set as supersession only;
-- the row is never deleted.
--
-- chain_head is populated by Phase 3 (hash-chain primitive). Phase 1 leaves
-- it NULL. cert holds the full base64url-encoded signed envelope produced by
-- agent-identity.js issueCert().

CREATE TABLE IF NOT EXISTS agent_identity (
  agent_id TEXT NOT NULL,
  pubkey TEXT NOT NULL,
  cert TEXT NOT NULL,
  device_fp TEXT NOT NULL,
  valid_from TIMESTAMPTZ NOT NULL,
  valid_until TIMESTAMPTZ NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ NULL,
  chain_head BYTEA NULL,
  PRIMARY KEY (agent_id, valid_from)
);

CREATE INDEX IF NOT EXISTS idx_agent_identity_active
  ON agent_identity (agent_id) WHERE revoked_at IS NULL;
