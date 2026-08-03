







ALTER TABLE agent_identity
  ADD COLUMN IF NOT EXISTS is_system_role BOOLEAN NOT NULL DEFAULT FALSE;






UPDATE agent_identity
   SET is_system_role = TRUE
 WHERE agent_id IN ('housekeeper', 'aimos_flag_signer', 'housekeeper');

-- Index for fast lookup of system-role identities (small table, but explicit).
CREATE INDEX IF NOT EXISTS idx_agent_identity_system_role
  ON agent_identity (is_system_role) WHERE is_system_role = TRUE;