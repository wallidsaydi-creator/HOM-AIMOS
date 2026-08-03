























-- Step 1: For each active housekeeper row, INSERT a new housekeeper row
-- with the same pubkey/cert/device_fp/valid_from/valid_until/chain_head.
-- The composite PK (agent_id, valid_from) allows the new row to coexist with
-- the old one (different agent_id, same valid_from).
INSERT INTO agent_identity
  (agent_id, pubkey, cert, device_fp, valid_from, valid_until, issued_at, revoked_at, chain_head, is_system_role)
SELECT
  'housekeeper',
  pubkey,
  cert,
  device_fp,
  valid_from,
  valid_until,
  issued_at,
  NULL,                       -- new row is active (not revoked)
  chain_head,
  TRUE                        -- system operational identity
FROM agent_identity
WHERE agent_id = 'housekeeper'
  AND revoked_at IS NULL;     -- only the active row(s)

-- Step 2: Revoke the housekeeper row(s) — supersession marker.
-- The row content (pubkey, cert, etc.) is unchanged; only revoked_at is set.
UPDATE agent_identity
   SET revoked_at = NOW()
 WHERE agent_id = 'housekeeper'
   AND revoked_at IS NULL;

-- Verification query (run after applying):
-- SELECT agent_id, is_system_role, revoked_at IS NOT NULL AS is_revoked, count(*)
--   FROM agent_identity
--  WHERE agent_id IN ('housekeeper', 'housekeeper')
--  GROUP BY agent_id, is_system_role, is_revoked;
-- Expected:
--   agent_id='housekeeper',    is_system_role=TRUE, is_revoked=FALSE, count=1 (or more if rotated)
--   agent_id='housekeeper', is_system_role=TRUE, is_revoked=TRUE,  count=1 (historical)