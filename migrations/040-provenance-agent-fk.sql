















































-- ─── 1. Add the missing epoch column, nullable ───────────────────────────────
ALTER TABLE aimos_memory_provenance
  ADD COLUMN IF NOT EXISTS agent_valid_from timestamptz;

-- ─── 2. Backfill it. Pick the identity epoch that was valid when the row was
--        signed. to_timestamp(ts_signed) converts the bigint unix-seconds signing
--        time; fall back to memory_originated_at, then now(). Only rows with a
--        non-null agent_id and a currently-null epoch are touched. ────────────
UPDATE aimos_memory_provenance p
   SET agent_valid_from = (
       SELECT max(a.valid_from) FROM agent_identity a
        WHERE a.agent_id = p.agent_id
          AND a.valid_from <= COALESCE(
                to_timestamp(NULLIF(p.ts_signed, 0)),
                p.memory_originated_at,
                now())
   )
 WHERE p.agent_id IS NOT NULL
   AND p.agent_valid_from IS NULL;

-- ─── 3. Orphan gate. If any row still attributes a memory to an agent with no
--        identity epoch, this is an incident — STOP, do not constrain. ─────────
DO $r3_040_orphan_gate$
DECLARE
  orphan_count bigint;
BEGIN
  SELECT count(*) INTO orphan_count
    FROM aimos_memory_provenance p
   WHERE p.agent_id IS NOT NULL
     AND p.agent_valid_from IS NULL;
  IF orphan_count > 0 THEN
    RAISE EXCEPTION
      'R3-040 ABORT: % provenance rows attribute a memory to an agent with no identity epoch. The ledger has phantom attributions — investigate as an incident before adding the FK. (Refusing to constrain over dirty data.)',
      orphan_count;
  END IF;
END
$r3_040_orphan_gate$;

-- ─── 4a. memory_id FK: CASCADE → RESTRICT. Discover the existing FK name
--         dynamically (system-generated in 018), drop it, re-add as RESTRICT. ──
DO $r3_040_memory_fk$
DECLARE
  con_name text;
BEGIN
  SELECT c.conname INTO con_name
    FROM pg_constraint c
   WHERE c.conrelid = 'aimos_memory_provenance'::regclass
     AND c.contype  = 'f'
     AND c.confrelid = 'aimos_memories'::regclass
     AND (SELECT attname FROM pg_attribute
           WHERE attrelid = c.conrelid AND attnum = c.conkey[1]) = 'memory_id'
   LIMIT 1;
  IF con_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE aimos_memory_provenance DROP CONSTRAINT %I', con_name);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'aimos_memory_provenance'::regclass
       AND conname  = 'aimos_memory_provenance_memory_id_restrict_fkey'
  ) THEN
    ALTER TABLE aimos_memory_provenance
      ADD CONSTRAINT aimos_memory_provenance_memory_id_restrict_fkey
      FOREIGN KEY (memory_id) REFERENCES aimos_memories(id) ON DELETE RESTRICT;
  END IF;
END
$r3_040_memory_fk$;

-- ─── 4b. The composite agent FK, bound to the identity epoch. ────────────────
DO $r3_040_agent_fk$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'aimos_memory_provenance'::regclass
       AND conname  = 'fk_provenance_agent'
  ) THEN
    ALTER TABLE aimos_memory_provenance
      ADD CONSTRAINT fk_provenance_agent
      FOREIGN KEY (agent_id, agent_valid_from)
      REFERENCES agent_identity(agent_id, valid_from);
  END IF;
END
$r3_040_agent_fk$;

COMMENT ON COLUMN aimos_memory_provenance.agent_valid_from IS
  'R3-040: the signing identity epoch — pairs with agent_id in the composite FK to agent_identity(agent_id, valid_from). NULLABLE (MATCH SIMPLE) so P-anchor/system rows with no epoch are permitted; any non-NULL value is enforced.';
