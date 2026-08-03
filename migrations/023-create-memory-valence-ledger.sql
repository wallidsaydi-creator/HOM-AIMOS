-- 023-create-memory-valence-ledger.sql
-- Aimos-2 / Paper 2 substrate — append-only valence ledger.
--
-- The valence ledger records every reward signal applied to a memory:
--   (memory_id, reward_sign, context_hash, recorded_at)
--
-- It is the substrate for the dynamic mutation governors (Cohen-Grossberg
-- bounded energy + Oja scalar self-limiting decay). Without it, the system
-- has no memory of valence history — `rewardSign = ±1` is applied at
-- stdp-kernel.js:285 then the sign is lost. The valence ledger makes the
-- system capable of "judging" (via the tanh judge in valence-judge.js) so
-- that dynamic mutation good↔bad becomes possible.
--
-- The ledger is append-only (no UPDATE/DELETE path) per Aladdin Law:
--   . The synapse changes. The neuron persists.
--   . Memory of valence is itself a memory — never deleted.
--
-- Substrate collection is unconditional: appendValence is called from
-- stdp-kernel.js applyRewardSignal AFTER the weight UPDATE, regardless of
-- whether the governor flags are ON. The judge function is callable but
-- drives nothing until governors attach. This means the ledger begins
-- populating from the moment the migration lands, even with all governor
-- flags OFF (shadow-first substrate).
--
-- H10 (no legacy aliases): N/A — new table.
-- H8 (no parallel edits): solo migration, sequential after 022.
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'memory_valence_ledger'
  ) THEN
    CREATE TABLE memory_valence_ledger (
      id           bigserial PRIMARY KEY,
      memory_id    uuid        NOT NULL REFERENCES aimos_memories(id) ON DELETE CASCADE,
      company_id   text        NOT NULL,
      reward_sign  smallint    NOT NULL CHECK (reward_sign IN (-1, 1)),
      context_hash text,
      recorded_at  timestamptz NOT NULL DEFAULT now()
    );
    COMMENT ON TABLE  memory_valence_ledger IS 'Append-only valence ledger (Aimos-2 / Paper 2 substrate). Records every reward signal applied to a memory; consumed by the tanh judge (valence-judge.js) to drive the Cohen-Grossberg and Oja governors.';
    COMMENT ON COLUMN memory_valence_ledger.reward_sign IS '+1 for success / positive valence, -1 for error / negative valence. CHECK constraint enforces the binary.';
    COMMENT ON COLUMN memory_valence_ledger.context_hash IS 'Optional hash of the recall context that produced the reward. NULL if no context was captured.';
    COMMENT ON COLUMN memory_valence_ledger.recorded_at IS 'When the reward signal was applied. Indexed DESC for the judge lookback.';
  END IF;
END
$body$;

CREATE INDEX IF NOT EXISTS idx_valence_memory_time
  ON memory_valence_ledger (memory_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_valence_company_time
  ON memory_valence_ledger (company_id, recorded_at DESC);

-- Verification query (run after applying):
-- SELECT count(*) FROM memory_valence_ledger;
--   -> 0 initially. Begins populating on the next applyRewardSignal call.