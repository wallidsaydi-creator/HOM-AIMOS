-- Tamper-evident, housekeeper-signed outcome trajectory for every memory.

ALTER TABLE public.memory_valence_ledger
  ADD COLUMN IF NOT EXISTS body_json jsonb,
  ADD COLUMN IF NOT EXISTS content_hash bytea,
  ADD COLUMN IF NOT EXISTS prev_hash bytea,
  ADD COLUMN IF NOT EXISTS row_hash bytea,
  ADD COLUMN IF NOT EXISTS ts_signed bigint,
  ADD COLUMN IF NOT EXISTS nonce text,
  ADD COLUMN IF NOT EXISTS sig bytea;

CREATE UNIQUE INDEX IF NOT EXISTS memory_valence_nonce_unique
  ON public.memory_valence_ledger (memory_id, nonce)
  WHERE nonce IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS memory_valence_one_genesis
  ON public.memory_valence_ledger (memory_id)
  WHERE prev_hash IS NULL AND row_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS memory_valence_next_unique
  ON public.memory_valence_ledger (memory_id, prev_hash)
  WHERE prev_hash IS NOT NULL;
