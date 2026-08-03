-- Authorization order is defined only by the signed prev_mutation_hash graph.
-- Timestamps and UUIDs remain immutable audit metadata, never chain authority.

DROP INDEX IF EXISTS public.aimos_authorization_effective_idx;
DROP INDEX IF EXISTS public.aimos_recall_authorization_latest;
DROP INDEX IF EXISTS public.aimos_authorization_one_genesis;
DROP INDEX IF EXISTS public.aimos_authorization_one_successor;
DROP INDEX IF EXISTS public.aimos_authorization_mutation_unique;

CREATE INDEX IF NOT EXISTS aimos_authorization_topology_scan
  ON public.aimos_authorization_events
    (company_id, subject_agent_id, subject_valid_from, capability);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_authorization_epoch_one_genesis
  ON public.aimos_authorization_events
    (company_id, subject_agent_id, subject_valid_from, capability)
  WHERE prev_mutation_hash IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_authorization_epoch_one_successor
  ON public.aimos_authorization_events
    (company_id, subject_agent_id, subject_valid_from, capability, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_authorization_epoch_mutation_unique
  ON public.aimos_authorization_events
    (company_id, subject_agent_id, subject_valid_from, capability, mutation_hash);

CREATE INDEX IF NOT EXISTS aimos_recall_authorization_topology_scan
  ON public.aimos_recall_authorization_events
    (company_id, subject_agent_id, subject_valid_from);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_recall_authorization_stream_mutation_unique
  ON public.aimos_recall_authorization_events
    (company_id, subject_agent_id, subject_valid_from, mutation_hash);

DO $authorization_topology_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_authorization_events'::regclass
       AND conname = 'aimos_authorization_predecessor_shape'
  ) THEN
    ALTER TABLE public.aimos_authorization_events
      ADD CONSTRAINT aimos_authorization_predecessor_shape
      CHECK (prev_mutation_hash IS NULL OR octet_length(prev_mutation_hash) = 32)
      NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_authorization_events'::regclass
       AND conname = 'aimos_authorization_predecessor_fkey'
  ) THEN
    ALTER TABLE public.aimos_authorization_events
      ADD CONSTRAINT aimos_authorization_predecessor_fkey
      FOREIGN KEY (company_id, subject_agent_id, subject_valid_from, capability, prev_mutation_hash)
      REFERENCES public.aimos_authorization_events
        (company_id, subject_agent_id, subject_valid_from, capability, mutation_hash)
      ON DELETE RESTRICT
      DEFERRABLE INITIALLY DEFERRED
      NOT VALID;
  END IF;
END
$authorization_topology_constraints$;

ALTER TABLE public.aimos_authorization_events
  VALIDATE CONSTRAINT aimos_authorization_predecessor_shape;
ALTER TABLE public.aimos_authorization_events
  VALIDATE CONSTRAINT aimos_authorization_predecessor_fkey;

DO $recall_authorization_topology_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_recall_authorization_events'::regclass
       AND conname = 'aimos_recall_authorization_predecessor_fkey'
  ) THEN
    ALTER TABLE public.aimos_recall_authorization_events
      ADD CONSTRAINT aimos_recall_authorization_predecessor_fkey
      FOREIGN KEY (company_id, subject_agent_id, subject_valid_from, prev_mutation_hash)
      REFERENCES public.aimos_recall_authorization_events
        (company_id, subject_agent_id, subject_valid_from, mutation_hash)
      ON DELETE RESTRICT
      DEFERRABLE INITIALLY DEFERRED
      NOT VALID;
  END IF;
END
$recall_authorization_topology_constraints$;

ALTER TABLE public.aimos_recall_authorization_events
  VALIDATE CONSTRAINT aimos_recall_authorization_predecessor_fkey;

COMMENT ON COLUMN public.aimos_authorization_events.created_at IS
  'Immutable audit timestamp only. Effective capability order is the verified prev_mutation_hash topology.';

COMMENT ON COLUMN public.aimos_authorization_events.authorization_event_id IS
  'Stable row identifier only. It is never authorization order.';

COMMENT ON COLUMN public.aimos_recall_authorization_events.created_at IS
  'Immutable audit timestamp only. Effective memory-access order is the verified prev_mutation_hash topology.';

COMMENT ON COLUMN public.aimos_recall_authorization_events.recall_authorization_event_id IS
  'Stable row identifier only. It is never authorization order.';

COMMENT ON CONSTRAINT aimos_authorization_predecessor_fkey
  ON public.aimos_authorization_events IS
  'Every non-genesis capability event names a retained predecessor in the same company, subject, exact identity epoch, and capability stream; runtime verification rejects zero/multiple heads, forks, cycles, and disconnected histories.';

COMMENT ON CONSTRAINT aimos_recall_authorization_predecessor_fkey
  ON public.aimos_recall_authorization_events IS
  'Every non-genesis master-signed memory-access event names a retained predecessor in the same company, subject, and exact identity epoch.';
