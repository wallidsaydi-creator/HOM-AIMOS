-- Native immutable version topology. A superseding memory must point to a
-- retained predecessor with the same company and key. Each version has at most
-- one successor and each post-version has exactly one recorded incoming edge.

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memories_company_key_id_unique
  ON public.aimos_memories (company_id, key, id);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memories_company_id_unique
  ON public.aimos_memories (company_id, id);

DO $supersession_constraints$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_memories_same_key_predecessor_fkey') THEN
    ALTER TABLE public.aimos_memories
      ADD CONSTRAINT aimos_memories_same_key_predecessor_fkey
      FOREIGN KEY (company_id, key, supersedes_id)
      REFERENCES public.aimos_memories(company_id, key, id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'supersession_events_prior_fkey') THEN
    ALTER TABLE public.supersession_events
      ADD CONSTRAINT supersession_events_prior_fkey
      FOREIGN KEY (company_id, prior_memory_id)
      REFERENCES public.aimos_memories(company_id, id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'supersession_events_post_fkey') THEN
    ALTER TABLE public.supersession_events
      ADD CONSTRAINT supersession_events_post_fkey
      FOREIGN KEY (company_id, post_memory_id)
      REFERENCES public.aimos_memories(company_id, id);
  END IF;
END
$supersession_constraints$;

CREATE UNIQUE INDEX IF NOT EXISTS supersession_events_one_successor_per_prior
  ON public.supersession_events (company_id, prior_memory_id);

CREATE UNIQUE INDEX IF NOT EXISTS supersession_events_one_predecessor_per_post
  ON public.supersession_events (company_id, post_memory_id);
