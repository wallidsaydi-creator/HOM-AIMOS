-- Retrieval pheromones are a bounded positive projection of signed recall
-- evidence. The restricted housekeeper lane may only read, insert, and raise
-- tau inside the same transaction that appends the cryptographic event.

ALTER TABLE public.retrieval_pheromones ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.retrieval_pheromones FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS retrieval_pheromones_company_isolation ON public.retrieval_pheromones;
CREATE POLICY retrieval_pheromones_company_isolation
  ON public.retrieval_pheromones
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

DO $pheromone_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE ALL ON public.retrieval_pheromones FROM agent_runtime;
    GRANT SELECT, INSERT ON public.retrieval_pheromones TO agent_runtime;
    GRANT UPDATE (tau, updated_at) ON public.retrieval_pheromones TO agent_runtime;
    GRANT USAGE, SELECT ON SEQUENCE public.retrieval_pheromones_id_seq TO agent_runtime;
    GRANT UPDATE (retrieval_weight) ON public.aimos_memories TO agent_runtime;
  END IF;
END
$pheromone_acl$;

COMMENT ON TABLE public.retrieval_pheromones IS
  'Positive-only materialized co-retrieval projection; every mutation is atomic with a housekeeper-signed aimos_events proof.';
