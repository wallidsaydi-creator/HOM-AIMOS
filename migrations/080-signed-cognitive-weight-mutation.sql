-- One native cognitive-weight mutation boundary.
--
-- A retrieval weight is mutable in both directions inside [0.1, 3.0], but a
-- database role may not change it directly. The application first appends a
-- housekeeper-signed REWEIGHT provenance node containing the exact old/new
-- state, then this database primitive atomically consumes that node once and
-- applies the projection. Memory content and eligibility remain retained.

ALTER TABLE public.aimos_memory_provenance
  ADD COLUMN binding_schema_version smallint NOT NULL DEFAULT 1;

ALTER TABLE public.aimos_memory_provenance
  ADD CONSTRAINT aimos_memory_provenance_binding_schema_version
  CHECK (binding_schema_version IN (1, 2));

CREATE TABLE public.aimos_cognitive_weight_projections (
  projection_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id text NOT NULL,
  memory_id uuid NOT NULL,
  provenance_mutation_hash bytea NOT NULL,
  old_weight real NOT NULL,
  new_weight real NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT aimos_cognitive_weight_projection_bound
    CHECK (old_weight >= 0.1 AND old_weight <= 3.0
       AND new_weight >= 0.1 AND new_weight <= 3.0),
  CONSTRAINT aimos_cognitive_weight_projection_once
    UNIQUE (memory_id, provenance_mutation_hash),
  CONSTRAINT aimos_cognitive_weight_projection_provenance_fk
    FOREIGN KEY (memory_id, provenance_mutation_hash)
    REFERENCES public.aimos_memory_provenance (memory_id, mutation_hash)
    ON DELETE RESTRICT
);

ALTER TABLE public.aimos_cognitive_weight_projections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_cognitive_weight_projections FORCE ROW LEVEL SECURITY;

CREATE POLICY aimos_cognitive_weight_projection_company_isolation
  ON public.aimos_cognitive_weight_projections
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

CREATE OR REPLACE FUNCTION public.apply_signed_cognitive_reweight(
  p_memory_id uuid,
  p_old_weight double precision,
  p_new_weight double precision,
  p_provenance_mutation_hash bytea
) RETURNS real
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  v_current_weight real;
  v_body jsonb;
  v_applied real;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'cognitive_company_scope_required';
  END IF;
  IF current_setting('app.current_agent_id', true) <> 'housekeeper' THEN
    RAISE EXCEPTION 'cognitive_housekeeper_scope_required';
  END IF;
  IF p_old_weight < 0.1 OR p_old_weight > 3.0
     OR p_new_weight < 0.1 OR p_new_weight > 3.0 THEN
    RAISE EXCEPTION 'cognitive_weight_out_of_bounds';
  END IF;

  SELECT m.retrieval_weight
    INTO v_current_weight
    FROM public.aimos_memories m
   WHERE m.id = p_memory_id
     AND m.company_id = v_company_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cognitive_memory_not_found';
  END IF;
  IF abs(v_current_weight::double precision - p_old_weight) > 0.000001 THEN
    RAISE EXCEPTION 'cognitive_old_weight_mismatch';
  END IF;

  SELECT p.body_json
    INTO v_body
    FROM public.aimos_memory_provenance p
   WHERE p.memory_id = p_memory_id
     AND p.mutation_hash = p_provenance_mutation_hash
     AND p.event_type = 'REWEIGHT'
     AND p.binding_schema_version = 2
     AND p.agent_id = 'housekeeper'
     AND p.backfilled = false
     AND p.sig IS NOT NULL
     AND octet_length(p.sig) = 64
     AND NOT EXISTS (
       SELECT 1
         FROM public.aimos_memory_provenance successor
        WHERE successor.memory_id = p.memory_id
          AND successor.prev_mutation_hash = p.mutation_hash
     );
  IF NOT FOUND OR v_body IS NULL THEN
    RAISE EXCEPTION 'signed_cognitive_provenance_required';
  END IF;
  IF v_body->>'event_type' <> 'REWEIGHT'
     OR v_body->>'memory_id' <> p_memory_id::text
     OR abs((v_body->>'old_weight')::double precision - p_old_weight) > 0.000001
     OR abs((v_body->>'new_weight')::double precision - p_new_weight) > 0.000001 THEN
    RAISE EXCEPTION 'signed_cognitive_transition_mismatch';
  END IF;

  INSERT INTO public.aimos_cognitive_weight_projections
    (company_id, memory_id, provenance_mutation_hash, old_weight, new_weight)
  VALUES
    (v_company_id, p_memory_id, p_provenance_mutation_hash, p_old_weight, p_new_weight);

  UPDATE public.aimos_memories
     SET retrieval_weight = p_new_weight::real
   WHERE id = p_memory_id
     AND company_id = v_company_id
  RETURNING retrieval_weight INTO v_applied;
  RETURN v_applied;
END
$function$;

REVOKE ALL ON FUNCTION public.apply_signed_cognitive_reweight(
  uuid, double precision, double precision, bytea
) FROM PUBLIC;

DO $cognitive_acl$
BEGIN
  REVOKE UPDATE (retrieval_weight) ON public.aimos_memories FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE UPDATE (retrieval_weight) ON public.aimos_memories FROM agent_runtime;
    GRANT SELECT, INSERT ON public.aimos_cognitive_weight_projections TO agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_cognitive_weight_projections FROM agent_runtime;
    GRANT EXECUTE ON FUNCTION public.apply_signed_cognitive_reweight(
      uuid, double precision, double precision, bytea
    ) TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE UPDATE (retrieval_weight) ON public.aimos_memories FROM aimos_app;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_cognitive_weight_projections FROM aimos_app;
  END IF;
END
$cognitive_acl$;

COMMENT ON TABLE public.aimos_cognitive_weight_projections IS
  'Append-only applications of exact housekeeper-signed REWEIGHT provenance. This projection changes recall frequency only; no memory is deleted, suppressed, expired, or deactivated.';

COMMENT ON FUNCTION public.apply_signed_cognitive_reweight(
  uuid, double precision, double precision, bytea
) IS
  'Sole restricted cognitive-weight mutation primitive. Consumes one terminal signed REWEIGHT transition exactly once and enforces [0.1,3.0].';
