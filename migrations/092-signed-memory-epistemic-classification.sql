-- Native retained-memory epistemic classification chain.
--
-- Classification is independent of admission and canonical content. A memory
-- remains retained with its original value/type/scope. This migration adds an
-- append-only signed classification history and a current projection consumed
-- by recall. Persistent retrieval-weight mutation remains owned by the existing
-- certified cognitive-weight chain.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE public.aimos_memories
  ADD COLUMN IF NOT EXISTS current_epistemic_label text NOT NULL DEFAULT 'unverified',
  ADD COLUMN IF NOT EXISTS current_epistemic_confidence_milli integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS current_epistemic_event_id uuid;

DO $memory_epistemic_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_memories_epistemic_label_valid'
       AND conrelid = 'public.aimos_memories'::regclass
  ) THEN
    ALTER TABLE public.aimos_memories
      ADD CONSTRAINT aimos_memories_epistemic_label_valid CHECK (
        current_epistemic_label IN (
          'unverified', 'supported', 'disputed', 'poison_suspect',
          'poison_likely', 'poison_confirmed', 'poison_refuted'
        )
      );
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_memories_epistemic_confidence_bound'
       AND conrelid = 'public.aimos_memories'::regclass
  ) THEN
    ALTER TABLE public.aimos_memories
      ADD CONSTRAINT aimos_memories_epistemic_confidence_bound CHECK (
        current_epistemic_confidence_milli BETWEEN 0 AND 1000
      );
  END IF;
END
$memory_epistemic_constraints$;

CREATE TABLE IF NOT EXISTS public.aimos_memory_epistemic_classifications (
  classification_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id text NOT NULL,
  memory_id uuid NOT NULL,
  label text NOT NULL,
  confidence_milli integer NOT NULL,
  authority_event_id uuid NOT NULL UNIQUE,
  event_mutation_hash bytea NOT NULL,
  live_content_hash bytea NOT NULL,
  prev_classification_hash bytea,
  classification_hash bytea NOT NULL UNIQUE,
  classified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT aimos_memory_epistemic_memory_fk
    FOREIGN KEY (memory_id) REFERENCES public.aimos_memories(id) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_epistemic_event_fk
    FOREIGN KEY (authority_event_id) REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  CONSTRAINT aimos_memory_epistemic_label_valid CHECK (
    label IN (
      'unverified', 'supported', 'disputed', 'poison_suspect',
      'poison_likely', 'poison_confirmed', 'poison_refuted'
    )
  ),
  CONSTRAINT aimos_memory_epistemic_confidence_bound
    CHECK (confidence_milli BETWEEN 0 AND 1000),
  CONSTRAINT aimos_memory_epistemic_event_hash_len
    CHECK (octet_length(event_mutation_hash) = 32),
  CONSTRAINT aimos_memory_epistemic_live_hash_len
    CHECK (octet_length(live_content_hash) = 32),
  CONSTRAINT aimos_memory_epistemic_prev_hash_len
    CHECK (prev_classification_hash IS NULL OR octet_length(prev_classification_hash) = 32),
  CONSTRAINT aimos_memory_epistemic_hash_len
    CHECK (octet_length(classification_hash) = 32),
  CONSTRAINT aimos_memory_epistemic_no_fork
    UNIQUE (memory_id, prev_classification_hash)
);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_epistemic_one_genesis
  ON public.aimos_memory_epistemic_classifications (memory_id)
  WHERE prev_classification_hash IS NULL;

CREATE INDEX IF NOT EXISTS aimos_memory_epistemic_company_memory_time
  ON public.aimos_memory_epistemic_classifications
  (company_id, memory_id, classified_at DESC);

DO $memory_epistemic_projection_fk$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'aimos_memories_current_epistemic_event_fk'
       AND conrelid = 'public.aimos_memories'::regclass
  ) THEN
    ALTER TABLE public.aimos_memories
      ADD CONSTRAINT aimos_memories_current_epistemic_event_fk
      FOREIGN KEY (current_epistemic_event_id)
      REFERENCES public.aimos_events(id) ON DELETE RESTRICT;
  END IF;
END
$memory_epistemic_projection_fk$;

ALTER TABLE public.aimos_memory_epistemic_classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_memory_epistemic_classifications FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS aimos_memory_epistemic_company_isolation
  ON public.aimos_memory_epistemic_classifications;
CREATE POLICY aimos_memory_epistemic_company_isolation
  ON public.aimos_memory_epistemic_classifications
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

CREATE OR REPLACE FUNCTION public.apply_signed_memory_epistemic_classification(
  p_memory_id uuid,
  p_label text,
  p_confidence_milli integer,
  p_authority_event_id uuid,
  p_live_content_hash bytea
) RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  v_memory_hash bytea;
  v_event record;
  v_prev_hash bytea;
  v_head_count integer;
  v_classification_hash bytea;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'epistemic_classification_company_scope_required';
  END IF;
  IF current_setting('app.current_agent_id', true) <> 'housekeeper' THEN
    RAISE EXCEPTION 'epistemic_classification_housekeeper_scope_required';
  END IF;
  IF p_label NOT IN (
    'unverified', 'supported', 'disputed', 'poison_suspect',
    'poison_likely', 'poison_confirmed', 'poison_refuted'
  ) THEN
    RAISE EXCEPTION 'epistemic_classification_label_invalid';
  END IF;
  IF p_confidence_milli < 0 OR p_confidence_milli > 1000 THEN
    RAISE EXCEPTION 'epistemic_classification_confidence_invalid';
  END IF;
  IF p_live_content_hash IS NULL OR octet_length(p_live_content_hash) <> 32 THEN
    RAISE EXCEPTION 'epistemic_classification_live_hash_invalid';
  END IF;

  SELECT content_hash
    INTO v_memory_hash
    FROM public.aimos_memories
   WHERE id = p_memory_id AND company_id = v_company_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'epistemic_classification_memory_not_found'; END IF;
  IF v_memory_hash IS NULL OR v_memory_hash <> p_live_content_hash THEN
    RAISE EXCEPTION 'epistemic_classification_memory_hash_mismatch';
  END IF;

  SELECT e.mutation_hash, e.metadata, e.signer_agent_id, e.proof_required
    INTO v_event
    FROM public.aimos_events e
   WHERE e.id = p_authority_event_id
     AND e.company_id = v_company_id
     AND e.operation = 'memory_epistemic_classified';
  IF NOT FOUND
     OR v_event.proof_required IS NOT TRUE
     OR v_event.signer_agent_id <> 'housekeeper'
     OR v_event.metadata->>'schema' <> 'aimos.memory-epistemic-classification/v1'
     OR v_event.metadata->>'memory_id' <> p_memory_id::text
     OR v_event.metadata->>'live_content_hash' <> encode(p_live_content_hash, 'hex')
     OR v_event.metadata->>'label' <> p_label
     OR (v_event.metadata->>'confidence_milli')::integer <> p_confidence_milli THEN
    RAISE EXCEPTION 'epistemic_classification_signed_event_invalid';
  END IF;

  SELECT count(*)::integer, (array_agg(c.classification_hash))[1]
    INTO v_head_count, v_prev_hash
    FROM public.aimos_memory_epistemic_classifications c
   WHERE c.company_id = v_company_id
     AND c.memory_id = p_memory_id
     AND NOT EXISTS (
       SELECT 1
         FROM public.aimos_memory_epistemic_classifications successor
        WHERE successor.company_id = c.company_id
          AND successor.memory_id = c.memory_id
          AND successor.prev_classification_hash = c.classification_hash
     );
  IF v_head_count > 1 THEN
    RAISE EXCEPTION 'epistemic_classification_existing_fork';
  END IF;
  IF v_head_count = 0 THEN v_prev_hash := decode(repeat('00', 32), 'hex'); END IF;

  v_classification_hash := digest(
    convert_to('aimos.memory-epistemic/v1', 'UTF8') || E'\\000'::bytea
    || uuid_send(p_memory_id)
    || int4send(octet_length(convert_to(p_label, 'UTF8')))
    || convert_to(p_label, 'UTF8')
    || int8send(p_confidence_milli::bigint)
    || p_live_content_hash
    || v_event.mutation_hash
    || v_prev_hash,
    'sha256'
  );

  INSERT INTO public.aimos_memory_epistemic_classifications (
    company_id, memory_id, label, confidence_milli, authority_event_id,
    event_mutation_hash, live_content_hash, prev_classification_hash,
    classification_hash
  ) VALUES (
    v_company_id, p_memory_id, p_label, p_confidence_milli,
    p_authority_event_id, v_event.mutation_hash, p_live_content_hash,
    CASE WHEN v_prev_hash = decode(repeat('00', 32), 'hex') THEN NULL ELSE v_prev_hash END,
    v_classification_hash
  );

  UPDATE public.aimos_memories
     SET current_epistemic_label = p_label,
         current_epistemic_confidence_milli = p_confidence_milli,
         current_epistemic_event_id = p_authority_event_id
   WHERE id = p_memory_id AND company_id = v_company_id;

  RETURN v_classification_hash;
END
$function$;

CREATE OR REPLACE FUNCTION public.verify_memory_epistemic_classification_chain(
  p_memory_id uuid
) RETURNS TABLE(
  ok boolean,
  chain_length integer,
  current_label text,
  current_confidence_milli integer,
  head_hash bytea,
  reason text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_company_id text;
  v_live_hash bytea;
  v_projected_label text;
  v_projected_confidence integer;
  v_projected_event_id uuid;
  v_total integer;
  v_length integer := 0;
  v_prev bytea := decode(repeat('00', 32), 'hex');
  v_expected bytea;
  v_last_label text := 'unverified';
  v_last_confidence integer := 0;
  v_last_event_id uuid := NULL;
  row record;
BEGIN
  v_company_id := current_setting('app.current_client_id', true);
  IF v_company_id IS NULL OR v_company_id = '' THEN
    RAISE EXCEPTION 'epistemic_verifier_company_scope_required';
  END IF;

  SELECT content_hash, current_epistemic_label,
         current_epistemic_confidence_milli, current_epistemic_event_id
    INTO v_live_hash, v_projected_label, v_projected_confidence, v_projected_event_id
    FROM public.aimos_memories
   WHERE id = p_memory_id AND company_id = v_company_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 0, NULL::text, NULL::integer, NULL::bytea,
                        'memory_not_found'::text;
    RETURN;
  END IF;

  SELECT count(*)::integer INTO v_total
    FROM public.aimos_memory_epistemic_classifications
   WHERE company_id = v_company_id AND memory_id = p_memory_id;

  FOR row IN
    WITH RECURSIVE walk AS (
      SELECT c.*, 1 AS depth
        FROM public.aimos_memory_epistemic_classifications c
       WHERE c.company_id = v_company_id
         AND c.memory_id = p_memory_id
         AND c.prev_classification_hash IS NULL
      UNION ALL
      SELECT successor.*, walk.depth + 1
        FROM public.aimos_memory_epistemic_classifications successor
        JOIN walk
          ON successor.company_id = walk.company_id
         AND successor.memory_id = walk.memory_id
         AND successor.prev_classification_hash = walk.classification_hash
    )
    SELECT walk.*,
           event.metadata AS event_metadata,
           event.mutation_hash AS signed_event_mutation_hash,
           event.signer_agent_id,
           event.proof_required
      FROM walk
      LEFT JOIN public.aimos_events event
        ON event.id = walk.authority_event_id
       AND event.company_id = walk.company_id
       AND event.operation = 'memory_epistemic_classified'
     ORDER BY walk.depth
  LOOP
    IF row.prev_classification_hash IS DISTINCT FROM
       (CASE WHEN v_length = 0 THEN NULL::bytea ELSE v_prev END) THEN
      RETURN QUERY SELECT false, v_length, v_last_label, v_last_confidence,
                          CASE WHEN v_length = 0 THEN NULL::bytea ELSE v_prev END,
                          'predecessor_mismatch'::text;
      RETURN;
    END IF;
    IF row.live_content_hash <> v_live_hash THEN
      RETURN QUERY SELECT false, v_length, v_last_label, v_last_confidence,
                          CASE WHEN v_length = 0 THEN NULL::bytea ELSE v_prev END,
                          'live_content_hash_mismatch'::text;
      RETURN;
    END IF;
    IF row.proof_required IS NOT TRUE
       OR row.signer_agent_id <> 'housekeeper'
       OR row.signed_event_mutation_hash IS NULL
       OR row.event_mutation_hash <> row.signed_event_mutation_hash
       OR row.event_metadata->>'schema' <> 'aimos.memory-epistemic-classification/v1'
       OR row.event_metadata->>'memory_id' <> p_memory_id::text
       OR row.event_metadata->>'live_content_hash' <> encode(v_live_hash, 'hex')
       OR row.event_metadata->>'label' <> row.label
       OR (row.event_metadata->>'confidence_milli')::integer <> row.confidence_milli THEN
      RETURN QUERY SELECT false, v_length, v_last_label, v_last_confidence,
                          CASE WHEN v_length = 0 THEN NULL::bytea ELSE v_prev END,
                          'signed_event_mismatch'::text;
      RETURN;
    END IF;

    v_expected := digest(
      convert_to('aimos.memory-epistemic/v1', 'UTF8') || E'\\000'::bytea
      || uuid_send(p_memory_id)
      || int4send(octet_length(convert_to(row.label, 'UTF8')))
      || convert_to(row.label, 'UTF8')
      || int8send(row.confidence_milli::bigint)
      || row.live_content_hash
      || row.event_mutation_hash
      || v_prev,
      'sha256'
    );
    IF row.classification_hash <> v_expected THEN
      RETURN QUERY SELECT false, v_length, v_last_label, v_last_confidence,
                          CASE WHEN v_length = 0 THEN NULL::bytea ELSE v_prev END,
                          'classification_hash_mismatch'::text;
      RETURN;
    END IF;

    v_length := v_length + 1;
    v_prev := row.classification_hash;
    v_last_label := row.label;
    v_last_confidence := row.confidence_milli;
    v_last_event_id := row.authority_event_id;
  END LOOP;

  IF v_length <> v_total THEN
    RETURN QUERY SELECT false, v_length, v_last_label, v_last_confidence,
                        CASE WHEN v_length = 0 THEN NULL::bytea ELSE v_prev END,
                        'fork_or_disconnected_history'::text;
    RETURN;
  END IF;
  IF v_length = 0 THEN
    IF v_projected_label <> 'unverified'
       OR v_projected_confidence <> 0
       OR v_projected_event_id IS NOT NULL THEN
      RETURN QUERY SELECT false, 0, v_projected_label, v_projected_confidence,
                          NULL::bytea, 'unbacked_projection'::text;
      RETURN;
    END IF;
    RETURN QUERY SELECT true, 0, 'unverified'::text, 0, NULL::bytea, NULL::text;
    RETURN;
  END IF;
  IF v_projected_label <> v_last_label
     OR v_projected_confidence <> v_last_confidence
     OR v_projected_event_id IS DISTINCT FROM v_last_event_id THEN
    RETURN QUERY SELECT false, v_length, v_last_label, v_last_confidence,
                        v_prev, 'projection_head_mismatch'::text;
    RETURN;
  END IF;

  RETURN QUERY SELECT true, v_length, v_last_label, v_last_confidence,
                      v_prev, NULL::text;
END
$function$;

REVOKE ALL ON public.aimos_memory_epistemic_classifications FROM PUBLIC;
REVOKE ALL ON FUNCTION public.apply_signed_memory_epistemic_classification(
  uuid, text, integer, uuid, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.verify_memory_epistemic_classification_chain(uuid)
  FROM PUBLIC;

DO $memory_epistemic_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    GRANT SELECT ON public.aimos_memory_epistemic_classifications TO agent_runtime;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE
      ON public.aimos_memory_epistemic_classifications FROM agent_runtime;
    REVOKE UPDATE (
      current_epistemic_label,
      current_epistemic_confidence_milli,
      current_epistemic_event_id
    ) ON public.aimos_memories FROM agent_runtime;
    GRANT EXECUTE ON FUNCTION public.apply_signed_memory_epistemic_classification(
      uuid, text, integer, uuid, bytea
    ) TO agent_runtime;
    GRANT EXECUTE ON FUNCTION public.verify_memory_epistemic_classification_chain(uuid)
      TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE
      ON public.aimos_memory_epistemic_classifications FROM aimos_app;
    REVOKE UPDATE (
      current_epistemic_label,
      current_epistemic_confidence_milli,
      current_epistemic_event_id
    ) ON public.aimos_memories FROM aimos_app;
  END IF;
END
$memory_epistemic_acl$;

COMMENT ON TABLE public.aimos_memory_epistemic_classifications IS
  'Append-only housekeeper-signed epistemic labels. Classification never changes canonical content, existence, or eligibility.';
COMMENT ON COLUMN public.aimos_memories.current_epistemic_label IS
  'Current projection of the append-only epistemic classification chain; unverified is not a claim of falsehood or truth.';
