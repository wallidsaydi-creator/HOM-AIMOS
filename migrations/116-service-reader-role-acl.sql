-- Stage a non-superuser identity for boot-critical verified reads.
-- The role is deliberately NOLOGIN until a separately signed credential
-- ceremony and SCRAM-only PostgreSQL admission have passed in a disposable
-- AIMOS cluster. This migration does not change the current serving pool.

DO $service_reader_role$
DECLARE
  reader pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO reader FROM pg_roles WHERE rolname = 'aimos_service_reader';
  IF NOT FOUND THEN
    CREATE ROLE aimos_service_reader
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
      NOBYPASSRLS NOINHERIT;
    SELECT * INTO reader FROM pg_roles WHERE rolname = 'aimos_service_reader';
  END IF;
  IF reader.rolcanlogin OR reader.rolsuper OR reader.rolcreatedb
     OR reader.rolcreaterole OR reader.rolreplication OR reader.rolbypassrls
     OR reader.rolinherit THEN
    RAISE EXCEPTION 'service_reader_role_attributes_invalid';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members
     WHERE member = reader.oid OR roleid = reader.oid
  ) THEN
    RAISE EXCEPTION 'service_reader_role_membership_forbidden';
  END IF;
END
$service_reader_role$;

REVOKE ALL PRIVILEGES ON SCHEMA public FROM aimos_service_reader;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM aimos_service_reader;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM aimos_service_reader;
GRANT USAGE ON SCHEMA public TO aimos_service_reader;

-- These columns are consumed by master/Housekeeper certificate verification,
-- revocation verification, and the signed system-config snapshot at boot.
GRANT SELECT (id, master_pubkey, fingerprint)
  ON public.aimos_master_identity TO aimos_service_reader;
GRANT SELECT (agent_id, cert, pubkey, valid_from, valid_until)
  ON public.agent_identity TO aimos_service_reader;
GRANT SELECT (
  agent_id, agent_valid_from, master_identity_id, master_fingerprint,
  target_cert_hash, prior_identity_hash, signed_body, content_hash,
  mutation_hash, ts_signed, nonce, sig
) ON public.aimos_agent_revocation_events TO aimos_service_reader;
GRANT SELECT (
  config_id, config_key, value_text, cert_fingerprint, content_hash,
  mutation_hash, prev_mutation_hash, nonce, ts_signed, sig,
  is_genesis, body_json, created_at
) ON public.aimos_system_config TO aimos_service_reader;

-- Stage a fixed-company boundary for any later SELECT grant on every current
-- forced-RLS table. The existing permissive company-context policy and this
-- restrictive policy both have to pass. Changing a session GUC alone cannot
-- widen this role beyond the installation's canonical company.
DO $service_reader_rls$
DECLARE
  relation_name text;
  relation_oid oid;
  forced_rls boolean;
  reader_oid oid := (SELECT oid FROM pg_roles WHERE rolname = 'aimos_service_reader');
  policy_row record;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'aimos_action_origin_verdicts', 'aimos_cognitive_weight_baselines',
    'aimos_cognitive_weight_projections', 'aimos_events', 'aimos_memories',
    'aimos_memory_epistemic_classifications', 'aimos_memory_origin_bindings',
    'aimos_origin_elevations', 'aimos_origin_ledger_entries',
    'aimos_request_receipts', 'dream_summary_layers', 'entity_memory_edges',
    'integration_tokens', 'procedural_skills', 'recommendation_log',
    'retrieval_pheromones', 'scheduled_tasks'
  ] LOOP
    SELECT c.oid, c.relrowsecurity AND c.relforcerowsecurity
      INTO relation_oid, forced_rls
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = relation_name
       AND c.relkind IN ('r', 'p');
    IF relation_oid IS NULL THEN
      RAISE EXCEPTION 'service_reader_rls_relation_missing:%', relation_name;
    END IF;
    IF NOT forced_rls OR NOT EXISTS (
      SELECT 1 FROM pg_policy p
       WHERE p.polrelid = relation_oid AND p.polpermissive
         AND p.polcmd IN ('*', 'r')
         AND pg_get_expr(p.polqual, p.polrelid) =
           '(company_id = current_setting(''app.current_client_id''::text, true))'
    ) THEN
      RAISE EXCEPTION 'service_reader_existing_company_policy_invalid:%', relation_name;
    END IF;
    SELECT p.polpermissive, p.polcmd, p.polroles,
           pg_get_expr(p.polqual, p.polrelid) AS predicate
      INTO policy_row FROM pg_policy p
     WHERE p.polrelid = relation_oid
       AND p.polname = 'aimos_service_reader_hom_only';
    IF NOT FOUND THEN
      EXECUTE format(
        'CREATE POLICY aimos_service_reader_hom_only ON public.%I AS RESTRICTIVE FOR SELECT TO aimos_service_reader USING (company_id = %L)',
        relation_name, 'hom'
      );
      SELECT p.polpermissive, p.polcmd, p.polroles,
             pg_get_expr(p.polqual, p.polrelid) AS predicate
        INTO policy_row FROM pg_policy p
       WHERE p.polrelid = relation_oid
         AND p.polname = 'aimos_service_reader_hom_only';
    END IF;
    IF policy_row.polpermissive OR policy_row.polcmd <> 'r'
       OR policy_row.polroles <> ARRAY[reader_oid]::oid[]
       OR policy_row.predicate <> '(company_id = ''hom''::text)' THEN
      RAISE EXCEPTION 'service_reader_rls_policy_invalid:%', relation_name;
    END IF;
  END LOOP;
END
$service_reader_rls$;

DO $service_reader_acl$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class relation
    JOIN pg_namespace schema ON schema.oid = relation.relnamespace
    WHERE schema.nspname = 'public' AND relation.relkind IN ('r', 'p')
      AND (has_table_privilege('aimos_service_reader', relation.oid, 'INSERT')
        OR has_table_privilege('aimos_service_reader', relation.oid, 'UPDATE')
        OR has_table_privilege('aimos_service_reader', relation.oid, 'DELETE')
        OR has_table_privilege('aimos_service_reader', relation.oid, 'TRUNCATE'))
  ) THEN
    RAISE EXCEPTION 'service_reader_write_privilege_forbidden';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class relation
    JOIN pg_namespace schema ON schema.oid = relation.relnamespace
    WHERE schema.nspname = 'public' AND relation.relkind IN ('r', 'p')
      AND relation.relname NOT IN (
        'aimos_master_identity', 'agent_identity',
        'aimos_agent_revocation_events', 'aimos_system_config'
      )
      AND has_any_column_privilege('aimos_service_reader', relation.oid, 'SELECT')
  ) THEN
    RAISE EXCEPTION 'service_reader_unscoped_select_forbidden';
  END IF;
END
$service_reader_acl$;
