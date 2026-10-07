-- Forward ACL for a non-superuser serving cutover. Neither role can log in
-- until independent signed credential custody and SCRAM admission are proven.
-- The service reader has only source-inventoried SELECT access. The separate
-- identity writer is for the signed HTTP agent-enrollment transaction, which
-- atomically appends an agent_identity row and a signed aimos_events terminal.

-- The migration runner applies db/signed-event-bytes.sql after all numbered
-- migrations. Fresh databases need this column before column-level grants;
-- the native SQL later installs its exact constraints and verifier functions.
ALTER TABLE public.aimos_events ADD COLUMN IF NOT EXISTS signed_body_bytes bytea;
DO $signed_event_column$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
     WHERE attrelid = 'public.aimos_events'::regclass
       AND attname = 'signed_body_bytes' AND atttypid = 'bytea'::regtype
       AND NOT attisdropped
  ) THEN RAISE EXCEPTION 'signed_event_bytes_column_invalid'; END IF;
END
$signed_event_column$;

DO $serving_roles$
DECLARE
  identity_writer pg_roles%ROWTYPE;
  reader pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO reader FROM pg_roles WHERE rolname = 'aimos_service_reader';
  IF NOT FOUND OR reader.rolcanlogin OR reader.rolsuper OR reader.rolbypassrls
     OR reader.rolcreatedb OR reader.rolcreaterole OR reader.rolreplication
     OR reader.rolinherit THEN
    RAISE EXCEPTION 'service_reader_stage_invalid';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = reader.oid OR roleid = reader.oid) THEN
    RAISE EXCEPTION 'service_reader_membership_forbidden';
  END IF;
  SELECT * INTO identity_writer FROM pg_roles WHERE rolname = 'aimos_identity_writer';
  IF NOT FOUND THEN
    CREATE ROLE aimos_identity_writer
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
      NOBYPASSRLS NOINHERIT;
    SELECT * INTO identity_writer FROM pg_roles WHERE rolname = 'aimos_identity_writer';
  END IF;
  IF identity_writer.rolcanlogin OR identity_writer.rolsuper
     OR identity_writer.rolbypassrls OR identity_writer.rolcreatedb
     OR identity_writer.rolcreaterole OR identity_writer.rolreplication
     OR identity_writer.rolinherit THEN
    RAISE EXCEPTION 'identity_writer_role_attributes_invalid';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members
     WHERE member = identity_writer.oid OR roleid = identity_writer.oid
  ) THEN
    RAISE EXCEPTION 'identity_writer_role_membership_forbidden';
  END IF;
END
$serving_roles$;

REVOKE ALL PRIVILEGES ON SCHEMA public FROM aimos_service_reader, aimos_identity_writer;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM aimos_service_reader, aimos_identity_writer;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM aimos_service_reader, aimos_identity_writer;
GRANT USAGE ON SCHEMA public TO aimos_service_reader, aimos_identity_writer;

-- Four boot-signature/config tables retain column-level SELECT. The extra
-- identity columns serve the signed setup/status read paths.
GRANT SELECT (id, master_pubkey, fingerprint)
  ON public.aimos_master_identity TO aimos_service_reader;
GRANT SELECT (agent_id, cert, pubkey, device_fp, valid_from, valid_until,
              issued_at, chain_head)
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

-- Every table below has a server-reachable primary SELECT in the Phase 0
-- caller inventory. The six FORCE RLS tables among them retain the hom-only
-- restrictive policy from migration 116. Absent optional legacy tables are
-- intentionally excluded rather than granted speculatively.
GRANT SELECT ON
  public.agent_messages, public.agent_profiles,
  public.agent_routing_policy, public.agent_runs, public.agent_state,
  public.agent_trust, public.ai_debt_register, public.aimos_capsules,
  public.aimos_conflicts, public.aimos_directives, public.aimos_events,
  public.aimos_governor_config, public.aimos_memories,
  public.aimos_recall_authorization_events,
  public.aimos_retrieval_drift_snapshots, public.concept_edges,
  public.concept_graph_builds, public.directive_claims,
  public.dream_summary_layers, public.embedding_projections,
  public.entity_memory_edges, public.fragility_labels,
  public.intervention_cost_matrix, public.memory_cross_refs,
  public.memory_valence_ledger, public.model_registry,
  public.procedural_skills, public.quim_index, public.quim_prototypes,
  public.recommendation_log, public.rule_hierarchy,
  public.session_energy, public.skill_bank, public.skill_running_stats,
  public.supersession_events
TO aimos_service_reader;

-- A role-level default supplies the installation's fixed company for
-- existing read-shaped query() call sites. It is not the isolation boundary:
-- migration 116's RESTRICTIVE policies keep this reader inside hom even if
-- a credential holder changes the mutable session GUC.
DO $serving_role_defaults$
BEGIN
  EXECUTE format(
    'ALTER ROLE aimos_service_reader IN DATABASE %I SET app.current_client_id = %L',
    current_database(), 'hom'
  );
  EXECUTE format(
    'ALTER ROLE aimos_identity_writer IN DATABASE %I SET app.current_client_id = %L',
    current_database(), 'hom'
  );
END
$serving_role_defaults$;

-- The identity writer is limited to the exact enrollment read and append
-- tables. Event INSERT is column-scoped to the signed native event payload.
GRANT SELECT ON public.agent_identity,
  public.aimos_agent_revocation_events, public.aimos_events
TO aimos_identity_writer;
GRANT SELECT (id, master_pubkey, fingerprint)
  ON public.aimos_master_identity TO aimos_identity_writer;
GRANT INSERT (agent_id, pubkey, cert, device_fp, valid_from, valid_until)
  ON public.agent_identity TO aimos_identity_writer;
GRANT INSERT (
  id, ts, company_id, agent_id, operation, key, metadata, parent_event_id,
  ledger_version, ledger_seq, signer_agent_id, signer_valid_from,
  cert_fingerprint, identity_tier, authority_kind, signed_body,
  content_hash, mutation_hash, prev_mutation_hash, ts_signed, nonce, sig,
  signed_body_bytes
) ON public.aimos_events TO aimos_identity_writer;

DO $identity_writer_rls$
DECLARE
  relation_oid oid := 'public.aimos_events'::regclass;
  writer_oid oid := (SELECT oid FROM pg_roles WHERE rolname = 'aimos_identity_writer');
  policy_row record;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c WHERE c.oid = relation_oid
      AND c.relrowsecurity AND c.relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'identity_writer_event_rls_required';
  END IF;
  SELECT p.polpermissive, p.polcmd, p.polroles,
         pg_get_expr(p.polqual, p.polrelid) AS predicate,
         pg_get_expr(p.polwithcheck, p.polrelid) AS check_predicate
    INTO policy_row FROM pg_policy p
   WHERE p.polrelid = relation_oid
     AND p.polname = 'aimos_identity_writer_hom_only';
  IF NOT FOUND THEN
    CREATE POLICY aimos_identity_writer_hom_only ON public.aimos_events
      AS RESTRICTIVE FOR ALL TO aimos_identity_writer
      USING (company_id = 'hom') WITH CHECK (company_id = 'hom');
    SELECT p.polpermissive, p.polcmd, p.polroles,
           pg_get_expr(p.polqual, p.polrelid) AS predicate,
           pg_get_expr(p.polwithcheck, p.polrelid) AS check_predicate
      INTO policy_row FROM pg_policy p
     WHERE p.polrelid = relation_oid
       AND p.polname = 'aimos_identity_writer_hom_only';
  END IF;
  IF policy_row.polpermissive OR policy_row.polcmd <> '*'
     OR policy_row.polroles <> ARRAY[writer_oid]::oid[]
     OR policy_row.predicate <> '(company_id = ''hom''::text)'
     OR policy_row.check_predicate <> '(company_id = ''hom''::text)' THEN
    RAISE EXCEPTION 'identity_writer_hom_policy_invalid';
  END IF;
END
$identity_writer_rls$;

DO $serving_acl_check$
DECLARE
  reader_tables text[] := ARRAY[
    'agent_identity', 'agent_messages', 'agent_profiles',
    'agent_routing_policy', 'agent_runs', 'agent_state', 'agent_trust',
    'ai_debt_register', 'aimos_agent_revocation_events', 'aimos_capsules',
    'aimos_conflicts', 'aimos_directives', 'aimos_events',
    'aimos_governor_config', 'aimos_master_identity', 'aimos_memories',
    'aimos_recall_authorization_events', 'aimos_retrieval_drift_snapshots',
    'aimos_system_config', 'concept_edges', 'concept_graph_builds',
    'directive_claims', 'dream_summary_layers', 'embedding_projections',
    'entity_memory_edges', 'fragility_labels', 'intervention_cost_matrix',
    'memory_cross_refs', 'memory_valence_ledger', 'model_registry',
    'procedural_skills', 'quim_index', 'quim_prototypes',
    'recommendation_log', 'rule_hierarchy', 'session_energy',
    'skill_bank', 'skill_running_stats', 'supersession_events'
  ];
  selected_count integer;
  reader_oid oid := (SELECT oid FROM pg_roles WHERE rolname = 'aimos_service_reader');
  writer_oid oid := (SELECT oid FROM pg_roles WHERE rolname = 'aimos_identity_writer');
  database_oid oid := (SELECT oid FROM pg_database WHERE datname = current_database());
BEGIN
  SELECT count(*) INTO selected_count FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
     AND has_any_column_privilege('aimos_service_reader', c.oid, 'SELECT');
  IF selected_count <> cardinality(reader_tables) OR EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
       AND has_any_column_privilege('aimos_service_reader', c.oid, 'SELECT')
       AND NOT c.relname = ANY(reader_tables)
  ) THEN
    RAISE EXCEPTION 'service_reader_select_surface_invalid';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
       AND (has_any_column_privilege('aimos_service_reader', c.oid, 'INSERT')
         OR has_any_column_privilege('aimos_service_reader', c.oid, 'UPDATE')
         OR has_table_privilege('aimos_service_reader', c.oid, 'DELETE')
         OR has_table_privilege('aimos_service_reader', c.oid, 'TRUNCATE'))
  ) THEN
    RAISE EXCEPTION 'service_reader_write_surface_invalid';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
       AND has_any_column_privilege('aimos_identity_writer', c.oid, 'SELECT')
       AND c.relname NOT IN (
         'agent_identity', 'aimos_agent_revocation_events',
         'aimos_events', 'aimos_master_identity'
       )
  ) THEN
    RAISE EXCEPTION 'identity_writer_select_surface_invalid';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
       AND ((has_any_column_privilege('aimos_identity_writer', c.oid, 'INSERT')
             AND c.relname NOT IN ('agent_identity', 'aimos_events'))
         OR has_any_column_privilege('aimos_identity_writer', c.oid, 'UPDATE')
         OR has_table_privilege('aimos_identity_writer', c.oid, 'DELETE')
         OR has_table_privilege('aimos_identity_writer', c.oid, 'TRUNCATE'))
  ) THEN
    RAISE EXCEPTION 'identity_writer_write_surface_invalid';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_db_role_setting s
     WHERE s.setrole = reader_oid AND s.setdatabase = database_oid
       AND 'app.current_client_id=hom' = ANY(s.setconfig)
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_db_role_setting s
     WHERE s.setrole = writer_oid AND s.setdatabase = database_oid
       AND 'app.current_client_id=hom' = ANY(s.setconfig)
  ) THEN
    RAISE EXCEPTION 'serving_role_company_default_missing';
  END IF;
END
$serving_acl_check$;
