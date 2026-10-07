-- A fresh first-launch enrollment reads the signed master locator and active
-- agent identity through the ordinary service reader. These tables contain
-- public identity/certificate data and Keychain slot names, not private keys.
-- Keep the reader's table set unchanged while completing its column scope.

GRANT SELECT ON public.aimos_master_identity,
  public.agent_identity,
  public.aimos_agent_revocation_events,
  public.aimos_system_config
TO aimos_service_reader;

DO $reader_identity_scope$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'aimos_master_identity', 'agent_identity',
    'aimos_agent_revocation_events', 'aimos_system_config'
  ] LOOP
    IF NOT has_table_privilege('aimos_service_reader',
      format('public.%I', table_name), 'SELECT') THEN
      RAISE EXCEPTION 'service_reader_identity_select_missing:%', table_name;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
       AND (has_any_column_privilege('aimos_service_reader', c.oid, 'INSERT')
         OR has_any_column_privilege('aimos_service_reader', c.oid, 'UPDATE')
         OR has_table_privilege('aimos_service_reader', c.oid, 'DELETE')
         OR has_table_privilege('aimos_service_reader', c.oid, 'TRUNCATE'))
  ) THEN RAISE EXCEPTION 'service_reader_write_surface_invalid'; END IF;
END
$reader_identity_scope$;
