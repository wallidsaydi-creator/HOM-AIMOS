-- The scheduler projection is retained, company-isolated state. Its authority
-- comes only from housekeeper-signed schedule events in aimos_events. Runtime
-- may create a projection or advance its status atomically with that event; it
-- may never delete, deactivate, truncate, or rewrite the delegated task.

ALTER TABLE public.scheduled_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scheduled_tasks FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scheduled_tasks_company_isolation ON public.scheduled_tasks;
CREATE POLICY scheduled_tasks_company_isolation ON public.scheduled_tasks
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (company_id = current_setting('app.current_client_id', true));

REVOKE ALL ON public.scheduled_tasks FROM PUBLIC;

DO $signed_scheduler_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.scheduled_tasks FROM agent_runtime;
    GRANT SELECT ON public.scheduled_tasks TO agent_runtime;
    GRANT INSERT (
      id, company_id, label, cron_expression, task_description, agent_id,
      is_active, created_at, updated_at
    ) ON public.scheduled_tasks TO agent_runtime;
    GRANT UPDATE (
      last_run_at, last_status, last_error, updated_at
    ) ON public.scheduled_tasks TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.scheduled_tasks FROM aimos_app;
  END IF;
END
$signed_scheduler_acl$;

COMMENT ON TABLE public.scheduled_tasks IS
  'Retained scheduler projection. schedule_created and schedule_run_* events in the verified housekeeper event history are the sole runtime authority.';
