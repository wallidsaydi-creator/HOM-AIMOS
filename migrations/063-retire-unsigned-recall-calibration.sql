-- Retain the historical calibration tables but remove them from runtime
-- authority. Live calibration is reconstructed from the verified housekeeper
-- event stream by services/retrieval/recall-calibrator.js.

REVOKE ALL ON public.recall_calibration FROM PUBLIC;
REVOKE ALL ON public.recall_observations FROM PUBLIC;

DO $legacy_calibration_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.recall_calibration FROM agent_runtime;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.recall_observations FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.recall_calibration FROM aimos_app;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.recall_observations FROM aimos_app;
  END IF;
END
$legacy_calibration_acl$;

COMMENT ON TABLE public.recall_calibration IS
  'Retained legacy unsigned projection; never runtime authority after migration 063.';
COMMENT ON TABLE public.recall_observations IS
  'Retained legacy unsigned observations; new feedback is cert-bound in the universal event ledger after migration 063.';
