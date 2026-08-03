-- 060-retire-capability-decay-model.sql
-- The legacy capability-tracking service contained an unsupported exponential
-- forgetting model and never received live observations. Retain any historical
-- diagnostic rows, but remove the table from runtime authority without deleting
-- or rewriting them.

REVOKE ALL PRIVILEGES ON capability_tracking FROM PUBLIC, aimos_app, agent_runtime;
REVOKE ALL PRIVILEGES ON SEQUENCE capability_tracking_id_seq FROM PUBLIC, aimos_app, agent_runtime;

COMMENT ON TABLE capability_tracking IS
  'RETIRED historical diagnostic state. Not memory authority and not a source of age-based decay, suppression, routing, or authorization.';
