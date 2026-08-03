-- 058-governor-config-runtime-acl.sql
-- The signed append-only governor ledger is authority only after its complete
-- cryptographic chain is verified. Runtime principals may read retained rows;
-- they may not forge, edit, delete, or truncate the authority stream.

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON aimos_governor_config
  FROM PUBLIC, aimos_app, agent_runtime;
REVOKE ALL PRIVILEGES ON SEQUENCE aimos_governor_config_config_id_seq
  FROM PUBLIC, aimos_app, agent_runtime;
GRANT SELECT ON aimos_governor_config TO agent_runtime;
