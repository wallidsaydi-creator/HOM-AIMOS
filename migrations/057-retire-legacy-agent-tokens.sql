-- 057-retire-legacy-agent-tokens.sql
--
-- Agent identity and authorization are certificate-envelope only. The legacy
-- bearer-token table is retained as historical non-memory state, but no runtime
-- principal may read it, append to it, or mutate it. No row is deleted.

REVOKE ALL PRIVILEGES ON TABLE agent_tokens FROM PUBLIC, aimos_app, agent_runtime;
REVOKE ALL PRIVILEGES ON SEQUENCE agent_tokens_id_seq FROM PUBLIC, aimos_app, agent_runtime;

COMMENT ON TABLE agent_tokens IS
  'RETIRED. Historical legacy bearer-token rows only. AIMOS identity is agent_identity certificate epochs; authorization is the signed append-only aimos_authorization_events ledger.';
