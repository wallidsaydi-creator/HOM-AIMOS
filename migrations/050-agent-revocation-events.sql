-- Revocation is a terminal, master-signed event for one exact identity epoch.
-- Historical agent_identity.revoked_at values remain readable only as legacy
-- metadata. They are not authorization truth; only a verified retained event
-- in this table can terminate an identity epoch.

CREATE TABLE IF NOT EXISTS public.aimos_agent_revocation_events (
  revocation_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id text NOT NULL,
  agent_valid_from timestamptz NOT NULL,
  master_identity_id integer NOT NULL DEFAULT 1,
  master_fingerprint text NOT NULL CHECK (master_fingerprint ~ '^[0-9a-f]{64}$'),
  target_cert_hash bytea NOT NULL CHECK (octet_length(target_cert_hash) = 32),
  prior_identity_hash bytea NOT NULL CHECK (octet_length(prior_identity_hash) = 32),
  signed_body jsonb NOT NULL,
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  mutation_hash bytea NOT NULL CHECK (octet_length(mutation_hash) = 32),
  ts_signed bigint NOT NULL,
  nonce text NOT NULL CHECK (length(nonce) > 0),
  sig bytea NOT NULL CHECK (octet_length(sig) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (agent_id, agent_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from),
  FOREIGN KEY (master_identity_id)
    REFERENCES public.aimos_master_identity(id),
  UNIQUE (agent_id, agent_valid_from),
  UNIQUE (mutation_hash),
  UNIQUE (nonce)
);

COMMENT ON TABLE public.aimos_agent_revocation_events IS
  'Append-only master-signed terminal revocation proof for one exact agent identity epoch.';

DO $revocation_acl$
BEGIN
  REVOKE ALL ON public.aimos_agent_revocation_events FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    GRANT SELECT ON public.aimos_agent_revocation_events TO agent_runtime;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_agent_revocation_events FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_agent_revocation_events FROM aimos_app;
  END IF;
END
$revocation_acl$;
