-- 047-append-only-authorization-events.sql
-- Capabilities are immutable signed grant/revoke events. Current permission is
-- the latest event per (company, subject, capability); no UPSERT or UPDATE.

CREATE TABLE IF NOT EXISTS public.aimos_authorization_events (
  authorization_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id text NOT NULL,
  subject_agent_id text NOT NULL,
  subject_valid_from timestamptz NOT NULL,
  capability text NOT NULL,
  allowed boolean NOT NULL,
  actor_agent_id text NOT NULL,
  actor_valid_from timestamptz NOT NULL,
  cert_fingerprint text NOT NULL CHECK (cert_fingerprint ~ '^[0-9a-f]{64}$'),
  signed_body jsonb NOT NULL,
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  mutation_hash bytea NOT NULL CHECK (octet_length(mutation_hash) = 32),
  prev_mutation_hash bytea,
  ts_signed bigint NOT NULL,
  nonce text NOT NULL,
  sig bytea NOT NULL CHECK (octet_length(sig) = 64),
  identity_tier text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (subject_agent_id, subject_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from),
  FOREIGN KEY (actor_agent_id, actor_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from)
);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_authorization_one_genesis
  ON public.aimos_authorization_events (company_id, subject_agent_id, capability)
  WHERE prev_mutation_hash IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_authorization_one_successor
  ON public.aimos_authorization_events (company_id, subject_agent_id, capability, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_authorization_mutation_unique
  ON public.aimos_authorization_events (company_id, subject_agent_id, capability, mutation_hash);

CREATE INDEX IF NOT EXISTS aimos_authorization_effective_idx
  ON public.aimos_authorization_events
  (company_id, subject_agent_id, capability, created_at DESC, authorization_event_id DESC);

DO $authorization_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    GRANT SELECT, INSERT ON public.aimos_authorization_events TO agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_authorization_events FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_authorization_events FROM aimos_app;
  END IF;
END
$authorization_acl$;
