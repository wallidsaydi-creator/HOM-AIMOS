-- Ordinary-agent recall authority is master-signed, epoch-bound, company-bound,
-- append-only, and carries an explicit clearance ceiling. Generic actor-signed
-- capability events cannot authorize memory disclosure because an actor must
-- never be able to self-grant recall.

CREATE TABLE IF NOT EXISTS public.aimos_recall_authorization_events (
  recall_authorization_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id text NOT NULL,
  subject_agent_id text NOT NULL,
  subject_valid_from timestamptz NOT NULL,
  allowed boolean NOT NULL,
  write_allowed boolean NOT NULL DEFAULT false,
  clearance_ceiling integer NOT NULL CHECK (clearance_ceiling BETWEEN 0 AND 12),
  data_class_ceiling text NOT NULL CHECK (data_class_ceiling IN ('public', 'internal', 'confidential', 'restricted')),
  master_fingerprint text NOT NULL,
  signed_body jsonb NOT NULL,
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  mutation_hash bytea NOT NULL CHECK (octet_length(mutation_hash) = 32),
  prev_mutation_hash bytea,
  ts_signed bigint NOT NULL CHECK (ts_signed > 0),
  nonce text NOT NULL CHECK (length(nonce) > 0),
  sig bytea NOT NULL CHECK (octet_length(sig) = 64),
  is_genesis boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT aimos_recall_authorization_subject_epoch_fkey
    FOREIGN KEY (subject_agent_id, subject_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from),
  CONSTRAINT aimos_recall_authorization_chain_shape CHECK (
    (is_genesis AND prev_mutation_hash IS NULL)
    OR
    (NOT is_genesis AND octet_length(prev_mutation_hash) = 32)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_master_identity_fingerprint_unique
  ON public.aimos_master_identity (fingerprint);

DO $recall_master_fkey$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_recall_authorization_master_fkey') THEN
    ALTER TABLE public.aimos_recall_authorization_events
      ADD CONSTRAINT aimos_recall_authorization_master_fkey
      FOREIGN KEY (master_fingerprint)
      REFERENCES public.aimos_master_identity(fingerprint);
  END IF;
END
$recall_master_fkey$;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_recall_authorization_mutation_unique
  ON public.aimos_recall_authorization_events (mutation_hash);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_recall_authorization_nonce_unique
  ON public.aimos_recall_authorization_events (master_fingerprint, nonce);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_recall_authorization_one_genesis
  ON public.aimos_recall_authorization_events (company_id, subject_agent_id, subject_valid_from)
  WHERE prev_mutation_hash IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_recall_authorization_one_successor
  ON public.aimos_recall_authorization_events
    (company_id, subject_agent_id, subject_valid_from, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS aimos_recall_authorization_latest
  ON public.aimos_recall_authorization_events
    (company_id, subject_agent_id, subject_valid_from, created_at DESC);

DO $recall_authorization_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_recall_authorization_events FROM agent_runtime;
    GRANT SELECT ON public.aimos_recall_authorization_events TO agent_runtime;
    GRANT SELECT (id, master_pubkey, fingerprint) ON public.aimos_master_identity TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.aimos_recall_authorization_events FROM aimos_app;
  END IF;
END
$recall_authorization_acl$;

COMMENT ON TABLE public.aimos_recall_authorization_events IS
  'Master-signed append-only memory access grants/revokes bound to one exact agent epoch, company, read/write authority, clearance ceiling, and data-class ceiling.';
