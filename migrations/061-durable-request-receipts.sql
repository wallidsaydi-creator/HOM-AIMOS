-- Durable cross-process replay protection and cryptographic admission receipts
-- for every protected certificate-envelope request.

CREATE TABLE IF NOT EXISTS public.aimos_request_receipts (
  request_receipt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id text NOT NULL,
  actor_agent_id text NOT NULL,
  actor_valid_from timestamptz NOT NULL,
  cert_fingerprint text NOT NULL CHECK (cert_fingerprint ~ '^[0-9a-f]{64}$'),
  request_sig_form integer NOT NULL CHECK (request_sig_form IN (3, 4)),
  signed_method text NOT NULL,
  signed_path text NOT NULL,
  signed_claims jsonb,
  signed_claims_hash bytea CHECK (signed_claims_hash IS NULL OR octet_length(signed_claims_hash) = 32),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  prev_mutation_hash bytea,
  mutation_hash bytea NOT NULL CHECK (octet_length(mutation_hash) = 32),
  ts_signed bigint NOT NULL CHECK (ts_signed > 0),
  nonce text NOT NULL CHECK (length(nonce) > 0),
  sig bytea NOT NULL CHECK (octet_length(sig) = 64),
  is_genesis boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (actor_agent_id, actor_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from),
  CHECK (
    (is_genesis AND prev_mutation_hash IS NULL)
    OR (NOT is_genesis AND octet_length(prev_mutation_hash) = 32)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_request_receipts_nonce_unique
  ON public.aimos_request_receipts (actor_agent_id, actor_valid_from, nonce);
CREATE UNIQUE INDEX IF NOT EXISTS aimos_request_receipts_mutation_unique
  ON public.aimos_request_receipts (mutation_hash);
CREATE UNIQUE INDEX IF NOT EXISTS aimos_request_receipts_one_genesis
  ON public.aimos_request_receipts (company_id, actor_agent_id, actor_valid_from)
  WHERE prev_mutation_hash IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS aimos_request_receipts_one_successor
  ON public.aimos_request_receipts (company_id, actor_agent_id, actor_valid_from, prev_mutation_hash)
  WHERE prev_mutation_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS aimos_request_receipts_stream
  ON public.aimos_request_receipts
    (company_id, actor_agent_id, actor_valid_from, created_at, request_receipt_id);

ALTER TABLE public.aimos_request_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aimos_request_receipts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS aimos_request_receipts_company_policy ON public.aimos_request_receipts;
CREATE POLICY aimos_request_receipts_company_policy ON public.aimos_request_receipts
  USING (company_id = current_setting('app.current_client_id', true))
  WITH CHECK (
    company_id = current_setting('app.current_client_id', true)
    AND actor_agent_id = current_setting('app.current_agent_id', true)
  );

REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_request_receipts
  FROM PUBLIC, aimos_app, agent_runtime;
GRANT SELECT, INSERT ON public.aimos_request_receipts TO agent_runtime;

COMMENT ON TABLE public.aimos_request_receipts IS
  'Append-only actor/epoch request admission ledger. Stores signed request hashes, never plaintext request bodies; unique nonces provide durable cross-process replay rejection.';
