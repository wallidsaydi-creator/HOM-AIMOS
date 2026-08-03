-- Persist the exact request-signature preimage class beside every ledger row
-- that copies an authenticated request signature. Provenance sig_form_version
-- remains the separate historical/body-only attestation namespace.

ALTER TABLE public.aimos_memory_provenance
  ADD COLUMN IF NOT EXISTS request_sig_form smallint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS signed_method text,
  ADD COLUMN IF NOT EXISTS signed_path text,
  ADD COLUMN IF NOT EXISTS signed_claims jsonb;

ALTER TABLE public.aimos_save_envelope
  ADD COLUMN IF NOT EXISTS request_sig_form smallint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS signed_method text,
  ADD COLUMN IF NOT EXISTS signed_path text,
  ADD COLUMN IF NOT EXISTS signed_claims jsonb;

ALTER TABLE public.aimos_authorization_events
  ADD COLUMN IF NOT EXISTS request_sig_form smallint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS signed_method text,
  ADD COLUMN IF NOT EXISTS signed_path text,
  ADD COLUMN IF NOT EXISTS signed_claims jsonb;

DO $request_signature_constraints$
DECLARE
  table_name text;
  constraint_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'aimos_memory_provenance',
    'aimos_save_envelope',
    'aimos_authorization_events'
  ]
  LOOP
    constraint_name := table_name || '_request_signature_context_valid';
    IF NOT EXISTS (
      SELECT 1
        FROM pg_constraint
       WHERE conname = constraint_name
         AND conrelid = format('public.%I', table_name)::regclass
    ) THEN
      EXECUTE format(
        'ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (
           (request_sig_form = 1 AND signed_method IS NULL AND signed_path IS NULL AND signed_claims IS NULL)
           OR
           (request_sig_form = 3 AND signed_method IS NOT NULL AND signed_path IS NOT NULL AND signed_claims IS NULL)
           OR
           (request_sig_form = 4 AND signed_method IS NOT NULL AND signed_path IS NOT NULL
             AND jsonb_typeof(signed_claims) = ''object''
             AND jsonb_typeof(signed_claims->''prev_chain_hash'') = ''string'')
         )',
        table_name,
        constraint_name
      );
    END IF;
  END LOOP;
END
$request_signature_constraints$;

COMMENT ON COLUMN public.aimos_memory_provenance.request_sig_form IS
  'Request envelope signature form: 1=body-only native evidence, 3=method/path-bound, 4=method/path plus chain/device claims.';
COMMENT ON COLUMN public.aimos_save_envelope.request_sig_form IS
  'Request envelope signature form retained for independent custody-proof verification.';
COMMENT ON COLUMN public.aimos_authorization_events.request_sig_form IS
  'Request envelope signature form retained for independent authorization-proof verification.';
