-- Make predecessor topology a database invariant for the credential lifecycle
-- and request-admission ledgers. This is the relational equivalent of the
-- historical-consistency requirement in Crosby & Wallach, "Efficient Data
-- Structures for Tamper-Evident Logging": every retained event belongs to one
-- append-only history and every non-genesis event names an existing predecessor.
-- No row is updated, deleted, expired, suppressed, or decayed.

DO $credential_topology_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_credential_lifecycle'::regclass
       AND conname = 'aimos_credential_lifecycle_hash_shape'
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT aimos_credential_lifecycle_hash_shape CHECK (
        octet_length(content_hash) = 32
        AND octet_length(mutation_hash) = 32
        AND (prev_mutation_hash IS NULL OR octet_length(prev_mutation_hash) = 32)
        AND octet_length(sig) = 64
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_credential_lifecycle'::regclass
       AND conname = 'aimos_credential_lifecycle_genesis_link'
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT aimos_credential_lifecycle_genesis_link
      CHECK (is_genesis = (prev_mutation_hash IS NULL)) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_credential_lifecycle'::regclass
       AND conname = 'aimos_credential_lifecycle_predecessor_fk'
  ) THEN
    ALTER TABLE public.aimos_credential_lifecycle
      ADD CONSTRAINT aimos_credential_lifecycle_predecessor_fk
      FOREIGN KEY (slot_id, prev_mutation_hash)
      REFERENCES public.aimos_credential_lifecycle(slot_id, mutation_hash)
      ON DELETE RESTRICT
      DEFERRABLE INITIALLY DEFERRED
      NOT VALID;
  END IF;
END
$credential_topology_constraints$;

ALTER TABLE public.aimos_credential_lifecycle
  VALIDATE CONSTRAINT aimos_credential_lifecycle_hash_shape;
ALTER TABLE public.aimos_credential_lifecycle
  VALIDATE CONSTRAINT aimos_credential_lifecycle_genesis_link;
ALTER TABLE public.aimos_credential_lifecycle
  VALIDATE CONSTRAINT aimos_credential_lifecycle_predecessor_fk;

DO $request_receipt_topology_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_request_receipts'::regclass
       AND conname = 'aimos_request_receipts_stream_mutation_unique'
  ) THEN
    ALTER TABLE public.aimos_request_receipts
      ADD CONSTRAINT aimos_request_receipts_stream_mutation_unique
      UNIQUE (company_id, actor_agent_id, actor_valid_from, mutation_hash);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.aimos_request_receipts'::regclass
       AND conname = 'aimos_request_receipts_predecessor_fk'
  ) THEN
    ALTER TABLE public.aimos_request_receipts
      ADD CONSTRAINT aimos_request_receipts_predecessor_fk
      FOREIGN KEY (company_id, actor_agent_id, actor_valid_from, prev_mutation_hash)
      REFERENCES public.aimos_request_receipts(
        company_id, actor_agent_id, actor_valid_from, mutation_hash
      )
      ON DELETE RESTRICT
      DEFERRABLE INITIALLY DEFERRED
      NOT VALID;
  END IF;
END
$request_receipt_topology_constraints$;

ALTER TABLE public.aimos_request_receipts
  VALIDATE CONSTRAINT aimos_request_receipts_predecessor_fk;

COMMENT ON CONSTRAINT aimos_credential_lifecycle_predecessor_fk
  ON public.aimos_credential_lifecycle IS
  'Every non-genesis credential event names a retained predecessor in the same slot; runtime verification additionally rejects forks, cycles, disconnected histories, and zero/multiple heads.';

COMMENT ON CONSTRAINT aimos_request_receipts_predecessor_fk
  ON public.aimos_request_receipts IS
  'Every non-genesis request receipt names a retained predecessor in the same company/actor/identity-epoch stream; runtime verification derives chronology only from this topology.';
