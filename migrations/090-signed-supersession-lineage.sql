-- 090-signed-supersession-lineage.sql
--
-- Evolve the existing cross-memory lineage ledger in place. A supersession is
-- authority only when a D2 housekeeper row signs the exact retained edge,
-- parent/child live hashes, signer epoch, and predecessor chain. No companion
-- table, trigger, compatibility wrapper, deletion, or historical rewrite.
--
-- Paper authority:
--   Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging"
--   (signed commitments and predecessor-consistent history).

ALTER TABLE public.aimos_memory_lineage
  ADD COLUMN IF NOT EXISTS attesting_agent_valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS body_json jsonb,
  ADD COLUMN IF NOT EXISTS content_hash bytea,
  ADD COLUMN IF NOT EXISTS mutation_hash bytea,
  ADD COLUMN IF NOT EXISTS prev_mutation_hash bytea,
  ADD COLUMN IF NOT EXISTS is_genesis boolean,
  ADD COLUMN IF NOT EXISTS request_sig_form smallint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS signed_method text,
  ADD COLUMN IF NOT EXISTS signed_path text,
  ADD COLUMN IF NOT EXISTS signed_claims jsonb,
  ADD COLUMN IF NOT EXISTS binding_schema_version smallint NOT NULL DEFAULT 1;

ALTER TABLE public.aimos_memory_lineage
  DROP CONSTRAINT IF EXISTS aimos_memory_lineage_child_id_fkey,
  DROP CONSTRAINT IF EXISTS aimos_memory_lineage_parent_id_fkey;

ALTER TABLE public.aimos_memory_lineage
  ADD CONSTRAINT aimos_memory_lineage_child_id_fkey
    FOREIGN KEY (child_id) REFERENCES public.aimos_memories(id) ON DELETE RESTRICT,
  ADD CONSTRAINT aimos_memory_lineage_parent_id_fkey
    FOREIGN KEY (parent_id) REFERENCES public.aimos_memories(id) ON DELETE RESTRICT;

ALTER TABLE public.aimos_memory_lineage
  ADD CONSTRAINT aimos_memory_lineage_signer_epoch_fkey
    FOREIGN KEY (attesting_agent_id, attesting_agent_valid_from)
    REFERENCES public.agent_identity(agent_id, valid_from),
  ADD CONSTRAINT aimos_memory_lineage_request_context_valid CHECK (
    (request_sig_form = 1 AND signed_method IS NULL AND signed_path IS NULL AND signed_claims IS NULL)
    OR (request_sig_form = 3 AND signed_method IS NOT NULL AND signed_path IS NOT NULL AND signed_claims IS NULL)
    OR (request_sig_form = 4 AND signed_method IS NOT NULL AND signed_path IS NOT NULL
        AND jsonb_typeof(signed_claims) = 'object'
        AND jsonb_typeof(signed_claims->'prev_chain_hash') = 'string')
  ),
  ADD CONSTRAINT aimos_memory_lineage_signed_d2_complete CHECK (
    attestation_tier <> 'D2' OR (
      attesting_agent_id IS NOT NULL
      AND attesting_agent_valid_from IS NOT NULL
      AND attesting_cert_fingerprint IS NOT NULL
      AND body_json IS NOT NULL
      AND octet_length(content_hash) = 32
      AND octet_length(mutation_hash) = 32
      AND (prev_mutation_hash IS NULL OR octet_length(prev_mutation_hash) = 32)
      AND octet_length(sig) = 64
      AND nonce IS NOT NULL
      AND ts_signed IS NOT NULL
      AND is_genesis = (prev_mutation_hash IS NULL)
      AND binding_schema_version = 2
    )
  );

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_lineage_child_mutation_unique
  ON public.aimos_memory_lineage(child_id, mutation_hash)
  WHERE mutation_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_lineage_one_signed_genesis
  ON public.aimos_memory_lineage(child_id)
  WHERE attestation_tier = 'D2' AND prev_mutation_hash IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_lineage_one_signed_successor
  ON public.aimos_memory_lineage(child_id, prev_mutation_hash)
  WHERE attestation_tier = 'D2' AND prev_mutation_hash IS NOT NULL;

REVOKE UPDATE, DELETE, TRUNCATE ON public.aimos_memory_lineage FROM PUBLIC, agent_runtime, aimos_app;
REVOKE UPDATE, DELETE, TRUNCATE ON public.supersession_events FROM PUBLIC, agent_runtime, aimos_app;

GRANT SELECT, INSERT (
  child_id, parent_id, parent_ids, derivation_type, attestation_tier,
  attesting_agent_id, attesting_agent_valid_from, attesting_cert_fingerprint,
  sig, nonce, ts_signed, backfilled, body_json, content_hash, mutation_hash,
  prev_mutation_hash, is_genesis, request_sig_form, signed_method, signed_path,
  signed_claims, binding_schema_version
) ON public.aimos_memory_lineage TO agent_runtime;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agent_runtime;

COMMENT ON COLUMN public.aimos_memory_lineage.binding_schema_version IS
  'v2 D2 rows are housekeeper-signed exact supersession receipts; legacy D1 and agent D3 rows remain retained without being promoted to authority.';
