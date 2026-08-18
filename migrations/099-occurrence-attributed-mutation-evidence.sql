-- 099-occurrence-attributed-mutation-evidence.sql
--
-- R7-M: every new outcome that can affect cognitive retrieval weight must bind
-- the exact signed recall receipt and disclosed occurrence. Historical valence
-- rows remain v1 and are never rewritten. Content-state mutation authority is
-- deliberately absent; v2 permits occurrence observation or principal-state
-- utility only.

ALTER TABLE public.memory_valence_ledger
  ADD COLUMN IF NOT EXISTS evidence_schema_version smallint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS target_scope text,
  ADD COLUMN IF NOT EXISTS target_live_content_hash bytea,
  ADD COLUMN IF NOT EXISTS target_occurrence_ref bytea,
  ADD COLUMN IF NOT EXISTS recall_event_id uuid,
  ADD COLUMN IF NOT EXISTS recall_event_mutation_hash bytea,
  ADD COLUMN IF NOT EXISTS recall_merkle_root bytea,
  ADD COLUMN IF NOT EXISTS security_closure_hash bytea,
  ADD COLUMN IF NOT EXISTS outcome_id uuid,
  ADD COLUMN IF NOT EXISTS outcome_event_id uuid,
  ADD COLUMN IF NOT EXISTS outcome_event_mutation_hash bytea;

DO $r7m_constraints$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname='memory_valence_ledger_r7m_v2_complete'
       AND conrelid='public.memory_valence_ledger'::regclass
  ) THEN
    ALTER TABLE public.memory_valence_ledger
      ADD CONSTRAINT memory_valence_ledger_r7m_v2_complete CHECK (
        evidence_schema_version = 1 OR (
          evidence_schema_version = 2
          AND target_scope IN ('occurrence_observation','principal_state')
          AND octet_length(target_live_content_hash)=32
          AND octet_length(target_occurrence_ref)=32
          AND recall_event_id IS NOT NULL
          AND octet_length(recall_event_mutation_hash)=32
          AND octet_length(recall_merkle_root)=32
          AND octet_length(security_closure_hash)=32
          AND outcome_id IS NOT NULL
          AND outcome_event_id IS NOT NULL
          AND octet_length(outcome_event_mutation_hash)=32
          AND body_json->>'evidence_schema'='hom.aimos.mutation-outcome-evidence/v2'
          AND body_json->>'target_scope'=target_scope
          AND body_json->>'memory_id'=memory_id::text
          AND body_json->>'target_live_content_hash'=encode(target_live_content_hash,'hex')
          AND body_json->>'target_occurrence_ref'=encode(target_occurrence_ref,'hex')
          AND body_json->>'recall_event_id'=recall_event_id::text
          AND body_json->>'recall_event_mutation_hash'=encode(recall_event_mutation_hash,'hex')
          AND body_json->>'recall_merkle_root'=encode(recall_merkle_root,'hex')
          AND body_json->>'security_closure_sha256'=encode(security_closure_hash,'hex')
          AND body_json->>'outcome_id'=outcome_id::text
          AND body_json->>'outcome_event_id'=outcome_event_id::text
          AND body_json->>'outcome_event_mutation_hash'=encode(outcome_event_mutation_hash,'hex')
        )
      );
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname='memory_valence_ledger_recall_event_fkey'
       AND conrelid='public.memory_valence_ledger'::regclass
  ) THEN
    ALTER TABLE public.memory_valence_ledger
      ADD CONSTRAINT memory_valence_ledger_recall_event_fkey
      FOREIGN KEY (recall_event_id) REFERENCES public.aimos_events(id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname='memory_valence_ledger_outcome_event_fkey'
       AND conrelid='public.memory_valence_ledger'::regclass
  ) THEN
    ALTER TABLE public.memory_valence_ledger
      ADD CONSTRAINT memory_valence_ledger_outcome_event_fkey
      FOREIGN KEY (outcome_event_id) REFERENCES public.aimos_events(id) ON DELETE RESTRICT;
  END IF;
END
$r7m_constraints$;

CREATE UNIQUE INDEX IF NOT EXISTS memory_valence_r7m_outcome_unique
  ON public.memory_valence_ledger (company_id,outcome_id)
  WHERE evidence_schema_version=2;

CREATE UNIQUE INDEX IF NOT EXISTS memory_valence_r7m_outcome_event_unique
  ON public.memory_valence_ledger (outcome_event_id)
  WHERE evidence_schema_version=2;

CREATE INDEX IF NOT EXISTS memory_valence_r7m_principal_state
  ON public.memory_valence_ledger
    (company_id,target_live_content_hash,memory_id,id)
  WHERE evidence_schema_version=2 AND target_scope='principal_state';

DO $r7m_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_runtime') THEN
    GRANT INSERT (
      evidence_schema_version,target_scope,target_live_content_hash,
      target_occurrence_ref,recall_event_id,recall_event_mutation_hash,
      recall_merkle_root,security_closure_hash,outcome_id,outcome_event_id,
      outcome_event_mutation_hash
    ) ON public.memory_valence_ledger TO agent_runtime;
  END IF;
END
$r7m_acl$;

COMMENT ON COLUMN public.memory_valence_ledger.target_scope IS
  'R7-M evidence scope. occurrence_observation is retained with zero weight authority; principal_state may drive one state representative; content_state is intentionally prohibited.';
