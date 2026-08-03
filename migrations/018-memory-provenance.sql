-- 018-memory-provenance.sql
-- Phase 4 Step 1 — Memory provenance ledger schema.
--
-- This is the memory-centric mutation ledger (the "vertical" lineage):
-- every mutation of a memory — regardless of which agent performed it —
-- gets one row here. The chain links by `prev_mutation_hash` WITHIN the
-- same `memory_id`, so a memory mutated by agent A and then agent B has
-- two rows with the second row's `prev_mutation_hash` pointing to the
-- first row's `mutation_hash`.
--
-- Contrast with `aimos_save_envelope` (the agent-chain-of-custody ledger,
-- T2/T3 + prev_chain_hash gated): the envelope ledger chains an AGENT'S
-- successive saves; the provenance ledger chains a MEMORY'S mutations
-- across identity transitions. Both ledgers persist side-by-side; this
-- table does NOT replace or modify the envelope ledger.
--
-- content_hash uses the exact same canonical form as the envelope ledger
-- (identity-chain.js#contentHash = sha256(canonicalJson(body)) via RFC
-- 8783 JCS), so the two ledgers can be cross-referenced on identical
-- content_hash bytes for any T2/T3 save that appears in both.
--
-- Three row brackets (see HOM-PHASE-4-DUAL-LEDGER-PLAN.md §1):
--   P-real    — backfilled, re-attested from a real envelope row
--               (backfilled=true, is_genesis=false, sig=<reviewer re-signs
--               provenance canonical form>, legacy_envelope_sig=<original
--               envelope sig>, ts_signed=<now>, memory_originated_at=
--               <memory.created_at>, identity_tier=<envelope tier>)
--   P-anchor  — backfilled genesis-anchor for unsigned memories
--               (is_genesis=true, backfilled=true, sig=NULL, ts_signed=
--               NULL, identity_tier='GENESIS', memory_originated_at=
--               <memory.created_at>, agent_id=<memory.agent_id or NULL>)
--   P-live    — going forward, written by commitProvenance on every save
--               (backfilled=false, is_genesis=false, real Ed25519 sig by
--               the acting agent, ts_signed=<now>, identity_tier=T1/T2/T3)
--
-- H10 (no legacy aliases): N/A — new table.
-- H8 (no parallel edits): solo migration, sequential.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS, so
-- manual-psql re-application is a no-op.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'aimos_memory_provenance'
  ) THEN
    CREATE TABLE aimos_memory_provenance (
      provenance_id    uuid         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
      memory_id        uuid         NOT NULL REFERENCES aimos_memories(id) ON DELETE CASCADE,
      agent_id         text,
      cert_fingerprint text,
      content_hash     bytea        NOT NULL,
      mutation_hash    bytea        NOT NULL,
      prev_mutation_hash bytea,
      ts_signed        bigint,
      nonce            text,
      sig              bytea,
      identity_tier    text         NOT NULL,
      is_genesis       boolean      NOT NULL DEFAULT false,
      backfilled       boolean      NOT NULL DEFAULT false,
      memory_originated_at timestamptz,
      legacy_envelope_sig bytea,
      created_at       timestamptz  NOT NULL DEFAULT now()
    );
    COMMENT ON TABLE  aimos_memory_provenance IS 'Memory-centric mutation ledger (Phase 4). Chains a memory''s mutations across identity transitions via prev_mutation_hash. Sibling to aimos_save_envelope (agent-chain ledger).';
    COMMENT ON COLUMN aimos_memory_provenance.provenance_id IS 'Synthetic PK; the chain is keyed by (memory_id, mutation_hash).';
    COMMENT ON COLUMN aimos_memory_provenance.content_hash IS 'sha256(canonicalJson(body)) — same canonical form as aimos_save_envelope.content_hash for cross-ledger reference.';
    COMMENT ON COLUMN aimos_memory_provenance.mutation_hash IS 'sha256(content_hash || prev_mutation_hash || nonce || String(ts_signed)). NULL prev for genesis.';
    COMMENT ON COLUMN aimos_memory_provenance.prev_mutation_hash IS 'Points to the previous row''s mutation_hash for this memory_id. NULL iff is_genesis=true.';
    COMMENT ON COLUMN aimos_memory_provenance.ts_signed IS 'When the sig was actually produced. NULL for P-anchor rows (genuinely unsigned at origin). P-real rows use now() (re-attestation time), NOT memory_originated_at.';
    COMMENT ON COLUMN aimos_memory_provenance.sig IS 'Ed25519 sig by acting agent over provenance canonical form. NULL for P-anchor (unsigned genesis).';
    COMMENT ON COLUMN aimos_memory_provenance.identity_tier IS 'T1/T2/T3 for P-real and P-live; GENESIS for P-anchor.';
    COMMENT ON COLUMN aimos_memory_provenance.is_genesis IS 'true iff this is the genesis row for this memory_id.';
    COMMENT ON COLUMN aimos_memory_provenance.backfilled IS 'true iff row was written by the backfill migration (Step 3). False for P-live rows.';
    COMMENT ON COLUMN aimos_memory_provenance.memory_originated_at IS 'The memory row''s original created_at — preserved for backfilled rows so re-attestation is not confused with origin.';
    COMMENT ON COLUMN aimos_memory_provenance.legacy_envelope_sig IS 'For P-real rows only: the original aimos_save_envelope.sig bytes, retained for audit. NULL for P-anchor and P-live.';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'aimos_memory_provenance_memory_mutation_unique'
      AND conrelid = 'aimos_memory_provenance'::regclass
  ) THEN
    ALTER TABLE aimos_memory_provenance
      ADD CONSTRAINT aimos_memory_provenance_memory_mutation_unique
      UNIQUE (memory_id, mutation_hash);
  END IF;
END
$body$;

CREATE INDEX IF NOT EXISTS aimos_memory_provenance_memory_created_idx
  ON aimos_memory_provenance (memory_id, created_at);

CREATE INDEX IF NOT EXISTS aimos_memory_provenance_agent_created_idx
  ON aimos_memory_provenance (agent_id, created_at);
