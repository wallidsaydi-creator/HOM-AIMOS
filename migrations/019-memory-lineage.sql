-- 019-memory-lineage.sql
-- Phase 4 Step 2 — Memory derivation lineage ledger schema.
--
-- This is the cross-memory derivation DAG (the "horizontal" lineage):
-- each row records "memory `child_id` was derived from {parent_ids...}
-- by `derivation_type`." Contrast with aimos_memory_provenance (the
-- vertical chain — a single memory's mutations over time). The two
-- ledgers share the same vertex set (memory_id) but encode different
-- graphs: provenance is a linked list per memory_id; lineage is a DAG
-- across memory_ids.
--
-- Derivation types (CHECK constraint below):
--   genesis              — origin row, no parents (input memories: conversation_feed, book_extract, ...)
--   genesis_known_unknown — backfill for a derivation we know happened, but whose parent set is irrecoverable (old compactions with no recorded parent metadata)
--   supersede            — child replaces parent (aimos_memories.parent_memory_id)
--   correct              — child corrects parent (aimos_memories.supersedes_id where is_correction=true)
--   propagate            — propagated from another agent (aimos_memories.propagated_from_agent)
--   agent_reasoning      — derived by an agent's reasoning from N parents (D3-signed in Phase 4)
--   compaction           — derived by compaction from N parents (D1 in Phase 4; D1+D2 in Phase 5)
--   synthesis            — derived by synthesis from N parents (Phase 5)
--   transformation       — derived by transformation from 1+ parents (Phase 5)
--   retrieval            — retrieved from existing memories (Phase 5)
--
-- Attestation tiers:
--   D1 — Structural only (sig=NULL). "The system state transitioned:
--        these parents were the inputs to this derivation." Always
--        written, no key required.
--   D2 — Server-attested (sig by an aimos-operator agent key).
--        Phase 5 — schema supports it now, code path not yet wired.
--   D3 — Agent-attested (Ed25519 sig by the acting agent over
--        canonicalJson({child_id, parent_ids, derivation_type,
--        ts_signed, nonce}) via RFC 8783 JCS, verified by
--        agent-identity.js#verifyPayloadSig). Phase 4 wires this only
--        for derivation_type='agent_reasoning'.
--
-- FK semantics:
--   child_id  ON DELETE CASCADE  — if the child memory is deleted, the lineage row about a non-existent memory is destroyed too (matches provenance ledger behavior).
--   parent_id ON DELETE SET NULL — if a parent memory is deleted, the lineage row is PRESERVED (audit trail: the derivation happened); only the FK-resolvable fast path is nulled. parent_ids[] retains the orphaned UUID as the honest audit record that the parent once existed.
--   parent_ids[] — uuid[] CANNOT have a FK in native PostgreSQL. Orphaned UUIDs in this array are the documented audit record; a junction table can be straight-additive in Phase 5 if full array-FK integrity is needed.
--
-- UNIQUE(child_id, derivation_type, ts_signed):
--   For D3 rows (ts_signed NOT NULL): prevents duplicate D3 rows for
--   the same derivation event. For D1 rows (ts_signed NULL): PostgreSQL
--   treats NULLs as distinct, so multiple D1 rows for the same
--   (child_id, derivation_type) ARE allowed (a memory can be compacted
--   more than once, each D1 row is a separate event). This is the
--   intended behavior.
--
-- H10 (no legacy aliases): N/A — new table.
-- H8 (no parallel edits): solo migration, sequential after 018.
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.

DO $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'aimos_memory_lineage'
  ) THEN
    CREATE TABLE aimos_memory_lineage (
      lineage_id               uuid         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
      child_id                 uuid         NOT NULL REFERENCES aimos_memories(id) ON DELETE CASCADE,
      parent_id                uuid         REFERENCES aimos_memories(id) ON DELETE SET NULL,
      parent_ids               uuid[]       NOT NULL DEFAULT '{}'::uuid[],
      derivation_type          text         NOT NULL CHECK (derivation_type IN
        ('genesis','genesis_known_unknown','supersede','correct','propagate',
         'agent_reasoning','compaction','synthesis','transformation','retrieval')),
      attestation_tier        text         NOT NULL DEFAULT 'D1' CHECK (attestation_tier IN ('D1','D2','D3')),
      attesting_agent_id       text,
      attesting_cert_fingerprint text,
      sig                      bytea,
      nonce                    text,
      ts_signed                bigint,
      backfilled               boolean      NOT NULL DEFAULT false,
      created_at               timestamptz  NOT NULL DEFAULT now()
    );
    COMMENT ON TABLE  aimos_memory_lineage IS 'Cross-memory derivation DAG (Phase 4). Each row records how child_id was derived from parent_ids[] by derivation_type. Sibling to aimos_memory_provenance (vertical chain).';
    COMMENT ON COLUMN aimos_memory_lineage.child_id IS 'The derived memory. ON DELETE CASCADE: if the child is deleted, the lineage row is destroyed (no audit on non-existent memory).';
    COMMENT ON COLUMN aimos_memory_lineage.parent_id IS 'FK-resolvable single-parent fast path. Populated from aimos_memories.parent_memory_id on backfill, or the first parent of parent_ids[] going forward. NULL for genesis / genesis_known_unknown. ON DELETE SET NULL: preserve the lineage row, null the fast path if a parent is deleted.';
    COMMENT ON COLUMN aimos_memory_lineage.parent_ids IS 'Full parent set (multi-parent for compaction/synthesis/agent_reasoning). uuid[] cannot have a native FK; orphaned UUIDs are the honest audit record that the parent once existed. Junction table is a Phase 5 straight-additive option.';
    COMMENT ON COLUMN aimos_memory_lineage.derivation_type IS 'genesis (origin), genesis_known_unknown (backfilled, lost parentage), supersede, correct, propagate, agent_reasoning (D3), compaction, synthesis, transformation, retrieval.';
    COMMENT ON COLUMN aimos_memory_lineage.attestation_tier IS 'D1 = structural only (sig=NULL); D2 = server-attested (Phase 5); D3 = agent-attested Ed25519.';
    COMMENT ON COLUMN aimos_memory_lineage.attesting_agent_id IS 'D3 only: the agent whose reasoning produced the derivation. NULL for D1/D2.';
    COMMENT ON COLUMN aimos_memory_lineage.sig IS 'D3: Ed25519 sig over canonicalJson({child_id, parent_ids, derivation_type, ts_signed, nonce}). D2: operator-key Ed25519 (Phase 5). D1: NULL.';
    COMMENT ON COLUMN aimos_memory_lineage.ts_signed IS 'D3/D2: when the sig was produced. D1: NULL. UNIQUE(child_id, derivation_type, ts_signed) uses NULLs-distinct semantics to allow multiple D1 events per (child_id, derivation_type).';
    COMMENT ON COLUMN aimos_memory_lineage.backfilled IS 'true iff row written by the Step 3 backfill migration. False for live rows going forward.';
  END IF;
END
$body$;

CREATE INDEX IF NOT EXISTS aimos_memory_lineage_child_idx
  ON aimos_memory_lineage (child_id);

CREATE INDEX IF NOT EXISTS aimos_memory_lineage_parent_idx
  ON aimos_memory_lineage (parent_id);

CREATE INDEX IF NOT EXISTS aimos_memory_lineage_derivation_type_idx
  ON aimos_memory_lineage (derivation_type);

CREATE UNIQUE INDEX IF NOT EXISTS aimos_memory_lineage_child_deriv_ts_unique
  ON aimos_memory_lineage (child_id, derivation_type, ts_signed);
