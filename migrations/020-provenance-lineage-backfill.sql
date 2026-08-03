-- 020-provenance-lineage-backfill.sql
-- Phase 4 Step 3 — Retroactive import into provenance + lineage ledgers.
--
-- Pure-SQL, idempotent via NOT EXISTS guards on every INSERT. Re-running
-- this migration is a no-op (no duplicate rows inserted; row counts print
-- as 0 on second run).
--
-- Ground truth (verified 2026-07-03 before writing):
--   - 19,041 total memories
--   - 43 envelope rows across 43 distinct memory_ids, all T2 reviewer,
--     going back to 2026-05-02 (most recent 2026-06-12)
--   - 18,998 memories have NO envelope row (P-anchor candidates)
--   - 2 memories have supersedes_id + is_correction=true (lineage 'correct')
--   - 0 memories have parent_memory_id populated
--   - 0 memories have propagated_from_agent populated
--
-- Three integrity brackets (see HOM-PHASE-4-DUAL-LEDGER-PLAN.md §1):
--
--   P-anchor (18,998 rows) — genesis-anchor for memories with no envelope
--     history. sig=NULL, ts_signed=NULL, identity_tier='GENESIS',
--     content_hash=sha256(value text bytes), mutation_hash=
--     sha256('genesis:'||memory_id), is_genesis=true, backfilled=true.
--     Honest claim: "This content existed at this memory_id, attributed
--     to agent_id, but was not cryptographically signed at origin."
--
--   P-real (43 rows) — direct import from aimos_save_envelope. The
--     envelope's Ed25519 sig was produced over canonicalJson(body)+'\n'+
--     nonce+'\n'+String(ts) — the SAME canonical form the provenance
--     ledger uses (because content_hash for both = sha256(canonicalJson(body))
--     via RFC 8785 JCS per identity-chain.js#contentHash). So the imported
--     sig remains a valid cryptographic attestation binding agent →
--     content_hash → nonce → ts. legacy_envelope_sig is NULL because the
--     sig IS the original envelope sig (not a re-signing) — the column is
--     retained for future re-attestation scenarios.
--
--   Lineage rows (19,041 total):
--     19,039 genesis / genesis_known_unknown (every memory without parent
--       metadata, by memory_type bucket)
--     2 'correct' (memories with supersedes_id + is_correction=true)
--
-- All 19,041 lineage rows are attestation_tier='D1' (structural, no sig).
-- D3 (agent-attested) rows are written live by commitLineage going forward,
-- not by backfill. D2 (server-attested) is Phase 5.
--
-- H10: N/A — new tables, no legacy aliases.
-- H8: solo migration, sequential after 019.
--
-- Post-backfill audit (verifier script, separate task):
--   - Verify all 43 P-real sigs validate against reviewer's current pubkey
--     (proves reviewer's cert hasn't rotated; sigs remain live attestations)
--   - Verify row counts: provenance=19,041, lineage=19,041
--   - Verify backfill markers: all 19,041 provenance rows have
--     backfilled=true; all 19,041 lineage rows have backfilled=true
--   - Verify chain integrity: every memory_id has exactly ONE genesis
--     provenance row (is_genesis=true)

DO $body$
DECLARE
  rows_p_anchor int;
  rows_p_real int;
  rows_lineage_input int;
  rows_lineage_derived int;
  rows_lineage_correct int;
  rows_lineage_supersede int;
BEGIN
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -- PART A: P-anchor — genesis-anchors for memories WITHOUT an envelope.
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INSERT INTO aimos_memory_provenance
    (memory_id, agent_id, content_hash, mutation_hash, prev_mutation_hash,
     ts_signed, nonce, sig, identity_tier, is_genesis, backfilled,
     memory_originated_at, legacy_envelope_sig)
  SELECT m.id,
         m.agent_id,
         sha256(convert_to(m.value, 'UTF8')),
         sha256(convert_to('genesis:' || m.id::text, 'UTF8')),
         NULL, NULL, NULL, NULL, 'GENESIS', true, true,
         m.created_at::timestamptz, NULL
    FROM aimos_memories m
   WHERE NOT EXISTS (
           SELECT 1 FROM aimos_memory_provenance p
            WHERE p.memory_id = m.id
         )
     AND NOT EXISTS (
           SELECT 1 FROM aimos_save_envelope e
            WHERE e.memory_id = m.id
         );
  GET DIAGNOSTICS rows_p_anchor = ROW_COUNT;

  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -- PART B: P-real — direct import from aimos_save_envelope.
  -- The envelope's content_hash, sig, nonce, ts_signed, agent_id,
  -- cert_fingerprint, identity_tier are imported as-is. The sig remains
  -- a valid Ed25519 attestation because the canonical form is shared.
  -- is_genesis=true because the envelope was the first cryptographic event
  -- for this memory_id (memory created and T2-saved in the same request).
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INSERT INTO aimos_memory_provenance
    (memory_id, agent_id, cert_fingerprint, content_hash, mutation_hash,
     prev_mutation_hash, ts_signed, nonce, sig, identity_tier,
     is_genesis, backfilled, memory_originated_at, legacy_envelope_sig)
  SELECT e.memory_id,
         e.agent_id,
         e.cert_fingerprint,
         e.content_hash,
         sha256(convert_to('genesis:' || e.memory_id::text, 'UTF8')),
         NULL,
         e.ts_signed,
         e.nonce,
         e.sig,
         e.identity_tier,
         true, true,
         m.created_at::timestamptz,
         NULL
    FROM aimos_save_envelope e
    JOIN aimos_memories m ON m.id = e.memory_id
   WHERE NOT EXISTS (
           SELECT 1 FROM aimos_memory_provenance p
            WHERE p.memory_id = e.memory_id
         );
  GET DIAGNOSTICS rows_p_real = ROW_COUNT;

  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -- PART C-A: Lineage genesis — input memory types (no derivation implied).
  -- derivation_type='genesis', parent_ids empty, attestation_tier='D1'.
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INSERT INTO aimos_memory_lineage
    (child_id, parent_id, parent_ids, derivation_type, attestation_tier, backfilled)
  SELECT m.id, NULL, ARRAY[]::uuid[], 'genesis', 'D1', true
    FROM aimos_memories m
   WHERE m.parent_memory_id IS NULL
     AND m.supersedes_id IS NULL
     AND m.memory_type IN (
       'conversation_feed','book_extract','session_debrief',
       'tacit_knowledge','bibliographic_reference','event_log',
       'procedural','episodic','declarative','quarantine',
       'agent_message','aimos_turn','infrastructure',
       'signal','dream_artifact'
     )
     AND NOT EXISTS (
           SELECT 1 FROM aimos_memory_lineage l WHERE l.child_id = m.id
         );
  GET DIAGNOSTICS rows_lineage_input = ROW_COUNT;

  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -- PART C-B: Lineage genesis_known_unknown — derivation output types
  -- with no recoverable parent metadata. Honest claim: "we know this
  -- memory was derived, but the parent set is lost to history."
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INSERT INTO aimos_memory_lineage
    (child_id, parent_id, parent_ids, derivation_type, attestation_tier, backfilled)
  SELECT m.id, NULL, ARRAY[]::uuid[], 'genesis_known_unknown', 'D1', true
    FROM aimos_memories m
   WHERE m.parent_memory_id IS NULL
     AND m.supersedes_id IS NULL
     AND m.memory_type NOT IN (
       'conversation_feed','book_extract','session_debrief',
       'tacit_knowledge','bibliographic_reference','event_log',
       'procedural','episodic','declarative','quarantine',
       'agent_message','aimos_turn','infrastructure',
       'signal','dream_artifact'
     )
     AND NOT EXISTS (
           SELECT 1 FROM aimos_memory_lineage l WHERE l.child_id = m.id
         );
  GET DIAGNOSTICS rows_lineage_derived = ROW_COUNT;

  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -- PART D1: Lineage 'correct' — memories with supersedes_id + is_correction
  -- where the parent memory STILL EXISTS. parent_id FK-resolvable fast path.
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INSERT INTO aimos_memory_lineage
    (child_id, parent_id, parent_ids, derivation_type, attestation_tier, backfilled)
  SELECT m.id, m.supersedes_id, ARRAY[m.supersedes_id]::uuid[], 'correct', 'D1', true
    FROM aimos_memories m
   WHERE m.supersedes_id IS NOT NULL
     AND m.is_correction = true
     AND EXISTS (SELECT 1 FROM aimos_memories p WHERE p.id = m.supersedes_id)
     AND NOT EXISTS (
           SELECT 1 FROM aimos_memory_lineage l
            WHERE l.child_id = m.id AND l.derivation_type = 'correct'
         );
  GET DIAGNOSTICS rows_lineage_correct = ROW_COUNT;

  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -- PART D2: Orphaned corrections — supersedes_id + is_correction=true but
  -- the parent memory has been deleted. FK on parent_id cannot resolve, so
  -- parent_id is NULL; parent_ids[] retains the dangling UUID as the audit
  -- record ("this memory corrected something with this id, but that
  -- something has been deleted"). derivation_type='genesis_known_unknown'
  -- honestly says "parent lost". Live data: 2 such rows (both corrections
  -- point to deleted parents as of 2026-07-03).
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INSERT INTO aimos_memory_lineage
    (child_id, parent_id, parent_ids, derivation_type, attestation_tier, backfilled)
  SELECT m.id, NULL, ARRAY[m.supersedes_id]::uuid[], 'genesis_known_unknown', 'D1', true
    FROM aimos_memories m
   WHERE m.supersedes_id IS NOT NULL
     AND m.is_correction = true
     AND NOT EXISTS (SELECT 1 FROM aimos_memories p WHERE p.id = m.supersedes_id)
     AND NOT EXISTS (
           SELECT 1 FROM aimos_memory_lineage l
            WHERE l.child_id = m.id AND l.derivation_type = 'genesis_known_unknown'
               AND l.parent_ids = ARRAY[m.supersedes_id]::uuid[]
         );

  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -- PART E1 (defensive): Lineage 'supersede' — parent_memory_id populated
  -- AND parent exists, OR supersedes_id + !is_correction AND parent exists.
  -- Currently 0 rows in live DB, but here for forward-safety.
  -- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INSERT INTO aimos_memory_lineage
    (child_id, parent_id, parent_ids, derivation_type, attestation_tier, backfilled)
  SELECT m.id, COALESCE(m.parent_memory_id, m.supersedes_id),
         ARRAY[COALESCE(m.parent_memory_id, m.supersedes_id)]::uuid[],
         'supersede', 'D1', true
    FROM aimos_memories m
   WHERE (
           (m.parent_memory_id IS NOT NULL
            AND EXISTS (SELECT 1 FROM aimos_memories p WHERE p.id = m.parent_memory_id))
           OR (m.supersedes_id IS NOT NULL AND m.is_correction = false
               AND EXISTS (SELECT 1 FROM aimos_memories p WHERE p.id = m.supersedes_id))
         )
     AND NOT EXISTS (
           SELECT 1 FROM aimos_memory_lineage l
            WHERE l.child_id = m.id AND l.derivation_type = 'supersede'
         );
  GET DIAGNOSTICS rows_lineage_supersede = ROW_COUNT;

  RAISE NOTICE 'Backfill complete: P-anchor=%, P-real=%, lineage-input=%, lineage-derived=%, lineage-correct=%, lineage-supersede=%',
    rows_p_anchor, rows_p_real, rows_lineage_input,
    rows_lineage_derived, rows_lineage_correct, rows_lineage_supersede;
END
$body$;

-- Post-backfill count summary (visible on psql stdout).
SELECT 'provenance_total'    AS metric, count(*)::text AS value FROM aimos_memory_provenance
UNION ALL SELECT 'p_anchor',  count(*)::text FROM aimos_memory_provenance WHERE is_genesis = true  AND backfilled = true AND identity_tier = 'GENESIS'
UNION ALL SELECT 'p_real',    count(*)::text FROM aimos_memory_provenance WHERE is_genesis = true  AND backfilled = true AND identity_tier <> 'GENESIS'
UNION ALL SELECT 'lineage_total', count(*)::text FROM aimos_memory_lineage
UNION ALL SELECT 'lineage_input', count(*)::text FROM aimos_memory_lineage WHERE derivation_type = 'genesis'
UNION ALL SELECT 'lineage_unknown', count(*)::text FROM aimos_memory_lineage WHERE derivation_type = 'genesis_known_unknown'
UNION ALL SELECT 'lineage_correct', count(*)::text FROM aimos_memory_lineage WHERE derivation_type = 'correct'
UNION ALL SELECT 'lineage_supersede', count(*)::text FROM aimos_memory_lineage WHERE derivation_type = 'supersede'
UNION ALL SELECT 'memories_total', count(*)::text FROM aimos_memories;
