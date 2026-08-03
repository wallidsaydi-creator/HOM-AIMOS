-- reconcile-legacy-oracle-rename.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- One-time reconciliation for databases that predate the oracle_* → aimos_*
-- rename (the rename happened in code + migration FILES only; live databases
-- still carry oracle_* relations and schema_migrations rows recorded under the
-- old filenames).
--
-- WHAT IT DOES, in one transaction:
--   1. Renames the 19 legacy oracle_* tables to their aimos_* twins.
--   2. Renames legacy sequences, constraints, and standalone indexes so the
--      end state matches a virgin 001-base-schema install (fresh-ceremony
--      asserts idx_aimos_memories_embedding_hnsw by name).
--   3. Renames the legacy search-vector trigger + function (body touches only
--      NEW.*, so it survives the table rename intact).
--   4. Renames secure_oracle_save → secure_aimos_save so migration 045 can
--      DROP it by its expected name, and REVOKEs its PUBLIC grant immediately
--      (it is SECURITY DEFINER and was executable by PUBLIC).
--   5. Rewrites the 7 schema_migrations rows recorded under pre-rename
--      filenames and NULLs their checksums so the runner's legacy backfill
--      re-baselines them from disk. Without this, migrations/run.js treats the
--      renamed files as PENDING and re-applies them.
--
-- WHY THIS IS NOT A NUMBERED MIGRATION: migrations/run.js loads the applied
-- set once, up front. A migration that fixes schema_migrations mid-run cannot
-- stop the same run from re-executing the renamed files. This script must run
-- BEFORE the runner, via:
--
--   psql -d <db> -v ON_ERROR_STOP=1 -1 -f scripts/db/reconcile-legacy-oracle-rename.sql
--
-- Safe on every database:
--   - virgin / genesis-born DBs (aimos-named already): every step no-ops.
--   - aimos_dev / oracle (legacy-named): full rename + record fix.
-- Idempotent: guarded by existence checks throughout; re-running no-ops.
--
-- ⚠️ TAKE A pg_dump BACKUP FIRST. This is DDL over the corpus tables.
-- ⚠️ Do NOT run against the production `oracle` DB while its server (:9000)
--    is serving — stop the app first; table renames invalidate its statements.

DO $reconcile$
DECLARE
  t     record;
  n_ren int := 0;
BEGIN
  -- ── 1. Tables ──────────────────────────────────────────────────────────────
  FOR t IN
    SELECT c.relname AS old_name,
           'aimos_' || substring(c.relname from 8) AS new_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND c.relname LIKE 'oracle\_%'
  LOOP
    IF EXISTS (SELECT 1 FROM pg_class c2
                 JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = 'public' AND c2.relname = t.new_name) THEN
      RAISE EXCEPTION
        'RECONCILE ABORT: both %.% and %.% exist — split-brain corpus. Resolve manually.',
        'public', t.old_name, 'public', t.new_name;
    END IF;
    EXECUTE format('ALTER TABLE public.%I RENAME TO %I', t.old_name, t.new_name);
    n_ren := n_ren + 1;
  END LOOP;
  RAISE NOTICE 'tables renamed: %', n_ren;

  -- ── 2a. Sequences ──────────────────────────────────────────────────────────
  FOR t IN
    SELECT c.relname AS old_name,
           replace(c.relname, 'oracle', 'aimos') AS new_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'S'
       AND c.relname LIKE '%oracle%'
  LOOP
    EXECUTE format('ALTER SEQUENCE public.%I RENAME TO %I', t.old_name, t.new_name);
  END LOOP;

  -- ── 2b. Constraints (renaming a constraint renames its backing index) ─────
  FOR t IN
    SELECT con.conname AS old_name,
           replace(con.conname, 'oracle', 'aimos') AS new_name,
           con.conrelid::regclass AS tbl
      FROM pg_constraint con
      JOIN pg_class c ON c.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND con.conname LIKE '%oracle%'
  LOOP
    EXECUTE format('ALTER TABLE %s RENAME CONSTRAINT %I TO %I',
                   t.tbl, t.old_name, t.new_name);
  END LOOP;

  -- ── 2c. Remaining standalone indexes ───────────────────────────────────────
  FOR t IN
    SELECT c.relname AS old_name,
           replace(c.relname, 'oracle', 'aimos') AS new_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'i'
       AND c.relname LIKE '%oracle%'
  LOOP
    EXECUTE format('ALTER INDEX public.%I RENAME TO %I', t.old_name, t.new_name);
  END LOOP;

  -- ── 3. Legacy search-vector trigger + function ────────────────────────────
  IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_oracle_search_vector') THEN
    EXECUTE 'ALTER TRIGGER trg_oracle_search_vector ON public.aimos_memories RENAME TO trg_aimos_search_vector';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'oracle_search_vector_update') THEN
    EXECUTE 'ALTER FUNCTION public.oracle_search_vector_update() RENAME TO aimos_search_vector_update';
  END IF;

  -- ── 4. secure_oracle_save → secure_aimos_save, and close the PUBLIC grant ─
  FOR t IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.proname = 'secure_oracle_save'
  LOOP
    EXECUTE format('ALTER FUNCTION %s RENAME TO secure_aimos_save', t.sig);
  END LOOP;
  FOR t IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.proname = 'secure_aimos_save'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', t.sig);
  END LOOP;

  -- ── 5. schema_migrations filename reconciliation ──────────────────────────
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'public' AND c.relname = 'schema_migrations') THEN
    UPDATE schema_migrations SET checksum = NULL, filename = v.new_name
      FROM (VALUES
        ('013-dormancy-oracle-events-index.sql',        '013-dormancy-aimos-events-index.sql'),
        ('016-oracle-save-envelope-nonce-unique.sql',   '016-aimos-save-envelope-nonce-unique.sql'),
        ('017b-system-envelopes-revoke-oracle-app.sql', '017b-system-envelopes-revoke-aimos-app.sql'),
        ('029-rename-piro-runtime-role.sql',            '029-rename-runtime-role.sql'),
        ('030-oracle-memories-content-hash.sql',        '030-aimos-memories-content-hash.sql'),
        ('032-secure-oracle-save-content-hash.sql',     '032-secure-aimos-save-content-hash.sql'),
        ('034-rename-oracle-2-governor-to-housekeeper.sql', '034-rename-aimos-2-governor-to-housekeeper.sql')
      ) AS v(old_name, new_name)
     WHERE schema_migrations.filename = v.old_name;
    RAISE NOTICE 'schema_migrations rows reconciled';
  END IF;

  -- ── Post-conditions (abort the transaction if anything is off) ────────────
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname LIKE 'oracle\_%') THEN
    RAISE EXCEPTION 'RECONCILE ABORT: oracle_* tables remain after rename pass';
  END IF;
END
$reconcile$;
