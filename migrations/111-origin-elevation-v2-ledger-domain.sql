-- 111-origin-elevation-v2-ledger-domain.sql
-- OB-5 successor: admit the already frozen v2 elevation schema to the native
-- no-fork origin ledger. Earlier applied migrations remain byte-immutable.

SET LOCAL lock_timeout = '10s';

ALTER TABLE public.aimos_origin_ledger_entries
  DROP CONSTRAINT aimos_origin_ledger_object_schema;
ALTER TABLE public.aimos_origin_ledger_entries
  ADD CONSTRAINT aimos_origin_ledger_object_schema CHECK (
    object_schema IN (
      'hom.aimos.memory-origin-binding/v1',
      'hom.aimos.memory-origin-binding/v2',
      'hom.aimos.memory-origin-binding/v3',
      'hom.aimos.origin-elevation/v1',
      'hom.aimos.origin-elevation/v2',
      'hom.aimos.action-origin-verdict/v1'
    )
  );
