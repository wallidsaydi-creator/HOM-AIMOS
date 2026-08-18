-- 098-request-receipt-occurrence-lookup.sql
--
-- Scale-correct O(1) authority lookup for a v3 content-state occurrence. The
-- receipt mutation hash is cryptographic evidence, not a content identifier;
-- this non-unique index accelerates an ambiguity-detecting lookup and grants no
-- save, recall, classification, mutation, or deletion authority.

CREATE INDEX CONCURRENTLY IF NOT EXISTS aimos_request_receipts_company_mutation_lookup
  ON public.aimos_request_receipts (company_id, mutation_hash);

COMMENT ON INDEX public.aimos_request_receipts_company_mutation_lookup IS
  'Supports bounded immediate-link verification of request authority referenced by signed occurrence v3 rows.';
