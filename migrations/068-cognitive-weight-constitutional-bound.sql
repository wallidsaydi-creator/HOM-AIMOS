-- Cognitive relevance is mutable in both directions, but it is never an
-- eligibility/deletion mechanism. The database itself enforces the Aladdin
-- compact interval so every retained memory remains recallable at W_MIN.

ALTER TABLE public.aimos_memories
  ADD CONSTRAINT aimos_memories_cognitive_weight_bound
  CHECK (retrieval_weight IS NOT NULL AND retrieval_weight >= 0.1 AND retrieval_weight <= 3.0)
  NOT VALID;

-- Validation is deliberately fail-closed. A pre-existing out-of-range value
-- requires a separately signed cognitive mutation ceremony; a migration must
-- not rewrite retained state or fabricate provenance.
ALTER TABLE public.aimos_memories
  VALIDATE CONSTRAINT aimos_memories_cognitive_weight_bound;

COMMENT ON CONSTRAINT aimos_memories_cognitive_weight_bound ON public.aimos_memories IS
  'Constitutional cognitive interval [0.1,3.0]. Weight changes are bidirectional signed mutations; 0.1 is low-frequency relevance, never suppression.';
