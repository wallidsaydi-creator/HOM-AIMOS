-- Migration 095: native QuIM and Concept/PPR derived retrieval projections.
--
-- These tables are append-only, housekeeper-attested derived indexes over
-- retained canonical memories. They create no memory, disclosure, deletion,
-- classification, or ranking authority. Runtime readers may consume only a
-- complete build whose root is named by signed system configuration.
--
-- Sources:
--   QuIM-RAG (arXiv:2501.02702): question-to-prototype inverted retrieval.
--   HippoRAG (arXiv:2405.14831): query-entity PPR and phrase-to-passage lift.

CREATE TABLE IF NOT EXISTS public.quim_index_builds (
  build_id uuid PRIMARY KEY,
  company_id text NOT NULL,
  schema_version text NOT NULL,
  algorithm_version text NOT NULL,
  question_generator text NOT NULL,
  embedding_model text NOT NULL,
  corpus_root_sha256 bytea NOT NULL CHECK (octet_length(corpus_root_sha256) = 32),
  index_root_sha256 bytea NOT NULL CHECK (octet_length(index_root_sha256) = 32),
  memory_count integer NOT NULL CHECK (memory_count >= 0),
  chunk_count integer NOT NULL CHECK (chunk_count >= 0),
  question_count integer NOT NULL CHECK (question_count >= 0),
  prototype_count integer NOT NULL CHECK (prototype_count > 0),
  max_bucket_size integer NOT NULL CHECK (max_bucket_size > 0),
  authority_event_id uuid NOT NULL REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (company_id, index_root_sha256)
);

ALTER TABLE public.quim_prototypes
  ADD COLUMN IF NOT EXISTS build_id uuid,
  ADD COLUMN IF NOT EXISTS centroid_vector vector(768),
  ADD COLUMN IF NOT EXISTS prototype_identity_sha256 bytea,
  ADD COLUMN IF NOT EXISTS authority_event_id uuid;

ALTER TABLE public.quim_index
  ADD COLUMN IF NOT EXISTS build_id uuid,
  ADD COLUMN IF NOT EXISTS question_embedding_vector vector(768),
  ADD COLUMN IF NOT EXISTS question_sha256 bytea,
  ADD COLUMN IF NOT EXISTS source_content_sha256 bytea,
  ADD COLUMN IF NOT EXISTS row_identity_sha256 bytea,
  ADD COLUMN IF NOT EXISTS chunk_ordinal integer,
  ADD COLUMN IF NOT EXISTS question_ordinal integer,
  ADD COLUMN IF NOT EXISTS authority_event_id uuid;

DO $quim_projection_constraints$
BEGIN
  ALTER TABLE public.quim_prototypes
    DROP CONSTRAINT IF EXISTS quim_prototypes_company_id_prototype_id_key;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'quim_prototypes_build_fkey'
       AND conrelid = 'public.quim_prototypes'::regclass
  ) THEN
    ALTER TABLE public.quim_prototypes
      ADD CONSTRAINT quim_prototypes_build_fkey
      FOREIGN KEY (build_id) REFERENCES public.quim_index_builds(build_id)
      ON DELETE RESTRICT NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'quim_prototypes_authority_event_fkey'
       AND conrelid = 'public.quim_prototypes'::regclass
  ) THEN
    ALTER TABLE public.quim_prototypes
      ADD CONSTRAINT quim_prototypes_authority_event_fkey
      FOREIGN KEY (authority_event_id) REFERENCES public.aimos_events(id)
      ON DELETE RESTRICT NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'quim_prototypes_native_shape'
       AND conrelid = 'public.quim_prototypes'::regclass
  ) THEN
    ALTER TABLE public.quim_prototypes
      ADD CONSTRAINT quim_prototypes_native_shape CHECK (
        build_id IS NULL OR (
          centroid_vector IS NOT NULL
          AND prototype_identity_sha256 IS NOT NULL
          AND octet_length(prototype_identity_sha256) = 32
          AND authority_event_id IS NOT NULL
          AND member_count > 0
        )
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'quim_index_build_fkey'
       AND conrelid = 'public.quim_index'::regclass
  ) THEN
    ALTER TABLE public.quim_index
      ADD CONSTRAINT quim_index_build_fkey
      FOREIGN KEY (build_id) REFERENCES public.quim_index_builds(build_id)
      ON DELETE RESTRICT NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'quim_index_authority_event_fkey'
       AND conrelid = 'public.quim_index'::regclass
  ) THEN
    ALTER TABLE public.quim_index
      ADD CONSTRAINT quim_index_authority_event_fkey
      FOREIGN KEY (authority_event_id) REFERENCES public.aimos_events(id)
      ON DELETE RESTRICT NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'quim_index_native_shape'
       AND conrelid = 'public.quim_index'::regclass
  ) THEN
    ALTER TABLE public.quim_index
      ADD CONSTRAINT quim_index_native_shape CHECK (
        build_id IS NULL OR (
          question_text IS NOT NULL
          AND question_embedding_vector IS NOT NULL
          AND question_sha256 IS NOT NULL AND octet_length(question_sha256) = 32
          AND source_content_sha256 IS NOT NULL AND octet_length(source_content_sha256) = 32
          AND row_identity_sha256 IS NOT NULL AND octet_length(row_identity_sha256) = 32
          AND chunk_ordinal >= 0
          AND question_ordinal >= 0
          AND authority_event_id IS NOT NULL
        )
      ) NOT VALID;
  END IF;

  ALTER TABLE public.quim_index DROP CONSTRAINT IF EXISTS quim_index_chunk_id_fkey;
  ALTER TABLE public.quim_index
    ADD CONSTRAINT quim_index_chunk_id_fkey
    FOREIGN KEY (chunk_id) REFERENCES public.aimos_memories(id)
    ON DELETE RESTRICT NOT VALID;
END
$quim_projection_constraints$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_quim_prototype_build_ordinal
  ON public.quim_prototypes(company_id, build_id, prototype_id)
  WHERE build_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_quim_prototype_identity
  ON public.quim_prototypes(company_id, prototype_identity_sha256)
  WHERE prototype_identity_sha256 IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_quim_index_row_identity
  ON public.quim_index(company_id, row_identity_sha256)
  WHERE row_identity_sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_quim_prototype_build
  ON public.quim_prototypes(company_id, build_id, prototype_id);
CREATE INDEX IF NOT EXISTS idx_quim_index_build_bucket
  ON public.quim_index(company_id, build_id, prototype_id);
CREATE INDEX IF NOT EXISTS idx_quim_index_build_chunk
  ON public.quim_index(company_id, build_id, chunk_id);

CREATE TABLE IF NOT EXISTS public.concept_graph_builds (
  build_id uuid PRIMARY KEY,
  company_id text NOT NULL,
  schema_version text NOT NULL,
  algorithm_version text NOT NULL,
  embedding_model text NOT NULL,
  corpus_root_sha256 bytea NOT NULL CHECK (octet_length(corpus_root_sha256) = 32),
  graph_root_sha256 bytea NOT NULL CHECK (octet_length(graph_root_sha256) = 32),
  memory_count integer NOT NULL CHECK (memory_count >= 0),
  concept_count integer NOT NULL CHECK (concept_count > 0),
  passage_edge_count integer NOT NULL CHECK (passage_edge_count > 0),
  relation_edge_count integer NOT NULL CHECK (relation_edge_count >= 0),
  authority_event_id uuid NOT NULL REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (company_id, graph_root_sha256)
);

CREATE TABLE IF NOT EXISTS public.concept_graph_nodes (
  node_id uuid PRIMARY KEY,
  company_id text NOT NULL,
  build_id uuid NOT NULL REFERENCES public.concept_graph_builds(build_id) ON DELETE RESTRICT,
  canonical_label text NOT NULL,
  normalized_label text NOT NULL,
  entity_type text NOT NULL,
  embedding vector(768) NOT NULL,
  passage_degree integer NOT NULL CHECK (passage_degree > 0),
  specificity double precision NOT NULL CHECK (specificity > 0 AND specificity <= 1),
  node_identity_sha256 bytea NOT NULL CHECK (octet_length(node_identity_sha256) = 32),
  authority_event_id uuid NOT NULL REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (company_id, build_id, normalized_label),
  UNIQUE (company_id, node_identity_sha256)
);

CREATE TABLE IF NOT EXISTS public.concept_passage_edges (
  id bigserial PRIMARY KEY,
  company_id text NOT NULL,
  build_id uuid NOT NULL REFERENCES public.concept_graph_builds(build_id) ON DELETE RESTRICT,
  concept_node_id uuid NOT NULL REFERENCES public.concept_graph_nodes(node_id) ON DELETE RESTRICT,
  memory_id uuid NOT NULL REFERENCES public.aimos_memories(id) ON DELETE RESTRICT,
  weight double precision NOT NULL CHECK (weight > 0 AND weight <= 1),
  source_content_sha256 bytea NOT NULL CHECK (octet_length(source_content_sha256) = 32),
  edge_identity_sha256 bytea NOT NULL CHECK (octet_length(edge_identity_sha256) = 32),
  authority_event_id uuid NOT NULL REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (company_id, edge_identity_sha256),
  UNIQUE (company_id, build_id, concept_node_id, memory_id)
);

CREATE TABLE IF NOT EXISTS public.concept_relation_edges (
  id bigserial PRIMARY KEY,
  company_id text NOT NULL,
  build_id uuid NOT NULL REFERENCES public.concept_graph_builds(build_id) ON DELETE RESTRICT,
  source_concept_node_id uuid NOT NULL REFERENCES public.concept_graph_nodes(node_id) ON DELETE RESTRICT,
  target_concept_node_id uuid NOT NULL REFERENCES public.concept_graph_nodes(node_id) ON DELETE RESTRICT,
  relation_type text NOT NULL,
  weight double precision NOT NULL CHECK (weight > 0 AND weight <= 1),
  source_memory_id uuid REFERENCES public.aimos_memories(id) ON DELETE RESTRICT,
  source_content_sha256 bytea,
  edge_identity_sha256 bytea NOT NULL CHECK (octet_length(edge_identity_sha256) = 32),
  authority_event_id uuid NOT NULL REFERENCES public.aimos_events(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (source_concept_node_id <> target_concept_node_id),
  CHECK (source_content_sha256 IS NULL OR octet_length(source_content_sha256) = 32),
  UNIQUE (company_id, edge_identity_sha256)
);

CREATE INDEX IF NOT EXISTS idx_concept_nodes_build_label
  ON public.concept_graph_nodes(company_id, build_id, normalized_label);
CREATE INDEX IF NOT EXISTS idx_concept_passage_concept
  ON public.concept_passage_edges(company_id, build_id, concept_node_id, memory_id);
CREATE INDEX IF NOT EXISTS idx_concept_passage_memory
  ON public.concept_passage_edges(company_id, build_id, memory_id, concept_node_id);
CREATE INDEX IF NOT EXISTS idx_concept_relation_source
  ON public.concept_relation_edges(company_id, build_id, source_concept_node_id);
CREATE INDEX IF NOT EXISTS idx_concept_relation_target
  ON public.concept_relation_edges(company_id, build_id, target_concept_node_id);

DO $native_retrieval_projection_acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    GRANT SELECT, INSERT ON
      public.quim_index_builds,
      public.quim_prototypes,
      public.quim_index,
      public.concept_graph_builds,
      public.concept_graph_nodes,
      public.concept_passage_edges,
      public.concept_relation_edges
      TO agent_runtime;
    GRANT USAGE, SELECT ON SEQUENCE
      public.quim_prototypes_id_seq,
      public.quim_index_id_seq,
      public.concept_passage_edges_id_seq,
      public.concept_relation_edges_id_seq
      TO agent_runtime;
    REVOKE UPDATE, DELETE, TRUNCATE ON
      public.quim_index_builds,
      public.quim_prototypes,
      public.quim_index,
      public.concept_graph_builds,
      public.concept_graph_nodes,
      public.concept_passage_edges,
      public.concept_relation_edges
      FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON
      public.quim_index_builds,
      public.quim_prototypes,
      public.quim_index,
      public.concept_graph_builds,
      public.concept_graph_nodes,
      public.concept_passage_edges,
      public.concept_relation_edges
      FROM aimos_app;
  END IF;
END
$native_retrieval_projection_acl$;

COMMENT ON TABLE public.quim_index_builds IS
  'Append-only signed QuIM build manifests. Runtime consumption additionally requires an exact signed activation policy.';
COMMENT ON TABLE public.concept_graph_builds IS
  'Append-only signed HippoRAG-derived concept graph manifests. Runtime consumption additionally requires an exact signed activation policy.';
COMMENT ON TABLE public.concept_passage_edges IS
  'Source-content-bound phrase-to-passage projection; no retention or disclosure authority.';
COMMENT ON TABLE public.concept_relation_edges IS
  'Source-grounded or bounded synonym concept relation; no retention or disclosure authority.';
