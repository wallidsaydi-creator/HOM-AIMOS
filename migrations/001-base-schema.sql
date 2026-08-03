-- migrations/001-base-schema.sql
-- Genesis base schema for AIMOS. Creates the base tables that migrations
-- 002-039 expect to already exist. Derived from pg_dump --schema-only of the
-- faithful production copy (aimos_dev, 22,020 memories), with the oracle_* ->
-- aimos_* rename applied and all objects that LATER migrations create/alter
-- removed (see report). Every statement is idempotent.
--
-- Boundary: RLS enable/force/policies belong to 002; the medallion/quant/node_type/
-- content_hash columns + their indexes belong to 004/005/007/030; cube_scope and
-- propagated_from_agent belong to 038; parent_event_id belongs to 039. None are
-- duplicated here. parent_memory_id IS kept here because migration 020 reads
-- aimos_memories.parent_memory_id, but the quantum migration that adds it is
-- sequenced at 038 (it historically ran first) -- so the base must carry it.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS agent_alarms (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id text NOT NULL,
    agent_id text NOT NULL,
    alarm_time timestamp with time zone NOT NULL,
    prompt text NOT NULL,
    status text DEFAULT 'pending'::text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_alarms_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'fired'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS agent_messages (
    id integer NOT NULL,
    company_id text NOT NULL,
    from_agent text NOT NULL,
    to_agent text NOT NULL,
    performative text NOT NULL,
    content jsonb NOT NULL,
    in_reply_to integer,
    conversation_id text,
    status text DEFAULT 'pending'::text,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone,
    CONSTRAINT agent_messages_performative_check CHECK ((performative = ANY (ARRAY['ASSERT'::text, 'QUERY'::text, 'REQUEST'::text, 'INFORM'::text, 'PROPOSE'::text, 'CONFIRM'::text, 'REJECT'::text]))),
    CONSTRAINT agent_messages_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'read'::text, 'replied'::text, 'expired'::text])))
);

CREATE SEQUENCE IF NOT EXISTS agent_messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE agent_messages_id_seq OWNED BY agent_messages.id;

CREATE TABLE IF NOT EXISTS agent_model_policy (
    company_id text NOT NULL,
    agent_id text NOT NULL,
    model_id text NOT NULL,
    priority integer DEFAULT 100 NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_permissions (
    company_id text NOT NULL,
    agent_id text NOT NULL,
    capability text NOT NULL,
    allowed boolean DEFAULT false,
    updated_by text,
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_profiles (
    company_id text NOT NULL,
    agent_id text NOT NULL,
    name text NOT NULL,
    tier text DEFAULT 'light'::text NOT NULL,
    persona text DEFAULT 'General agent'::text NOT NULL,
    persona_embedding vector(768),
    persona_version integer DEFAULT 1 NOT NULL,
    clearance_level integer DEFAULT 1 NOT NULL,
    tool_profile text DEFAULT 'full'::text NOT NULL,
    tool_deltas jsonb DEFAULT '{}'::jsonb NOT NULL,
    allow_delegation boolean DEFAULT true NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    last_seen timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    tad_resistance_score double precision DEFAULT 0.5 NOT NULL,
    role_slot text DEFAULT 'general'::text NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_routing_policy (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id text NOT NULL,
    source_agent_id text NOT NULL,
    target_agent_id text NOT NULL,
    match_type text DEFAULT 'keyword'::text NOT NULL,
    intent text,
    keywords text[] DEFAULT '{}'::text[] NOT NULL,
    priority integer DEFAULT 100 NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_runs (
    run_id text NOT NULL,
    company_id text NOT NULL,
    session_key text NOT NULL,
    idempotency_key text,
    source_agent_id text NOT NULL,
    resolved_agent_id text NOT NULL,
    persona_version integer DEFAULT 1 NOT NULL,
    model_requested text,
    model_resolved text,
    fallback_used boolean DEFAULT false NOT NULL,
    delegated_to text,
    queue_wait_ms integer DEFAULT 0 NOT NULL,
    channel text,
    peer_id text,
    intent text,
    status text DEFAULT 'running'::text NOT NULL,
    error text,
    response_preview text,
    prompt_chars integer DEFAULT 0 NOT NULL,
    response_chars integer DEFAULT 0 NOT NULL,
    context_compacted boolean DEFAULT false NOT NULL,
    context_compaction_ratio double precision,
    self_healed_at timestamp without time zone,
    self_heal_note text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    confidence double precision,
    authorization_trajectory jsonb DEFAULT '[]'::jsonb NOT NULL,
    authorization_chain_hash text
);

CREATE TABLE IF NOT EXISTS agent_state (
    company_id text NOT NULL,
    agent_id text NOT NULL,
    phase text DEFAULT 'idle'::text,
    current_task text,
    beliefs jsonb DEFAULT '{}'::jsonb,
    desires jsonb DEFAULT '{}'::jsonb,
    intentions jsonb DEFAULT '[]'::jsonb,
    waiting_for text,
    blockers text[] DEFAULT '{}'::text[],
    confidence double precision DEFAULT 0.5,
    last_action text,
    next_action text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_tokens (
    id integer NOT NULL,
    company_id text NOT NULL,
    agent_id text NOT NULL,
    token text NOT NULL,
    label text,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone
);

CREATE SEQUENCE IF NOT EXISTS agent_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE agent_tokens_id_seq OWNED BY agent_tokens.id;

CREATE TABLE IF NOT EXISTS agent_trust (
    agent_id text NOT NULL,
    company_id text NOT NULL,
    trust_score double precision DEFAULT 0.5 NOT NULL,
    estimated_latency_ms double precision DEFAULT 5000 NOT NULL,
    liveness boolean DEFAULT true,
    success_count integer DEFAULT 0,
    failure_count integer DEFAULT 0,
    last_success_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_debt_register (
    id integer NOT NULL,
    company_id text NOT NULL,
    category text NOT NULL,
    severity text DEFAULT 'medium'::text NOT NULL,
    blast_radius text,
    remediation_effort text,
    owner text,
    status text DEFAULT 'open'::text NOT NULL,
    description text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS ai_debt_register_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE ai_debt_register_id_seq OWNED BY ai_debt_register.id;

CREATE TABLE IF NOT EXISTS autonomy_config (
    company_id text NOT NULL,
    agent_id text NOT NULL,
    auto_threshold double precision DEFAULT 0.8,
    notify_threshold double precision DEFAULT 0.6,
    escalate_below double precision DEFAULT 0.6,
    allowed_actions text[] DEFAULT '{recall,save}'::text[],
    blocked_actions text[] DEFAULT '{deploy,trade,delete}'::text[],
    max_tool_loops integer DEFAULT 8,
    require_human_above_cost double precision DEFAULT 0.0,
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS capability_tracking (
    id integer NOT NULL,
    company_id text NOT NULL,
    domain text NOT NULL,
    h_value double precision DEFAULT 1.0 NOT NULL,
    d_value double precision DEFAULT 0.0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS capability_tracking_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE capability_tracking_id_seq OWNED BY capability_tracking.id;

CREATE TABLE IF NOT EXISTS directive_claims (
    directive_id uuid NOT NULL,
    company_id text NOT NULL,
    claimed_by text NOT NULL,
    run_id text,
    lease_until timestamp without time zone NOT NULL,
    status text DEFAULT 'claimed'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS dream_summary_layers (
    id integer NOT NULL,
    company_id text NOT NULL,
    dream_date date NOT NULL,
    layer integer NOT NULL,
    parent_layer_id integer,
    summary text NOT NULL,
    embedding vector(768),
    theme text,
    event_count integer DEFAULT 0,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT dream_summary_layers_layer_check CHECK ((layer = ANY (ARRAY[1, 2, 3])))
);

CREATE SEQUENCE IF NOT EXISTS dream_summary_layers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE dream_summary_layers_id_seq OWNED BY dream_summary_layers.id;

CREATE TABLE IF NOT EXISTS embedding_projections (
    id integer NOT NULL,
    company_id text NOT NULL,
    source_dimensions integer NOT NULL,
    stable_dimensions integer NOT NULL,
    matrix_data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS embedding_projections_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE embedding_projections_id_seq OWNED BY embedding_projections.id;

CREATE TABLE IF NOT EXISTS entity_memory_edges (
    id integer NOT NULL,
    company_id text DEFAULT 'hom'::text NOT NULL,
    entity text NOT NULL,
    entity_type text DEFAULT 'unknown'::text NOT NULL,
    memory_id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS entity_memory_edges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE entity_memory_edges_id_seq OWNED BY entity_memory_edges.id;

CREATE TABLE IF NOT EXISTS fragility_labels (
    id integer NOT NULL,
    company_id text NOT NULL,
    component text NOT NULL,
    fragility text NOT NULL,
    rationale text,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT fragility_labels_fragility_check CHECK ((fragility = ANY (ARRAY['fragile'::text, 'robust'::text, 'antifragile'::text])))
);

CREATE SEQUENCE IF NOT EXISTS fragility_labels_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE fragility_labels_id_seq OWNED BY fragility_labels.id;

CREATE TABLE IF NOT EXISTS integration_settings (
    company_id text NOT NULL,
    provider text NOT NULL,
    enabled boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS integration_tokens (
    company_id text NOT NULL,
    provider text NOT NULL,
    access_token text,
    refresh_token text,
    expires_at timestamp without time zone,
    metadata jsonb DEFAULT '{}'::jsonb,
    updated_at timestamp without time zone DEFAULT now(),
    id uuid,
    created_at timestamp with time zone DEFAULT now(),
    cluster_id text DEFAULT 'identity_vault.auth'::text,
    auth_type text DEFAULT 'oauth'::text
);

CREATE TABLE IF NOT EXISTS intervention_cost_matrix (
    id integer NOT NULL,
    company_id text NOT NULL,
    action_type text NOT NULL,
    fp_cost double precision DEFAULT 0,
    fn_cost double precision DEFAULT 0,
    tp_benefit double precision DEFAULT 0,
    tn_benefit double precision DEFAULT 0,
    notes text,
    updated_at timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE IF NOT EXISTS intervention_cost_matrix_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE intervention_cost_matrix_id_seq OWNED BY intervention_cost_matrix.id;

CREATE TABLE IF NOT EXISTS mcp_connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id text NOT NULL,
    name text NOT NULL,
    url text NOT NULL,
    protocol text DEFAULT 'mcp'::text,
    status text DEFAULT 'connected'::text,
    metadata jsonb DEFAULT '{}'::jsonb,
    last_error text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT mcp_connections_status_check CHECK ((status = ANY (ARRAY['connected'::text, 'disconnected'::text, 'error'::text])))
);

CREATE TABLE IF NOT EXISTS memory_cross_refs (
    id integer NOT NULL,
    company_id text NOT NULL,
    source_memory_id uuid NOT NULL,
    target_memory_id uuid NOT NULL,
    similarity double precision NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    edge_strength real DEFAULT 0,
    edge_type text DEFAULT 'similarity'::text
);

CREATE SEQUENCE IF NOT EXISTS memory_cross_refs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE memory_cross_refs_id_seq OWNED BY memory_cross_refs.id;

CREATE TABLE IF NOT EXISTS model_registry (
    id integer NOT NULL,
    company_id text NOT NULL,
    model_id text NOT NULL,
    version text NOT NULL,
    framework text NOT NULL,
    eval_metric text NOT NULL,
    threshold double precision NOT NULL,
    status text DEFAULT 'experimental'::text NOT NULL,
    metadata jsonb,
    registered_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS model_registry_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE model_registry_id_seq OWNED BY model_registry.id;

CREATE TABLE IF NOT EXISTS aimos_capsules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    task_id text NOT NULL,
    company_id text NOT NULL,
    agent_id text NOT NULL,
    goal text,
    status text DEFAULT 'running'::text,
    step integer DEFAULT 0,
    scratchpad jsonb,
    checkpoint_state jsonb,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aimos_conflicts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id text NOT NULL,
    old_memory_id uuid,
    new_memory_id uuid,
    conflict_type text,
    resolution text,
    resolved_by text,
    resolved_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aimos_directives (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id text NOT NULL,
    agent_id text NOT NULL,
    goal text NOT NULL,
    status text DEFAULT 'pending'::text,
    priority integer DEFAULT 1,
    clearance_level integer DEFAULT 5,
    result jsonb,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    archived_at timestamp without time zone,
    archived_reason text,
    CONSTRAINT aimos_directives_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])))
);

CREATE TABLE IF NOT EXISTS aimos_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ts timestamp without time zone DEFAULT now(),
    company_id text NOT NULL,
    agent_id text NOT NULL,
    operation text NOT NULL,
    key text,
    metadata jsonb
);

CREATE TABLE IF NOT EXISTS aimos_forgetting_curve (
    id integer NOT NULL,
    company_id text NOT NULL,
    memory_id text,
    decay_constant double precision DEFAULT 0.15 NOT NULL,
    forgetting_exponent double precision DEFAULT 0.5 NOT NULL,
    sample_count integer DEFAULT 0 NOT NULL,
    last_fit_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS aimos_forgetting_curve_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE aimos_forgetting_curve_id_seq OWNED BY aimos_forgetting_curve.id;

CREATE TABLE IF NOT EXISTS aimos_memories (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id text NOT NULL,
    agent_id text NOT NULL,
    key text NOT NULL,
    value text NOT NULL,
    embedding vector(768),
    scope text NOT NULL,
    clearance_level integer DEFAULT 1,
    memory_type text DEFAULT 'declarative'::text,
    source text DEFAULT 'internal'::text,
    memory_tier text DEFAULT 'short-term'::text,
    decay_weight double precision DEFAULT 1.0,
    promoted_at timestamp with time zone,
    expires_at timestamp with time zone,
    is_correction boolean DEFAULT false,
    supersedes_id uuid,
    credit_score numeric DEFAULT 1.0,
    temporal_weight numeric DEFAULT 1.0,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    is_active boolean DEFAULT true,
    data_class text DEFAULT 'public'::text,
    parent_memory_id uuid,
    search_vector tsvector,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    utility_score double precision,
    trust_score double precision,
    retrieval_weight real DEFAULT 1.0,
    consolidation_age real DEFAULT 1.0,
    access_count integer DEFAULT 0,
    last_accessed_at timestamp with time zone,
    eligibility_tag jsonb,
    repetition_count integer DEFAULT 0,
    ease_factor real DEFAULT 2.5,
    next_review_at timestamp with time zone,
    useful_count integer DEFAULT 0,
    last_useful_at timestamp with time zone,
    memory_tags text[] DEFAULT '{}'::text[],
    ts_created timestamp with time zone DEFAULT now(),
    cluster_id text,
    last_verified_at timestamp with time zone,
    verified_by text,
    verification_basis text,
    freshness_state text DEFAULT 'unverified'::text,
    semantic_triples jsonb,
    surprise_at_save double precision,
    compression_ratio double precision DEFAULT 1.0,
    CONSTRAINT aimos_memories_data_class_check CHECK ((data_class = ANY (ARRAY['public'::text, 'internal'::text, 'confidential'::text, 'restricted'::text]))),
    CONSTRAINT aimos_memories_freshness_state_check CHECK ((freshness_state = ANY (ARRAY['fresh'::text, 'aging'::text, 'stale'::text, 'historical'::text, 'unverified'::text]))),
    CONSTRAINT aimos_memories_memory_tier_check CHECK ((memory_tier = ANY (ARRAY['short-term'::text, 'working'::text, 'long-term'::text])))
);

CREATE TABLE IF NOT EXISTS aimos_retention_config (
    company_id text NOT NULL,
    short_term_hours integer DEFAULT 6,
    working_hours integer DEFAULT 48,
    decay_rate double precision DEFAULT 0.95,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aimos_retrieval_drift_snapshots (
    id integer NOT NULL,
    company_id text NOT NULL,
    benchmark_name text NOT NULL,
    benchmark_path text NOT NULL,
    benchmark_exists boolean DEFAULT false NOT NULL,
    benchmark_mtime timestamp with time zone,
    benchmark_age_hours double precision,
    benchmark_run_id text,
    benchmark_accuracy double precision,
    benchmark_correct integer,
    benchmark_total_questions integer,
    avg_evidence_count double precision,
    zero_evidence_rate double precision,
    not_found_rate double precision,
    avg_latency_ms integer,
    hom_active_memory_count integer CONSTRAINT aimos_retrieval_drift_snapsho_hom_active_memory_count_not_null NOT NULL,
    total_active_memory_count integer CONSTRAINT aimos_retrieval_drift_snaps_total_active_memory_count_not_null NOT NULL,
    benchmark_memory_count_hom_active integer,
    benchmark_memory_count_total_active integer,
    memory_growth_since_benchmark integer,
    memory_growth_since_benchmark_ratio double precision,
    accuracy_delta_from_previous double precision,
    zero_evidence_delta_from_previous double precision,
    status text NOT NULL,
    reasons jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS aimos_retrieval_drift_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE aimos_retrieval_drift_snapshots_id_seq OWNED BY aimos_retrieval_drift_snapshots.id;

CREATE TABLE IF NOT EXISTS aimos_skills (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id text NOT NULL,
    skill_name text NOT NULL,
    content text,
    clearance_level integer DEFAULT 1,
    created_at timestamp without time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS procedural_skills (
    id integer NOT NULL,
    company_id text NOT NULL,
    agent_id text DEFAULT 'system'::text NOT NULL,
    skill_name text NOT NULL,
    trigger_pattern text,
    steps jsonb DEFAULT '[]'::jsonb NOT NULL,
    expected_outcome text,
    success_count integer DEFAULT 0,
    fail_count integer DEFAULT 0,
    last_used timestamp with time zone,
    tags text[] DEFAULT '{}'::text[],
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    skill_embedding vector(768)
);

CREATE SEQUENCE IF NOT EXISTS procedural_skills_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE procedural_skills_id_seq OWNED BY procedural_skills.id;

CREATE TABLE IF NOT EXISTS recall_calibration (
    company_id text NOT NULL,
    channel text NOT NULL,
    intercept double precision DEFAULT 0.0 NOT NULL,
    slope double precision DEFAULT 1.0 NOT NULL,
    learning_rate double precision DEFAULT 0.01 NOT NULL,
    round_count integer DEFAULT 0 NOT NULL,
    correction_history jsonb DEFAULT '[]'::jsonb,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT recall_calibration_channel_check CHECK ((channel = ANY (ARRAY['belief'::text, 'preference'::text])))
);

CREATE TABLE IF NOT EXISTS recall_observations (
    id integer NOT NULL,
    company_id text NOT NULL,
    memory_id uuid,
    offline_score double precision NOT NULL,
    online_usefulness double precision,
    channel text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE IF NOT EXISTS recall_observations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE recall_observations_id_seq OWNED BY recall_observations.id;

CREATE TABLE IF NOT EXISTS recommendation_log (
    id integer NOT NULL,
    company_id text NOT NULL,
    agent_id text NOT NULL,
    recommendation text NOT NULL,
    confidence_at_time double precision NOT NULL,
    outcome_window_hours integer DEFAULT 24,
    outcome_due_at timestamp with time zone,
    actual_outcome text,
    outcome_score double precision,
    scored_at timestamp with time zone,
    context jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE IF NOT EXISTS recommendation_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE recommendation_log_id_seq OWNED BY recommendation_log.id;

CREATE TABLE IF NOT EXISTS retrieval_pheromones (
    id integer NOT NULL,
    company_id text NOT NULL,
    memory_id integer,
    pheromone_level double precision DEFAULT 1.0,
    last_accessed timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now(),
    memory_id_a uuid,
    memory_id_b uuid,
    tau real DEFAULT 0.1,
    updated_at timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE IF NOT EXISTS retrieval_pheromones_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE retrieval_pheromones_id_seq OWNED BY retrieval_pheromones.id;

CREATE TABLE IF NOT EXISTS rule_hierarchy (
    id text NOT NULL,
    company_id text NOT NULL,
    description text NOT NULL,
    level integer NOT NULL,
    is_represented boolean DEFAULT true,
    is_causally_accessible boolean DEFAULT false,
    last_modified_by text,
    last_modified_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS run_idempotency (
    company_id text NOT NULL,
    agent_id text NOT NULL,
    idempotency_key text NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id text NOT NULL,
    company_id text NOT NULL,
    label text NOT NULL,
    cron_expression text NOT NULL,
    task_description text NOT NULL,
    agent_id text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    last_run_at timestamp with time zone,
    last_status text,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS session_lanes (
    company_id text NOT NULL,
    session_key text NOT NULL,
    run_status text DEFAULT 'idle'::text NOT NULL,
    active_run_id text,
    last_agent_id text,
    last_model text,
    last_run_at timestamp without time zone,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS skill_running_stats (
    id integer NOT NULL,
    company_id text NOT NULL,
    skill_id text NOT NULL,
    mu double precision DEFAULT 0 NOT NULL,
    variance double precision DEFAULT 1 NOT NULL,
    n_samples integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS skill_running_stats_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE skill_running_stats_id_seq OWNED BY skill_running_stats.id;

CREATE TABLE IF NOT EXISTS supersession_events (
    id integer NOT NULL,
    company_id text NOT NULL,
    prior_memory_id uuid NOT NULL,
    post_memory_id uuid NOT NULL,
    trigger_type text DEFAULT 'correction'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb
);

CREATE SEQUENCE IF NOT EXISTS supersession_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE supersession_events_id_seq OWNED BY supersession_events.id;

CREATE TABLE IF NOT EXISTS transformation_cache (
    company_id text NOT NULL,
    cache_key text NOT NULL,
    input_schema_hash text NOT NULL,
    output_schema_hash text NOT NULL,
    result jsonb NOT NULL,
    hit_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    last_hit_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trigger_rules (
    id integer NOT NULL,
    company_id text NOT NULL,
    name text NOT NULL,
    trigger_type text NOT NULL,
    condition jsonb NOT NULL,
    action jsonb NOT NULL,
    enabled boolean DEFAULT true,
    last_fired timestamp with time zone,
    fire_count integer DEFAULT 0,
    cooldown_seconds integer DEFAULT 300,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT trigger_rules_trigger_type_check CHECK ((trigger_type = ANY (ARRAY['memory_save'::text, 'event_log'::text, 'schedule'::text, 'threshold'::text, 'agent_state_change'::text])))
);

CREATE SEQUENCE IF NOT EXISTS trigger_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE trigger_rules_id_seq OWNED BY trigger_rules.id;

CREATE TABLE IF NOT EXISTS user_reference_points (
    id integer NOT NULL,
    company_id text DEFAULT 'hom'::text NOT NULL,
    user_id text NOT NULL,
    domain text NOT NULL,
    reference_point double precision DEFAULT 0.5 NOT NULL,
    n_samples integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS user_reference_points_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE user_reference_points_id_seq OWNED BY user_reference_points.id;

ALTER TABLE ONLY agent_messages ALTER COLUMN id SET DEFAULT nextval('agent_messages_id_seq'::regclass);

ALTER TABLE ONLY agent_tokens ALTER COLUMN id SET DEFAULT nextval('agent_tokens_id_seq'::regclass);

ALTER TABLE ONLY ai_debt_register ALTER COLUMN id SET DEFAULT nextval('ai_debt_register_id_seq'::regclass);

ALTER TABLE ONLY capability_tracking ALTER COLUMN id SET DEFAULT nextval('capability_tracking_id_seq'::regclass);

ALTER TABLE ONLY dream_summary_layers ALTER COLUMN id SET DEFAULT nextval('dream_summary_layers_id_seq'::regclass);

ALTER TABLE ONLY embedding_projections ALTER COLUMN id SET DEFAULT nextval('embedding_projections_id_seq'::regclass);

ALTER TABLE ONLY entity_memory_edges ALTER COLUMN id SET DEFAULT nextval('entity_memory_edges_id_seq'::regclass);

ALTER TABLE ONLY fragility_labels ALTER COLUMN id SET DEFAULT nextval('fragility_labels_id_seq'::regclass);

ALTER TABLE ONLY intervention_cost_matrix ALTER COLUMN id SET DEFAULT nextval('intervention_cost_matrix_id_seq'::regclass);

ALTER TABLE ONLY memory_cross_refs ALTER COLUMN id SET DEFAULT nextval('memory_cross_refs_id_seq'::regclass);

ALTER TABLE ONLY model_registry ALTER COLUMN id SET DEFAULT nextval('model_registry_id_seq'::regclass);

ALTER TABLE ONLY aimos_forgetting_curve ALTER COLUMN id SET DEFAULT nextval('aimos_forgetting_curve_id_seq'::regclass);

ALTER TABLE ONLY aimos_retrieval_drift_snapshots ALTER COLUMN id SET DEFAULT nextval('aimos_retrieval_drift_snapshots_id_seq'::regclass);

ALTER TABLE ONLY procedural_skills ALTER COLUMN id SET DEFAULT nextval('procedural_skills_id_seq'::regclass);

ALTER TABLE ONLY recall_observations ALTER COLUMN id SET DEFAULT nextval('recall_observations_id_seq'::regclass);

ALTER TABLE ONLY recommendation_log ALTER COLUMN id SET DEFAULT nextval('recommendation_log_id_seq'::regclass);

ALTER TABLE ONLY retrieval_pheromones ALTER COLUMN id SET DEFAULT nextval('retrieval_pheromones_id_seq'::regclass);

ALTER TABLE ONLY skill_running_stats ALTER COLUMN id SET DEFAULT nextval('skill_running_stats_id_seq'::regclass);

ALTER TABLE ONLY supersession_events ALTER COLUMN id SET DEFAULT nextval('supersession_events_id_seq'::regclass);

ALTER TABLE ONLY trigger_rules ALTER COLUMN id SET DEFAULT nextval('trigger_rules_id_seq'::regclass);

ALTER TABLE ONLY user_reference_points ALTER COLUMN id SET DEFAULT nextval('user_reference_points_id_seq'::regclass);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_alarms_pkey' AND conrelid = 'agent_alarms'::regclass) THEN
    ALTER TABLE ONLY agent_alarms
    ADD CONSTRAINT agent_alarms_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_messages_pkey' AND conrelid = 'agent_messages'::regclass) THEN
    ALTER TABLE ONLY agent_messages
    ADD CONSTRAINT agent_messages_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_model_policy_pkey' AND conrelid = 'agent_model_policy'::regclass) THEN
    ALTER TABLE ONLY agent_model_policy
    ADD CONSTRAINT agent_model_policy_pkey PRIMARY KEY (company_id, agent_id, model_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_permissions_pkey' AND conrelid = 'agent_permissions'::regclass) THEN
    ALTER TABLE ONLY agent_permissions
    ADD CONSTRAINT agent_permissions_pkey PRIMARY KEY (company_id, agent_id, capability);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_profiles_pkey' AND conrelid = 'agent_profiles'::regclass) THEN
    ALTER TABLE ONLY agent_profiles
    ADD CONSTRAINT agent_profiles_pkey PRIMARY KEY (company_id, agent_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_routing_policy_pkey' AND conrelid = 'agent_routing_policy'::regclass) THEN
    ALTER TABLE ONLY agent_routing_policy
    ADD CONSTRAINT agent_routing_policy_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_runs_pkey' AND conrelid = 'agent_runs'::regclass) THEN
    ALTER TABLE ONLY agent_runs
    ADD CONSTRAINT agent_runs_pkey PRIMARY KEY (run_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_state_pkey' AND conrelid = 'agent_state'::regclass) THEN
    ALTER TABLE ONLY agent_state
    ADD CONSTRAINT agent_state_pkey PRIMARY KEY (company_id, agent_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_tokens_pkey' AND conrelid = 'agent_tokens'::regclass) THEN
    ALTER TABLE ONLY agent_tokens
    ADD CONSTRAINT agent_tokens_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_trust_pkey' AND conrelid = 'agent_trust'::regclass) THEN
    ALTER TABLE ONLY agent_trust
    ADD CONSTRAINT agent_trust_pkey PRIMARY KEY (agent_id, company_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ai_debt_register_pkey' AND conrelid = 'ai_debt_register'::regclass) THEN
    ALTER TABLE ONLY ai_debt_register
    ADD CONSTRAINT ai_debt_register_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'autonomy_config_pkey' AND conrelid = 'autonomy_config'::regclass) THEN
    ALTER TABLE ONLY autonomy_config
    ADD CONSTRAINT autonomy_config_pkey PRIMARY KEY (company_id, agent_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'capability_tracking_company_id_domain_key' AND conrelid = 'capability_tracking'::regclass) THEN
    ALTER TABLE ONLY capability_tracking
    ADD CONSTRAINT capability_tracking_company_id_domain_key UNIQUE (company_id, domain);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'capability_tracking_pkey' AND conrelid = 'capability_tracking'::regclass) THEN
    ALTER TABLE ONLY capability_tracking
    ADD CONSTRAINT capability_tracking_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'directive_claims_pkey' AND conrelid = 'directive_claims'::regclass) THEN
    ALTER TABLE ONLY directive_claims
    ADD CONSTRAINT directive_claims_pkey PRIMARY KEY (directive_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'dream_summary_layers_pkey' AND conrelid = 'dream_summary_layers'::regclass) THEN
    ALTER TABLE ONLY dream_summary_layers
    ADD CONSTRAINT dream_summary_layers_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'embedding_projections_company_id_source_dimensions_stable_d_key' AND conrelid = 'embedding_projections'::regclass) THEN
    ALTER TABLE ONLY embedding_projections
    ADD CONSTRAINT embedding_projections_company_id_source_dimensions_stable_d_key UNIQUE (company_id, source_dimensions, stable_dimensions);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'embedding_projections_pkey' AND conrelid = 'embedding_projections'::regclass) THEN
    ALTER TABLE ONLY embedding_projections
    ADD CONSTRAINT embedding_projections_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'entity_memory_edges_pkey' AND conrelid = 'entity_memory_edges'::regclass) THEN
    ALTER TABLE ONLY entity_memory_edges
    ADD CONSTRAINT entity_memory_edges_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fragility_labels_company_id_component_key' AND conrelid = 'fragility_labels'::regclass) THEN
    ALTER TABLE ONLY fragility_labels
    ADD CONSTRAINT fragility_labels_company_id_component_key UNIQUE (company_id, component);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fragility_labels_pkey' AND conrelid = 'fragility_labels'::regclass) THEN
    ALTER TABLE ONLY fragility_labels
    ADD CONSTRAINT fragility_labels_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'integration_settings_pkey' AND conrelid = 'integration_settings'::regclass) THEN
    ALTER TABLE ONLY integration_settings
    ADD CONSTRAINT integration_settings_pkey PRIMARY KEY (company_id, provider);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'intervention_cost_matrix_company_id_action_type_key' AND conrelid = 'intervention_cost_matrix'::regclass) THEN
    ALTER TABLE ONLY intervention_cost_matrix
    ADD CONSTRAINT intervention_cost_matrix_company_id_action_type_key UNIQUE (company_id, action_type);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'intervention_cost_matrix_pkey' AND conrelid = 'intervention_cost_matrix'::regclass) THEN
    ALTER TABLE ONLY intervention_cost_matrix
    ADD CONSTRAINT intervention_cost_matrix_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'mcp_connections_company_id_name_key' AND conrelid = 'mcp_connections'::regclass) THEN
    ALTER TABLE ONLY mcp_connections
    ADD CONSTRAINT mcp_connections_company_id_name_key UNIQUE (company_id, name);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'mcp_connections_pkey' AND conrelid = 'mcp_connections'::regclass) THEN
    ALTER TABLE ONLY mcp_connections
    ADD CONSTRAINT mcp_connections_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'memory_cross_refs_company_id_source_memory_id_target_memory_key' AND conrelid = 'memory_cross_refs'::regclass) THEN
    ALTER TABLE ONLY memory_cross_refs
    ADD CONSTRAINT memory_cross_refs_company_id_source_memory_id_target_memory_key UNIQUE (company_id, source_memory_id, target_memory_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'memory_cross_refs_pkey' AND conrelid = 'memory_cross_refs'::regclass) THEN
    ALTER TABLE ONLY memory_cross_refs
    ADD CONSTRAINT memory_cross_refs_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'model_registry_company_id_model_id_version_key' AND conrelid = 'model_registry'::regclass) THEN
    ALTER TABLE ONLY model_registry
    ADD CONSTRAINT model_registry_company_id_model_id_version_key UNIQUE (company_id, model_id, version);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'model_registry_pkey' AND conrelid = 'model_registry'::regclass) THEN
    ALTER TABLE ONLY model_registry
    ADD CONSTRAINT model_registry_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_capsules_pkey' AND conrelid = 'aimos_capsules'::regclass) THEN
    ALTER TABLE ONLY aimos_capsules
    ADD CONSTRAINT aimos_capsules_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_capsules_task_id_key' AND conrelid = 'aimos_capsules'::regclass) THEN
    ALTER TABLE ONLY aimos_capsules
    ADD CONSTRAINT aimos_capsules_task_id_key UNIQUE (task_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_conflicts_pkey' AND conrelid = 'aimos_conflicts'::regclass) THEN
    ALTER TABLE ONLY aimos_conflicts
    ADD CONSTRAINT aimos_conflicts_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_directives_pkey' AND conrelid = 'aimos_directives'::regclass) THEN
    ALTER TABLE ONLY aimos_directives
    ADD CONSTRAINT aimos_directives_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_events_pkey' AND conrelid = 'aimos_events'::regclass) THEN
    ALTER TABLE ONLY aimos_events
    ADD CONSTRAINT aimos_events_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_forgetting_curve_pkey' AND conrelid = 'aimos_forgetting_curve'::regclass) THEN
    ALTER TABLE ONLY aimos_forgetting_curve
    ADD CONSTRAINT aimos_forgetting_curve_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_memories_pkey' AND conrelid = 'aimos_memories'::regclass) THEN
    ALTER TABLE ONLY aimos_memories
    ADD CONSTRAINT aimos_memories_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_retention_config_pkey' AND conrelid = 'aimos_retention_config'::regclass) THEN
    ALTER TABLE ONLY aimos_retention_config
    ADD CONSTRAINT aimos_retention_config_pkey PRIMARY KEY (company_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_retrieval_drift_snapshots_pkey' AND conrelid = 'aimos_retrieval_drift_snapshots'::regclass) THEN
    ALTER TABLE ONLY aimos_retrieval_drift_snapshots
    ADD CONSTRAINT aimos_retrieval_drift_snapshots_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aimos_skills_pkey' AND conrelid = 'aimos_skills'::regclass) THEN
    ALTER TABLE ONLY aimos_skills
    ADD CONSTRAINT aimos_skills_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'procedural_skills_company_id_skill_name_key' AND conrelid = 'procedural_skills'::regclass) THEN
    ALTER TABLE ONLY procedural_skills
    ADD CONSTRAINT procedural_skills_company_id_skill_name_key UNIQUE (company_id, skill_name);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'procedural_skills_pkey' AND conrelid = 'procedural_skills'::regclass) THEN
    ALTER TABLE ONLY procedural_skills
    ADD CONSTRAINT procedural_skills_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'recall_calibration_pkey' AND conrelid = 'recall_calibration'::regclass) THEN
    ALTER TABLE ONLY recall_calibration
    ADD CONSTRAINT recall_calibration_pkey PRIMARY KEY (company_id, channel);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'recall_observations_pkey' AND conrelid = 'recall_observations'::regclass) THEN
    ALTER TABLE ONLY recall_observations
    ADD CONSTRAINT recall_observations_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'recommendation_log_pkey' AND conrelid = 'recommendation_log'::regclass) THEN
    ALTER TABLE ONLY recommendation_log
    ADD CONSTRAINT recommendation_log_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'retrieval_pheromones_edge_uq' AND conrelid = 'retrieval_pheromones'::regclass) THEN
    ALTER TABLE ONLY retrieval_pheromones
    ADD CONSTRAINT retrieval_pheromones_edge_uq UNIQUE (company_id, memory_id_a, memory_id_b);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'retrieval_pheromones_pkey' AND conrelid = 'retrieval_pheromones'::regclass) THEN
    ALTER TABLE ONLY retrieval_pheromones
    ADD CONSTRAINT retrieval_pheromones_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'rule_hierarchy_pkey' AND conrelid = 'rule_hierarchy'::regclass) THEN
    ALTER TABLE ONLY rule_hierarchy
    ADD CONSTRAINT rule_hierarchy_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'run_idempotency_pkey' AND conrelid = 'run_idempotency'::regclass) THEN
    ALTER TABLE ONLY run_idempotency
    ADD CONSTRAINT run_idempotency_pkey PRIMARY KEY (company_id, agent_id, idempotency_key);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'scheduled_tasks_pkey' AND conrelid = 'scheduled_tasks'::regclass) THEN
    ALTER TABLE ONLY scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'session_lanes_pkey' AND conrelid = 'session_lanes'::regclass) THEN
    ALTER TABLE ONLY session_lanes
    ADD CONSTRAINT session_lanes_pkey PRIMARY KEY (company_id, session_key);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'skill_running_stats_company_id_skill_id_key' AND conrelid = 'skill_running_stats'::regclass) THEN
    ALTER TABLE ONLY skill_running_stats
    ADD CONSTRAINT skill_running_stats_company_id_skill_id_key UNIQUE (company_id, skill_id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'skill_running_stats_pkey' AND conrelid = 'skill_running_stats'::regclass) THEN
    ALTER TABLE ONLY skill_running_stats
    ADD CONSTRAINT skill_running_stats_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'supersession_events_pkey' AND conrelid = 'supersession_events'::regclass) THEN
    ALTER TABLE ONLY supersession_events
    ADD CONSTRAINT supersession_events_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'transformation_cache_pkey' AND conrelid = 'transformation_cache'::regclass) THEN
    ALTER TABLE ONLY transformation_cache
    ADD CONSTRAINT transformation_cache_pkey PRIMARY KEY (company_id, cache_key);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'trigger_rules_pkey' AND conrelid = 'trigger_rules'::regclass) THEN
    ALTER TABLE ONLY trigger_rules
    ADD CONSTRAINT trigger_rules_pkey PRIMARY KEY (id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_reference_points_pkey' AND conrelid = 'user_reference_points'::regclass) THEN
    ALTER TABLE ONLY user_reference_points
    ADD CONSTRAINT user_reference_points_pkey PRIMARY KEY (id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_agent_alarms_pending ON agent_alarms USING btree (alarm_time) WHERE (status = 'pending'::text);

CREATE INDEX IF NOT EXISTS idx_agent_model_policy_order ON agent_model_policy USING btree (company_id, agent_id, is_primary DESC, priority);

CREATE INDEX IF NOT EXISTS idx_agent_msg_conv ON agent_messages USING btree (conversation_id);

CREATE INDEX IF NOT EXISTS idx_agent_msg_to ON agent_messages USING btree (company_id, to_agent, status);

CREATE INDEX IF NOT EXISTS idx_agent_profiles_role_slot ON agent_profiles USING btree (company_id, role_slot);

CREATE INDEX IF NOT EXISTS idx_agent_routing_policy_lookup ON agent_routing_policy USING btree (company_id, source_agent_id, enabled, priority);

CREATE INDEX IF NOT EXISTS idx_agent_runs_authorization_hash ON agent_runs USING btree (company_id, authorization_chain_hash);

CREATE INDEX IF NOT EXISTS idx_agent_tokens_active ON agent_tokens USING btree (token) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_crossref_composite ON memory_cross_refs USING btree (company_id, source_memory_id, target_memory_id, similarity DESC);

CREATE INDEX IF NOT EXISTS idx_crossref_source ON memory_cross_refs USING btree (company_id, source_memory_id);

CREATE INDEX IF NOT EXISTS idx_crossref_target ON memory_cross_refs USING btree (company_id, target_memory_id);

CREATE INDEX IF NOT EXISTS idx_directives_agent ON aimos_directives USING btree (agent_id, status);

CREATE INDEX IF NOT EXISTS idx_directives_company ON aimos_directives USING btree (company_id);

CREATE INDEX IF NOT EXISTS idx_dream_layers_lookup ON dream_summary_layers USING btree (company_id, dream_date, layer);

CREATE INDEX IF NOT EXISTS idx_entity_edges_composite ON entity_memory_edges USING btree (company_id, entity, memory_id);

CREATE INDEX IF NOT EXISTS idx_entity_edges_entity ON entity_memory_edges USING btree (company_id, entity);

CREATE INDEX IF NOT EXISTS idx_entity_edges_memory ON entity_memory_edges USING btree (company_id, memory_id);

CREATE INDEX IF NOT EXISTS idx_events_agent ON aimos_events USING btree (agent_id);

CREATE INDEX IF NOT EXISTS idx_events_company_ts ON aimos_events USING btree (company_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_events_ts ON aimos_events USING btree (ts DESC);

CREATE INDEX IF NOT EXISTS idx_integration_tokens_cluster_created_at ON integration_tokens USING btree (cluster_id, created_at DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_integration_tokens_company_provider_created_at ON integration_tokens USING btree (company_id, provider, created_at DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_mcp_connections_company ON mcp_connections USING btree (company_id);

CREATE INDEX IF NOT EXISTS idx_mcp_connections_status ON mcp_connections USING btree (status);

CREATE INDEX IF NOT EXISTS idx_memories_agent ON aimos_memories USING btree (agent_id);

CREATE INDEX IF NOT EXISTS idx_memories_company ON aimos_memories USING btree (company_id);

CREATE INDEX IF NOT EXISTS idx_memories_data_class ON aimos_memories USING btree (company_id, data_class);

CREATE INDEX IF NOT EXISTS idx_memories_retrieval_weight ON aimos_memories USING btree (company_id, retrieval_weight DESC) WHERE (is_active = true);

CREATE INDEX IF NOT EXISTS idx_memories_skill_type ON aimos_memories USING btree (memory_type) WHERE ((company_id = 'hom'::text) AND (is_active = true));

CREATE INDEX IF NOT EXISTS idx_memory_cross_refs_company_source ON memory_cross_refs USING btree (company_id, source_memory_id);

CREATE INDEX IF NOT EXISTS idx_memory_cross_refs_company_target ON memory_cross_refs USING btree (company_id, target_memory_id);

CREATE INDEX IF NOT EXISTS idx_aimos_events_company_key_operation ON aimos_events USING btree (company_id, key, operation);

CREATE INDEX IF NOT EXISTS idx_aimos_key_trgm ON aimos_memories USING gin (key gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_aimos_memories_cluster_created_at ON aimos_memories USING btree (company_id, cluster_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_aimos_memories_company_key ON aimos_memories USING btree (company_id, key);

CREATE INDEX IF NOT EXISTS idx_aimos_memories_embedding_hnsw ON aimos_memories USING hnsw (embedding vector_cosine_ops) WITH (m='32', ef_construction='200');

CREATE INDEX IF NOT EXISTS idx_aimos_memories_freshness ON aimos_memories USING btree (company_id, freshness_state, last_verified_at DESC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_aimos_memories_valid_window ON aimos_memories USING btree (company_id, valid_from DESC NULLS LAST, valid_until DESC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_aimos_search_vector ON aimos_memories USING gin (search_vector);

CREATE INDEX IF NOT EXISTS idx_procedural_skills ON aimos_memories USING btree (company_id, memory_type, created_at) WHERE ((memory_type = 'procedural'::text) AND (is_active = true));

CREATE INDEX IF NOT EXISTS idx_procedural_skills_lookup ON procedural_skills USING btree (company_id, agent_id);

CREATE INDEX IF NOT EXISTS idx_procedural_skills_tags ON procedural_skills USING gin (tags);

CREATE INDEX IF NOT EXISTS idx_recommendation_log_agent ON recommendation_log USING btree (company_id, agent_id);

CREATE INDEX IF NOT EXISTS idx_recommendation_log_due ON recommendation_log USING btree (outcome_due_at) WHERE (actual_outcome IS NULL);

CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_company_active ON scheduled_tasks USING btree (company_id, is_active);

CREATE INDEX IF NOT EXISTS idx_supersession_post ON supersession_events USING btree (company_id, post_memory_id);

CREATE INDEX IF NOT EXISTS idx_supersession_prior ON supersession_events USING btree (company_id, prior_memory_id);

CREATE INDEX IF NOT EXISTS idx_transformation_cache_company_last_hit ON transformation_cache USING btree (company_id, last_hit_at DESC);

CREATE INDEX IF NOT EXISTS idx_trigger_rules_active ON trigger_rules USING btree (company_id, enabled, trigger_type);

CREATE UNIQUE INDEX IF NOT EXISTS user_reference_points_company_user_domain_idx ON user_reference_points USING btree (company_id, user_id, domain);

CREATE OR REPLACE RULE block_event_delete AS
    ON DELETE TO aimos_events DO INSTEAD NOTHING;

CREATE OR REPLACE RULE block_memory_delete AS
    ON DELETE TO aimos_memories DO INSTEAD NOTHING;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_messages_in_reply_to_fkey' AND conrelid = 'agent_messages'::regclass) THEN
    ALTER TABLE ONLY agent_messages
    ADD CONSTRAINT agent_messages_in_reply_to_fkey FOREIGN KEY (in_reply_to) REFERENCES agent_messages(id);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'dream_summary_layers_parent_layer_id_fkey' AND conrelid = 'dream_summary_layers'::regclass) THEN
    ALTER TABLE ONLY dream_summary_layers
    ADD CONSTRAINT dream_summary_layers_parent_layer_id_fkey FOREIGN KEY (parent_layer_id) REFERENCES dream_summary_layers(id);
  END IF;
END $$;
