






















DROP FUNCTION IF EXISTS public.secure_aimos_save(text, text, text, text, text, text, text);

CREATE OR REPLACE FUNCTION public.secure_aimos_save(
    p_company_id TEXT,
    p_agent_id TEXT,
    p_key TEXT,
    p_value TEXT,
    p_scope TEXT,
    p_memory_type TEXT,
    p_proof_hash TEXT,
    p_content_hash BYTEA
) RETURNS VOID AS $$
DECLARE
    v_valid BOOLEAN;
BEGIN
    -- Validate Proof-of-Context (Knowledge Proof MFA)
    SELECT EXISTS (
        SELECT 1 FROM security.active_proofs
        WHERE proof_hash = p_proof_hash
        AND expires_at > NOW()
    ) INTO v_valid;

    IF NOT v_valid THEN
        INSERT INTO security.audit_log (agent_id, operation, table_name, status, knowledge_proof_used)
        VALUES (p_agent_id, 'INSERT', 'aimos_memories', 'denied', p_proof_hash);
        RAISE EXCEPTION 'Constitutional Violation: Knowledge proof invalid or expired. Acquire evidence first.';
    END IF;

    -- Enforce Aladdin Law: Only inserts/upserts allowed via this path.
    -- p_content_hash is the precomputed
    --   sha256(canonicalJson({key, value, scope, memory_type,
    --                          clearance_level, data_class, source}))
    -- from the JS caller. The hash is the live-row integrity check (Phase 9a).
    -- DB persists it; JS computed it.
    INSERT INTO public.aimos_memories (
        company_id, agent_id, key, value, scope, memory_type,
        created_at, updated_at, is_active, content_hash
    )
    VALUES (
        p_company_id, p_agent_id, p_key, p_value, p_scope, p_memory_type,
        NOW(), NOW(), true, p_content_hash
    );

    INSERT INTO security.audit_log (agent_id, operation, table_name, status, knowledge_proof_used)
    VALUES (p_agent_id, 'INSERT', 'aimos_memories', 'allowed', p_proof_hash);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION public.secure_aimos_save TO agent_runtime;

-- Visibility: confirm the new signature.
SELECT
    p.proname AS function_name,
    pg_get_function_identity_arguments(p.oid) AS args
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.proname = 'secure_aimos_save';