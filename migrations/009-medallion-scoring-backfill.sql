-- 009: Medallion scoring backfill
-- Promote bronze memories to proper silver/gold tiers.
-- The silver tier must exist as a real intermediate layer between gold and bronze.
-- This aligns the SQL with the expanded JS inferMedallionLayer().

-- Gold: curated, production-ready, identity-defining knowledge
UPDATE aimos_memories SET medallion_layer = 'gold'
  WHERE memory_type IN ('milestone', 'product', 'identity', 'procedural',
                        'crew_identity', 'dream_summary', 'self_improvement',
                        'infrastructure')
  AND medallion_layer != 'gold';

-- Silver: validated, enriched, useful knowledge (expanded from original 6 to 21 types)
UPDATE aimos_memories SET medallion_layer = 'silver'
  WHERE memory_type IN ('session', 'directive', 'heartbeat', 'intel',
                        'constitution_check', 'test',
                        'book_extract', 'tacit_knowledge', 'session_debrief',
                        'procedural_seed', 'self_reflection', 'core_belief',
                        'strategic_directive', 'after_action_review', 'shared_failure',
                        'operational_rule', 'declarative', 'architecture',
                        'research', 'dream_pattern', 'bibliographic_reference')
  AND medallion_layer != 'silver';

-- All others remain bronze (raw, episodic, noise):
-- conversation_feed, event_log, episodic, quarantine, aimos_trace,
-- agent_message, aimos_turn, signal, active_loop