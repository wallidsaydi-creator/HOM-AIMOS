// ═══════════════════════════════════════════════════════════════════════════════
// DREAM FEEDBACK (dream-feedback.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: Senge Fifth Discipline (systems thinking), MemGPT (Packer 2023)
// Additive TEM authority: TiMem: Temporal-Hierarchical Memory Consolidation
// for Long-Horizon Conversational Agents
//
// P2-7: Bidirectional Dream Flow
//
// Retained reflection evidence feeds constraints back into nightly dreams.
// The dreaming system (offline consolidation) is not purely generative —
// it is shaped by what the agent learned was important during the week.
//
// Dream constraints modulate:
//   - Signal generator weights (which memory types to amplify)
//   - Clustering thresholds (how aggressively to group memories)
//   - Low-frequency patterns (error types to rehearse less often, never hide)
//
// Stored as Aimos memory type='episodic', key='dream_constraints:{company_id}'
//
// TiMem note: dream outputs can be surfaced with TMT level/bucket metadata via
// timem-hierarchy.js. Dream consolidation formulas and thresholds remain owned
// by the existing dream pipeline.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 12)
// → Calls: services/shared/native-llm.js (constraint synthesis)
// → Calls: services/observe/event-ledger.js (feedback events)
// Pipeline: DREAM_PIPELINE
// Position: dream constraints
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { runProvider } from '../core/providers.js';
import { logEvent } from '../observe/event-ledger.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;

// Aimos key for latest dream constraints
const DREAM_CONSTRAINTS_KEY_PREFIX = 'dream_constraints';

/**
 * Generate dream constraints from a retained reflection summary.
 *
 * @param {Object|string} weeklyReflection - Weekly learning summary
 * @param {string} [weeklyReflection.key_learnings] - What was learned this week
 * @param {string} [weeklyReflection.repeated_errors] - Error patterns to rehearse less often
 * @param {string} [weeklyReflection.high_value_domains] - Domains to emphasise
 * @param {number} [weeklyReflection.overall_performance] - 0-1 performance score
 * @returns {Promise<{signal_weights: Object, focus_areas: string[], low_frequency_patterns: string[]}>}
 */
export async function generateDreamConstraints(weeklyReflection) {
  const reflectionText = typeof weeklyReflection === 'string'
    ? weeklyReflection
    : JSON.stringify(weeklyReflection || {});

  const prompt = `You are a dream consolidation engine. Translate a weekly agent reflection into dream constraints.

WEEKLY REFLECTION:
${reflectionText.slice(0, 2000)}

Dream constraints shape nightly memory consolidation:
- signal_weights: relative emphasis per memory type (semantic, procedural, episodic, declarative)
- focus_areas: domains/topics to explore more deeply in dreams
- low_frequency_patterns: error categories or failure patterns to replay less often without excluding them

Return ONLY a JSON object — no markdown, no explanation.
Output format:
{
  "signal_weights": {
    "semantic": 0.0-1.0,
    "procedural": 0.0-1.0,
    "episodic": 0.0-1.0,
    "declarative": 0.0-1.0
  },
  "focus_areas": ["<domain1>", "<domain2>"],
  "low_frequency_patterns": ["<error_pattern1>"],
  "clustering_threshold": 0.5-0.95,
  "reasoning": "<why these constraints were chosen>"
}`;

  let raw = '';
  try {
    raw = await runProvider({ prompt });
  } catch (err) {
    console.error('[dream-feedback] generateDreamConstraints LLM call failed:', err.message);
  }

  // Parse result with safe defaults
  const defaults = {
    signal_weights: { semantic: 0.5, procedural: 0.5, episodic: 0.5, declarative: 0.5 },
    focus_areas: [],
    low_frequency_patterns: [],
    clustering_threshold: 0.75,
    reasoning: 'Default constraints — LLM call failed or parse error',
  };

  try {
    const stripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(stripped);

    // Validate and clamp signal_weights
    const weights = parsed?.signal_weights || {};
    const clampedWeights = {};
    for (const [type, val] of Object.entries(weights)) {
      clampedWeights[type] = Math.max(0, Math.min(1, Number(val) || 0.5));
    }

    return {
      signal_weights: Object.keys(clampedWeights).length ? clampedWeights : defaults.signal_weights,
      focus_areas: Array.isArray(parsed?.focus_areas) ? parsed.focus_areas : [],
      low_frequency_patterns: Array.isArray(parsed?.low_frequency_patterns) ? parsed.low_frequency_patterns : [],
      clustering_threshold: typeof parsed?.clustering_threshold === 'number'
        ? Math.max(0.5, Math.min(0.95, parsed.clustering_threshold))
        : defaults.clustering_threshold,
      reasoning: String(parsed?.reasoning || ''),
      generated_at: new Date().toISOString(),
    };
  } catch {
    return { ...defaults, generated_at: new Date().toISOString() };
  }
}

/**
 * Load the latest dream constraints from Aimos for a company.
 *
 * @param {string} [companyId]
 * @returns {Promise<Object|null>} Dream constraints object, or null if none saved
 */
export async function loadDreamConstraints(companyId) {
  const cid = companyId || COMPANY;
  const constraintsKey = `${DREAM_CONSTRAINTS_KEY_PREFIX}:${cid}`;

  try {
    const result = await query(
      `SELECT value, updated_at FROM aimos_memories
       WHERE company_id = $1 AND key = $2
       ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST
       LIMIT 1`,
      [cid, constraintsKey]
    );

    if (!result.rows.length) return null;

    const raw = result.rows[0].value;
    try {
      return typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      return { raw_value: raw, loaded_at: result.rows[0].updated_at };
    }
  } catch (err) {
    console.error('[dream-feedback] loadDreamConstraints DB error:', err.message);
    return null;
  }
}

/**
 * Save generated dream constraints to Aimos.
 * Upserts under key 'dream_constraints:{companyId}'.
 *
 * @param {Object} constraints - From generateDreamConstraints()
 * @param {string} [companyId]
 * @returns {Promise<void>}
 */
async function saveDreamConstraints(constraints, companyId) {
  const cid = companyId || COMPANY;
  const constraintsKey = `${DREAM_CONSTRAINTS_KEY_PREFIX}:${cid}`;

  await persistMemory({
    company_id: cid,
    agent_id: 'dream-feedback',
    mutation_authority: 'housekeeper',
    key: constraintsKey,
    value: JSON.stringify(constraints),
    scope: 'global',
    memory_type: 'episodic',
    clearance_level: 3,
    source: 'dream-feedback',
  });
}

/**
 * Apply dream constraints to a dream configuration object.
 * Modifies signal generator weights, clustering thresholds, and focus areas.
 * Returns a new config object — original is not mutated.
 *
 * @param {Object} dreamConfig - Existing dream configuration
 * @param {Object} constraints - From generateDreamConstraints() or loadDreamConstraints()
 * @returns {Object} Modified dream configuration
 */
export function applyConstraintsToDream(dreamConfig, constraints) {
  if (!dreamConfig || typeof dreamConfig !== 'object') {
    return dreamConfig;
  }
  if (!constraints || typeof constraints !== 'object') {
    return { ...dreamConfig };
  }

  const modified = { ...dreamConfig };

  // Apply signal weights
  if (constraints.signal_weights && typeof constraints.signal_weights === 'object') {
    modified.signal_weights = {
      ...(dreamConfig.signal_weights || {}),
      ...constraints.signal_weights,
    };
  }

  // Apply clustering threshold
  if (typeof constraints.clustering_threshold === 'number') {
    modified.clustering_threshold = constraints.clustering_threshold;
  }

  // Apply focus areas — append to existing, deduplicate
  if (Array.isArray(constraints.focus_areas) && constraints.focus_areas.length > 0) {
    const existing = Array.isArray(dreamConfig.focus_areas) ? dreamConfig.focus_areas : [];
    modified.focus_areas = Array.from(new Set([...existing, ...constraints.focus_areas]));
  }

  // Apply low-frequency patterns. This is a replay-frequency preference only;
  // no memory or evidence becomes ineligible for recall.
  if (Array.isArray(constraints.low_frequency_patterns) && constraints.low_frequency_patterns.length > 0) {
    const existing = Array.isArray(dreamConfig.low_frequency_patterns) ? dreamConfig.low_frequency_patterns : [];
    modified.low_frequency_patterns = Array.from(new Set([...existing, ...constraints.low_frequency_patterns]));
  }

  // Record constraint application metadata
  modified._constraints_applied_at = new Date().toISOString();
  modified._constraints_reasoning = constraints.reasoning || '';

  return modified;
}

/**
 * Full cycle: generate constraints from weekly reflection, save to Aimos,
 * and return the constraints ready for dream application.
 *
 * @param {Object|string} weeklyReflection
 * @param {string} [companyId]
 * @returns {Promise<Object>} Generated and saved constraints
 */
export async function processWeeklyReflection(weeklyReflection, companyId) {
  const cid = companyId || COMPANY;

  const constraints = await generateDreamConstraints(weeklyReflection);

  try {
    await saveDreamConstraints(constraints, cid);
    await logEvent(cid, 'dream-feedback', 'dream_constraints_updated', `${DREAM_CONSTRAINTS_KEY_PREFIX}:${cid}`, {
      reasoning: `Dream constraints updated from weekly reflection. Focus: ${(constraints.focus_areas || []).slice(0, 3).join(', ')}`,
      focusAreas: constraints.focus_areas,
      lowFrequencyPatterns: constraints.low_frequency_patterns,
    });
  } catch (err) {
    console.error('[dream-feedback] processWeeklyReflection save error:', err.message);
  }

  return constraints;
}
