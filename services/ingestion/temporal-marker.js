// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into ingestion-orchestrator.js (SAVE pipeline, parallel observer step)
// Purpose: ASMR observer agent 3 — extracts dates, sequences, supersession
//          chains (old_value → new_value) at WRITE time
// Wire into: ingestion-orchestrator.js (SAVE pipeline, parallel observer step)
// Sources: Dynamic Theory of Mind as Temporal Memory (arXiv 2026), HippoRAG
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Observer Agent 3: Temporal Marker
 *
 * Extracts dates, event sequences, change events, and supersession chains
 * (old_value → new_value) from raw text using the native provider path configured
 * for Aimos ingestion.
 *
 * Supersession detection is the critical capability: if a user says
 * "I moved from London to Paris", this triggers a supersession record
 * marking London as the OLD value and Paris as the NEW current state.
 * This enables the ASMR technique to resolve conflicting memories at query time.
 *
 * @module services/ingestion/temporal-marker
 */
import { callNativeLlm } from '../shared/native-llm.js';

const TEMPORAL_PROMPT = `You are a temporal information extraction engine. Extract all temporal markers, change events, and state supersessions from text. Return ONLY valid JSON. No explanation, no markdown.

Extract all temporal and change information from the text below. Return ONLY a JSON object.

Output format (JSON only — no markdown, no explanation):
{
  "markers": [
    {
      "text": "exact quote or paraphrase from source",
      "type": "event|change|duration|deadline|recurring",
      "entity": "what this time reference is about",
      "date": "ISO 8601 date or relative expression (e.g. last week, 3 years ago)",
      "confidence": 0.0-1.0
    }
  ],
  "supersessions": [
    {
      "entity": "what attribute changed (e.g. location, job, status)",
      "old_value": "previous state",
      "new_value": "current state after change",
      "when": "when the change occurred (date or relative)"
    }
  ],
  "sequence": ["first thing that happened", "second thing", "..."]
}

Type definitions:
- event:     something that happened at a point in time
- change:    something that was X and is now Y (generates a supersession)
- duration:  something lasting a continuous period
- deadline:  a future target date or expiry
- recurring: something that repeats (weekly, annually, etc.)

CRITICAL — Supersession rule:
If the text says someone MOVED, CHANGED, SWITCHED, UPDATED, REPLACED, LEFT, JOINED, or any equivalent — create a supersession entry capturing old → new state.

Return empty arrays for each key if nothing is found.

Text to analyse:
`;

/**
 * Extract temporal markers and supersession chains from raw text.
 *
 * @param {string} text - Content to extract temporal info from
 * @param {Object} [opts={}]
 * @param {string} [opts.provider] - Native provider override
 * @param {string} [opts.model] - Native model override
 * @returns {Promise<{
 *   markers: Array<{text: string, type: string, entity: string, date: string, confidence: number}>,
 *   supersessions: Array<{entity: string, oldValue: string, newValue: string, when: string}>,
 *   sequence: string[]
 * }>}
 */
export async function extractTemporalMarkers(text, opts = {}) {
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return { markers: [], supersessions: [], sequence: [] };
  }

  const prompt = TEMPORAL_PROMPT + text.slice(0, 4000);

  let raw;
  try {
    raw = await callNativeLlm({
      prompt,
      provider: opts.provider,
      model: opts.model,
      providerConfigKeys: ['AIMOS_INGEST_PROVIDER', 'LLM_PROVIDER'],
      modelConfigKeys: ['AIMOS_INGEST_MODEL', 'LLM_MODEL']
    });
  } catch (err) {
    console.error('[temporal-marker] Native provider call failed:', err.message);
    throw err;
  }

  if (!raw) {
    return { markers: [], supersessions: [], sequence: [] };
  }

  return parseTemporalResponse(raw);
}

/**
 * Parse raw LLM output into typed temporal structures.
 * Normalises field name variants (old_value / oldValue, new_value / newValue).
 *
 * @param {string} raw
 * @returns {{markers: Array, supersessions: Array, sequence: string[]}}
 */
function parseTemporalResponse(raw) {
  const empty = { markers: [], supersessions: [], sequence: [] };
  if (!raw || typeof raw !== 'string') return empty;

  const stripped = raw.replace(/```(?:json)?\s*/gi, '').replace(/```/g, '').trim();
  const jsonMatch = stripped.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    console.warn('[temporal-marker] No JSON found in LLM response');
    return empty;
  }

  let parsed;
  try {
    parsed = JSON.parse(jsonMatch[0]);
  } catch (err) {
    console.warn('[temporal-marker] JSON parse failed:', err.message);
    return empty;
  }

  const VALID_TYPES = ['event', 'change', 'duration', 'deadline', 'recurring'];

  const markers = (Array.isArray(parsed.markers) ? parsed.markers : []).map(m => {
    const c = clampConfidence(m.confidence);
    return {
      text: String(m.text || '').trim(),
      type: VALID_TYPES.includes(String(m.type || '').toLowerCase()) ? String(m.type).toLowerCase() : 'event',
      entity: String(m.entity || '').trim(),
      date: String(m.date || '').trim(),
      confidence: c.value,
      confidenceIsDefault: c.isDefault || false,
      confidenceReason: c.reason || null
    };
  });

  // Accept both snake_case (old_value) and camelCase (oldValue) from LLM output
  const supersessions = (Array.isArray(parsed.supersessions) ? parsed.supersessions : []).map(s => ({
    entity: String(s.entity || '').trim(),
    oldValue: String(s.old_value ?? s.oldValue ?? '').trim(),
    newValue: String(s.new_value ?? s.newValue ?? '').trim(),
    when: String(s.when || '').trim()
  })).filter(s => s.entity.length > 0 || s.oldValue.length > 0 || s.newValue.length > 0);

  const sequence = Array.isArray(parsed.sequence)
    ? parsed.sequence.map(s => String(s)).filter(s => s.length > 0)
    : [];

  return { markers, supersessions, sequence };
}

function clampConfidence(raw) {
  const n = Number(raw);
  if (isNaN(n)) return { value: 0.5, isDefault: true, reason: 'nan_input' };
  return { value: Math.max(0, Math.min(1, n)), isDefault: false, reason: null };
}
