// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into ingestion-orchestrator.js (SAVE pipeline, parallel observer step)
// Purpose: ASMR observer agent 1 — extracts named entities at WRITE time
// Wire into: ingestion-orchestrator.js (SAVE pipeline, parallel observer step)
// Sources: HippoRAG (Gutierrez 2024), MemGPT (Packer 2023)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Observer Agent 1: Entity Extractor
 *
 * Extracts named entities (person, organization, location, date, amount, product)
 * from raw text using the native provider path configured for Aimos ingestion.
 *
 * Called at WRITE time as part of the ASMR parallel observer pipeline.
 *
 * @module services/ingestion/entity-extractor
 *
 * Additive Batch9 Wave5 authority: Deep-Learned Observation Operators, ELISA,
 * and HGP-Mamba. Aimos exposes reversible text observation-operator
 * diagnostics only; multimodal ingestion remains inactive until a native
 * backend path and tests exist.
 */
import { callNativeLlm } from '../shared/native-llm.js';

// Entity types the extractor recognises
const ENTITY_TYPES = ['person', 'organization', 'location', 'date', 'amount', 'product', 'event', 'concept'];

// Mapping from common LLM/regex divergent type labels to canonical types
// Prevents proper_noun vs organization divergence between extraction paths
const TYPE_ALIASES = {
  proper_noun: 'person',
  propernoun: 'person',
  person_type: 'person',
  company: 'organization',
  company_name: 'organization',
  corp: 'organization',
  institution: 'organization',
  group: 'organization',
  agency: 'organization',
  place: 'location',
  city: 'location',
  country: 'location',
  address: 'location',
  region: 'location',
  time: 'date',
  datetime: 'date',
  timestamp: 'date',
  money: 'amount',
  currency: 'amount',
  price: 'amount',
  software: 'product',
  hardware: 'product',
  platform: 'product',
  meeting: 'event',
  conference: 'event',
  topic: 'concept',
  subject: 'concept',
  category: 'concept',
  field: 'concept',
};
const WAVE5_OBSERVATION_OPERATOR_AUTHORITIES = [
  'Deep-Learned Observation Operators for Artificial Intelligence Weather Forecasting Models',
  'ELISA: An Interpretable Hybrid Generative AI Agent for Expression-Grounded Discovery in Single-Cell Genomics',
  'HGP-Mamba: Integrating Histology and Generated Protein Features for Mamba-based Multimodal Survival Risk Prediction',
];
const NON_TEXT_MODALITIES = new Set(['image', 'video', 'audio', 'multimodal']);

const SYSTEM_PROMPT = `You are a named entity extraction engine. Extract entities from text and return ONLY valid JSON. No explanation, no markdown fences, no prose.`;

const EXTRACTION_PROMPT = `You are a named entity extraction engine. Extract entities from text and return ONLY valid JSON. No explanation, no markdown fences, no prose.

Extract all named entities from the text below. Return ONLY a JSON object.

Valid entity types: person, organization, location, date, amount, product, event, concept

Output format (JSON only — no markdown, no explanation):
{"entities": [{"value": "entity text", "type": "category", "confidence": 0.0-1.0}]}

Rules:
- Only include entities explicitly present in the text
- Do NOT infer entities not mentioned
- Confidence: 1.0 = explicit, 0.8 = strongly implied, 0.5 = ambiguous
- Normalize dates to ISO 8601 where possible
- Return {"entities": []} if no entities found

Text to analyse:
`;

/**
 * Extract named entities from raw text.
 *
 * @param {string} text - Content to extract entities from
 * @param {Object} [opts={}]
 * @param {string} [opts.provider] - Native provider override
 * @param {string} [opts.model] - Native model override
 * @param {string} [opts.sourceId] - Optional source ID for provenance tracking
 * @returns {Promise<{entities: Array<{value: string, type: string, confidence: number, sourceId?: string}>}>}
 */
export async function extractEntities(text, opts = {}) {
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return { entities: [] };
  }

  const prompt = EXTRACTION_PROMPT + text.slice(0, 4000); // guard against huge inputs

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
    console.error('[entity-extractor] Native provider call failed:', err.message);
    throw err;
  }

  if (!raw) {
    return { entities: [] };
  }

  return parseEntityResponse(raw);
}

/**
 * Parse raw LLM output into a typed entity list.
 * Robust against markdown fences, leading prose, and malformed JSON.
 *
 * @param {string} raw
 * @returns {{entities: Array<{value: string, type: string, confidence: number}>}}
 */
function parseEntityResponse(raw) {
  if (!raw || typeof raw !== 'string') return { entities: [] };

  // Strip markdown code fences if present
  const stripped = raw.replace(/```(?:json)?\s*/gi, '').replace(/```/g, '').trim();

  // Find the first JSON object in the output
  const jsonMatch = stripped.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    console.warn('[entity-extractor] No JSON found in LLM response');
    return { entities: [] };
  }

  let parsed;
  try {
    parsed = JSON.parse(jsonMatch[0]);
  } catch (err) {
    console.warn('[entity-extractor] JSON parse failed:', err.message);
    return { entities: [] };
  }

  const rawEntities = Array.isArray(parsed.entities) ? parsed.entities : [];

  const entities = rawEntities
    .map(e => {
      const c = clampConfidence(e.confidence);
      return {
        value: String(e.value || '').trim(),
        type: normaliseType(e.type),
        confidence: c.value,
        confidenceIsDefault: c.isDefault || false,
        confidenceReason: c.reason || null
      };
    })
    .filter(e => e.value.length > 0);

  return { entities };
}

function normaliseType(raw) {
  const t = String(raw || '').toLowerCase().trim();
  // Check canonical types first
  if (ENTITY_TYPES.includes(t)) return t;
  // Check alias mapping for divergent labels (proper_noun → person, company → organization, etc.)
  if (TYPE_ALIASES[t]) return TYPE_ALIASES[t];
  // Fallback: preserve known singular forms, else concept
  return 'concept';
}

function clampConfidence(raw) {
  const n = Number(raw);
  if (isNaN(n)) return { value: 0.5, isDefault: true, reason: 'nan_input' };
  return { value: Math.max(0, Math.min(1, n)), isDefault: false, reason: null };
}

// ─── Phase 4: Alias Resolution ───────────────────────────────────────────────

const CORPORATE_SUFFIXES = /\s*\b(Inc|LLC|Corp|Ltd|Co|SA|AG|GmbH|PLC|NV|BV|Pty|Oy|AB|AS)\.?\s*$/i;

/**
 * Normalize an entity value for grouping: lowercase, trim, strip corporate suffixes.
 * @param {string} value
 * @returns {string}
 */
function normalizeForGrouping(value) {
  return String(value)
    .trim()
    .replace(CORPORATE_SUFFIXES, '')
    .trim()
    .toLowerCase();
}

/**
 * Compute Levenshtein distance between two strings.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = b[i - 1] === a[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Resolve entity aliases — group entities that likely refer to the same thing.
 *
 * Groups by normalized form (lowercase, trimmed, corporate suffixes stripped),
 * then merges groups where the normalized forms have Levenshtein distance <= 2
 * or one is a substring of the other.
 *
 * @param {Array<{value: string, type: string, confidence: number}>} entities
 * @returns {Array<{canonical: string, type: string, confidence: number, aliases: string[]}>}
 */
export function resolveAliases(entities) {
  if (!Array.isArray(entities) || entities.length === 0) return [];

  // Step 1: Group by exact normalized form
  const groups = new Map(); // normalizedKey → { values: Map<originalValue, count>, type, maxConfidence }

  for (const entity of entities) {
    const key = normalizeForGrouping(entity.value);
    if (!key) continue;

    if (!groups.has(key)) {
      groups.set(key, {
        values: new Map(),
        type: entity.type,
        maxConfidence: entity.confidence
      });
    }
    const g = groups.get(key);
    g.values.set(entity.value, (g.values.get(entity.value) || 0) + 1);
    g.maxConfidence = Math.max(g.maxConfidence, entity.confidence);
  }

  // Step 2: Merge groups with similar normalized keys (Levenshtein <= 2 or substring)
  const keys = [...groups.keys()];
  const merged = new Map(); // representative key → merged group
  const keyToRepresentative = new Map();

  for (const key of keys) {
    if (keyToRepresentative.has(key)) continue;

    keyToRepresentative.set(key, key);
    merged.set(key, groups.get(key));

    for (const other of keys) {
      if (other === key || keyToRepresentative.has(other)) continue;
      const isSimilar =
        levenshtein(key, other) <= 2 ||
        key.includes(other) ||
        other.includes(key);

      if (isSimilar) {
        keyToRepresentative.set(other, key);
        const target = merged.get(key);
        const source = groups.get(other);
        for (const [val, count] of source.values) {
          target.values.set(val, (target.values.get(val) || 0) + count);
        }
        target.maxConfidence = Math.max(target.maxConfidence, source.maxConfidence);
      }
    }
  }

  // Step 3: Pick canonical form — most common, then longest
  const results = [];
  for (const [, group] of merged) {
    const sorted = [...group.values.entries()].sort((a, b) => {
      if (b[1] !== a[1]) return b[1] - a[1]; // most common first
      return b[0].length - a[0].length;       // longest first as tiebreak
    });

    const canonical = sorted[0][0];
    const aliases = sorted.slice(1).map(([v]) => v);

    results.push({
      canonical,
      type: group.type,
      confidence: group.maxConfidence,
      aliases
    });
  }

  return results;
}

// ─── Phase 4: Evidence / Provenance Tracking ─────────────────────────────────

/**
 * Attach provenance evidence to extracted entities.
 *
 * For each entity, locates its character offset in sourceText and captures
 * a context window of 30 characters before and after the match.
 *
 * @param {Array<{value: string, type: string, confidence: number}>} entities
 * @param {string} sourceId - Identifier for the source document
 * @param {string} sourceText - Full text of the source document
 * @returns {Array<{value: string, type: string, confidence: number, sourceId: string, offset: number, context: string}>}
 */
export function attachEvidence(entities, sourceId, sourceText) {
  if (!Array.isArray(entities)) return [];
  const text = typeof sourceText === 'string' ? sourceText : '';

  return entities.map(entity => {
    const idx = text.indexOf(entity.value);
    const offset = idx >= 0 ? idx : -1;

    let context = '';
    if (offset >= 0) {
      const start = Math.max(0, offset - 30);
      const end = Math.min(text.length, offset + entity.value.length + 30);
      context = text.slice(start, end);
    }

    return {
      ...entity,
      sourceId: sourceId || null,
      offset,
      context
    };
  });
}

export function buildObservationOperatorDiagnostics({
  rawInput = '',
  sourceId = null,
  modality = 'text',
  extractedEntities = [],
} = {}) {
  const normalizedModality = String(modality || 'text').toLowerCase();
  const text = String(rawInput || '');
  const entities = Array.isArray(extractedEntities) ? extractedEntities : [];
  const sourceBoundEntities = attachEvidence(entities, sourceId, text);
  const nonTextRequested = NON_TEXT_MODALITIES.has(normalizedModality);

  return {
    diagnostic_type: 'observation_operator',
    source_papers: WAVE5_OBSERVATION_OPERATOR_AUTHORITIES,
    status: nonTextRequested ? 'inactive_future_contract' : 'text_operator_ready',
    diagnostic_only: true,
    modality: normalizedModality,
    source_id: sourceId || null,
    operator_mapping: {
      raw_observation_present: text.trim().length > 0,
      model_compatible_state: nonTextRequested ? 'not_available_without_backend_path' : 'entity_candidates_with_source_offsets',
      reversible_to_source: true,
      source_bound_entity_count: sourceBoundEntities.filter((entity) => entity.offset >= 0).length,
    },
    entities: sourceBoundEntities,
    guardrails: {
      learned_operator_training_enabled: false,
      multimodal_ingestion_enabled: false,
      non_text_production_claim: false,
      raw_source_deleted: false,
      canonical_memory_changed: false,
    },
  };
}
