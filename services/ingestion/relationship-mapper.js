// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into ASMR ingestion via ingestion-orchestrator.js
// Purpose: ASMR observer agent 2 — extracts SPO triples at WRITE time
// ← Called by: ingestion-orchestrator.js (long-content relationship observer)
// Pipeline: /v1/ingest -> asmr-pipeline.js -> ingestion-orchestrator.js
// Position: write-time relationship observer for content >300 chars
// Sources: HippoRAG (Gutierrez 2024), Knowledge Graph extraction methods
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Observer Agent 2: Relationship Mapper
 *
 * Extracts subject-predicate-object triples from raw text using the native
 * provider path configured for Aimos ingestion. Part of the ASMR parallel observer pipeline —
 * runs at WRITE time.
 *
 * @module services/ingestion/relationship-mapper
 *
 * Additive Batch9 Wave5 authority: Ontology-Aware Design Patterns, ELISA, and
 * Rhizome OS-1. Aimos exposes typed relationship/evidence diagnostics only;
 * graph persistence, ranking, and PPR behavior are unchanged.
 */
import { callNativeLlm } from '../shared/native-llm.js';

const WAVE5_RELATIONSHIP_AUTHORITIES = [
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture',
  'ELISA: An Interpretable Hybrid Generative AI Agent for Expression-Grounded Discovery in Single-Cell Genomics',
  'Rhizome OS-1: Rhizome Semi-Autonomous Operating System for Small Molecule Drug Discovery',
];

const RELATIONSHIP_PROMPT = `You are a relationship extraction engine. Extract subject-predicate-object triples from text and return ONLY valid JSON. No explanation, no markdown fences.

Extract all relationships between entities in the text below. Return ONLY a JSON object.

Output format (JSON only — no markdown, no explanation):
{"relationships": [{"subject": "entity1", "predicate": "relationship_type", "object": "entity2", "confidence": 0.0-1.0}]}

Predicate naming conventions (use snake_case):
works_at, reports_to, lives_in, married_to, friends_with, owns, manages, created,
member_of, located_in, part_of, acquired_by, founded_by, employed_by, studied_at,
invested_in, partners_with, competes_with, subsidiary_of, predecessor_of, successor_of

Rules:
- Only extract relationships explicitly stated or strongly implied
- Use snake_case for all predicates (replace spaces with underscores)
- Both subject and object must be concrete entities (not pronouns)
- Confidence: 1.0 = explicit, 0.8 = strongly implied, 0.5 = ambiguous
- Return {"relationships": []} if no relationships found

Text to analyse:
`;

/**
 * Extract relationship triples from raw text.
 *
 * @param {string} text - Content to extract relationships from
 * @param {Object} [opts={}]
 * @param {string} [opts.provider] - Native provider override
 * @param {string} [opts.model] - Native model override
 * @returns {Promise<{relationships: Array<{subject: string, predicate: string, object: string, confidence: number}>}>}
 */
export async function extractRelationships(text, opts = {}) {
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return { relationships: [] };
  }

  const prompt = RELATIONSHIP_PROMPT + text.slice(0, 4000);

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
    console.error('[relationship-mapper] Native provider call failed:', err.message);
    throw err;
  }

  if (!raw) {
    return { relationships: [] };
  }

  return parseRelationshipResponse(raw, text);
}

/**
 * Parse raw LLM output into typed relationship triples.
 *
 * @param {string} raw
 * @param {string} [sourceText='']
 * @returns {{relationships: Array<{subject: string, predicate: string, object: string, confidence: number}>}}
 */
function parseRelationshipResponse(raw, sourceText = '') {
  if (!raw || typeof raw !== 'string') {
    return { relationships: extractExplicitRelationships(sourceText) };
  }

  const stripped = raw.replace(/```(?:json)?\s*/gi, '').replace(/```/g, '').trim();
  const jsonMatch = stripped.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    console.warn('[relationship-mapper] No JSON found in LLM response');
    return { relationships: extractExplicitRelationships(sourceText) };
  }

  let parsed;
  try {
    parsed = JSON.parse(jsonMatch[0]);
  } catch (err) {
    try {
      parsed = JSON.parse(repairEscapedJsonStructure(jsonMatch[0]));
    } catch {
      console.warn('[relationship-mapper] JSON parse failed:', err.message);
      return { relationships: extractExplicitRelationships(sourceText) };
    }
  }

  const rawRels = Array.isArray(parsed.relationships) ? parsed.relationships : [];

  const relationships = rawRels
    .map(r => {
      const c = clampConfidence(r.confidence);
      return {
        subject: String(r.subject || '').trim(),
        predicate: toSnakeCase(r.predicate),
        object: String(r.object || '').trim(),
        confidence: c.value,
        confidenceIsDefault: c.isDefault || false,
        confidenceReason: c.reason || null
      };
    })
    // Both subject and object must be non-empty to form a valid triple
    .filter(isUsableRelationship);

  return {
    relationships: relationships.length > 0
      ? relationships
      : extractExplicitRelationships(sourceText)
  };
}

function toSnakeCase(raw) {
  return String(raw || 'related_to')
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '');
}

function repairEscapedJsonStructure(raw) {
  return String(raw || '').replace(/\\([\[\]{}:,])/g, '$1');
}

const ENTITY_PATTERN = '([A-Z][A-Za-z0-9&\'-]*(?:\\s+[A-Z][A-Za-z0-9&\'-]*){0,3})';
const EXPLICIT_RELATIONSHIP_PATTERNS = [
  { predicate: 'works_at', confidence: 1.0, re: new RegExp(`\\b${ENTITY_PATTERN}\\s+(?:works|worked)\\s+at\\s+${ENTITY_PATTERN}\\b`, 'g') },
  { predicate: 'reports_to', confidence: 1.0, re: new RegExp(`\\b${ENTITY_PATTERN}\\s+reports?\\s+to\\s+${ENTITY_PATTERN}\\b`, 'g') },
  { predicate: 'manages', confidence: 0.9, re: new RegExp(`\\b${ENTITY_PATTERN}\\s+manages\\s+(?:the\\s+)?${ENTITY_PATTERN}\\b`, 'g') },
  { predicate: 'owns', confidence: 1.0, re: new RegExp(`\\b${ENTITY_PATTERN}\\s+owns\\s+${ENTITY_PATTERN}\\b`, 'g') },
  { predicate: 'partners_with', confidence: 0.9, re: new RegExp(`\\b${ENTITY_PATTERN}\\s+partners\\s+with\\s+${ENTITY_PATTERN}\\b`, 'g') },
  { predicate: 'studied_at', confidence: 1.0, re: new RegExp(`\\b${ENTITY_PATTERN}\\s+studied\\s+at\\s+${ENTITY_PATTERN}\\b`, 'g') },
  { predicate: 'part_of', confidence: 0.95, re: new RegExp(`\\b${ENTITY_PATTERN}\\s+is\\s+part\\s+of\\s+${ENTITY_PATTERN}\\b`, 'g') },
];

function extractExplicitRelationships(text) {
  const source = String(text || '');
  const relationships = [];
  const seen = new Set();
  for (const pattern of EXPLICIT_RELATIONSHIP_PATTERNS) {
    pattern.re.lastIndex = 0;
    for (const match of source.matchAll(pattern.re)) {
      const subject = normalizeEntity(match[1]);
      const object = normalizeEntity(match[2]);
      const rel = {
        subject,
        predicate: pattern.predicate,
        object,
        confidence: pattern.confidence
      };
      const key = `${rel.subject.toLowerCase()}|${rel.predicate}|${rel.object.toLowerCase()}`;
      if (!seen.has(key) && isUsableRelationship(rel)) {
        seen.add(key);
        relationships.push(rel);
      }
    }
  }
  return relationships;
}

function normalizeEntity(raw) {
  return String(raw || '')
    .replace(/\s+/g, ' ')
    .replace(/[.,;:!?]+$/g, '')
    .trim();
}

function isUsableRelationship(rel) {
  const subject = String(rel.subject || '').trim();
  const object = String(rel.object || '').trim();
  const predicate = String(rel.predicate || '').trim();
  if (!subject || !object || !predicate) return false;
  if (isPlaceholderEntity(subject) || isPlaceholderEntity(object)) return false;
  return true;
}

function isPlaceholderEntity(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return /^(entity\d*|subject|object|entity1|entity2)$/.test(normalized);
}

function clampConfidence(raw) {
  const n = Number(raw);
  if (isNaN(n)) return { value: 0.5, isDefault: true, reason: 'nan_input' };
  return { value: Math.max(0, Math.min(1, n)), isDefault: false, reason: null };
}

// ─── Phase 4: DAG Validation (Cycle Detection) ──────────────────────────────

/**
 * Validate that a set of relationships forms a DAG (no cycles).
 *
 * Uses Kahn's algorithm for topological sorting. If cycles are detected,
 * returns the nodes involved in cycles.
 *
 * @param {Array<{subject: string, predicate: string, object: string, confidence: number}>} relationships
 * @returns {{valid: true, topologicalOrder: string[]} | {valid: false, cycles: string[]}}
 */
export function validateDAG(relationships) {
  if (!Array.isArray(relationships) || relationships.length === 0) {
    return { valid: true, topologicalOrder: [] };
  }

  // Build adjacency list and in-degree map
  const adjacency = new Map();  // node → Set of outgoing neighbours
  const inDegree = new Map();   // node → number of incoming edges
  const allNodes = new Set();

  for (const rel of relationships) {
    const src = rel.subject;
    const dst = rel.object;
    if (!src || !dst) continue;

    allNodes.add(src);
    allNodes.add(dst);

    if (!adjacency.has(src)) adjacency.set(src, new Set());
    adjacency.get(src).add(dst);

    if (!inDegree.has(dst)) inDegree.set(dst, 0);
    if (!inDegree.has(src)) inDegree.set(src, 0);

    inDegree.set(dst, inDegree.get(dst) + 1);
  }

  // Kahn's algorithm: start with nodes that have in-degree 0
  const queue = [];
  for (const node of allNodes) {
    if ((inDegree.get(node) || 0) === 0) {
      queue.push(node);
    }
  }

  const topologicalOrder = [];
  while (queue.length > 0) {
    const node = queue.shift();
    topologicalOrder.push(node);

    const neighbours = adjacency.get(node);
    if (neighbours) {
      for (const neighbour of neighbours) {
        const newDegree = inDegree.get(neighbour) - 1;
        inDegree.set(neighbour, newDegree);
        if (newDegree === 0) {
          queue.push(neighbour);
        }
      }
    }
  }

  if (topologicalOrder.length === allNodes.size) {
    return { valid: true, topologicalOrder };
  }

  // Nodes not in topological order are part of cycles
  const cycles = [...allNodes].filter(n => !topologicalOrder.includes(n));
  return { valid: false, cycles };
}

export function buildTypedRelationshipDiagnostics({
  relationships = [],
  sourceId = null,
  sourceText = '',
} = {}) {
  const rawRelationships = Array.isArray(relationships) ? relationships : [];
  const text = String(sourceText || '');
  const typed = rawRelationships
    .map((rel, index) => {
      const subject = String(rel.subject || rel.source || '').trim();
      const object = String(rel.object || rel.target || '').trim();
      const predicate = toSnakeCase(rel.predicate || rel.edge_type || rel.relationship_type || 'related_to');
      const subjectOffset = subject ? text.indexOf(subject) : -1;
      const objectOffset = object ? text.indexOf(object) : -1;
      const c = clampConfidence(rel.confidence);
      return {
        relationship_id: `typed-rel-${index + 1}`,
        subject,
        predicate,
        object,
        relationship_type: predicate.toUpperCase(),
        confidence: c.value,
        confidenceIsDefault: c.isDefault || false,
        confidenceReason: c.reason || null,
        source_id: sourceId || rel.sourceId || null,
        evidence_offsets: {
          subject: subjectOffset,
          object: objectOffset,
        },
        source_bound: subjectOffset >= 0 || objectOffset >= 0,
      };
    })
    .filter((rel) => rel.subject && rel.object && rel.predicate);

  const dag = validateDAG(typed);
  return {
    diagnostic_type: 'typed_relationship_mapping',
    source_papers: WAVE5_RELATIONSHIP_AUTHORITIES,
    status: typed.length > 0 ? 'typed_relationships_ready' : 'no_relationships',
    diagnostic_only: true,
    source_id: sourceId || null,
    relationship_count: typed.length,
    relationship_types: [...new Set(typed.map((rel) => rel.relationship_type))],
    source_bound_count: typed.filter((rel) => rel.source_bound).length,
    relationships: typed,
    dag,
    guardrails: {
      graph_persistence_enabled: false,
      ontology_reasoner_enabled: false,
      ranking_math_changed: false,
      ppr_math_changed: false,
      canonical_memory_changed: false,
    },
  };
}
