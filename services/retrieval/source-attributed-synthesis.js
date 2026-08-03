/**
 * SOURCE-ATTRIBUTED RECALL SYNTHESIS
 *
 * Paper authority:
 * - Generative Retrieval Overcomes Limitations of Traditional Information
 *   Retrieval Methods in Identifier Ambiguity (Batch 6/7)
 * - From Guessing to Placeholding (Batch 6/7)
 * - Additive Batch8 authority: Reasoning Graphs: Self-Improving,
 *   Deterministic RAG through Evidence-Centric Feedback
 * - Additive Batch8 Wave 3 authority: MERIT, VerifAI, CSMCIR, and BRIDGE.
 *   Aimos exposes interpretable evidence trails, source-bound claim cards,
 *   and future multimodal text-intent bridge diagnostics only. NLI scoring,
 *   contrastive memory-bank training, and RL query alignment stay guarded.
 *
 * Purpose:
 * - Build a compact, source-attributed answer sketch from the top retrieved
 *   Aimos candidates.
 * - Keep synthesis bounded to retrieved evidence. If evidence is thin, return
 *   an explicit placeholder instead of inventing a conclusion.
 *
 * Guardrails:
 * - This is deterministic extractive synthesis, not free-form LLM generation.
 * - It does not change retrieval ranking, recall calibration, trust scoring,
 *   MVS, STDP, or memory write math.
 * - Additive Batch9/9.5 Wave5 authority: Ontology-Aware Design Patterns,
 *   ELISA, Reconstructing Content via Collaborative Attention, One Token per
 *   Highly Selective Frame, Sink-Token-Aware Pruning, and Long-Horizon
 *   Streaming Video Generation. Aimos exposes typed evidence paths and one
 *   evidence card per event as text-safe diagnostics only.
 */

const DEFAULT_TOP_N = 5;
const REASONING_GRAPHS_AUTHORITY = 'Reasoning Graphs: Self-Improving, Deterministic RAG through Evidence-Centric Feedback';
const BATCH8_WAVE3_EVIDENCE_AUTHORITIES = [
  'MERIT: Memory-Enhanced Retrieval for Interpretable Knowledge Tracing',
  'VerifAI: A Verifiable Open-Source Search Engine for Biomedical Question Answering',
  'CSMCIR: CoT-Enhanced Symmetric Alignment with Memory Bank for Composed Image Retrieval',
];
const BATCH9_WAVE5_REPRESENTATION_AUTHORITIES = [
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture',
  'ELISA: An Interpretable Hybrid Generative AI Agent for Expression-Grounded Discovery in Single-Cell Genomics',
  'Reconstructing Content via Collaborative Attention to Improve Multimodal Embedding Quality',
];
const BATCH9_5_EVENT_CARD_AUTHORITIES = [
  'One Token per Highly Selective Frame- Towards Extreme Compression for Long Video Understanding',
  'Sink-Token-Aware Pruning for Fine-Grained Video Understanding in Efficient Video LLMs',
  'Long-Horizon Streaming Video Generation via Hybrid Attention with Decoupled Distillation',
];
const STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'how', 'i',
  'in', 'is', 'it', 'of', 'on', 'or', 'that', 'the', 'this', 'to', 'was',
  'we', 'what', 'when', 'where', 'which', 'why', 'with', 'you',
]);

function tokenize(text = '') {
  return String(text)
    .toLowerCase()
    .replace(/[^a-z0-9_:-]+/g, ' ')
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function splitSentences(text = '') {
  const normalized = String(text || '').replace(/\s+/g, ' ').trim();
  if (!normalized) return [];
  return normalized
    .split(/(?<=[.!?])\s+/)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
}

function firstMeaningfulSentence(memory = {}) {
  const sentences = splitSentences(memory.value);
  if (sentences.length) return sentences[0];
  return String(memory.value || '').replace(/\s+/g, ' ').trim().slice(0, 280);
}

function scoreEvidenceSentence(sentence, queryTokens, memory = {}) {
  const sentenceTokens = new Set(tokenize(sentence));
  const hits = queryTokens.filter((token) => sentenceTokens.has(token)).length;
  const lexical = queryTokens.length ? hits / queryTokens.length : 0;
  const recallConfidence = Number(memory.recall_confidence ?? memory.similarity ?? memory.rerank_score ?? 0.5);
  const authority = Number(memory.trust_score ?? memory.credit_score ?? 0.5);
  return lexical * 0.55 + Math.max(0, Math.min(1, recallConfidence)) * 0.3 + Math.max(0, Math.min(1, authority)) * 0.15;
}

function buildEvidenceSource(memory = {}, index = 0, excerpt = '') {
  return {
    index: index + 1,
    id: memory.id || null,
    key: memory.key || null,
    memory_type: memory.memory_type || null,
    source: memory.source || memory.agent_id || null,
    created_at: memory.created_at || null,
    confidence: Number(memory.recall_confidence ?? memory.similarity ?? memory.rerank_score ?? 0),
    excerpt: String(excerpt || memory.value || '').replace(/\s+/g, ' ').trim().slice(0, 320),
  };
}

function stableGraphId(prefix, value, index = 0) {
  const slug = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_:-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return `${prefix}:${slug || index + 1}`;
}

function inferEvidenceVerdict(memory = {}) {
  const confidence = Number(memory.recall_confidence ?? memory.similarity ?? memory.rerank_score ?? 0);
  if (confidence >= 0.7) return 'used';
  if (confidence > 0) return 'weakly_used';
  return 'candidate';
}

function evidenceConfidence(memory = {}) {
  return Number(memory.recall_confidence ?? memory.similarity ?? memory.rerank_score ?? 0);
}

function normalizeRelationshipType(raw = '') {
  const normalized = String(raw || 'related_to')
    .toUpperCase()
    .trim()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return normalized || 'RELATED_TO';
}

function eventIdentity(event = {}, index = 0) {
  return String(
    event.event_id ||
    event.eventId ||
    event.key ||
    event.id ||
    event.memory_id ||
    `event-${index + 1}`
  );
}

export function buildOneEvidenceCardPerEventPolicy({
  events = [],
  maxExcerptChars = 260,
} = {}) {
  const safeEvents = Array.isArray(events) ? events : [];
  const cards = safeEvents.map((event, index) => {
    const eventId = eventIdentity(event, index);
    const excerpt = String(event.excerpt || event.value || event.text || event.summary || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, Math.max(80, Math.min(Number(maxExcerptChars) || 260, 600)));
    return {
      card_type: 'one_evidence_card_per_event',
      event_id: eventId,
      memory_id: event.id || event.memory_id || null,
      key: event.key || null,
      source: event.source || event.agent_id || null,
      relationship_type: normalizeRelationshipType(event.relationship_type || event.predicate || 'evidence_event'),
      excerpt,
      open_memory_handle: event.key || event.id || event.memory_id || eventId,
      raw_event_dump_included: false,
      raw_media_included: false,
      status: 'text_safe_evidence_card',
    };
  });

  return {
    policy: 'one_evidence_card_per_event',
    source_papers: BATCH9_5_EVENT_CARD_AUTHORITIES,
    diagnostic_only: true,
    event_count: safeEvents.length,
    card_count: cards.length,
    cards,
    invariant_holds: cards.length === safeEvents.length,
    text_safe_inheritance: true,
    guardrails: {
      raw_video_tokens_exposed: false,
      raw_audio_tokens_exposed: false,
      raw_image_payload_exposed: false,
      raw_tool_protocol_exposed: false,
      canonical_memory_changed: false,
      production_multimodal_claim: false,
    },
  };
}

export function buildTypedEvidencePathDiagnostics({
  queryText = '',
  memories = [],
  relationships = [],
  topN = DEFAULT_TOP_N,
} = {}) {
  const candidates = Array.isArray(memories)
    ? memories.filter((memory) => memory && (memory.key || memory.id || String(memory.value || '').trim()))
    : [];
  const capped = candidates.slice(0, Math.max(1, Math.min(Number(topN) || DEFAULT_TOP_N, 12)));
  const relationInputs = Array.isArray(relationships) ? relationships : [];
  const sourceByName = new Map();

  capped.forEach((memory, index) => {
    const aliases = [
      memory.key,
      memory.id,
      memory.memory_id,
      memory.event_id,
      `evidence-${index + 1}`,
    ].filter(Boolean).map(String);
    for (const alias of aliases) sourceByName.set(alias.toLowerCase(), memory);
  });

  const typedRelationships = relationInputs.length > 0
    ? relationInputs
    : capped.map((memory, index) => ({
        subject: queryText || 'query',
        predicate: 'supported_by',
        object: memory.key || memory.id || `evidence-${index + 1}`,
        confidence: evidenceConfidence(memory) || 0.5,
      }));

  const edges = typedRelationships
    .map((rel, index) => {
      const objectKey = String(rel.object || rel.target || '').toLowerCase();
      const subjectKey = String(rel.subject || rel.source || '').toLowerCase();
      const sourceMemory = sourceByName.get(objectKey) || sourceByName.get(subjectKey) || capped[index % Math.max(capped.length, 1)] || {};
      return {
        edge_id: stableGraphId('typed_edge', `${rel.subject || 'query'}-${rel.predicate || rel.edge_type || index}-${rel.object || 'evidence'}`, index),
        subject: String(rel.subject || rel.source || queryText || 'query'),
        relationship_type: normalizeRelationshipType(rel.predicate || rel.edge_type || rel.relationship_type),
        object: String(rel.object || rel.target || sourceMemory.key || sourceMemory.id || `evidence-${index + 1}`),
        confidence: Number(Math.max(0, Math.min(Number(rel.confidence ?? evidenceConfidence(sourceMemory) ?? 0.5), 1)).toFixed(3)),
        source_key: sourceMemory.key || null,
        source_id: sourceMemory.id || null,
        source: sourceMemory.source || sourceMemory.agent_id || null,
        evidence_path: [
          stableGraphId('query', queryText || 'query'),
          stableGraphId('relationship', rel.predicate || rel.edge_type || 'supported_by', index),
          stableGraphId('source', sourceMemory.key || sourceMemory.id || `source-${index + 1}`, index),
        ],
      };
    })
    .filter((edge) => edge.subject && edge.object);

  const eventCardPolicy = buildOneEvidenceCardPerEventPolicy({ events: capped });
  const relationshipTypes = [...new Set(edges.map((edge) => edge.relationship_type))];
  const sources = [...new Set(edges.map((edge) => edge.source_key || edge.source_id).filter(Boolean))];

  return {
    diagnostic_type: 'typed_relationship_evidence_paths',
    status: capped.length > 0 ? 'typed_evidence_paths_ready' : 'no_evidence',
    source_papers: BATCH9_WAVE5_REPRESENTATION_AUTHORITIES,
    diagnostic_only: true,
    relationship_type_count: relationshipTypes.length,
    relationship_types: relationshipTypes,
    source_count: sources.length,
    sources,
    edges,
    evidence_cards: eventCardPolicy.cards,
    one_evidence_card_per_event: eventCardPolicy.invariant_holds,
    event_card_policy: eventCardPolicy,
    guardrails: {
      ranking_math_changed: false,
      ppr_math_changed: false,
      recall_behavior_changed: false,
      hidden_chain_of_thought_exposed: false,
      raw_tool_protocol_exposed: false,
      raw_media_payload_exposed: false,
      canonical_memory_changed: false,
      multimodal_production_claim: false,
    },
  };
}

export function buildInterpretableEvidenceTrail({
  queryText = '',
  selectedEvidence = [],
  evidenceGraph = null,
} = {}) {
  const graphCards = new Map(
    (Array.isArray(evidenceGraph?.evidence_cards) ? evidenceGraph.evidence_cards : [])
      .map((card) => [card.key || card.memory_id, card])
  );

  const trail = (Array.isArray(selectedEvidence) ? selectedEvidence : []).map((entry, index) => {
    const memory = entry.memory || entry;
    const key = memory.key || memory.id || null;
    const graphCard = graphCards.get(key) || graphCards.get(memory.id) || {};
    const confidence = Number(
      memory.recall_confidence ?? memory.similarity ?? memory.rerank_score ?? entry.score ?? 0
    );
    const excerpt = String(entry.sentence || graphCard.excerpt || firstMeaningfulSentence(memory) || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 320);
    const verdict = graphCard.verdict || inferEvidenceVerdict(memory);

    return {
      step: index + 1,
      key,
      memory_id: memory.id || null,
      memory_type: memory.memory_type || null,
      source: memory.source || memory.agent_id || null,
      created_at: memory.created_at || null,
      freshness_state: memory.freshness_state || null,
      confidence: Number(Math.max(0, Math.min(confidence, 1)).toFixed(3)),
      verdict,
      selected_reason: verdict === 'used'
        ? 'Top retrieved evidence directly supports the bounded answer.'
        : 'Evidence was retained as a weak or candidate support signal.',
      excerpt,
      query_overlap: tokenize(queryText).filter((token) => excerpt.toLowerCase().includes(token)).slice(0, 8),
    };
  });

  return {
    source_papers: BATCH8_WAVE3_EVIDENCE_AUTHORITIES,
    diagnostic_only: true,
    trail,
    trail_count: trail.length,
    claim_verification_math_guarded: {
      merit_schema_centroids: false,
      verifai_nli_scoring: false,
      csmcir_contrastive_memory_bank: false,
    },
    ranking_math_changed: false,
    hidden_chain_of_thought_exposed: false,
    canonical_memory_changed: false,
  };
}

export function buildDeterministicEvidenceGraph({
  queryText = '',
  memories = [],
  topN = DEFAULT_TOP_N,
  claimText = null,
} = {}) {
  const candidates = Array.isArray(memories)
    ? memories.filter((memory) => memory && String(memory.value || '').trim())
    : [];
  const capped = candidates.slice(0, Math.max(1, Math.min(Number(topN) || DEFAULT_TOP_N, 12)));
  const claimNodeId = stableGraphId('claim', claimText || queryText || 'bounded-claim');
  if (!capped.length) {
    return {
      graph_type: 'deterministic_evidence_graph',
      status: 'no_evidence',
      source_paper: REASONING_GRAPHS_AUTHORITY,
      diagnostic_only: true,
      node_count: 0,
      edge_count: 0,
      nodes: [],
      edges: [],
      evidence_cards: [],
      evidence_profile: {
        coverage: 0,
        evaluated_edge_count: 0,
        cold_start: true,
        reliability_formula_guarded: 'R(k_i,tau)=used_correct/incoming_evaluations',
      },
      guardrails: {
        graph_persistence_enabled: false,
        retrieval_exclusion_enabled: false,
        ranking_math_changed: false,
        ppr_math_changed: false,
        recall_behavior_changed: false,
        hidden_chain_of_thought_exposed: false,
        canonical_memory_changed: false,
        deletion_enabled: false,
      },
    };
  }

  const nodes = [
    {
      id: claimNodeId,
      node_type: 'claim',
      label: String(claimText || 'bounded source-attributed answer').slice(0, 220),
      source_metadata: {
        paper: REASONING_GRAPHS_AUTHORITY,
        role: 'deterministic_claim',
      },
    },
  ];
  const edges = [];
  const evidenceCards = [];

  capped.forEach((memory, index) => {
    const evidenceNodeId = stableGraphId('evidence', memory.key || memory.id || `memory-${index}`, index);
    const sourceNodeId = stableGraphId('source_memory', memory.id || memory.key || `memory-${index}`, index);
    const excerpt = firstMeaningfulSentence(memory);
    const confidence = evidenceConfidence(memory);
    const verdict = inferEvidenceVerdict(memory);
    const confidenceDelta = Number(Math.max(Math.min(confidence - 0.5, 0.5), -0.5).toFixed(3));
    nodes.push({
      id: evidenceNodeId,
      node_type: 'evidence',
      key: memory.key || null,
      memory_type: memory.memory_type || null,
      label: String(memory.key || memory.id || `evidence ${index + 1}`).slice(0, 180),
      excerpt: String(excerpt || '').slice(0, 260),
      source_metadata: {
        table: memory.evidence_table || memory.source || 'aimos_memories',
        source: memory.source || memory.agent_id || null,
        created_at: memory.created_at || null,
        freshness_state: memory.freshness_state || null,
      },
    });
    nodes.push({
      id: sourceNodeId,
      node_type: 'source_memory',
      key: memory.key || null,
      memory_id: memory.id || null,
      label: String(memory.key || memory.id || `source memory ${index + 1}`).slice(0, 180),
      source_metadata: {
        table: memory.evidence_table || memory.source || 'aimos_memories',
        source: memory.source || memory.agent_id || null,
        created_at: memory.created_at || null,
        freshness_state: memory.freshness_state || null,
      },
    });
    edges.push({
      from: claimNodeId,
      to: evidenceNodeId,
      edge_type: 'SUPPORTED_BY',
      verdict,
      confidence_delta: confidenceDelta,
      reason: String(excerpt || 'Evidence contributes to the source-attributed answer.').slice(0, 260),
      source_metadata: {
        paper: REASONING_GRAPHS_AUTHORITY,
        relation: 'claim_to_evidence',
        rank: index + 1,
      },
    });
    edges.push({
      from: evidenceNodeId,
      to: sourceNodeId,
      edge_type: 'CITED_FROM',
      verdict,
      confidence_delta: confidenceDelta,
      reason: 'Evidence node is source-bound to the original Aimos memory.',
      source_metadata: {
        paper: REASONING_GRAPHS_AUTHORITY,
        relation: 'evidence_to_source_memory',
        memory_key: memory.key || null,
      },
    });
    evidenceCards.push({
      card_type: 'deterministic_evidence_card',
      evidence_id: evidenceNodeId,
      memory_id: memory.id || null,
      key: memory.key || null,
      source: memory.source || memory.agent_id || null,
      excerpt: String(excerpt || '').slice(0, 260),
      verdict,
      reason: String(excerpt || 'Evidence contributes to the source-attributed answer.').slice(0, 260),
      confidence_delta: confidenceDelta,
      reliability_score: Number(Math.max(0, Math.min(confidence, 1)).toFixed(3)),
      verdict_distribution: { [verdict]: 1 },
      prior_correct_evaluation_count: 0,
      top_reason: String(excerpt || '').slice(0, 180),
      freshness_state: memory.freshness_state || null,
      status: 'source_attributed',
    });
  });

  return {
    graph_type: 'deterministic_evidence_graph',
    status: 'source_attributed',
    source_paper: REASONING_GRAPHS_AUTHORITY,
    diagnostic_only: true,
    node_count: nodes.length,
    edge_count: edges.length,
    nodes,
    edges,
    evidence_cards: evidenceCards,
    evidence_profile: {
      coverage: capped.length,
      evaluated_edge_count: edges.length,
      cold_start: capped.length === 0,
      reliability_formula_guarded: 'R(k_i,tau)=used_correct/incoming_evaluations',
    },
    guardrails: {
      graph_persistence_enabled: false,
      retrieval_exclusion_enabled: false,
      ranking_math_changed: false,
      ppr_math_changed: false,
      recall_behavior_changed: false,
      hidden_chain_of_thought_exposed: false,
      canonical_memory_changed: false,
      deletion_enabled: false,
    },
  };
}

/**
 * Build a source-attributed synthesis envelope.
 *
 * @param {{
 *   queryText?: string,
 *   memories?: Array<object>,
 *   topN?: number,
 *   minEvidence?: number
 * }} options
 * @returns {object}
 */
export function buildSourceAttributedSynthesis({
  queryText = '',
  memories = [],
  topN = DEFAULT_TOP_N,
  minEvidence = 1,
  relationships = [],
} = {}) {
  const candidates = Array.isArray(memories)
    ? memories.filter((memory) => memory && String(memory.value || '').trim())
    : [];
  const queryTokens = tokenize(queryText);
  const capped = candidates.slice(0, Math.max(1, Math.min(Number(topN) || DEFAULT_TOP_N, 12)));

  const evidence = capped
    .map((memory, index) => {
      const sentences = splitSentences(memory.value);
      const bestSentence = (sentences.length ? sentences : [firstMeaningfulSentence(memory)])
        .map((sentence) => ({
          sentence,
          score: scoreEvidenceSentence(sentence, queryTokens, memory),
        }))
        .sort((a, b) => b.score - a.score)[0];

      return {
        memory,
        index,
        sentence: bestSentence?.sentence || firstMeaningfulSentence(memory),
        score: Number((bestSentence?.score || 0).toFixed(3)),
      };
    })
    .filter((entry) => entry.sentence)
    .sort((a, b) => b.score - a.score);

  if (evidence.length < minEvidence) {
    const evidenceGraph = buildDeterministicEvidenceGraph({
      queryText,
      memories: [],
      topN,
      claimText: null,
    });
    const typedEvidencePaths = buildTypedEvidencePathDiagnostics({
      queryText,
      memories: [],
      relationships,
      topN,
    });
    return {
      status: 'insufficient_evidence',
      synthesis: null,
      source_count: 0,
      sources: [],
      evidence_graph: evidenceGraph,
      typed_evidence_paths: typedEvidencePaths,
      evidence_trail: buildInterpretableEvidenceTrail({
        queryText,
        selectedEvidence: [],
        evidenceGraph,
      }),
      placeholder: {
        action: 'retrieve_more_evidence_or_supply_exact_key',
        reason: 'No retrieved source text was available for bounded synthesis.',
      },
      source_papers: [
        'Generative Retrieval identifier ambiguity',
        'From Guessing to Placeholding',
      ],
      generative_model_used: false,
      ranking_math_changed: false,
    };
  }

  const selected = evidence.slice(0, Math.min(3, evidence.length));
  const synthesis = selected
    .map((entry, idx) => `[${idx + 1}] ${entry.sentence}`)
    .join(' ');
  const evidenceGraph = buildDeterministicEvidenceGraph({
    queryText,
    memories: selected.map((entry) => entry.memory),
    topN: selected.length,
    claimText: synthesis,
  });
  const typedEvidencePaths = buildTypedEvidencePathDiagnostics({
    queryText,
    memories: selected.map((entry) => entry.memory),
    relationships,
    topN: selected.length,
  });

  return {
    status: 'source_attributed',
    synthesis,
    source_count: selected.length,
    sources: selected.map((entry, idx) => buildEvidenceSource(entry.memory, idx, entry.sentence)),
    evidence_graph: evidenceGraph,
    typed_evidence_paths: typedEvidencePaths,
    evidence_trail: buildInterpretableEvidenceTrail({
      queryText,
      selectedEvidence: selected,
      evidenceGraph,
    }),
    diagnostics: {
      candidate_count: candidates.length,
      top_n_considered: capped.length,
      query_token_count: queryTokens.length,
      evidence_scores: selected.map((entry) => entry.score),
    },
    source_papers: [
      'Generative Retrieval identifier ambiguity',
      'From Guessing to Placeholding',
    ],
    generation_method: 'deterministic_extractive_source_attributed',
    generative_model_used: false,
    ranking_math_changed: false,
  };
}

export default {
  buildSourceAttributedSynthesis,
  buildDeterministicEvidenceGraph,
  buildInterpretableEvidenceTrail,
  buildTypedEvidencePathDiagnostics,
  buildOneEvidenceCardPerEventPolicy,
};
