/**
 * procedural-reasoning-retriever.js — Hierarchical Procedural Reasoning recall
 * Source: Learning Hierarchical Procedural Memory for LLM Agents through
 * Bayesian Selection and Contrastive Refinement (MACLA; Forouzandeh et al.,
 * arXiv:2512.18950, 2025)
 * Additive Batch8 authority: MemCoT: Test-Time Scaling through
 * Memory-Driven Chain-of-Thought — public memory-reasoning cards only.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js when recall-mode-planner selects reasoning_trace
 * 2. → Pulls from: aimos_memories (session_reasoning, ai_adr, session_debrief)
 * 3. → Pulls from: procedural_skills (reusable procedures and playbooks)
 * 4. ↔ Interacts with: services/observe/explainer.js and architecture-registry.js outputs
 *
 * LOGIC GUIDE:
 * MACLA decouples reasoning from learning by storing external procedures and
 * meta-procedures. This read path makes those artifacts recallable across
 * sessions without exposing hidden scratchpad or changing Bayesian selection
 * behavior. Reliability math is diagnostic only; it does not select actions.
 */

import { query as defaultQuery } from '../../db/connection.js';

const MAX_LIMIT = 50;
const MEMORY_REASONING_CARD_LIMIT = 5;
const MEMORY_REASONING_CARD_SCHEMA = 'batch8-memcot-public-card-v1';
const MEMORY_REASONING_CARD_AUTHORITY = 'MemCoT: Test-Time Scaling through Memory-Driven Chain-of-Thought';

function clampLimit(limit) {
  return Math.min(Math.max(Number(limit || 10), 1), MAX_LIMIT);
}

function truncate(text, max = 700) {
  const value = String(text || '').replace(/\s+/g, ' ').trim();
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function slugPart(value, fallback = 'card') {
  const slug = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
  return slug || fallback;
}

function firstSentence(text, max = 260) {
  const value = truncate(text, max * 2);
  const match = value.match(/^(.{20,}?[.!?])\s/);
  return truncate(match?.[1] || value, max);
}

function contentNeedle(queryText, planner) {
  return String(planner?.content_hint || queryText || '')
    .replace(/\b(show|reasoning|trace|behind|this|fix|decision|why|how|what|was|the|please|latest)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function isSolutionReasoningQuery(queryText = '', planner = {}) {
  const haystack = `${queryText || ''} ${planner?.mode || ''} ${planner?.content_hint || ''}`.toLowerCase();
  return (
    /reasoning_trace/.test(haystack)
    || /\b(how|why|what led|reasoning|rationale|approach)\b/.test(haystack)
    || /\b(solve|solved|fix|fixed|decide|decided|decision|handled|recover|recovered)\b/.test(haystack)
  );
}

function safeJson(value, fallback = null) {
  if (value == null) return fallback;
  if (Array.isArray(value) || (typeof value === 'object' && value !== null)) return value;
  try {
    return JSON.parse(String(value));
  } catch {
    return fallback;
  }
}

function betaReliability(successCount = 0, failCount = 0) {
  const success = Math.max(Number(successCount || 0), 0);
  const fail = Math.max(Number(failCount || 0), 0);
  // MACLA tracks Beta(alpha, beta). We use a neutral Beta(1,1) prior for
  // diagnostic reliability only, not for action selection or utility ranking.
  const alpha = success + 1;
  const beta = fail + 1;
  const posteriorMean = alpha / (alpha + beta);
  const observedTotal = success + fail;
  return {
    alpha,
    beta,
    posterior_mean: Number(posteriorMean.toFixed(3)),
    observed_success_rate: observedTotal > 0 ? Number((success / observedTotal).toFixed(3)) : null,
    success_count: success,
    fail_count: fail,
    evidence_count: observedTotal,
    diagnostic_only: true,
  };
}

function classifyProcedure(row) {
  const tags = Array.isArray(row.tags) ? row.tags.map(String) : [];
  if (tags.some((tag) => /meta|playbook|composition/i.test(tag))) return 'meta_procedure';
  const steps = safeJson(row.steps, []);
  if (Array.isArray(steps) && steps.length > 3) return 'procedure';
  return 'atomic_procedure';
}

function reasoningRowToMemory(row, index) {
  return {
    id: String(row.id),
    key: row.key,
    value: row.value,
    agent_id: row.agent_id,
    memory_type: row.memory_type,
    scope: row.scope,
    source: row.source,
    clearance_level: row.clearance_level,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_verified_at: row.last_verified_at,
    verified_by: row.verified_by,
    verification_basis: row.verification_basis,
    freshness_state: row.freshness_state,
    similarity: Math.max(0.72, 0.95 - index * 0.03),
    rerank_score: Math.max(0.72, 0.95 - index * 0.03),
    recall_confidence: Math.max(0.7, 0.93 - index * 0.04),
    procedural_reasoning_role: row.key?.startsWith('ai_adr:') ? 'decision_record' : 'reasoning_artifact',
  };
}

function skillRowToProcedure(row) {
  const steps = safeJson(row.steps, []);
  const reliability = betaReliability(row.success_count, row.fail_count);
  return {
    id: String(row.id),
    skill_name: row.skill_name,
    trigger_pattern: row.trigger_pattern || null,
    expected_outcome: row.expected_outcome || null,
    procedure_type: classifyProcedure(row),
    steps: Array.isArray(steps) ? steps.slice(0, 12) : [],
    tags: Array.isArray(row.tags) ? row.tags : [],
    last_used: row.last_used || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    reliability,
    source_metadata: {
      table: 'procedural_skills',
      paper: 'MACLA',
      selection_math: 'diagnostic_beta_reliability_only',
    },
  };
}

function procedureToMemory(procedure, index) {
  const summary = [
    `Procedure: ${procedure.skill_name}`,
    procedure.trigger_pattern ? `Trigger: ${procedure.trigger_pattern}` : null,
    procedure.expected_outcome ? `Expected outcome: ${procedure.expected_outcome}` : null,
    procedure.steps?.length ? `Steps: ${JSON.stringify(procedure.steps).slice(0, 450)}` : null,
  ].filter(Boolean).join('\n');

  return {
    id: `procedural_skill:${procedure.id}`,
    key: `procedural_skill:${procedure.skill_name}`,
    value: truncate(summary),
    agent_id: 'procedural-memory',
    memory_type: procedure.procedure_type,
    scope: 'procedural',
    source: 'procedural_skills',
    clearance_level: 10,
    created_at: procedure.created_at,
    updated_at: procedure.updated_at,
    similarity: Math.max(0.7, 0.9 - index * 0.03),
    rerank_score: Math.max(0.7, 0.9 - index * 0.03),
    recall_confidence: Math.max(0.68, 0.88 - index * 0.03),
    procedural_reasoning_role: procedure.procedure_type,
    reliability: procedure.reliability,
  };
}

function confidenceFrom(artifact, procedure) {
  const artifactConfidence = Number(
    artifact?.recall_confidence
    ?? artifact?.rerank_score
    ?? artifact?.similarity
    ?? 0.5
  );
  const procedureConfidence = Number(procedure?.reliability?.posterior_mean ?? 0.5);
  const confidence = (artifactConfidence + procedureConfidence) / 2;
  return Number(Math.min(Math.max(confidence, 0), 1).toFixed(3));
}

function buildEvidenceRef(artifact) {
  if (!artifact) return null;
  return {
    id: artifact.id,
    key: artifact.key,
    memory_type: artifact.memory_type,
    source: artifact.source || null,
    created_at: artifact.created_at || null,
    freshness_state: artifact.freshness_state || null,
    excerpt: firstSentence(artifact.value, 320),
    source_metadata: {
      table: 'aimos_memories',
      role: artifact.procedural_reasoning_role || 'reasoning_artifact',
    },
  };
}

function buildProcedureRef(procedure) {
  if (!procedure) return null;
  const stepLabels = Array.isArray(procedure.steps)
    ? procedure.steps
      .map((step) => (typeof step === 'string' ? step : step?.action || step?.name || step?.label))
      .filter(Boolean)
      .slice(0, 4)
      .map((step) => truncate(step, 80))
    : [];
  return {
    id: procedure.id,
    key: `procedural_skill:${procedure.skill_name}`,
    procedure_type: procedure.procedure_type,
    trigger_pattern: procedure.trigger_pattern || null,
    expected_outcome: procedure.expected_outcome || null,
    step_count: Array.isArray(procedure.steps) ? procedure.steps.length : 0,
    public_step_summary: stepLabels,
    reliability_posterior_mean: procedure.reliability?.posterior_mean ?? null,
    source_metadata: {
      table: 'procedural_skills',
      role: 'reusable_public_procedure_summary',
    },
  };
}

function buildCardLinks(traceLinks, artifact, procedure) {
  const artifactKey = artifact?.key;
  const procedureKey = procedure?.skill_name ? `procedural_skill:${procedure.skill_name}` : null;
  return (traceLinks || [])
    .filter((link) => (
      (artifactKey && link.from === artifactKey)
      || (procedureKey && link.to === procedureKey)
    ))
    .slice(0, 3)
    .map((link) => ({
      from: link.from,
      to: link.to,
      edge_type: link.edge_type,
      shared_terms: Array.isArray(link.shared_terms) ? link.shared_terms.slice(0, 5) : [],
      source_metadata: link.source_metadata || null,
    }));
}

export function buildPublicMemoryReasoningCards(
  reasoningArtifacts = [],
  procedures = [],
  traceLinks = [],
  opts = {}
) {
  const maxCards = Math.min(
    Math.max(Number(opts.limit || MEMORY_REASONING_CARD_LIMIT), 1),
    MEMORY_REASONING_CARD_LIMIT
  );
  const cardCount = Math.min(
    Math.max(reasoningArtifacts.length, procedures.length),
    maxCards
  );
  if (!cardCount) return [];

  const problemHint = truncate(
    opts.problemHint
    || contentNeedle(opts.queryText || '', opts.planner || {})
    || procedures[0]?.trigger_pattern
    || reasoningArtifacts[0]?.key
    || 'reasoning request',
    180
  );

  const cards = [];
  for (let index = 0; index < cardCount; index += 1) {
    const artifact = reasoningArtifacts[index] || reasoningArtifacts[0] || null;
    const procedure = procedures[index] || procedures[0] || null;
    const evidenceRef = buildEvidenceRef(artifact);
    const procedureRef = buildProcedureRef(procedure);
    const supportRefs = [
      evidenceRef?.key,
      procedureRef?.key,
    ].filter(Boolean);
    const publicSummary = truncate(
      [
        artifact?.value ? firstSentence(artifact.value, 260) : null,
        procedure?.expected_outcome ? `Expected outcome: ${truncate(procedure.expected_outcome, 180)}` : null,
      ].filter(Boolean).join(' '),
      420
    );

    cards.push({
      card_id: `memcot:${index + 1}:${slugPart(procedure?.skill_name || artifact?.key || problemHint)}`,
      card_type: 'public_memory_reasoning_card',
      schema_version: MEMORY_REASONING_CARD_SCHEMA,
      query_id: opts.queryId || null,
      session_id: opts.sessionId || null,
      user_query_summary: truncate(opts.queryText || '', 180),
      question_intent: 'solution_reasoning',
      iteration_index: index,
      subquery: problemHint,
      problem_hint: problemHint,
      public_summary: publicSummary || 'A persisted reasoning artifact or procedure matched the request.',
      semantic_state_summary: truncate(
        artifact?.procedural_reasoning_role || procedure?.procedure_type || 'reasoning_artifact',
        120
      ),
      trajectory_summary: procedureRef?.public_step_summary?.length
        ? `Procedure summary: ${procedureRef.public_step_summary.join(' -> ')}`
        : 'Evidence-only reasoning summary.',
      blind_spots: supportRefs.length ? [] : ['no_public_support_refs'],
      pruned_intents: [],
      sufficiency_status: supportRefs.length ? 'bounded_evidence_available' : 'insufficient_public_evidence',
      next_query_or_stop_reason: supportRefs.length ? 'stop_public_card_ready' : 'need_more_evidence',
      zoom_in_evidence_refs: evidenceRef ? [evidenceRef] : [],
      zoom_out_context_refs: procedureRef ? [procedureRef] : [],
      evidence_refs: evidenceRef ? [evidenceRef] : [],
      procedure_refs: procedureRef ? [procedureRef] : [],
      links: buildCardLinks(traceLinks, artifact, procedure),
      answer_support_refs: supportRefs,
      confidence: confidenceFrom(artifact, procedure),
      guard_flags: {
        hidden_chain_of_thought_exposed: false,
        private_reasoning_exposed: false,
        raw_trace_exposed: false,
        ranking_mutated: false,
        selection_math_enabled: false,
        canonical_memory_changed: false,
        deletion_enabled: false,
      },
      data_class: 'public_reasoning_summary',
      diagnostic_only: true,
      created_at: new Date(0).toISOString(),
      paper_authority: MEMORY_REASONING_CARD_AUTHORITY,
    });
  }
  return cards;
}

async function readReasoningArtifacts({
  queryFn,
  companyId,
  agentId,
  clearanceLevel,
  contentHint,
  dataClassFilter,
  limit,
}) {
  const params = [companyId, clearanceLevel, agentId];
  let whereClause = `
    company_id = $1
    AND clearance_level <= $2
    AND (clearance_level > 2 OR agent_id = $3 OR agent_id IS NULL)
    AND (
      memory_type = 'session_reasoning'
      OR key LIKE 'ai_adr:%'
      OR memory_type = 'after_action_review'
      OR memory_type = 'session_debrief'
    )
  `;

  if (Array.isArray(dataClassFilter) && dataClassFilter.length) {
    params.push(dataClassFilter);
    whereClause += ` AND COALESCE(data_class, 'public') = ANY($${params.length}::text[])`;
  }

  if (contentHint.length >= 3) {
    params.push(`%${contentHint}%`);
    whereClause += ` AND (key ILIKE $${params.length} OR value ILIKE $${params.length})`;
  }

  params.push(limit);
  const result = await queryFn(
    `SELECT id, key, value, agent_id, memory_type, scope, source, clearance_level,
            retrieval_weight, created_at, updated_at, last_verified_at,
            verified_by, verification_basis, freshness_state
     FROM aimos_memories
     WHERE ${whereClause}
     ORDER BY
       CASE
         WHEN key LIKE 'ai_adr:%' THEN 0
         WHEN memory_type = 'session_reasoning' THEN 1
         WHEN memory_type = 'after_action_review' THEN 2
         ELSE 3
       END,
       created_at DESC
     LIMIT $${params.length}`,
    params
  );

  return (result.rows || []).map(reasoningRowToMemory);
}

async function readProceduralSkills({
  queryFn,
  companyId,
  agentId,
  contentHint,
  limit,
}) {
  const params = [companyId];
  let whereClause = `company_id = $1`;

  if (agentId) {
    params.push(agentId);
    whereClause += ` AND (agent_id = $${params.length} OR agent_id = 'system')`;
  }

  if (contentHint.length >= 3) {
    params.push(`%${contentHint}%`);
    whereClause += ` AND (
      skill_name ILIKE $${params.length}
      OR COALESCE(trigger_pattern, '') ILIKE $${params.length}
      OR COALESCE(expected_outcome, '') ILIKE $${params.length}
      OR steps::text ILIKE $${params.length}
      OR tags::text ILIKE $${params.length}
    )`;
  }

  params.push(limit);
  const result = await queryFn(
    `SELECT id, company_id, agent_id, skill_name, trigger_pattern, steps,
            expected_outcome, success_count, fail_count, last_used, tags,
            created_at, updated_at
     FROM procedural_skills
     WHERE ${whereClause}
     ORDER BY
       (COALESCE(success_count, 0) + COALESCE(fail_count, 0)) DESC,
       updated_at DESC NULLS LAST,
       created_at DESC
     LIMIT $${params.length}`,
    params
  ).catch(() => ({ rows: [] }));

  return (result.rows || []).map(skillRowToProcedure);
}

function buildTraceLinks(reasoningArtifacts, procedures) {
  const links = [];
  for (const artifact of reasoningArtifacts.slice(0, 8)) {
    const artifactText = `${artifact.key} ${artifact.value}`.toLowerCase();
    for (const procedure of procedures.slice(0, 8)) {
      const procedureText = `${procedure.skill_name} ${procedure.trigger_pattern || ''} ${procedure.expected_outcome || ''}`.toLowerCase();
      const sharedTerms = procedureText
        .split(/\W+/)
        .filter((term) => term.length >= 5 && artifactText.includes(term))
        .slice(0, 5);
      if (sharedTerms.length) {
        links.push({
          from: artifact.key,
          to: `procedural_skill:${procedure.skill_name}`,
          edge_type: 'reasoning_to_procedure',
          shared_terms: sharedTerms,
          source_metadata: {
            paper: 'MACLA',
            relation: 'procedure reuse candidate',
          },
        });
      }
    }
  }
  return links.slice(0, 12);
}

export async function retrieveProceduralReasoning({
  queryText = '',
  planner = {},
  companyId,
  agentId,
  clearanceLevel = 10,
  limit = 10,
  dataClassFilter = null,
  queryFn = defaultQuery,
} = {}) {
  const startedAt = Date.now();
  const maxRows = clampLimit(limit);
  const contentHint = contentNeedle(queryText, planner);

  const [reasoningArtifacts, procedures] = await Promise.all([
    readReasoningArtifacts({
      queryFn,
      companyId,
      agentId,
      clearanceLevel,
      contentHint,
      dataClassFilter,
      limit: maxRows,
    }),
    readProceduralSkills({
      queryFn,
      companyId,
      agentId,
      contentHint,
      limit: maxRows,
    }),
  ]);

  const procedureMemories = procedures.map(procedureToMemory);
  const memories = [...reasoningArtifacts, ...procedureMemories].slice(0, maxRows);
  const traceLinks = buildTraceLinks(reasoningArtifacts, procedures);
  const publicMemoryReasoningCards = isSolutionReasoningQuery(queryText, planner)
    ? buildPublicMemoryReasoningCards(reasoningArtifacts, procedures, traceLinks, {
      queryText,
      planner,
      limit: Math.min(maxRows, MEMORY_REASONING_CARD_LIMIT),
    })
    : [];

  return {
    memories,
    reasoning_artifacts: reasoningArtifacts,
    procedure_candidates: procedures,
    trace_links: traceLinks,
    public_memory_reasoning_cards: publicMemoryReasoningCards,
    memory_reasoning_cards: publicMemoryReasoningCards,
    diagnostics: {
      reasoning_artifact_count: reasoningArtifacts.length,
      procedure_candidate_count: procedures.length,
      trace_link_count: traceLinks.length,
      memory_reasoning_card_count: publicMemoryReasoningCards.length,
      content_hint: contentHint || null,
      retrieval_path: 'macla_existing_aimos_tables',
      source_tables: ['aimos_memories', 'procedural_skills'],
      batch8_authority: {
        memcot: {
          paper: MEMORY_REASONING_CARD_AUTHORITY,
          implementation: 'public_memory_reasoning_cards',
          diagnostic_only: true,
        },
      },
      memcot_guardrails: {
        hidden_chain_of_thought_exposed: false,
        raw_private_reasoning_exposed: false,
        ranking_mutated: false,
        memory_order_changed: false,
        deletion_enabled: false,
      },
      guarded_math: {
        expected_utility_selection: false,
        contrastive_refinement: false,
        bayesian_action_selection: false,
        memcot_test_time_scaling_loop: false,
      },
      latency_ms: Date.now() - startedAt,
    },
  };
}
