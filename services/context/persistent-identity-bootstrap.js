/**
 * persistent-identity-bootstrap.js — multi-anchor boot identity envelope
 * Source: Persistent Identity in AI Agents: A Multi-Anchor Architecture for
 * Resilient Memory and Continuity (Menon, arXiv:2604.09588, 2026)
 * Additive Wave 2 authority: Eyla — Toward an Identity-Anchored LLM
 * Architecture with Integrated Biological Priors (Arif, 2026). Eyla is used
 * here for its identity-consistency contract: stable identity anchors load
 * before episodic/session memory, and continuity must survive a fresh model
 * session without relying on an explicit recap.
 * Additive Batch9 Wave6 authority: PHMForge lifecycle benchmarks add
 * diagnostic continuity/readiness checks for HOM Local inheritance. They do not
 * activate inheritance or mutate identity anchors.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: routes/aimos.js /identity/bootstrap
 * 2. → Pulls from: hom-constitution.js, brain-contract.js, aimos_memories
 * 3. ↔ Supports: context-renewal.js and agent-runner.js boot/context assembly
 *
 * LOGIC GUIDE:
 * The paper separates identity from episodic memory and distributes continuity
 * across multiple anchors. This service assembles those anchors from existing
 * Aimos sources. It does not compute behavioral KL divergence, identity hashes,
 * Eyla ICS scoring, HiPPO/SSM memory compression, or mutate auth identity-vault
 * state.
 */

import { query as defaultQuery } from '../../db/connection.js';
import { getHomConstitutionRules } from '../core/hom-constitution.js';
import { buildBrainOperatingMemories } from '../core/brain-contract.js';

const ANCHOR_ORDER = [
  'constitutional',
  'operating_contract',
  'procedural',
  'episodic',
  'salience',
  'social',
];

function truncate(text, max = 700) {
  const value = String(text || '').replace(/\s+/g, ' ').trim();
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function anchorFromMemory(row) {
  const type = String(row.memory_type || '').toLowerCase();
  const key = String(row.key || '').toLowerCase();
  let anchorType = 'episodic';
  if (['identity', 'core_belief', 'crew_identity', 'operational_rule'].includes(type) || key.startsWith('identity:')) {
    anchorType = 'constitutional';
  } else if (['procedural', 'skill', 'tacit_knowledge'].includes(type) || key.includes('procedure')) {
    anchorType = 'procedural';
  } else if (['dream_summary', 'dream_pattern', 'strategic_directive'].includes(type)) {
    anchorType = 'salience';
  } else if (key.includes('handoff') || key.includes('coordination') || key.includes('provider')) {
    anchorType = 'social';
  }

  return {
    anchor_type: anchorType,
    key: row.key,
    memory_type: row.memory_type,
    value: truncate(row.value),
    source: row.source || 'aimos_memories',
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    reliability: {
      source: 'aimos_memory',
      diagnostic_only: true,
    },
  };
}

function staticAnchors() {
  const constitution = getHomConstitutionRules().slice(0, 8).map((rule, index) => ({
    anchor_type: 'constitutional',
    key: `hom_constitution:${index + 1}`,
    memory_type: 'operational_rule',
    value: rule,
    source: 'hom-constitution.js',
    created_at: null,
    updated_at: null,
    reliability: { source: 'runtime_constant', diagnostic_only: true },
  }));

  const contract = buildBrainOperatingMemories().map((memory) => ({
    anchor_type: 'operating_contract',
    key: memory.key,
    memory_type: memory.memoryType,
    value: truncate(memory.value),
    source: 'brain-contract.js',
    created_at: null,
    updated_at: null,
    reliability: { source: 'runtime_constant', diagnostic_only: true },
  }));

  return [...constitution, ...contract];
}

function summarizeAnchors(anchors) {
  const counts = Object.fromEntries(ANCHOR_ORDER.map((anchor) => [anchor, 0]));
  for (const anchor of anchors) {
    if (counts[anchor.anchor_type] == null) counts[anchor.anchor_type] = 0;
    counts[anchor.anchor_type] += 1;
  }
  const presentTypes = Object.entries(counts).filter(([, count]) => count > 0).map(([type]) => type);
  return {
    anchor_types_present: presentTypes,
    anchor_counts: counts,
    resilience_degree: presentTypes.length,
    single_anchor_failure_risk: presentTypes.length <= 1,
    missing_anchor_types: ANCHOR_ORDER.filter((type) => !presentTypes.includes(type)),
  };
}

function classifyContinuityArtifact(row = {}) {
  const key = String(row.key || '').toLowerCase();
  const type = String(row.memory_type || row.memoryType || '').toLowerCase();
  if (key.startsWith('ai_adr:') || type === 'session_reasoning' || type === 'procedural') {
    return 'reasoning_procedure';
  }
  if (type === 'session_debrief' || key.startsWith('session_debrief:')) {
    return 'session_debrief';
  }
  if (type === 'dream_summary' || key.includes('dream')) {
    return 'dream_salience';
  }
  if (type === 'identity' || type === 'core_belief' || key.startsWith('identity:')) {
    return 'identity_anchor';
  }
  return 'episodic_context';
}

function artifactSummary(row = {}) {
  return {
    key: row.key,
    memory_type: row.memory_type || row.memoryType || null,
    continuity_role: classifyContinuityArtifact(row),
    source: row.source || 'aimos_memories',
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    excerpt: truncate(row.value, 420),
  };
}

function artifactText(row = {}) {
  return String([row.key, row.memory_type || row.memoryType, row.value, row.summary, row.excerpt]
    .filter(Boolean)
    .join(' '))
    .toLowerCase();
}

export function buildLifecycleContinuityBenchmarkDiagnostics({
  artifacts = [],
  queryText = 'what changed last week?',
} = {}) {
  const rows = Array.isArray(artifacts) ? artifacts : [];
  const timelineEvidence = rows.filter((row) => row.created_at || row.updated_at || row.date);
  const problemSolutionEvidence = rows.filter((row) => {
    const text = artifactText(row);
    return /(problem|bug|issue|blocked|failure|regression)/.test(text)
      && /(fix|solution|resolved|patched|implemented|proof|test)/.test(text);
  });
  const proofEvidence = rows.filter((row) => /(test|proof|passed|verified|probe|regression)/.test(artifactText(row)));
  const evidenceBacked = timelineEvidence.length > 0 && problemSolutionEvidence.length > 0 && proofEvidence.length > 0;

  return {
    source_papers: [
      'PHMForge: A Scenario-Driven Agentic Benchmark for Industrial Asset Lifecycle Maintenance',
      'Persistent Identity in AI Agents',
      'Eyla: Toward an Identity-Anchored LLM Architecture with Integrated Biological Priors',
    ],
    status: evidenceBacked ? 'lifecycle_evidence_ready' : 'insufficient_lifecycle_evidence',
    diagnostic_only: true,
    query_text: queryText,
    evidence_counts: {
      artifact_count: rows.length,
      timeline_evidence: timelineEvidence.length,
      problem_solution_evidence: problemSolutionEvidence.length,
      proof_evidence: proofEvidence.length,
    },
    answer_contract: {
      answer_from_timeline_evidence: true,
      problem_solution_recall_required: true,
      recent_session_bias_allowed: false,
      raw_database_shortcut_allowed: false,
    },
    hom_local_inheritance: {
      prepared_after_proof: evidenceBacked,
      activated: false,
      requires_aimos_recall_proof: true,
      requires_regression_proof: true,
    },
    aladdin_boundary: {
      canonical_memory_changed: false,
      canonical_memory_removed: false,
      identity_anchor_mutated: false,
    },
  };
}

export function buildEylaContinuityThread({
  bootstrap = null,
  sessionArtifacts = [],
  agentId,
  companyId = 'hom',
} = {}) {
  if (!agentId) throw new Error('buildEylaContinuityThread: agentId is required (no default)');
  const anchors = Array.isArray(bootstrap?.anchors) ? bootstrap.anchors : [];
  const stableAnchors = anchors.filter(anchor =>
    ['constitutional', 'operating_contract', 'procedural'].includes(anchor.anchor_type)
  );
  const relationalAnchors = anchors.filter(anchor =>
    ['social', 'salience'].includes(anchor.anchor_type)
  );
  const episodicAnchors = anchors.filter(anchor => anchor.anchor_type === 'episodic');
  const artifacts = [...sessionArtifacts.map(artifactSummary), ...episodicAnchors.map(artifactSummary)]
    .filter(item => item.key)
    .slice(0, 40);

  const latestArtifact = artifacts
    .slice()
    .sort((a, b) => String(b.updated_at || b.created_at || '').localeCompare(String(a.updated_at || a.created_at || '')))[0] || null;

  const continuityStatus =
    stableAnchors.length >= 2 && artifacts.length > 0
      ? 'reboot_reconstructable'
      : stableAnchors.length >= 2
        ? 'identity_only'
        : 'insufficient_anchors';

  return {
    source_paper: 'Eyla: Toward an Identity-Anchored LLM Architecture with Integrated Biological Priors',
    company_id: companyId,
    agent_id: agentId,
    continuity_status: continuityStatus,
    thread_contract: {
      identity_first_boot: true,
      session_memory_secondary: true,
      explicit_recap_required: false,
      survives_fresh_model_session: stableAnchors.length >= 2,
      canonical_aimos_memory_only: true,
    },
    thread: {
      stable_identity_anchor_count: stableAnchors.length,
      relational_anchor_count: relationalAnchors.length,
      session_artifact_count: artifacts.length,
      latest_artifact: latestArtifact,
      boot_order: [
        'constitutional_identity',
        'operating_contract',
        'procedural_reasoning',
        'recent_session_artifacts',
        'salience_and_social_context',
      ],
      stable_anchor_keys: stableAnchors.slice(0, 12).map(anchor => anchor.key),
      session_artifacts: artifacts,
    },
    failure_modes: {
      no_session_artifacts: artifacts.length === 0,
      weak_identity_anchor_set: stableAnchors.length < 2,
      action: artifacts.length === 0
        ? 'return identity-only boot and ask Aimos recall/session route for continuity evidence'
        : 'continue from latest persisted session artifact',
    },
    guarded_math: {
      identity_consistency_score: false,
      hippo_state_space_compression: false,
      biological_prior_weighting: false,
      kl_identity_drift: false,
    },
    aladdin_boundary: {
      physical_delete_allowed: false,
      canonical_identity_anchors_persistent: true,
      session_artifacts_persistent: true,
    },
  };
}

export async function buildPersistentIdentityBootstrap({
  companyId = 'hom',
  agentId,
  limit = 24,
  queryFn = defaultQuery,
} = {}) {
  if (!agentId) throw new Error('buildPersistentIdentityBootstrap: agentId is required (no default)');
  const maxRows = Math.min(Math.max(Number(limit || 24), 1), 80);
  const params = [companyId, agentId, maxRows];
  const result = await queryFn(
    `SELECT key, value, memory_type, scope, source, created_at, updated_at
     FROM aimos_memories
     WHERE company_id = $1
       AND (
         agent_id = $2
         OR agent_id IS NULL
         OR memory_type IN ('identity', 'core_belief', 'crew_identity', 'operational_rule', 'procedural', 'tacit_knowledge', 'strategic_directive', 'dream_summary')
         OR key LIKE 'identity:%'
         OR key LIKE 'os:hom:%'
       )
     ORDER BY
       CASE
         WHEN memory_type IN ('identity', 'core_belief', 'crew_identity', 'operational_rule') THEN 0
         WHEN memory_type IN ('procedural', 'tacit_knowledge') THEN 1
         WHEN memory_type IN ('dream_summary', 'strategic_directive') THEN 2
         ELSE 3
       END,
       updated_at DESC NULLS LAST,
       created_at DESC NULLS LAST
     LIMIT $3`,
    params
  ).catch(() => ({ rows: [] }));

  const anchors = [...staticAnchors(), ...(result.rows || []).map(anchorFromMemory)];
  const summary = summarizeAnchors(anchors);

  return {
    source_paper: 'Persistent Identity in AI Agents',
    company_id: companyId,
    agent_id: agentId,
    anchors,
    boot_order: ANCHOR_ORDER.filter((type) => summary.anchor_counts[type] > 0),
    summary,
    guarded_math: {
      behavioral_signature_distribution: false,
      kl_identity_continuity: false,
      identity_hash_drift_detection: false,
      eyla_identity_consistency_score: false,
      eyla_hippo_state_space_compression: false,
    },
  };
}
