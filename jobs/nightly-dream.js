/**
 * nightly-dream.js — Offline consolidation and dream artifact production
 *
 * Sources:
 * - Existing dream pipeline sources in `services/dream/*`
 * - `dream-feedback.js`: Senge Fifth Discipline and MemGPT
 * - Aladdin retention: preserve value; adjust salience, never erase value
 *
 * Priority TEM relation:
 * Dream transparency is an additive visibility layer. It exposes structured
 * nightly outputs for recall/inspect without changing dream scoring,
 * consolidation thresholds, or STDP-like evidence updates.
 */
import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import { createHash } from 'node:crypto';
import { query, withTransaction } from '../db/connection.js';
import { getEmbedding } from '../services/core/embeddings.js';
import { logEvent } from '../services/observe/event-ledger.js';
import { persistMemory } from '../services/write/persist-memory.js';
import { runDreamConsolidation } from '../services/dream/spiced-consolidator.js';
import { scoreDueRecommendations, curateSkillsFromSuccesses, computeForwardTransfer, computeBackwardTransfer, computePerformanceMaintenance } from '../services/learning/agent-learning.js';
import {
  formatRetrievalDriftSummary,
  recordRetrievalDriftSnapshot,
} from '../services/observe/retrieval-drift-monitor.js';
import { computeSurprise, getAnisotropyStats } from '../services/retrieval/similarity-stats.js';
import { auditSupersessionChains } from '../services/temporal/temporal-resolver.js';
import { replayFailuresBatch, generateAntiSkill } from '../services/learning/failure-replay.js';
import { runErrorNormalizationCycle } from '../services/learning/error-normalizer.js';
import { clusterSimilarSkills, extractAbstraction, promoteProvisionalSkill, flagRedundantSkills } from '../services/learning/skill-consolidation.js';
import { runDeltaPipeline } from '../services/dream/delta-writer.js';
import { loadDreamConstraints } from '../services/dream/dream-feedback.js';
import { getNextReviewBatch, scheduleRepetition } from '../services/learning/spaced-repetition.js';
import { detectMasteryParadox } from '../services/observe/mastery-paradox-detector.js';
import { runEntanglementAutonomyAudit } from '../services/observe/entanglement-monitor.js';
import { runSVDDMemoryIntegrityCheck } from '../services/observe/svdd-anomaly.js';
import { runTemporalFingerprintAudit } from '../services/temporal/temporal-fingerprinter.js';
import { analyzeTopicCoverage, runTopicBudgetAudit } from '../services/temporal/topic-budget.js';
import { runEmbeddingStabilityAudit } from '../services/retrieval/embedding-stability.js';
import { runCalibrationUpdate } from '../services/retrieval/recall-calibrator.js';
import { canonicalJson } from '../services/security/agent-identity.js';
import { runHebbianConsensusBatch, HEBBIAN_CONSTANTS } from '../services/dream/hebbian-consensus.js';
import { governorConfigLedger } from '../services/governance/governor-config-ledger.js';

// ─── ALADDIN RETENTION: No tiering, no expiry, no promotion, no pruning. ─────
// Everything is long-term from the moment it's saved. Storage is cheap.
// Retrieval quality is the bottleneck, not storage cost.
// BlackRock keeps everything. So do we.
//
// Dream transparency artifact persistence is additive. It exposes nightly
// outputs without changing dream scoring or consolidation thresholds. Dream
// feedback remains governed by Senge and MemGPT.

// ─── PARALLELISM HELPER ──────────────────────────────────────────────────────
// Bounded-concurrency map. Architecture-authority promises parallel LLM calls
// for dream stages; this enforces it while capping concurrent provider calls.
async function pMap(items, worker, concurrency = 8) {
  const results = new Array(items.length);
  let cursor = 0;
  async function pump() {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      try { results[i] = await worker(items[i], i); }
      catch (err) { results[i] = { __error: err.message }; }
    }
  }
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, pump);
  await Promise.all(runners);
  return results;
}

// ─── FELIX HEALTH LOOP ───────────────────────────────────────────────────────
// Collect today's memories across all activity types, render a bullet recap,
// identify blockers, and save a proper dream_summary to Aimos.
// Fix 2026-03-31: was only pulling event_log — missed session_exchange,
// procedural, and declarative memories entirely. Dreams were blind to
// everything the duplicate brain and session hooks produced.
// Fix 2026-04-05: added session_debrief — PreCompact saves conversation feeds
// to this type before compaction; dreams must process them.
// Bound (defect 9): under a never-delete retention law an unbounded
// SELECT … ORDER BY created_at loads the entire day's history into memory and
// is a likely cause of the 512MB heap warning heartbeat.js already emits. Cap to
// the most-recent DREAM_DAY_EVENT_LIMIT rows (default 10000) while preserving
// chronological (ASC) order for downstream bullet rendering.
const DAY_EVENT_LIMIT = 10_000;

async function insertDreamSummaryLayer({
  companyId,
  dreamDate,
  layer,
  parentLayerId = null,
  summary,
  embedding,
  theme,
  eventCount,
  metadata = {},
}) {
  const snapshot = {
    company_id: companyId,
    dream_date: dreamDate,
    layer: Number(layer),
    parent_layer_id: parentLayerId == null ? null : Number(parentLayerId),
    summary: String(summary),
    theme: theme == null ? null : String(theme),
    event_count: Number(eventCount || 0),
    metadata,
  };
  const contentHash = createHash('sha256')
    .update(Buffer.from(canonicalJson(snapshot), 'utf8'))
    .digest();
  return withTransaction(async (client) => {
    const authority = await logEvent(companyId, 'housekeeper', 'dream_summary_layer_created', `dream:${dreamDate}:layer:${layer}`, {
      dream_date: dreamDate,
      layer: Number(layer),
      parent_layer_id: parentLayerId == null ? null : Number(parentLayerId),
      theme: snapshot.theme,
      event_count: snapshot.event_count,
      content_hash: contentHash.toString('hex'),
      reasoning: 'The housekeeper retained one deterministic dream hierarchy layer and signed its complete canonical snapshot hash in the same transaction.',
      source_knowledge: 'nightly-dream.js — algorithmic three-layer retained dream hierarchy',
    }, null, { client, returnReceipt: true });
    const inserted = await client.query(
      `INSERT INTO dream_summary_layers
         (company_id, dream_date, layer, parent_layer_id, summary, embedding,
          theme, event_count, metadata, content_hash, authority_event_id)
       VALUES ($1,$2,$3,$4,$5,$6::vector,$7,$8,$9,$10,$11)
       RETURNING id`,
      [
        companyId, dreamDate, Number(layer), parentLayerId, summary,
        embedding ? JSON.stringify(embedding) : null, theme, Number(eventCount || 0),
        JSON.stringify(metadata), contentHash, authority.event_id,
      ]
    );
    return inserted.rows[0].id;
  }, { restricted: true, client_id: companyId, agent_id: 'housekeeper' });
}

async function collectDayEvents(companyId, since) {
  const result = await query(
    `SELECT key, value, created_at, memory_type FROM (
       SELECT key, value, created_at, memory_type
       FROM aimos_memories
       WHERE company_id = $1
         AND memory_type IN ('event_log', 'session_exchange', 'procedural', 'declarative', 'session_debrief')
         AND created_at >= $2
       ORDER BY created_at DESC
       LIMIT $3
     ) sub
     ORDER BY created_at ASC`,
    [companyId, since, DAY_EVENT_LIMIT]
  );
  return result.rows;
}

async function detectLoggingGap(companyId, since) {
  const result = await query(
    `SELECT COUNT(*) as total FROM aimos_memories
     WHERE company_id = $1
       AND memory_type NOT IN ('event_log', 'session_exchange', 'procedural', 'declarative', 'session_debrief', 'dream_summary', 'dream_pattern')
       AND created_at >= $2`,
    [companyId, since]
  );
  return parseInt(result.rows[0]?.total || '0', 10);
}

function identifyBlockers(events) {
  const blockerKeywords = ['failed', 'error', 'blocked', 'crash', 'missing', 'timeout', 'not found'];
  return events.filter((e) => {
    const lower = String(e.value || '').toLowerCase();
    return blockerKeywords.some((kw) => lower.includes(kw));
  });
}

function renderEventBullets(events) {
  if (!events.length) return '  (no events logged today)';
  return events.map((e) => {
    // value is already a bullet string like "• HH:MM — [action] summary"
    // Emit as-is or fall back to key + created_at
    const v = String(e.value || e.key || '');
    return v.startsWith('•') ? v : `• ${new Date(e.created_at).toISOString().slice(11, 16)} — ${v}`;
  }).join('\n');
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Event Deduplication ──────────────────────────────────────────────────────
// Consecutive identical or near-identical events (e.g., heartbeat errors) are
// collapsed into a single representative + count. This prevents noise from
// drowning real signal in the dream's hierarchical summarization.
function deduplicateEvents(events) {
  if (events.length < 2) return events;
  const deduped = [];
  let i = 0;
  while (i < events.length) {
    const current = events[i];
    const currentVal = String(current.value || '').slice(0, 150);
    let count = 1;
    let j = i + 1;
    while (j < events.length) {
      const nextVal = String(events[j].value || '').slice(0, 150);
      if (nextVal === currentVal) {
        count++;
        j++;
      } else {
        break;
      }
    }
    if (count > 1) {
      deduped.push({
        ...current,
        value: `${String(current.value || '')} [×${count} repeated]`
      });
    } else {
      deduped.push(current);
    }
    i = j;
  }
  return deduped;
}

// ─── Senge Reflection: Five Disciplines analysis of today's events ──────────
// Source: The Fifth Discipline (Peter Senge, 1990) — ingested into Aimos as
// book:books:01_fifth_discipline_senge. The five disciplines operate as an
// integrated whole: removing any one breaks the learning system.
function runSengeReflection(events, blockers) {
  const allText = events.map((e) => String(e.value || '')).join('\n').toLowerCase();
  const lines = [];

  lines.push('SENGE FIVE DISCIPLINES REFLECTION:');
  lines.push('');

  // 1. Systems Thinking — did we see feedback loops or act linearly?
  const hasRevert = allText.includes('revert') || allText.includes('reverted');
  const hasRepeat = allText.includes('again') || allText.includes('same issue') || allText.includes('still');
  const feedbackLoops = hasRevert || hasRepeat;
  lines.push('  1. SYSTEMS THINKING (circular cause-effect, not linear):');
  if (feedbackLoops) {
    lines.push('     ⚠️ Feedback loop detected — reverts or repeated issues suggest actions are not considering downstream effects.');
    lines.push('     Ask: What is the delay between action and consequence that we are not seeing?');
  } else if (blockers.length > 0) {
    lines.push('     ⚠️ Blockers present — are these symptoms of a deeper systemic issue or isolated failures?');
  } else {
    lines.push('     ✓ No obvious feedback loops detected today.');
  }
  lines.push('');

  // 2. Personal Mastery — gap between what we know and what we do
  const hasRush = allText.includes('rush') || allText.includes('bypass') || allText.includes('skip');
  const hasShallow = allText.includes('headline') || allText.includes('shallow');
  const masteryGap = hasRush || hasShallow;
  lines.push('  2. PERSONAL MASTERY (gap between vision and current reality):');
  if (masteryGap) {
    lines.push('     ⚠️ Mastery gap detected — rushing or shallow execution suggests acting on instinct over discipline.');
    lines.push('     Ask: Where did we know the right thing to do but chose speed instead?');
  } else {
    lines.push('     ✓ No obvious mastery gaps detected today.');
  }
  lines.push('');

  // 3. Mental Models — were assumptions examined or acted on blindly?
  const hasAssumption = allText.includes('assumed') || allText.includes('thought it was') || allText.includes('turned out');
  const hasCorrection = allText.includes('correction') || allText.includes('actually') || allText.includes('was wrong');
  const unexaminedModels = hasAssumption || hasCorrection;
  lines.push('  3. MENTAL MODELS (examine assumptions driving action):');
  if (unexaminedModels) {
    lines.push('     ⚠️ Assumption surfaced — a correction or surprise suggests an unexamined mental model was driving action.');
    lines.push('     Ask: What did we assume was true that turned out to be false?');
  } else {
    lines.push('     ✓ No unexamined assumptions surfaced today.');
  }
  lines.push('');

  // 4. Shared Vision — were actions aligned with the grand directive?
  const hasDirective = allText.includes('directive') || allText.includes('grand') || allText.includes('revenue') || allText.includes('client');
  const hasDetour = allText.includes('detour') || allText.includes('rabbit hole') || allText.includes('side track');
  lines.push('  4. SHARED VISION (alignment with grand directive):');
  if (hasDetour) {
    lines.push('     ⚠️ Possible detour from grand directive detected.');
    lines.push('     Ask: Did today\'s work move us closer to revenue and autonomy, or was it maintenance?');
  } else if (hasDirective) {
    lines.push('     ✓ Actions appear aligned with grand directive (revenue/clients/autonomy referenced).');
  } else {
    lines.push('     ⚠️ No reference to grand directive in today\'s events. Were actions aligned?');
  }
  lines.push('');

  // 5. Team Learning — what did the operator and agent learn together?
  const hasLesson = allText.includes('learned') || allText.includes('lesson') || allText.includes('insight')
    || allText.includes('feedback') || allText.includes('revert');
  lines.push('  5. TEAM LEARNING (what did we learn together today?):');
  if (hasLesson) {
    lines.push('     ✓ Learning signals detected — feedback, corrections, or shared insights logged.');
    lines.push('     Carry forward: What specifically changed in how we work together?');
  } else {
    lines.push('     ⚠️ No team learning signals detected. Were insights captured or lost?');
  }
  lines.push('');

  // Event quality assessment
  const eventLengths = events.map((e) => String(e.value || '').length);
  const avgLength = eventLengths.length ? Math.round(eventLengths.reduce((a, b) => a + b, 0) / eventLengths.length) : 0;
  const shortEvents = eventLengths.filter((l) => l < 100).length;
  const richEvents = eventLengths.filter((l) => l > 500).length;
  const hasReasoning = events.filter((e) => /reasoning|because|root cause|why/i.test(String(e.value || ''))).length;

  lines.push('  EVENT QUALITY:');
  lines.push(`     Total events: ${events.length} | Avg length: ${avgLength} chars`);
  lines.push(`     Short (<100 chars): ${shortEvents} | Rich (>500 chars): ${richEvents} | With reasoning: ${hasReasoning}`);
  if (shortEvents > events.length * 0.5) {
    lines.push('     ⚠️ More than half of events are short headlines. Substance is being lost.');
  }
  if (hasReasoning < events.length * 0.2 && events.length > 3) {
    lines.push('     ⚠️ Less than 20% of events carry reasoning traces. WHY is missing from the record.');
  }

  return lines.join('\n');
}

// ─── Garbage Filter: Remove double-encoded delta:insight entries ─────────────
// The dream previously created garbage delta:insight entries that are just
// JSON-wrapped copies of existing data (triple-nested JSON). These drown out
// real reasoning. Filter them out before hierarchical summarization.
function isGarbageInsight(value) {
  const text = String(value || '');
  // Pattern 1: Double-encoded JSON insight wrapping pre-compact feed
  if (text.includes('"category":"insight"') && text.includes('"content":"')) {
    return true;
  }
  // Pattern 2: Insight wrapping another insight (recursive encoding)
  if (text.includes('"category":"insight"') && text.includes('\\\"category\\\":\\\"insight\\\"')) {
    return true;
  }
  // Pattern 3: Insight with only a title and no substance
  if (text.includes('"category":"insight"') && text.length < 200) {
    return true;
  }
  return false;
}

function filterGarbageEvents(events) {
  const filtered = events.filter(e => !isGarbageInsight(e.value));
  const removed = events.length - filtered.length;
  if (removed > 0) {
    console.log(`[dream] Filtered ${removed} garbage delta:insight entries (${events.length} → ${filtered.length})`);
  }
  return filtered;
}

// ─── Reasoning Passthrough: Detect structured reasoning content ──────────────
// Pre-compact feeds and reasoning deltas already contain structured reasoning.
// The LLM summarizer destroys this. If content is already structured, pass
// it through directly instead of asking a compact model to summarize it.
const REASONING_MARKERS = [
  '[PROBLEM]', '[ROOT_CAUSE]', '[DECISION]', '[ALADDIN_LOCK]',
  'PRE-COMPACT FEED', 'PRE-COMPACT REASONING',
  '### Exchange', '**OPERATOR:**', '**REVIEWER:**',
  'USER:', 'ASSISTANT:',
  'root cause', 'fixed by', 'breakthrough',
];

function hasStructuredReasoning(text) {
  const lower = text.toLowerCase();
  return REASONING_MARKERS.some(marker => lower.includes(marker.toLowerCase()));
}

// ─── Quality Gate: Validate LLM output before accepting ─────────────────────
// Haiku often returns empty or generic output ("Cluster of N summaries").
// If the output is garbage, use the original input instead.
function isGarbageOutput(output, originalInput) {
  if (!output || output.length < 20) return true;
  if (output.startsWith('Cluster of') && output.includes('summaries')) return true;
  if (output.startsWith('Day summary:') && output.length < 50) return true;
  if (output === originalInput) return false; // passthrough is fine
  // If output is shorter than 30% of input and input had reasoning, it's garbage
  if (hasStructuredReasoning(originalInput) && output.length < originalInput.length * 0.3) return true;
  return false;
}

// ─── Feature 1: Hierarchical Summarization (3-layer dream, NO LLM) ──────────
// Pass 1: Group events by hour, extract reasoning algorithmically
// Pass 2: Embed pass-1 summaries, cluster by cosine similarity > 0.7, theme each cluster
// Pass 3: Algorithmic meta-analysis — decisions, patterns, recurring themes
// Store all 3 layers; layer 3 also saved as aimos_memories type dream_pattern.
// Only runs if >= 5 events; degrades gracefully to single-pass on failure.
// NO LLM calls — all algorithmic, model-agnostic.
async function runHierarchicalSummarization(companyId, events, dreamDate) {
  if (events.length < 5) return { layers: 0, reason: 'insufficient_events' };

  // Step 1: Filter garbage delta:insight entries (double-encoded JSON)
  const cleanEvents = filterGarbageEvents(events);

  // Step 2: Deduplicate — heartbeat noise kills reasoning
  const dedupedEvents = deduplicateEvents(cleanEvents);
  console.log(`[dream] ${events.length} raw → ${cleanEvents.length} clean → ${dedupedEvents.length} after dedup`);

  const results = { layer1: 0, layer2: 0, layer3: 0 };

  try {
    const schema = await query(
      `SELECT ARRAY(
         SELECT required.column_name
           FROM unnest(ARRAY[
             'id','company_id','dream_date','layer','parent_layer_id','summary',
             'embedding','theme','event_count','metadata','content_hash',
             'authority_event_id','created_at'
           ]) AS required(column_name)
          WHERE NOT EXISTS (
            SELECT 1 FROM information_schema.columns actual
             WHERE actual.table_schema = current_schema()
               AND actual.table_name = 'dream_summary_layers'
               AND actual.column_name = required.column_name
          )
       ) AS missing_columns`,
    );
    if (schema.rows[0]?.missing_columns?.length) {
      const error = new Error(`MIGRATION_SCHEMA_MISSING:dream_summary_layers:${schema.rows[0].missing_columns.join(',')}`);
      error.code = 'MIGRATION_SCHEMA_MISSING';
      throw error;
    }

    // ALADDIN: kernel hard-blocks DELETE. Each run's INSERTs carry their fresh
    // ids forward and downstream SELECTs filter by those ids so older same-day
    // rows (from prior reruns) are ignored, not destroyed.

    // ─── PASS 1: Group by hour, extract reasoning algorithmically ────────────
    // NO LLM calls. Extract structured reasoning directly from pre-compact feeds
    // and event logs. If content has reasoning markers, pass through as-is.
      const hourGroups = {};
      for (const event of dedupedEvents) {
      const hour = new Date(event.created_at).toISOString().slice(11, 13);
        if (!hourGroups[hour]) hourGroups[hour] = [];
      hourGroups[hour].push(event);
    }

      const layer1Ids = [];
      const layer1Tasks = Object.entries(hourGroups).map(async ([hour, group]) => {
        // Check if any event in this hour has structured reasoning
        const reasoningEvents = group.filter(e => hasStructuredReasoning(e.value));
        let summary;

        if (reasoningEvents.length > 0) {
          // PASS THROUGH: Already structured reasoning — don't destroy it
        summary = reasoningEvents.map(e => String(e.value || '').slice(0, 2000)).join('\n\n');
      } else {
          // Algorithmic summary: extract key facts without LLM
        const bullets = group.map(e => {
            const v = String(e.value || e.key || '');
            return v.startsWith('•') ? v : `• ${new Date(e.created_at).toISOString().slice(11, 16)} — ${v.slice(0, 200)}`;
        });
          summary = bullets.join('\n');
      }

      const embedding = await getEmbedding(summary);
        return insertDreamSummaryLayer({
          companyId,
          dreamDate,
          layer: 1,
          summary,
          embedding,
          theme: `Hour ${hour}`,
          eventCount: group.length,
          metadata: { hour },
        });
    });

      const layer1Results = await Promise.all(layer1Tasks);
      layer1Ids.push(...layer1Results);
      results.layer1 = layer1Ids.length;

    if (layer1Ids.length === 0) return { layers: 0, reason: 'no_layer1_summaries' };

    // ─── PASS 2: Cluster layer-1 summaries by cosine similarity > 0.7 ────────
    // Filter strictly by this run's freshly-inserted ids; prior same-day rows
    // (Aladdin keeps them) are intentionally ignored.
    const layer1Rows = await query(
        `SELECT id, summary, embedding, theme FROM dream_summary_layers
         WHERE company_id = $1 AND id = ANY($2::int[])
         ORDER BY id`,
      [companyId, layer1Ids]
      );

      // Greedy clustering — but the similarity matrix is computed in ONE
      // set-based query instead of the former O(n²) per-pair round-trips
      // (defect 8). The `a.id < b.id` join predicate halves the work and drops
      // self-pairs; the DB filters to sim > 0.7 so only real edges cross the
      // wire. We then reconstruct the original greedy semantics (seed row + all
      // still-unclustered rows similar to that seed) from an in-memory adjacency
      // map — zero further DB calls.
      const SIM_THRESHOLD = 0.7;
      const adjacency = new Map(); // id -> Set(neighbourId) with sim > threshold
      const rowIds = layer1Rows.rows.filter(r => r.embedding).map(r => r.id);
      if (rowIds.length > 1) {
        try {
          const simPairs = await query(
            `SELECT a.id AS a_id, b.id AS b_id
               FROM dream_summary_layers a
               JOIN dream_summary_layers b ON a.id < b.id
              WHERE a.company_id = $1 AND b.company_id = $1
                AND a.id = ANY($2::int[]) AND b.id = ANY($2::int[])
                AND a.embedding IS NOT NULL AND b.embedding IS NOT NULL
                AND 1 - (a.embedding <=> b.embedding) > $3`,
            [companyId, rowIds, SIM_THRESHOLD]
          );
          for (const pair of simPairs.rows) {
            if (!adjacency.has(pair.a_id)) adjacency.set(pair.a_id, new Set());
            if (!adjacency.has(pair.b_id)) adjacency.set(pair.b_id, new Set());
            adjacency.get(pair.a_id).add(pair.b_id);
            adjacency.get(pair.b_id).add(pair.a_id);
          }
        } catch (err) {
          console.error('[dream-L2] Set-based similarity query failed:', err.message?.slice(0, 120));
        }
      }

      const clustered = new Set();
      const clusters = [];
      for (const row of layer1Rows.rows) {
        if (clustered.has(row.id)) continue;
        const cluster = [row];
        clustered.add(row.id);
        const neighbours = adjacency.get(row.id);
        if (neighbours) {
          for (const other of layer1Rows.rows) {
            if (clustered.has(other.id) || !other.embedding) continue;
            if (neighbours.has(other.id)) {
              cluster.push(other);
              clustered.add(other.id);
            }
          }
        }
        clusters.push(cluster);
      }

      const layer2Ids = [];
      const layer2Tasks = clusters.map(async (cluster) => {
      // Algorithmic theme extraction — no LLM
      const clusterText = cluster.map(c => c.summary).join('\n');
      let theme;

      // Detect theme from content patterns
        if (clusterText.includes('[PROBLEM]') || clusterText.includes('root cause')) {
          theme = 'Problem Solving & Debugging';
        } else if (clusterText.includes('[DECISION]') || clusterText.includes('decided')) {
        theme = 'Architectural Decisions';
        } else if (clusterText.includes('PRE-COMPACT') || clusterText.includes('reasoning')) {
          theme = 'Session Reasoning & Continuity';
      } else if (clusterText.includes('error') || clusterText.includes('failed')) {
          theme = 'Error Analysis & Recovery';
      } else if (clusterText.includes('deploy') || clusterText.includes('implement')) {
          theme = 'Implementation & Deployment';
        } else {
          theme = `Cluster of ${cluster.length} related events`;
      }

        const clusterSummary = `Theme: ${theme}\n${cluster.map(c => `- ${c.summary.slice(0, 200)}`).join('\n')}`;
      const embedding = await getEmbedding(clusterSummary);
        const parentId = cluster[0].id;
        return insertDreamSummaryLayer({
          companyId,
          dreamDate,
          layer: 2,
          parentLayerId: parentId,
          summary: clusterSummary,
          embedding,
          theme,
          eventCount: cluster.length,
          metadata: { cluster_ids: cluster.map(c => c.id) },
        });
      });

      const layer2Results = await Promise.all(layer2Tasks);
      layer2Ids.push(...layer2Results);
      results.layer2 = layer2Ids.length;

      // ─── PASS 3: Extract decisions, patterns, recurring themes ───────────────
      if (layer2Ids.length > 0) {
      const layer2Rows = await query(
          `SELECT id, summary, theme FROM dream_summary_layers
           WHERE company_id = $1 AND id = ANY($2::int[])
           ORDER BY id`,
          [companyId, layer2Ids]
        );

      // Algorithmic meta-analysis — no LLM
      const themes = layer2Rows.rows.map(r => r.theme);
      const allSummaries = layer2Rows.rows.map(r => r.summary).join('\n\n');

      // Count reasoning signals
      const reasoningCount = (allSummaries.match(/\[PROBLEM\]|\[ROOT_CAUSE\]|\[DECISION\]|\[ALADDIN_LOCK\]/g) || []).length;
      const errorCount = (allSummaries.match(/error|failed|blocked/gi) || []).length;
      const decisionCount = (allSummaries.match(/\[DECISION\]|decided|deploy/gi) || []).length;

        const metaSummary = [
        `NIGHTLY DREAM META-ANALYSIS — ${dreamDate}`,
          ``,
          `THEMES IDENTIFIED: ${themes.join(', ')}`,
        ``,
          `REASONING SIGNALS: ${reasoningCount} structured reasoning entries preserved`,
        `ERRORS/FAILURES: ${errorCount} issues detected`,
          `DECISIONS: ${decisionCount} architectural or operational decisions`,
          ``,
        `KEY INSIGHTS:`,
          ...themes.map(t => `- ${t}`),
          ``,
          `RECOMMENDATION: ${reasoningCount > 0 ? 'Reasoning pipeline is healthy. Pre-compact feeds preserved.' : 'No structured reasoning detected. Check pre-compact hook.'}`,
        ].join('\n');

        const embedding = await getEmbedding(metaSummary);
      await insertDreamSummaryLayer({
        companyId,
        dreamDate,
        layer: 3,
        parentLayerId: layer2Ids[0],
        summary: metaSummary,
        embedding,
        theme: 'Meta-analysis',
        eventCount: events.length,
        metadata: { layer2_ids: layer2Ids },
      });
      results.layer3 = 1;

      // Save layer 3 as dream_pattern in aimos_memories
      // Aladdin law: append a new retained version; the prior version remains
      // addressable through the explicit supersession topology.
      const patternKey = `dream_pattern:${dreamDate}`;
      await persistMemory({
        company_id: companyId,
        agent_id: 'housekeeper',
        key: patternKey,
        value: metaSummary,
        scope: 'system',
        memory_type: 'dream_pattern',
        clearance_level: 5,
        source: 'nightly-dream',
        mutation_authority: 'housekeeper',
      });
    }

    return { layers: results.layer1 + results.layer2 + results.layer3, ...results };
  } catch (err) {
    console.error('[dream-hierarchical] Error:', err.message);
    return { layers: 0, error: err.message };
  }
}

// ─── DREAM CONSOLIDATION V2 ─────────────────────────────────────────────────
// Replaces dead runTierMaintenance(). All Aladdin-compatible: keep everything,
// improve what surfaces. Source: D-MEM + EMoT + ToM (Batch 2 research).

/**
 * Stage 1: Utility diagnostics — classify today's memories without changing
 * their recall eligibility. The complete result is signed in the event ledger.
 */
async function runUtilityScoring(companyId, since) {
  let scored = 0;
  try {
    const classifications = [];
    const unscored = await query(
      `SELECT id, value, memory_type FROM aimos_memories
       WHERE company_id = $1 AND created_at >= $2
       LIMIT 200`,
      [companyId, since]
    );

    for (const row of unscored.rows) {
      const text = String(row.value || '').toLowerCase();
      const len = text.length;

      // Heuristic utility classification (avoids LLM call for speed)
      let utility = 0.5; // default: short_term
      // Transient: phatic, very short, status-only
      if (len < 50 || /^(ok|done|yes|no|got it|thanks|acknowledged)/i.test(text)) {
        utility = 0.2;
      }
      // Persistent: decisions, corrections, strategic, procedural, session_debrief
      else if (row.memory_type === 'procedural' || row.memory_type === 'strategic_directive' || row.memory_type === 'session_debrief') {
        utility = 0.9;
      } else if (/\b(decision|decided|correction|strategy|architecture|always|never|rule|policy)\b/.test(text)) {
        utility = 0.85;
      } else if (/\b(learned|lesson|insight|pattern|root cause|because)\b/.test(text)) {
        utility = 0.75;
      }
      // Short-term: event logs, status updates
      else if (row.memory_type === 'event_log' && len < 200) {
        utility = 0.35;
      }

      classifications.push({ memory_id: row.id, utility });
      scored++;
    }
    if (classifications.length) {
      await logEvent(companyId, 'housekeeper', 'memory_utility_diagnostics', `dream:${new Date(since).toISOString()}`, {
        classifications,
        canonical_memory_changed: false,
        recall_eligibility_changed: false,
        reasoning: 'Housekeeper classified memory utility for observation only; Aladdin law forbids lowering memory eligibility.',
        source_knowledge: 'nightly-dream.js evidence-based utility diagnostics',
      });
    }
  } catch (err) {
    console.warn('[dream-v2] utility scoring error:', err.message);
  }
  return { scored };
}

/**
 * Stage 2: Evidence Pattern Analysis — identify unreferenced and high-value memories.
 * Trust is driven by usage, graph evidence, and credit; age is not a term.
 */
async function runAccessPatternAnalysis(companyId) {
  let orphans = 0;
  let trustScored = 0;
  try {
    // Find memories with no usage evidence. Age is deliberately irrelevant.
    const orphanResult = await query(
      `SELECT COUNT(*) as count FROM aimos_memories
       WHERE company_id = $1
         AND COALESCE(access_count, 0) = 0`,
      [companyId]
    );
    orphans = parseInt(orphanResult.rows[0]?.count || '0', 10);

    // Compute evidence-derived trust diagnostics without mutating memory rows.
    const untrusted = await query(
      `SELECT id, access_count, credit_score,
              (SELECT COUNT(*) FROM memory_cross_refs WHERE source_memory_id = om.id AND company_id = $1) as cross_ref_count
       FROM aimos_memories om
       WHERE company_id = $1
       LIMIT 500`,
      [companyId]
    );

    // Get max values for normalization
    const maxAccess = await query(
      `SELECT MAX(access_count) as max_dw FROM aimos_memories WHERE company_id = $1`,
      [companyId]
    );
    const maxDW = parseFloat(maxAccess.rows[0]?.max_dw || '2');
    const maxRefs = 10; // reasonable cap
    const diagnostics = [];
    for (const row of untrusted.rows) {
      const accessFreq = Math.min(1, (Number(row.access_count) || 0) / Math.max(maxDW, 1));
      const crossRefs = Math.min(1, (parseInt(row.cross_ref_count, 10) || 0) / maxRefs);
      const credit = Math.min(1, (parseFloat(row.credit_score) || 1.0) / 2);

      const trustScore = 0.45 * accessFreq + 0.30 * crossRefs + 0.25 * credit;

      diagnostics.push({ memory_id: row.id, trust_score: Number(trustScore.toFixed(6)) });
      trustScored++;
    }
    if (diagnostics.length) {
      await logEvent(companyId, 'housekeeper', 'memory_trust_diagnostics', 'dream:access-patterns', {
        diagnostics,
        canonical_memory_changed: false,
        recall_eligibility_changed: false,
        reasoning: 'Housekeeper measured evidence strength without mutating or suppressing canonical memories.',
        source_knowledge: 'nightly-dream.js evidence-pattern diagnostics',
      });
    }
  } catch (err) {
    console.warn('[dream-v2] access pattern error:', err.message);
  }
  return { orphans, trustScored };
}

/**
 * Stage 4: Supersession Chain Audit — verify chain integrity.
 */
async function runSupersessionAudit(companyId) {
  try {
    return await auditSupersessionChains(companyId);
  } catch (err) {
    console.warn('[dream-v2] supersession audit error:', err.message);
    return { intact: 0, broken: [] };
  }
}

export async function runNightlyDream(companyId = AIMOS_COMPANY_ID) {

  // Score expired recommendations — grades past predictions against actual agent performance
  let scoreResult = { scored: 0 };
  try { scoreResult = await scoreDueRecommendations(); } catch (e) { scoreResult = { scored: 0, error: e.message }; }

  // ─── Feature 7: Autonomous Skill Curation (Ameisen Loop) ──────────────────
  let curationResult = { curated: 0 };
  try { curationResult = await curateSkillsFromSuccesses(companyId); } catch (e) { curationResult = { curated: 0, error: e.message }; }

  let retrievalDrift = null;
  try {
    retrievalDrift = await recordRetrievalDriftSnapshot(companyId);
  } catch (e) {
    retrievalDrift = { status: 'critical', reasons: [`monitor_failed:${e.message}`] };
  }

  const now = new Date();
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  // ─── FELIX: collect real events instead of empty task_summary count ────────
  const events = await collectDayEvents(companyId, since);
  const gapCount = await detectLoggingGap(companyId, since);
  const blockers = identifyBlockers(events);
  const bulletList = renderEventBullets(events);
  const blockerList = blockers.length
    ? blockers.map((b) => `  ⚠️ ${String(b.value || b.key).split('\n')[0]}`).join('\n')
    : '  (none)';

  // Determine "what to pick up tomorrow" from the most recent non-blocker event's `next:` field
  const nextItems = events
    .map((e) => {
      const match = String(e.value || '').match(/next:\s*(.+)/);
      return match ? match[1].trim() : null;
    })
    .filter(Boolean);
  const nextSection = nextItems.length ? nextItems.map((n) => `  → ${n}`).join('\n') : '  (nothing queued)';

  // ─── Feature 1: Hierarchical Summarization ──────────────────────────────────
  const dreamDate = now.toISOString().slice(0, 10);
  let hierarchicalResult = { layers: 0 };
  try { hierarchicalResult = await runHierarchicalSummarization(companyId, events, dreamDate); } catch (e) { hierarchicalResult = { layers: 0, error: e.message }; }

  // ─── DREAM CONSOLIDATION V2: Retrieval quality reasoning (Batch 2) ────────
  // Stage 1: Utility Scoring (D-MEM)
  let utilityResult = { scored: 0 };
  try { utilityResult = await runUtilityScoring(companyId, since); } catch (e) { utilityResult = { scored: 0, error: e.message }; }

  // Stage 2: Access Pattern Analysis (EMoT)
  let accessResult = { orphans: 0, trustScored: 0 };
  try { accessResult = await runAccessPatternAnalysis(companyId); } catch (e) { accessResult = { orphans: 0, trustScored: 0, error: e.message }; }

  // Stage 4: Supersession Chain Audit (ToM)
  let supersessionResult = { intact: 0, broken: [] };
  try { supersessionResult = await runSupersessionAudit(companyId); } catch (e) { supersessionResult = { intact: 0, broken: [], error: e.message }; }

  // Stage 5: Retrieval Quality Check (existing — retrieval drift monitor)

  // --- Stage 6: Failure Replay ---
  let failureReplayResult = { clusters: 0, antiSkills: 0 };
  try {
    const failureClusters = await replayFailuresBatch(companyId, since.toISOString());
    let antiSkillsSaved = 0;
    for (const cluster of failureClusters) {
      const asResult = await generateAntiSkill(cluster, companyId);
      if (asResult.saved) antiSkillsSaved++;
    }
    const errorNormalizer = await runErrorNormalizationCycle(failureClusters, companyId, {
      agentId: 'housekeeper',
      eventKey: `error-normalizer:${dreamDate}`,
    });
    failureReplayResult = { clusters: failureClusters.length, antiSkills: antiSkillsSaved, errorNormalizer };
    console.log('[dream] Stage 6 result:', failureReplayResult);
  } catch (err) {
    console.warn('[dream] Stage 6 (failure-replay) failed:', err.message);
  }

  // --- Stage 7: Skill Consolidation (parallel per architecture-authority.json) ---
  // LLM abstraction calls are independent per cluster → Promise.all with 8-way cap.
  // Cluster count hard-capped at MAX_CLUSTERS to bound runtime.
  let skillConsolidationResult = { clusters: 0, abstractions: 0, promoted: 0, redundant: 0 };
  try {
    const MAX_CLUSTERS = 40;
    const LLM_CONCURRENCY = 8;
    const allClusters = await clusterSimilarSkills(companyId);
    const skillClusters = allClusters.slice(0, MAX_CLUSTERS);

    // Parallel abstraction extraction (bounded)
    const abResults = await pMap(
      skillClusters,
      (cluster) => extractAbstraction(cluster, companyId),
      LLM_CONCURRENCY
    );
    const abstractionCount = abResults.filter(r => r && r.saved).length;

    // Flatten all skillIds across clusters, promote in parallel (DB-bound)
    const allSkillIds = skillClusters.flatMap(c => c.skillIds);
    await pMap(allSkillIds, (sid) => promoteProvisionalSkill(sid, companyId), 16);

    const redundant = await flagRedundantSkills(companyId);
    skillConsolidationResult = {
      clusters: skillClusters.length,
      abstractions: abstractionCount,
      promoted: allSkillIds.length,
      redundant: redundant.length,
      totalClustersFound: allClusters.length
    };
    console.log('[dream] Stage 7 result:', skillConsolidationResult);
  } catch (err) {
    console.warn('[dream] Stage 7 (skill-consolidation) failed:', err.message);
  }

  // --- Stage 8: Delta Writer ---
  let deltaWriterResult = { added: 0, deduped: 0, deltasGenerated: 0 };
  try {
    const generatorOutput = { usedMemoryIds: [], helpful: [], harmful: [] };
    const reflectorOutput = events
      .filter(e => String(e.value || '').length > 50)
      .map(e => `[insight] - ${String(e.value || '').slice(0, 200)}`)
      .join('\n');
    const result = await runDeltaPipeline(generatorOutput, reflectorOutput, companyId);
    deltaWriterResult = result || deltaWriterResult;
    console.log('[dream] Stage 8 result:', deltaWriterResult);
  } catch (err) {
    console.warn('[dream] Stage 8 (delta-writer) failed:', err.message);
  }

  // --- Stage 9: Dream Feedback ---
  let dreamFeedbackResult = { constraintsLoaded: false, constraints: null };
  try {
    const constraints = await loadDreamConstraints(companyId);
    dreamFeedbackResult = {
      constraintsLoaded: !!constraints,
      focusAreas: constraints?.focus_areas?.length || 0,
      lowFrequencyPatterns: constraints?.low_frequency_patterns?.length || 0,
      constraints: constraints || null,
    };
    console.log('[dream] Stage 9 result:', dreamFeedbackResult);
  } catch (err) {
    console.warn('[dream] Stage 9 (dream-feedback) failed:', err.message);
  }

  // --- Stage 10: Spaced Repetition ---
  let spacedRepResult = { due: 0, scheduled: 0 };
  try {
    const dueBatch = await getNextReviewBatch(companyId, 50);
    let scheduled = 0;
    for (const mem of dueBatch) {
      const schedule = await scheduleRepetition(mem.id, companyId);
      if (schedule.scheduled) scheduled++;
    }
    spacedRepResult = { due: dueBatch.length, scheduled };
    console.log('[dream] Stage 10 result:', spacedRepResult);
  } catch (err) {
    console.warn('[dream] Stage 10 (spaced-repetition) failed:', err.message);
  }

  // --- Stage 11: Mastery Paradox Detector ---
  let masteryParadoxResult = { detected: false, reason: '' };
  try {
    const result = await detectMasteryParadox('general', companyId, 30);
    masteryParadoxResult = result || masteryParadoxResult;
    console.log('[dream] Stage 11 result:', masteryParadoxResult);
  } catch (err) {
    console.warn('[dream] Stage 11 (mastery-paradox-detector) failed:', err.message);
  }

  // ─── Stage 12-18: Temporal/Observe hooks (Phase 7 wiring) ──────────────────

  // --- Stage 12: Entanglement Monitor — memory cross-ref classification ---
  let entanglementResult = {};
  try {
    const stage12Result = await runEntanglementAutonomyAudit({ companyId, windowHours: 24, maxAgents: 20 });
    entanglementResult = stage12Result || entanglementResult;
    console.log('[dream] Stage 12 result:', entanglementResult);
  } catch (err) { console.error('[dream] Stage 12 (entanglement-monitor) failed (non-fatal):', err.message); }

  // --- Stage 13: SVDD Anomaly — anomaly detection on embeddings ---
  let svddAnomalyResult = {};
  try {
    const stage13Result = await runSVDDMemoryIntegrityCheck({ companyId, limit: 50 });
    svddAnomalyResult = stage13Result || svddAnomalyResult;
    console.log('[dream] Stage 13 result:', svddAnomalyResult);
  } catch (err) { console.error('[dream] Stage 13 (svdd-anomaly) failed (non-fatal):', err.message); }

  // --- Stage 15: Temporal Fingerprinter — temporal fingerprint updates ---
  let fingerprintResult = {};
  try {
    const stage15Result = await runTemporalFingerprintAudit({ companyId, windowHours: 24 });
    fingerprintResult = stage15Result || fingerprintResult;
    console.log('[dream] Stage 15 result:', fingerprintResult);
  } catch (err) { console.error('[dream] Stage 15 (temporal-fingerprinter) failed (non-fatal):', err.message); }

  // --- Stage 16: Topic Budget — per-topic memory rebalance + audit ---
  let topicBudgetResult = {};
  try {
    const rebalanceResult = await analyzeTopicCoverage(companyId);
    const auditResult = await runTopicBudgetAudit({ companyId, rebalanceResult });
    topicBudgetResult = { rebalance: rebalanceResult, audit: auditResult };
    console.log('[dream] Stage 16 result:', topicBudgetResult);
  } catch (err) { console.error('[dream] Stage 16 (topic-budget) failed (non-fatal):', err.message); }

  // --- Stage 18: Embedding Stability — embedding stability check ---
  let embeddingStabilityResult = {};
  try {
    const stage18Result = await runEmbeddingStabilityAudit({ companyId, sampleLimit: 10 });
    embeddingStabilityResult = stage18Result || embeddingStabilityResult;
    console.log('[dream] Stage 18 result:', embeddingStabilityResult);
  } catch (err) { console.error('[dream] Stage 18 (embedding-stability) failed (non-fatal):', err.message); }

  // --- Stage 19: Signed recall calibration update --------------------------
  // Housekeeper owns this autonomous transition. With no pending signed
  // usefulness evidence, it performs no mutation and appends no fake round.
  let recallCalibrationResult = { updated: false };
  try {
    recallCalibrationResult = await runCalibrationUpdate(companyId);
    console.log('[dream] Stage 19 result:', {
      updated: recallCalibrationResult.updated,
      calibration_event_id: recallCalibrationResult.snapshot?.calibrationEventId || null,
      pending_observations: recallCalibrationResult.snapshot?.pendingObservationCount || 0,
    });
  } catch (err) {
    console.error('[dream] Stage 19 (signed recall calibration) failed before mutation:', err.message);
  }

  const loggingGapWarning = (events.length === 0 && gapCount > 0)
    ? [`\n⚠️ LOGGING GAP DETECTED: 0 events logged but ${gapCount} memories were saved. Session(s) did not follow event logging protocol.`]
    : [];

  // ─── Senge Reflection: Five Disciplines analysis ────────────────────────────
  const sengeReflection = runSengeReflection(events, blockers);

  let value = [
    `Nightly Health Loop — ${now.toISOString().slice(0, 10)}`,
    '',
    `EVENTS TODAY (${events.length}):`,
    bulletList,
    ...loggingGapWarning,
    '',
    `BLOCKERS FOUND (${blockers.length}):`,
    blockerList,
    '',
    'PICK UP TOMORROW:',
    nextSection,
    '',
    `RETENTION: Aladdin (all long-term, nothing expires)`,
    `OUTCOME SCORER: ${scoreResult.scored} recommendations graded${scoreResult.error ? ' (error: ' + scoreResult.error + ')' : ''}`,
    `SKILL CURATION: ${curationResult.curated} skills curated${curationResult.error ? ' (error: ' + curationResult.error + ')' : ''}`,
    `RETRIEVAL DRIFT: ${formatRetrievalDriftSummary(retrievalDrift)}`,
    `HIERARCHICAL DREAM: ${hierarchicalResult.layers} layers generated (L1=${hierarchicalResult.layer1 || 0}, L2=${hierarchicalResult.layer2 || 0}, L3=${hierarchicalResult.layer3 || 0})${hierarchicalResult.error ? ' (error: ' + hierarchicalResult.error + ')' : ''}`,
    '',
    '── DREAM CONSOLIDATION V2 (Batch 2 Research) ──',
    `UTILITY DIAGNOSTICS: ${utilityResult.scored} memories classified without eligibility mutation${utilityResult.error ? ' (error: ' + utilityResult.error + ')' : ''}`,
    `ACCESS PATTERNS: ${accessResult.orphans} unreferenced memories | ${accessResult.trustScored} signed trust diagnostics${accessResult.error ? ' (error: ' + accessResult.error + ')' : ''}`,
    `SUPERSESSION CHAINS: ${supersessionResult.intact} intact | ${supersessionResult.broken.length} broken${supersessionResult.broken.length > 0 ? ' ⚠️' : ''}`,
    '',
    '── DREAM STAGES (Phase 1 Wiring) ──',
    `FAILURE REPLAY: ${failureReplayResult.clusters} clusters | ${failureReplayResult.antiSkills} anti-skills generated`,
    `ERROR NORMALIZER: processed=${failureReplayResult.errorNormalizer?.processed || 0} | stats=${failureReplayResult.errorNormalizer?.statsUpdated || 0} | stability=${failureReplayResult.errorNormalizer?.stabilityLoss ?? 'n/a'}`,
    `SKILL CONSOLIDATION: ${skillConsolidationResult.clusters} clusters | ${skillConsolidationResult.abstractions} abstractions | ${skillConsolidationResult.redundant} redundant flagged`,
    `DELTA WRITER: ${deltaWriterResult.added} added | ${deltaWriterResult.deduped} deduped | ${deltaWriterResult.deltasGenerated} deltas generated`,
    `DREAM FEEDBACK: constraints loaded=${dreamFeedbackResult.constraintsLoaded} | focus areas=${dreamFeedbackResult.focusAreas || 0} | low-frequency=${dreamFeedbackResult.lowFrequencyPatterns || 0}`,
    `SPACED REPETITION: ${spacedRepResult.due} due | ${spacedRepResult.scheduled} scheduled`,
    `MASTERY PARADOX: detected=${masteryParadoxResult.detected} | ${masteryParadoxResult.reason || 'n/a'}`,
    `RECALL CALIBRATION: ${recallCalibrationResult.updated ? 'signed update committed' : 'no pending signed observations'} | event=${recallCalibrationResult.snapshot?.calibrationEventId || 'unavailable'}`,
    '',
    sengeReflection,
    '',
    `Generated: ${now.toISOString()}`
  ].join('\n');

  // ─── L2M Phase 4: Compute learning transfer metrics ──────────────────────
  try {
    const l2mAgents = await query(
      `SELECT DISTINCT agent_id FROM aimos_events
       WHERE company_id = $1 AND operation = 'agent_run_metric'
       AND ts >= NOW() - INTERVAL '90 days' LIMIT 20`,
      [companyId]
    );
    const l2mLines = [];
    for (const row of l2mAgents.rows) {
      const [ft, bt, pm] = await Promise.all([
        computeForwardTransfer(row.agent_id, companyId),
        computeBackwardTransfer(row.agent_id, companyId),
        computePerformanceMaintenance(row.agent_id, companyId)
      ]);
      l2mLines.push(`${row.agent_id}: FT=${ft.forwardTransfer.toFixed(3)} BT=${bt.backwardTransfer.toFixed(3)} PM=${pm.performanceMaintenance.toFixed(3)}`);
    }
    if (l2mLines.length) {
      value += `\n\n── L2M LEARNING TRANSFER ──\n${l2mLines.join('\n')}`;
    }
  } catch (l2mErr) {
    console.warn('[nightly-dream] L2M metrics failed:', l2mErr.message);
  }

  // SPICED promotion-only neuromorphic consolidation — Batch 5
  const consolidationResult = await runDreamConsolidation();
  await logEvent(companyId, 'housekeeper', 'dream_spiced_consolidation', 'dream:spiced', {
    ...consolidationResult,
    reasoning: 'The housekeeper completed the promotion-only SPICED consolidation cycle and retained its complete outcome as signed operational evidence.',
    source_knowledge: 'SPICED Eq. 5 promotion-only Aimos mapping; nightly-dream.js',
  });

  const key = `dream:${now.toISOString().slice(0, 10)}`;
  const embedding = await getEmbedding(value);
  // Aladdin-compliant: persistMemory appends a same-key retained version and
  // records the explicit predecessor/successor relation atomically.
  await persistMemory({
    company_id: companyId,
    agent_id: 'housekeeper',
    key,
    value,
    scope: 'system',
    clearance_level: 5,
    memory_type: 'dream_summary',
    source: 'nightly-dream',
    mutation_authority: 'housekeeper',
  });

  let topConsolidatedMemories = [];
  try {
    const topResult = await query(
      `SELECT id, key, memory_type, retrieval_weight, created_at
       FROM aimos_memories
       WHERE company_id = $1
         AND created_at >= $2
       ORDER BY retrieval_weight DESC NULLS LAST, created_at DESC
       LIMIT 5`,
      [companyId, since.toISOString()]
    );
    topConsolidatedMemories = topResult.rows.map((row) => ({
      id: row.id,
      key: row.key,
      memory_type: row.memory_type,
      retrieval_weight: Number(row.retrieval_weight || 0),
      created_at: row.created_at,
    }));
  } catch (dreamArtifactErr) {
    console.warn('[nightly-dream] top consolidated memory snapshot failed:', dreamArtifactErr.message);
  }

  const dreamArtifact = {
    run_date: dreamDate,
    summary: value,
    patterns: {
      blocker_count: blockers.length,
      blockers: blockers.slice(0, 10).map((entry) => String(entry.value || entry.key || '').split('\n')[0]),
      focus_areas: dreamFeedbackResult.constraints?.focus_areas || [],
      low_frequency_patterns: dreamFeedbackResult.constraints?.low_frequency_patterns || [],
    },
    constraints_applied: dreamFeedbackResult.constraints || null,
    top_consolidated_memories: topConsolidatedMemories,
    weight_changes_summary: consolidationResult,
    conflicts_or_low_frequency_patterns: {
      blockers_found: blockers.length,
      low_frequency_patterns: dreamFeedbackResult.constraints?.low_frequency_patterns || [],
    },
    source_window: {
      from: since.toISOString(),
      to: now.toISOString(),
      events_captured: events.length,
      logging_gap_count: gapCount,
    },
    hierarchy: {
      layers: hierarchicalResult.layers || 0,
      retrieval_drift_status: retrievalDrift?.status || 'unknown',
    },
  };

  const artifactKey = `dream_artifact:${dreamDate}`;
  const artifactValue = JSON.stringify(dreamArtifact);
  await persistMemory({
    company_id: companyId,
    agent_id: 'housekeeper',
    key: artifactKey,
    value: artifactValue,
    scope: 'system',
    clearance_level: 5,
    memory_type: 'dream_artifact',
    source: 'nightly-dream',
    mutation_authority: 'housekeeper',
  });

  await logEvent(companyId, 'housekeeper', 'dream', key, {
    events_captured: events.length,
    blockers_found: blockers.length,
    retrieval_drift_status: retrievalDrift?.status || 'unknown',
    reasoning: `Dream consolidation synthesized ${events.length} events into a single narrative with ${blockers.length} blockers identified. This creates a compressed memory of the day — what happened, what went wrong, what to do next. Without this, individual events scatter and context is lost.`,
    source_knowledge: 'nightly-dream.js — retained hierarchical consolidation: events→daily summary→long-horizon reflection'
  });

  await logEvent(
    companyId,
    'housekeeper',
    retrievalDrift?.status === 'critical' || retrievalDrift?.status === 'warning'
      ? 'retrieval_drift_alert'
      : 'retrieval_drift_snapshot',
    `retrieval-drift:${now.toISOString().slice(0, 10)}`,
    {
      status: retrievalDrift?.status || 'unknown',
      summary: formatRetrievalDriftSummary(retrievalDrift),
      reasons: retrievalDrift?.reasons || [],
      benchmark_accuracy: retrievalDrift?.benchmarkAccuracy ?? null,
      hom_active_memory_count: retrievalDrift?.homActiveMemoryCount ?? null,
      reasoning: 'Retrieval quality must be measured against memory growth. This snapshot detects silent recall degradation before it compounds into memory drift, benchmark loops, or cross-system pollution.',
      source_knowledge: 'retrieval-drift-monitor.js — benchmark accuracy, zero-evidence rate, benchmark freshness, and memory growth monitoring'
    }
  );

  // --- Stage 20: Hebbian Consensus Consolidation (shadow-first, additive) ---
  // Relational sleep pass (HeLa-Mem association→consolidation): supported hubs
  // are elevated, divergent members attenuated, ALL via the signed cognitive-
  // weight chain. Existence untouched (weight = frequency, floor 0.1). No-op
  // unless the HEBBIAN_CONSENSUS governor flag is enabled. The whole corpus is
  // swept over DEFAULT_BATCHES nights — one deterministic rotating batch/night.
  let hebbianConsensusResult = { enabled: false };
  try {
    const batchCount = HEBBIAN_CONSTANTS.DEFAULT_BATCHES;
    const batchIndex = Math.floor(now.getTime() / 86_400_000) % batchCount;
    hebbianConsensusResult = await runHebbianConsensusBatch(batchIndex, batchCount, {
      companyId,
      readFlag: governorConfigLedger.readFlag,
    });
    console.log('[dream] Stage 20 (hebbian-consensus) result:', hebbianConsensusResult);
  } catch (err) { console.error('[dream] Stage 20 (hebbian-consensus) failed (non-fatal):', err.message); }

  return {
    events_captured: events.length,
    blockers_found: blockers.length,
    recommendations_scored: scoreResult.scored,
    hebbian_consensus: hebbianConsensusResult,
    skills_curated: curationResult.curated,
    hierarchical_layers: hierarchicalResult.layers,
    retrieval_drift_status: retrievalDrift?.status || 'unknown',
    // Dream Consolidation v2
    utility_scored: utilityResult.scored,
    orphan_memories: accessResult.orphans,
    trust_scored: accessResult.trustScored,
    supersession_chains_intact: supersessionResult.intact,
    supersession_chains_broken: supersessionResult.broken.length,
    // Phase 1 wired stages
    failure_replay_clusters: failureReplayResult.clusters,
    failure_replay_anti_skills: failureReplayResult.antiSkills,
    skill_consolidation_clusters: skillConsolidationResult.clusters,
    skill_consolidation_abstractions: skillConsolidationResult.abstractions,
    delta_writer_added: deltaWriterResult.added,
    delta_writer_deduped: deltaWriterResult.deduped,
    dream_feedback_loaded: dreamFeedbackResult.constraintsLoaded,
    spaced_rep_due: spacedRepResult.due,
    spaced_rep_scheduled: spacedRepResult.scheduled,
    mastery_paradox_detected: masteryParadoxResult.detected
  };
}
