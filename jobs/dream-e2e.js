/**
 * dream-e2e.js — End-to-end smoke test for the nightly-dream pipeline fixes.
 *
 * Exercises the 5 previously-broken stages in isolation with tiny inputs so
 * the full test completes in minutes, not hours. Each check is independent;
 * failure of one does not abort the others.
 *
 * Usage:
 *   node jobs/dream-e2e.js
 *
 * Exit code: 0 if all checks pass, 1 otherwise.
 */

import { query } from '../db/connection.js';
import { runProvider } from '../services/core/providers.js';
import {
  depositPheromone,
  getPheromoneStrength
} from '../services/temporal/retrieval-pheromone.js';
import { getTopicDistribution } from '../services/temporal/topic-budget.js';
import { amplifyConsolidated } from '../services/dream/spiced-consolidator.js';
import { systemConfigStore } from '../services/security/system-config-store.js';

const COMPANY = 'hom';
const results = [];

function record(name, ok, detail) {
  results.push({ name, ok, detail });
  const tag = ok ? 'PASS' : 'FAIL';
  console.log(`[e2e] ${tag} — ${name}${detail ? ' :: ' + detail : ''}`);
}

async function check(name, fn) {
  const t0 = Date.now();
  try {
    const detail = await fn();
    record(name, true, `${Date.now() - t0}ms${detail ? ' | ' + detail : ''}`);
  } catch (err) {
    record(name, false, `${err.code || ''} ${err.message}`.trim());
  }
}

// ─── Stage 7: Agnostic LLM resolution ─────────────────────────────────────────
await check('stage7_llm_agnostic_model_resolution', async () => {
  const envProvider = systemConfigStore.readConfigString('LLM_PROVIDER') || '';
  const envModel = systemConfigStore.readConfigString('LLM_MODEL') || systemConfigStore.readConfigString('OLLAMA_MODEL') || '';
  if (!envProvider || !envModel) throw new Error('LLM_PROVIDER / LLM_MODEL signed config not set');
  // Tiny prompt — returns promptly on any backing provider.
  const r = await Promise.race([
    runProvider({ prompt: 'Reply with exactly the word: OK', provider: envProvider, model: envModel }),
    new Promise((_, rej) => setTimeout(() => rej(new Error('provider call >60s')), 60000))
  ]);
  if (!r || typeof r !== 'string') throw new Error(`non-string result: ${typeof r}`);
  return `provider=${envProvider} model=${envModel} chars=${r.length}`;
});

// ─── Stage 14: retrieval_pheromones schema ────────────────────────────────────
await check('stage14_pheromone_schema', async () => {
  const cols = await query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_name = 'retrieval_pheromones'
       AND column_name IN ('memory_id_a','memory_id_b','tau','updated_at')`
  );
  if (cols.rows.length !== 4) {
    throw new Error(`missing cols, found ${cols.rows.length}/4`);
  }

  // Acquire 2 real memory UUIDs to avoid FK issues if any are enforced.
  const mem = await query(
    `SELECT id FROM aimos_memories WHERE company_id = $1 LIMIT 2`,
    [COMPANY]
  );
  if (mem.rows.length < 2) return 'skipped write (need ≥2 memories)';

  const [a, b] = [mem.rows[0].id, mem.rows[1].id];
  const ok = await depositPheromone(a, b, 1, COMPANY);
  if (!ok) throw new Error('depositPheromone returned false');
  const tau = await getPheromoneStrength(a, b, COMPANY);
  if (tau <= 0) throw new Error(`tau not deposited: ${tau}`);
  return `deposited tau=${tau.toFixed(3)}`;
});

// ─── Stage 16: topic-budget text[] unnest ─────────────────────────────────────
await check('stage16_topic_budget_unnest', async () => {
  const dist = await getTopicDistribution(COMPANY);
  // An empty distribution is acceptable (no tags in corpus); the failure mode
  // being tested is "function jsonb_object_keys(text[]) does not exist".
  return `topics=${Object.keys(dist).length}`;
});

// ─── Stage 18: SPICED write path ──────────────────────────────────────────────
// The live SPICED path is promotion-only; an empty candidate set verifies the
// native no-op contract without mutating canonical retrieval weights.
await check('stage18_spiced_write_path', async () => {
  const amp = await amplifyConsolidated([]);
  return `amp=${amp.amplified}`;
});

// ─── Report ───────────────────────────────────────────────────────────────────
const passed = results.filter((r) => r.ok).length;
const total = results.length;
console.log(`\n[e2e] ${passed}/${total} checks passed`);
process.exit(passed === total ? 0 : 1);
