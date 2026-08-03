/**
 * boot-integrity.js — Automated integrity verification on server start
 *
 * Runs architecture-authority, native service-file, and database health checks
 * automatically when the server boots. No manual commands needed.
 *
 * Created: 2026-04-03
 */

import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { query } from '../db/connection.js';
import { logEvent } from '../services/observe/event-ledger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const COMPANY = AIMOS_COMPANY_ID;

/**
 * Run full boot-time integrity verification.
 * Called automatically by startBackgroundServices() in server.js.
 *
 * @returns {Promise<{passed: number, failed: number, checks: object}>}
 */
export async function runBootIntegrity() {
  const results = { passed: 0, failed: 0, checks: {}, timestamp: new Date().toISOString() };

  function check(name, condition) {
    if (condition) {
      results.passed++;
      results.checks[name] = 'PASS';
    } else {
      results.failed++;
      results.checks[name] = 'FAIL';
    }
  }

  // ─── 1. Architecture Authority ────────────────────────────────────────────
  try {
    const authorityPath = resolve(ROOT, 'architecture-authority.json');
    check('architecture_authority_exists', existsSync(authorityPath));
    const raw = JSON.parse(readFileSync(authorityPath, 'utf8'));
    check('architecture_schema_valid', raw.schema === 'hom.architecture-authority/v1');
    check('backend_first_authority', raw.governance?.backend_first_authority === true);
  } catch {
    check('architecture_authority_parse', false);
  }

  // ─── 2. Critical Service Files Exist ──────────────────────────────────────
  const criticalFiles = [
    'services/core/deontic-reasoner.js',
    'services/observe/explainer.js',
    'services/core/constitution-enforcer.js',
    'services/observe/agent-trace.js',
    'services/retrieval/multi-stage-retrieval.js',
    'services/orchestration/agent-runner.js',
    'services/orchestration/meta-controller.js',
    'services/learning/stdp-kernel.js',
    'services/dream/spiced-consolidator.js',
    'services/security/system-config-store.js',
    'routes/aimos.js',
  ];

  for (const f of criticalFiles) {
    check(`file:${f.split('/').pop()}`, existsSync(resolve(ROOT, f)));
  }

  // ─── 3. DB connectivity + medallion column ────────────────────────────────
  try {
    await query('SELECT 1 AS ping');
    check('db_connected', true);
  } catch {
    check('db_connected', false);
  }

  try {
    const colCheck = await query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'aimos_memories' AND column_name = 'medallion_layer'
    `);
    check('medallion_column', colCheck.rows.length > 0);
  } catch {
    check('medallion_column', false);
  }

  // ─── 4. Memory count sanity ───────────────────────────────────────────────
  try {
    const countResult = await query(
      'SELECT COUNT(*) as cnt FROM aimos_memories',
      []
    );
    const memCount = parseInt(countResult.rows[0]?.cnt || 0);
    check('memories_exist', memCount > 0);
    results.checks['memory_count'] = memCount;
  } catch {
    check('memories_exist', false);
  }

  // Embeddings are a retrieval-readiness diagnostic, not an eligibility
  // filter: every retained memory remains canonical whether embedded or not.
  try {
    const embeddedResult = await query(
      `SELECT COUNT(*)::int AS cnt FROM aimos_memories
        WHERE company_id = $1 AND embedding IS NOT NULL`,
      [COMPANY]
    );
    const embeddedCount = Number(embeddedResult.rows[0]?.cnt || 0);
    results.checks['embedded_memory_count'] = embeddedCount;
    check('retrieval_embeddings_present', embeddedCount > 0);
  } catch {
    check('retrieval_embeddings_present', false);
  }

  // ─── 5. Medallion layer distribution ──────────────────────────────────────
  try {
    const layerResult = await query(
      `SELECT medallion_layer, COUNT(*) as cnt FROM aimos_memories
       WHERE company_id IN ($1, 'system')
       GROUP BY medallion_layer`,
      [COMPANY]
    );
    const layers = {};
    for (const r of layerResult.rows) {
      layers[r.medallion_layer || 'bronze'] = parseInt(r.cnt);
    }
    results.checks['medallion_layers'] = layers;
    check('medallion_populated', Object.keys(layers).length > 0);
  } catch {
    check('medallion_populated', false);
  }

  // ─── Log result to Aimos ─────────────────────────────────────────────────
  try {
    await logEvent(COMPANY, 'system', 'boot_integrity', `boot_integrity:${results.timestamp}`, {
      passed: results.passed,
      failed: results.failed,
      checks: results.checks,
      reasoning: 'Housekeeper recorded the complete native boot-integrity result after architecture, service-file, database, and retained-memory checks.',
      source_knowledge: 'jobs/boot-integrity.js — native boot verification',
    });
  } catch { /* fire and forget */ }

  const status = results.failed === 0 ? 'HEALTHY' : 'DEGRADED';
  console.log(`[BOOT-INTEGRITY] ${status}: ${results.passed} passed, ${results.failed} failed`);
  if (results.failed > 0) {
    const failures = Object.entries(results.checks).filter(([, v]) => v === 'FAIL').map(([k]) => k);
    console.warn(`[BOOT-INTEGRITY] Failures: ${failures.join(', ')}`);
  }

  return results;
}
