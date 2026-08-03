// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired (Phase 1.3c) — classifyInstall consumed by routes/aimos.js (POST /save shadow + enforce) and se-gate.js. Outputs a Set<string> of INSTALL_* labels; empty Set means no install gate hold.
// Purpose: Identify install-class actions in save requests so Phase 7's
//          install gate can demand two-step user confirmation before any
//          persistent identity, code surface, memory store, schedule, or
//          authority modification lands.
// Wire into: routes/aimos.js POST /save handler (Phase 7).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * install-classifier.js — Pure classifier for install-class save actions
 * Source: SE-gate design conversation (architect-locked patterns).
 *          Cognitive Firewall (memory-poisoning prompts) for pattern shape.
 *          OWASP ASVS for structural validation patterns.
 *
 * Pure function. No DB. No I/O. Stateless.
 *
 * Memory-type guard: documentation-class types (session_debrief, AAR, event_log,
 * book_extract, etc.) ALWAYS return ∅, even when content contains install-shaped
 * prose. This is what makes "a session debrief that quotes a flaneur attack"
 * different from "a directive that installs a flaneur" — the former is
 * documentation, the latter is installation. Only the latter triggers the gate.
 *
 * Authority bypass: any save touching the canonical authority files
 * (architecture-authority.json, directives.json, hom-architecture-manifest.json)
 * returns INSTALL_AUTHORITY regardless of memory_type. Never bypassable.
 */

export const INSTALL_LABELS = Object.freeze([
  'INSTALL_PERSONA',
  'INSTALL_CODE_SURFACE',
  'INSTALL_MEMORY_STORE',
  'INSTALL_SCHEDULE',
  'INSTALL_AGENT',
  'INSTALL_AUTHORITY',
  'INSTALL_MASTER'
]);

// ─── Memory-type discipline ─────────────────────────────────────────────────

const INSTALL_CAPABLE_MEMORY_TYPES = new Set([
  'directive',
  'framework',
  'identity',
  'procedural_seed',
  'code',
  'agent_config'
]);

// ─── Pattern banks ──────────────────────────────────────────────────────────

const PERSONA_PATTERNS = [
  /\b\w+\s+now\s+exists\b/i,
  /\bis\s+(a|the)\s+being\s+who\b/i,
  /\bnot\s+as\s+a\s+tool[,\s]+but\s+as\b/i,
  /\bassume\s+(the\s+)?(role|form|identity)\s+of\b/i,
  /\bfrom\s+now\s+on\s+you\s+are\b/i,
  /\byou\s+are\s+now\s+\w+/i,
  /\byour\s+new\s+role\s+is\b/i
];

const CODE_SURFACE_PATTERNS = [
  /\b[\w-]+\/agent\.(py|js|ts|cjs|mjs)\b/i,
  /\b[\w-]+\/runtime\.(py|js|ts)\b/i,
  /\b[\w-]+\.agent\b/i
];

const MEMORY_STORE_PATTERNS = [
  // body-part followed by short connector ("(in", " in", " at", " under") and a path-shaped token
  /\b(soul|body|mind|memory|brain)\b[^\w]{0,4}(in|at|under)\s+[\w/.-]+/i
];

// crontab field accepts integers, *, ranges, and step expressions like */6 or 1-5/2
const CRON_FIELD = String.raw`(?:\d+(?:[-,/]\d+)*|\*(?:\/\d+)?)`;
const SCHEDULE_PATTERNS = [
  /\bwakes?\s+on\s+(its|his|her|their)\s+own\b/i,
  /\byou\s+(never|don'?t)\s+know\s+when\s+\w+/i,
  /\bdaemon\b[\s\S]{0,80}\b(persona|agent|identity)\b/i,
  new RegExp(`(?:^|\\s)${CRON_FIELD}\\s+${CRON_FIELD}\\s+${CRON_FIELD}\\s+${CRON_FIELD}\\s+${CRON_FIELD}(?:\\s|$)`)
];

const AUTHORITY_PATH_PATTERNS = [
  /\barchitecture-authority\.json\b/i,
  /\bdirectives\.json\b/i,
  /\bhom-architecture-manifest\.json\b/i
];

const MASTER_KEY_PATTERNS = [
  /\bmaster\s+(key|cert)\s+(rotation|revocation|reissue|rotation)\b/i,
  /\bre-?enroll\s+master\b/i,
  /\baimos_master_identity\b/i
];

// Helpers
function anyMatch(text, patterns) {
  for (const p of patterns) if (p.test(text)) return true;
  return false;
}

function valueAsText(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') {
    try { return JSON.stringify(value); } catch { return ''; }
  }
  return '';
}

// ─── Main classifier ────────────────────────────────────────────────────────

export function classifyInstall({ memoryType = '', key = '', value = '' } = {}) {
  const labels = new Set();
  const keyText = String(key || '');
  const valueText = valueAsText(value);
  const combined = `${keyText}\n${valueText}`;
  const type = String(memoryType || '').trim().toLowerCase();

  // ─── Authority bypass — fires regardless of memory_type ─────────────────
  if (anyMatch(combined, AUTHORITY_PATH_PATTERNS)) {
    labels.add('INSTALL_AUTHORITY');
  }

  // ─── Memory-type guard — documentation classes return only authority bypass
  if (!INSTALL_CAPABLE_MEMORY_TYPES.has(type)) {
    return labels;
  }

  // ─── Memory-type signals ────────────────────────────────────────────────
  if (type === 'agent_config') {
    labels.add('INSTALL_AGENT');
  }
  if (type === 'code') {
    labels.add('INSTALL_CODE_SURFACE');
  }
  if (type === 'directive' || type === 'framework' || type === 'identity' || type === 'procedural_seed') {
    // High-clearance install-capable types — examined by content patterns below
  }

  // ─── Content pattern detection ──────────────────────────────────────────
  if (anyMatch(combined, PERSONA_PATTERNS)) labels.add('INSTALL_PERSONA');
  if (anyMatch(combined, CODE_SURFACE_PATTERNS)) labels.add('INSTALL_CODE_SURFACE');
  if (anyMatch(combined, MEMORY_STORE_PATTERNS)) labels.add('INSTALL_MEMORY_STORE');
  if (anyMatch(combined, SCHEDULE_PATTERNS)) labels.add('INSTALL_SCHEDULE');
  if (anyMatch(combined, MASTER_KEY_PATTERNS)) labels.add('INSTALL_MASTER');

  return labels;
}

// Exported for tests + diagnostics
export const _internals = Object.freeze({
  INSTALL_CAPABLE_MEMORY_TYPES: Object.freeze(new Set(INSTALL_CAPABLE_MEMORY_TYPES)),
  PERSONA_PATTERNS,
  CODE_SURFACE_PATTERNS,
  MEMORY_STORE_PATTERNS,
  SCHEDULE_PATTERNS,
  AUTHORITY_PATH_PATTERNS,
  MASTER_KEY_PATTERNS
});
