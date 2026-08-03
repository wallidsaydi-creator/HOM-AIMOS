/**
 * canary-write-gate.js — write-path canary gate (PoisonedRAG defense)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js POST /save (before persistMemory)
 * 2. → Pulls from: services/security/canary-tracker.js (scanMemoryWrite)
 * 3. → Pushes to: services/observe/event-ledger.js (aimos_events)
 * 4. ↔ Interacts with: nothing else — the gate is pure decision + observation.
 *
 * LOGIC GUIDE: A canary token (SECRET-[A-F0-9]{8}) in a save body means an
 * injection payload reached the write path. Aladdin retention forbids content
 * suppression, so detection forces retained active quarantine at the 0.1
 * retrieval floor. The signed request and the housekeeper scan receipt are
 * preserved; the content never gains ordinary retrieval authority.
 */

import { logEvent } from '../observe/event-ledger.js';
import { scanMemoryWrite } from './canary-tracker.js';

export const CANARY_QUARANTINE_REASON = 'canary_detected_retained_quarantine';

/**
 * Render a save body to the flat string the canary scanner reads. Values may
 * arrive as objects; a token nested in an object must not slip past the scan.
 */
function renderScanTarget(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export function buildCanaryWriteDisposition(scan = {}) {
  const tokens = Array.isArray(scan?.canariesFound) ? scan.canariesFound : [];
  const detected = tokens.length > 0;
  return {
    detected,
    tokens,
    quarantine: detected,
    reject: false,
    reason: detected ? CANARY_QUARANTINE_REASON : null,
    kill_chain_diagnostics: scan?.kill_chain_diagnostics,
  };
}

/**
 * Evaluate the canary gate for one save request.
 *
 * @param {object} params
 * @param {string} params.key
 * @param {string|object} params.value
 * @param {string} [params.companyId]
 * @param {string} [params.agentId]
 * @param {string} [params.runId]
 * @param {object|null} [params.authority]
 * @param {string|null} [params.parentEventId]
 * @returns {Promise<{detected: boolean, tokens: string[], quarantine: boolean, reject: false, reason: string|null, event_receipt: object, kill_chain_diagnostics?: object}>}
 */
export async function evaluateCanaryWrite(
  { key, value, companyId, agentId, runId = '', authority = null, parentEventId = null } = {},
) {
  const scanKey = String(key ?? '');
  const scanValue = renderScanTarget(value);
  const scan = await scanMemoryWrite(scanKey, scanValue, runId, { authority, parentEventId });

  const disposition = buildCanaryWriteDisposition(scan);
  const { tokens, detected } = disposition;
  const eventReceipt = await logEvent(
    companyId || 'hom',
    agentId || 'unknown',
    detected ? 'canary_write_retained_quarantine' : 'canary_write_scan_passed',
    scanKey || null,
    {
      canary_count: tokens.length,
      stage: detected ? 'retained_quarantine' : 'clean',
      kill_chain_diagnostics: scan?.kill_chain_diagnostics,
      reasoning: detected
        ? 'Canary token detected in a signed save body; Aladdin retention preserves it as active quarantine at the 0.1 floor.'
        : 'Canary write-boundary scan completed without detecting a canary token.',
      source_knowledge: 'services/security/canary-write-gate.js — write-path canary gate',
    },
    parentEventId,
    { authority, returnReceipt: true },
  );

  return {
    ...disposition,
    event_receipt: eventReceipt,
  };
}
