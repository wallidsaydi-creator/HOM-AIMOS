import { createHash, randomUUID } from 'node:crypto';

import { logEvent as defaultLogEvent } from '../../../services/observe/event-ledger.js';
import { canonicalJson } from './cr9-postgres.mjs';

const START = 'database_administration_started';
const TERMINAL = 'database_administration_terminal';
const SCHEMA_V1 = 'hom.aimos.database-administration-effect/v1';
const SCHEMA = 'hom.aimos.database-administration-effect/v2';

function projectionHash(value) {
  return createHash('sha256').update(Buffer.from(canonicalJson(value ?? null), 'utf8')).digest('hex');
}

function metadataOf(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  try { return JSON.parse(row?.metadata || '{}'); } catch { return {}; }
}

function mutationHashOf(row) {
  return typeof row?.mutation_hash === 'string' ? row.mutation_hash : Buffer.from(row?.mutation_hash || []).toString('hex');
}

export function reconstructCr9DatabaseAdministration(rows = []) {
  if (!Array.isArray(rows) || rows.length > 100_000) throw new Error('cr9_database_effect_recovery_limit');
  const actions = new Map();
  for (const row of rows) {
    if (![START, TERMINAL].includes(row?.operation)) continue;
    const metadata = metadataOf(row);
    if (![SCHEMA_V1, SCHEMA].includes(metadata.schema)) continue;
    const actionId = String(metadata.action_id || row.key || '');
    if (!actionId || String(row.key || '') !== actionId) throw new Error('cr9_database_effect_key_invalid');
    const trace = actions.get(actionId) || { actionId, start: null, terminal: null };
    if (row.operation === START) {
      if (trace.start) throw new Error('cr9_database_effect_start_fork');
      trace.start = row;
    } else {
      if (trace.terminal) throw new Error('cr9_database_effect_terminal_fork');
      trace.terminal = row;
    }
    actions.set(actionId, trace);
  }
  const ordered = [...actions.values()].sort((left, right) => left.actionId.localeCompare(right.actionId));
  for (const trace of ordered) {
    if (!trace.start) throw new Error('cr9_database_effect_terminal_without_start');
    if (!trace.terminal) continue;
    const start = metadataOf(trace.start);
    const terminal = metadataOf(trace.terminal);
    const planBindingValid = start.schema === SCHEMA_V1
      ? terminal.authorization_sha256 === start.authorization_sha256
      : /^[0-9a-f]{64}$/.test(String(start.operator_plan_sha256 || ''))
        && terminal.operator_plan_sha256 === start.operator_plan_sha256;
    if (String(trace.terminal.parent_event_id || '') !== String(trace.start.id || trace.start.event_id || '')
        || terminal.start_event_id !== String(trace.start.id || trace.start.event_id || '')
        || terminal.start_mutation_hash !== mutationHashOf(trace.start)
        || terminal.operation !== start.operation
        || terminal.target_sha256 !== start.target_sha256
        || terminal.input_sha256 !== start.input_sha256
        || !planBindingValid
        || !['SUCCEEDED', 'FAILED', 'INDETERMINATE'].includes(terminal.disposition)
        || !/^[0-9a-f]{64}$/.test(String(terminal.result_sha256 || ''))) {
      throw new Error('cr9_database_effect_terminal_binding_invalid');
    }
  }
  return Object.freeze({
    complete: Object.freeze(ordered.filter((trace) => trace.terminal)),
    open: Object.freeze(ordered.filter((trace) => !trace.terminal)),
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export function createCr9DatabaseAdministrationOwner({
  ownerPool,
  logEventFn = defaultLogEvent,
  uuidFn = randomUUID,
} = {}) {
  if (!ownerPool?.connect || typeof logEventFn !== 'function') throw new Error('cr9_database_owner_dependencies_invalid');

  async function begin({ operation, target, inputProjection, authorizationSha256 }) {
    if (!operation || !target || !/^[0-9a-f]{64}$/.test(String(authorizationSha256 || ''))) {
      throw new Error('cr9_database_effect_start_invalid');
    }
    const actionId = uuidFn();
    const targetSha256 = projectionHash({ kind: 'database', target });
    const inputSha256 = projectionHash(inputProjection);
    const receipt = await logEventFn('hom', 'housekeeper', START, actionId, {
      schema: SCHEMA,
      action_id: actionId,
      operation,
      target_sha256: targetSha256,
      input_sha256: inputSha256,
      operator_plan_sha256: authorizationSha256,
      reasoning: 'Housekeeper retained the exact operator-authorized database administration projection before one bounded attempt.',
      source_knowledge: 'CR9 database administration owner — RFC 6962 / RFC 8032 / RFC 8785',
    }, null, { returnReceipt: true, exclusiveOperationKey: true });
    return Object.freeze({ actionId, operation, targetSha256, inputSha256, authorizationSha256, receipt });
  }

  async function terminal(action, disposition, resultProjection, { client = null } = {}) {
    const normalized = String(disposition || '').toUpperCase();
    if (!action?.receipt?.event_id || !['SUCCEEDED', 'FAILED', 'INDETERMINATE'].includes(normalized)) {
      throw new Error('cr9_database_effect_terminal_invalid');
    }
    return logEventFn('hom', 'housekeeper', TERMINAL, action.actionId, {
      schema: SCHEMA,
      action_id: action.actionId,
      operation: action.operation,
      target_sha256: action.targetSha256,
      input_sha256: action.inputSha256,
      operator_plan_sha256: action.authorizationSha256,
      start_event_id: action.receipt.event_id,
      start_mutation_hash: action.receipt.mutation_hash,
      disposition: normalized,
      result_sha256: projectionHash(resultProjection),
      reasoning: 'Housekeeper retained one terminal disposition bound to the database administration start and exact result projection.',
      source_knowledge: 'CR9 database administration owner — signed start/terminal protocol',
    }, action.receipt.event_id, {
      client,
      identityQueryFn: client ? (text, values) => client.query(text, values) : undefined,
      returnReceipt: true,
      exclusiveOperationKey: true,
    });
  }

  async function apply({ operation, target, inputProjection, authorizationSha256, mutate, verify }) {
    if (typeof mutate !== 'function' || typeof verify !== 'function') throw new Error('cr9_database_effect_callbacks_invalid');
    const action = await begin({ operation, target, inputProjection, authorizationSha256 });
    const client = await ownerPool.connect();
    try {
      await client.query('BEGIN');
      const mutationResult = await mutate(client);
      const verificationResult = await verify(client);
      const receipt = await terminal(action, 'SUCCEEDED', { mutationResult, verificationResult }, { client });
      await client.query('COMMIT');
      return Object.freeze({ action, mutationResult, verificationResult, terminal: receipt });
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch { /* connection may be unavailable */ }
      try {
        await terminal(action, 'FAILED', { error_class: error?.name || 'database_administration_error' });
      } catch (terminalError) {
        error.terminalError = terminalError;
      }
      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({ begin, terminal, apply });
}

export const CR9_DATABASE_EFFECT_PROTOCOL = Object.freeze({ schema: SCHEMA, start: START, terminal: TERMINAL });
