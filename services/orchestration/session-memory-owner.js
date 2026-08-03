/**
 * session-memory-owner.js — Native durable session retention and finalization
 *
 * Paper authorities reviewed before implementation:
 * - Generative Agents: retain the complete observation stream and link derived
 *   reflection to its source observations.
 * - TiMem: persist L1 dialogue evidence online and create L2 session state at
 *   the session boundary, with temporal containment.
 * - Chronos: retain raw turns in a turn calendar and add structured temporal
 *   records rather than replacing the source dialogue.
 * - DF-ERC: conversational utterances remain speaker-bound and modality
 *   context remains distinct from the utterance text.
 *
 * HOM adaptations: raw turns remain permanently retained; finalization stores
 * a verified hash manifest, not a destructive summary. TiMem recall gating,
 * recency decay, forgetting, deletion, and suppression are intentionally not
 * implemented because they conflict with Aladdin full-retention law.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. <- Called by session-runner.js and signed /aimos/session routes.
 * 2. -> Calls persist-memory.js, memory-provenance.js, and event-ledger.js.
 * 3. -> Reads only its `sess:<session_id>:` conversation_feed/manifest rows.
 * Pipeline: SESSION | Position: native durable session owner
 */

import { createHash } from 'node:crypto';
import { withTransaction } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';
import { memoryProvenanceLedger } from '../security/memory-provenance.js';
import { canonicalJson } from '../security/agent-identity.js';
import { logEvent } from '../observe/event-ledger.js';
import {
  normalizeSessionId,
  sessionKeyLikePattern,
  sessionKeyPrefix,
} from '../shared/session-scope.js';

const TURN_SCHEMA = 'aimos.session-turn/v1';
const EXCHANGE_SCHEMA = 'aimos.session-exchange/v1';
const ORDERED_EXCHANGE_SCHEMA = 'aimos.session-exchange/v2';
const FINALIZATION_SCHEMA = 'aimos.session-finalization/v1';
const TURN_SEQUENCE_WIDTH = 12;
const TURN_ROLES = new Set(['user', 'assistant', 'system', 'tool']);
const MAX_SPEAKER_BYTES = 512;
const MAX_IMAGE_CONTEXT_ITEMS = 16;
const MAX_IMAGE_CONTEXT_TEXT_BYTES = 8192;

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function asHex(value) {
  if (Buffer.isBuffer(value)) return value.toString('hex');
  const text = String(value || '').trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(text) ? text : null;
}

function normalizeRequiredText(value, errorCode, maxBytes = 1_048_576) {
  const text = String(value ?? '');
  if (!text.trim()) throw new Error(errorCode);
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error(`${errorCode}_too_large`);
  return text;
}

function normalizeRole(value) {
  const role = String(value || '').trim().toLowerCase();
  if (!TURN_ROLES.has(role)) throw new Error('session_turn_role_invalid');
  return role;
}

function normalizeOptionalText(value, errorCode, maxBytes) {
  if (value == null) return null;
  const text = String(value).trim();
  if (!text) return null;
  if (/[\x00-\x1F\x7F]/u.test(text)) throw new Error(errorCode);
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error(`${errorCode}_too_large`);
  return text;
}

function normalizeSpeaker(value) {
  return normalizeOptionalText(value, 'session_turn_speaker_invalid', MAX_SPEAKER_BYTES);
}

function normalizeImageContext(value) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > MAX_IMAGE_CONTEXT_ITEMS) {
    throw new Error('session_turn_image_context_invalid');
  }
  return value.map((entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error('session_turn_image_context_invalid');
    }
    for (const key of Object.keys(entry)) {
      if (!['url', 'caption', 'query'].includes(key)) {
        throw new Error('session_turn_image_context_invalid');
      }
    }
    const url = normalizeOptionalText(entry.url, 'session_turn_image_url_invalid', MAX_IMAGE_CONTEXT_TEXT_BYTES);
    const caption = normalizeOptionalText(entry.caption, 'session_turn_image_caption_invalid', MAX_IMAGE_CONTEXT_TEXT_BYTES);
    const query = normalizeOptionalText(entry.query, 'session_turn_image_query_invalid', MAX_IMAGE_CONTEXT_TEXT_BYTES);
    if (!url && !caption && !query) throw new Error('session_turn_image_context_invalid');
    return {
      ...(url ? { url } : {}),
      ...(caption ? { caption } : {}),
      ...(query ? { query } : {}),
    };
  });
}

function normalizeIso(value, errorCode) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) throw new Error(errorCode);
  return date.toISOString();
}

function turnTokenHash(turnId) {
  return sha256Hex(Buffer.from(normalizeRequiredText(turnId, 'session_turn_id_required', 4096), 'utf8'));
}

function orderedTurnIdHashesSha256(turns) {
  return sha256Hex(Buffer.from(canonicalJson(turns.map((turn) => turn.turnIdHash)), 'utf8'));
}

function normalizeExpectedTurnCount(value) {
  if (value == null) return null;
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 1) {
    throw new Error('session_finalization_expected_turn_count_invalid');
  }
  return count;
}

function normalizeExpectedTurnIdHashesSha256(value) {
  if (value == null) return null;
  const hash = String(value).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) {
    throw new Error('session_finalization_expected_turn_id_hashes_invalid');
  }
  return hash;
}

function parseJsonObject(value, errorCode) {
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(errorCode);
    return parsed;
  } catch (error) {
    if (error?.message === errorCode) throw error;
    throw new Error(errorCode);
  }
}

function parseTurnKey(key, prefix) {
  const raw = String(key || '');
  if (!raw.startsWith(prefix)) throw new Error('session_turn_key_scope_invalid');
  const match = raw.slice(prefix.length).match(/^turn:(\d{12}):([0-9a-f]{64})$/);
  if (!match) throw new Error('session_turn_key_invalid');
  const sequence = Number(match[1]);
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error('session_turn_sequence_invalid');
  return { sequence, turnIdHash: match[2] };
}

function buildTurnKey(sessionId, sequence, idHash) {
  if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence >= 10 ** TURN_SEQUENCE_WIDTH) {
    throw new Error('session_turn_sequence_exhausted');
  }
  return `${sessionKeyPrefix(sessionId)}turn:${String(sequence).padStart(TURN_SEQUENCE_WIDTH, '0')}:${idHash}`;
}

function parseTurnRow(row, sessionId) {
  const prefix = sessionKeyPrefix(sessionId);
  const keyParts = parseTurnKey(row.key, prefix);
  const record = parseJsonObject(row.value, 'session_turn_record_invalid');
  const exact = record.schema === TURN_SCHEMA
    && record.session_id === sessionId
    && Number(record.sequence) === keyParts.sequence
    && record.turn_id_sha256 === keyParts.turnIdHash
    && TURN_ROLES.has(record.role)
    && typeof record.content === 'string'
    && typeof record.observed_at === 'string';
  if (!exact) throw new Error('session_turn_record_binding_invalid');
  normalizeIso(record.observed_at, 'session_turn_observed_at_invalid');
  if (record.speaker !== undefined && normalizeSpeaker(record.speaker) !== record.speaker) {
    throw new Error('session_turn_record_binding_invalid');
  }
  if (record.image_context !== undefined
    && canonicalJson(normalizeImageContext(record.image_context)) !== canonicalJson(record.image_context)) {
    throw new Error('session_turn_record_binding_invalid');
  }
  return { row, record, sequence: keyParts.sequence, turnIdHash: keyParts.turnIdHash };
}

function largestPowerOfTwoBelow(value) {
  let power = 1;
  while ((power << 1) < value) power <<= 1;
  return power;
}

export function sessionMerkleRoot(entries = []) {
  const leaves = entries.map((entry) => createHash('sha256').update(Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from(canonicalJson(entry), 'utf8'),
  ])).digest());
  if (!leaves.length) return createHash('sha256').update(Buffer.alloc(0)).digest();
  const tree = (nodes) => {
    if (nodes.length === 1) return nodes[0];
    const split = largestPowerOfTwoBelow(nodes.length);
    return createHash('sha256').update(Buffer.concat([
      Buffer.from([0x01]),
      tree(nodes.slice(0, split)),
      tree(nodes.slice(split)),
    ])).digest();
  };
  return tree(leaves);
}

function ledgerHash(result, key) {
  return asHex(result?.[key]?.mutationHash || result?.[key]?.mutation_hash || null);
}

function makeEventAuthority(context = {}) {
  return context.requestAuthority || (
    context.mutationAuthority && context.mutationAuthority !== 'housekeeper'
      ? context.mutationAuthority
      : null
  );
}

function existingTurnMatches(parsed, {
  role,
  content,
  idHash,
  sourceRef,
  speaker,
  imageContext,
}) {
  return parsed.record.role === role
    && parsed.record.content === content
    && parsed.record.turn_id_sha256 === idHash
    && (parsed.record.source_ref ?? null) === sourceRef
    && (parsed.record.speaker ?? null) === speaker
    && canonicalJson(parsed.record.image_context ?? []) === canonicalJson(imageContext);
}

function buildExchangeSpecs(turns, sessionId) {
  const exchanges = [];
  for (let index = 0; index < turns.length; index += 2) {
    const group = turns.slice(index, index + 2);
    const [first, second] = group;
    const useLegacyPair = group.length === 2
      && first.record.role === 'user'
      && second.record.role === 'assistant'
      && !first.record.speaker
      && !second.record.speaker
      && !(first.record.image_context?.length)
      && !(second.record.image_context?.length);
    if (!useLegacyPair) {
      const sourceBinding = {
        schema: ORDERED_EXCHANGE_SCHEMA,
        session_id: sessionId,
        turn_sequences: group.map((turn) => turn.sequence),
        source_memory_ids: group.map((turn) => String(turn.row.id)),
        source_content_sha256: group.map((turn) => sha256Hex(Buffer.from(turn.record.content, 'utf8'))),
      };
      const exchangeHash = sha256Hex(Buffer.from(canonicalJson(sourceBinding), 'utf8'));
      exchanges.push({
        key: `${sessionKeyPrefix(sessionId)}exchange:${String(first.sequence).padStart(TURN_SEQUENCE_WIDTH, '0')}-${String(second?.sequence ?? first.sequence).padStart(TURN_SEQUENCE_WIDTH, '0')}:${exchangeHash}`,
        record: {
          ...sourceBinding,
          valid_from: first.record.observed_at,
          valid_until: (second || first).record.observed_at,
          turns: group.map((turn) => ({
            sequence: turn.sequence,
            role: turn.record.role,
            content: turn.record.content,
            observed_at: turn.record.observed_at,
            ...(turn.record.source_ref ? { source_ref: turn.record.source_ref } : {}),
            ...(turn.record.speaker ? { speaker: turn.record.speaker } : {}),
            ...(turn.record.image_context?.length ? { image_context: turn.record.image_context } : {}),
          })),
        },
        sourceTurns: group,
      });
      continue;
    }
    const user = first;
    const assistant = second;
    const sourceBinding = {
      schema: EXCHANGE_SCHEMA,
      session_id: sessionId,
      user_sequence: user.sequence,
      assistant_sequence: assistant.sequence,
      source_memory_ids: [String(user.row.id), String(assistant.row.id)],
      source_content_sha256: [
        sha256Hex(Buffer.from(user.record.content, 'utf8')),
        sha256Hex(Buffer.from(assistant.record.content, 'utf8')),
      ],
    };
    const exchangeHash = sha256Hex(Buffer.from(canonicalJson(sourceBinding), 'utf8'));
    exchanges.push({
      key: `${sessionKeyPrefix(sessionId)}exchange:${String(user.sequence).padStart(TURN_SEQUENCE_WIDTH, '0')}-${String(assistant.sequence).padStart(TURN_SEQUENCE_WIDTH, '0')}:${exchangeHash}`,
      record: {
        ...sourceBinding,
        valid_from: user.record.observed_at,
        valid_until: assistant.record.observed_at,
        user: user.record.content,
        assistant: assistant.record.content,
      },
      sourceTurns: [user, assistant],
    });
  }
  return exchanges;
}

function ensureEvidenceVerified(evidence, memoryIds) {
  const rejected = Array.isArray(evidence?.rejected) ? evidence.rejected : [];
  if (rejected.length) {
    const error = new Error('session_turn_provenance_verification_failed');
    error.rejected = rejected;
    throw error;
  }
  for (const memoryId of memoryIds) {
    if (!evidence?.verified?.has(String(memoryId)) || !evidence?.proofs?.get(String(memoryId))) {
      throw new Error('session_turn_provenance_missing');
    }
  }
}

export function createSessionMemoryOwner(deps = {}) {
  const withTransactionFn = deps.withTransaction || withTransaction;
  const persistMemoryFn = deps.persistMemory || persistMemory;
  const logEventFn = deps.logEvent || logEvent;
  const verifyEvidenceFn = deps.verifyEvidence
    || ((args) => memoryProvenanceLedger.verifyRecallEvidence(args));

  async function appendTurn(input = {}, context = {}) {
    const sessionId = normalizeSessionId(input.session_id ?? input.sessionId);
    const companyId = String(context.companyId || input.company_id || 'hom').trim();
    const agentId = String(context.agentId || input.agent_id || '').trim();
    if (!companyId) throw new Error('session_company_required');
    if (!agentId) throw new Error('session_agent_required');
    const role = normalizeRole(input.role);
    const content = normalizeRequiredText(input.content, 'session_turn_content_required');
    const observedAt = normalizeIso(input.observed_at ?? input.observedAt, 'session_turn_observed_at_invalid');
    const idHash = turnTokenHash(input.turn_id ?? input.turnId);
    const sourceRef = input.source_ref == null
      ? null
      : normalizeOptionalText(input.source_ref, 'session_turn_source_ref_invalid', 4096);
    const speaker = normalizeSpeaker(input.speaker);
    const imageContext = normalizeImageContext(input.image_context ?? input.imageContext);
    const source = String(input.source || context.source || 'session-runtime').trim() || 'session-runtime';
    const clearanceLevel = Number(input.clearance_level ?? context.clearanceLevel ?? 1);
    if (!Number.isInteger(clearanceLevel) || clearanceLevel < 1 || clearanceLevel > 12) {
      throw new Error('session_turn_clearance_invalid');
    }
    const prefix = sessionKeyPrefix(sessionId);
    const turnPattern = sessionKeyLikePattern(sessionId, 'turn:');
    const finalPattern = sessionKeyLikePattern(sessionId, 'final:');

    return withTransactionFn(async (client) => {
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`${companyId.length}:${companyId}${prefix.length}:${prefix}`],
      );

      const existing = await client.query(
        `SELECT id::text, key, value, agent_id, source, created_at, content_hash, memory_type
           FROM aimos_memories
          WHERE company_id = $1
            AND memory_type IN ('conversation_feed', 'quarantine')
            AND key LIKE $2 ESCAPE '\\'
            AND right(key, 65) = $3
          ORDER BY key
          LIMIT 2`,
        [companyId, turnPattern, `:${idHash}`],
      );
      if (existing.rows.length > 1) throw new Error('session_turn_idempotency_fork');
      if (existing.rows[0]) {
        const parsed = parseTurnRow(existing.rows[0], sessionId);
        if (!existingTurnMatches(parsed, {
          role,
          content,
          idHash,
          sourceRef,
          speaker,
          imageContext,
        })) {
          throw new Error('session_turn_idempotency_conflict');
        }
        const evidence = await verifyEvidenceFn({
          memoryIds: [String(existing.rows[0].id)],
          client,
        });
        ensureEvidenceVerified(evidence, [String(existing.rows[0].id)]);
        const proof = evidence.proofs.get(String(existing.rows[0].id));
        const receipt = await logEventFn(companyId, agentId, 'session_turn_idempotent_replay', existing.rows[0].key, {
          session_id: sessionId,
          turn_sequence: parsed.sequence,
          memory_id: existing.rows[0].id,
          canonical_memory_changed: false,
          reasoning: 'The native session owner observed an exact retry and reused the retained signed turn instead of creating a new memory version.',
          source_knowledge: 'session-memory-owner.js — deterministic turn idempotency',
        }, null, { client, returnReceipt: true, authority: makeEventAuthority(context) });
        return {
          success: true,
          idempotent: true,
          memory_id: existing.rows[0].id,
          key: existing.rows[0].key,
          session_id: sessionId,
          sequence: parsed.sequence,
          quarantined: existing.rows[0].memory_type === 'quarantine',
          live_content_hash: proof.live_content_hash,
          save_mutation_hash: proof.save_mutation_hash,
          binding_mutation_hash: proof.binding_mutation_hash,
          event_receipt: receipt,
        };
      }

      const finalized = await client.query(
        `SELECT id::text, key
           FROM aimos_memories
          WHERE company_id = $1
            AND memory_type = 'session_manifest'
            AND key LIKE $2 ESCAPE '\\'
          ORDER BY key
          LIMIT 1`,
        [companyId, finalPattern],
      );
      if (finalized.rows[0]) throw new Error('session_already_finalized');

      const latest = await client.query(
        `SELECT key
           FROM aimos_memories
          WHERE company_id = $1
            AND memory_type IN ('conversation_feed', 'quarantine')
            AND key LIKE $2 ESCAPE '\\'
          ORDER BY key DESC
          LIMIT 1`,
        [companyId, turnPattern],
      );
      const sequence = latest.rows[0]
        ? parseTurnKey(latest.rows[0].key, prefix).sequence + 1
        : 1;
      const key = buildTurnKey(sessionId, sequence, idHash);
      const record = {
        schema: TURN_SCHEMA,
        session_id: sessionId,
        sequence,
        turn_id_sha256: idHash,
        role,
        observed_at: observedAt,
        source_ref: sourceRef,
        content,
        ...(speaker ? { speaker } : {}),
        ...(imageContext.length ? { image_context: imageContext } : {}),
      };
      const value = canonicalJson(record);
      const saved = await persistMemoryFn({
        company_id: companyId,
        agent_id: agentId,
        key,
        value,
        scope: 'global',
        clearance_level: clearanceLevel,
        memory_type: 'conversation_feed',
        source,
        valid_from: observedAt,
        session_id: sessionId,
        mutation_authority: context.mutationAuthority || context.requestAuthority || 'housekeeper',
        client,
      });
      if (saved?.rejected || !saved?.id) {
        const error = new Error(`session_turn_persist_failed:${saved?.reason || 'memory_id_missing'}`);
        error.persistResult = saved;
        throw error;
      }
      const receipt = await logEventFn(companyId, agentId, 'session_turn_appended', key, {
        session_id: sessionId,
        turn_sequence: sequence,
        turn_id_sha256: idHash,
        role,
        quarantined: Boolean(saved.quarantined),
        memory_id: saved.id,
        live_content_hash: asHex(saved.live_content_hash),
        save_mutation_hash: ledgerHash(saved, 'ledger_commit'),
        binding_mutation_hash: ledgerHash(saved, 'binding_commit'),
        reasoning: 'The native session owner retained one ordered raw turn through the canonical signed memory transaction.',
        source_knowledge: 'Generative Agents observation stream + TiMem L1 + Chronos turn calendar',
      }, null, { client, returnReceipt: true, authority: makeEventAuthority(context) });
      return {
        success: true,
        idempotent: false,
        memory_id: saved.id,
        key,
        session_id: sessionId,
        sequence,
        quarantined: Boolean(saved.quarantined),
        live_content_hash: asHex(saved.live_content_hash),
        save_mutation_hash: ledgerHash(saved, 'ledger_commit'),
        binding_mutation_hash: ledgerHash(saved, 'binding_commit'),
        event_receipt: receipt,
      };
    }, {
      restricted: true,
      client_id: companyId,
      agent_id: agentId,
    });
  }

  async function finalizeSession(input = {}, context = {}) {
    const sessionId = normalizeSessionId(input.session_id ?? input.sessionId);
    const companyId = String(context.companyId || input.company_id || 'hom').trim();
    const agentId = String(context.agentId || input.agent_id || '').trim();
    if (!companyId) throw new Error('session_company_required');
    if (!agentId) throw new Error('session_agent_required');
    const prefix = sessionKeyPrefix(sessionId);
    const turnPattern = sessionKeyLikePattern(sessionId, 'turn:');
    const exchangePattern = sessionKeyLikePattern(sessionId, 'exchange:');
    const finalPattern = sessionKeyLikePattern(sessionId, 'final:');
    const expectedTurnCount = normalizeExpectedTurnCount(
      input.expected_turn_count ?? input.expectedTurnCount,
    );
    const expectedTurnIdHashesSha256 = normalizeExpectedTurnIdHashesSha256(
      input.expected_turn_id_hashes_sha256 ?? input.expectedTurnIdHashesSha256,
    );
    const clearanceLevel = Number(input.clearance_level ?? context.clearanceLevel ?? 1);
    if (!Number.isInteger(clearanceLevel) || clearanceLevel < 1 || clearanceLevel > 12) {
      throw new Error('session_finalization_clearance_invalid');
    }

    return withTransactionFn(async (client) => {
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`${companyId.length}:${companyId}${prefix.length}:${prefix}`],
      );
      const turnsResult = await client.query(
        `SELECT id::text, key, value, agent_id, source, created_at, content_hash, memory_type
           FROM aimos_memories
          WHERE company_id = $1
            AND memory_type IN ('conversation_feed', 'quarantine')
            AND key LIKE $2 ESCAPE '\\'
          ORDER BY key`,
        [companyId, turnPattern],
      );
      if (!turnsResult.rows.length) throw new Error('session_has_no_turns');
      const turns = turnsResult.rows.map((row) => parseTurnRow(row, sessionId));
      for (let index = 0; index < turns.length; index += 1) {
        if (turns[index].sequence !== index + 1) throw new Error('session_turn_sequence_gap');
      }
      const turnIdHashesSha256 = orderedTurnIdHashesSha256(turns);
      if (expectedTurnCount != null && expectedTurnCount !== turns.length) {
        throw new Error('session_finalization_expected_turn_count_mismatch');
      }
      if (expectedTurnIdHashesSha256 != null
        && expectedTurnIdHashesSha256 !== turnIdHashesSha256) {
        throw new Error('session_finalization_expected_turn_id_hashes_mismatch');
      }
      const memoryIds = turns.map((turn) => String(turn.row.id));
      const evidence = await verifyEvidenceFn({ memoryIds, client });
      ensureEvidenceVerified(evidence, memoryIds);
      const leaves = turns.map((turn) => {
        const proof = evidence.proofs.get(String(turn.row.id));
        return {
          sequence: turn.sequence,
          memory_id: String(turn.row.id),
          key: turn.row.key,
          role: turn.record.role,
          observed_at: turn.record.observed_at,
          turn_id_sha256: turn.turnIdHash,
          content_sha256: sha256Hex(Buffer.from(turn.record.content, 'utf8')),
          live_content_hash: proof.live_content_hash,
          save_mutation_hash: proof.save_mutation_hash,
          binding_mutation_hash: proof.binding_mutation_hash,
        };
      });
      const root = sessionMerkleRoot(leaves).toString('hex');
      const key = `${prefix}final:${root}`;
      const exchangeSpecs = buildExchangeSpecs(turns, sessionId);
      const existing = await client.query(
        `SELECT id::text, key, value
           FROM aimos_memories
          WHERE company_id = $1
            AND memory_type = 'session_manifest'
            AND key LIKE $2 ESCAPE '\\'
          ORDER BY key
          LIMIT 2`,
        [companyId, finalPattern],
      );
      if (existing.rows.length > 1) throw new Error('session_finalization_fork');
      const existingExchanges = await client.query(
        `SELECT id::text, key, value, agent_id, source, created_at, content_hash
           FROM aimos_memories
          WHERE company_id = $1
            AND memory_type = 'session_exchange'
            AND key LIKE $2 ESCAPE '\\'
          ORDER BY key`,
        [companyId, exchangePattern],
      );
      const existingExchangeByKey = new Map(existingExchanges.rows.map((row) => [row.key, row]));
      const expectedExchangeKeys = new Set(exchangeSpecs.map((spec) => spec.key));
      if (existingExchanges.rows.some((row) => !expectedExchangeKeys.has(row.key))) {
        throw new Error('session_exchange_composition_conflict');
      }
      const exchangeRows = [];
      for (const spec of exchangeSpecs) {
        const existingExchange = existingExchangeByKey.get(spec.key);
        if (existingExchange) {
          const prior = parseJsonObject(existingExchange.value, 'session_exchange_record_invalid');
          if (canonicalJson(prior) !== canonicalJson(spec.record)) {
            throw new Error('session_exchange_composition_conflict');
          }
          exchangeRows.push(existingExchange);
          continue;
        }
        if (existing.rows[0]) throw new Error('session_exchange_missing_after_finalization');
        const savedExchange = await persistMemoryFn({
          company_id: companyId,
          agent_id: agentId,
          key: spec.key,
          value: canonicalJson(spec.record),
          scope: 'global',
          clearance_level: clearanceLevel,
          memory_type: 'session_exchange',
          source: String(input.source || context.source || 'housekeeper:session-finalization'),
          valid_from: spec.record.valid_from,
          valid_until: spec.record.valid_until,
          session_id: sessionId,
          compression_ratio: 1,
          mutation_authority: 'housekeeper',
          client,
        });
        if (savedExchange?.rejected || !savedExchange?.id) {
          const error = new Error(`session_exchange_persist_failed:${savedExchange?.reason || 'memory_id_missing'}`);
          error.persistResult = savedExchange;
          throw error;
        }
        exchangeRows.push({
          id: savedExchange.id,
          key: spec.key,
          value: canonicalJson(spec.record),
          agent_id: agentId,
        });
      }
      const exchangeIds = exchangeRows.map((row) => String(row.id));
      const exchangeEvidence = exchangeIds.length
        ? await verifyEvidenceFn({ memoryIds: exchangeIds, client })
        : { verified: new Set(), proofs: new Map(), rejected: [] };
      ensureEvidenceVerified(exchangeEvidence, exchangeIds);
      const exchangeLeaves = exchangeRows.map((row, index) => {
        const proof = exchangeEvidence.proofs.get(String(row.id));
        const record = exchangeSpecs[index].record;
        return {
          ordinal: index + 1,
          memory_id: String(row.id),
          key: row.key,
          ...(record.user_sequence == null ? {} : { user_sequence: record.user_sequence }),
          ...(record.assistant_sequence == null ? {} : { assistant_sequence: record.assistant_sequence }),
          ...(Array.isArray(record.turn_sequences) ? { turn_sequences: record.turn_sequences } : {}),
          source_memory_ids: record.source_memory_ids,
          live_content_hash: proof.live_content_hash,
          save_mutation_hash: proof.save_mutation_hash,
          binding_mutation_hash: proof.binding_mutation_hash,
        };
      });
      const exchangeRoot = sessionMerkleRoot(exchangeLeaves).toString('hex');
      if (existing.rows[0]) {
        const prior = parseJsonObject(existing.rows[0].value, 'session_finalization_record_invalid');
        if (existing.rows[0].key !== key
          || prior.schema !== FINALIZATION_SCHEMA
          || prior.session_merkle_root !== root
          || prior.exchange_merkle_root !== exchangeRoot
          || Number(prior.turn_count) !== turns.length
          || (prior.turn_id_hashes_sha256 != null
            && prior.turn_id_hashes_sha256 !== turnIdHashesSha256)
          || Number(prior.exchange_count) !== exchangeLeaves.length) {
          throw new Error('session_finalization_conflict');
        }
        const receipt = await logEventFn(companyId, agentId, 'session_finalization_idempotent_replay', key, {
          session_id: sessionId,
          memory_id: existing.rows[0].id,
          turn_count: turns.length,
          turn_id_hashes_sha256: turnIdHashesSha256,
          exchange_count: exchangeLeaves.length,
          session_merkle_root: root,
          exchange_merkle_root: exchangeRoot,
          canonical_memory_changed: false,
          reasoning: 'The housekeeper observed an exact finalization retry and reused the retained signed session manifest.',
          source_knowledge: 'session-memory-owner.js — deterministic finalization idempotency',
        }, null, { client, returnReceipt: true, authority: makeEventAuthority(context) });
        return {
          success: true,
          idempotent: true,
          memory_id: existing.rows[0].id,
          key,
          session_id: sessionId,
          turn_count: turns.length,
          turn_id_hashes_sha256: turnIdHashesSha256,
          exchange_count: exchangeLeaves.length,
          session_merkle_root: root,
          exchange_merkle_root: exchangeRoot,
          event_receipt: receipt,
        };
      }

      const observedTimes = turns.map((turn) => turn.record.observed_at);
      const manifest = {
        schema: FINALIZATION_SCHEMA,
        session_id: sessionId,
        state: 'finalized',
        turn_count: turns.length,
        turn_id_hashes_sha256: turnIdHashesSha256,
        valid_from: observedTimes[0],
        valid_until: observedTimes.at(-1),
        subject_agent_ids: [...new Set(turns.map((turn) => String(turn.row.agent_id)))].sort(),
        session_merkle_algorithm: 'RFC6962_SHA256_DOMAIN_SEPARATED',
        session_merkle_root: root,
        exchange_count: exchangeLeaves.length,
        exchange_merkle_root: exchangeRoot,
        turns: leaves,
        exchanges: exchangeLeaves,
      };
      const saved = await persistMemoryFn({
        company_id: companyId,
        agent_id: agentId,
        key,
        value: canonicalJson(manifest),
        scope: 'global',
        clearance_level: clearanceLevel,
        memory_type: 'session_manifest',
        source: String(input.source || context.source || 'housekeeper:session-finalization'),
        valid_from: observedTimes[0],
        valid_until: observedTimes.at(-1),
        session_id: sessionId,
        compression_ratio: 1,
        mutation_authority: 'housekeeper',
        client,
      });
      if (saved?.rejected || !saved?.id) {
        const error = new Error(`session_finalization_persist_failed:${saved?.reason || 'memory_id_missing'}`);
        error.persistResult = saved;
        throw error;
      }
      const receipt = await logEventFn(companyId, agentId, 'session_finalized', key, {
        session_id: sessionId,
        memory_id: saved.id,
        turn_count: turns.length,
        turn_id_hashes_sha256: turnIdHashesSha256,
        exchange_count: exchangeLeaves.length,
        session_merkle_root: root,
        exchange_merkle_root: exchangeRoot,
        live_content_hash: asHex(saved.live_content_hash),
        save_mutation_hash: ledgerHash(saved, 'ledger_commit'),
        binding_mutation_hash: ledgerHash(saved, 'binding_commit'),
        raw_turns_retained: true,
        summary_replaced_raw_turns: false,
        reasoning: 'The housekeeper finalized the session only after every retained raw turn passed native provenance verification.',
        source_knowledge: 'Generative Agents source pointers + TiMem L2 closure + Chronos raw/event separation',
      }, null, { client, returnReceipt: true, authority: makeEventAuthority(context) });
      return {
        success: true,
        idempotent: false,
        memory_id: saved.id,
        key,
        session_id: sessionId,
        turn_count: turns.length,
        turn_id_hashes_sha256: turnIdHashesSha256,
        exchange_count: exchangeLeaves.length,
        session_merkle_root: root,
        exchange_merkle_root: exchangeRoot,
        live_content_hash: asHex(saved.live_content_hash),
        save_mutation_hash: ledgerHash(saved, 'ledger_commit'),
        binding_mutation_hash: ledgerHash(saved, 'binding_commit'),
        event_receipt: receipt,
      };
    }, {
      restricted: true,
      client_id: companyId,
      agent_id: agentId,
    });
  }

  async function loadVerifiedTurns(input = {}, context = {}) {
    const sessionId = normalizeSessionId(input.session_id ?? input.sessionId);
    const companyId = String(context.companyId || input.company_id || 'hom').trim();
    const agentId = String(context.agentId || input.agent_id || 'housekeeper').trim();
    const turnPattern = sessionKeyLikePattern(sessionId, 'turn:');
    return withTransactionFn(async (client) => {
      const result = await client.query(
        `SELECT id::text, key, value, agent_id, source, created_at, content_hash, memory_type
           FROM aimos_memories
          WHERE company_id = $1
            AND memory_type IN ('conversation_feed', 'quarantine')
            AND key LIKE $2 ESCAPE '\\'
          ORDER BY key`,
        [companyId, turnPattern],
      );
      if (!result.rows.length) return [];
      const turns = result.rows.map((row) => parseTurnRow(row, sessionId));
      const memoryIds = turns.map((turn) => String(turn.row.id));
      const evidence = await verifyEvidenceFn({ memoryIds, client });
      ensureEvidenceVerified(evidence, memoryIds);
      return turns.map((turn) => ({
        memory_id: String(turn.row.id),
        sequence: turn.sequence,
        role: turn.record.role,
        content: turn.record.content,
        observed_at: turn.record.observed_at,
        source_ref: turn.record.source_ref ?? null,
        speaker: turn.record.speaker ?? null,
        image_context: turn.record.image_context ?? [],
      }));
    }, {
      restricted: true,
      client_id: companyId,
      agent_id: agentId,
    });
  }

  return Object.freeze({ appendTurn, finalizeSession, loadVerifiedTurns });
}

export const sessionMemoryOwner = createSessionMemoryOwner();

export const SESSION_MEMORY_CONSTANTS = Object.freeze({
  TURN_SCHEMA,
  EXCHANGE_SCHEMA,
  ORDERED_EXCHANGE_SCHEMA,
  FINALIZATION_SCHEMA,
  TURN_SEQUENCE_WIDTH,
  TURN_ROLES: [...TURN_ROLES],
  MAX_SPEAKER_BYTES,
  MAX_IMAGE_CONTEXT_ITEMS,
});
