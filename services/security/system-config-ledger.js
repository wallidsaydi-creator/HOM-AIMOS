// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live 2026-07-05 (Phase 1) — replaces `process.env.EXECUTIVE_AGENT_ID`
// + every hardcoded `'reviewer'` default for system-level config with a signed,
// hash-chained, replay-protected delegation record. The HOM architecture is
// "Three Orthogonal Guarantees" — every state mutation is signed, hash-
// chained, auditable. Env vars + hardcoded agent defaults are silently
// editable, unsigned, unchained, operator-specific — exactly the drift the
// architecture prevents. This ledger puts operator delegation in the same
// audit plane as the mutations it authorizes.
//
// Agent-free architecture: the system has NO identity. This ledger is the
// operator's tool to designate the privileged runner (OPERATOR_AGENT_ID).
// The signer is the operator's MASTER identity (the trust root, universally
// enrollable), NOT a fixed system cert. Any operator can enroll a master +
// delegate their own operator agent — the reviewer test passes.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * system-config-ledger.js — cert-enveloped delegation ledger for system config
 *
 * Each row in `aimos_system_config` (migration 028) is one signed delegation
 * event for a config_key. The latest row per config_key is the live config
 * state. Delegating = appending a signed row (NEVER UPDATE/DELETE — Aladdin).
 *
 * Signing identity: the operator's MASTER identity (enrolled via
 * enroll-master.js, privkey encrypted in macOS keychain). The master is the
 * trust root — NOT an agent, NOT a system identity. Universally enrollable.
 *
 * Mirrors governor-config-ledger.js but:
 *   . value_text text (string-valued, not boolean) — supports arbitrary
 *     delegation values (agent_id, alias list, etc.).
 *   . signer is the operator's master identity (loaded + decrypted by the
 *     CLI, passed in as `masterPrivkeyB64u`). The ledger service does NOT
 *     do keychain I/O — that's the CLI's job. The service is pure crypto +
 *     DB.
 *   . readConfigString returns string | null (distinguishes "no row" from
 *     "row with empty value").
 *   . fail-to-null semantics (no row → null → callers handle null
 *     explicitly, no fallback to any hardcoded agent).
 *
 * Chain shape (mirrors 025 + 018 + 021, keyed on config_key):
 *   . ONE GENESIS PER config_key (partial unique index)
 *   . NO FORK-RACE on prev link (partial unique index)
 *   . CONSISTENCY is_genesis ⟺ prev IS NULL (CHECK)
 *   . NONCE UNIQUENESS (replay protection)
 *   . mutation_hash = sha256(content_hash || prev_mutation_hash || nonce || ts)
 *
 * Reader cache (mirrors governor-config-ledger): 30s TTL in-memory Map.
 * The systemConfigStore (load-once at boot + SIGHUP-reload) is the runtime
 * reader; this ledger's readConfigString is the uncached DB path for CLIs
 * + tests.
 */

import crypto from 'node:crypto';
import { createHash } from 'node:crypto';
import { signPayload, canonicalJson } from './agent-identity.js';
import { contentHash } from './identity-chain.js';
import { pool as defaultPool } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';
import {
  AIMOS_COMPANY_ID,
  validateAimosHttpOrigin,
} from '../core/runtime-config.js';

const COMPANY = AIMOS_COMPANY_ID;

export const SYSTEM_CONFIG_DEFINITIONS = Object.freeze({
  OPERATOR_AGENT_ID: Object.freeze({ type: 'agent_id', allowEmpty: true }),
  EXECUTIVE_AGENT_ALIASES: Object.freeze({ type: 'agent_alias_list', allowEmpty: true }),
  // Local same-process code should use native runtime facts. This signed value
  // is reserved for retained external AIMOS clients and must remain an origin.
  AIMOS_BASE_URL: Object.freeze({ type: 'aimos_http_origin', allowEmpty: true }),
  // Mutable Sentinel lock state is master-signed and append-only. Absence of a
  // row means the optional cybersecurity workflow is not administratively
  // locked; a present value must be an exact signed boolean.
  SENTINEL_LOCKED: Object.freeze({ type: 'boolean', allowEmpty: false }),

  // Provider selection and model routing are mutable operational authority.
  LLM_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  LLM_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  AIMOS_INGEST_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  AIMOS_INGEST_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  AIMOS_RETRIEVAL_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  AIMOS_RETRIEVAL_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  DEFAULT_AGENT_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  FAST_LANE_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  CEO_PRIMARY_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  CEO_FALLBACK_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  RECOVERY_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  ANTHROPIC_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  OLLAMA_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  LMSTUDIO_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  GEMINI_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  PERPLEXITY_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  OPENAI_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  CODEX_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  OPENROUTER_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  GROQ_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  DEEPSEEK_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  TOGETHER_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  XAI_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  VENICE_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  ANTHROPIC_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  OLLAMA_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  LMSTUDIO_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  GEMINI_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  PERPLEXITY_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  OPENAI_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  CODEX_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  OPENROUTER_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  GROQ_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  DEEPSEEK_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  TOGETHER_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  XAI_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),
  VENICE_MODEL_HINTS: Object.freeze({ type: 'model_list', allowEmpty: true }),

  // Non-secret provider endpoints and OAuth registration metadata.
  ANTHROPIC_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  OLLAMA_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  LMSTUDIO_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  OPENAI_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  CODEX_CHATGPT_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  OPENROUTER_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  GROQ_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  DEEPSEEK_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  TOGETHER_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  XAI_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  VENICE_BASE_URL: Object.freeze({ type: 'http_url', allowEmpty: true }),
  OPENAI_OAUTH_ISSUER: Object.freeze({ type: 'http_url', allowEmpty: true }),
  CODEX_OAUTH_ISSUER: Object.freeze({ type: 'http_url', allowEmpty: true }),
  GOOGLE_CLIENT_ID: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  GITHUB_CLIENT_ID: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  SALESFORCE_CLIENT_ID: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  SALESFORCE_ORIGIN: Object.freeze({ type: 'salesforce_origin', allowEmpty: true }),
  OPENAI_CLIENT_ID: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  CODEX_CLIENT_ID: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  GOOGLE_REDIRECT_URI: Object.freeze({ type: 'http_url', allowEmpty: true }),
  GITHUB_REDIRECT_URI: Object.freeze({ type: 'http_url', allowEmpty: true }),
  SALESFORCE_REDIRECT_URI: Object.freeze({ type: 'http_url', allowEmpty: true }),
  CODEX_INTERNAL_ORIGINATOR: Object.freeze({ type: 'bounded_identifier', allowEmpty: true }),
  CODEX_ACCOUNT_ID: Object.freeze({ type: 'bounded_identifier', allowEmpty: true }),
  OPENROUTER_HTTP_REFERER: Object.freeze({ type: 'http_url', allowEmpty: true }),
  OPENROUTER_APP_TITLE: Object.freeze({ type: 'bounded_string', allowEmpty: true }),

  // Filesystem facts, display metadata, and bounded JSON remain signed facts.
  CODEX_AUTH_JSON: Object.freeze({ type: 'absolute_path', allowEmpty: true }),
  CODEX_HOME: Object.freeze({ type: 'absolute_path', allowEmpty: true }),
  MODEL_CONTEXT_WINDOWS_JSON: Object.freeze({ type: 'json_object', allowEmpty: true }),
  CONTEXT_WINDOW_TOKENS: Object.freeze({ type: 'positive_integer', allowEmpty: true }),
  FAST_LANE_MAX_CHARS: Object.freeze({ type: 'positive_integer', allowEmpty: true }),
  CODEX_REASONING_EFFORT: Object.freeze({ type: 'reasoning_effort', allowEmpty: true }),
  CODEX_TEXT_VERBOSITY: Object.freeze({ type: 'text_verbosity', allowEmpty: true }),
  EXECUTIVE_AGENT_NAME: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  EXECUTIVE_DISPLAY_NAME: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  AIMOS_OPERATOR_BRAIN_AGENT_ID: Object.freeze({ type: 'agent_id', allowEmpty: true }),
  AIMOS_OPERATOR_BRAIN_IDENTITY: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  AIMOS_OPERATOR_BRAIN_RUNTIME: Object.freeze({ type: 'bounded_string', allowEmpty: true }),
  TELEGRAM_CHAT_ID: Object.freeze({ type: 'bounded_identifier', allowEmpty: true }),
  YOUTUBE_CHANNEL_ID: Object.freeze({ type: 'bounded_identifier', allowEmpty: true }),

  // Paper-backed recall behavior is off when absent and may only be changed by
  // a master-signed append. The algorithms and their paper-derived constants
  // remain unchanged in the recall owner.
  RECALL_ENABLE_ROLE_DATE_BINDING: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_ENABLE_SPEAKER_ENTITY_BINDING: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_ENABLE_GROUNDING_HINTS: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_ENABLE_AGGREGATE_OPERATOR: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_RELAX_COMPARISON_SUFFICIENCY: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_CACHE_ENABLED: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_EARLY_EXIT_ENABLED: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_QUIM_ENABLED: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_GOVERNANCE_ENABLED: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_INSTRUMENTATION_ENABLED: Object.freeze({ type: 'boolean', allowEmpty: false }),
  RECALL_FRESHNESS_RANKING_ENABLED: Object.freeze({ type: 'boolean', allowEmpty: false }),
  AGENT_RUNNER_DEBUG_PROMPT: Object.freeze({ type: 'boolean', allowEmpty: false }),
  MODEL_PREFERENCE_CHAT: Object.freeze({ type: 'model_preference', allowEmpty: true }),
  MODEL_PREFERENCE_HEAVY: Object.freeze({ type: 'model_preference', allowEmpty: true }),
  MODEL_PREFERENCE_RESEARCH: Object.freeze({ type: 'model_preference', allowEmpty: true }),
  MODEL_PREFERENCE_FAST: Object.freeze({ type: 'model_preference', allowEmpty: true }),
  MODEL_PREFERENCE_CODING: Object.freeze({ type: 'model_preference', allowEmpty: true }),
  // Retained legacy keys: independently committed halves remain verifiable
  // history but are no longer consumed as live model-selection authority.
  MODEL_PREFERENCE_CHAT_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  MODEL_PREFERENCE_CHAT_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  MODEL_PREFERENCE_HEAVY_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  MODEL_PREFERENCE_HEAVY_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  MODEL_PREFERENCE_RESEARCH_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  MODEL_PREFERENCE_RESEARCH_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  MODEL_PREFERENCE_FAST_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  MODEL_PREFERENCE_FAST_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
  MODEL_PREFERENCE_CODING_PROVIDER: Object.freeze({ type: 'provider_id', allowEmpty: true }),
  MODEL_PREFERENCE_CODING_MODEL: Object.freeze({ type: 'model_id', allowEmpty: true }),
});

const AGENT_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
const MODEL_PROVIDER_IDS = new Set([
  'anthropic', 'ollama', 'lmstudio', 'gemini', 'perplexity', 'openai',
  'codex', 'openrouter', 'groq', 'deepseek', 'together', 'xai', 'venice'
]);

export function validateSystemConfigValue(configKey, value) {
  const definition = SYSTEM_CONFIG_DEFINITIONS[configKey];
  if (!definition) return { ok: false, reason: 'unknown_config_key' };
  if (typeof value !== 'string') return { ok: false, reason: 'value_must_be_string' };

  const normalized = value.trim();
  if (!normalized) {
    return definition.allowEmpty
      ? { ok: true, value: '' }
      : { ok: false, reason: 'empty_value' };
  }

  if (definition.type === 'agent_id') {
    return AGENT_ID_RE.test(normalized)
      ? { ok: true, value: normalized }
      : { ok: false, reason: 'invalid_agent_id' };
  }

  if (definition.type === 'agent_alias_list') {
    const aliases = normalized.split(',').map((entry) => entry.trim()).filter(Boolean);
    if (!aliases.length || aliases.some((entry) => !AGENT_ID_RE.test(entry))) {
      return { ok: false, reason: 'invalid_agent_alias_list' };
    }
    return { ok: true, value: [...new Set(aliases)].join(',') };
  }

  if (definition.type === 'aimos_http_origin') {
    return validateAimosHttpOrigin(normalized, configKey);
  }

  if (definition.type === 'boolean') {
    const lower = normalized.toLowerCase();
    return lower === 'true' || lower === 'false'
      ? { ok: true, value: lower }
      : { ok: false, reason: 'invalid_boolean' };
  }

  if (definition.type === 'provider_id') {
    const provider = normalized.toLowerCase();
    return MODEL_PROVIDER_IDS.has(provider)
      ? { ok: true, value: provider }
      : { ok: false, reason: 'invalid_provider_id' };
  }

  if (definition.type === 'model_preference') {
    try {
      const parsed = JSON.parse(normalized);
      const provider = String(parsed?.provider || '').trim().toLowerCase();
      const model = String(parsed?.model || '').trim();
      if (
        !parsed || typeof parsed !== 'object' || Array.isArray(parsed)
        || Object.keys(parsed).some((key) => !['provider', 'model'].includes(key))
        || !MODEL_PROVIDER_IDS.has(provider)
        || !model || model.length > 256 || /[\u0000-\u001f\u007f]/.test(model)
      ) {
        return { ok: false, reason: 'invalid_model_preference' };
      }
      return { ok: true, value: JSON.stringify({ provider, model }) };
    } catch {
      return { ok: false, reason: 'invalid_model_preference' };
    }
  }

  if (definition.type === 'model_id') {
    return normalized.length <= 256 && !/[\u0000-\u001f\u007f]/.test(normalized)
      ? { ok: true, value: normalized }
      : { ok: false, reason: 'invalid_model_id' };
  }

  if (definition.type === 'model_list') {
    const models = normalized.split(',').map((entry) => entry.trim()).filter(Boolean);
    if (!models.length || models.length > 128 || models.some((entry) => entry.length > 256 || /[\u0000-\u001f\u007f]/.test(entry))) {
      return { ok: false, reason: 'invalid_model_list' };
    }
    return { ok: true, value: [...new Set(models)].join(',') };
  }

  if (definition.type === 'http_url') {
    try {
      const parsed = new URL(normalized);
      if (!['http:', 'https:'].includes(parsed.protocol)) return { ok: false, reason: 'invalid_protocol' };
      if (parsed.username || parsed.password) return { ok: false, reason: 'embedded_credentials_forbidden' };
      return { ok: true, value: parsed.toString() };
    } catch {
      return { ok: false, reason: 'invalid_absolute_url' };
    }
  }

  if (definition.type === 'salesforce_origin') {
    try {
      const parsed = new URL(normalized);
      const host = parsed.hostname.toLowerCase();
      const approvedHost = host === 'salesforce.com'
        || host.endsWith('.salesforce.com')
        || host === 'force.com'
        || host.endsWith('.force.com');
      if (
        parsed.protocol !== 'https:'
        || parsed.username
        || parsed.password
        || parsed.port
        || parsed.pathname !== '/'
        || parsed.search
        || parsed.hash
        || !approvedHost
      ) {
        return { ok: false, reason: 'invalid_salesforce_origin' };
      }
      return { ok: true, value: parsed.origin };
    } catch {
      return { ok: false, reason: 'invalid_salesforce_origin' };
    }
  }

  if (definition.type === 'bounded_string') {
    return normalized.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(normalized)
      ? { ok: true, value: normalized }
      : { ok: false, reason: 'invalid_string' };
  }

  if (definition.type === 'bounded_identifier') {
    return /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$/.test(normalized)
      ? { ok: true, value: normalized }
      : { ok: false, reason: 'invalid_identifier' };
  }

  if (definition.type === 'absolute_path') {
    return normalized.startsWith('/') && normalized.length <= 4096 && !/[\u0000\r\n]/.test(normalized)
      ? { ok: true, value: normalized }
      : { ok: false, reason: 'invalid_absolute_path' };
  }

  if (definition.type === 'positive_integer') {
    const number = Number(normalized);
    return Number.isSafeInteger(number) && number > 0
      ? { ok: true, value: String(number) }
      : { ok: false, reason: 'invalid_positive_integer' };
  }

  if (definition.type === 'json_object') {
    try {
      const parsed = JSON.parse(normalized);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return { ok: false, reason: 'invalid_json_object' };
      }
      return { ok: true, value: JSON.stringify(parsed) };
    } catch {
      return { ok: false, reason: 'invalid_json_object' };
    }
  }

  if (definition.type === 'reasoning_effort') {
    return ['none', 'minimal', 'low', 'medium', 'high'].includes(normalized.toLowerCase())
      ? { ok: true, value: normalized.toLowerCase() }
      : { ok: false, reason: 'invalid_reasoning_effort' };
  }

  if (definition.type === 'text_verbosity') {
    return ['low', 'medium', 'high'].includes(normalized.toLowerCase())
      ? { ok: true, value: normalized.toLowerCase() }
      : { ok: false, reason: 'invalid_text_verbosity' };
  }

  return { ok: false, reason: 'unsupported_config_type' };
}

export const SYSTEM_CONFIG_CONSTANTS = Object.freeze({
  // The signer is the operator's MASTER identity (CA / trust-root analog),
  // NOT a fixed system cert. The master is enrolled via enroll-master.js
  // and is universally equal across deployments. The cert fingerprint is
  // looked up from aimos_master_identity at commit time.
  IDENTITY_TIER: 'T0', // master identity is the trust root (T0)
  CACHE_TTL_MS: 30_000,
  ALLOWED_CONFIG_KEYS: Object.freeze(Object.keys(SYSTEM_CONFIG_DEFINITIONS))
});

const DEFAULT_TTL_MS = SYSTEM_CONFIG_CONSTANTS.CACHE_TTL_MS;

// ─── In-memory cache (mirrors governor-config-ledger.js:81-100) ─────────────
const _cache = new Map(); // key: config_key → { value: string|null, fetchedAt: number }

function _cacheGet(configKey, nowFn = Date.now) {
  const hit = _cache.get(configKey);
  if (!hit) return undefined;
  if ((nowFn() - hit.fetchedAt) >= DEFAULT_TTL_MS) {
    _cache.delete(configKey);
    return undefined;
  }
  return hit.value;
}

function _cacheSet(configKey, value, nowFn = Date.now) {
  _cache.set(configKey, { value, fetchedAt: nowFn() });
}

function _cacheInvalidate(configKey) {
  if (configKey) _cache.delete(configKey);
  else _cache.clear();
}

// ─── Hash helpers (mirrors governor-config-ledger.js:103-111) ───────────────
function _tsBuf(ts) { return Buffer.from(String(ts), 'utf8'); }
function _nonceBuf(nonce) { return Buffer.from(nonce, 'utf8'); }

export function computeSystemConfigMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts) {
  const parts = prevMutationHashBuf
    ? [contentHashBuf, prevMutationHashBuf, _nonceBuf(nonce), _tsBuf(ts)]
    : [contentHashBuf, _nonceBuf(nonce), _tsBuf(ts)];
  return createHash('sha256').update(Buffer.concat(parts)).digest();
}

function _validateConfigKey(configKey) {
  if (typeof configKey !== 'string' || configKey.length === 0) return false;
  return SYSTEM_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS.includes(configKey);
}

// ─── Factory (mirrors governor-config-ledger.js:119) ─────────────────────────
export function createSystemConfigLedger(deps = {}) {
  const pool = deps.pool || defaultPool;
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));
  const nowFn = typeof deps.nowFn === 'function' ? deps.nowFn : Date.now;

  async function getLatestMutationHash(configKey) {
    const r = await queryFn(
      `SELECT mutation_hash, value_text
         FROM aimos_system_config
        WHERE config_key = $1
        ORDER BY created_at DESC, config_id DESC
        LIMIT 1`,
      [configKey]
    );
    if (!r || !Array.isArray(r.rows) || r.rows.length === 0) {
      return { prevMutationHash: null, isGenesis: true, prevValue: null };
    }
    const row = r.rows[0];
    return {
      prevMutationHash: row.mutation_hash,
      isGenesis: false,
      prevValue: row.value_text
    };
  }

  /**
   * Read the live config value for a config_key. Returns string | null.
   * No row → null (callers handle null explicitly — no fallback).
   * Fail-closed: DB error → logEvent + return null.
   *
   * This is the uncached DB path. The runtime reader is systemConfigStore
   * (load-once at boot + SIGHUP-reload). This function is for CLIs + tests
   * that need the live DB state without going through the store.
   */
  async function readConfigString(configKey) {
    if (!_validateConfigKey(configKey)) return null;
    const cached = _cacheGet(configKey, nowFn);
    if (cached !== undefined) return cached;

    try {
      const r = await queryFn(
        `SELECT value_text
           FROM aimos_system_config
          WHERE config_key = $1
          ORDER BY created_at DESC, config_id DESC
          LIMIT 1`,
        [configKey]
      );
      if (!r || !Array.isArray(r.rows) || r.rows.length === 0) {
        _cacheSet(configKey, null, nowFn);
        return null;
      }
      const validated = validateSystemConfigValue(configKey, r.rows[0].value_text);
      if (!validated.ok) return null;
      _cacheSet(configKey, validated.value, nowFn);
      return validated.value;
    } catch (err) {
      await logEvent(COMPANY, 'system_config', 'read_failed', configKey, {
        error: String(err?.message || err),
        config_key: configKey
      }).catch(() => {});
      return null; // fail-to-null — callers handle explicitly
    }
  }

  /**
   * Append a signed delegation row. The master privkey is passed in by the
   * CLI (which prompts for the passphrase + decrypts the keychain blob).
   * The ledger service does NOT do keychain I/O — pure crypto + DB.
   *
   * Returns { ok:true, ... } | { ok:false, reason }.
   */
  async function commitConfigValue({
    configKey,
    value,
    reason,
    operator,
    masterPrivkeyB64u,
    masterFingerprint
  } = {}) {
    if (!_validateConfigKey(configKey)) {
      return { ok: false, reason: 'malformed_input' };
    }
    const validatedValue = validateSystemConfigValue(configKey, value);
    if (!validatedValue.ok) {
      return { ok: false, reason: 'invalid_config_value', detail: validatedValue.reason };
    }
    const normalizedValue = validatedValue.value;
    if (typeof reason !== 'string' || reason.length === 0) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (typeof masterPrivkeyB64u !== 'string' || masterPrivkeyB64u.length === 0) {
      return { ok: false, reason: 'master_privkey_required' };
    }
    if (typeof masterFingerprint !== 'string' || masterFingerprint.length === 0) {
      return { ok: false, reason: 'master_fingerprint_required' };
    }

    const { IDENTITY_TIER } = SYSTEM_CONFIG_CONSTANTS;

    const ts = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('base64url');

    // Fetch the latest mutation hash + prev value BEFORE signing so the
    // persisted body_json EXACTLY matches the signed body (signature covers
    // prev_value — audit-trail integrity). A fork-race between this SELECT
    // and the INSERT below returns 'fork_race' to the caller, who retries.
    const { prevMutationHash, isGenesis, prevValue } = await getLatestMutationHash(configKey);

    const body = {
      config_key: configKey,
      value_text: normalizedValue,
      reason,
      operator: operator || 'unknown',
      identity_tier: IDENTITY_TIER,
      ts_signed: ts,
      prev_value: prevValue // signature-covered; persisted body matches signed body
    };

    let sigB64u, sigBytes;
    try {
      sigB64u = signPayload(masterPrivkeyB64u, body, nonce, ts);
      sigBytes = Buffer.from(sigB64u, 'base64url');
      if (sigBytes.length !== 64) {
        throw new Error(`unexpected sig length ${sigBytes.length}`);
      }
    } catch (err) {
      await logEvent(COMPANY, 'system_config', 'sign_failed_skip', configKey, {
        error: String(err?.message || err),
        config_key: configKey
      }).catch(() => {});
      return { ok: false, reason: 'sign_failed' };
    }

    const cHash = contentHash(body);
    // cert_fingerprint = the master pubkey fingerprint (sha256 of the master
    // pubkey, stored in aimos_master_identity.fingerprint). The master has
    // no cert (it IS the CA / trust root), so we use the pubkey fingerprint
    // as the audit-trail identifier. The verify path uses masterPubkeyCache
    // which fetches the same master pubkey.
    const certFingerprint = masterFingerprint;

    for (let attempt = 0; attempt < 2; attempt++) {
      const mutationHash = computeSystemConfigMutationHash(cHash, prevMutationHash, nonce, ts);

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `INSERT INTO aimos_system_config
              (config_key, value_text, cert_fingerprint, content_hash,
               mutation_hash, prev_mutation_hash, ts_signed, nonce, sig,
               is_genesis, body_json)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            configKey, normalizedValue, certFingerprint, cHash,
            mutationHash, prevMutationHash, ts, nonce, sigBytes,
            isGenesis,
            JSON.stringify(body)
          ]
        );
        await client.query('COMMIT');
        _cacheInvalidate(configKey);
        return {
          ok: true,
          contentHash: cHash,
          mutationHash,
          prevMutationHash,
          isGenesis,
          tsSigned: ts,
          certFingerprint
        };
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        if (err.code === '23505' && err.constraint === 'aimos_system_config_one_genesis') {
          if (attempt === 0) {
            // Another writer beat us to genesis. Re-fetch as non-genesis.
            // Re-signing inline would require restructuring; the race is rare.
            return {
              ok: false,
              reason: 'duplicate_genesis',
              detail: 'another writer claimed genesis; retry the CLI call'
            };
          }
          return { ok: false, reason: 'duplicate_genesis' };
        }
        if (err.code === '23505' && err.constraint === 'aimos_system_config_next_unique') {
          return { ok: false, reason: 'fork_race', currentPrev: prevMutationHash };
        }
        if (err.code === '23505' && err.constraint === 'aimos_system_config_nonce_unique') {
          return { ok: false, reason: 'nonce_collision' };
        }
        await logEvent(COMPANY, 'system_config', 'commit_error', configKey, {
          error: String(err?.message || err),
          config_key: configKey
        }).catch(() => {});
        return { ok: false, reason: 'commit_error', detail: String(err?.message || err) };
      } finally {
        client.release();
      }
    }
    return { ok: false, reason: 'retry_exhausted' };
  }

  return {
    readConfigString,
    commitConfigValue,
    _cacheInvalidate,
    _cacheGet,
    _validateConfigKey
  };
}

export const systemConfigLedger = createSystemConfigLedger();

export default systemConfigLedger;
