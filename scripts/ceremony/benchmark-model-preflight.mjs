#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs';
import { mkdir, open, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { pool, agentPool } from '../../db/connection.js';
import { appendIntegrationToken, getLatestIntegrationToken } from '../../services/integrations/identity-vault.js';
import { canonicalJson, verifyStoredPayloadSig } from '../../services/security/agent-identity.js';
import { loadCredentialCache } from '../../services/security/credential-cache.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { systemConfigStore } from '../../services/security/system-config-store.js';
import { logEvent, readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { listProviderModels, runProvider } from '../../services/core/providers.js';
import {
  AIMOS_COMPANY_ID,
  resolveAimosDatabaseName,
} from '../../services/core/runtime-config.js';

const BRAIN_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const LIVE = process.argv.includes('--live');
const GENERATOR_MODEL = String(cliValue('--generator-model') || 'gpt-5.4').trim();
const JUDGE_MODEL = 'gpt-5.6-terra';
const MIN_ACCESS_TOKEN_REMAINING_SECONDS = 24 * 60 * 60;
const MAX_AUTH_FILE_BYTES = 64 * 1024;
const MAX_MODELS_CACHE_BYTES = 2 * 1024 * 1024;
const MAX_SMOKE_ATTEMPTS = 3;
const execFileAsync = promisify(execFile);
const MODEL_PRICING = Object.freeze({
  'gpt-5.4': Object.freeze({ input: 2.50, cached_input: 0.25, output: 15.00 }),
  'gpt-5.5': Object.freeze({ input: 5.00, cached_input: 0.50, output: 30.00 }),
  'gpt-5.6-terra': Object.freeze({ input: 2.50, cached_input: 0.25, output: 15.00 }),
});
const PRICING = Object.freeze({
  currency: 'USD',
  unit: 'one_million_tokens',
  verified_on: '2026-07-21',
  models: Object.freeze({
    [GENERATOR_MODEL]: MODEL_PRICING[GENERATOR_MODEL],
    [JUDGE_MODEL]: MODEL_PRICING[JUDGE_MODEL],
  }),
  sources: Object.freeze({
    [GENERATOR_MODEL]: `https://developers.openai.com/api/docs/models/${GENERATOR_MODEL}`,
    [JUDGE_MODEL]: 'https://developers.openai.com/api/docs/models/gpt-5.6-terra',
  }),
});

const GENERATOR_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['role', 'arithmetic_sum', 'evidence_ids'],
  properties: {
    role: { type: 'string', enum: ['generator_preflight'] },
    arithmetic_sum: { type: 'integer', minimum: 7, maximum: 7 },
    evidence_ids: {
      type: 'array',
      minItems: 1,
      maxItems: 1,
      items: { type: 'string', enum: ['evidence:alpha'] },
    },
  },
});

const JUDGE_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'score', 'cited_evidence_ids', 'reason'],
  properties: {
    verdict: { type: 'string', enum: ['supported'] },
    score: { type: 'integer', minimum: 1, maximum: 1 },
    cited_evidence_ids: {
      type: 'array',
      minItems: 1,
      maxItems: 1,
      items: { type: 'string', enum: ['evidence:wilson-1'] },
    },
    reason: { type: 'string', minLength: 1, maxLength: 240 },
  },
});

const GENERATOR_PROMPT = [
  'This is a deterministic model-access preflight.',
  'Return the schema-constrained object with role generator_preflight, arithmetic_sum 7,',
  'and evidence_ids containing only evidence:alpha.',
].join(' ');

const JUDGE_PROMPT = [
  'Judge only this supplied evidence.',
  'Evidence evidence:wilson-1 states: Wilson stored the blue notebook in cabinet seven.',
  'Candidate: Wilson stored the blue notebook in cabinet seven.',
  'Return verdict supported, score 1, cite only evidence:wilson-1, and give a brief reason.',
].join(' ');

function cliValue(name) {
  const inline = process.argv.find((arg) => arg.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalSha256(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

async function sha256FileHandle(handle) {
  const hash = createHash('sha256');
  for await (const chunk of handle.createReadStream({ autoClose: false })) {
    hash.update(chunk);
  }
  return hash.digest('hex');
}

async function readCodexCompatibility(binaryPath, modelsCachePath) {
  const binaryHandle = await open(binaryPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let binarySha256;
  try {
    const stat = await binaryHandle.stat();
    if (!stat.isFile()) throw new Error('codex_client_binary_not_regular_file');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
      throw new Error('codex_client_binary_owner_mismatch');
    }
    if ((stat.mode & 0o111) === 0) throw new Error('codex_client_binary_not_executable');
    binarySha256 = await sha256FileHandle(binaryHandle);
  } finally {
    await binaryHandle.close();
  }

  const { stdout, stderr } = await execFileAsync(binaryPath, ['--version'], {
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 4096,
  });
  if (String(stderr || '').trim()) throw new Error('codex_client_version_wrote_stderr');
  const versionOutput = String(stdout || '').trim();
  const versionMatch = /^codex-cli (\d+\.\d+\.\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(versionOutput);
  if (!versionMatch) throw new Error('codex_client_version_output_malformed');
  const backendCompatibilityVersion = versionMatch[1];

  const cacheHandle = await open(modelsCachePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let cacheRaw;
  let cacheSha256;
  try {
    const stat = await cacheHandle.stat();
    if (!stat.isFile()) throw new Error('codex_models_cache_not_regular_file');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
      throw new Error('codex_models_cache_owner_mismatch');
    }
    if (stat.size < 2 || stat.size > MAX_MODELS_CACHE_BYTES) {
      throw new Error('codex_models_cache_size_invalid');
    }
    cacheRaw = await cacheHandle.readFile();
    cacheSha256 = sha256(cacheRaw);
  } finally {
    await cacheHandle.close();
  }
  let cache;
  try {
    cache = JSON.parse(cacheRaw.toString('utf8'));
  } catch {
    throw new Error('codex_models_cache_json_malformed');
  }
  const cachedCompatibilityVersion = String(cache?.client_version || '').trim();
  if (cachedCompatibilityVersion !== backendCompatibilityVersion) {
    throw new Error('codex_client_compatibility_sources_disagree');
  }

  return Object.freeze({
    binaryPath,
    binarySha256,
    binaryVersion: versionMatch[0].slice('codex-cli '.length),
    backendCompatibilityVersion,
    modelsCachePath,
    modelsCacheSha256: cacheSha256,
  });
}

function decodeJwtPayload(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('codex_access_token_is_not_a_jwt');
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid');
    return payload;
  } catch {
    throw new Error('codex_access_token_payload_is_malformed');
  }
}

async function readProtectedCodexAuth(authPath) {
  const handle = await open(authPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('codex_auth_source_not_regular_file');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
      throw new Error('codex_auth_source_owner_mismatch');
    }
    if ((stat.mode & 0o077) !== 0) throw new Error('codex_auth_source_permissions_not_private');
    if (stat.size < 2 || stat.size > MAX_AUTH_FILE_BYTES) throw new Error('codex_auth_source_size_invalid');
    const raw = await handle.readFile();
    let parsed;
    try {
      parsed = JSON.parse(raw.toString('utf8'));
    } catch {
      throw new Error('codex_auth_source_json_malformed');
    }
    const accessToken = String(parsed?.tokens?.access_token || '');
    const refreshToken = String(parsed?.tokens?.refresh_token || '');
    const accountId = String(parsed?.tokens?.account_id || '').trim();
    const authMode = String(parsed?.auth_mode || '').trim().toLowerCase();
    if (!accessToken || !refreshToken || !accountId || !authMode) {
      throw new Error('codex_auth_source_incomplete');
    }
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(accountId)) {
      throw new Error('codex_auth_account_id_malformed');
    }
    const claims = decodeJwtPayload(accessToken);
    const claimAccountId = String(claims?.['https://api.openai.com/auth']?.chatgpt_account_id || '').trim();
    if (!claimAccountId || claimAccountId !== accountId) {
      throw new Error('codex_auth_account_claim_mismatch');
    }
    const expiresAtSeconds = Number(claims.exp);
    if (!Number.isSafeInteger(expiresAtSeconds) || expiresAtSeconds <= 0) {
      throw new Error('codex_auth_access_expiry_missing');
    }
    const remainingSeconds = expiresAtSeconds - Math.floor(Date.now() / 1000);
    if (remainingSeconds < MIN_ACCESS_TOKEN_REMAINING_SECONDS) {
      throw new Error(`codex_auth_access_lifetime_below_${MIN_ACCESS_TOKEN_REMAINING_SECONDS}_seconds`);
    }
    const lastRefresh = parsed?.last_refresh ? new Date(parsed.last_refresh) : null;
    if (lastRefresh && !Number.isFinite(lastRefresh.getTime())) {
      throw new Error('codex_auth_last_refresh_malformed');
    }
    return {
      accessToken,
      refreshToken,
      accountId,
      accountIdSha256: sha256(Buffer.from(accountId, 'utf8')),
      authMode,
      accessExpiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
      remainingSeconds,
      lastRefresh: lastRefresh?.toISOString() || null,
      sourceSha256: sha256(raw),
      sourceMode: (stat.mode & 0o777).toString(8).padStart(3, '0'),
    };
  } finally {
    await handle.close();
  }
}

function safeCredentialUseEvidence(evidence) {
  if (!evidence) return null;
  const mutationHash = String(evidence.terminalMutationHash || '').toLowerCase();
  if (!evidence.useId || !evidence.terminalProvenanceId || !/^[0-9a-f]{64}$/.test(mutationHash)) {
    throw new Error('credential_use_terminal_evidence_missing');
  }
  return {
    use_id: String(evidence.useId),
    terminal_provenance_id: String(evidence.terminalProvenanceId),
    terminal_mutation_hash: mutationHash,
    outcome: String(evidence.outcome || ''),
  };
}

function requireUsage(usage) {
  if (!usage
      || !Number.isSafeInteger(usage.inputTokens)
      || !Number.isSafeInteger(usage.outputTokens)
      || !Number.isSafeInteger(usage.totalTokens)) {
    throw new Error('codex_response_usage_missing');
  }
  return usage;
}

function apiEquivalentCost(usage, model) {
  const valid = requireUsage(usage);
  const pricing = MODEL_PRICING[model];
  if (!pricing) throw new Error(`model_pricing_missing:${model}`);
  const cached = Number.isSafeInteger(valid.cachedInputTokens) ? valid.cachedInputTokens : 0;
  const uncached = Math.max(valid.inputTokens - cached, 0);
  return Number((
    (uncached * pricing.input)
    + (cached * pricing.cached_input)
    + (valid.outputTokens * pricing.output)
  ).toFixed(8)) / 1_000_000;
}

function parseStrictJson(text, label) {
  const serialized = String(text || '').trim();
  if (!serialized.startsWith('{') || !serialized.endsWith('}')) {
    throw new Error(`${label}_response_not_bare_json`);
  }
  try {
    const parsed = JSON.parse(serialized);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid');
    return parsed;
  } catch {
    throw new Error(`${label}_response_json_malformed`);
  }
}

function validateGeneratorOutput(output) {
  if (canonicalJson(output) !== canonicalJson({
    role: 'generator_preflight',
    arithmetic_sum: 7,
    evidence_ids: ['evidence:alpha'],
  })) {
    throw new Error('generator_preflight_semantic_contract_failed');
  }
}

function validateJudgeOutput(output) {
  if (output?.verdict !== 'supported'
      || output?.score !== 1
      || !Array.isArray(output?.cited_evidence_ids)
      || output.cited_evidence_ids.length !== 1
      || output.cited_evidence_ids[0] !== 'evidence:wilson-1'
      || typeof output?.reason !== 'string'
      || !output.reason.trim()) {
    throw new Error('judge_preflight_semantic_contract_failed');
  }
}

function safeCallEvidence({ role, requestedModel, reasoningEffort, prompt, schema, response, output, latencyMs }) {
  if (response.model !== requestedModel) {
    throw new Error(`${role}_model_substitution_detected:${response.model || 'missing'}`);
  }
  if (response.status !== 'completed' || !response.responseId) {
    throw new Error(`${role}_response_evidence_incomplete`);
  }
  const usage = requireUsage(response.usage);
  return {
    role,
    requested_model: requestedModel,
    actual_model: response.model,
    reasoning_effort: reasoningEffort,
    response_id: response.responseId,
    response_status: response.status,
    latency_ms: latencyMs,
    prompt_sha256: sha256(Buffer.from(prompt, 'utf8')),
    schema_sha256: canonicalSha256(schema),
    output_sha256: canonicalSha256(output),
    validated_output: output,
    usage,
    transport_diagnostics: response.diagnostics,
    api_equivalent_cost_usd: apiEquivalentCost(usage, requestedModel),
    credential_use: safeCredentialUseEvidence(response.credentialUseEvidence),
  };
}

function receiptPath() {
  const requested = cliValue('--receipt-file');
  const output = requested
    ? path.resolve(requested)
    : path.join(BRAIN_ROOT, 'eval', 'public-results', 'model-preflight', `${new Date().toISOString().replaceAll(/[:.]/g, '')}.json`);
  const relative = path.relative(BRAIN_ROOT, output);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('benchmark_model_preflight_receipt_must_remain_under_brain_root');
  }
  return output;
}

function decodeCertClaims(certString) {
  const serialized = String(certString || '');
  try {
    const parsed = JSON.parse(serialized);
    return parsed?.body || parsed;
  } catch {
    const parsed = JSON.parse(Buffer.from(serialized, 'base64url').toString('utf8'));
    return parsed?.body || parsed;
  }
}

async function writeExclusiveJson(outputPath, value) {
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  const handle = await open(outputPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
  try {
    await handle.writeFile(serialized, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  return sha256(Buffer.from(serialized, 'utf8'));
}

async function runSmokeCall({ role, model, reasoningEffort, prompt, schema, validate }) {
  for (let attempt = 1; attempt <= MAX_SMOKE_ATTEMPTS; attempt += 1) {
    const startedAt = Date.now();
    try {
      const response = await runProvider({
        provider: 'codex',
        model,
        systemPrompt: 'Follow the strict response schema. Use only evidence explicitly supplied by the user.',
        userPrompt: prompt,
        reasoningEffort,
        textVerbosity: 'low',
        responseSchema: { name: `${role}_preflight`, schema },
        returnMetadata: true,
        useContext: { subjectAgentId: 'housekeeper' },
      });
      const output = parseStrictJson(response.text, role);
      validate(output);
      if (attempt > 1) {
        console.log(JSON.stringify({
          event: 'benchmark_model_preflight_smoke_recovered',
          role,
          model,
          attempt,
        }));
      }
      return safeCallEvidence({
        role,
        requestedModel: model,
        reasoningEffort,
        prompt,
        schema,
        response,
        output,
        latencyMs: Date.now() - startedAt,
      });
    } catch (error) {
      const message = String(error?.message || error);
      const retryable = /Codex response was empty|Codex response ended with status incomplete|Codex error \((?:408|409|425|429|5\d\d)\)|fetch failed|AbortError|timeout|ECONNRESET|ETIMEDOUT/i.test(message);
      console.error(JSON.stringify({
        event: 'benchmark_model_preflight_smoke_failed',
        role,
        model,
        attempt,
        max_attempts: MAX_SMOKE_ATTEMPTS,
        retryable,
        error: message.slice(0, 1200),
      }));
      if (!retryable || attempt === MAX_SMOKE_ATTEMPTS) throw error;
      await new Promise((resolve) => setTimeout(resolve, 750 * attempt));
    }
  }
  throw new Error(`${role}_preflight_attempts_exhausted`);
}

async function main() {
  if (!['gpt-5.4', 'gpt-5.5'].includes(GENERATOR_MODEL)) {
    throw new Error(`unsupported_benchmark_generator_model:${GENERATOR_MODEL}`);
  }
  const databaseName = resolveAimosDatabaseName();
  if (databaseName !== 'aimos') {
    throw new Error('benchmark_model_preflight_requires_canonical_aimos_database');
  }
  const authPath = path.resolve(cliValue('--auth-file') || path.join(os.homedir(), '.codex', 'auth.json'));
  const codexBinaryPath = path.resolve(
    cliValue('--codex-binary') || '/Applications/ChatGPT.app/Contents/Resources/codex',
  );
  const modelsCachePath = path.resolve(
    cliValue('--models-cache') || path.join(os.homedir(), '.codex', 'models_cache.json'),
  );
  const auth = await readProtectedCodexAuth(authPath);
  const codexClient = await readCodexCompatibility(codexBinaryPath, modelsCachePath);
  const dryRun = {
    mode: LIVE ? 'LIVE' : 'DRY_RUN',
    database: databaseName,
    provider: 'codex',
    auth_source: {
      source_sha256: auth.sourceSha256,
      mode: auth.sourceMode,
      auth_mode: auth.authMode,
      account_id_sha256: auth.accountIdSha256,
      access_expires_at: auth.accessExpiresAt,
      access_remaining_seconds: auth.remainingSeconds,
      refresh_token_present: Boolean(auth.refreshToken),
    },
    codex_client: {
      binary_version: codexClient.binaryVersion,
      binary_sha256: codexClient.binarySha256,
      backend_compatibility_version: codexClient.backendCompatibilityVersion,
      models_cache_sha256: codexClient.modelsCacheSha256,
    },
    required_models: [
      { model: GENERATOR_MODEL, role: 'generator', reasoning_effort: 'medium' },
      { model: JUDGE_MODEL, role: 'judge', reasoning_effort: 'high' },
    ],
    external_calls_if_live: 3,
  };
  console.log(JSON.stringify(dryRun, null, 2));
  if (!LIVE) return;

  const configLoad = await systemConfigStore.loadAll();
  if (!configLoad.ok) throw new Error(`system_config_store_load_failed:${configLoad.reason}`);
  await loadCredentialCache();

  const enrollmentMetadata = {
    account_id: auth.accountId,
    account_id_sha256: auth.accountIdSha256,
    auth_mode: auth.authMode,
    client_version: codexClient.backendCompatibilityVersion,
    client_binary_version: codexClient.binaryVersion,
    client_binary_sha256: codexClient.binarySha256,
    source_kind: 'codex_desktop_oauth_import',
    source_file_sha256: auth.sourceSha256,
    source_last_refresh: auth.lastRefresh,
  };
  const existing = await getLatestIntegrationToken(AIMOS_COMPANY_ID, 'codex');
  const reuseExistingLifecycle = Boolean(
    existing?.credential_integrity
    && existing.access_token_hash === sha256(Buffer.from(auth.accessToken, 'utf8'))
    && existing.refresh_token_hash === sha256(Buffer.from(auth.refreshToken, 'utf8'))
    && canonicalJson(existing.metadata) === canonicalJson(enrollmentMetadata)
    && existing.access_token_checkout?.effectiveMutationHash
    && existing.refresh_token_checkout?.effectiveMutationHash,
  );
  const enrollment = reuseExistingLifecycle
    ? {
      expires_at: existing.expires_at ? new Date(existing.expires_at).toISOString() : null,
      access_lifecycle_mutation_hash: existing.access_token_checkout.effectiveMutationHash,
      refresh_lifecycle_mutation_hash: existing.refresh_token_checkout.effectiveMutationHash,
    }
    : await appendIntegrationToken({
      companyId: AIMOS_COMPANY_ID,
      provider: 'codex',
      accessToken: auth.accessToken,
      refreshToken: auth.refreshToken,
      expiresAt: auth.accessExpiresAt,
      metadata: enrollmentMetadata,
      authType: 'oauth',
      initiatingSubjectAgentId: 'housekeeper',
    });

  const materialized = await getLatestIntegrationToken(AIMOS_COMPANY_ID, 'codex');
  if (!materialized?.credential_integrity
      || materialized.metadata?.account_id_sha256 !== auth.accountIdSha256
      || materialized.metadata?.account_id !== auth.accountId
      || materialized.metadata?.client_version !== codexClient.backendCompatibilityVersion
      || materialized.metadata?.client_binary_sha256 !== codexClient.binarySha256
      || materialized.access_token_hash !== sha256(Buffer.from(auth.accessToken, 'utf8'))
      || materialized.refresh_token_hash !== sha256(Buffer.from(auth.refreshToken, 'utf8'))) {
    throw new Error('codex_identity_vault_postcondition_failed');
  }

  const catalog = await listProviderModels('codex', {
    subjectAgentId: 'housekeeper',
    includeCredentialUseEvidence: true,
  });
  if (!catalog.available) throw new Error(`codex_live_catalog_failed:${catalog.error || 'unknown'}`);
  const requiredCatalog = [GENERATOR_MODEL, JUDGE_MODEL].map((modelId) => {
    const model = catalog.models.find((entry) => entry.modelId === modelId);
    if (!model) throw new Error(`required_codex_model_absent:${modelId}`);
    if (!model.supportedInApi) throw new Error(`required_codex_model_not_supported_in_api:${modelId}`);
    const requiredEffort = modelId === GENERATOR_MODEL ? 'medium' : 'high';
    if (!model.reasoningEffortOptions.includes(requiredEffort)) {
      throw new Error(`required_codex_reasoning_effort_absent:${modelId}:${requiredEffort}`);
    }
    return model;
  });

  const generator = await runSmokeCall({
    role: 'generator',
    model: GENERATOR_MODEL,
    reasoningEffort: 'medium',
    prompt: GENERATOR_PROMPT,
    schema: GENERATOR_SCHEMA,
    validate: validateGeneratorOutput,
  });
  const judge = await runSmokeCall({
    role: 'judge',
    model: JUDGE_MODEL,
    reasoningEffort: 'high',
    prompt: JUDGE_PROMPT,
    schema: JUDGE_SCHEMA,
    validate: validateJudgeOutput,
  });

  const enrollmentEvidence = {
    access_lifecycle_mutation_hash: enrollment.access_lifecycle_mutation_hash,
    refresh_lifecycle_mutation_hash: enrollment.refresh_lifecycle_mutation_hash,
    access_credential_hash: materialized.access_token_hash,
    refresh_credential_hash: materialized.refresh_token_hash,
    expires_at: enrollment.expires_at,
    account_id_sha256: auth.accountIdSha256,
    lifecycle_reused: reuseExistingLifecycle,
  };
  const catalogEvidence = {
    client_version: codexClient.backendCompatibilityVersion,
    required_models: requiredCatalog,
    returned_model_count: catalog.models.length,
    credential_use: safeCredentialUseEvidence(catalog.credentialUseEvidence),
  };
  const costEvidence = {
    billing_lane: 'chatgpt_subscription_oauth',
    api_equivalent_pricing: PRICING,
    api_equivalent_smoke_cost_usd: Number((
      generator.api_equivalent_cost_usd + judge.api_equivalent_cost_usd
    ).toFixed(8)),
    note: 'This is an API-price equivalent for comparison; subscription billing is not asserted as API metering.',
  };
  const evidenceRoot = canonicalSha256({
    enrollment: enrollmentEvidence,
    catalog: catalogEvidence,
    calls: [generator, judge],
    cost: costEvidence,
  });
  const ledgerReceipt = await logEvent(
    AIMOS_COMPANY_ID,
    'housekeeper',
    'benchmark_model_preflight_completed',
    evidenceRoot,
    {
      evidence_root_sha256: evidenceRoot,
      account_id_sha256: auth.accountIdSha256,
      generator_model: GENERATOR_MODEL,
      generator_response_id: generator.response_id,
      judge_model: JUDGE_MODEL,
      judge_response_id: judge.response_id,
      reasoning: 'The housekeeper verified the exact generator and judge through the live Codex catalog and strict schema-bound smoke calls before benchmark execution.',
    },
    null,
    { returnReceipt: true },
  );
  const verifiedEvent = await readVerifiedEventById(ledgerReceipt.event_id, AIMOS_COMPANY_ID);
  const ledgerMutationHash = Buffer.from(verifiedEvent.mutation_hash).toString('hex');
  if (ledgerMutationHash !== ledgerReceipt.mutation_hash) {
    throw new Error('benchmark_model_preflight_event_verification_failed');
  }

  const packageJson = JSON.parse(await readFile(path.join(BRAIN_ROOT, 'package.json'), 'utf8'));
  const receiptBody = {
    schema_version: 'aimos.benchmark-model-preflight/v1',
    ceremony_id: randomUUID(),
    company_id: AIMOS_COMPANY_ID,
    database: databaseName,
    software_release: `HOM-AIMOS/${packageJson.version}`,
    auth_source: {
      source_sha256: auth.sourceSha256,
      source_mode: auth.sourceMode,
      auth_mode: auth.authMode,
      account_id_sha256: auth.accountIdSha256,
      access_expires_at: auth.accessExpiresAt,
      refresh_token_present: true,
    },
    codex_client: {
      binary_version: codexClient.binaryVersion,
      binary_sha256: codexClient.binarySha256,
      backend_compatibility_version: codexClient.backendCompatibilityVersion,
      models_cache_sha256: codexClient.modelsCacheSha256,
    },
    enrollment: enrollmentEvidence,
    catalog: catalogEvidence,
    calls: [generator, judge],
    cost: costEvidence,
    evidence_root_sha256: evidenceRoot,
    ledger_event: {
      event_id: ledgerReceipt.event_id,
      ledger_seq: ledgerReceipt.ledger_seq,
      content_hash: ledgerReceipt.content_hash,
      mutation_hash: ledgerReceipt.mutation_hash,
      prev_mutation_hash: ledgerReceipt.prev_mutation_hash,
      signer_agent_id: ledgerReceipt.signer_agent_id,
      signer_valid_from: ledgerReceipt.signer_valid_from,
      cert_fingerprint: ledgerReceipt.cert_fingerprint,
    },
  };
  const signed = await signAsHousekeeper(receiptBody);
  const certClaims = decodeCertClaims(signed.certString);
  const signatureProof = verifyStoredPayloadSig(
    certClaims.pubkey,
    signed.body,
    signed.nonce,
    signed.signedTs,
    signed.sigB64u,
  );
  if (!signatureProof.valid) throw new Error(`benchmark_model_preflight_receipt_signature_invalid:${signatureProof.reason}`);
  const envelope = {
    body: signed.body,
    proof: {
      signer_agent_id: signed.agentId,
      signer_valid_from: signed.validFromIso,
      identity_tier: signed.identityTier,
      cert_fingerprint: sha256(Buffer.from(signed.certString, 'utf8')),
      nonce: signed.nonce,
      ts_signed: signed.signedTs,
      signature: signed.sigB64u,
    },
    verification: {
      receipt_signature_valid: true,
      ledger_event_valid: true,
      credential_lifecycle_binding_valid: true,
      model_catalog_exact_match: true,
      structured_smoke_calls_valid: true,
    },
  };
  const outputPath = receiptPath();
  const receiptSha256 = await writeExclusiveJson(outputPath, envelope);
  console.log(JSON.stringify({
    success: true,
    receipt: outputPath,
    receipt_sha256: receiptSha256,
    ceremony_id: signed.body.ceremony_id,
    evidence_root_sha256: evidenceRoot,
    external_calls: 3,
  }, null, 2));
}

main()
  .catch((error) => {
    console.error(`[benchmark-model-preflight] ${error?.message || String(error)}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await Promise.allSettled([pool.end(), agentPool.end()]);
  });
