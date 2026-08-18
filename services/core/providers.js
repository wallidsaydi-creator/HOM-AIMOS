/**
 * providers.js — Model Provider Resolution and Health Engine
 * Source: Circuit Breaker (Netflix Hystrix), Health check patterns
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-tools.js, governance-resolver.js, model-preferences.js
 * 2. → Pulls from: keychain credentials and signed system configuration
 * 3. ↔ Interacts with: provider-native HTTP adapters (no CLI subprocess path)
 * 4. ↔ Interacts with: services/orchestration/http.js (Status checks)
 *
 * LOGIC GUIDE: Manages model-to-provider mapping. Handles key rotation,
 * timeout enforcement, and health monitoring for configured model providers.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-tools.js, governance-resolver.js, model-preferences.js
// Pipeline: AGENT_RUN | Position: Model resolution (provider status check)
// ─────────────────────────────────────────────────────────────────────────────
import { fetchWithTimeout } from '../orchestration/http.js';
import {
  syncIdentityVault as syncIdentityVaultToken
} from '../integrations/identity-vault.js';
import { isCircuitAvailable, recordSuccess as recordCircuitSuccess, recordFailure as recordCircuitFailure, getMaxFailoverAttempts, getCircuitState } from './provider-circuit-breaker.js';
import { recordCallOutcome, getHealthyProviders as getHealthyProvidersByScore } from './provider-health.js';
import { logEvent } from '../observe/event-ledger.js';
import { checkoutCachedCredential, peekCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';
import { AIMOS_COMPANY_ID } from './runtime-config.js';

const PROVIDER_REQUEST_TIMEOUT_MS = 60_000;
const CODEX_REQUEST_TIMEOUT_MS = 180_000;
const COMPANY_ID = AIMOS_COMPANY_ID;
const OLLAMA_BASE_URL = 'http://127.0.0.1:11434';
const LMSTUDIO_BASE_URL = 'http://127.0.0.1:1234/v1';
const CODEX_CHATGPT_BASE_URL = 'https://chatgpt.com/backend-api';
const LOCAL_PROVIDER_CACHE = {
  ollama: { available: false, probing: false, checkedAt: 0 },
  lmstudio: { available: false, probing: false, checkedAt: 0 }
};
const LOCAL_PROVIDER_PROBE_TTL_MS = 15_000;

async function probeLocalProvider(provider) {
  const state = LOCAL_PROVIDER_CACHE[provider];
  if (!state || state.probing) return;
  if (Date.now() - state.checkedAt < LOCAL_PROVIDER_PROBE_TTL_MS) return;

  state.probing = true;
  const url = provider === 'ollama'
    ? `${OLLAMA_BASE_URL}/api/tags`
    : `${LMSTUDIO_BASE_URL}/models`;

  try {
    const response = await fetchWithTimeout(url, { headers: { Accept: 'application/json' } }, 3_000);
    state.available = response.ok;
  } catch {
    state.available = false;
  } finally {
    state.checkedAt = Date.now();
    state.probing = false;
  }
}

function scheduleLocalProviderProbe(provider) {
  probeLocalProvider(provider).catch(() => {});
}

function getLocalProviderAvailability(provider) {
  const state = LOCAL_PROVIDER_CACHE[provider];
  if (!state) return false;
  // First call (checkedAt === 0): optimistic true while probe runs async
  if (state.checkedAt === 0) {
    scheduleLocalProviderProbe(provider);
    return true;
  }
  scheduleLocalProviderProbe(provider);
  return state.available || false;
}

function reasoningEffortOptionsForProvider(providerId) {
  if (['ollama', 'lmstudio'].includes(providerId)) {
    return ['none', 'low', 'medium'];
  }
  return ['minimal', 'low', 'medium', 'high'];
}

function baseModelPayload(providerId, modelId, displayLabel) {
  return {
    providerId,
    modelId,
    displayLabel: displayLabel || modelId,
    available: true,
    hidden: false,
    reasoningEffortOptions: reasoningEffortOptionsForProvider(providerId)
  };
}

function normalizeOpenAiModelPayload(providerId, payload) {
  const modelId = String(payload?.id || '').trim();
  if (!modelId) return null;
  return baseModelPayload(providerId, modelId, payload?.name || payload?.display_name || modelId);
}

export function normalizeCodexModelPayload(payload) {
  const modelId = String(payload?.id || payload?.slug || payload?.model || '').trim();
  if (!modelId) return null;
  const reasoningEffortOptions = Array.isArray(payload?.supported_reasoning_levels)
    ? [...new Set(payload.supported_reasoning_levels
      .map((entry) => String(entry?.effort || entry || '').trim().toLowerCase())
      .filter((effort) => CODEX_REASONING_EFFORTS.includes(effort)))]
    : [];
  const contextWindow = Number(payload?.context_window);
  return {
    ...baseModelPayload('codex', modelId, payload?.name || payload?.display_name || modelId),
    reasoningEffortOptions,
    supportedInApi: payload?.supported_in_api === true,
    contextWindow: Number.isSafeInteger(contextWindow) && contextWindow > 0 ? contextWindow : null,
  };
}

function dedupeModels(models) {
  const deduped = [];
  for (const model of models) {
    if (!deduped.some((item) => item.modelId === model.modelId)) {
      deduped.push(model);
    }
  }
  return deduped;
}

function checkoutGeminiCredential() {
  // A1a: keychain only. Canonical slot is gemini_api_key.
  // Fall back to google_api_key only if gemini not present (transition aid).
  return checkoutCachedCredential('gemini_api_key')
    || checkoutCachedCredential('google_api_key');
}

function hasCodexChatgptAuth() {
  return !!(
    peekCachedCredential('oauth_codex_access_token')
    || peekCachedCredential('codex_api_key')
  );
}

export function resolveCodexAccountBinding(vaultMetadata, configuredValue = '') {
  const vaultAccountId = String(vaultMetadata?.account_id || '').trim();
  const configuredAccountId = String(configuredValue || '').trim();
  if (vaultAccountId && configuredAccountId && vaultAccountId !== configuredAccountId) {
    throw new Error('Codex OAuth account binding conflicts with the signed legacy account configuration.');
  }
  const accountId = vaultAccountId || configuredAccountId;
  if (accountId && !/^[A-Za-z0-9_-]{1,128}$/.test(accountId)) {
    throw new Error('Codex OAuth account binding is malformed.');
  }
  return accountId;
}

export function resolveCodexClientVersion(vaultMetadata) {
  const clientVersion = String(vaultMetadata?.client_version || '').trim();
  if (!/^\d+\.\d+\.\d+$/.test(clientVersion)) {
    throw new Error('Codex backend compatibility version is missing or malformed in the signed OAuth lifecycle.');
  }
  return clientVersion;
}

export function buildCodexModelsRequestUrl(endpoint, clientVersion) {
  const normalizedVersion = resolveCodexClientVersion({ client_version: clientVersion });
  let requestUrl;
  try {
    requestUrl = new URL(endpoint);
  } catch {
    throw new Error('Codex model catalog endpoint is malformed.');
  }
  if (requestUrl.searchParams.has('client_version')) {
    throw new Error('Codex model catalog endpoint already contains client_version.');
  }
  requestUrl.searchParams.set('client_version', normalizedVersion);
  return requestUrl.toString();
}

async function loadCodexChatgptAuth({ requireClientVersion = false } = {}) {
  const vault = await syncIdentityVault('codex');
  const checkout = vault.accessToken
    ? vault.accessCredentialCheckout
    : checkoutCachedCredential('codex_api_key');
  const accessToken = vault.accessToken || checkout?.value || '';
  const accountId = resolveCodexAccountBinding(
    vault.metadata,
    systemConfigStore.readConfigString('CODEX_ACCOUNT_ID'),
  );
  if (!accessToken || !accountId) {
    throw new Error('Codex ChatGPT auth missing. Enroll one signed OAuth lifecycle with its account binding.');
  }
  return {
    accessToken,
    accountId,
    clientVersion: requireClientVersion ? resolveCodexClientVersion(vault.metadata) : null,
    credentialCheckout: checkout,
    source: vault.accessToken ? 'vault' : 'cache',
  };
}

export async function syncIdentityVault(provider, options = {}) {
  const aliasesByProvider = {
    gemini: ['google', 'gmail'],
    openai: [],
    codex: []
  };

  return syncIdentityVaultToken({
    companyId: options.companyId || COMPANY_ID,
    provider,
    aliases: options.aliases || aliasesByProvider[provider] || [],
    markovMse: options.markovMse,
    humanMse: options.humanMse
  });
}

async function resolveGeminiAuth() {
  const vault = await syncIdentityVault('gemini');
  if (vault.accessToken && !vault.failingMvs) {
    return {
      mode: 'vault',
      apiKey: '',
      headers: { Authorization: `Bearer ${vault.accessToken}` },
      querySuffix: '',
      credentialCheckout: vault.accessCredentialCheckout,
    };
  }

  const checkout = checkoutGeminiCredential();
  if (!checkout) throw new Error('Gemini API key missing');
  return {
    mode: 'api_key',
    apiKey: checkout.value,
    headers: {},
    querySuffix: `?key=${encodeURIComponent(checkout.value)}`,
    credentialCheckout: checkout,
  };
}

async function resolveOpenAiCompatAuth(provider, config) {
  const baseUrl = typeof config?.baseUrl === 'function'
    ? config.baseUrl()
    : (config?.baseUrl || '');
  const staticHeaders = typeof config?.headers === 'function'
    ? config.headers()
    : (config?.headers || {});

  if (provider === 'openai') {
    const vault = await syncIdentityVault('openai');
    if (vault.accessToken && !vault.failingMvs) {
      return {
        apiKey: vault.accessToken,
        baseUrl,
        headers: staticHeaders,
        source: vault.recursivelyRecalled ? 'recursive_recall' : 'vault',
        credentialCheckout: vault.accessCredentialCheckout,
      };
    }
  }
  if (provider === 'codex') {
    const vault = await syncIdentityVault('codex');
    if (vault.accessToken && !vault.failingMvs) {
      return {
        apiKey: vault.accessToken,
        baseUrl,
        headers: staticHeaders,
        source: vault.recursivelyRecalled ? 'recursive_recall' : 'vault',
        credentialCheckout: vault.accessCredentialCheckout,
      };
    }
  }

  const checkout = typeof config?.credentialCheckout === 'function'
    ? config.credentialCheckout()
    : null;
  const apiKey = checkout?.value || config?.fallbackApiKey || '';
  if (!apiKey) throw new Error(`${provider} API key missing`);
  return {
    apiKey,
    baseUrl,
    headers: staticHeaders,
    source: checkout ? 'api_key' : 'provider_placeholder',
    credentialCheckout: checkout,
  };
}

// ─── Signed-ledger hint parsing ──────────────────────────────────────────────
// No hardcoded models. ${PROVIDER}_MODEL_HINTS is read from system config.
function parseHints(configKey) {
  const raw = String(systemConfigStore.readConfigString(configKey) || '').trim();
  if (!raw) return [];
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

const PROVIDER_REGISTRY = Object.freeze({
  anthropic: {
    type: 'adapter',
    modelHints: () => parseHints('ANTHROPIC_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('ANTHROPIC_MODEL') || '',
    isAvailable: () => peekCachedCredential('anthropic_api_key'),
    credentialCheckout: () => checkoutCachedCredential('anthropic_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('ANTHROPIC_BASE_URL') || 'https://api.anthropic.com'
  },
  ollama: {
    type: 'adapter',
    modelHints: () => parseHints('OLLAMA_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('OLLAMA_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => getLocalProviderAvailability('ollama'),
    baseUrl: () => systemConfigStore.readConfigString('OLLAMA_BASE_URL') || OLLAMA_BASE_URL
  },
  lmstudio: {
    type: 'openai_compatible',
    modelHints: () => parseHints('LMSTUDIO_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('LMSTUDIO_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => getLocalProviderAvailability('lmstudio'),
    baseUrl: () => systemConfigStore.readConfigString('LMSTUDIO_BASE_URL') || LMSTUDIO_BASE_URL,
    credentialCheckout: () => checkoutCachedCredential('lmstudio_api_key'),
    fallbackApiKey: 'lm-studio'
  },
  gemini: {
    type: 'adapter',
    modelHints: () => parseHints('GEMINI_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('GEMINI_MODEL') || '',
    isAvailable: () => peekCachedCredential('gemini_api_key') || peekCachedCredential('google_api_key')
  },
  perplexity: {
    type: 'adapter',
    modelHints: () => parseHints('PERPLEXITY_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('PERPLEXITY_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => peekCachedCredential('perplexity_api_key')
  },
  openai: {
    type: 'openai_compatible',
    modelHints: () => parseHints('OPENAI_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('OPENAI_MODEL') || '',
    isAvailable: () => peekCachedCredential('openai_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('OPENAI_BASE_URL') || 'https://api.openai.com/v1',
    credentialCheckout: () => checkoutCachedCredential('openai_api_key')
  },
  codex: {
    type: 'adapter',
    modelHints: () => parseHints('CODEX_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('CODEX_MODEL') || systemConfigStore.readConfigString('OPENAI_MODEL') || 'gpt-5.4',
    isAvailable: () => hasCodexChatgptAuth(),
    baseUrl: () => systemConfigStore.readConfigString('CODEX_CHATGPT_BASE_URL') || CODEX_CHATGPT_BASE_URL
  },
  openrouter: {
    type: 'openai_compatible',
    modelHints: () => parseHints('OPENROUTER_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('OPENROUTER_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => peekCachedCredential('openrouter_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('OPENROUTER_BASE_URL') || 'https://openrouter.ai/api/v1',
    credentialCheckout: () => checkoutCachedCredential('openrouter_api_key'),
    headers: () => ({
      ...(systemConfigStore.readConfigString('OPENROUTER_HTTP_REFERER') ? { 'HTTP-Referer': systemConfigStore.readConfigString('OPENROUTER_HTTP_REFERER') } : {}),
      ...(systemConfigStore.readConfigString('OPENROUTER_APP_TITLE') ? { 'X-Title': systemConfigStore.readConfigString('OPENROUTER_APP_TITLE') } : {})
    })
  },
  groq: {
    type: 'openai_compatible',
    modelHints: () => parseHints('GROQ_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('GROQ_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => peekCachedCredential('groq_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('GROQ_BASE_URL') || 'https://api.groq.com/openai/v1',
    credentialCheckout: () => checkoutCachedCredential('groq_api_key')
  },
  deepseek: {
    type: 'openai_compatible',
    modelHints: () => parseHints('DEEPSEEK_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('DEEPSEEK_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => peekCachedCredential('deepseek_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('DEEPSEEK_BASE_URL') || 'https://api.deepseek.com/v1',
    credentialCheckout: () => checkoutCachedCredential('deepseek_api_key')
  },
  together: {
    type: 'openai_compatible',
    modelHints: () => parseHints('TOGETHER_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('TOGETHER_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => peekCachedCredential('together_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('TOGETHER_BASE_URL') || 'https://api.together.xyz/v1',
    credentialCheckout: () => checkoutCachedCredential('together_api_key')
  },
  xai: {
    type: 'openai_compatible',
    modelHints: () => parseHints('XAI_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('XAI_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => peekCachedCredential('xai_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('XAI_BASE_URL') || 'https://api.x.ai/v1',
    credentialCheckout: () => checkoutCachedCredential('xai_api_key')
  },
  venice: {
    type: 'openai_compatible',
    modelHints: () => parseHints('VENICE_MODEL_HINTS'),
    defaultModel: () => systemConfigStore.readConfigString('VENICE_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || '',
    isAvailable: () => peekCachedCredential('venice_api_key'),
    baseUrl: () => systemConfigStore.readConfigString('VENICE_BASE_URL') || 'https://api.venice.ai/api/v1',
    credentialCheckout: () => checkoutCachedCredential('venice_api_key')
  }
});

function resolveKnownProviderAlias(value) {
  const v = String(value || '').trim().toLowerCase();
  if (!v) return '';
  if (v in PROVIDER_REGISTRY) return v;

  if (v === 'google') return 'gemini';
  if (v === 'sonar') return 'perplexity';
  if (v === 'perplexity.ai') return 'perplexity';
  if (v === 'oai') return 'openai';
  if (v === 'or') return 'openrouter';
  if (v === 'venice' || v === 'venice.ai') return 'venice';

  return '';
}

function inferProviderFromModel(value) {
  const model = String(value || '').trim().toLowerCase();
  if (!model) return '';

  if (model.startsWith('gemini')) return 'gemini';
  if (model.startsWith('sonar') || model.includes('perplexity')) return 'perplexity';
  if (model.startsWith('gpt-') || /^(o1|o3|o4)(-|$)/.test(model) || model.includes('chatgpt')) return 'openai';
  if (model.startsWith('openai/')) return 'openai';
  if (model.startsWith('openrouter/') || model.startsWith('or/')) return 'openrouter';
  if (model.startsWith('groq/')) return 'groq';
  if (model.startsWith('deepseek/')) return 'deepseek';
  if (model.startsWith('together/')) return 'together';
  if (model.startsWith('xai/') || model.startsWith('grok-')) return 'xai';
  if (model.startsWith('venice/')) return 'venice';

  return '';
}

function splitProviderAndModel(value) {
  const raw = String(value || '').trim();
  if (!raw) return { provider: '', model: '' };

  for (const separator of [':', '/']) {
    const idx = raw.indexOf(separator);
    if (idx <= 0) continue;
    const left = raw.slice(0, idx).trim().toLowerCase();
    const provider = resolveKnownProviderAlias(left);
    if (!provider) continue;
    const model = raw.slice(idx + 1).trim();
    return { provider, model };
  }

  return { provider: resolveKnownProviderAlias(raw), model: '' };
}

export function resolveProviderForModel(providerOrModel, explicitModel = '') {
  const modelOverride = String(explicitModel || '').trim();
  const split = splitProviderAndModel(providerOrModel);
  const inferredProvider = split.provider || inferProviderFromModel(providerOrModel);

  let provider = inferredProvider || resolveKnownProviderAlias(providerOrModel);
  if (!provider) provider = inferProviderFromModel(modelOverride);

  const providerConfig = provider ? PROVIDER_REGISTRY[provider] : null;
  const candidateModel = modelOverride || split.model || String(providerOrModel || '').trim();

  let model = candidateModel;
  if (provider && provider === resolveKnownProviderAlias(providerOrModel) && !modelOverride && !split.model) {
    model = providerConfig?.defaultModel?.() || '';
  } else if (!model && providerConfig?.defaultModel) {
    model = providerConfig.defaultModel() || '';
  }

  return { provider, model };
}

function providerAvailabilityReason(provider) {
  switch (provider) {
    case 'gemini':
      return 'missing GEMINI_API_KEY/GOOGLE_API_KEY';
    case 'perplexity':
      return 'missing PERPLEXITY_API_KEY';
    case 'openai':
      return 'missing OPENAI_API_KEY';
    case 'codex':
      return 'missing Codex Desktop ChatGPT auth';
    case 'openrouter':
      return 'missing OPENROUTER_API_KEY';
    case 'groq':
      return 'missing GROQ_API_KEY';
    case 'deepseek':
      return 'missing DEEPSEEK_API_KEY';
    case 'together':
      return 'missing TOGETHER_API_KEY';
    case 'xai':
      return 'missing XAI_API_KEY';
    case 'venice':
      return 'missing VENICE_API_KEY';
    case 'ollama':
      return 'awaiting background probe on 127.0.0.1:11434';
    case 'lmstudio':
      return 'awaiting background probe on 127.0.0.1:1234';
    default:
      return 'not configured';
  }
}

function isAvailable(providerOrModel) {
  const resolution = resolveProviderForModel(providerOrModel);
  if (!resolution.provider) return false;
  const config = PROVIDER_REGISTRY[resolution.provider];
  if (!config || typeof config.isAvailable !== 'function') return false;
  return config.isAvailable();
}

function resolveHints(config) {
  if (typeof config?.modelHints === 'function') {
    try { const r = config.modelHints(); return Array.isArray(r) ? r : []; } catch { return []; }
  }
  return Array.isArray(config?.modelHints) ? [...config.modelHints] : [];
}

export function getProviderRegistry() {
  return Object.fromEntries(
    Object.entries(PROVIDER_REGISTRY).map(([key, config]) => [
      key,
      {
        key,
        type: config.type,
        modelHints: resolveHints(config),
        defaultModel: config.defaultModel?.() || null
      }
    ])
  );
}

export function discoverActiveProviders() {
  return Object.entries(PROVIDER_REGISTRY).map(([provider, config]) => {
    const active = !!config.isAvailable?.();
    return {
      provider,
      type: config.type,
      active,
      reason: active ? 'configured' : providerAvailabilityReason(provider),
      defaultModel: config.defaultModel?.() || null,
      modelHints: resolveHints(config)
    };
  });
}

// ─── Runtime provider sensing — "who drives the car right now" ───────────────
// Architecture is provider-agnostic. LLM_PROVIDER signed configuration is a preference: when
// the configured provider is available with a usable model, it wins. Otherwise
// we fall through to auto-detect (first adapter where isAvailable passes).
// Throw only when no adapter is configured at all.
export function pickActiveProvider() {
  const envProvider = resolveKnownProviderAlias(systemConfigStore.readConfigString('LLM_PROVIDER') || '');
  if (envProvider) {
    const config = PROVIDER_REGISTRY[envProvider];
    if (config?.isAvailable?.()) {
      const model = config.defaultModel?.() || '';
      if (model) return { provider: envProvider, model };
      // Configured provider has no resolvable model — fall through to auto-detect.
    }
    // Configured provider not currently available — fall through to auto-detect.
  }
  for (const [provider, config] of Object.entries(PROVIDER_REGISTRY)) {
    if (!config.isAvailable?.()) continue;
    const model = config.defaultModel?.() || '';
    if (!model) continue;
    return { provider, model };
  }
  throw new Error('[pickActiveProvider] No adapter active. Ledger LLM_PROVIDER/LLM_MODEL or provision a keychain credential.');
}

export function providerStatus(providerOrModel) {
  return isAvailable(providerOrModel) ? 'available' : 'unavailable';
}

function getOpenAICompatConfig(provider) {
  const config = PROVIDER_REGISTRY[provider];
  if (!config || config.type !== 'openai_compatible') return null;
  return {
    credentialCheckout: config.credentialCheckout,
    fallbackApiKey: config.fallbackApiKey,
    baseUrl: config.baseUrl,
    defaultModel: config.defaultModel?.() || '',
    headers: config.headers
  };
}

async function listOpenAiCompatibleModels(providerId, config, useContext = {}) {
  const auth = await resolveOpenAiCompatAuth(providerId, config);
  const baseUrl = String(auth.baseUrl || '').replace(/\/+$/, '');
  if (!baseUrl) {
    throw new Error(`Provider '${providerId}' is not configured`);
  }

  const endpoint = `${baseUrl}/models`;
  const reservation = auth.credentialCheckout
    ? await credentialLedger.reserveCredentialUse({
      ...auth.credentialCheckout,
      operation: `${providerId}.models.list`,
      endpoint,
      requestHash: credentialUseEvidenceHash({ method: 'GET', provider: providerId, endpoint }),
      subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
      requestReceiptId: useContext?.requestReceiptId || null,
      requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
      autonomousActionEventId: useContext?.autonomousActionEventId || null,
    })
    : null;
  let response = null;
  let terminalAttempted = false;
  try {
    response = await fetchWithTimeout(endpoint, {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${auth.apiKey}`,
        ...(auth.headers || {})
      }
    });
    if (!response.ok) {
      throw new Error(`Model catalog request failed with HTTP ${response.status}`);
    }
    const payload = await response.json();
    if (reservation) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeClass: 'http_response',
        outcomeHash: credentialUseEvidenceHash({ status: response.status, payload }),
      });
    }
    return (Array.isArray(payload?.data) ? payload.data : [])
      .map((item) => normalizeOpenAiModelPayload(providerId, item))
      .filter(Boolean);
  } catch (error) {
    if (reservation && !terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: response?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

async function listCodexModels(useContext = {}) {
  const {
    accessToken,
    accountId,
    clientVersion,
    credentialCheckout,
  } = await loadCodexChatgptAuth({ requireClientVersion: true });
  const baseUrl = String(PROVIDER_REGISTRY.codex.baseUrl?.() || CODEX_CHATGPT_BASE_URL).replace(/\/+$/, '');
  const endpoint = `${baseUrl}/codex/models`;
  const requestUrl = buildCodexModelsRequestUrl(endpoint, clientVersion);
  const reservation = credentialCheckout
    ? await credentialLedger.reserveCredentialUse({
      ...credentialCheckout,
      operation: 'codex.models.list',
      endpoint,
      requestHash: credentialUseEvidenceHash({
        method: 'GET',
        provider: 'codex',
        endpoint,
        requestUrl,
        accountId,
        clientVersion,
      }),
      subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
      requestReceiptId: useContext?.requestReceiptId || null,
      requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
      autonomousActionEventId: useContext?.autonomousActionEventId || null,
    })
    : null;
  let response = null;
  let terminalAttempted = false;
  try {
    response = await fetchWithTimeout(requestUrl, {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
        'ChatGPT-Account-ID': accountId,
      }
    }, CODEX_REQUEST_TIMEOUT_MS);
    if (!response.ok) {
      throw new Error(`Model catalog request failed with HTTP ${response.status}`);
    }
    const payload = await response.json();
    let credentialUseEvidence = null;
    if (reservation) {
      terminalAttempted = true;
      credentialUseEvidence = await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeClass: 'http_response',
        outcomeHash: credentialUseEvidenceHash({ status: response.status, payload }),
      });
    }
    const rawModels = Array.isArray(payload?.models)
      ? payload.models
      : Array.isArray(payload?.data)
        ? payload.data
        : [];
    const models = rawModels
      .map((item) => {
        return normalizeCodexModelPayload(item);
      })
      .filter(Boolean);
    return { models, credentialUseEvidence };
  } catch (error) {
    if (reservation && !terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: response?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

async function listAnthropicModels(useContext = {}) {
  const credentialCheckout = PROVIDER_REGISTRY.anthropic.credentialCheckout?.();
  const apiKey = String(credentialCheckout?.value || '').trim();
  const baseUrl = String(PROVIDER_REGISTRY.anthropic.baseUrl?.() || 'https://api.anthropic.com').replace(/\/+$/, '');
  if (!apiKey) throw new Error("Provider 'anthropic' is not configured");

  const endpoint = `${baseUrl}/v1/models`;
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credentialCheckout,
    operation: 'anthropic.models.list',
    endpoint,
    requestHash: credentialUseEvidenceHash({ method: 'GET', provider: 'anthropic', endpoint }),
    subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
    requestReceiptId: useContext?.requestReceiptId || null,
    requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext?.autonomousActionEventId || null,
  });
  let response = null;
  let terminalAttempted = false;
  try {
    response = await fetchWithTimeout(endpoint, {
      headers: {
        Accept: 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      }
    });
    if (!response.ok) {
      throw new Error(`Model catalog request failed with HTTP ${response.status}`);
    }
    const payload = await response.json();
    terminalAttempted = true;
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'completed',
      outcomeClass: 'http_response',
      outcomeHash: credentialUseEvidenceHash({ status: response.status, payload }),
    });
    return (Array.isArray(payload?.data) ? payload.data : [])
      .map((item) => {
        const modelId = String(item?.id || '').trim();
        if (!modelId) return null;
        return baseModelPayload('anthropic', modelId, item?.display_name || modelId);
      })
      .filter(Boolean);
  } catch (error) {
    if (!terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: response?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

async function listGeminiModels(useContext = {}) {
  const auth = await resolveGeminiAuth();
  const endpoint = 'https://generativelanguage.googleapis.com/v1beta/models';
  const url = auth.querySuffix
    ? `${endpoint}${auth.querySuffix}`
    : endpoint;
  const reservation = auth.credentialCheckout
    ? await credentialLedger.reserveCredentialUse({
      ...auth.credentialCheckout,
      operation: 'gemini.models.list',
      endpoint,
      requestHash: credentialUseEvidenceHash({ method: 'GET', provider: 'gemini', endpoint }),
      subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
      requestReceiptId: useContext?.requestReceiptId || null,
      requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
      autonomousActionEventId: useContext?.autonomousActionEventId || null,
    })
    : null;
  let response = null;
  let terminalAttempted = false;
  try {
    response = await fetchWithTimeout(url, {
      headers: {
        Accept: 'application/json',
        ...(auth.headers || {})
      }
    });
    if (!response.ok) {
      throw new Error(`Model catalog request failed with HTTP ${response.status}`);
    }
    const payload = await response.json();
    if (reservation) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeClass: 'http_response',
        outcomeHash: credentialUseEvidenceHash({ status: response.status, payload }),
      });
    }
    return (Array.isArray(payload?.models) ? payload.models : [])
      .filter((item) => Array.isArray(item?.supportedGenerationMethods)
        ? item.supportedGenerationMethods.includes('generateContent')
        : true)
      .map((item) => {
        const modelId = String(item?.name || '').replace(/^models\//, '').trim();
        if (!modelId) return null;
        return baseModelPayload('gemini', modelId, item?.displayName || modelId);
      })
      .filter(Boolean);
  } catch (error) {
    if (reservation && !terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: response?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

async function listOllamaModels() {
  const response = await fetchWithTimeout(`${OLLAMA_BASE_URL}/api/tags`, {
    headers: { Accept: 'application/json' }
  });

  if (!response.ok) {
    throw new Error(`Model catalog request failed with HTTP ${response.status}`);
  }

  const payload = await response.json();
  return (Array.isArray(payload?.models) ? payload.models : [])
    .map((item) => {
      const modelId = String(item?.name || '').trim();
      if (!modelId) return null;
      return baseModelPayload('ollama', modelId, modelId);
    })
    .filter(Boolean);
}

export async function listProviderModels(providerId, useContext = {}) {
  const provider = String(providerId || '').trim().toLowerCase();
  const registry = getProviderRegistry();
  const config = registry[provider];
  if (!config) {
    throw new Error(`Unknown provider '${provider}'`);
  }

  try {
    let models = [];
    if (provider === 'anthropic') {
      models = await listAnthropicModels(useContext);
    } else if (provider === 'gemini') {
      models = await listGeminiModels(useContext);
    } else if (provider === 'ollama') {
      models = await listOllamaModels();
    } else if (provider === 'codex') {
      const catalog = await listCodexModels(useContext);
      models = catalog.models;
      if (useContext?.includeCredentialUseEvidence) {
        return {
          providerId: provider,
          available: true,
          error: null,
          models: dedupeModels(models),
          credentialUseEvidence: catalog.credentialUseEvidence,
        };
      }
    } else {
      models = await listOpenAiCompatibleModels(provider, PROVIDER_REGISTRY[provider], useContext);
    }

    return {
      providerId: provider,
      available: true,
      error: null,
      models: dedupeModels(models)
    };
  } catch (error) {
    return {
      providerId: provider,
      available: false,
      error: error?.message || String(error),
      models: []
    };
  }
}

export async function runProvider({
  provider,
  prompt,
  messages = [],
  model,
  systemPrompt,
  userPrompt,
  toolDefs = [],
  toolExecutionOptions = {},
  onToken,
  useContext = {},
  reasoningEffort,
  textVerbosity,
  maxOutputTokens,
  responseSchema,
  returnMetadata = false,
}) {
  // A1b: config-driven defaults via systemConfigStore.
  const envProvider = String(systemConfigStore.readConfigString('LLM_PROVIDER') || '').trim();
  const envModel = String(systemConfigStore.readConfigString('LLM_MODEL') || '').trim();
  const providerArg = provider || envProvider;
  const modelArg = model || envModel;

  const resolution = resolveProviderForModel(providerArg, modelArg);
  const providerKey = resolution.provider;
  const resolvedModel = resolution.model;

  if (!providerKey) {
    throw new Error(
      '[runProvider] No provider resolved. Set LLM_PROVIDER (anthropic|gemini|ollama|codex|openai|openrouter|groq|deepseek|together|xai|venice|perplexity) and LLM_MODEL.'
    );
  }

  switch (providerKey) {
    case 'gemini':
      return runGemini(prompt, resolvedModel, onToken, useContext);
    case 'perplexity':
      return runPerplexity({
        prompt,
        messages,
        systemPrompt,
        userPrompt,
        modelOverride: resolvedModel,
        toolDefs,
        toolExecutionOptions,
        onToken,
        useContext,
      });
    case 'anthropic': {
      const credentialCheckout = PROVIDER_REGISTRY.anthropic.credentialCheckout();
      const apiKey = credentialCheckout?.value || '';
      const baseUrl = PROVIDER_REGISTRY.anthropic.baseUrl();
      return runAnthropic({
        prompt,
        messages,
        systemPrompt,
        userPrompt,
        modelOverride: resolvedModel,
        apiKey,
        credentialCheckout,
        baseUrl,
        onToken,
        useContext,
      });
    }
    case 'codex':
      return runCodex({
        prompt,
        messages,
        systemPrompt,
        userPrompt,
        model: resolvedModel,
        onToken,
        useContext,
        reasoningEffort,
        textVerbosity,
        maxOutputTokens,
        responseSchema,
        returnMetadata,
      });
    case 'ollama':
      return runOllama({ prompt, messages, systemPrompt, userPrompt, model: resolvedModel, onToken });
    case 'openai':
    case 'openrouter':
    case 'groq':
    case 'deepseek':
    case 'together':
    case 'xai':
    case 'venice': {
      const config = getOpenAICompatConfig(providerKey);
      return runOpenAICompat({
        provider: providerKey,
        config,
        prompt,
        messages,
        systemPrompt,
        userPrompt,
        modelOverride: resolvedModel,
        toolDefs,
        toolExecutionOptions,
        onToken,
        useContext,
      });
    }
    default:
      throw new Error(`Unknown provider: ${provider}`);
  }
}

function codexReasoningEffort() {
  const raw = String(systemConfigStore.readConfigString('CODEX_REASONING_EFFORT') || 'low')
    .trim()
    .toLowerCase();
  return ['low', 'medium', 'high'].includes(raw) ? raw : 'low';
}

function codexTextVerbosity() {
  const raw = String(systemConfigStore.readConfigString('CODEX_TEXT_VERBOSITY') || 'low')
    .trim()
    .toLowerCase();
  return ['low', 'medium', 'high'].includes(raw) ? raw : 'low';
}

const CODEX_REASONING_EFFORTS = Object.freeze(['none', 'low', 'medium', 'high', 'xhigh', 'max', 'ultra']);
const CODEX_TEXT_VERBOSITIES = Object.freeze(['low', 'medium', 'high']);

function normalizeCodexReasoningEffort(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!CODEX_REASONING_EFFORTS.includes(normalized)) {
    throw new Error(`Unsupported Codex reasoning effort: ${value}`);
  }
  return normalized;
}

function normalizeCodexTextVerbosity(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!CODEX_TEXT_VERBOSITIES.includes(normalized)) {
    throw new Error(`Unsupported Codex text verbosity: ${value}`);
  }
  return normalized;
}

function normalizeCodexResponseSchema(responseSchema) {
  if (responseSchema == null) return null;
  const name = String(responseSchema?.name || '').trim();
  const schema = responseSchema?.schema;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
    throw new Error('Codex response schema name is malformed.');
  }
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    throw new Error('Codex response schema must be a JSON Schema object.');
  }
  const encoded = JSON.stringify(schema);
  if (Buffer.byteLength(encoded, 'utf8') > 64 * 1024) {
    throw new Error('Codex response schema exceeds 64 KiB.');
  }
  return { type: 'json_schema', name, schema: JSON.parse(encoded), strict: true };
}

function buildCodexResponsesInput(conversation) {
  const input = [];
  let instructions = '';

  for (const message of conversation) {
    const role = String(message?.role || '').trim();
    const content = String(message?.content || '');
    if (!content) continue;
    if (role === 'system') {
      instructions += `${instructions ? '\n\n' : ''}${content}`;
      continue;
    }
    input.push({
      role: role === 'assistant' ? 'assistant' : 'user',
      content: [{
        type: role === 'assistant' ? 'output_text' : 'input_text',
        text: content,
      }],
    });
  }

  return { instructions, input };
}

export function buildCodexResponsesPayload({
  model,
  instructions,
  input,
  reasoningEffort,
  textVerbosity,
  maxOutputTokens = null,
  responseSchema = null,
} = {}) {
  const normalizedModel = String(model || '').trim();
  if (!normalizedModel) throw new Error('Codex request model is required.');
  if (!Array.isArray(input) || input.length === 0) throw new Error('Codex request input is required.');
  if (maxOutputTokens != null) {
    throw new Error('Codex ChatGPT transport does not support maxOutputTokens.');
  }
  const normalizedResponseSchema = normalizeCodexResponseSchema(responseSchema);
  return {
    model: normalizedModel,
    instructions: String(instructions || ''),
    input,
    tools: [],
    tool_choice: 'auto',
    parallel_tool_calls: false,
    reasoning: { effort: normalizeCodexReasoningEffort(reasoningEffort) },
    store: false,
    stream: true,
    include: ['reasoning.encrypted_content'],
    text: {
      verbosity: normalizeCodexTextVerbosity(textVerbosity),
      ...(normalizedResponseSchema ? { format: normalizedResponseSchema } : {}),
    },
  };
}

function extractCodexResponseEventText(event) {
  if (event?.type === 'response.output_text.delta') {
    return { kind: 'delta', text: String(event.delta || '') };
  }
  if (event?.type === 'response.output_text.done') {
    return { kind: 'final', text: String(event.text || '') };
  }
  if (event?.type === 'response.output_item.done' && Array.isArray(event?.item?.content)) {
    const text = event.item.content
      .map((part) => {
        if (part?.type === 'output_text' || part?.type === 'text') return String(part.text || '');
        return '';
      })
      .join('');
    return { kind: 'final', text };
  }
  return { kind: 'none', text: '' };
}

function extractCodexTerminalResponseText(response) {
  if (!Array.isArray(response?.output)) return '';
  return response.output
    .flatMap((item) => (Array.isArray(item?.content) ? item.content : []))
    .map((part) => {
      if (part?.type === 'output_text' || part?.type === 'text') return String(part.text || '');
      return '';
    })
    .join('');
}

function safeCodexDiagnosticString(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return null;
  return normalized.slice(0, 160);
}

function safeUsageInteger(value) {
  const normalized = Number(value);
  return Number.isSafeInteger(normalized) && normalized >= 0 ? normalized : null;
}

function sanitizeCodexUsage(usage) {
  if (!usage || typeof usage !== 'object') return null;
  return {
    inputTokens: safeUsageInteger(usage.input_tokens),
    outputTokens: safeUsageInteger(usage.output_tokens),
    totalTokens: safeUsageInteger(usage.total_tokens),
    cachedInputTokens: safeUsageInteger(usage.input_tokens_details?.cached_tokens),
    reasoningOutputTokens: safeUsageInteger(usage.output_tokens_details?.reasoning_tokens),
  };
}

export function parseCodexSseResponse(raw, onToken) {
  let deltaText = '';
  let finalText = '';
  let terminalText = '';
  let completedResponse = null;
  let terminalEventType = null;
  let terminalErrorCode = null;
  let terminalErrorType = null;
  let incompleteReason = null;
  let dataLineCount = 0;
  let parsedEventCount = 0;
  let malformedDataCount = 0;
  const eventTypes = new Set();
  const serialized = String(raw || '');
  for (const block of serialized.split(/\r?\n\r?\n+/)) {
    const dataLines = block.split('\n').filter(line => line.startsWith('data:'));
    for (const line of dataLines) {
      dataLineCount += 1;
      const payload = line.slice(5).trim();
      if (!payload || payload === '[DONE]') continue;
      let event;
      try {
        event = JSON.parse(payload);
      } catch {
        malformedDataCount += 1;
        continue;
      }
      parsedEventCount += 1;
      if (event?.type) eventTypes.add(String(event.type));
      const extracted = extractCodexResponseEventText(event);
      if (extracted.kind === 'delta') {
        deltaText += extracted.text;
        if (typeof onToken === 'function' && extracted.text) onToken(extracted.text);
      } else if (extracted.kind === 'final') {
        finalText += extracted.text;
      }
      if (['response.completed', 'response.failed', 'response.incomplete'].includes(event?.type)) {
        completedResponse = event.response || null;
        terminalEventType = String(event.type);
        terminalText = extractCodexTerminalResponseText(completedResponse);
        terminalErrorCode = safeCodexDiagnosticString(
          event?.error?.code || completedResponse?.error?.code,
        );
        terminalErrorType = safeCodexDiagnosticString(
          event?.error?.type || completedResponse?.error?.type,
        );
        incompleteReason = safeCodexDiagnosticString(completedResponse?.incomplete_details?.reason);
      }
    }
  }
  return Object.freeze({
    text: (deltaText || finalText || terminalText).trim(),
    responseId: completedResponse?.id ? String(completedResponse.id) : null,
    model: completedResponse?.model ? String(completedResponse.model) : null,
    status: completedResponse?.status ? String(completedResponse.status) : null,
    usage: sanitizeCodexUsage(completedResponse?.usage),
    diagnostics: Object.freeze({
      rawBytes: Buffer.byteLength(serialized, 'utf8'),
      dataLineCount,
      parsedEventCount,
      malformedDataCount,
      eventTypes: Object.freeze([...eventTypes].sort()),
      terminalEventType,
      terminalErrorCode,
      terminalErrorType,
      incompleteReason,
    }),
  });
}

function codexResponseDiagnosticSuffix(parsed) {
  return JSON.stringify(parsed?.diagnostics || {});
}

async function runCodex({
  prompt,
  messages = [],
  systemPrompt,
  userPrompt,
  model,
  onToken,
  useContext = {},
  reasoningEffort,
  textVerbosity,
  maxOutputTokens,
  responseSchema,
  returnMetadata = false,
} = {}) {
  const resolvedModel = model || PROVIDER_REGISTRY.codex.defaultModel?.();
  if (!resolvedModel) throw new Error('Codex model missing (set CODEX_MODEL or pass model)');

  const { accessToken, accountId, credentialCheckout } = await loadCodexChatgptAuth();
  const conversation = buildProviderMessages({ prompt, messages, systemPrompt, userPrompt });
  const { instructions, input } = buildCodexResponsesInput(conversation);
  if (input.length === 0) throw new Error('Codex request missing user input');

  const baseUrl = String(PROVIDER_REGISTRY.codex.baseUrl?.() || CODEX_CHATGPT_BASE_URL).replace(/\/+$/, '');
  const endpoint = `${baseUrl}/codex/responses`;
  const payload = buildCodexResponsesPayload({
    model: resolvedModel,
    instructions,
    input,
    reasoningEffort: reasoningEffort || codexReasoningEffort(),
    textVerbosity: textVerbosity || codexTextVerbosity(),
    maxOutputTokens,
    responseSchema,
  });
  const reservation = credentialCheckout
    ? await credentialLedger.reserveCredentialUse({
      ...credentialCheckout,
      operation: 'codex.responses.create',
      endpoint,
      requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, accountId, payload }),
      subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
      requestReceiptId: useContext?.requestReceiptId || null,
      requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
      autonomousActionEventId: useContext?.autonomousActionEventId || null,
    })
    : null;
  let response = null;
  let terminalAttempted = false;
  try {
    response = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'ChatGPT-Account-ID': accountId,
        Accept: 'text/event-stream',
        'Content-Type': 'application/json',
        'OpenAI-Beta': 'responses=v1',
      },
      body: JSON.stringify(payload)
    }, CODEX_REQUEST_TIMEOUT_MS);
    const raw = await response.text();
    if (!response.ok) {
      throw new Error(`Codex error (${response.status}): ${raw.slice(0, 1000)}`);
    }
    const parsed = parseCodexSseResponse(raw, onToken);
    if (parsed.status && parsed.status !== 'completed') {
      throw new Error(
        `Codex response ended with status ${parsed.status}:${codexResponseDiagnosticSuffix(parsed)}`,
      );
    }
    if (!parsed.text) {
      throw new Error(`Codex response was empty:${codexResponseDiagnosticSuffix(parsed)}`);
    }
    let credentialUseEvidence = null;
    if (reservation) {
      terminalAttempted = true;
      credentialUseEvidence = await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeClass: 'stream_completed',
        outcomeHash: credentialUseEvidenceHash({ status: response.status, raw }),
      });
    }
    return returnMetadata
      ? Object.freeze({ ...parsed, credentialUseEvidence })
      : parsed.text;
  } catch (error) {
    if (reservation && !terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: response?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

// ─── Native Ollama adapter — local HTTP, no SDK, no wrapper ─────────────────
async function runOllama({ prompt, messages = [], systemPrompt, userPrompt, model, onToken } = {}) {
  const baseUrl = OLLAMA_BASE_URL;
  const resolvedModel = model || systemConfigStore.readConfigString('OLLAMA_MODEL');
  if (!resolvedModel) throw new Error('Ollama model missing (set OLLAMA_MODEL or pass model)');

  const conversation = buildProviderMessages({ prompt, messages, systemPrompt, userPrompt });
  const stream = typeof onToken === 'function';

  const res = await fetchWithTimeout(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: resolvedModel, messages: conversation, stream })
  }, PROVIDER_REQUEST_TIMEOUT_MS);

  if (!res.ok) throw new Error(`Ollama error (${res.status}): ${await res.text()}`);

  if (!stream) {
    const data = await res.json();
    return data?.message?.content || '';
  }

  if (!res.body) throw new Error('Ollama stream body missing');
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let full = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let parsed;
      try { parsed = JSON.parse(trimmed); } catch { continue; }
      const delta = parsed?.message?.content || '';
      if (!delta) continue;
      full += delta;
      onToken(delta);
    }
  }
  return full;
}

async function runGemini(prompt, modelOverride, onToken, useContext = {}) {
  const model = modelOverride || systemConfigStore.readConfigString('GEMINI_MODEL') || systemConfigStore.readConfigString('LLM_MODEL');
  if (!model) throw new Error('Gemini model missing (set GEMINI_MODEL or LLM_MODEL)');
  let lastError = null;
  const auth = await resolveGeminiAuth();

  if (typeof onToken === 'function') {
    for (const querySuffix of [auth.querySuffix]) {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent`;
      const url = `${endpoint}${querySuffix}${querySuffix ? '&' : '?'}alt=sse`;
      const payload = { contents: [{ parts: [{ text: prompt }] }] };
      const reservation = auth.credentialCheckout
        ? await credentialLedger.reserveCredentialUse({
          ...auth.credentialCheckout,
          operation: 'gemini.content.stream',
          endpoint,
          requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload, stream: true }),
          subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
          requestReceiptId: useContext?.requestReceiptId || null,
          requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
          requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
          requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
          autonomousActionEventId: useContext?.autonomousActionEventId || null,
        })
        : null;
      let res = null;
      let terminalAttempted = false;
      let full = '';
      try {
        res = await fetchWithTimeout(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(auth.headers || {}) },
          body: JSON.stringify(payload)
        }, PROVIDER_REQUEST_TIMEOUT_MS);
        if (!res.ok) {
          throw new Error(`Gemini error (${res.status}): ${await res.text()}`);
        }
        if (!res.body) throw new Error('Gemini stream body missing');

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line.startsWith('data:')) continue;
            const eventPayload = line.slice(5).trim();
            if (!eventPayload || eventPayload === '[DONE]') continue;

            let parsed;
            try {
              parsed = JSON.parse(eventPayload);
            } catch {
              continue;
            }

            const text = parsed?.candidates?.[0]?.content?.parts
              ?.map((part) => (typeof part?.text === 'string' ? part.text : ''))
              .join('') || '';
            if (!text) continue;

            const delta = text.startsWith(full) ? text.slice(full.length) : text;
            if (!delta) continue;
            full += delta;
            onToken(delta);
          }
        }
        if (reservation) {
          terminalAttempted = true;
          await credentialLedger.finalizeCredentialUse({
            reservation,
            outcome: 'completed',
            outcomeClass: 'stream_completed',
            outcomeHash: credentialUseEvidenceHash({ status: res.status, text: full }),
          });
        }
        return full;
      } catch (error) {
        if (reservation && !terminalAttempted) {
          terminalAttempted = true;
          await credentialLedger.finalizeCredentialUse({
            reservation,
            outcome: 'failed',
            errorClass: error?.name || 'provider_request_failed',
            outcomeClass: 'provider_request_failed',
            outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, partialText: full, error: error?.message || String(error) }),
          });
        }
        lastError = error?.message || String(error);
      }
    }

    throw new Error(lastError || 'Gemini request failed');
  }

  for (const querySuffix of [auth.querySuffix]) {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
    const url = `${endpoint}${querySuffix}`;
    const payload = { contents: [{ parts: [{ text: prompt }] }] };
    const reservation = auth.credentialCheckout
      ? await credentialLedger.reserveCredentialUse({
        ...auth.credentialCheckout,
        operation: 'gemini.content.generate',
        endpoint,
        requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload }),
        subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
        requestReceiptId: useContext?.requestReceiptId || null,
        requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
        requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
        requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
        autonomousActionEventId: useContext?.autonomousActionEventId || null,
      })
      : null;
    let res = null;
    let terminalAttempted = false;
    try {
      res = await fetchWithTimeout(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(auth.headers || {}) },
        body: JSON.stringify(payload)
      }, PROVIDER_REQUEST_TIMEOUT_MS);
      if (!res.ok) {
        throw new Error(`Gemini error (${res.status}): ${await res.text()}`);
      }
      const data = await res.json();
      if (reservation) {
        terminalAttempted = true;
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'completed',
          outcomeClass: 'http_response',
          outcomeHash: credentialUseEvidenceHash({ status: res.status, data }),
        });
      }
      return data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    } catch (error) {
      if (reservation && !terminalAttempted) {
        terminalAttempted = true;
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          errorClass: error?.name || 'provider_request_failed',
          outcomeClass: 'provider_request_failed',
          outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, error: error?.message || String(error) }),
        });
      }
      lastError = error?.message || String(error);
    }
  }

  throw new Error(lastError || 'Gemini request failed');
}

function buildProviderMessages({ prompt, messages = [], systemPrompt, userPrompt }) {
  const providedMessages = Array.isArray(messages)
    ? messages
      .filter((entry) => entry && typeof entry.role === 'string' && typeof entry.content === 'string')
      .map((entry) => ({ role: entry.role, content: entry.content }))
    : [];

  if (providedMessages.length > 0) return providedMessages;

  const resolvedUserPrompt = (() => {
    if (typeof userPrompt === 'string' && userPrompt.trim()) return userPrompt;
    return String(prompt || '');
  })();

  return [
    ...(typeof systemPrompt === 'string' && systemPrompt.trim()
      ? [{ role: 'system', content: systemPrompt }]
      : []),
    { role: 'user', content: resolvedUserPrompt }
  ];
}

// ─── Anthropic Messages API ─────────────────────────────────────────────
async function runAnthropic({
  prompt,
  messages = [],
  systemPrompt,
  userPrompt,
  modelOverride,
  apiKey,
  credentialCheckout,
  baseUrl,
  onToken,
  useContext = {},
}) {
  const model = modelOverride || systemConfigStore.readConfigString('ANTHROPIC_MODEL') || systemConfigStore.readConfigString('LLM_MODEL');
  if (!model) throw new Error('Anthropic model missing (set ANTHROPIC_MODEL or LLM_MODEL)');
  if (!apiKey) throw new Error('Anthropic API key missing');

  const conversation = buildProviderMessages({ prompt, messages, systemPrompt, userPrompt });

  // Anthropic uses 'system' as a top-level field, not in messages
  let systemContent = '';
  const anthropicMessages = conversation.filter(m => {
    if (m.role === 'system') {
      systemContent += (systemContent ? '\n' : '') + m.content;
      return false;
    }
    return true;
  });

  const payload = {
    model,
    max_tokens: 4096,
    messages: anthropicMessages,
    ...(systemContent ? { system: systemContent } : {}),
  };

  if (typeof onToken === 'function') {
    return runAnthropicStream({
      model,
      systemContent,
      messages: anthropicMessages,
      baseUrl,
      apiKey,
      credentialCheckout,
      onToken,
      useContext,
    });
  }

  const endpoint = `${baseUrl.replace(/\/$/, '')}/v1/messages`;
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credentialCheckout,
    operation: 'anthropic.messages.create',
    endpoint,
    requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload }),
    subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
    requestReceiptId: useContext?.requestReceiptId || null,
    requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext?.autonomousActionEventId || null,
  });
  let res = null;
  let terminalAttempted = false;
  try {
    res = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(payload)
    }, PROVIDER_REQUEST_TIMEOUT_MS);
    if (!res.ok) throw new Error(`Anthropic error (${res.status}): ${await res.text()}`);
    const data = await res.json();
    terminalAttempted = true;
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'completed',
      outcomeClass: 'http_response',
      outcomeHash: credentialUseEvidenceHash({ status: res.status, data }),
    });
    return data?.content?.[0]?.text || '';
  } catch (error) {
    if (!terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

async function runAnthropicStream({ model, systemContent, messages, baseUrl, apiKey, credentialCheckout, onToken, useContext = {} }) {
  const endpoint = `${baseUrl.replace(/\/$/, '')}/v1/messages`;
  const payload = {
    model,
    max_tokens: 4096,
    messages,
    stream: true,
    ...(systemContent ? { system: systemContent } : {}),
  };
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credentialCheckout,
    operation: 'anthropic.messages.stream',
    endpoint,
    requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload }),
    subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
    requestReceiptId: useContext?.requestReceiptId || null,
    requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext?.autonomousActionEventId || null,
  });
  let res = null;
  let terminalAttempted = false;
  let full = '';
  try {
    res = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(payload)
    }, PROVIDER_REQUEST_TIMEOUT_MS);
    if (!res.ok) throw new Error(`Anthropic error (${res.status}): ${await res.text()}`);
    if (!res.body) throw new Error('Anthropic stream body missing');

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('data:')) continue;
        const payloadText = line.slice(5).trim();
        if (!payloadText || payloadText === '[DONE]') continue;
        let parsed;
        try { parsed = JSON.parse(payloadText); } catch { continue; }
        const type = parsed?.type || '';
        if (type === 'content_block_delta') {
          const delta = parsed?.delta?.text || '';
          if (delta) {
            full += delta;
            onToken(delta);
          }
        }
      }
    }
    terminalAttempted = true;
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'completed',
      outcomeClass: 'stream_completed',
      outcomeHash: credentialUseEvidenceHash({ status: res.status, text: full }),
    });
    return full;
  } catch (error) {
    if (!terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, partialText: full, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

async function runOpenAICompat({
  provider,
  config,
  prompt,
  messages = [],
  systemPrompt,
  userPrompt,
  modelOverride,
  toolDefs = [],
  toolExecutionOptions = {},
  onToken,
  useContext = {},
}) {
  const model = modelOverride || config.defaultModel;
  if (!model) throw new Error(`${provider} model missing`);
  const auth = await resolveOpenAiCompatAuth(provider, config);

  const conversation = buildProviderMessages({ prompt, messages, systemPrompt, userPrompt });
  const toolSchemas = (toolDefs || [])
    .map((toolDef) => toolDef?.schema)
    .filter(Boolean);
  const executeToolFn = toolExecutionOptions?.executeToolFn;
  const forcedToolName = String(toolExecutionOptions?.forcedToolName || '').trim();
  const maxRounds = 8;

  if (typeof onToken === 'function' && toolSchemas.length === 0) {
    return runOpenAICompatStream({
      provider,
      auth,
      model,
      messages: conversation,
      onToken,
      useContext,
    });
  }

  for (let round = 0; round < maxRounds; round += 1) {
    const payload = {
      model,
      messages: conversation,
      temperature: 0.2
    };

    if (toolSchemas.length > 0) {
      payload.tools = toolSchemas;
      payload.tool_choice = forcedToolName
        ? { type: 'function', function: { name: forcedToolName } }
        : 'auto';
    }

    const endpoint = `${String(auth.baseUrl || '').replace(/\/$/, '')}/chat/completions`;
    const reservation = auth.credentialCheckout
      ? await credentialLedger.reserveCredentialUse({
        ...auth.credentialCheckout,
        operation: `${provider}.chat.completions`,
        endpoint,
        requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload, round }),
        subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
        requestReceiptId: useContext?.requestReceiptId || null,
        requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
        requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
        requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
        autonomousActionEventId: useContext?.autonomousActionEventId || null,
      })
      : null;
    let res = null;
    let terminalAttempted = false;
    let data;
    try {
      res = await fetchWithTimeout(endpoint, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${auth.apiKey}`,
          'Content-Type': 'application/json',
          ...(auth.headers || {})
        },
        body: JSON.stringify(payload)
      }, PROVIDER_REQUEST_TIMEOUT_MS);
      if (!res.ok) throw new Error(`${provider} error (${res.status}): ${await res.text()}`);
      data = await res.json();
      if (reservation) {
        terminalAttempted = true;
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'completed',
          outcomeClass: 'http_response',
          outcomeHash: credentialUseEvidenceHash({ status: res.status, data }),
        });
      }
    } catch (error) {
      if (reservation && !terminalAttempted) {
        terminalAttempted = true;
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          errorClass: error?.name || 'provider_request_failed',
          outcomeClass: 'provider_request_failed',
          outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, error: error?.message || String(error) }),
        });
      }
      throw error;
    }
    const message = data?.choices?.[0]?.message || {};
    const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
    const text = contentToText(message.content);

    if (toolCalls.length === 0) {
      if (typeof onToken === 'function') {
        emitChunkedText(text, onToken);
      }
      return text;
    }

    conversation.push({
      role: 'assistant',
      content: message.content ?? '',
      tool_calls: toolCalls
    });

    if (typeof executeToolFn !== 'function') {
      throw new Error(`${provider} requested tool calls but no tool executor was provided`);
    }

    const executedToolResults = [];

    for (let i = 0; i < toolCalls.length; i += 1) {
      const tc = toolCalls[i] || {};
      const toolName = tc?.function?.name;
      const toolCallId = tc.id || `${provider}-tool-${round}-${i}`;
      let result;
      try {
        const args = parseToolArgs(tc?.function?.arguments);
        result = await executeToolFn(toolName, args);
        if (isToolApprovalPayload(result)) {
          throw createToolApprovalError(toolName, result);
        }
      } catch (err) {
        if (err?.code === 'TOOL_APPROVAL_REQUIRED') throw err;
        result = { error: err.message };
      }

      executedToolResults.push({ name: toolName || 'unknown_tool', result });
      conversation.push({
        role: 'tool',
        tool_call_id: toolCallId,
        name: toolName || 'unknown_tool',
        content: JSON.stringify(result)
      });
    }

    if (toolExecutionOptions?.returnAfterSingleToolCall === true && executedToolResults.length > 0) {
      return executedToolResults
        .map(({ name, result }) => `${name}: ${summarizeToolResult(result)}`)
        .join('\n');
    }
  }

  throw new Error(`${provider} tool loop exceeded max rounds without final response`);
}

async function runOpenAICompatStream({ provider, auth, model, messages, onToken, useContext = {} }) {
  const payload = {
    model,
    messages,
    temperature: 0.2,
    stream: true
  };

  const endpoint = `${String(auth.baseUrl || '').replace(/\/$/, '')}/chat/completions`;
  const reservation = auth.credentialCheckout
    ? await credentialLedger.reserveCredentialUse({
      ...auth.credentialCheckout,
      operation: `${provider}.chat.completions.stream`,
      endpoint,
      requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload }),
      subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
      requestReceiptId: useContext?.requestReceiptId || null,
      requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
      autonomousActionEventId: useContext?.autonomousActionEventId || null,
    })
    : null;
  let res = null;
  let terminalAttempted = false;
  let full = '';
  try {
    res = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${auth.apiKey}`,
        'Content-Type': 'application/json',
        ...(auth.headers || {})
      },
      body: JSON.stringify(payload)
    }, PROVIDER_REQUEST_TIMEOUT_MS);
    if (!res.ok) throw new Error(`${provider} error (${res.status}): ${await res.text()}`);
    if (!res.body) throw new Error(`${provider} stream body missing`);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('data:')) continue;
        const payloadText = line.slice(5).trim();
        if (!payloadText || payloadText === '[DONE]') continue;
        let parsed;
        try {
          parsed = JSON.parse(payloadText);
        } catch {
          continue;
        }
        const delta = String(parsed?.choices?.[0]?.delta?.content || '');
        if (!delta) continue;
        full += delta;
        onToken(delta);
      }
    }
    if (reservation) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeClass: 'stream_completed',
        outcomeHash: credentialUseEvidenceHash({ status: res.status, text: full }),
      });
    }
    return full;
  } catch (error) {
    if (reservation && !terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, partialText: full, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

function parseToolArgs(rawArguments) {
  if (!rawArguments) return {};
  if (typeof rawArguments === 'object') return rawArguments;
  try {
    return JSON.parse(rawArguments);
  } catch (err) {
    throw new Error(`Invalid tool arguments JSON: ${rawArguments}`);
  }
}

function contentToText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === 'string') return part;
        if (part && typeof part === 'object' && typeof part.text === 'string') return part.text;
        return '';
      })
      .join('')
      .trim();
  }
  return '';
}

function summarizeToolResult(result) {
  if (result == null) return '';
  if (typeof result === 'string') return result;
  if (typeof result?.message === 'string' && result.message.trim()) return result.message;
  if (typeof result?.error === 'string' && result.error.trim()) return `Tool error: ${result.error}`;
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

function isToolApprovalPayload(result) {
  return !!(result && typeof result === 'object' && result.requiresApproval);
}

function createToolApprovalError(toolName, toolResult) {
  const approvalRequestId = toolResult?.approvalRequestId || null;
  const error = new Error(
    `Tool approval required for '${toolName}'${approvalRequestId ? ` (${approvalRequestId})` : ''}`
  );
  error.code = 'TOOL_APPROVAL_REQUIRED';
  error.toolApproval = {
    tool: toolName,
    ...toolResult
  };
  return error;
}

function stripWrappingQuotes(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  const quotePairs = [
    ['"', '"'],
    ["'", "'"],
    ['`', '`']
  ];
  for (const [left, right] of quotePairs) {
    if (text.startsWith(left) && text.endsWith(right) && text.length >= 2) {
      return text.slice(1, -1).trim();
    }
  }
  return text;
}

function parseExactReplyDirective(prompt) {
  const match = String(prompt || '').match(/reply\s+exactly\s*:\s*([^\n]+)/i);
  if (!match) return '';
  let value = match[1].trim();
  value = value.replace(/[.]+$/, '').trim();
  return stripWrappingQuotes(value);
}

function parseAimosSaveArgs(prompt) {
  const text = String(prompt || '');
  const kv = text.match(/key\s*=\s*([^,\s]+)\s*,\s*value\s*=\s*([^\n]+)/i);
  if (kv) {
    const key = stripWrappingQuotes(kv[1]).replace(/[.,;]+$/, '').trim();
    const valueSegment = String(kv[2] || '')
      .split(/\bthen\s+reply\b|\breply\s+exactly\b/i)[0]
      .trim();
    const value = stripWrappingQuotes(valueSegment).replace(/[.,;]+$/, '').trim();
    if (key && value) {
      return { content: `${key}=${value}`, tags: ['auto', 'fallback'] };
    }
  }

  const quoted = text.match(/(?:save|store)\s+["'`](.+?)["'`]/i);
  if (quoted && quoted[1]) {
    const content = stripWrappingQuotes(quoted[1]).trim();
    if (content) return { content, tags: ['auto', 'fallback'] };
  }

  return null;
}

function parseImessageSendArgs(prompt) {
  const text = String(prompt || '');
  const messageMatch = text.match(/send\s+["'`](.+?)["'`]/i);
  const toMatch = text.match(/\bto\s+([+A-Za-z0-9@._-]{3,})/i);
  if (!messageMatch || !toMatch) return null;
  const message = stripWrappingQuotes(messageMatch[1]).trim();
  const to = stripWrappingQuotes(toMatch[1]).trim();
  if (!message || !to) return null;
  return { to, message };
}

function deriveFallbackToolArgs(toolName, prompt) {
  const normalized = String(toolName || '').trim();
  if (!normalized) return null;

  switch (normalized) {
    case 'aimos_save':
      return parseAimosSaveArgs(prompt);
    case 'imessage_send':
      return parseImessageSendArgs(prompt);
    default:
      return null;
  }
}

async function runPerplexity({
  prompt,
  messages = [],
  systemPrompt,
  userPrompt,
  modelOverride,
  toolDefs = [],
  toolExecutionOptions = {},
  onToken,
  useContext = {},
}) {
  const credentialCheckout = checkoutCachedCredential('perplexity_api_key');
  if (!credentialCheckout) throw new Error('Perplexity API key missing');
  const key = credentialCheckout.value;
  const model = modelOverride || systemConfigStore.readConfigString('PERPLEXITY_MODEL') || systemConfigStore.readConfigString('LLM_MODEL');
  if (!model) throw new Error('Perplexity model missing (set PERPLEXITY_MODEL or LLM_MODEL)');
  const resolvedSystemPrompt = typeof systemPrompt === 'string' ? systemPrompt : '';
  const providedMessages = Array.isArray(messages)
    ? messages
      .filter((entry) => entry && typeof entry.role === 'string' && typeof entry.content === 'string')
      .map((entry) => ({ role: entry.role, content: entry.content }))
    : [];
  const resolvedUserPrompt = (() => {
    if (typeof userPrompt === 'string' && userPrompt.trim()) return userPrompt;
    const latestUser = [...providedMessages].reverse().find((entry) => entry.role === 'user');
    if (latestUser?.content) return String(latestUser.content);
    return String(prompt || '');
  })();
  const conversation = providedMessages.length > 0
    ? [...providedMessages]
    : [
      ...(resolvedSystemPrompt ? [{ role: 'system', content: resolvedSystemPrompt }] : []),
      { role: 'user', content: resolvedUserPrompt }
    ];
  const toolSchemas = (toolDefs || [])
    .map((toolDef) => toolDef?.schema)
    .filter(Boolean);
  const executeToolFn = toolExecutionOptions?.executeToolFn;
  const forcedToolName = String(toolExecutionOptions?.forcedToolName || '').trim();
  const maxRounds = 8;

  if (typeof onToken === 'function' && toolSchemas.length === 0) {
    return runPerplexityStream({
      key,
      credentialCheckout,
      model,
      messages: conversation,
      onToken,
      useContext,
    });
  }

  for (let round = 0; round < maxRounds; round += 1) {
    const payload = {
      model,
      messages: conversation,
      temperature: 0.2
    };

    if (toolSchemas.length > 0) {
      payload.tools = toolSchemas;
      payload.tool_choice = forcedToolName ? 'required' : 'auto';
    }

    const endpoint = 'https://api.perplexity.ai/chat/completions';
    const reservation = await credentialLedger.reserveCredentialUse({
      ...credentialCheckout,
      operation: 'perplexity.chat.completions',
      endpoint,
      requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload, round }),
      subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
      requestReceiptId: useContext?.requestReceiptId || null,
      requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
      autonomousActionEventId: useContext?.autonomousActionEventId || null,
    });
    let res = null;
    let terminalAttempted = false;
    let data;
    try {
      res = await fetchWithTimeout(endpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      }, PROVIDER_REQUEST_TIMEOUT_MS);
      if (!res.ok) throw new Error(`Perplexity error (${res.status}): ${await res.text()}`);
      data = await res.json();
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeClass: 'http_response',
        outcomeHash: credentialUseEvidenceHash({ status: res.status, data }),
      });
    } catch (error) {
      if (!terminalAttempted) {
        terminalAttempted = true;
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          errorClass: error?.name || 'provider_request_failed',
          outcomeClass: 'provider_request_failed',
          outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, error: error?.message || String(error) }),
        });
      }
      throw error;
    }
    const message = data?.choices?.[0]?.message || {};
    const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
    const text = contentToText(message.content);

    if (toolCalls.length === 0) {
      const fallbackToolName = forcedToolName
        || (toolSchemas.length === 1 ? String(toolSchemas[0]?.function?.name || '').trim() : '');
      const fallbackArgs = deriveFallbackToolArgs(fallbackToolName, resolvedUserPrompt);

      if (fallbackToolName && fallbackArgs && typeof executeToolFn === 'function') {
        let fallbackResult;
        try {
          fallbackResult = await executeToolFn(fallbackToolName, fallbackArgs);
          if (isToolApprovalPayload(fallbackResult)) {
            throw createToolApprovalError(fallbackToolName, fallbackResult);
          }
        } catch (err) {
          if (err?.code === 'TOOL_APPROVAL_REQUIRED') throw err;
          fallbackResult = { error: err.message };
        }

        const exactReply = parseExactReplyDirective(resolvedUserPrompt);
        if (toolExecutionOptions?.returnAfterSingleToolCall === true) {
          return exactReply || `${fallbackToolName}: ${summarizeToolResult(fallbackResult)}`;
        }

        conversation.push({
          role: 'tool',
          tool_call_id: `fallback-${round}`,
          name: fallbackToolName,
          content: JSON.stringify(fallbackResult)
        });
      }

      if (typeof onToken === 'function') {
        emitChunkedText(text, onToken);
      }
      return text;
    }

    conversation.push({
      role: 'assistant',
      content: message.content ?? '',
      tool_calls: toolCalls
    });

    if (typeof executeToolFn !== 'function') {
      throw new Error('Perplexity requested tool calls but no tool executor was provided');
    }

    const executedToolResults = [];
    for (let i = 0; i < toolCalls.length; i += 1) {
      const tc = toolCalls[i] || {};
      const toolName = tc?.function?.name;
      const toolCallId = tc.id || `perplexity-tool-${round}-${i}`;
      let result;
      try {
        const args = parseToolArgs(tc?.function?.arguments);
        result = await executeToolFn(toolName, args);
        if (isToolApprovalPayload(result)) {
          throw createToolApprovalError(toolName, result);
        }
      } catch (err) {
        if (err?.code === 'TOOL_APPROVAL_REQUIRED') throw err;
        result = { error: err.message };
      }
      executedToolResults.push({ name: toolName || 'unknown_tool', result });
      conversation.push({
        role: 'tool',
        tool_call_id: toolCallId,
        name: toolName || 'unknown_tool',
        content: JSON.stringify(result)
      });
    }

    if (toolExecutionOptions?.returnAfterSingleToolCall === true && executedToolResults.length > 0) {
      return executedToolResults
        .map(({ name, result }) => `${name}: ${summarizeToolResult(result)}`)
        .join('\n');
    }
  }

  throw new Error('Perplexity tool loop exceeded max rounds without final response');
}

async function runPerplexityStream({ key, credentialCheckout, model, messages, onToken, useContext = {} }) {
  const payload = {
    model,
    messages,
    temperature: 0.2,
    stream: true
  };

  const endpoint = 'https://api.perplexity.ai/chat/completions';
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credentialCheckout,
    operation: 'perplexity.chat.completions.stream',
    endpoint,
    requestHash: credentialUseEvidenceHash({ method: 'POST', endpoint, payload }),
    subjectAgentId: useContext?.actorAgentId || useContext?.subjectAgentId || useContext?.agentId || 'housekeeper',
    requestReceiptId: useContext?.requestReceiptId || null,
    requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext?.autonomousActionEventId || null,
  });
  let res = null;
  let terminalAttempted = false;
  let full = '';
  try {
    res = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    }, PROVIDER_REQUEST_TIMEOUT_MS);
    if (!res.ok) throw new Error(`Perplexity error (${res.status}): ${await res.text()}`);
    if (!res.body) throw new Error('Perplexity stream body missing');

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('data:')) continue;
        const payloadText = line.slice(5).trim();
        if (!payloadText || payloadText === '[DONE]') continue;
        let parsed;
        try {
          parsed = JSON.parse(payloadText);
        } catch {
          continue;
        }
        const delta = String(parsed?.choices?.[0]?.delta?.content || '');
        if (!delta) continue;
        full += delta;
        onToken(delta);
      }
    }
    terminalAttempted = true;
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'completed',
      outcomeClass: 'stream_completed',
      outcomeHash: credentialUseEvidenceHash({ status: res.status, text: full }),
    });
    return full;
  } catch (error) {
    if (!terminalAttempted) {
      terminalAttempted = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        errorClass: error?.name || 'provider_request_failed',
        outcomeClass: 'provider_request_failed',
        outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, partialText: full, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

// ─── PROVIDER FAILOVER ────────────────────────────────────────────────────────
// Source: Circuit Breaker (Netflix Hystrix), Release It (Nygard)
//
// Try primary provider, fall back to next-healthy on failure.
// Each attempt is logged to aimos_events with identity tier info.
// No wrapper — the caller still signs its own envelope natively (Phase 10).
// runProviderWithFailover only handles provider SELECTION, not HTTP interception.
//
// Aladdin: failover marks providers temporarily unavailable but never deletes
//           provider configuration or data.

export async function runProviderWithFailover({
  provider: primaryProvider,
  prompt,
  messages = [],
  model: primaryModel,
  systemPrompt,
  userPrompt,
  toolDefs = [],
  toolExecutionOptions = {},
  onToken,
  agentId = 'system',
  identityTier = 'unknown',
  useContext = {},
} = {}) {
  const maxAttempts = getMaxFailoverAttempts();
  const attempts = [];

  // Build candidate list: primary first, then healthy alternatives sorted by health score
  const candidates = [];
  if (primaryProvider && isCircuitAvailable(primaryProvider)) {
    const resolution = resolveProviderForModel(primaryProvider, primaryModel);
    if (resolution.provider && resolution.model) {
      candidates.push({ provider: resolution.provider, model: resolution.model });
    }
  }

  // Add healthy alternatives from registry, sorted by health score
  const allProviderIds = Object.keys(PROVIDER_REGISTRY);
  const healthyAlternatives = getHealthyProvidersByScore(allProviderIds)
    .filter(h => h.providerId !== primaryProvider)
    .filter(h => isCircuitAvailable(h.providerId));

  for (const alt of healthyAlternatives) {
    const config = PROVIDER_REGISTRY[alt.providerId];
    const altModel = config?.defaultModel?.() || '';
    if (!altModel) continue;
    if (!candidates.some(c => c.provider === alt.providerId)) {
      candidates.push({ provider: alt.providerId, model: altModel });
    }
  }

  // If no candidates at all, try primary anyway (last resort)
  if (candidates.length === 0 && primaryProvider) {
    const resolution = resolveProviderForModel(primaryProvider, primaryModel);
    if (resolution.provider && resolution.model) {
      candidates.push({ provider: resolution.provider, model: resolution.model });
    }
  }

  for (let i = 0; i < Math.min(maxAttempts, candidates.length); i++) {
    const candidate = candidates[i];
    const startTime = Date.now();

    try {
      const result = await runProvider({
        provider: candidate.provider,
        prompt,
        messages,
        model: candidate.model,
        systemPrompt,
        userPrompt,
        toolDefs,
        toolExecutionOptions,
        onToken,
        useContext: {
          agentId,
          ...useContext,
        },
      });

      const latencyMs = Date.now() - startTime;
      recordCircuitSuccess(candidate.provider);
      recordCallOutcome(candidate.provider, true, latencyMs);

      // Log successful attempt (best-effort, non-blocking)
      try {
        await logEvent(
          COMPANY_ID,
          agentId,
          'provider_call',
          `call:${candidate.provider}:${Date.now()}`,
          {
            provider: candidate.provider,
            model: candidate.model,
            latency_ms: latencyMs,
            attempt: i + 1,
            identity_tier: identityTier,
            success: true
          }
        );
      } catch { /* event logging is best-effort */ }

      return result;
    } catch (err) {
      if (String(err?.message || '').startsWith('credential_use_')) {
        throw err;
      }
      const latencyMs = Date.now() - startTime;
      recordCircuitFailure(candidate.provider);
      recordCallOutcome(candidate.provider, false, latencyMs);

      attempts.push({
        provider: candidate.provider,
        model: candidate.model,
        error: err?.message || String(err),
        latency: latencyMs,
        attempt: i + 1
      });

      // Log failed attempt (best-effort, non-blocking)
      try {
        await logEvent(
          COMPANY_ID,
          agentId,
          'provider_failure',
          `failure:${candidate.provider}:${Date.now()}`,
          {
            provider: candidate.provider,
            model: candidate.model,
            error: err?.message || String(err),
            latency_ms: latencyMs,
            attempt: i + 1,
            circuit_state: getCircuitState(candidate.provider),
            identity_tier: identityTier,
            success: false
          }
        );
      } catch { /* event logging is best-effort */ }
    }
  }

  // All attempts exhausted
  const fallbackError = new Error(
    `All ${attempts.length} provider attempts failed: ${attempts.map(a => `${a.provider}: ${a.error}`).join('; ')}`
  );
  fallbackError.code = 'PROVIDER_FAILOVER_EXHAUSTED';
  fallbackError.attempts = attempts;
  throw fallbackError;
}
