import {
  discoverActiveProviders,
  resolveProviderForModel,
  runProvider
} from '../core/providers.js';
import { systemConfigStore } from '../security/system-config-store.js';

function clean(value) {
  if (typeof value !== 'string') return '';
  return value.trim();
}

function firstSignedConfig(keys = []) {
  for (const key of keys) {
    const value = clean(systemConfigStore.readConfigString(key));
    if (value) return value;
  }
  return '';
}

function normalizeTarget(resolution) {
  if (!resolution?.provider) {
    throw new Error('[native-llm] No provider resolved for Aimos native path');
  }

  return resolution;
}

export function listNativeProviderTargets(opts = {}) {
  const requestedProvider = clean(opts.provider) || firstSignedConfig(opts.providerConfigKeys || ['LLM_PROVIDER']);
  const requestedModel = clean(opts.model) || firstSignedConfig(opts.modelConfigKeys || ['LLM_MODEL', 'OLLAMA_MODEL']);
  const requestedResolution = resolveProviderForModel(
    requestedProvider || requestedModel,
    requestedModel
  );

  const targets = [];
  const seen = new Set();

  const addTarget = (resolution) => {
    try {
      const target = normalizeTarget(resolution);
      const key = `${target.provider}::${target.model || ''}`;
      if (!seen.has(key)) {
        seen.add(key);
        targets.push(target);
      }
    } catch (_error) {
      // Ignore unresolved targets while preserving provider-agnostic fallback behavior.
    }
  };

  if (requestedResolution.provider) {
    addTarget(requestedResolution);
    return targets;
  }

  for (const entry of discoverActiveProviders()) {
    if (!entry.active) continue;
    addTarget(resolveProviderForModel(entry.provider, requestedModel));
  }

  if (targets.length === 0) {
    throw new Error('[native-llm] No native provider is configured');
  }

  return targets;
}

function summarizeProviderError(error) {
  const message = error instanceof Error ? error.message : String(error || 'unknown provider error');
  return message.replace(/\s+/g, ' ').trim();
}

export async function callNativeLlm(promptOrOpts, maybeOpts = {}) {
  const opts = promptOrOpts && typeof promptOrOpts === 'object' && !Array.isArray(promptOrOpts)
    ? promptOrOpts
    : { ...maybeOpts, prompt: promptOrOpts };

  const prompt = clean(opts.prompt);
  const userPrompt = clean(opts.userPrompt) || prompt;
  const systemPrompt = clean(opts.systemPrompt);

  if (!userPrompt) return '';

  const targets = listNativeProviderTargets(opts);
  const failures = [];

  for (const target of targets) {
    try {
      return await runProvider({
        provider: target.provider,
        model: target.model || undefined,
        prompt: prompt || userPrompt,
        systemPrompt,
        userPrompt
      });
    } catch (error) {
      failures.push(`${target.provider}:${target.model || 'default'} => ${summarizeProviderError(error)}`);
    }
  }

  throw new Error(`[native-llm] All Aimos-native providers failed: ${failures.join(' | ')}`);
}
