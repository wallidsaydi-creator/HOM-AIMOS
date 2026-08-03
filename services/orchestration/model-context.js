// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: hom-constitution.js
// Pipeline: CONSTITUTION | Position: Model context window configuration
// ─────────────────────────────────────────────────────────────────────────────
import { systemConfigStore } from '../security/system-config-store.js';

function parseNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
}

function getDefaultContextWindowTokens() {
  const v = systemConfigStore.readConfigString('CONTEXT_WINDOW_TOKENS');
  const n = parseNumber(v);
  return n || 128_000;
}

function getModelContextOverrides() {
  const raw = systemConfigStore.readConfigString('MODEL_CONTEXT_WINDOWS_JSON');
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return [];
    return Object.entries(parsed)
      .map(([pattern, tokens]) => {
        const n = parseNumber(tokens);
        if (!pattern || !n) return null;
        return { pattern: String(pattern).trim().toLowerCase(), tokens: n };
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

// Provider/model context windows must be supplied by MODEL_CONTEXT_WINDOWS_JSON
// or the global CONTEXT_WINDOW_TOKENS fallback. No model-family literals here.
const BASE_RULES = [];

export function normalizeModelId(modelId) {
  let model = String(modelId || '').trim().toLowerCase();
  if (!model) return '';
  model = model.replace(/^openai[:/]/, '');
  model = model.replace(/^perplexity[:/]/, '');
  return model;
}

function wildcardMatch(pattern, model) {
  if (!pattern.includes('*')) return model === pattern;
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(model);
}

function matchRule(pattern, model) {
  const p = String(pattern || '').trim().toLowerCase();
  if (!p) return false;
  if (p.includes('*')) return wildcardMatch(p, model);
  return model === p || model.startsWith(p) || model.includes(p);
}

export function getModelContextWindow(modelId) {
  const model = normalizeModelId(modelId);

  if (!model) {
    return {
      model,
      windowTokens: getDefaultContextWindowTokens(),
      source: 'global-default'
    };
  }

  const overrides = getModelContextOverrides();
  for (const override of overrides) {
    if (matchRule(override.pattern, model)) {
      return {
        model,
        windowTokens: override.tokens,
        source: 'config-override'
      };
    }
  }

  const rule = BASE_RULES.find((item) => matchRule(item.pattern, model));
  if (rule) {
    return {
      model,
      windowTokens: rule.tokens,
      source: rule.source
    };
  }

  return {
    model,
    windowTokens: getDefaultContextWindowTokens(),
    source: 'global-default'
  };
}
