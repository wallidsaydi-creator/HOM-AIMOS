import os from 'node:os';

export const ONBOARDING_MODEL_TASKS = Object.freeze(['CHAT', 'HEAVY', 'RESEARCH', 'FAST', 'CODING']);
export const PUBLIC_AGENT_CLEARANCE_DEFAULT = 10;
export const PUBLIC_AGENT_CLEARANCE_MAXIMUM = 10;

export function normalizeOnboardingAgentId(value) {
  const agentId = String(value || '').trim();
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(agentId)) {
    throw new Error('onboarding_agent_id_invalid');
  }
  if (new Set(['housekeeper', 'aimos_flag_signer']).has(agentId.toLowerCase())) {
    throw new Error('onboarding_system_agent_id_reserved');
  }
  return agentId;
}

export function defaultOnboardingKeychainAccount(context, username = os.userInfo().username) {
  const user = String(username || '').trim();
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(user)) throw new Error('onboarding_os_user_invalid');
  return context?.canonical ? user : `${user}-${String(context?.instance || '')}`;
}

export function normalizeOnboardingModelPreference(providerValue, modelValue) {
  const provider = String(providerValue || '').trim().toLowerCase();
  const model = String(modelValue || '').trim();
  if (!provider && !model) return null;
  if (!provider || !model) throw new Error('onboarding_model_preference_incomplete');
  if (!/^[a-z0-9_-]{1,64}$/.test(provider) || model.length > 256 || /[\u0000-\u001f\u007f]/.test(model)) {
    throw new Error('onboarding_model_preference_invalid');
  }
  return Object.freeze({ provider, model });
}

export function onboardingModelConfigEntries(preference) {
  if (!preference) return [];
  const value = JSON.stringify({ provider: preference.provider, model: preference.model });
  return ONBOARDING_MODEL_TASKS.map((task) => Object.freeze({
    configKey: `MODEL_PREFERENCE_${task}`,
    value,
  }));
}
