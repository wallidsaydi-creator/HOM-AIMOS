import express from 'express';
import { fetchWithTimeout } from '../services/orchestration/http.js';
import {
  getModelPreferences,
  resolveModelForRequest
} from '../services/orchestration/model-preferences.js';
import { peekCachedCredential } from '../services/security/credential-cache.js';

const router = express.Router();

function preferencesToList(preferences = {}) {
  return Object.entries(preferences).map(([taskType, pref]) => ({
    taskType,
    provider: pref?.provider || '',
    model: pref?.model || ''
  }));
}

function hasGeminiKey() {
  return !!(peekCachedCredential('gemini_api_key') || peekCachedCredential('google_api_key'));
}

function hasPerplexityKey() {
  return peekCachedCredential('perplexity_api_key');
}

// checkOllamaHealth removed — Ollama retired 2026-03-25

router.get('/model', async (req, res) => {
  const preferences = getModelPreferences();
  const list = preferencesToList(preferences);
  const format = String(req.query?.format || '').trim().toLowerCase();
  if (format === 'wrapped' || format === 'object') {
    return res.json({
      success: true,
      preferences,
      items: list
    });
  }
  res.json(list);
});

router.post('/model', async (req, res) => {
  const taskType = String(req.body?.taskType || '').trim();
  const provider = String(req.body?.provider || '').trim();
  const model = String(req.body?.model || '').trim();

  if (!taskType || !provider || !model) {
    return res.status(400).json({
      success: false,
      error: 'taskType, provider, and model are required'
    });
  }

  const configKey = `MODEL_PREFERENCE_${taskType.toUpperCase()}`;
  const preference = JSON.stringify({ provider, model });
  return res.status(410).json({
    success: false,
    error: 'unsigned model preference mutation retired',
    ceremony: `node scripts/identity/set-system-config.js ${configKey} '${preference}' --reason=model_preference`,
  });
});

router.post('/model/resolve', async (req, res) => {
  const taskType = String(req.body?.taskType || '').trim();
  const prompt = String(req.body?.prompt || '').trim();
  const resolution = resolveModelForRequest({ taskType, prompt });
  res.json({ success: true, resolution });
});

router.get('/model/health', async (req, res) => {
  const preferences = getModelPreferences();
  const models = preferencesToList(preferences);

  const statuses = models.map((item) => {
    if (item.provider === 'gemini') {
      return {
        ...item,
        available: hasGeminiKey(),
        reason: hasGeminiKey() ? null : 'GEMINI_API_KEY/GOOGLE_API_KEY missing'
      };
    }
    if (item.provider === 'perplexity') {
      return {
        ...item,
        available: hasPerplexityKey(),
        reason: hasPerplexityKey() ? null : 'PERPLEXITY_API_KEY missing'
      };
    }
    return {
      ...item,
      available: true,
      reason: null
    };
  });

  const taskTypeHealth = {};
  const modelHealth = {};
  for (const status of statuses) {
    if (status.taskType) taskTypeHealth[status.taskType] = !!status.available;
    if (status.model) modelHealth[status.model] = !!status.available;
  }

  const format = String(req.query?.format || '').trim().toLowerCase();
  if (format === 'wrapped' || format === 'object') {
    return res.json({
      success: true,
      statuses,
      taskTypeHealth,
      modelHealth
    });
  }

  // Backward-compatible shape consumed by desktop UI.
  res.json({
    ...taskTypeHealth,
    ...modelHealth
  });
});

export default router;
