import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import express from 'express';
import {
  imessageSearchContact,
  imessageListChats,
  listIntegrationStatus,
} from '../services/integrations/integration-tools.js';
import { peekCachedCredential } from '../services/security/credential-cache.js';
import { systemConfigStore } from '../services/security/system-config-store.js';
import { executeTool } from '../services/orchestration/tool-registry.js';
import { requireCapability } from '../services/security/require-capability.js';

const router = express.Router();

// Global auth-gate is the sole identity authority. This route adds only the
// browser-origin constraint; no shared session-token path is admitted.
const ALLOWED_ORIGINS_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

router.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (origin && !ALLOWED_ORIGINS_RE.test(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  next();
});

const PROVIDERS = [
  { id: 'google', name: 'Google', type: 'oauth', auth: 'google', tokenProvider: 'google' },
  { id: 'gmail', name: 'Gmail', type: 'oauth', auth: 'google', tokenProvider: 'google' },
  { id: 'youtube', name: 'YouTube', type: 'oauth', auth: 'google', tokenProvider: 'google' },
  { id: 'calendar', name: 'Calendar', type: 'oauth', auth: 'google', tokenProvider: 'google' },
  { id: 'drive', name: 'Google Drive', type: 'oauth', auth: 'google', tokenProvider: 'google' },
  { id: 'github', name: 'GitHub', type: 'oauth', auth: 'github' },
  { id: 'openai', name: 'OpenAI', type: 'oauth', auth: 'openai', tokenProvider: 'openai' },
  { id: 'codex', name: 'Codex', type: 'oauth', auth: 'codex', tokenProvider: 'codex' },
  { id: 'x', name: 'X.com', type: 'token' },
  { id: 'salesforce', name: 'Salesforce', type: 'oauth', auth: 'salesforce' },
  { id: 'stripe', name: 'Stripe', type: 'token' },
  { id: 'telegram', name: 'Telegram', type: 'token' },
  { id: 'imessage', name: 'iMessage', type: 'local' }
];
router.get('/status', async (_req, res, next) => {
  try {
    const nativeStatus = await listIntegrationStatus();
    const byProvider = new Map(nativeStatus.map((entry) => [entry.id, entry]));
    const status = PROVIDERS.map(p => {
      const connected = Boolean(byProvider.get(p.id)?.connected);
      return {
        id: p.id,
        name: p.name,
        type: p.type,
        enabled: connected,
        connected,
      };
    });

    res.json({ providers: status });
  } catch (error) {
    next(error);
  }
});

router.post('/telegram/send', requireCapability('email'), async (req, res, next) => {
  const chatId = String(req.body?.chat_id || systemConfigStore.readConfigString('TELEGRAM_CHAT_ID') || '').trim();
  const text = String(req.body?.text || '').trim();

  if (!chatId || !text) return res.status(400).json({ success: false, error: 'chat_id and text are required' });

  try {
    const payload = await executeTool('telegram_send', {
      chat_id: chatId,
      text,
      parse_mode: null,
    }, req.agentId, {
      executionContext: req.executionContext,
      credentialUseContext: req.executionContext,
    });
    if (payload?.blocked || payload?.requiresApproval) return res.status(403).json(payload);
    res.json({ success: true, message: payload.result || payload });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// Request Automation permission — first call triggers macOS TCC prompt
router.post('/imessage/request-access', requireCapability('email'), async (req, res, next) => {
  try {
    const result = await executeTool('imessage_request_access', {
      request_access: true,
    }, req.agentId, {
      executionContext: req.executionContext,
      credentialUseContext: req.executionContext,
    });
    if (result?.blocked || result?.requiresApproval) return res.status(403).json(result);
    res.json({ ...result, connected: result?.success === true });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Read recent chats — delegates to service layer which validates + caps limit
router.get('/imessage/chats', async (req, res, next) => {
  try {
    const chats = await imessageListChats({ limit: req.query.limit }, req.executionContext || {});
    res.json({ success: true, chats });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Send a message
router.post('/imessage/send', requireCapability('email'), async (req, res, next) => {
  const { to, message } = req.body || {};
  if (!to || !message) return res.status(400).json({ error: 'to and message required' });
  try {
    const result = await executeTool('imessage_send', { to, message }, req.agentId, {
      executionContext: req.executionContext,
      credentialUseContext: req.executionContext,
    });
    if (result?.blocked || result?.requiresApproval) return res.status(403).json(result);
    res.json(result);
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/imessage/search-contact', async (req, res, next) => {
  const q = String(req.query.q || req.query.query || '').trim();
  if (!q) return res.status(400).json({ success: false, error: 'q is required' });
  try {
    const matches = await imessageSearchContact({ query: q }, req.executionContext || {});
    res.json({ success: true, matches });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

export default router;
