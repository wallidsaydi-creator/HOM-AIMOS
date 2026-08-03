import express from 'express';
import { gmailListInbox, calendarTodayEvents } from '../services/integrations/google-tools.js';
import { searchWeb } from '../services/integrations/web-search.js';
import { executeTool } from '../services/orchestration/tool-registry.js';

const router = express.Router();

router.post('/quick-action', async (req, res) => {
  const action = String(req.body?.action || '').trim().toLowerCase();

  try {
    if (action === 'email') {
      const messages = await gmailListInbox({ maxResults: 5, query: 'in:inbox' }, req.executionContext);
      return res.json({ success: true, action, messages });
    }

    if (action === 'calendar') {
      const calendar = await calendarTodayEvents(req.executionContext);
      return res.json({ success: true, action, ...calendar });
    }

    if (action === 'search') {
      const query = String(req.body?.query || '').trim();
      if (!query) {
        return res.status(400).json({ success: false, error: 'query is required for search action' });
      }
      const result = await searchWeb({
        query,
        maxResults: Number(req.body?.maxResults) || 5,
        useContext: {
          actorAgentId: req.executionContext?.actorAgentId,
          requestReceiptId: req.executionContext?.requestReceiptId,
          requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
          requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
          requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
        },
      });
      return res.json({ success: true, action, ...result });
    }

    if (action === 'remember') {
      const text = String(req.body?.text || '').trim();
      if (!text) {
        return res.status(400).json({ success: false, error: 'text is required for remember action' });
      }
      const saved = await executeTool('aimos_save', { content: text }, req.agentId, {
        executionContext: req.executionContext,
        credentialUseContext: req.executionContext,
        clearanceLevel: 1,
      });
      return res.json({ success: true, action, result: saved });
    }

    return res.status(400).json({
      success: false,
      error: 'Unknown action. Supported: email, calendar, search, remember'
    });
  } catch (error) {
    const msg = String(error?.message || error || '');
    if (/not configured|missing|not connected|oauth/i.test(msg)) {
      return res.json({ success: false, error: msg, available: false });
    }
    return res.status(500).json({ success: false, error: msg });
  }
});

export default router;
