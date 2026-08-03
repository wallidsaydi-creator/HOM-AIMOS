import express from 'express';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { searchWeb } from '../services/integrations/web-search.js';
import { xSearchRecent } from '../services/integrations/x-search.js';
import { xGetMyProfile, xGetMyTimeline, xPostTweet, xReplyToTweet, xQuoteTweet } from '../services/integrations/x-tools.js';
import {
  stripeAccountSummary,
  stripeListCustomers,
  stripeListSubscriptions,
  stripeListPaymentIntents
} from '../services/integrations/stripe-tools.js';
import {
  listIntegrationStatus,
  githubListRepos,
  githubSearchIssues,
  githubListMyIssues,
  githubListMyPullRequests,
  salesforceListObjects,
  contactsSearch,
  imessageListChats,
  imessageSearchContact,
  imessageSend
} from '../services/integrations/integration-tools.js';
import { executeTool, preflightTool } from '../services/orchestration/tool-registry.js';
import {
  getToolApprovalRequest,
  listToolApprovalRequests,
  markToolApprovalApproved,
  markToolApprovalExecuted,
  markToolApprovalFailed,
  markToolApprovalRejected,
  reserveToolApprovalExecution,
} from '../services/orchestration/tool-approval-store.js';
import {
  gmailListInbox, gmailSearchMessages, gmailSendMessage, gmailReplyMessage, gmailGetMessage, gmailGetThread,
  youtubeSearch, youtubeChannelStats, youtubeVideoDetails, youtubeListChannelVideos,
  driveListFiles, driveGetFile, driveReadTextFile,
  calendarListEvents, calendarCreateEvent, calendarTodayEvents,
  docsGetDocument, sheetsGetValues,
  googleGetProfile
} from '../services/integrations/google-tools.js';
import { createScheduledTask, listScheduledTasks } from '../services/orchestration/scheduler.js';
import { telegramGetUpdates, telegramSendMessage } from '../services/integrations/telegram-tools.js';
import { systemConfigStore } from '../services/security/system-config-store.js';
import { requireCapability } from '../services/security/require-capability.js';

const router = express.Router();

// R1 Step 1: per-endpoint authorization now lives in the shared
// requireCapability(capability) middleware. Identity comes ONLY from
// req.agentId (the verified cert); the catch path DENIES with 503.
// The previous inline gate read agent_id from the body/query/x-agent-id
// header and failed OPEN on DB errors — both removed.

const SKILL_DEFAULT_ROOTS = [
  path.join(os.homedir(), '.agents', 'skills'),
  path.join(os.homedir(), '.codex', 'skills'),
  path.join(os.homedir(), '.claude', 'skills')
];

function inferSkillSource(skillPath) {
  const lower = skillPath.toLowerCase();
  if (lower.includes('/.agents/')) return 'openclaw';
  if (lower.includes('/.codex/')) return 'codex';
  if (lower.includes('/anthropic') || lower.includes('/claude')) return 'anthropic';
  return 'custom';
}

function safeStat(p) {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}

function readFirstLine(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    for (const line of lines) {
      const t = line.trim();
      if (t.startsWith('#')) return t.replace(/^#+\s*/, '');
      if (t.length > 0) return t.slice(0, 120);
    }
  } catch {}
  return '';
}

function scanSkillRoots(roots, maxItems = 2000, maxDepth = 8) {
  const out = [];
  const stack = roots
    .filter(Boolean)
    .map(r => ({ dir: path.resolve(r), depth: 0 }));

  while (stack.length && out.length < maxItems) {
    const { dir, depth } = stack.pop();
    if (depth > maxDepth) continue;
    const st = safeStat(dir);
    if (!st || !st.isDirectory()) continue;

    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (out.length >= maxItems) break;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      if (entry.name !== 'SKILL.md') continue;

      const skillDir = path.dirname(full);
      out.push({
        id: path.basename(skillDir),
        name: path.basename(skillDir),
        source: inferSkillSource(full),
        skillPath: full,
        rootPath: roots.find(r => full.startsWith(path.resolve(r))) || '',
        title: readFirstLine(full)
      });
    }
  }

  return out.sort((a, b) => a.name.localeCompare(b.name));
}

function isMissingConfigError(error) {
  const message = String(error?.message || '').toLowerCase();
  if (!message) return false;
  return (
    message.includes('not configured')
    || message.includes('missing')
    || message.includes('not connected')
    || message.includes('oauth')
    || message.includes('requires funded')
    || message.includes('requires elevated')
  );
}

function unavailable(res, message) {
  return res.json({ success: false, error: message, available: false });
}

function handleServiceError(res, error, fallbackMessage, next) {
  if (isMissingConfigError(error)) {
    return unavailable(res, fallbackMessage);
  }
  error.statusCode = 500;
  return next(error);
}

// ─── WEB ──────────────────────────────────────────────────────────────────────

router.post('/web/search', async (req, res, next) => {
  const { query, maxResults } = req.body || {};
  if (!query) return res.status(400).json({ success: false, error: 'query is required' });
  try {
    const result = await searchWeb({
      query,
      maxResults: maxResults || 5,
      useContext: {
        actorAgentId: req.executionContext?.actorAgentId,
        requestReceiptId: req.executionContext?.requestReceiptId,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
      },
    });
    res.json({ success: true, ...result });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/x/search', async (req, res, next) => {
  const query = req.query.q || req.query.query;
  if (!query) return res.status(400).json({ success: false, error: 'q is required' });
  try {
    const result = await xSearchRecent({
      query: String(query),
      maxResults: Number(req.query.max) || Number(req.query.maxResults) || 20,
      useContext: req.executionContext,
    });
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(
      res,
      error,
      'X credentials are not enrolled in the signed Keychain lane.',
      next
    );
  }
});

router.get('/x/profile', async (req, res, next) => {
  try {
    const result = await xGetMyProfile(req.executionContext);
    res.json(result);
  } catch (error) {
    handleServiceError(
      res,
      error,
      'X credentials are not enrolled in the signed Keychain lane.',
      next
    );
  }
});

router.get('/x/timeline', async (req, res, next) => {
  const max = Number(req.query.max || req.query.maxResults || 20);
  try {
    const result = await xGetMyTimeline({ max, useContext: req.executionContext });
    res.json(result);
  } catch (error) {
    handleServiceError(
      res,
      error,
      'X credentials are not enrolled in the signed Keychain lane.',
      next
    );
  }
});

router.post('/x/reply', requireCapability('x'), async (req, res, next) => {
  const text = String(req.body?.text || '').trim();
  const replyToTweetId = String(req.body?.reply_to_tweet_id || '').trim();
  if (!text) return res.status(400).json({ success: false, error: 'text is required' });
  if (!replyToTweetId) return res.status(400).json({ success: false, error: 'reply_to_tweet_id is required' });
  try {
    const result = await xReplyToTweet({ text, replyToTweetId, useContext: req.executionContext });
    res.json(result);
  } catch (error) {
    handleServiceError(
      res,
      error,
      'X posting credentials are not enrolled in the signed Keychain lane.',
      next
    );
  }
});

router.post('/x/post', requireCapability('x'), async (req, res, next) => {
  const text = String(req.body?.text || '').trim();
  if (!text) return res.status(400).json({ success: false, error: 'text is required' });
  try {
    const result = await xPostTweet({ text, useContext: req.executionContext });
    res.json(result);
  } catch (error) {
    handleServiceError(
      res,
      error,
      'X posting credentials are not enrolled in the signed Keychain lane.',
      next
    );
  }
});

router.post('/x/quote', requireCapability('x'), async (req, res, next) => {
  const text = String(req.body?.text || '').trim();
  const quoteTweetId = String(req.body?.quote_tweet_id || '').trim();
  if (!text) return res.status(400).json({ success: false, error: 'text is required' });
  if (!quoteTweetId) return res.status(400).json({ success: false, error: 'quote_tweet_id is required' });
  try {
    const result = await xQuoteTweet({ text, quoteTweetId, useContext: req.executionContext });
    res.json(result);
  } catch (error) {
    handleServiceError(
      res,
      error,
      'X posting credentials are not enrolled in the signed Keychain lane.',
      next
    );
  }
});

router.get('/stripe/account', async (req, res, next) => {
  try {
    const result = await stripeAccountSummary({
      actorAgentId: req.executionContext?.actorAgentId,
      requestReceiptId: req.executionContext?.requestReceiptId,
      requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
      requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
      requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
    });
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(res, error, 'Stripe credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.get('/stripe/customers', async (req, res, next) => {
  try {
    const result = await stripeListCustomers({
      limit: Number(req.query.limit) || 20,
      email: String(req.query.email || ''),
      useContext: {
        actorAgentId: req.executionContext?.actorAgentId,
        requestReceiptId: req.executionContext?.requestReceiptId,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
      },
    });
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(res, error, 'Stripe credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.get('/stripe/subscriptions', async (req, res, next) => {
  try {
    const result = await stripeListSubscriptions({
      limit: Number(req.query.limit) || 20,
      status: String(req.query.status || 'all'),
      useContext: {
        actorAgentId: req.executionContext?.actorAgentId,
        requestReceiptId: req.executionContext?.requestReceiptId,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
      },
    });
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(res, error, 'Stripe credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.get('/stripe/payment-intents', async (req, res, next) => {
  try {
    const result = await stripeListPaymentIntents({
      limit: Number(req.query.limit) || 20,
      useContext: {
        actorAgentId: req.executionContext?.actorAgentId,
        requestReceiptId: req.executionContext?.requestReceiptId,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
      },
    });
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(res, error, 'Stripe credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.get('/integrations/status', async (req, res, next) => {
  try {
    const result = await listIntegrationStatus();
    res.json({ success: true, providers: result });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/telegram/send', requireCapability('email'), async (req, res, next) => {
  const chatId = String(req.body?.chat_id || systemConfigStore.readConfigString('TELEGRAM_CHAT_ID') || '').trim();
  const text = String(req.body?.text || '').trim();

  if (!chatId || !text) {
    return res.status(400).json({ success: false, error: 'chat_id and text are required' });
  }

  try {
    const payload = await telegramSendMessage({
      chatId,
      text,
      parseMode: 'Markdown',
      useContext: {
        actorAgentId: req.executionContext?.actorAgentId,
        requestReceiptId: req.executionContext?.requestReceiptId,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
      },
    });
    res.json({ success: true, message: payload?.result || null });
  } catch (error) {
    handleServiceError(res, error, 'Telegram credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.get('/telegram/recent', async (req, res, next) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
  try {
    const payload = await telegramGetUpdates({
      limit,
      useContext: {
        actorAgentId: req.executionContext?.actorAgentId,
        requestReceiptId: req.executionContext?.requestReceiptId,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
      },
    });
    const items = (payload?.result || []).map((item) => ({
      update_id: item.update_id,
      chat_id: item?.message?.chat?.id || item?.channel_post?.chat?.id || null,
      text: item?.message?.text || item?.channel_post?.text || '',
      date: item?.message?.date || item?.channel_post?.date || null,
      from: item?.message?.from?.username || item?.message?.from?.first_name || ''
    }));
    res.json({ success: true, count: items.length, items });
  } catch (error) {
    handleServiceError(res, error, 'Telegram credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.post('/github/repos', requireCapability('github'), async (req, res, next) => {
  try {
    const result = await githubListRepos({
      limit: Number(req.body?.limit) || 20,
      visibility: String(req.body?.visibility || 'all')
    }, req.executionContext);
    res.json({ success: true, items: result });
  } catch (error) {
    handleServiceError(res, error, 'GitHub credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.post('/github/issues/search', requireCapability('github'), async (req, res, next) => {
  try {
    const query = String(req.body?.query || '');
    const result = await githubSearchIssues({
      query,
      limit: Number(req.body?.limit) || 10
    }, req.executionContext);
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(res, error, 'GitHub credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.post('/github/issues', requireCapability('github'), async (req, res, next) => {
  try {
    const items = await githubListMyIssues(
      { limit: Number(req.body?.limit) || 20 },
      req.executionContext,
    );
    res.json({ success: true, items });
  } catch (error) {
    handleServiceError(res, error, 'GitHub credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.post('/github/prs', requireCapability('github'), async (req, res, next) => {
  try {
    const items = await githubListMyPullRequests(
      { limit: Number(req.body?.limit) || 20 },
      req.executionContext,
    );
    res.json({ success: true, items });
  } catch (error) {
    handleServiceError(res, error, 'GitHub credential is not enrolled in the signed Keychain lane.', next);
  }
});

router.post('/salesforce/objects', requireCapability('salesforce'), async (req, res, next) => {
  try {
    const result = await salesforceListObjects({
      limit: Number(req.body?.limit) || 50
    }, req.executionContext);
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(
      res,
      error,
      'Salesforce credential or signed SALESFORCE_ORIGIN is not enrolled.',
      next
    );
  }
});

router.get('/imessage/chats', async (req, res, next) => {
  try {
    const chats = await imessageListChats({ limit: Number(req.query.limit) || 10 });
    res.json({ success: true, chats });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/imessage/send', requireCapability('email'), async (req, res, next) => {
  try {
    const result = await imessageSend({
      to: req.body?.to,
      message: req.body?.message
    });
    res.json(result);
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/imessage/search-contact', async (req, res, next) => {
  const q = String(req.query.q || req.query.query || '').trim();
  if (!q) return res.status(400).json({ success: false, error: 'q is required' });
  try {
    const matches = await imessageSearchContact({ query: q });
    res.json({ success: true, matches });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/contacts/search', async (req, res, next) => {
  const q = String(req.query.q || req.query.query || '').trim();
  if (!q) return res.status(400).json({ success: false, error: 'q is required' });
  try {
    const matches = await contactsSearch({ query: q });
    res.json({ success: true, matches });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/preflight', async (req, res) => {
  const { name, args, agentId } = req.body || {};
  if (!name) return res.status(400).json({ success: false, error: 'name is required' });
  const result = preflightTool(String(name), args || {}, String(agentId || 'unknown'));
  res.json({ success: result.ok, ...result });
});

router.get('/approvals', requireCapability('admin_override'), async (req, res, next) => {
  const status = String(req.query.status || 'pending').trim();
  const agentId = req.query.agentId ? String(req.query.agentId) : null;
  const limit = Number(req.query.limit) || 50;
  try {
    const items = await listToolApprovalRequests({ status, agentId, limit });
    res.json({ success: true, items });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/approvals/:id/approve', requireCapability('admin_override'), async (req, res, next) => {
  const approvalId = String(req.params.id || '').trim();
  if (!approvalId) return res.status(400).json({ success: false, error: 'approval id is required' });

  const approval = await getToolApprovalRequest(approvalId);
  if (!approval) return res.status(404).json({ success: false, error: 'approval request not found' });

  if (approval.status !== 'pending' && approval.status !== 'approved') {
    return res.status(409).json({
      success: false,
      error: `approval request is already ${approval.status}`,
      approval
    });
  }

  try {
    const approved = approval.status === 'pending'
      ? (await markToolApprovalApproved(approvalId, req.executionContext)).approval
      : approval;
    const reserved = await reserveToolApprovalExecution(approvalId, req.executionContext);
    const result = await executeTool(
      approved.tool,
      approved.args || {},
      approved.agentId || 'unknown',
      {
        approved: true,
        executionContext: req.executionContext,
        credentialUseContext: req.executionContext,
        approvalEvidence: {
          approvalId,
          reservationEventId: reserved.receipt.event_id,
          reservationMutationHash: reserved.receipt.mutation_hash,
        },
      }
    );
    const updated = await markToolApprovalExecuted(approvalId, result, req.executionContext);
    res.json({ success: true, approval: updated.approval, result });
  } catch (error) {
    try {
      await markToolApprovalFailed(approvalId, error?.message || error, req.executionContext);
    } catch { /* the original execution error remains authoritative */ }
    error.statusCode = 500;
    next(error);
  }
});

router.post('/approvals/:id/reject', requireCapability('admin_override'), async (req, res, next) => {
  const approvalId = String(req.params.id || '').trim();
  if (!approvalId) return res.status(400).json({ success: false, error: 'approval id is required' });

  const approval = await getToolApprovalRequest(approvalId);
  if (!approval) return res.status(404).json({ success: false, error: 'approval request not found' });

  const reason = String(req.body?.reason || 'Rejected from UI');
  try {
    const updated = await markToolApprovalRejected(approvalId, reason, req.executionContext);
    res.json({ success: true, approval: updated.approval });
  } catch (error) {
    error.statusCode = 409;
    next(error);
  }
});

router.get('/skills/scan', async (req, res) => {
  // Security: never scan from homedir root — restrict to known skill directories only
  const roots = SKILL_DEFAULT_ROOTS;

  const maxItems = Math.min(Math.max(Number(req.query.max) || 2000, 100), 10000);
  const maxDepth = Math.min(Math.max(Number(req.query.depth) || (fullMachine ? 10 : 8), 2), 12);
  const items = scanSkillRoots(roots, maxItems, maxDepth);

  const bySource = items.reduce((acc, item) => {
    acc[item.source] = (acc[item.source] || 0) + 1;
    return acc;
  }, {});

  res.json({
    success: true,
    total: items.length,
    roots,
    bySource,
    items
  });
});

// ─── GOOGLE PROFILE ──────────────────────────────────────────────────────────

router.get('/google/profile', async (req, res, next) => {
  try { res.json(await googleGetProfile(req.executionContext)); }
  catch (e) {
    handleServiceError(res, e, 'Google not configured. Connect Google OAuth first.', next);
  }
});

// ─── GMAIL ────────────────────────────────────────────────────────────────────

router.get('/gmail/inbox', async (req, res, next) => {
  try {
    const messages = await gmailListInbox({ maxResults: Number(req.query.max) || 10, query: req.query.q }, req.executionContext);
    res.json({ success: true, messages });
  } catch (e) {
    handleServiceError(
      res,
      e,
      'Gmail not configured. Connect Google OAuth first.',
      next
    );
  }
});

router.get('/gmail/search', async (req, res, next) => {
  if (!req.query.q) return res.status(400).json({ error: 'q is required' });
  try {
    const messages = await gmailSearchMessages({ query: req.query.q, maxResults: Number(req.query.max) || 10 }, req.executionContext);
    res.json({ success: true, messages });
  } catch (e) {
    handleServiceError(
      res,
      e,
      'Gmail not configured. Connect Google OAuth first.',
      next
    );
  }
});

router.get('/gmail/message/:id', async (req, res, next) => {
  try { res.json(await gmailGetMessage(req.params.id, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

router.get('/gmail/thread/:id', async (req, res, next) => {
  try { res.json(await gmailGetThread(req.params.id, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

router.post('/gmail/send', requireCapability('email'), async (req, res, next) => {
  const { to, subject, body } = req.body || {};
  if (!to || !subject || !body) return res.status(400).json({ error: 'to, subject, body required' });
  try { res.json(await gmailSendMessage({ to, subject, body }, req.executionContext)); }
  catch (e) {
    handleServiceError(
      res,
      e,
      'Gmail not configured. Connect Google OAuth first.',
      next
    );
  }
});

router.post('/gmail/reply', requireCapability('email'), async (req, res, next) => {
  const messageId = String(req.body?.messageId || '').trim();
  const body = String(req.body?.body || '').trim();
  if (!messageId || !body) {
    return res.status(400).json({ success: false, error: 'messageId and body are required' });
  }
  try {
    const result = await gmailReplyMessage({ messageId, body }, req.executionContext);
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(
      res,
      error,
      'Gmail not configured. Connect Google OAuth first.',
      next
    );
  }
});

router.post('/email/send', async (req, res, next) => {
  const { to, subject, body } = req.body || {};
  if (!to || !subject || !body) {
    return res.status(400).json({ success: false, error: 'to, subject, body required' });
  }
  try {
    const result = await gmailSendMessage({ to, subject, body }, req.executionContext);
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(
      res,
      error,
      'Gmail not configured. Connect Google OAuth first.',
      next
    );
  }
});

router.post('/email/reply', async (req, res, next) => {
  const messageId = String(req.body?.messageId || '').trim();
  const body = String(req.body?.body || '').trim();
  if (!messageId || !body) {
    return res.status(400).json({ success: false, error: 'messageId and body are required' });
  }
  try {
    const result = await gmailReplyMessage({ messageId, body }, req.executionContext);
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(
      res,
      error,
      'Gmail not configured. Connect Google OAuth first.',
      next
    );
  }
});

// ─── YOUTUBE ──────────────────────────────────────────────────────────────────

router.get('/youtube/search', async (req, res, next) => {
  if (!req.query.q) return res.status(400).json({ error: 'q is required' });
  try { res.json(await youtubeSearch({ query: req.query.q, maxResults: Number(req.query.max) || 10 }, req.executionContext)); }
  catch (e) {
    handleServiceError(res, e, 'YouTube not configured. Connect Google OAuth first.', next);
  }
});

router.get('/youtube/channel', async (req, res, next) => {
  try { res.json(await youtubeChannelStats(req.query.id, req.executionContext)); }
  catch (e) {
    handleServiceError(res, e, 'YouTube not configured. Connect Google OAuth first.', next);
  }
});

router.get('/youtube/channel/videos', async (req, res, next) => {
  try { res.json(await youtubeListChannelVideos({ channelId: req.query.id, maxResults: Number(req.query.max) || 20 }, req.executionContext)); }
  catch (e) {
    handleServiceError(res, e, 'YouTube not configured. Connect Google OAuth first.', next);
  }
});

// Compatibility alias used by the macOS Integrations panel.
router.get('/youtube/videos', async (req, res, next) => {
  try { res.json(await youtubeListChannelVideos({ channelId: req.query.id, maxResults: Number(req.query.max) || 20 }, req.executionContext)); }
  catch (e) {
    handleServiceError(res, e, 'YouTube not configured. Connect Google OAuth first.', next);
  }
});

router.get('/youtube/recent', async (req, res, next) => {
  try {
    const result = await youtubeListChannelVideos({
      channelId: req.query.id,
      maxResults: Number(req.query.max) || 20
    }, req.executionContext);
    res.json({ success: true, ...result });
  } catch (error) {
    handleServiceError(res, error, 'YouTube not configured. Connect Google OAuth first.', next);
  }
});

router.get('/youtube/video/:id', async (req, res, next) => {
  try { res.json(await youtubeVideoDetails(req.params.id, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

// ─── DRIVE ────────────────────────────────────────────────────────────────────

router.get('/drive/files', async (req, res, next) => {
  try { res.json(await driveListFiles({ query: req.query.q, maxResults: Number(req.query.max) || 20, mimeType: req.query.mime }, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

router.get('/drive/file/:id', async (req, res, next) => {
  try { res.json(await driveGetFile(req.params.id, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

router.get('/drive/file/:id/content', async (req, res, next) => {
  try { res.send(await driveReadTextFile(req.params.id, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

// ─── CALENDAR ─────────────────────────────────────────────────────────────────

router.get('/calendar/today', async (req, res, next) => {
  try { res.json(await calendarTodayEvents(req.executionContext)); }
  catch (e) {
    handleServiceError(res, e, 'Calendar not configured. Connect Google OAuth first.', next);
  }
});

router.get('/calendar/events', async (req, res, next) => {
  try {
    const events = await calendarListEvents({ maxResults: Number(req.query.max) || 20, timeMin: req.query.from }, req.executionContext);
    res.json(events);
  } catch (e) {
    handleServiceError(res, e, 'Calendar not configured. Connect Google OAuth first.', next);
  }
});

router.post('/calendar/events', async (req, res, next) => {
  const { summary, description, start, end } = req.body || {};
  if (!summary || !start || !end) return res.status(400).json({ error: 'summary, start, end required' });
  try { res.json(await calendarCreateEvent({ summary, description, start, end }, req.executionContext)); }
  catch (e) {
    handleServiceError(res, e, 'Calendar not configured. Connect Google OAuth first.', next);
  }
});

router.post('/calendar/create', async (req, res, next) => {
  const { summary, description, start, end } = req.body || {};
  if (!summary || !start) {
    return res.status(400).json({ success: false, error: 'summary and start are required' });
  }

  const endValue = String(end || '').trim()
    || new Date(new Date(start).getTime() + 60 * 60 * 1000).toISOString();

  try {
    const event = await calendarCreateEvent({
      summary,
      description: description || '',
      start,
      end: endValue
    }, req.executionContext);
    res.json({ success: true, event });
  } catch (error) {
    handleServiceError(res, error, 'Calendar not configured. Connect Google OAuth first.', next);
  }
});

// ─── DOCS / SHEETS ────────────────────────────────────────────────────────────

router.get('/docs/:id', async (req, res, next) => {
  try { res.json(await docsGetDocument(req.params.id, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

router.get('/sheets/:id/values', async (req, res, next) => {
  try { res.json(await sheetsGetValues(req.params.id, req.query.range, req.executionContext)); }
  catch (e) { e.statusCode = 500; next(e); }
});

// ─── SCHEDULE ─────────────────────────────────────────────────────────────────

router.get('/schedule/tasks', requireCapability('admin_override'), async (req, res, next) => {
  try {
    const items = await listScheduledTasks();
    res.json({ success: true, items });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/schedule/tasks', requireCapability('admin_override'), async (req, res, next) => {
  const cronExpression = String(req.body?.cron_expression || '').trim();
  const taskDescription = String(req.body?.task_description || '').trim();
  const label = String(req.body?.label || '').trim();
  const actorAgentId = String(req.executionContext?.actorAgentId || '').trim();
  const agentId = String(req.body?.agent_id || actorAgentId).trim();

  if (!cronExpression || !taskDescription || !label) {
    return res.status(400).json({
      success: false,
      error: 'cron_expression, task_description, and label are required'
    });
  }

  if (!agentId) {
    return res.status(400).json({
      success: false,
      error: 'agent_id is required'
    });
  }

  try {
    const schedule = await createScheduledTask({
      cronExpression,
      taskDescription,
      label,
      agentId,
      authority: {
        kind: 'verified_request',
        actorAgentId,
        actorValidFromIso: req.executionContext.actorValidFromIso,
        requestReceiptId: req.executionContext.requestReceiptId,
        requestReceiptMutationHash: req.executionContext.requestReceiptMutationHash,
        requestAdmissionEventId: req.executionContext.requestAdmissionEventId,
        requestAdmissionMutationHash: req.executionContext.requestAdmissionMutationHash,
        certString: req.identityCertString,
        sigBytes: req.identitySigBytes,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
      },
    });
    res.json({ success: true, scheduled: true, schedule });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

export default router;
