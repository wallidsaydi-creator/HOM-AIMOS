import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import express from 'express';
import { gmailListInbox, calendarTodayEvents } from '../services/integrations/google-tools.js';
import { query } from '../db/connection.js';
import { systemConfigStore } from '../services/security/system-config-store.js';

const router = express.Router();
const COMPANY = AIMOS_COMPANY_ID;
const EXECUTIVE_DISPLAY_NAME = String(systemConfigStore.readConfigString('EXECUTIVE_DISPLAY_NAME') || 'Reviewer').trim() || 'Reviewer';

const briefingConfig = {
  sections: {
    email: true,
    calendar: true,
    tasks: true
  },
  preferredTime: '08:00'
};

function asSection({ key, title, icon, ok, items = [], error = null }) {
  return {
    key,
    title,
    icon,
    success: !!ok,
    items,
    error: ok ? null : (error || 'Section unavailable')
  };
}

function toLegacyItems(key, items = []) {
  if (key === 'email') {
    return items.map((item) => ({
      title: String(item.subject || item.title || '(No subject)'),
      subtitle: String(item.snippet || item.subtitle || ''),
      time: String(item.date || '')
    }));
  }
  if (key === 'calendar') {
    return items.map((item) => ({
      title: String(item.summary || item.title || '(Untitled event)'),
      subtitle: String(item.location || item.subtitle || ''),
      time: String(item.time || '')
    }));
  }
  return items.map((item) => ({
    title: String(item.title || '(Untitled task)'),
    subtitle: String(item.status || ''),
    time: String(item.created_at || '')
  }));
}

async function loadPendingTasks(limit = 10) {
  const results = [];

  // Load pending directives (aimos_tasks table does not exist; use aimos_directives directly).
  const fallback = await query(
    `SELECT id, goal, status, priority, created_at
     FROM aimos_directives
     WHERE company_id = $1
       AND status = 'pending'
       AND authority_event_id IS NOT NULL
     ORDER BY priority DESC NULLS LAST, created_at DESC
     LIMIT $2`,
    [COMPANY, limit]
  );
  for (const row of fallback.rows) {
    results.push({
      id: row.id,
      title: row.goal || '(Untitled directive)',
      status: row.status || 'pending',
      priority: row.priority ?? null,
      created_at: row.created_at || null
    });
  }
  return results;
}

router.get('/config', async (req, res) => {
  res.json({ success: true, config: briefingConfig });
});

router.post('/config', async (req, res) => {
  const sections = req.body?.sections;
  const preferredTime = req.body?.preferredTime;

  if (sections && typeof sections === 'object') {
    for (const key of ['email', 'calendar', 'tasks']) {
      if (typeof sections[key] === 'boolean') {
        briefingConfig.sections[key] = sections[key];
      }
    }
  }
  if (typeof preferredTime === 'string' && preferredTime.trim()) {
    briefingConfig.preferredTime = preferredTime.trim();
  }

  res.json({ success: true, config: briefingConfig });
});

async function buildBriefingPayload(credentialUseContext = {}) {
  const sections = [];

  if (briefingConfig.sections.email) {
    try {
      const messages = await gmailListInbox({ maxResults: 5, query: 'in:inbox' }, credentialUseContext);
      sections.push(asSection({
        key: 'email',
        title: 'Inbox',
        icon: 'mail',
        ok: true,
        items: (messages || []).map((m) => ({
          id: m.id,
          sender: m.from || '',
          subject: m.subject || '(No subject)',
          snippet: m.snippet || '',
          date: m.date || null
        }))
      }));
    } catch (error) {
      sections.push(asSection({
        key: 'email',
        title: 'Inbox',
        icon: 'mail',
        ok: false,
        error: error?.message || String(error)
      }));
    }
  }

  if (briefingConfig.sections.calendar) {
    try {
      const today = await calendarTodayEvents(credentialUseContext);
      sections.push(asSection({
        key: 'calendar',
        title: "Today's Calendar",
        icon: 'calendar',
        ok: true,
        items: (today?.events || []).map((event) => ({
          id: event.id,
          summary: event.summary,
          time: event.time,
          start: event.start,
          end: event.end,
          location: event.location || ''
        }))
      }));
    } catch (error) {
      sections.push(asSection({
        key: 'calendar',
        title: "Today's Calendar",
        icon: 'calendar',
        ok: false,
        error: error?.message || String(error)
      }));
    }
  }

  if (briefingConfig.sections.tasks) {
    try {
      const pending = await loadPendingTasks(10);
      sections.push(asSection({
        key: 'tasks',
        title: 'Pending Tasks',
        icon: 'checklist',
        ok: true,
        items: pending
      }));
    } catch (error) {
      sections.push(asSection({
        key: 'tasks',
        title: 'Pending Tasks',
        icon: 'checklist',
        ok: false,
        error: error?.message || String(error)
      }));
    }
  }

  const okSections = sections.filter((section) => section.success).length;
  const sectionByKey = Object.fromEntries(
    sections.map((section) => [
      section.key,
      {
        error: section.error,
        items: toLegacyItems(section.key, section.items)
      }
    ])
  );

  return {
    success: true,
    generatedAt: new Date().toISOString(),
    sections,
    // Backward-compatible top-level sections consumed by the current desktop view.
    email: sectionByKey.email || { error: 'Email section unavailable', items: [] },
    calendar: sectionByKey.calendar || { error: 'Calendar section unavailable', items: [] },
    tasks: sectionByKey.tasks || { error: 'Tasks section unavailable', items: [] },
    summary: {
      totalSections: sections.length,
      successfulSections: okSections,
      failedSections: sections.length - okSections
    }
  };
}

router.get('/today', async (req, res) => {
  const payload = await buildBriefingPayload(req.executionContext);
  res.json(payload);
});

router.get('/push', async (req, res) => {
  const payload = await buildBriefingPayload(req.executionContext);
  const sections = Array.isArray(payload?.sections) ? payload.sections : [];
  const emailCount = sections.find((s) => s.key === 'email')?.items?.length || 0;
  const calendarCount = sections.find((s) => s.key === 'calendar')?.items?.length || 0;
  const taskCount = sections.find((s) => s.key === 'tasks')?.items?.length || 0;
  const failed = sections.filter((s) => !s.success).length;

  res.json({
    success: true,
    title: `${EXECUTIVE_DISPLAY_NAME} Daily Briefing`,
    subtitle: `${emailCount} emails • ${calendarCount} events • ${taskCount} tasks`,
    body: failed > 0
      ? `Some sections are unavailable (${failed}). Open app for details.`
      : 'Everything is synced and ready.',
    badge: emailCount + taskCount
  });
});

export default router;
