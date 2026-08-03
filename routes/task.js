import express from 'express';
import { ensureAgent, tasks } from '../services/orchestration/agent-store.js';
import { runProvider, providerStatus } from '../services/core/providers.js';
import { searchWeb } from '../services/integrations/web-search.js';
import { getPermissions } from '../services/core/permissions.js';
import { persistMemory } from '../services/write/persist-memory.js';
import { logEvent } from '../services/observe/event-ledger.js';
import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';

const router = express.Router();

function scheduleTaskCleanup(taskId, ttlMs = 5 * 60 * 1000) {
  setTimeout(() => {
    tasks.delete(taskId);
  }, ttlMs).unref?.();
}

router.get('/', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 500);
  const status = (req.query.status || '').toString().toLowerCase();

  let records = Array.from(tasks.values());
  if (status) {
    records = records.filter(t => String(t.status || '').toLowerCase() === status);
  }

  records.sort((a, b) => {
    const aTime = new Date(a.createdAt || 0).getTime();
    const bTime = new Date(b.createdAt || 0).getTime();
    return bTime - aTime;
  });
  const normalized = records.slice(0, limit).map(r => ({
    ...r,
    agent_id: r.agent_id || r.agentId || null,
    created_at: r.created_at || r.createdAt || null
  }));
  res.json(normalized);
});

router.post('/', async (req, res) => {
  const { agentId, task, source, priority, model, persona, allowWeb = true, providerModel } = req.body || {};
  if (!agentId || !task) {
    return res.status(400).json({ success: false, error: 'agentId and task are required' });
  }

  const actorAgentId = req.executionContext?.actorAgentId || req.agentId || null;
  if (!actorAgentId) {
    return res.status(401).json({ success: false, error: 'envelope_actor_required' });
  }

  const actorPermissions = await getPermissions(actorAgentId, AIMOS_COMPANY_ID);
  if (agentId !== actorAgentId && actorPermissions.delegate !== true && actorPermissions.admin_override !== true) {
    return res.status(403).json({
      success: false,
      error: 'target_agent_not_authorized',
      actor_agent_id: actorAgentId,
      target_agent_id: agentId,
      required_capability: 'delegate',
    });
  }

  let agent;
  try {
    agent = ensureAgent(agentId, { model, persona });
  } catch (error) {
    if (error?.code === 'MODEL_POLICY_UNAVAILABLE') {
      return res.status(503).json({ success: false, error: error.message });
    }
    throw error;
  }
  if (model) agent.model = model;
  if (persona) agent.persona = persona;
  agent.isActive = true;

  const taskId = `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const status = providerStatus(agent.model);
  const perms = actorPermissions;
  const adminOverride = perms.admin_override === true;

  const record = {
    id: taskId,
    agentId,
    task,
    source: source || 'app',
    priority: priority || 1,
    model: agent.model,
    status: status === 'available' ? 'running' : 'blocked',
    result: null,
    error: null,
    createdAt: new Date().toISOString()
  };

  tasks.set(taskId, record);

  if (status !== 'available') {
    record.error = `Provider ${agent.model} unavailable`;
    record.status = 'blocked';
    tasks.set(taskId, record);
    scheduleTaskCleanup(taskId);
    return res.json({
      success: false,
      taskId,
      status: record.status,
      error: record.error
    });
  }

  try {
    let webContext = '';
    const webAllowed = adminOverride || perms.internet === true;
    if (allowWeb && webAllowed) {
      const search = await searchWeb({
        query: task,
        maxResults: 5,
        useContext: {
          actorAgentId,
          requestReceiptId: req.executionContext?.requestReceiptId,
          requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash,
          requestAdmissionEventId: req.executionContext?.requestAdmissionEventId,
          requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash,
        },
      });
      if (search?.results?.length) {
        const lines = search.results
          .slice(0, 5)
          .map(r => `- ${r.title} (${r.url}) ${r.description || ''}`)
          .join('\n');
        webContext = `\n\nWeb results (${search.provider}):\n${lines}`;
      }
    }

    const prompt = `${task}${webContext}`;
    const response = await runProvider({
      provider: agent.model,
      prompt,
      model: providerModel,
      useContext: req.executionContext,
    });

    record.status = 'completed';
    record.result = response;
    tasks.set(taskId, record);
    scheduleTaskCleanup(taskId);

    // Auto-summary memory write (prevents habit erosion)
    await writeTaskSummary({
      taskId,
      companyId: AIMOS_COMPANY_ID,
      agentId,
      task,
      result: response
    });

    return res.json({ success: true, taskId, status: record.status, result: response });
  } catch (error) {
    record.status = 'failed';
    record.error = error.message;
    tasks.set(taskId, record);
    scheduleTaskCleanup(taskId);
    return res.status(500).json({ success: false, taskId, status: record.status, error: record.error });
  }
});

router.get('/:id', (req, res) => {
  const record = tasks.get(req.params.id);
  if (!record) return res.status(404).json({ error: 'Task not found' });
  res.json(record);
});

export default router;

async function writeTaskSummary({ taskId, companyId, agentId, task, result }) {
  const key = `task:${taskId}:summary`;
  const trimmed = (result || '').toString().trim();
  const summary = trimmed.length > 1200 ? `${trimmed.slice(0, 1200)}…` : trimmed;
  const value = [
    `Task: ${task}`,
    `Outcome: ${summary || 'No response captured.'}`,
    'Key learnings: (auto-summary)',
    'Decisions: (auto-summary)'
  ].join('\n');

  try {
    await persistMemory({
      company_id: companyId,
      agent_id: agentId,
      key,
      value,
      scope: agentId,
      clearance_level: 5,
      memory_type: 'task_summary',
      source: 'task.js',
      mutation_authority: 'housekeeper'
    });
    await logEvent(companyId, agentId, 'save', key, {
      reasoning: `Task auto-summary saved to Aimos as '${key}'. Completed tasks become searchable knowledge — what was done, by whom, and the outcome. This feeds the retained dream-consolidation loop.`,
      source_knowledge: 'task.js auto-summary — task completion → memory pipeline'
    });
  } catch (err) {
    // Don't fail the task if memory write fails
    console.warn('Auto-summary memory write failed:', err.message);
  }
}
