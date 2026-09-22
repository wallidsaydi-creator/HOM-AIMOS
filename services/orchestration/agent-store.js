/**
 * agent-store.js — In-Memory Agent and Task Registry
 * Source: Multi-Agent Systems (Wooldridge), Actor Model (Hewitt)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js, governance-resolver.js
 * 2. → Pulls from: agent_profiles (Initial seed values)
 * 3. → Pushes to: In-memory Map (High-speed lookup)
 * 4. ↔ Interacts with: BDI state management logic
 *
 * LOGIC GUIDE: Maintains the "Live Roster" of active agents. 
 * Handles default personas, clearance levels, and model preferences per agent.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
export const agents = new Map();
export const tasks = new Map();

export function bindTaskOwnership(record, executionContext, delegation = null) {
  const companyId = String(executionContext?.companyId || '').trim();
  const initiatingActorId = String(executionContext?.actorAgentId || '').trim();
  const rawEpoch = String(executionContext?.actorValidFromIso || '').trim();
  const parsedEpoch = Date.parse(rawEpoch);
  if (!companyId || !initiatingActorId || !Number.isFinite(parsedEpoch)) {
    throw new Error('task_ownership_context_invalid');
  }
  const owned = { ...record };
  Object.defineProperty(owned, 'ownership', {
    enumerable: true,
    value: Object.freeze({
      scopeMarker: `company:${companyId}`,
      companyId,
      initiatingActorId,
      initiatingActorValidFromIso: new Date(parsedEpoch).toISOString(),
      requestAdmissionEventId: executionContext.requestAdmissionEventId || null,
      requestReceiptMutationHash: executionContext.requestReceiptMutationHash || null,
      delegation: delegation ? Object.freeze({ ...delegation }) : null,
    }),
  });
  return owned;
}

export function taskOwnedByExecutionContext(record, executionContext) {
  const ownership = record?.ownership;
  if (!ownership || ownership.scopeMarker !== `company:${String(executionContext?.companyId || '')}`) {
    return false;
  }
  const epoch = Date.parse(String(executionContext?.actorValidFromIso || ''));
  return ownership.companyId === String(executionContext?.companyId || '')
    && ownership.initiatingActorId === String(executionContext?.actorAgentId || '')
    && Number.isFinite(epoch)
    && ownership.initiatingActorValidFromIso === new Date(epoch).toISOString();
}

export function taskListProjection(record) {
  return {
    id: record.id,
    agent_id: record.agent_id || record.agentId || null,
    source: record.source || null,
    priority: record.priority ?? null,
    model: record.model || null,
    status: record.status || null,
    created_at: record.created_at || record.createdAt || null,
  };
}

export function taskDetailProjection(record) {
  return {
    ...taskListProjection(record),
    task: record.task ?? null,
    result: record.result ?? null,
    error: record.error ?? null,
  };
}

export function ensureAgent(id, defaults = {}) {
  if (!agents.has(id)) {
    const model = String(defaults.model || '').trim();
    if (!model) {
      const error = new Error(`model_policy_unavailable:${id}`);
      error.code = 'MODEL_POLICY_UNAVAILABLE';
      throw error;
    }
    agents.set(id, {
      id,
      name: defaults.name || id,
      tier: defaults.tier || 'light',
      model,
      tools: defaults.tools || ['aimos'],
      persona: defaults.persona || 'General agent',
      clearanceLevel: defaults.clearanceLevel || 1,
      isActive: false,
      lastSeen: null
    });
  }
  return agents.get(id);
}

export function listAgents() {
  return Array.from(agents.values());
}
