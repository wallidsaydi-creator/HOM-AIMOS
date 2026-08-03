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
