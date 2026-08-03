/**
 * WORKSPACE PARTITIONS — FOUR-PARTITION AGENT SHARED MEMORY
 * Sources: Team Topologies (fracture planes), CoALA (Sumers 2023) — BDI state
 *
 * Structure agent shared memory into 4 immutable/append-only partitions:
 * - B_ctx: task definition (immutable)
 * - B_work: intermediate outputs (append-only)
 * - B_sys: execution trace (append-only)
 * - B_ans: final deliverable (write-once at completion)
 *
 * Created: 2026-03-31
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run step 1)
// → Calls: (in-memory partition management — no downstream service call)
// Pipeline: AGENT_RUN_PIPELINE
// Position: workspace init
// ─────────────────────────────────────────────────────────────────────────────

const PARTITION_NAMES = new Set(['B_ctx', 'B_work', 'B_sys', 'B_ans']);

/**
 * Create new workspace with four empty partitions
 *
 * @param {string} runId - Run ID for this workspace
 * @returns {{B_ctx: object, B_work: object, B_sys: object, B_ans: object}}
 */
export function createWorkspace(runId) {
  return {
    runId,
    B_ctx: {},    // immutable task definition
    B_work: {},   // intermediate outputs (append-only)
    B_sys: {},    // execution trace (timing, decisions, errors)
    B_ans: {},    // final deliverable (set at completion)
    _metadata: {
      createdAt: new Date().toISOString(),
      lastModified: new Date().toISOString(),
      accessLog: []
    }
  };
}

/**
 * Set partition data with validation
 * Enforces immutability of B_ctx and write-once semantics for B_ans.
 *
 * @param {object} workspace - Workspace object
 * @param {string} partition - Partition name ('B_ctx'|'B_work'|'B_sys'|'B_ans')
 * @param {any} data - Data to set
 * @returns {{success: boolean, reason?: string}}
 */
export function setPartition(workspace, partition, data) {
  if (!PARTITION_NAMES.has(partition)) {
    return { success: false, reason: `Invalid partition: ${partition}` };
  }

  if (!workspace) {
    return { success: false, reason: 'Workspace not initialized' };
  }

  // B_ctx is immutable (set once, never modified)
  if (partition === 'B_ctx') {
    if (Object.keys(workspace.B_ctx).length > 0) {
      return { success: false, reason: 'B_ctx is immutable and already set' };
    }
  }

  // B_ans is write-once (can only set once)
  if (partition === 'B_ans') {
    if (Object.keys(workspace.B_ans).length > 0) {
      return { success: false, reason: 'B_ans is write-once and already set' };
    }
  }

  // B_work and B_sys allow append (merge, not replace)
  if (partition === 'B_work' || partition === 'B_sys') {
    workspace[partition] = { ...workspace[partition], ...data };
  } else {
    workspace[partition] = data;
  }

  workspace._metadata.lastModified = new Date().toISOString();
  workspace._metadata.accessLog.push({
    partition,
    action: 'write',
    timestamp: new Date().toISOString()
  });

  return { success: true };
}

/**
 * Get partition data
 *
 * @param {object} workspace - Workspace object
 * @param {string} partition - Partition name
 * @returns {any}
 */
export function getPartition(workspace, partition) {
  if (!PARTITION_NAMES.has(partition)) {
    throw new Error(`Invalid partition: ${partition}`);
  }

  if (!workspace) {
    throw new Error('Workspace not initialized');
  }

  workspace._metadata.accessLog.push({
    partition,
    action: 'read',
    timestamp: new Date().toISOString()
  });

  return workspace[partition];
}

/**
 * Serialize workspace to JSON for Aimos storage
 *
 * @param {object} workspace - Workspace object
 * @returns {string}
 */
export function serializeWorkspace(workspace) {
  if (!workspace) {
    throw new Error('Workspace not initialized');
  }

  const serialized = {
    runId: workspace.runId,
    B_ctx: workspace.B_ctx,
    B_work: workspace.B_work,
    B_sys: workspace.B_sys,
    B_ans: workspace.B_ans,
    _metadata: workspace._metadata
  };

  return JSON.stringify(serialized);
}

/**
 * Deserialize workspace from Aimos storage
 *
 * @param {string} json - Serialized workspace JSON
 * @returns {object}
 */
export function deserializeWorkspace(json) {
  if (!json) {
    throw new Error('Invalid serialized workspace');
  }

  try {
    const workspace = JSON.parse(json);
    if (!workspace.runId) {
      throw new Error('Missing runId in deserialized workspace');
    }
    return workspace;
  } catch (err) {
    throw new Error(`Failed to deserialize workspace: ${err.message}`);
  }
}

/**
 * Get workspace summary (sizes, modification time)
 *
 * @param {object} workspace - Workspace object
 * @returns {object}
 */
export function getWorkspaceSummary(workspace) {
  if (!workspace) {
    throw new Error('Workspace not initialized');
  }

  return {
    runId: workspace.runId,
    createdAt: workspace._metadata?.createdAt,
    lastModified: workspace._metadata?.lastModified,
    sizes: {
      B_ctx: Object.keys(workspace.B_ctx).length,
      B_work: Object.keys(workspace.B_work).length,
      B_sys: Object.keys(workspace.B_sys).length,
      B_ans: Object.keys(workspace.B_ans).length
    },
    isComplete: Object.keys(workspace.B_ans).length > 0,
    accessCount: workspace._metadata?.accessLog?.length || 0
  };
}

/**
 * Clear workspace (for testing/cleanup)
 *
 * @param {object} workspace - Workspace object
 * @returns {void}
 */
export function clearWorkspace(workspace) {
  if (!workspace) return;
  workspace.B_ctx = {};
  workspace.B_work = {};
  workspace.B_sys = {};
  workspace.B_ans = {};
  workspace._metadata.lastModified = new Date().toISOString();
  workspace._metadata.accessLog = [];
}
