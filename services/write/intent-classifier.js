/**
 * INTENT CLASSIFIER — CLASSIFY SCOPE AND ENFORCE VERB POLICY
 *
 * Classify every request early in pipeline into read-only, read-write, or
 * administrative scope. Enforce HTTP verb policy (read-only cannot POST/PUT).
 *
 * NOTE: Aladdin Law (no-delete) is enforced here. DELETE is a BANNED verb.
 *
 * Batch 10 Lane 1: getCompressionPolicy(intentClass) — 500xCompressor
 *   Maps existing classifyIntent() output to compression ratios.
 *   Pure function export — no pipeline change.
 *   declarative → 0.05, procedural_seed → 0.40, event_log → 0.05, session_debrief → 0.20
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js
// Pipeline: TOOL_REGISTRY | Position: Scope classification (read/write/admin)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Classify request intent and scope
 */
export function classifyIntent(prompt, toolsInvoked = []) {
  const text = String(prompt || '').toLowerCase();

  const readOnlyKeywords = [
    'show', 'find', 'list', 'get', 'retrieve', 'search', 'check', 'view',
    'display', 'read', 'summarize', 'query', 'look up', 'what is', 'tell me',
    'explain', 'describe'
  ];

  const readWriteKeywords = [
    'create', 'add', 'modify', 'update', 'edit', 'change', 'set', 'store',
    'save', 'write', 'put', 'insert', 'append', 'attach', 'link', 'connect'
  ];

  // Aladdin Law: Removal keywords are suppressed/blocked
  const administrativeKeywords = [
    'reset', 'clear', 'purge', 'backup', 'restore', 'migrate', 'upgrade', 
    'grant', 'revoke', 'admin', 'sudo', 'configure system'
  ];

  let readOnlyCount = readOnlyKeywords.filter(kw => text.includes(kw)).length;
  let readWriteCount = readWriteKeywords.filter(kw => text.includes(kw)).length;
  const adminCount = administrativeKeywords.filter(kw => text.includes(kw)).length;

  const toolScope = inferScopeFromTools(toolsInvoked);
  if (toolScope === 'read-write') readWriteCount += 3;
  if (toolScope === 'read-only') readOnlyCount += 2;

  const maxScore = Math.max(readOnlyCount, readWriteCount, adminCount);

  let scope = 'read-only';
  let confidence = 0.5;

  if (adminCount > 0 && adminCount >= readWriteCount && adminCount >= readOnlyCount) {
    scope = 'administrative';
    confidence = Math.min(0.95, 0.6 + adminCount * 0.1);
  } else if (readWriteCount > 0 && readWriteCount >= readOnlyCount) {
    scope = 'read-write';
    confidence = Math.min(0.95, 0.6 + readWriteCount * 0.1);
  } else {
    scope = 'read-only';
    confidence = Math.min(0.95, 0.6 + readOnlyCount * 0.1);
  }

  if (maxScore === 0) {
    scope = 'read-only';
    confidence = 0.3;
  }

  const reason = buildClassificationReason(scope, readOnlyCount, readWriteCount, adminCount);
  return { scope, confidence, reason };
}

function inferScopeFromTools(tools = []) {
  const adminTools = ['reset_state', 'clear_cache'];
  const writeTools = ['create', 'update', 'insert', 'write', 'store'];
  const readTools = ['query', 'search', 'fetch', 'get'];

  for (const tool of tools) {
    const toolLower = String(tool).toLowerCase();
    if (adminTools.some(t => toolLower.includes(t))) return 'administrative';
    if (writeTools.some(t => toolLower.includes(t))) return 'read-write';
  }
  return 'read-only';
}

function buildClassificationReason(scope, roCount, rwCount, adminCount) {
  const counts = [];
  if (roCount > 0) counts.push(`read-only (${roCount})`);
  if (rwCount > 0) counts.push(`read-write (${rwCount})`);
  if (adminCount > 0) counts.push(`administrative (${adminCount})`);
  return `Determined ${scope} scope. Keyword matches: ${counts.join(', ')}`;
}

export function enforceVerbPolicy(scope, httpVerb) {
  const verb = String(httpVerb || 'GET').toUpperCase();

  const verbScopes = {
    'GET': ['read-only', 'read-write', 'administrative'],
    'HEAD': ['read-only', 'read-write', 'administrative'],
    'OPTIONS': ['read-only', 'read-write', 'administrative'],
    'POST': ['read-write', 'administrative'],
    'PUT': ['read-write', 'administrative'],
    'PATCH': ['read-write', 'administrative'],
    'DELETE': [], // ALADDIN LAW: DELETE is globally banned
    'TRACE': []
  };

  const allowedScopes = verbScopes[verb] || [];
  if (allowedScopes.includes(scope)) {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason: `${scope} scope cannot perform ${verb} operations. Aladdin Law (no-delete) enforced.`
  };
}

export function buildEnforcementPolicy(classification, httpVerb) {
  const verbPolicy = enforceVerbPolicy(classification.scope, httpVerb);
  return {
    scope: classification.scope,
    scope_confidence: classification.confidence,
    http_verb: httpVerb,
    verb_allowed: verbPolicy.allowed,
    reason: verbPolicy.reason || 'Allowed',
    requires_approval: classification.scope === 'administrative',
    approval_level: classification.scope === 'administrative' ? 'high' : 'none'
  };
}

export function validateAgainstPolicy(classification, httpVerb, userClearance = 0) {
  const policy = buildEnforcementPolicy(classification, httpVerb);
  if (!policy.verb_allowed) return { valid: false, reason: policy.reason };
  if (policy.requires_approval && userClearance < 10) {
    return { valid: false, reason: 'Administrative scope requires clearance level 10+' };
  }
  return { valid: true };
}

export function getRecommendedAction(classification) {
  const actions = {
    'read-only': {
      description: 'Safe read operation',
      requiresAudit: false,
      requiresApproval: false,
      defaultVerbs: ['GET', 'HEAD']
    },
    'read-write': {
      description: 'Data modification operation',
      requiresAudit: true,
      requiresApproval: false,
      defaultVerbs: ['POST', 'PUT', 'PATCH']
    },
    'administrative': {
      description: 'System-level operation',
      requiresAudit: true,
      requiresApproval: true,
      defaultVerbs: ['PATCH'] // PATCH only, no DELETE
    }
  };
  return actions[classification.scope] || actions['read-only'];
}

// ─── BATCH 10 LANE 1: COMPRESSION POLICY (500xCompressor) ──────────────────────
// Maps intent classification to compression ratios.
// Pure function — no pipeline change.
// Aladdin: compression only reduces context window bandwidth, never deletes.
// ─────────────────────────────────────────────────────────────────────────────

const INTENT_COMPRESSION_MAP = {
  declarative: 0.05,
  procedural_seed: 0.40,
  procedural: 0.40,
  event_log: 0.05,
  session_debrief: 0.20,
  heartbeat: 0.05,
  insight: 0.05,
  correction: 0.10,
};

/**
 * Get compression policy for a given intent classification.
 *
 * @param {string} intentClass - The intent class from classifyIntent()
 * @returns {{ stage: string, ratio: number, preserve_equations: boolean, intent_class: string }}
 */
export function getCompressionPolicy(intentClass) {
  const ratio = INTENT_COMPRESSION_MAP[intentClass] ?? 0.05;
  return {
    stage: 'extract→compress',
    ratio,
    preserve_equations: true,
    intent_class: intentClass,
  };
}
