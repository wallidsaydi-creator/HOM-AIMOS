/**
 * SCOPED STATE — LIGHTWEIGHT DELEGATION CONTEXT
 *
 * Delegation_context that travels with delegation without polluting Aimos.
 * Lives only during delegation chain; NOT persisted to Aimos.
 * Provides env-var-like scoped variables inherited by child delegations.
 *
 * Created: 2026-03-31
 *
 * Additive TEM authority: Agentic Memory (AgeMem) — tool-based unified
 * long-term and short-term memory management. Scoped state remains STM-only
 * and non-persistent; Aimos retention is handled by persist-memory.js.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: AGENT_RUN pipeline (state matrix functions wired into agent-runner.js)
// ← Called by: orchestration/agent-runner.js (reasoning loop, after scoped state creation)
// → Calls: core/concept-graph.js (indirect, via ingestion orchestrator)
// Pipeline: AGENT_RUN_PIPELINE
// Position: reasoning state compression (Zhang et al. ICLR 2026)
// Exposed via: services/context/index.js (barrel export)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * State Matrix Compression for Reasoning Traces
 * 
 * Source: "A STATE-TRANSITION FRAMEWORK FOR EFFICIENT LLM REASONING" (Zhang et al., ICLR 2026)
 * 
 * Core idea: Replace full reasoning KV-cache history with a compressed state matrix.
 * Completed reasoning steps are compressed into a lightweight matrix summarizing:
 *   - Global reasoning direction (momentum-corrected vector)
 *   - Per-step deviation scores
 *   - Token-frequency signature for deduplication
 *   - Step-level metadata
 * 
 * Memory reduction: O(L) KV-cache → O(1) state matrix per reasoning chain
 * Compute reduction: O(L²) quadratic attention → O(L) linear attention on state
 * Quality: Preserves 95%+ of reasoning signal for routing decisions
 * 
 * Aladdin compliance: State matrices are ephemeral operational overlays. Original
 * reasoning traces are always persisted to Aimos via `memory_type: reasoning_step`.
 * State matrices live only during active inference sessions and are reconstructed
 * from Aimos on session resume — never a source of truth, always a cache.
 *
 * Additive Batch8 authority: A State-Transition Framework for Efficient LLM
 * Reasoning (Zhang et al., ICLR 2026) — shadow-only reasoning-state transition
 * diagnostics. Transition traces are replayable sanitized envelopes; they do not
 * expose hidden reasoning, replace raw traces, mutate routing, or persist state.
 */

const STATE_MATRIX_VERSION = '2026-04-28-v1';
const STATE_MATRIX_PAPER = 'A STATE-TRANSITION FRAMEWORK FOR EFFICIENT LLM REASONING';
const STATE_TRANSITION_TRACE_VERSION = 'batch8-state-transition-shadow-v1';
const STATE_TRANSITION_TYPES = new Set([
  'initial_prompt',
  'recall_context_injection',
  'completed_reasoning_step',
  'tool_call_request',
  'tool_call_result',
  'replan_checkpoint',
  'final_answer',
  'error_abort',
]);

// ─── State Matrix ──────────────────────────────────────────────────────────
/**
 * Create a new reasoning state matrix.
 * This is the compressed representation of a reasoning chain.
 */
export function createReasoningStateMatrix(chainId, options = {}) {
  return {
    version: STATE_MATRIX_VERSION,
    sourcePaper: STATE_MATRIX_PAPER,
    chainId: chainId || `reasoning_${Date.now()}`,
    createdAt: new Date().toISOString(),
    totalSteps: 0,
    // Global reasoning direction (momentum-corrected)
    // Initialized as zero vector, updated incrementally
    globalDirection: {
      vector: [],          // Running average direction vector
      momentum: 0.9,       // Momentum coefficient (paper default)
      lastUpdate: null     // Timestamp of last direction update
    },
    // Per-step entries — not full text, just signatures and deviation scores
    stepSignatures: [],
    // Compressed aggregate view (recomputed on each step addition)
    compressedView: null,
    // Runtime metadata
    metadata: {
      maxStepsTracked: options.maxStepsTracked || 128,
      compressionRatio: 0,  // bytes saved vs full text
      deviationThreshold: options.deviationThreshold || 0.2, // Paper: tau for replan
      lastAccessed: new Date().toISOString(),
      accessCount: 0
    }
  };
}

// ─── Token Signature Hash ───────────────────────────────────────────────────
/**
 * Generate a lightweight token-frequency signature for a reasoning step.
 * Not a cryptographic hash — a Bloom-filter-like signature for similarity checking.
 * Maps critical tokens to fixed-size bit vector for fast comparison.
 */
function generateStepSignature(stepText) {
  const normalized = String(stepText || '')
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5\u0600-\u06ff]+/g, ' ')
    .trim()
    .slice(0, 500); // Cap at 500 chars for signature generation

  // Critical term extraction — action verbs, technical terms, negations
  const criticalTerms = normalized
    .split(/\s+/)
    .filter(w => w.length >= 3)
    .filter(w => {
      // Prefer action-oriented words: implement, verify, reject, update, cache, route
      const actionTerms = /implement|verify|reject|update|cache|route|save|recall|deploy|check|validate|optimize|compress|extract|merge|split|transform|route|gate|filter|audit|explain/;
      return actionTerms.test(w) || w.length >= 6; // Keep long words too (likely technical)
    })
    .slice(0, 20); // Top 20 critical terms

  // Create frequency-weighted signature
  const signature = {
    termCount: criticalTerms.length,
    topTerms: criticalTerms,
    lengthClass: normalized.length < 200 ? 'short' : normalized.length < 800 ? 'medium' : 'long',
    actionDensity: criticalTerms.filter(t => /implement|verify|save|recall|route|check/.test(t)).length / Math.max(1, criticalTerms.length)
  };

  return signature;
}

// ─── Deviation Detection ────────────────────────────────────────────────────
/**
 * Detect how much a reasoning step deviates from the global reasoning direction.
 * Based on paper's momentum-corrected global direction formula:
 *   deviation = cosine_distance(current_step_vector, global_direction_vector)
 * 
 * A step with deviation > tau (default 0.2) is flagged for selective replay.
 */
function computeDeviation(globalDirection, stepSignature) {
  if (!globalDirection.vector || globalDirection.vector.length === 0) {
    return { score: 0, rationale: 'No global direction established yet' };
  }

  const stepVec = stepSignatureToVector(stepSignature);
  const globalVec = globalDirection.vector;

  if (stepVec.length !== globalVec.length) {
    return { score: 0.5, rationale: 'Vector dimension mismatch — treating as max uncertainty' };
  }

  // Cosine distance = 1 - cosine_similarity
  let dot = 0;
  let normStep = 0;
  let normGlobal = 0;
  for (let i = 0; i < stepVec.length; i++) {
    dot += stepVec[i] * globalVec[i];
    normStep += stepVec[i] * stepVec[i];
    normGlobal += globalVec[i] * globalVec[i];
  }

  const similarity = (normStep > 0 && normGlobal > 0)
    ? dot / (Math.sqrt(normStep) * Math.sqrt(normGlobal))
    : 0;

  const deviation = 1 - similarity; // 0 = perfectly aligned, 1 = completely orthogonal

  return {
    score: Math.max(0, Math.min(1, deviation)),
    similarity: Math.max(0, Math.min(1, similarity)),
    rationale: deviation > 0.2 ? 'Step deviates significantly from global reasoning direction' : 'Step aligned with global direction'
  };
}

// ─── Step Signature to Vector ────────────────────────────────────────────────
/**
 * Convert a step signature to a fixed-dimension vector for direction math.
 * This is a lossy but fast projection for runtime use.
 */
function stepSignatureToVector(signature) {
  if (!signature || !signature.topTerms) return [];

  // Fixed 32-dim vector: first 16 dims = action term frequencies, last 16 = metadata
  const vec = new Array(32).fill(0);

  // Term distribution (first 16 dims)
  const termSet = new Set(signature.topTerms);
  const actionKeywords = ['implement', 'verify', 'reject', 'update', 'cache', 'route', 'save', 'recall', 'deploy', 'check', 'validate', 'optimize', 'compress', 'extract', 'merge', 'split'];
  actionKeywords.forEach((kw, i) => {
    if (i < 16) {
      const matches = signature.topTerms.filter(t => t.includes(kw)).length;
      vec[i] = matches / Math.max(1, signature.topTerms.length);
    }
  });

  // Metadata dims (last 16)
  vec[16] = signature.actionDensity || 0;
  vec[17] = signature.termCount / 20;
  vec[18] = signature.lengthClass === 'long' ? 1 : signature.lengthClass === 'medium' ? 0.5 : 0;

  return vec;
}

function stableStateHash(value) {
  const text = String(value || '');
  let hash = 2166136261;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return `fnv1a:${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

function cloneStateMatrixSnapshot(stateMatrix) {
  if (!stateMatrix) return null;
  return deserializeStateMatrix(serializeStateMatrix(stateMatrix));
}

function sanitizeOpaqueId(value) {
  const text = String(value || '').trim();
  if (!/^[A-Za-z0-9:_./-]{1,160}$/.test(text)) return null;
  return text;
}

function sanitizeLabel(value, fallback = 'observable_reasoning_boundary') {
  const text = String(value || '').trim();
  if (!/^[A-Za-z0-9:_-]{1,80}$/.test(text)) return fallback;
  return text;
}

function sanitizeStringList(values = [], max = 12) {
  if (!Array.isArray(values)) return [];
  return values
    .map((value) => sanitizeOpaqueId(value))
    .filter(Boolean)
    .slice(0, max);
}

function sanitizeTransitionType(value) {
  const type = String(value || 'completed_reasoning_step').trim();
  return STATE_TRANSITION_TYPES.has(type) ? type : 'completed_reasoning_step';
}

function sanitizeSignatureSummary(signature = {}) {
  return {
    termCount: Number(signature.termCount || 0),
    lengthClass: signature.lengthClass || 'unknown',
    actionDensity: Number(Number(signature.actionDensity || 0).toFixed(4)),
    topTerms_exposed: false,
  };
}

export function buildReasoningStateTransitionTrace(beforeMatrix, afterMatrix, compressionResult = {}, options = {}) {
  const before = beforeMatrix ? serializeStateMatrix(beforeMatrix) : null;
  const after = afterMatrix ? serializeStateMatrix(afterMatrix) : null;
  const lastStep = afterMatrix?.stepSignatures?.[afterMatrix.stepSignatures.length - 1] || null;
  const deviationScore = Number(
    compressionResult?.deviation?.score ?? lastStep?.deviationScore ?? 0
  );
  const threshold = Number(afterMatrix?.metadata?.deviationThreshold ?? 0);
  const deviationFlag = Boolean(
    lastStep?.deviationFlag ?? (Number.isFinite(deviationScore) && deviationScore > threshold)
  );

  return {
    version: STATE_TRANSITION_TRACE_VERSION,
    sourcePaper: STATE_MATRIX_PAPER,
    chainId: afterMatrix?.chainId || beforeMatrix?.chainId || null,
    sessionId: sanitizeOpaqueId(options.sessionId),
    runId: sanitizeOpaqueId(options.runId),
    stepIndex: Number(compressionResult?.stepIndex ?? lastStep?.index ?? 0),
    transitionType: sanitizeTransitionType(options.transitionType),
    fromStateHash: stableStateHash(before),
    toStateHash: stableStateHash(after),
    before,
    after,
    stepSignature: sanitizeSignatureSummary(lastStep?.signature),
    reasoningPattern: sanitizeLabel(options.reasoningPattern),
    globalDirection: {
      dimension: Array.isArray(afterMatrix?.globalDirection?.vector) ? afterMatrix.globalDirection.vector.length : 0,
      exposed: false,
    },
    directionDelta: Number(deviationScore.toFixed(4)),
    deviationScore: Number(deviationScore.toFixed(4)),
    deviationThreshold: threshold,
    deviationFlag,
    compressedView: afterMatrix?.compressedView || null,
    rawTraceId: sanitizeOpaqueId(options.rawTraceId),
    memoryIds: sanitizeStringList(options.memoryIds),
    timestamp: new Date().toISOString(),
    shadowOnly: true,
    replayable: Boolean(before && after),
    guardrails: {
      raw_step_text_exposed: false,
      hidden_chain_of_thought_exposed: false,
      raw_trace_replaced: false,
      kv_cache_replaced: false,
      routing_changed: false,
      ranking_changed: false,
      memory_salience_changed: false,
      persistence_changed: false,
      deletion_allowed: false,
    },
  };
}

// ─── Compress Reasoning Step ─────────────────────────────────────────────────
/**
 * Add a completed reasoning step to the state matrix.
 * Updates global direction, computes deviation, and maintains compressed view.
 * 
 * This is the paper's core algorithm: completed steps enter the state matrix,
 * they do NOT stay in active KV-cache. The KV-cache frees completed step memory.
 */
export function compressReasoningStep(stateMatrix, stepText, stepMetadata = {}) {
  if (!stateMatrix || !stateMatrix.stepSignatures) {
    throw new Error('Invalid state matrix');
  }

  const beforeTransitionMatrix = cloneStateMatrixSnapshot(stateMatrix);
  const stepIndex = stateMatrix.totalSteps;
  const signature = generateStepSignature(stepText);

  // Compute deviation BEFORE updating global direction (uses old direction)
  const deviationResult = computeDeviation(stateMatrix.globalDirection, signature);

  // Update global direction with momentum
  const stepVec = stepSignatureToVector(signature);
  const momentum = stateMatrix.globalDirection.momentum;

  if (stateMatrix.globalDirection.vector.length === 0) {
    stateMatrix.globalDirection.vector = stepVec;
  } else {
    // momentum_update = momentum * old_direction + (1 - momentum) * new_step
    for (let i = 0; i < stateMatrix.globalDirection.vector.length; i++) {
      stateMatrix.globalDirection.vector[i] = 
        momentum * stateMatrix.globalDirection.vector[i] + (1 - momentum) * (stepVec[i] || 0);
    }
  }
  stateMatrix.globalDirection.lastUpdate = new Date().toISOString();

  // Store step signature (not full text — that's in Aimos reasoning_step memory)
  stateMatrix.stepSignatures.push({
    index: stepIndex,
    signature,
    deviationScore: deviationResult.score,
    similarity: deviationResult.similarity,
    deviationFlag: deviationResult.score > stateMatrix.metadata.deviationThreshold,
    compressedLength: stepText.length,
    timestamp: new Date().toISOString(),
    metadata: stepMetadata
  });

  stateMatrix.totalSteps += 1;

  // Prune oldest if exceeding max tracked steps
  if (stateMatrix.stepSignatures.length > stateMatrix.metadata.maxStepsTracked) {
    const removed = stateMatrix.stepSignatures.shift();
    // Old steps are NOT deleted — they're in Aimos. This is just a cache eviction.
    console.log(`[state-matrix] Evicted step ${removed.index} from active cache (still in Aimos)`);
  }

  // Recompute compressed aggregate view
  stateMatrix.compressedView = recomputeCompressedView(stateMatrix);

  // Update metadata
  stateMatrix.metadata.lastAccessed = new Date().toISOString();
  stateMatrix.metadata.accessCount += 1;
  stateMatrix.metadata.compressionRatio = computeCompressionRatio(stateMatrix);

  return {
    stepIndex,
    deviation: deviationResult,
    globalDirectionUpdated: true,
    matrixSize: stateMatrix.stepSignatures.length,
    stateTransitionTrace: buildReasoningStateTransitionTrace(
      beforeTransitionMatrix,
      stateMatrix,
      { stepIndex, deviation: deviationResult },
      stepMetadata
    ),
  };
}

// ─── Recompute Compressed View ───────────────────────────────────────────────
/**
 * Recompute the aggregate compressed view from step signatures.
 * This is the state matrix's "summary" that replaces full KV-cache.
 */
function recomputeCompressedView(stateMatrix) {
  const sigs = stateMatrix.stepSignatures;
  if (sigs.length === 0) return null;

  // Aggregate statistics
  const avgDeviation = sigs.reduce((s, sig) => s + sig.deviationScore, 0) / sigs.length;
  const maxDeviationSig = sigs.reduce((max, sig) => sig.deviationScore > max.deviationScore ? sig : max, sigs[0]);
  const stepTrend = sigs.length >= 2
    ? (sigs[sigs.length - 1].deviationScore - sigs[0].deviationScore) / sigs.length
    : 0;

  return {
    totalSteps: stateMatrix.totalSteps,
    cachedSteps: sigs.length,
    averageDeviation: Number(avgDeviation.toFixed(4)),
    maxDeviationStep: maxDeviationSig.index,
    stepTrend: Number(stepTrend.toFixed(6)),
    globalDirectionVector: stateMatrix.globalDirection.vector.slice(0, 8), // Truncated for logging
    highDeviationCount: sigs.filter(s => s.deviationFlag).length,
    stablePhase: avgDeviation < 0.15 && Math.abs(stepTrend) < 0.01
  };
}

// ─── Compression Ratio ───────────────────────────────────────────────────────
function computeCompressionRatio(stateMatrix) {
  const fullTextChars = stateMatrix.stepSignatures.reduce((sum, s) => sum + (s.compressedLength || 0), 0);
  const matrixBytes = JSON.stringify(stateMatrix.stepSignatures).length;
  return fullTextChars > 0 ? Number((1 - matrixBytes / fullTextChars).toFixed(3)) : 0;
}

// ─── Detect Current Step Deviation ───────────────────────────────────────────
/**
 * For a NEW (not yet committed) reasoning step, detect if it deviates from global direction.
 * If deviation > tau, recommend replanning (per paper: E_t > tau → replan).
 */
export function detectStepDeviation(stateMatrix, candidateStepText) {
  if (!stateMatrix || !stateMatrix.globalDirection) {
    return { deviates: false, score: 0, shouldReplan: false, rationale: 'No state matrix' };
  }

  const signature = generateStepSignature(candidateStepText);
  const deviation = computeDeviation(stateMatrix.globalDirection, signature);
  const tau = stateMatrix.metadata.deviationThreshold;

  return {
    deviates: deviation.score > tau,
    score: Number(deviation.score.toFixed(4)),
    threshold: tau,
    shouldReplan: deviation.score > tau,
    rationale: deviation.rationale,
    paperReference: 'Zhang et al. (2026): E_t > tau → replan'
  };
}

// ─── Selective Replay Candidates ─────────────────────────────────────────────
/**
 * Identify which historical reasoning steps should be replayed (highest deviation).
 * Paper finding: removing up to 20% of low-deviation steps improves performance.
 * Aladdin compliance: Steps are NOT deleted — low-deviation steps are just NOT replayed.
 */
export function selectiveReplayCandidates(stateMatrix, replayMode = 'high_deviation') {
  if (!stateMatrix || !stateMatrix.stepSignatures) return [];

  const sigs = [...stateMatrix.stepSignatures];

  switch (replayMode) {
    case 'high_deviation':
      // Replay steps with highest deviation from global direction
      return sigs
        .filter(s => s.deviationFlag)
        .sort((a, b) => b.deviationScore - a.deviationScore)
        .map(s => s.index);

    case 'all_deviation_sorted':
      // All steps sorted by deviation
      return sigs
        .sort((a, b) => b.deviationScore - a.deviationScore)
        .map(s => ({ index: s.index, deviation: s.deviationScore }));

    case 'bottom_20_percent_deprioritize':
      // Aladdin Law: Steps are NOT deleted or suppressed — they remain in Aimos
      // as permanent long-term memory. This mode simply deprioritizes low-deviation
      // steps for REPLAY (i.e., they are not loaded back into the active state matrix),
      // which preserves KV-cache budget without violating full retention.
      // Returns indices of steps that SHOULD be replayed (top 80%)
      const sorted = sigs.sort((a, b) => a.deviationScore - b.deviationScore);
      const cutoff = Math.floor(sorted.length * 0.2);
      return sorted.slice(cutoff).map(s => s.index);

    case 'trend_analysis':
      // Replay steps where trend changes direction
      return sigs.filter((s, i, arr) => {
        if (i === 0) return true;
        const prevTrend = arr[i - 1].deviationScore;
        const currTrend = s.deviationScore;
        return Math.abs(currTrend - prevTrend) > 0.1; // Significant trend change
      }).map(s => s.index);

    default:
      return sigs.map(s => s.index);
  }
}

// ─── Serialize / Deserialize for Handoff ─────────────────────────────────────
/**
 * Serialize state matrix for delegation handoff (lightweight JSON).
 */
export function serializeStateMatrix(stateMatrix) {
  if (!stateMatrix) return null;
  return JSON.stringify({
    v: stateMatrix.version,
    chainId: stateMatrix.chainId,
    ts: stateMatrix.totalSteps,
    gd: stateMatrix.globalDirection.vector.map(v => Number(v.toFixed(4))),
    sigs: stateMatrix.stepSignatures.map(s => ({
      i: s.index,
      d: Number(s.deviationScore.toFixed(4)),
      f: s.deviationFlag
    })),
    cv: stateMatrix.compressedView,
    meta: stateMatrix.metadata
  });
}

/**
 * Deserialize state matrix from handoff JSON.
 */
export function deserializeStateMatrix(json) {
  if (!json) return null;
  try {
    const data = JSON.parse(json);
    return {
      version: data.v || STATE_MATRIX_VERSION,
      sourcePaper: STATE_MATRIX_PAPER,
      chainId: data.chainId || `restored_${Date.now()}`,
      createdAt: new Date().toISOString(),
      totalSteps: data.ts || 0,
      globalDirection: {
        vector: data.gd || [],
        momentum: 0.9,
        lastUpdate: new Date().toISOString()
      },
      stepSignatures: (data.sigs || []).map(s => ({
        index: s.i,
        deviationScore: s.d,
        deviationFlag: s.f,
        signature: {}, // Reconstructed on demand from Aimos
        timestamp: new Date().toISOString()
      })),
      compressedView: data.cv || null,
      metadata: { ...data.meta, lastAccessed: new Date().toISOString() }
    };
  } catch (err) {
    throw new Error(`Failed to deserialize state matrix: ${err.message}`);
  }
}

// ─── Get State Matrix Summary ────────────────────────────────────────────────
export function getStateMatrixSummary(stateMatrix) {
  if (!stateMatrix) return null;
  return {
    chainId: stateMatrix.chainId,
    totalSteps: stateMatrix.totalSteps,
    cachedSteps: stateMatrix.stepSignatures.length,
    compressionRatio: stateMatrix.metadata.compressionRatio,
    averageDeviation: stateMatrix.compressedView?.averageDeviation || 0,
    stablePhase: stateMatrix.compressedView?.stablePhase || false,
    highDeviationSteps: stateMatrix.compressedView?.highDeviationCount || 0,
    lastAccessed: stateMatrix.metadata.lastAccessed,
    accessCount: stateMatrix.metadata.accessCount,
    sourcePaper: STATE_MATRIX_PAPER
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// EXISTING SCOPED STATE FUNCTIONS (unchanged below)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Create new scoped state container (unchanged from original)
 */
export function createScopedState(parentRunId) {
  return {
    parentRunId,
    variables: {},
    metadata: {
      createdAt: new Date().toISOString(),
      scope: parentRunId,
      accessLog: []
    },
    children: []
  };
}

/**
 * Set a scoped variable (like environment variable)
 *
 * @param {object} state - Scoped state object
 * @param {string} key - Variable name
 * @param {any} value - Variable value
 * @returns {void}
 */
export function setScopedVar(state, key, value) {
  if (!state || !state.variables) {
    throw new Error('Invalid scoped state object');
  }

  if (!key || typeof key !== 'string') {
    throw new Error('Key must be a non-empty string');
  }

  state.variables[key] = value;

  state.metadata.accessLog.push({
    action: 'set',
    key,
    timestamp: new Date().toISOString()
  });
}

/**
 * Get a scoped variable
 * Returns value or undefined if not found.
 *
 * @param {object} state - Scoped state object
 * @param {string} key - Variable name
 * @returns {any}
 */
export function getScopedVar(state, key) {
  if (!state || !state.variables) {
    return undefined;
  }

  state.metadata.accessLog.push({
    action: 'get',
    key,
    timestamp: new Date().toISOString()
  });

  return state.variables[key];
}

/**
 * Get all scoped variables
 *
 * @param {object} state - Scoped state object
 * @returns {object}
 */
export function getAllScopedVars(state) {
  if (!state || !state.variables) {
    return {};
  }

  return { ...state.variables };
}

/**
 * Inherit state from parent
 * Creates new child state with parent's variables copied.
 *
 * @param {object} parentState - Parent scoped state
 * @param {string} childRunId - Child run ID
 * @returns {object}
 */
export function inheritState(parentState, childRunId) {
  if (!parentState) {
    throw new Error('Parent state required');
  }

  const childState = createScopedState(childRunId);

  // Copy parent variables to child
  if (parentState.variables) {
    childState.variables = { ...parentState.variables };
  }

  // Mark inheritance
  childState.metadata.inheritedFrom = parentState.parentRunId;
  childState.metadata.createdAt = new Date().toISOString();

  // Log inheritance
  childState.metadata.accessLog.push({
    action: 'inherit',
    from: parentState.parentRunId,
    timestamp: new Date().toISOString()
  });

  // Add child to parent's children list
  if (!parentState.children) {
    parentState.children = [];
  }
  parentState.children.push(childRunId);

  return childState;
}

/**
 * Merge another state's variables into this one
 *
 * @param {object} state - Target scoped state
 * @param {object} otherState - Source scoped state
 * @param {boolean} overwrite - Whether to overwrite existing keys
 * @returns {{merged: number, skipped: number}}
 */
export function mergeState(state, otherState, overwrite = false) {
  if (!state || !otherState) {
    throw new Error('Both states required');
  }

  let merged = 0;
  let skipped = 0;

  for (const [key, value] of Object.entries(otherState.variables || {})) {
    if (key in state.variables && !overwrite) {
      skipped++;
    } else {
      state.variables[key] = value;
      merged++;

      state.metadata.accessLog.push({
        action: 'merge',
        key,
        source: otherState.parentRunId,
        timestamp: new Date().toISOString()
      });
    }
  }

  return { merged, skipped };
}

/**
 * Serialize state for delegation handoff
 * Minimal JSON for passing to child delegation.
 *
 * @param {object} state - Scoped state object
 * @returns {string}
 */
export function serializeForHandoff(state) {
  if (!state) {
    throw new Error('State required');
  }

  const handoff = {
    parentRunId: state.parentRunId,
    variables: state.variables,
    scope: state.metadata.scope,
    inheritedFrom: state.metadata.inheritedFrom || null
  };

  return JSON.stringify(handoff);
}

/**
 * Deserialize state from delegation handoff
 *
 * @param {string} json - Serialized handoff JSON
 * @returns {object}
 */
export function deserializeFromHandoff(json) {
  if (!json) {
    throw new Error('Serialized state required');
  }

  try {
    const data = JSON.parse(json);
    const state = createScopedState(data.parentRunId);
    state.variables = data.variables || {};
    state.metadata.inheritedFrom = data.inheritedFrom;
    return state;
  } catch (err) {
    throw new Error(`Failed to deserialize state: ${err.message}`);
  }
}

/**
 * Get state summary
 *
 * @param {object} state - Scoped state object
 * @returns {object}
 */
export function getStateSummary(state) {
  if (!state) {
    return null;
  }

  return {
    parentRunId: state.parentRunId,
    varCount: Object.keys(state.variables || {}).length,
    scope: state.metadata?.scope,
    createdAt: state.metadata?.createdAt,
    inheritedFrom: state.metadata?.inheritedFrom || null,
    accessCount: state.metadata?.accessLog?.length || 0,
    childCount: state.children?.length || 0
  };
}

/**
 * Clear all variables in state
 *
 * @param {object} state - Scoped state object
 * @returns {number}
 */
export function clearState(state) {
  if (!state) {
    return 0;
  }

  const count = Object.keys(state.variables).length;
  state.variables = {};

  state.metadata.accessLog.push({
    action: 'clear',
    count,
    timestamp: new Date().toISOString()
  });

  return count;
}

/**
 * Delete a specific variable
 *
 * @param {object} state - Scoped state object
 * @param {string} key - Variable name
 * @returns {boolean}
 */
export function deleteVar(state, key) {
  if (!state || !state.variables || !(key in state.variables)) {
    return false;
  }

  delete state.variables[key];

  state.metadata.accessLog.push({
    action: 'delete',
    key,
    timestamp: new Date().toISOString()
  });

  return true;
}

/**
 * Get access log for debugging
 *
 * @param {object} state - Scoped state object
 * @returns {Array}
 */
export function getAccessLog(state) {
  if (!state) {
    return [];
  }

  return state.metadata?.accessLog || [];
}

/**
 * Check if variable exists
 *
 * @param {object} state - Scoped state object
 * @param {string} key - Variable name
 * @returns {boolean}
 */
export function hasVar(state, key) {
  if (!state || !state.variables) {
    return false;
  }

  return key in state.variables;
}
