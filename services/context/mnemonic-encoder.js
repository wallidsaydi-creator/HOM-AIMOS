/**
 * MNEMONIC ENCODER — TAG MEMORIES WITH ENCODING STYLES
 * Sources: Memory Palace (Method of Loci), cognitive psychology encoding research
 *
 * Tag memories with encoding style (visual_hook, loci_room, chunking, temporal_ladder,
 * narrative_hook) for optimized retrieval. Enables style-matching ranking.
 *
 * Batch 10 Lane 3: VSA-based mnemonic encoding with residue arithmetic
 *   Three new encoding modes: visual (binding), narrative (bundling), procedural (chaining)
 *   computeVSAMnemonicEncoding: VSA representations alongside existing string encodings
 *   computeResidueArithmetic: v mod p for cleanup memory addressing
 *   Aladdin: VSA mnemonics are retrieval augmentation. Existing encoding modes are preserved.
 *
 * Created: 2026-03-31
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (SAVE pipeline step 4, RECALL pipeline step 16)
// → Calls: (style tagging — no downstream service call)
// Pipeline: SAVE_PIPELINE, RECALL_PIPELINE
// Position: encoding on save, style-match on recall
// ─────────────────────────────────────────────────────────────────────────────

const ENCODING_STYLES = {
  visual_hook: {
    name: 'Visual Hook',
    description: 'Dashboard-style memory, high visual component',
    keywords: ['chart', 'graph', 'image', 'visual', 'screenshot', 'diagram', 'icon'],
    taskTypes: ['data_visualization', 'dashboard', 'report']
  },
  loci_room: {
    name: 'Loci Room',
    description: 'Relationship-based memory, navigable structure',
    keywords: ['relationship', 'link', 'connect', 'associate', 'entity', 'graph', 'network'],
    taskTypes: ['entity_mapping', 'relationship', 'knowledge_graph']
  },
  chunking: {
    name: 'Chunking',
    description: 'Procedure-based memory, step-by-step breakdown',
    keywords: ['step', 'procedure', 'process', 'algorithm', 'sequence', 'instruction', 'how to'],
    taskTypes: ['procedure', 'workflow', 'recipe', 'guide']
  },
  temporal_ladder: {
    name: 'Temporal Ladder',
    description: 'Timeline-based memory, temporal ordering',
    keywords: ['time', 'date', 'timeline', 'history', 'event', 'phase', 'era', 'sequence'],
    taskTypes: ['timeline', 'history', 'chronicle', 'evolution']
  },
  narrative_hook: {
    name: 'Narrative Hook',
    description: 'Decision-based memory, story with reasoning',
    keywords: ['decision', 'choice', 'reason', 'because', 'story', 'narrative', 'why'],
    taskTypes: ['decision_log', 'case_study', 'incident', 'analysis']
  }
};

/**
 * Detect encoding style of a memory value
 *
 * @param {any} value - Memory value to analyze
 * @param {string} memoryType - Type of memory (from aimos_memories)
 * @returns {{style: string, confidence: number}}
 */
export function detectEncodingStyle(value, memoryType = '') {
  if (value == null || value === undefined) return { style: 'visual_hook', confidence: 0 };
  const text = typeof value === 'string' ? value.toLowerCase() : JSON.stringify(value || '').toLowerCase();

  // Keyword scoring
  const styleScores = {};

  for (const [styleName, styleInfo] of Object.entries(ENCODING_STYLES)) {
    let score = 0;

    // Check keywords
    for (const keyword of styleInfo.keywords) {
      const count = (text.match(new RegExp(keyword, 'g')) || []).length;
      score += count;
    }

    // Check memory type match
    if (memoryType && styleInfo.taskTypes.includes(memoryType.toLowerCase())) {
      score += 5;
    }

    styleScores[styleName] = score;
  }

  // Find highest score
  let maxStyle = 'visual_hook';
  let maxScore = 0;

  for (const [style, score] of Object.entries(styleScores)) {
    if (score > maxScore) {
      maxScore = score;
      maxStyle = style;
    }
  }

  // Calculate confidence (0-1)
  const totalScore = Object.values(styleScores).reduce((a, b) => a + b, 0);
  const confidence = totalScore > 0 ? (maxScore / totalScore) : 0.3;

  return {
    style: maxStyle,
    confidence: Math.min(1, confidence)
  };
}

/**
 * Get preferred encoding style for a task type
 *
 * @param {string} taskType - Task type (data_visualization, entity_mapping, procedure, etc.)
 * @returns {string}
 */
export function getPreferredStyle(taskType) {
  const taskLower = String(taskType || '').toLowerCase();

  // Direct mapping for common task types
  const styleMap = {
    'data_visualization': 'visual_hook',
    'dashboard': 'visual_hook',
    'report': 'visual_hook',
    'chart': 'visual_hook',
    'entity_mapping': 'loci_room',
    'relationship': 'loci_room',
    'knowledge_graph': 'loci_room',
    'network': 'loci_room',
    'procedure': 'chunking',
    'workflow': 'chunking',
    'recipe': 'chunking',
    'guide': 'chunking',
    'how_to': 'chunking',
    'timeline': 'temporal_ladder',
    'history': 'temporal_ladder',
    'chronicle': 'temporal_ladder',
    'evolution': 'temporal_ladder',
    'decision_log': 'narrative_hook',
    'case_study': 'narrative_hook',
    'incident': 'narrative_hook',
    'analysis': 'narrative_hook'
  };

  return styleMap[taskLower] || 'visual_hook';
}

/**
 * Rank memories by encoding style match
 * Reorders memories to prioritize those matching preferred style.
 *
 * @param {Array<object>} memories - Array of memory objects
 * @param {string} preferredStyle - Preferred encoding style
 * @returns {Array<object>}
 */
export function rankByStyleMatch(memories, preferredStyle) {
  if (!Array.isArray(memories) || memories.length === 0) {
    return [];
  }

  // Score each memory
  const scored = memories.map(memory => {
    const detected = detectEncodingStyle(
      memory.value,
      memory.memory_type
    );

    // Score is higher if style matches preference
    let styleScore = 0;
    if (detected.style === preferredStyle) {
      styleScore = 0.9;
    } else {
      // Give some score for any detected style
      styleScore = detected.confidence * 0.5;
    }

    return {
      memory,
      detected_style: detected.style,
      style_confidence: detected.confidence,
      style_score: styleScore,
      final_score: styleScore * (memory.trust_score || 0.5)
    };
  });

  // Sort by final score (descending)
  scored.sort((a, b) => b.final_score - a.final_score);

  // Return reordered memories with style metadata
  return scored.map(item => ({
    ...item.memory,
    _encoding_style: item.detected_style,
    _style_confidence: item.style_confidence,
    _style_match: item.detected_style === preferredStyle
  }));
}

/**
 * Get style profile for a batch of memories
 *
 * @param {Array<object>} memories - Array of memory objects
 * @returns {object}
 */
export function getStyleProfile(memories) {
  const profile = {};

  for (const style of Object.keys(ENCODING_STYLES)) {
    profile[style] = { count: 0, total_confidence: 0 };
  }

  for (const memory of memories) {
    const detected = detectEncodingStyle(memory.value, memory.memory_type);
    profile[detected.style].count++;
    profile[detected.style].total_confidence += detected.confidence;
  }

  // Calculate average confidence per style
  for (const style of Object.keys(profile)) {
    if (profile[style].count > 0) {
      profile[style].avg_confidence = profile[style].total_confidence / profile[style].count;
    } else {
      profile[style].avg_confidence = 0;
    }
  }

  return profile;
}

/**
 * Recommend encoding style for new memory
 *
 * @param {any} value - Memory value
 * @param {string} taskType - Task type
 * @returns {string}
 */
export function recommendStyle(value, taskType) {
  // Task type preference is primary
  if (taskType) {
    const preferred = getPreferredStyle(taskType);
    return preferred;
  }

  // Fall back to content detection
  const detected = detectEncodingStyle(value);
  return detected.style;
}

/**
 * Convert memory to specific encoding style
 * (For future use: transform memory representation)
 *
 * @param {object} memory - Memory object
 * @param {string} targetStyle - Target encoding style
 * @returns {object}
 */
export function convertToStyle(memory, targetStyle) {
  if (!ENCODING_STYLES[targetStyle]) {
    throw new Error(`Unknown encoding style: ${targetStyle}`);
  }

  return {
    ...memory,
    encoding_style: targetStyle,
    converted_at: new Date().toISOString(),
    original_style: memory.encoding_style || 'unknown'
  };
}

/**
 * Get style-specific retrieval hints
 *
 * @param {string} style - Encoding style
 * @returns {object}
 */
export function getRetrievalHints(style) {
  const hints = {
    visual_hook: {
      searchStrategy: 'focus on visual descriptors',
      rankingFactor: 'image_quality, completeness',
      queryExample: 'dashboard showing metrics'
    },
    loci_room: {
      searchStrategy: 'navigate relationships',
      rankingFactor: 'connection_count, hierarchy_depth',
      queryExample: 'entities connected to project_x'
    },
    chunking: {
      searchStrategy: 'step-by-step reconstruction',
      rankingFactor: 'sequence_position, completeness',
      queryExample: 'steps to accomplish task_y'
    },
    temporal_ladder: {
      searchStrategy: 'timeline-based retrieval',
      rankingFactor: 'temporal_distance, event_significance',
      queryExample: 'events from Jan-Feb 2026'
    },
    narrative_hook: {
      searchStrategy: 'decision reasoning chain',
      rankingFactor: 'reasoning_clarity, outcome_significance',
      queryExample: 'why decision_z was made'
    }
  };

  return hints[style] || hints.visual_hook;
}

// ─── SEMANTIC BIN TAGGING (8-way classifier) ────────────────────────────────
//
// RENAMED 2026-04-17 (Phase 6 / Aimos `36e39524-...`): this was originally
// labeled "TurboESM Cognitive 3-Bit Quantization (L10)" per an aspirational
// plan. That label conflates it with KV-cache quantization (KVQuant/KIVI),
// which it is not. It is a rule-based 8-way semantic tag classifier: every
// memory is mapped to one of eight labeled bins based on importance,
// memory_type, and keyword/phrase matches on the value string. It does not
// quantize any continuous signal, does not reduce storage, and does not
// replace embeddings — embeddings remain full 768-d (all-mpnet-base-v2).
//
// No paper backs this specific mapping. The upstream file header cites
// Method-of-Loci / cognitive-psychology encoding research for the
// ENCODING_STYLES taxonomy above; the eight bins here are heuristic and
// inherit no additional paper citation. Do not cite TurboQuant (Jegou TPAMI
// 2011, Aimos `6d59066f-...`) against this function — that paper governs
// vector quantization, a different concern.
//
// The three bits of information per output token come from the 8 possible
// values of `bin`; they do NOT represent three bits of the underlying
// embedding or KV cache.

/**
 * Semantic bin taxonomy — 8 labels for memory provenance + role.
 * Stable numeric codes are kept because downstream consumers format them
 * as hex tokens ("0x3-0x6-0x1"); changing the integers would invalidate
 * any stored reasoning traces.
 */
const SEMANTIC_BIN_MAP = {
  ROUTINE:    0x0, // Low importance / noise
  BOOTSTRAP:  0x1, // Context initialization
  EVIDENCE:   0x2, // Data discovery / observations
  REASONING:  0x3, // Internal logic steps
  CONFLICT:   0x4, // Detected contradictions
  TUNING:     0x5, // Performance / optimization
  DECISION:   0x6, // Strategic turning points
  AUTHORITY:  0x7  // Goal achievement / ground truth
};

/**
 * Classify a sequence of memories into semantic-bin tokens.
 *
 * @param {Array<object>} memories - Working memory objects
 * @returns {string} - Hex-token sequence (e.g. "0x1-0x3-0x6")
 */
export function encodeSemanticBins(memories) {
  if (!Array.isArray(memories) || memories.length === 0) return '';

  return memories.map(mem => {
    let bin = SEMANTIC_BIN_MAP.ROUTINE;
    const importance = parseFloat(mem.retrieval_weight || 1.0);
    const type = String(mem.memory_type || '').toLowerCase();
    const val = String(mem.value || '').toLowerCase();

    // 1. High-tier Authority (Aladdin Law, Directives)
    if (importance >= 2.0 || type === 'procedural' || type === 'identity') {
      bin = SEMANTIC_BIN_MAP.AUTHORITY;
    }
    // 2. Strategic Decisions
    else if (val.includes('decision') || val.includes('approved') || type === 'milestone') {
      bin = SEMANTIC_BIN_MAP.DECISION;
    }
    // 3. Conflict Detection
    else if (mem.conflict_detected || val.includes('contradict') || val.includes('error')) {
      bin = SEMANTIC_BIN_MAP.CONFLICT;
    }
    // 4. Tuning & Optimization
    else if (val.includes('latency') || val.includes('optimize') || val.includes('speed')) {
      bin = SEMANTIC_BIN_MAP.TUNING;
    }
    // 5. Reasoning Steps
    else if (type === 'analysis' || val.includes('because') || val.includes('reasoning')) {
      bin = SEMANTIC_BIN_MAP.REASONING;
    }
    // 6. Evidence Discovery
    else if (type === 'intel' || type === 'evidence' || val.includes('found')) {
      bin = SEMANTIC_BIN_MAP.EVIDENCE;
    }
    // 7. Bootstrap
    else if (val.includes('bootstrap') || val.includes('started') || type === 'session') {
      bin = SEMANTIC_BIN_MAP.BOOTSTRAP;
    }

    return `0x${bin.toString(16)}`;
  }).join('-');
}

// ─── BATCH 10 LANE 3: VSA-BASED MNEMONIC ENCODING + RESIDUE ARITHMETIC ──────
// Papers: VSA Survey, HEY PENTTI (Hyperdimensional Computing)
// Three new VSA encoding modes: visual (binding), narrative (bundling), procedural (chaining)
// computeVSAMnemonicEncoding: produces VSA representation alongside existing string encoding
// computeResidueArithmetic: v mod p for cleanup memory addressing
// Aladdin: VSA mnemonics are retrieval augmentation. Existing encoding modes are preserved.
// ─────────────────────────────────────────────────────────────────────────────

const VSA_MNEMONIC_DIM = 10000; // VSA vector dimension for mnemonic encoding

// VSA encoding modes mapped to existing encoding styles
const VSA_ENCODING_MODES = {
  visual: {
    operation: 'binding', // XOR for bipolar vectors — subject ⊗ object
    description: 'Visual hook: bind perceptual features together',
    maps_to: 'visual_hook',
  },
  narrative: {
    operation: 'bundling', // Element-wise sum + sign() — Σ events
    description: 'Narrative hook: bundle event sequences',
    maps_to: 'narrative_hook',
  },
  procedural: {
    operation: 'chaining', // Sequential binding — step1 ⊗ step2 ⊗ step3
    description: 'Procedural: chain step-by-step operations',
    maps_to: 'chunking',
  },
};

/**
 * Generate a deterministic bipolar VSA vector from a text seed.
 * Uses hash-based deterministic projection for reproducibility.
 *
 * @param {string} seed - Text seed for deterministic generation
 * @param {number} dim - Vector dimension (default VSA_MNEMONIC_DIM)
 * @returns {number[]} - Bipolar vector with elements in {-1, +1}
 */
function seedToBipolarVector(seed, dim = VSA_MNEMONIC_DIM) {
  const text = String(seed || '').toLowerCase();
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
  }

  // Deterministic PRNG from hash
  let state = Math.abs(hash) || 1;
  function nextBit() {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return (state >> 16) & 1; // Use high bits for better distribution
  }

  const vector = new Array(dim);
  for (let i = 0; i < dim; i++) {
    vector[i] = nextBit() ? 1 : -1;
  }
  return vector;
}

/**
 * VSA binding operation (XOR for bipolar vectors).
 * Binds two vectors together: result[i] = a[i] * b[i]
 *
 * @param {number[]} a - Bipolar VSA vector
 * @param {number[]} b - Bipolar VSA vector
 * @returns {number[]} - Bound bipolar vector
 */
function vsaBind(a, b) {
  const dim = Math.min(a.length, b.length);
  const result = new Array(dim);
  for (let i = 0; i < dim; i++) {
    result[i] = (a[i] || 0) * (b[i] || 0);
  }
  return result;
}

/**
 * VSA bundling operation (superposition + sign normalization).
 * Bundles multiple vectors: sum element-wise, then sign() to normalize.
 *
 * @param {number[][]} vectors - Array of bipolar VSA vectors
 * @returns {number[]} - Bundled bipolar vector
 */
function vsaBundle(vectors) {
  if (!Array.isArray(vectors) || vectors.length === 0) return [];
  const dim = vectors[0]?.length || 0;
  if (dim === 0) return [];

  const sum = new Array(dim).fill(0);
  for (const vec of vectors) {
    for (let i = 0; i < dim; i++) {
      sum[i] += (vec[i] || 0);
    }
  }

  // Normalize to bipolar via sign
  return sum.map(v => v >= 0 ? 1 : -1);
}

/**
 * VSA chaining operation (sequential binding).
 * Chains steps in order: step1 ⊗ step2 ⊗ step3 ⊗ ...
 *
 * @param {number[][]} steps - Array of bipolar VSA vectors in sequence order
 * @returns {number[]} - Chained bipolar vector
 */
function vsaChain(steps) {
  if (!Array.isArray(steps) || steps.length === 0) return [];
  let result = steps[0];
  for (let i = 1; i < steps.length; i++) {
    result = vsaBind(result, steps[i]);
  }
  return result;
}

/**
 * Compute VSA mnemonic encoding for a memory.
 * Produces VSA representations alongside existing string encodings.
 * Three encoding modes:
 *   visual: binding — bind perceptual features together
 *   narrative: bundling — bundle event sequences
 *   procedural: chaining — chain step-by-step operations
 *
 * @param {Object} memory - Memory object with value, memory_type, etc.
 * @param {string} style - VSA encoding mode: 'visual', 'narrative', or 'procedural'
 * @returns {{ vsa_vector: number[], encoding_mode: string, operation: string, source_papers: string[], diagnostic_only: boolean }}
 */
export function computeVSAMnemonicEncoding(memory, style = 'visual') {
  const mem = memory || {};
  const mode = VSA_ENCODING_MODES[style] || VSA_ENCODING_MODES.visual;

  // Extract key features from memory for VSA encoding
  const key = String(mem.key || mem.id || '').toLowerCase();
  const value = String(mem.value || '').toLowerCase();
  const type = String(mem.memory_type || '').toLowerCase();

  // Generate seed vectors from memory features
  const keyVector = seedToBipolarVector(key);
  const typeVector = seedToBipolarVector(type);

  // Extract significant words from value for feature vectors
  const words = value.split(/\s+/).filter(w => w.length > 3).slice(0, 5);
  const wordVectors = words.map(w => seedToBipolarVector(w));

  let vsaVector;

  if (mode.operation === 'binding') {
    // Visual: bind key ⊗ type ⊗ (bundled words)
    const wordBundle = wordVectors.length > 0 ? vsaBundle(wordVectors) : typeVector;
    vsaVector = vsaBind(vsaBind(keyVector, typeVector), wordBundle);
  } else if (mode.operation === 'bundling') {
    // Narrative: bundle all feature vectors together
    const allVectors = [keyVector, typeVector, ...wordVectors];
    vsaVector = vsaBundle(allVectors);
  } else {
    // Procedural: chain key ⊗ type ⊗ word1 ⊗ word2 ⊗ ...
    const chainSteps = [keyVector, typeVector, ...wordVectors];
    vsaVector = vsaChain(chainSteps);
  }

  return {
    vsa_vector: vsaVector,
    vsa_dim: vsaVector.length,
    encoding_mode: style,
    operation: mode.operation,
    maps_to_existing_style: mode.maps_to,
    features_used: { key: !!key, type: !!type, words: words.length },
    source_papers: ['VSA Survey', 'HEY PENTTI (Hyperdimensional Computing)'],
    diagnostic_only: true,
    existing_styles_preserved: true,
    aladdin_boundary: {
      vsa_mnemonic_is_retrieval_augmentation: true,
      existing_string_encoding_unchanged: true,
    },
  };
}

/**
 * Compute residue arithmetic for cleanup memory addressing.
 * Formula: residue = v mod p (element-wise modulo)
 * In hyperdimensional computing, residue arithmetic enables associative
 * cleanup: given a noisy vector, find the nearest clean item by computing
 * v mod p for each stored clean item and checking alignment.
 *
 * @param {number[]} vector - Input vector (can be dense or bipolar)
 * @param {number} prime - Prime modulus for residue computation (default 127)
 * @returns {{ residue: number[], prime: number, source_papers: string[], diagnostic_only: boolean }}
 */
export function computeResidueArithmetic(vector, prime = 127) {
  const vec = Array.isArray(vector) ? vector : [];
  const p = Math.max(2, Number(prime) || 127); // Ensure prime >= 2

  if (vec.length === 0) {
    return {
      residue: [],
      prime: p,
      source_papers: ['VSA Survey', 'HEY PENTTI (Hyperdimensional Computing)'],
      diagnostic_only: true,
      note: 'Empty input vector — residue undefined',
    };
  }

  // Compute residue: v mod p for each element
  // For bipolar vectors {-1, +1}, map to {0, 1} first, then mod p
  const residue = vec.map(v => {
    const mapped = v === -1 ? 0 : v === 1 ? 1 : v; // Map bipolar to {0,1} if needed
    return ((Math.floor(Math.abs(mapped) * 1000) % p) + p) % p; // Element-wise mod p
  });

  // Compute residue distribution statistics
  const histogram = new Array(p).fill(0);
  for (const r of residue) {
    const bin = Math.min(Math.floor(r), p - 1);
    histogram[bin]++;
  }
  const maxBin = Math.max(...histogram);
  const entropy = histogram.reduce((ent, count) => {
    if (count === 0) return ent;
    const prob = count / residue.length;
    return ent - prob * Math.log2(prob);
  }, 0);

  return {
    residue: residue.slice(0, 100), // Trim for diagnostic readability
    prime: p,
    residue_dim: vec.length,
    residue_distribution: {
      unique_values: new Set(residue).size,
      max_bin_count: maxBin,
      entropy: Number(entropy.toFixed(4)),
      uniform_distribution_entropy: Number(Math.log2(p).toFixed(4)),
    },
    formula: 'residue = v mod p (element-wise modulo for cleanup memory)',
    source_papers: ['VSA Survey', 'HEY PENTTI (Hyperdimensional Computing)'],
    diagnostic_only: true,
  };
}
