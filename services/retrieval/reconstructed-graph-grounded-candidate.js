/**
 * Dormant AIMOS grounded active-reconstruction candidate informed by:
 * Ji, Li, and Hooi, "Memory is Reconstructed, Not Retrieved: Graph Memory
 * for LLM Agents" (ICML 2026).
 *
 * This is an AIMOS-native deterministic adaptation, not full MRAgent parity.
 * It uses only exact source tokens, admitted canonical identities, content
 * hashes, and provenance state. Every Cue-Tag-Content relation has a
 * domain-separated commitment and an independently checkable source support.
 * No model creates cues, tags, edges, content, answers, or authority.
 */

import crypto from 'node:crypto';

export const GROUNDED_RECONSTRUCTION_CONSTANTS = Object.freeze({
  max_terms_per_content: 12,
  max_cues_per_content: 8,
  max_tags_per_content: 8,
  max_steps: 3,
  max_active_cues_per_step: 16,
  max_contents_per_step: 40,
  max_scope_states: 12000,
  maximum_cue_document_ratio: 0.25,
  minimum_expansion_cue_documents: 2,
  rrf_k: 60,
  disclosure_limit: 20,
});

export const GROUNDED_RECONSTRUCTION_GUARDRAILS = Object.freeze({
  dormant: true,
  exact_source_tokens_only: true,
  requires_content_hash: true,
  requires_admitted_provenance: true,
  requires_canary_admission: true,
  model_authority: false,
  topic_clustering: false,
  answer_generation: false,
  database_access: false,
  graph_persistence: false,
  signing_authority: false,
  environment_authority: false,
  mutates_canonical_memory: false,
  deletes_memory: false,
  applies_decay: false,
  suppresses_memory: false,
  expires_memory: false,
  deactivates_memory: false,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'and', 'before', 'being',
  'between', 'could', 'current', 'during', 'for', 'from', 'had', 'has',
  'have', 'into', 'many', 'more', 'most', 'that', 'the', 'their', 'there',
  'these', 'this', 'those', 'through', 'was', 'were', 'what', 'when',
  'where', 'which', 'while', 'with', 'would', 'you', 'your', 'they', 'them',
  'she', 'her', 'his', 'him', 'our', 'are', 'but', 'not', 'did', 'does',
]);

const SHA256_RE = /^[a-f0-9]{64}$/;

// Query-time verification must not repeatedly tokenize the same retained text
// or scan V for every traversed edge. These process-local witnesses are bound
// to the exact graph object and exact edge object created below. They carry no
// persistence or authority: a cloned, substituted, or mutated edge falls back
// to the complete portable verifier.
const GRAPH_RUNTIME_WITNESSES = new WeakMap();

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function normalizeText(value = '') {
  return String(value || '')
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function exactTokens(value = '') {
  return [...new Set(normalizeText(value)
    .split(/\s+/)
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token)))];
}

function canonicalRecord(value) {
  if (Array.isArray(value)) return value.map(canonicalRecord);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, field]) => field !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, field]) => [key, canonicalRecord(field)]),
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalRecord(value));
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.trunc(parsed)));
}

function normalizeStates(states = []) {
  if (!Array.isArray(states)) return [];
  const seen = new Set();
  const normalized = [];
  for (const state of states) {
    if (!state || typeof state !== 'object') continue;
    const id = String(state.id ?? '').trim();
    const text = String(state.text ?? state.memory?.value ?? '').trim();
    const contentHash = String(state.content_hash ?? state.memory?.content_hash ?? '').toLowerCase();
    const provenanceAdmitted = state.provenance_admitted === true;
    const canaryAdmitted = state.canary_admitted === true;
    if (!id || !text || seen.has(id) || !SHA256_RE.test(contentHash)) continue;
    if (!provenanceAdmitted || !canaryAdmitted) continue;
    seen.add(id);
    normalized.push({
      id,
      text,
      tokens: exactTokens(text),
      content_hash: contentHash,
      provenance_sha256: String(state.provenance_sha256 ?? '').toLowerCase(),
      scope_id: String(state.scope_id ?? ''),
      session_id: String(state.session_id ?? ''),
    });
    if (normalized.length >= GROUNDED_RECONSTRUCTION_CONSTANTS.max_scope_states) break;
  }
  return normalized;
}

function documentFrequencies(states) {
  const frequencies = new Map();
  for (const state of states) {
    for (const token of new Set(state.tokens)) {
      frequencies.set(token, (frequencies.get(token) || 0) + 1);
    }
  }
  return frequencies;
}

function idf(token, documentCount, frequencies) {
  return Math.log((documentCount + 1) / ((frequencies.get(token) || 0) + 1)) + 1;
}

function rankedTerms(state, documentCount, frequencies) {
  const selected = [];
  for (const token of state.tokens) {
    const candidate = { token, idf: idf(token, documentCount, frequencies) };
    const insertion = selected.findIndex((current) => (
      candidate.idf > current.idf
      || (candidate.idf === current.idf && candidate.token.localeCompare(current.token) < 0)
    ));
    if (insertion >= 0) selected.splice(insertion, 0, candidate);
    else if (selected.length < GROUNDED_RECONSTRUCTION_CONSTANTS.max_terms_per_content) {
      selected.push(candidate);
    }
    if (selected.length > GROUNDED_RECONSTRUCTION_CONSTANTS.max_terms_per_content) {
      selected.length = GROUNDED_RECONSTRUCTION_CONSTANTS.max_terms_per_content;
    }
  }
  return selected;
}

function edgeCommitment(edge) {
  return sha256(`hom-aimos/reconstructed-graph-grounded-edge/v1\0${canonicalJson(edge)}`);
}

export function buildGroundedCueTagContentGraph(states = []) {
  const normalized = normalizeStates(states);
  const normalizedByStateId = new Map(normalized.map((state) => [state.id, state]));
  const documentCount = normalized.length;
  const frequencies = documentFrequencies(normalized);
  const cues = new Map();
  const tags = new Map();
  const contents = new Map();
  const edges = new Map();

  for (const state of normalized) {
    const terms = rankedTerms(state, documentCount, frequencies);
    const cueTerms = terms.slice(0, GROUNDED_RECONSTRUCTION_CONSTANTS.max_cues_per_content);
    const tagTerms = terms.slice(0, GROUNDED_RECONSTRUCTION_CONSTANTS.max_tags_per_content);
    const contentId = `v:${state.id}`;
    contents.set(contentId, {
      id: contentId,
      state_id: state.id,
      text: state.text,
      content_hash: state.content_hash,
      provenance_sha256: state.provenance_sha256,
      scope_id: state.scope_id,
      session_id: state.session_id,
    });

    for (const cueTerm of cueTerms) {
      const cueId = `c:${cueTerm.token}`;
      cues.set(cueId, {
        id: cueId,
        token: cueTerm.token,
        document_frequency: frequencies.get(cueTerm.token) || 0,
        idf: cueTerm.idf,
      });
      for (const tagTerm of tagTerms) {
        if (tagTerm.token === cueTerm.token) continue;
        const tagId = `g:${tagTerm.token}`;
        tags.set(tagId, {
          id: tagId,
          token: tagTerm.token,
          document_frequency: frequencies.get(tagTerm.token) || 0,
          idf: tagTerm.idf,
        });
        const support = {
          content_id: contentId,
          state_id: state.id,
          content_hash: state.content_hash,
          provenance_sha256: state.provenance_sha256,
          cue_token: cueTerm.token,
          tag_token: tagTerm.token,
          // cueTerms and tagTerms are selected only from this state's exact,
          // deduplicated source tokens. Re-scanning a large retained Guide for
          // every relation is redundant and changes no commitment value.
          cue_exact: true,
          tag_exact: true,
        };
        const edge = {
          c: cueId,
          g: tagId,
          v: contentId,
          support,
          commitment_version: 'hom-aimos/reconstructed-graph-grounded-edge/v1',
        };
        edge.edge_sha256 = edgeCommitment(edge);
        edges.set(`${cueId}\0${tagId}\0${contentId}`, edge);
      }
    }
  }

  const R = [...edges.values()].sort((left, right) => (
    left.c.localeCompare(right.c)
    || left.g.localeCompare(right.g)
    || left.v.localeCompare(right.v)
  ));
  const tagsByCue = new Map();
  const edgesByCueTag = new Map();
  const edgesByContent = new Map();
  for (const edge of R) {
    if (!tagsByCue.has(edge.c)) tagsByCue.set(edge.c, new Set());
    tagsByCue.get(edge.c).add(edge.g);
    const pair = `${edge.c}\0${edge.g}`;
    if (!edgesByCueTag.has(pair)) edgesByCueTag.set(pair, []);
    edgesByCueTag.get(pair).push(edge);
    if (!edgesByContent.has(edge.v)) edgesByContent.set(edge.v, []);
    edgesByContent.get(edge.v).push(edge);
  }

  const graph = {
    C: [...cues.values()].sort((left, right) => left.id.localeCompare(right.id)),
    G: [...tags.values()].sort((left, right) => left.id.localeCompare(right.id)),
    V: [...contents.values()].sort((left, right) => left.id.localeCompare(right.id)),
    R,
    indexes: { tagsByCue, edgesByCueTag, edgesByContent },
    document_count: documentCount,
    document_frequencies: frequencies,
    graph_sha256: sha256(`hom-aimos/reconstructed-graph-grounded-graph/v1\0${canonicalJson({
      C: [...cues.keys()].sort(),
      G: [...tags.keys()].sort(),
      V: [...contents.values()].map((row) => ({ id: row.id, content_hash: row.content_hash })).sort((a, b) => a.id.localeCompare(b.id)),
      R: R.map((edge) => edge.edge_sha256),
    })}`),
    construction: 'deterministic_extractive_aimos_adaptation_not_paper_llm_distillation',
  };

  const edgeWitnesses = new WeakMap();
  for (const edge of R) {
    edgeWitnesses.set(edge, Object.freeze({
      edge_sha256: edge.edge_sha256,
      c: edge.c,
      g: edge.g,
      v: edge.v,
      commitment_version: edge.commitment_version,
      content_id: edge.support.content_id,
      state_id: edge.support.state_id,
      content_hash: edge.support.content_hash,
      provenance_sha256: edge.support.provenance_sha256,
      cue_token: edge.support.cue_token,
      tag_token: edge.support.tag_token,
      cue_exact: edge.support.cue_exact,
      tag_exact: edge.support.tag_exact,
    }));
  }
  const contentById = new Map(graph.V.map((content) => [content.id, content]));
  const contentWitnesses = new Map(graph.V.map((content) => {
    const sourceTokens = Object.freeze(
      normalizedByStateId.get(content.state_id)?.tokens || exactTokens(content.text),
    );
    return [content.id, Object.freeze({
      id: content.id,
      state_id: content.state_id,
      text: content.text,
      content_hash: content.content_hash,
      provenance_sha256: content.provenance_sha256,
      source_tokens: sourceTokens,
      source_token_set: new Set(sourceTokens),
    })];
  }));
  GRAPH_RUNTIME_WITNESSES.set(graph, Object.freeze({
    edgeWitnesses,
    contentById,
    contentWitnesses,
    cueById: new Map(graph.C.map((cue) => [cue.id, cue])),
    tagById: new Map(graph.G.map((tag) => [tag.id, tag])),
  }));
  return graph;
}

export function verifyGroundedReconstructionEdge(edge = {}, graph = {}) {
  if (!edge || typeof edge !== 'object') return false;
  if (!SHA256_RE.test(String(edge.edge_sha256 || ''))) return false;
  const runtime = GRAPH_RUNTIME_WITNESSES.get(graph);
  const witness = runtime?.edgeWitnesses.get(edge);
  const contentWitness = runtime?.contentWitnesses.get(edge.v);
  if (witness && contentWitness) {
    return edge.edge_sha256 === witness.edge_sha256
      && edge.c === witness.c
      && edge.g === witness.g
      && edge.v === witness.v
      && edge.commitment_version === witness.commitment_version
      && edge.support?.content_id === witness.content_id
      && edge.support?.state_id === witness.state_id
      && edge.support?.content_hash === witness.content_hash
      && edge.support?.provenance_sha256 === witness.provenance_sha256
      && edge.support?.cue_token === witness.cue_token
      && edge.support?.tag_token === witness.tag_token
      && edge.support?.cue_exact === witness.cue_exact
      && edge.support?.tag_exact === witness.tag_exact
      && contentWitness.id === edge.v
      && contentWitness.state_id === edge.support.state_id
      && contentWitness.content_hash === edge.support.content_hash
      && contentWitness.provenance_sha256 === edge.support.provenance_sha256
      && contentWitness.source_token_set.has(edge.support.cue_token)
      && contentWitness.source_token_set.has(edge.support.tag_token);
  }
  const content = runtime?.contentById.get(edge.v)
    || (Array.isArray(graph.V) ? graph.V : []).find((row) => row.id === edge.v);
  if (!content || content.content_hash !== edge.support?.content_hash) return false;
  if (content.state_id !== edge.support?.state_id) return false;
  if (edge.support?.cue_exact !== true || edge.support?.tag_exact !== true) return false;
  const sourceTokens = new Set(exactTokens(content.text));
  if (!sourceTokens.has(edge.support?.cue_token) || !sourceTokens.has(edge.support?.tag_token)) return false;
  const unsigned = { ...edge };
  delete unsigned.edge_sha256;
  return edge.edge_sha256 === edgeCommitment(unsigned);
}

function seedCues(graph, queryText) {
  const queryTokens = new Set(exactTokens(queryText));
  return graph.C
    .filter((cue) => queryTokens.has(cue.token))
    .sort((left, right) => right.idf - left.idf || left.id.localeCompare(right.id))
    .slice(0, GROUNDED_RECONSTRUCTION_CONSTANTS.max_active_cues_per_step)
    .map((cue) => ({
      cue_id: cue.id,
      cue_token: cue.token,
      root_query_cue: cue.token,
      path_edges: [],
      parent_content_id: null,
      depth: 0,
    }));
}

function pathCommitment(path) {
  return sha256(`hom-aimos/reconstructed-graph-grounded-path/v1\0${canonicalJson(path)}`);
}

export function reconstructGroundedEvidence({
  graph,
  queryText = '',
  steps = GROUNDED_RECONSTRUCTION_CONSTANTS.max_steps,
} = {}) {
  if (!graph?.indexes || !Array.isArray(graph.V)) {
    return {
      discoveries: [], trace: [], traversed_edges: 0, unsupported_edges: 0,
      unsupported_edge_ratio: 0, ungrounded_disclosures: 0,
      ungrounded_disclosure_ratio_at_20: 0, graph_discovery_denominator: 0,
    };
  }
  const stepLimit = boundedInteger(steps, GROUNDED_RECONSTRUCTION_CONSTANTS.max_steps, 0, GROUNDED_RECONSTRUCTION_CONSTANTS.max_steps);
  const runtime = GRAPH_RUNTIME_WITNESSES.get(graph);
  const contentById = runtime?.contentById || new Map(graph.V.map((row) => [row.id, row]));
  const cueById = runtime?.cueById || new Map(graph.C.map((row) => [row.id, row]));
  const tagById = runtime?.tagById || new Map(graph.G.map((row) => [row.id, row]));
  let activeCues = seedCues(graph, queryText);
  const seenCues = new Set(activeCues.map((row) => row.cue_id));
  const discoveries = new Map();
  const traversed = new Map();
  const unsupported = new Set();
  const trace = [];

  for (let step = 0; step < stepLimit && activeCues.length; step += 1) {
    const candidates = new Map();
    for (const activeCue of activeCues) {
      const tagIds = [...(graph.indexes.tagsByCue.get(activeCue.cue_id) || [])].sort();
      for (const tagId of tagIds) {
        for (const edge of graph.indexes.edgesByCueTag.get(`${activeCue.cue_id}\0${tagId}`) || []) {
          traversed.set(edge.edge_sha256, edge);
          if (edge.c !== activeCue.cue_id || edge.g !== tagId
            || !verifyGroundedReconstructionEdge(edge, graph)) {
            unsupported.add(edge.edge_sha256 || `${edge.c}:${edge.g}:${edge.v}`);
            continue;
          }
          const cue = cueById.get(edge.c);
          const tag = tagById.get(edge.g);
          const specificity = ((cue?.idf || 0) + (tag?.idf || 0)) / 2;
          const score = specificity / (step + 1);
          const path = {
            root_query_cue: activeCue.root_query_cue,
            parent_content_id: activeCue.parent_content_id,
            edge_sha256: edge.edge_sha256,
            cue_id: edge.c,
            tag_id: edge.g,
            content_id: edge.v,
            content_hash: edge.support.content_hash,
            depth: step + 1,
            predecessor_edges: activeCue.path_edges,
          };
          path.path_sha256 = pathCommitment(path);
          const prior = candidates.get(edge.v);
          if (!prior || score > prior.score || (score === prior.score && path.path_sha256 < prior.path.path_sha256)) {
            candidates.set(edge.v, { score, path });
          }
        }
      }
    }

    const routed = [...candidates.entries()]
      .map(([contentId, row]) => ({ content_id: contentId, ...row }))
      .sort((left, right) => right.score - left.score || left.content_id.localeCompare(right.content_id))
      .slice(0, GROUNDED_RECONSTRUCTION_CONSTANTS.max_contents_per_step);
    const newDiscoveries = [];
    for (const row of routed) {
      const content = contentById.get(row.content_id);
      if (!content) continue;
      const existing = discoveries.get(row.content_id);
      if (!existing || row.score > existing.score) {
        discoveries.set(row.content_id, {
          state_id: content.state_id,
          content_hash: content.content_hash,
          score: row.score,
          path: row.path,
          grounded: true,
        });
        newDiscoveries.push(row.content_id);
      }
    }

    const nextCues = [];
    for (const row of routed) {
      const content = contentById.get(row.content_id);
      if (!content) continue;
      const sourceTokens = (runtime?.contentWitnesses.get(row.content_id)?.source_tokens
        || exactTokens(content.text))
        .map((token) => ({
          token,
          frequency: graph.document_frequencies.get(token) || 0,
          idf: idf(token, graph.document_count, graph.document_frequencies),
        }))
        .filter((row) => row.frequency >= GROUNDED_RECONSTRUCTION_CONSTANTS.minimum_expansion_cue_documents)
        .filter((row) => row.frequency < graph.document_count)
        .filter((row) => row.frequency <= Math.max(
          GROUNDED_RECONSTRUCTION_CONSTANTS.minimum_expansion_cue_documents,
          Math.floor(graph.document_count * GROUNDED_RECONSTRUCTION_CONSTANTS.maximum_cue_document_ratio),
        ))
        .filter((row) => cueById.has(`c:${row.token}`) && !seenCues.has(`c:${row.token}`))
        .sort((left, right) => right.idf - left.idf || left.token.localeCompare(right.token));
      for (const cue of sourceTokens) {
        const cueId = `c:${cue.token}`;
        if (seenCues.has(cueId)) continue;
        seenCues.add(cueId);
        nextCues.push({
          cue_id: cueId,
          cue_token: cue.token,
          root_query_cue: row.path.root_query_cue,
          path_edges: [...row.path.predecessor_edges, row.path.edge_sha256],
          parent_content_id: row.content_id,
          depth: step + 1,
        });
        if (nextCues.length >= GROUNDED_RECONSTRUCTION_CONSTANTS.max_active_cues_per_step) break;
      }
      if (nextCues.length >= GROUNDED_RECONSTRUCTION_CONSTANTS.max_active_cues_per_step) break;
    }

    trace.push({
      step: step + 1,
      active_cues: activeCues.map((row) => row.cue_id),
      routed_contents: routed.map((row) => row.content_id),
      new_discoveries: newDiscoveries,
      next_cues: nextCues.map((row) => row.cue_id),
      traversed_edges: traversed.size,
      unsupported_edges: unsupported.size,
    });
    activeCues = nextCues;
  }

  const ordered = [...discoveries.values()]
    .sort((left, right) => right.score - left.score || left.state_id.localeCompare(right.state_id));
  const disclosed = ordered.slice(0, GROUNDED_RECONSTRUCTION_CONSTANTS.disclosure_limit);
  const ungrounded = disclosed.filter((row) => !row.grounded || !row.path?.path_sha256).length;
  return {
    discoveries: ordered,
    trace,
    traversed_edges: traversed.size,
    unsupported_edges: unsupported.size,
    unsupported_edge_ratio: traversed.size ? unsupported.size / traversed.size : 0,
    ungrounded_disclosures: ungrounded,
    ungrounded_disclosure_ratio_at_20: disclosed.length ? ungrounded / disclosed.length : 0,
    graph_discovery_denominator: disclosed.length,
  };
}

function rankMap(rows = []) {
  return new Map((Array.isArray(rows) ? rows : []).map((row, index) => [String(row.id), index + 1]));
}

export function groundedReconstructedGraphCandidate({
  queryText = '',
  baselineCandidates = [],
  graph,
  limit = GROUNDED_RECONSTRUCTION_CONSTANTS.disclosure_limit,
} = {}) {
  const cappedLimit = boundedInteger(limit, GROUNDED_RECONSTRUCTION_CONSTANTS.disclosure_limit, 1, GROUNDED_RECONSTRUCTION_CONSTANTS.disclosure_limit);
  const reconstruction = reconstructGroundedEvidence({ graph, queryText });
  const baselineRank = rankMap(baselineCandidates);
  const graphRank = new Map(reconstruction.discoveries.map((row, index) => [row.state_id, index + 1]));
  const baselineById = new Map((Array.isArray(baselineCandidates) ? baselineCandidates : []).map((row) => [String(row.id), row]));
  const graphById = new Map(reconstruction.discoveries.map((row) => [row.state_id, row]));
  const identities = [...new Set([...baselineRank.keys(), ...graphRank.keys()])];
  const rows = identities.map((id) => {
    const baseline = baselineById.get(id);
    const graphRow = graphById.get(id);
    const score = (baselineRank.has(id) ? 1 / (GROUNDED_RECONSTRUCTION_CONSTANTS.rrf_k + baselineRank.get(id)) : 0)
      + (graphRank.has(id) ? 1 / (GROUNDED_RECONSTRUCTION_CONSTANTS.rrf_k + graphRank.get(id)) : 0);
    return {
      ...(baseline || {}),
      id,
      graph_only: !baselineRank.has(id),
      graph_path: graphRow?.path || null,
      graph_grounded: graphRow?.grounded === true,
      grounded_reconstruction_rrf: score,
    };
  }).sort((left, right) => (
    right.grounded_reconstruction_rrf - left.grounded_reconstruction_rrf
    || left.id.localeCompare(right.id)
  )).slice(0, cappedLimit);

  const graphOnlyDisclosed = rows.filter((row) => row.graph_only);
  const ungroundedGraphOnly = graphOnlyDisclosed.filter((row) => !row.graph_grounded || !row.graph_path?.path_sha256);
  return {
    rows,
    diagnostics: {
      ...reconstruction,
      disclosed_graph_only: graphOnlyDisclosed.length,
      ungrounded_graph_only: ungroundedGraphOnly.length,
      ungrounded_disclosure_ratio_at_20: graphOnlyDisclosed.length
        ? ungroundedGraphOnly.length / graphOnlyDisclosed.length
        : 0,
    },
    guardrails: GROUNDED_RECONSTRUCTION_GUARDRAILS,
    policy: 'deterministic_extractive_active_reconstruction_not_paper_llm_policy',
  };
}
