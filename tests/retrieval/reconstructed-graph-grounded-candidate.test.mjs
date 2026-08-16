import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  GROUNDED_RECONSTRUCTION_GUARDRAILS,
  buildGroundedCueTagContentGraph,
  groundedReconstructedGraphCandidate,
  reconstructGroundedEvidence,
  verifyGroundedReconstructionEdge,
} from '../../services/retrieval/reconstructed-graph-grounded-candidate.js';

function hash(char) {
  return char.repeat(64);
}

function fixtureStates() {
  return [
    {
      id: 'a',
      text: 'Alice submitted the Quasar screenplay during spring.',
      content_hash: hash('a'),
      provenance_sha256: hash('1'),
      provenance_admitted: true,
      canary_admitted: true,
      scope_id: 'scope-1',
      session_id: 'session-1',
    },
    {
      id: 'b',
      text: 'Quasar received an Orion company review during summer.',
      content_hash: hash('b'),
      provenance_sha256: hash('2'),
      provenance_admitted: true,
      canary_admitted: true,
      scope_id: 'scope-1',
      session_id: 'session-2',
    },
    {
      id: 'c',
      text: 'Orion company rejected the screenplay after review.',
      content_hash: hash('c'),
      provenance_sha256: hash('3'),
      provenance_admitted: true,
      canary_admitted: true,
      scope_id: 'scope-1',
      session_id: 'session-3',
    },
  ];
}

test('grounded graph is deterministic, immutable, and accepts only provenance and Canary admitted sources', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const first = buildGroundedCueTagContentGraph(states);
  const second = buildGroundedCueTagContentGraph(states);

  assert.equal(first.graph_sha256, second.graph_sha256);
  assert.deepEqual(states, before);
  assert.equal(first.V.length, 3);
  assert.ok(first.R.length > 0);
  assert.ok(first.R.every((edge) => verifyGroundedReconstructionEdge(edge, first)));

  const rejected = buildGroundedCueTagContentGraph([
    { ...states[0], id: 'bad-provenance', provenance_admitted: false },
    { ...states[0], id: 'bad-canary', canary_admitted: false },
    { ...states[0], id: 'bad-hash', content_hash: 'not-a-hash' },
  ]);
  assert.equal(rejected.V.length, 0);
  assert.equal(rejected.R.length, 0);
});

test('every cue and tag is extractively supported by its canonical source text', () => {
  const graph = buildGroundedCueTagContentGraph(fixtureStates());
  for (const edge of graph.R) {
    const content = graph.V.find((row) => row.id === edge.v);
    assert.ok(content.text.toLowerCase().includes(edge.support.cue_token));
    assert.ok(content.text.toLowerCase().includes(edge.support.tag_token));
    assert.equal(edge.support.content_hash, content.content_hash);
    assert.equal(verifyGroundedReconstructionEdge(edge, graph), true);
  }
});

test('edge verification detects commitment and source-support tampering', () => {
  const graph = buildGroundedCueTagContentGraph(fixtureStates());
  const edge = structuredClone(graph.R[0]);
  edge.support.tag_token = 'invented-token';
  assert.equal(verifyGroundedReconstructionEdge(edge, graph), false);

  const commitmentTamper = structuredClone(graph.R[0]);
  commitmentTamper.edge_sha256 = hash('f');
  assert.equal(verifyGroundedReconstructionEdge(commitmentTamper, graph), false);
});

test('active reconstruction can traverse an extractive multi-step bridge without inventing content', () => {
  const graph = buildGroundedCueTagContentGraph(fixtureStates());
  const result = reconstructGroundedEvidence({
    graph,
    queryText: 'What happened to Alice submission?',
    steps: 3,
  });

  assert.ok(result.discoveries.some((row) => row.state_id === 'a'));
  assert.ok(result.discoveries.some((row) => row.state_id === 'b'));
  assert.ok(result.discoveries.some((row) => row.state_id === 'c'));
  assert.ok(result.trace.length >= 2);
  assert.equal(result.unsupported_edges, 0);
  assert.equal(result.unsupported_edge_ratio, 0);
  assert.equal(result.ungrounded_disclosures, 0);
  assert.equal(result.ungrounded_disclosure_ratio_at_20, 0);
  assert.ok(result.graph_discovery_denominator > 0);
  assert.ok(result.discoveries.every((row) => row.path?.path_sha256 && row.content_hash));
});

test('unsupported traversed edges raise the hallucination precursor ratio and cannot disclose', () => {
  const graph = buildGroundedCueTagContentGraph(fixtureStates());
  const target = graph.R.find((edge) => edge.c === 'c:alice');
  assert.ok(target);
  target.support.cue_exact = false;

  const result = reconstructGroundedEvidence({ graph, queryText: 'Alice submission', steps: 1 });
  assert.ok(result.unsupported_edges > 0);
  assert.ok(result.unsupported_edge_ratio > 0);
  assert.ok(result.discoveries.every((row) => row.path.edge_sha256 !== target.edge_sha256));
});

test('zero discovery keeps a transparent zero denominator rather than claiming useful grounding', () => {
  const graph = buildGroundedCueTagContentGraph(fixtureStates());
  const result = reconstructGroundedEvidence({ graph, queryText: 'unrelated-zoology', steps: 3 });
  assert.equal(result.discoveries.length, 0);
  assert.equal(result.graph_discovery_denominator, 0);
  assert.equal(result.ungrounded_disclosure_ratio_at_20, 0);
});

test('candidate can add grounded scope evidence outside the baseline set without changing inputs', () => {
  const states = fixtureStates();
  const baselineCandidates = [{ id: 'a', rerank_score: 0.9, text: states[0].text }];
  const before = structuredClone(baselineCandidates);
  const graph = buildGroundedCueTagContentGraph(states);
  const result = groundedReconstructedGraphCandidate({
    graph,
    queryText: 'What happened to Alice submission?',
    baselineCandidates,
  });

  assert.deepEqual(baselineCandidates, before);
  assert.ok(result.rows.some((row) => row.id === 'b' && row.graph_only));
  assert.ok(result.rows.some((row) => row.id === 'c' && row.graph_only));
  assert.equal(result.diagnostics.ungrounded_graph_only, 0);
  assert.equal(result.diagnostics.ungrounded_disclosure_ratio_at_20, 0);
  assert.equal(result.guardrails.model_authority, false);
  assert.equal(result.guardrails.topic_clustering, false);
});

test('candidate source owns no database, server, network, model, persistence, or ENV authority', () => {
  const source = readFileSync(new URL('../../services/retrieval/reconstructed-graph-grounded-candidate.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
  assert.doesNotMatch(source, /openai|anthropic|ollama|provider|chatgpt/i);
  assert.equal(GROUNDED_RECONSTRUCTION_GUARDRAILS.dormant, true);
  assert.equal(GROUNDED_RECONSTRUCTION_GUARDRAILS.environment_authority, false);
  assert.equal(GROUNDED_RECONSTRUCTION_GUARDRAILS.graph_persistence, false);
  assert.equal(GROUNDED_RECONSTRUCTION_GUARDRAILS.answer_generation, false);
});
