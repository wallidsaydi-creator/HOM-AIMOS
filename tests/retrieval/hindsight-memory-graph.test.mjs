import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  HINDSIGHT_CONSTANTS,
  HINDSIGHT_GUARDRAILS,
  bm25Scores,
  buildHindsightGraph,
  hindsightMemoryGraphScores,
  memoryPartition,
  partitionMemoryUnit,
  reciprocalRankFusion,
  semanticEdgeWeight,
  temprSpreadingActivation,
  temporalEdgeWeight,
  temporalIntervalScores,
  updateOpinionConfidence,
} from '../../services/retrieval/hindsight-memory-graph.js';

const DAY = 86_400_000;

function fixtureStates() {
  return [
    {
      id: 'world-1',
      text: 'Alice founded Acme in Rome.',
      embedding: [1, 0],
      entities: ['Alice', 'Acme'],
      interval: { start: Date.UTC(2026, 0, 1), end: Date.UTC(2026, 0, 2) },
      causal_links: [{ target: 'experience-1', type: 'causes', weight: 1 }],
      memory: { source: 'fixture', created_at: '2026-01-01T00:00:00.000Z' },
    },
    {
      id: 'experience-1',
      text: 'I joined Acme after meeting Alice.',
      embedding: [0.9, 0.1],
      entities: ['Alice', 'Acme'],
      interval: { start: Date.UTC(2026, 0, 3), end: Date.UTC(2026, 0, 3) },
      memory: { source: 'fixture', created_at: '2026-01-03T00:00:00.000Z' },
    },
    {
      id: 'opinion-1',
      text: 'I think remote work is useful.',
      embedding: [0, 1],
      entities: ['Remote Work'],
      interval: { start: Date.UTC(2026, 1, 1), end: Date.UTC(2026, 1, 1) },
      memory: { source: 'fixture', confidence: 0.7, created_at: '2026-02-01T00:00:00.000Z' },
    },
    {
      id: 'observation-1',
      text: 'Currently Alice leads the Acme profile.',
      embedding: [0.95, 0.05],
      entities: ['Alice', 'Acme'],
      interval: { start: Date.UTC(2026, 0, 4), end: Date.UTC(2026, 0, 4) },
      memory: { source: 'fixture', created_at: '2026-01-04T00:00:00.000Z' },
    },
  ];
}

test('partitioning realizes W/B/O/S without mutating input', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const units = states.map(partitionMemoryUnit);
  const partition = memoryPartition(units);

  assert.deepEqual(states, before);
  assert.deepEqual(
    [partition.W.length, partition.B.length, partition.O.length, partition.S.length],
    [1, 1, 1, 1],
  );
  assert.equal(units[2].c, 0.7);
  assert.equal(partitionMemoryUnit(null), null);
  assert.equal(partitionMemoryUnit({ id: 'empty', text: '' }), null);
});

test('graph construction is deterministic, typed, explicit, bounded, and immutable', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const first = buildHindsightGraph(states);
  const second = buildHindsightGraph(states);

  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.equal(first.V.length, 4);
  assert.ok(first.E.some((edge) => edge.type === 'entity' && edge.from === 'world-1' && edge.to === 'experience-1'));
  assert.ok(first.E.some((edge) => edge.type === 'causes' && edge.from === 'world-1' && edge.to === 'experience-1'));
  assert.ok(first.E.some((edge) => edge.type === 'semantic'));
  assert.ok(first.E.some((edge) => edge.type === 'temporal'));
  assert.ok(first.E.every((edge) => Number.isFinite(edge.weight) && edge.weight > 0 && edge.weight <= 1));

  const oversized = Array.from({ length: HINDSIGHT_CONSTANTS.max_nodes + 20 }, (_, index) => ({
    id: `node-${index}`,
    text: `Memory node ${index}`,
  }));
  assert.equal(buildHindsightGraph(oversized).V.length, HINDSIGHT_CONSTANTS.max_nodes);
  assert.deepEqual(buildHindsightGraph([null, {}, { id: 'x', text: 'valid memory' }, { id: 'x', text: 'duplicate' }]).V.map((row) => row.u), ['x']);
});

test('temporal and semantic edge equations preserve their mathematical bounds', () => {
  const left = { tau_s: 0, v: [1, 0] };
  const right = { tau_s: 10 * DAY, v: [0.8, 0.2] };
  assert.ok(Math.abs(temporalEdgeWeight(left, right, 10) - Math.exp(-1)) < 1e-12);
  assert.equal(temporalEdgeWeight(left, right, 0), 0);
  assert.ok(semanticEdgeWeight(left, right, 0.9) > 0.9);
  assert.equal(semanticEdgeWeight(left, { v: [0, 1] }, 0.1), 0);
  assert.equal(semanticEdgeWeight({ v: [1, Number.NaN] }, right), 0);
});

test('BM25 uses corpus document frequency and length normalization', () => {
  const units = [
    { u: 'rare', t: 'quasar memory' },
    { u: 'common-1', t: 'memory memory memory memory' },
    { u: 'common-2', t: 'memory record' },
  ];
  const rare = bm25Scores('quasar', units);
  const common = bm25Scores('memory', units);
  assert.ok(rare.get('rare') > 0);
  assert.ok(common.get('common-1') > common.get('rare'));
  assert.deepEqual([...bm25Scores('', units)], []);
});

test('spreading activation is hop-bounded and finite on cycles', () => {
  const graph = {
    V: [{ u: 'a' }, { u: 'b' }, { u: 'c' }],
    E: [
      { from: 'a', to: 'b', weight: 1, type: 'entity' },
      { from: 'b', to: 'c', weight: 1, type: 'causal' },
      { from: 'c', to: 'a', weight: 1, type: 'entity' },
    ],
  };
  const scores = temprSpreadingActivation(graph, new Map([['a', 1]]), { maxHops: 3 });
  assert.equal(scores.size, 3);
  assert.ok(scores.get('b') > 0);
  assert.ok(scores.get('c') > 0);
  assert.ok([...scores.values()].every((score) => Number.isFinite(score) && score >= 0 && score <= 1));
});

test('temporal interval retrieval requires overlap and scores midpoint proximity', () => {
  const units = [
    { u: 'inside', tau_s: 10, tau_e: 20 },
    { u: 'overlap', tau_s: 0, tau_e: 12 },
    { u: 'outside', tau_s: 30, tau_e: 40 },
  ];
  const scores = temporalIntervalScores(units, { start: 10, end: 20 });
  assert.equal(scores.get('inside'), 1);
  assert.ok(scores.has('overlap'));
  assert.equal(scores.has('outside'), false);
  assert.equal(temporalIntervalScores(units, null).size, 0);
});

test('RRF is raw Equation 15 and ignores duplicate identities within a channel', () => {
  const scores = reciprocalRankFusion([
    [{ id: 'a' }, { id: 'a' }, { id: 'b' }],
    [{ id: 'b' }, { id: 'a' }],
  ], 60);
  assert.ok(Math.abs(scores.get('a') - ((1 / 61) + (1 / 62))) < 1e-12);
  assert.ok(Math.abs(scores.get('b') - ((1 / 62) + (1 / 61))) < 1e-12);
  assert.equal(scores.get('b'), scores.get('a'));
});

test('dormant recall kernel is deterministic, bounded, token-budgeted, and does not invent a neural channel', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const input = {
    queryText: 'Alice Acme',
    queryEmbedding: [1, 0],
    queryInterval: { start: Date.UTC(2026, 0, 1), end: Date.UTC(2026, 0, 5) },
    states,
    tokenBudget: 10,
  };
  const first = hindsightMemoryGraphScores(input);
  const second = hindsightMemoryGraphScores(input);

  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.ok(first.used_tokens <= first.budget_tokens);
  assert.equal(first.channel_stats.neural_cross_encoder, 0);
  assert.equal(first.guardrails.dormant, true);
  assert.equal(first.guardrails.persists_opinion_updates, false);
  assert.ok([...first.scoreById.values()].every((score) => Number.isFinite(score) && score >= 0 && score <= 1));
  assert.equal(hindsightMemoryGraphScores({ states: null }).graph_stats.nodes, 0);
});

test('opinion confidence arithmetic is pure Equation 26 and never persists', () => {
  assert.equal(updateOpinionConfidence(0.5, 'reinforce', 0.1), 0.6);
  assert.equal(updateOpinionConfidence(0.5, 'weaken', 0.1), 0.4);
  assert.equal(updateOpinionConfidence(0.5, 'contradict', 0.1), 0.3);
  assert.equal(updateOpinionConfidence(0.5, 'neutral', 0.1), 0.5);
  assert.equal(updateOpinionConfidence(0.95, 'reinforce', 0.1), 1);
  assert.equal(updateOpinionConfidence(0.05, 'contradict', 0.1), 0);
});

test('source remains a pure dormant kernel with no database, server, or environment authority', () => {
  const source = readFileSync(new URL('../../services/retrieval/hindsight-memory-graph.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
  assert.doesNotMatch(source, /crossEncoderScore|bm25Like|graphCentralityScores/);
  assert.match(source, /neural_cross_encoder_implemented:\s*false/);
  assert.equal(HINDSIGHT_GUARDRAILS.uses_environment_authority, false);
});
