import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  RECONSTRUCTED_GRAPH_ACTIONS,
  RECONSTRUCTED_GRAPH_CONSTANTS,
  RECONSTRUCTED_GRAPH_GUARDRAILS,
  buildCueTagContentGraph,
  buildRelationIndexes,
  lexicalCoverageSufficiency,
  phiContentToCueTag,
  phiCueTagToContent,
  phiCueToTag,
  reconstructMemoryState,
  reconstructedGraphMemoryScores,
  routeLexicalReconstructionCandidates,
  selectDeterministicReconstructionActions,
  traverseReconstructionActions,
} from '../../services/retrieval/reconstructed-graph-memory.js';

function fixtureStates() {
  return [
    { id: 'a', text: 'Alice joined Project Quasar in Rome during May 2026.' },
    { id: 'b', text: 'Alice approved the Quasar launch after the Rome review.' },
    { id: 'c', text: 'Caroline visited Berlin for an art exhibition.' },
  ];
}

function manualGraph() {
  const R = [
    { c: 'c:alice', g: 'g:collaboration', v: 'v:target' },
    { c: 'c:quasar', g: 'g:project', v: 'v:target' },
  ];
  return {
    C: [
      { id: 'c:alice', cue: 'alice' },
      { id: 'c:quasar', cue: 'quasar' },
    ],
    G: [
      { id: 'g:collaboration', tag: 'collaboration' },
      { id: 'g:project', tag: 'project' },
    ],
    V: [{ id: 'v:target', state_id: 'target', text: 'Project Quasar launches tomorrow.', layer: 'episodic' }],
    R,
    indexes: buildRelationIndexes(R),
  };
}

test('graph construction is deterministic, immutable, malformed-safe, unique, and capped', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const first = buildCueTagContentGraph(states);
  const second = buildCueTagContentGraph(states);

  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.equal(first.V.length, 3);
  assert.equal(new Set(first.R.map((row) => `${row.c}\0${row.g}\0${row.v}`)).size, first.R.length);
  assert.ok(first.R.every((row) => row.c.startsWith('c:') && row.g.startsWith('g:') && row.v.startsWith('v:')));
  assert.deepEqual(
    buildCueTagContentGraph([null, {}, { id: 'x', text: '' }, { id: 'x', text: 'valid memory' }, { id: 'x', text: 'duplicate memory' }]).V.map((row) => row.state_id),
    ['x'],
  );

  const oversized = Array.from({ length: RECONSTRUCTED_GRAPH_CONSTANTS.max_states + 8 }, (_, index) => ({
    id: `state-${index}`,
    text: `Distinct graph memory ${index}`,
  }));
  assert.equal(buildCueTagContentGraph(oversized).V.length, RECONSTRUCTED_GRAPH_CONSTANTS.max_states);
});

test('indexed Cue-Tag-Content mappings realize Equations 5, 8, and 9 exactly', () => {
  const graph = manualGraph();
  assert.deepEqual(phiCueToTag(graph, ['c:alice']), ['g:collaboration']);
  assert.deepEqual(phiCueTagToContent(graph, ['c:alice'], ['g:collaboration']), ['v:target']);
  assert.deepEqual(phiCueTagToContent(graph, ['c:alice'], ['g:project']), []);
  assert.deepEqual(phiCueTagToContent(graph, [], ['g:collaboration']), []);
  assert.deepEqual(phiContentToCueTag(graph, ['v:target']), [
    { c: 'c:alice', g: 'g:collaboration' },
    { c: 'c:quasar', g: 'g:project' },
  ]);
});

test('action selection and controlled traversal remain explicit deterministic adaptations', () => {
  assert.deepEqual(selectDeterministicReconstructionActions(['c:alice']), [RECONSTRUCTED_GRAPH_ACTIONS.cue_to_tag]);
  assert.deepEqual(selectDeterministicReconstructionActions(['c:alice', 'g:collaboration']), [
    RECONSTRUCTED_GRAPH_ACTIONS.cue_to_tag,
    RECONSTRUCTED_GRAPH_ACTIONS.cue_tag_to_content,
  ]);
  assert.deepEqual(selectDeterministicReconstructionActions(['v:target']), [RECONSTRUCTED_GRAPH_ACTIONS.content_to_cue_tag]);
  assert.deepEqual(
    traverseReconstructionActions(manualGraph(), ['c:alice', 'g:collaboration'], [
      RECONSTRUCTED_GRAPH_ACTIONS.cue_to_tag,
      RECONSTRUCTED_GRAPH_ACTIONS.cue_tag_to_content,
    ]),
    ['g:collaboration', 'v:target'],
  );
});

test('lexical routing can acquire structurally connected content with zero direct similarity', () => {
  const graph = manualGraph();
  const [row] = routeLexicalReconstructionCandidates(graph, 'Alice', ['v:target']);
  assert.equal(row.id, 'v:target');
  assert.equal(row.score, 0);
  assert.match(row.policy, /not_paper_f_route/);

  const result = reconstructMemoryState({ graph, queryText: 'Alice missing-evidence', steps: 3 });
  assert.ok(result.Z.includes('v:target'));
  assert.deepEqual(result.H.map((entry) => entry.id), ['v:target']);
  assert.equal(result.candidate_window_only, true);
});

test('reconstruction state is monotone, bounded, and keeps unique history under cycles', () => {
  const graph = manualGraph();
  const result = reconstructMemoryState({ graph, queryText: 'Alice missing-evidence', steps: 100 });

  assert.ok(result.trace.length <= RECONSTRUCTED_GRAPH_CONSTANTS.max_steps);
  assert.equal(result.H.length, new Set(result.H.map((row) => row.id)).size);
  assert.equal(result.H.length, 1);
  assert.ok((result.activation_counts['v:target'] || 0) >= 1);
  for (let index = 1; index < result.trace.length; index += 1) {
    assert.ok(result.trace[index].active_after >= result.trace[index - 1].active_after);
    assert.ok(result.trace[index].history_size >= result.trace[index - 1].history_size);
  }
  assert.ok(['stagnation', 'max_steps'].includes(result.termination_reason));
});

test('termination diagnostics distinguish no seed, lexical sufficiency, and stagnation', () => {
  const graph = manualGraph();
  assert.equal(reconstructMemoryState({ graph, queryText: 'unrelated' }).termination_reason, 'no_seed_cues');

  const sufficient = reconstructMemoryState({ graph, queryText: 'Quasar project' });
  assert.equal(sufficient.termination_reason, 'lexical_coverage_sufficient');
  assert.equal(sufficient.trace.at(-1).lexical_coverage, 1);

  const stalled = reconstructMemoryState({ graph, queryText: 'Alice missing-evidence' });
  assert.ok(stalled.trace.some((row) => row.repeated_activation_count > 0));
  assert.ok(['stagnation', 'max_steps'].includes(stalled.termination_reason));
});

test('lexical coverage is a bounded AIMOS diagnostic rather than paper model sufficiency', () => {
  assert.deepEqual(lexicalCoverageSufficiency('', []), {
    sufficient: false,
    coverage: 0,
    covered_tokens: 0,
    query_tokens: 0,
  });
  const partial = lexicalCoverageSufficiency('Alice Quasar Rome', [{ text: 'Alice reviewed Quasar.' }]);
  assert.equal(partial.coverage, 2 / 3);
  assert.equal(partial.sufficient, false);
  assert.equal(lexicalCoverageSufficiency('Alice Quasar', [{ text: 'Alice reviewed Quasar.' }]).sufficient, true);
});

test('service output is deterministic, bounded, candidate-window-only, and honest about missing paper stages', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const first = reconstructedGraphMemoryScores({ queryText: 'Alice Quasar Rome approval', states });
  const second = reconstructedGraphMemoryScores({ queryText: 'Alice Quasar Rome approval', states });

  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.equal(first.reconstructed_context_count, first.unique_reconstructed_context_count);
  assert.ok([...first.scoreById.values()].every((score) => Number.isFinite(score) && score >= 0 && score <= 1));
  assert.ok([...first.diagnosticsById.values()].every((row) => Number.isFinite(row.relation_degree)));
  assert.equal(first.guardrails.candidate_window_only, true);
  assert.equal(first.guardrails.uses_model_policy, false);
  assert.ok(first.unimplemented_paper_components.includes('LLM action selection f_select'));
  assert.equal(reconstructedGraphMemoryScores({ states: null }).graph_stats.contents, 0);
});

test('the kernel cannot invent or retrieve content outside the admitted graph', () => {
  const result = reconstructedGraphMemoryScores({
    queryText: 'outside target',
    states: [{ id: 'inside', text: 'Only admitted content exists here.' }],
  });
  assert.deepEqual([...result.scoreById.keys()], ['inside']);
  assert.equal(result.diagnosticsById.has('outside'), false);
});

test('source contains no database, network, server, persistence, or environment authority', () => {
  const source = readFileSync(new URL('../../services/retrieval/reconstructed-graph-memory.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
  assert.doesNotMatch(source, /\bpi_a\b|Native Graph Memory reconstruction recall operator/);
  assert.equal(RECONSTRUCTED_GRAPH_GUARDRAILS.dormant, true);
  assert.equal(RECONSTRUCTED_GRAPH_GUARDRAILS.uses_environment_authority, false);
  assert.equal(RECONSTRUCTED_GRAPH_GUARDRAILS.accesses_database, false);
  assert.equal(RECONSTRUCTED_GRAPH_GUARDRAILS.mutates_canonical_memory, false);
});
