import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { partitionGraphCanaryDisclosure } from '../../services/retrieval/native-recall-pipeline.js';

test('Concept graph Canary closure withholds marked disclosure without mutating retained evidence', () => {
  const clean = Object.freeze({ id: 'clean', key: 'memory:clean', value: 'ordinary retained evidence' });
  const marked = Object.freeze({ id: 'marked', key: 'memory:marked', value: 'tracked SECRET-DEADBEEF evidence' });
  const input = Object.freeze([clean, marked]);

  const result = partitionGraphCanaryDisclosure(input);

  assert.deepEqual(result.admitted, [clean]);
  assert.deepEqual(result.withheld, [marked]);
  assert.deepEqual(result.canary_tokens, ['SECRET-DEADBEEF']);
  assert.equal(input.length, 2, 'canonical retained input remains present');
  assert.equal(marked.value, 'tracked SECRET-DEADBEEF evidence');
});

test('Concept graph security closure follows graph fusion and epistemic selection before every output consumer', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const graph = source.indexOf("markStage('concept_graph_ppr')");
  const epistemic = source.indexOf("markStage('epistemic_trust_selection')", graph);
  const closure = source.indexOf('await closeGraphSecurityBoundary({', epistemic);
  const workingMemory = source.indexOf('workingMemory = disclosureMemories', closure);
  const reinforcement = source.indexOf('reinforceRetrievedPheromones(disclosureMemories', closure);
  const receipt = source.indexOf('calibratedRecallResponse.recall_receipt = await finalizeNativeRecall({', closure);

  assert.ok(graph >= 0);
  assert.ok(epistemic > graph);
  assert.ok(closure > epistemic);
  assert.ok(workingMemory > closure);
  assert.ok(reinforcement > closure);
  assert.ok(receipt > reinforcement);
});

test('Concept closure records Canary and Aladdin evidence while keeping SABER outside runtime authority', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const begin = source.indexOf('async function closeNativeRecallSecurityBoundary');
  const end = source.indexOf('\nasync function closeGraphSecurityBoundary', begin);
  const owner = source.slice(begin, end);

  assert.match(owner, /scanRelayedMemory\(/);
  assert.match(owner, /'graph_security_closure'/);
  assert.match(owner, /graph_decision_sha256/);
  assert.match(owner, /graph_edge_commitment_sha256/);
  assert.match(owner, /canonical_memory_changed:\s*false/);
  assert.match(owner, /retention_changed:\s*false/);
  assert.match(owner, /deletion_performed:\s*false/);
  assert.match(owner, /suppression_performed:\s*false/);
  assert.match(owner, /runtime_authority:\s*false/);
  assert.match(owner, /separate_isolated_campaign_required/);
});

test('exact identifier recall passes Canary and Aladdin closure before response disclosure', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const exact = source.indexOf('if (identifierLookup.status === IDENTIFIER_RECALL_STATUS.EXACT_MATCH');
  const exactCondition = source.slice(exact, source.indexOf('{', exact));
  const epistemic = source.indexOf('const identifierEpistemic = await selectAndLedgerEpistemicRecall', exact);
  const closure = source.indexOf("boundaryId: 'identifier_exact'", epistemic);
  const body = source.indexOf('const identifierBody = {', closure);
  const receipt = source.indexOf('calibratedIdentifierBody.recall_receipt = await finalizeNativeRecall', body);

  assert.ok(exact >= 0);
  assert.doesNotMatch(exactCondition, /magmaConfig/,
    'an enforced graph policy cannot override explicit memory-id authority');
  assert.ok(epistemic > exact);
  assert.ok(closure > epistemic);
  assert.ok(body > closure);
  assert.ok(receipt > body);
  assert.match(source.slice(closure, body), /memories:\s*identifierEpistemic\.memories/);
  assert.match(source.slice(body, receipt), /memories:\s*identifierSecurity\.memories/);
  assert.match(source.slice(body, receipt), /recall_security_closure:\s*identifierSecurity\.decision/);
  assert.match(source.slice(body, receipt), /applicability:\s*'not_applicable_explicit_identifier'/);
  assert.match(source.slice(body, receipt), /authority_ruling:\s*'exact_identifier_non_substitutable'/);
  assert.match(source.slice(body, receipt), /substitution_authorized:\s*false/);
  assert.match(source.slice(body, receipt), /graph_traversal_executed:\s*false/);
});
