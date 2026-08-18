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

test('one final security closure follows graph fusion and epistemic selection before every output consumer', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const graph = source.indexOf("markStage('concept_graph_ppr')");
  const epistemic = source.indexOf("markStage('epistemic_trust_selection')", graph);
  const closure = source.indexOf('const finalSecurityClosure = await governCanaryRecallFinalClosure({', epistemic);
  const workingMemory = source.indexOf('workingMemory = disclosureMemories', closure);
  const reinforcement = source.indexOf('reinforceRetrievedPheromones(disclosureMemories', closure);
  const receipt = source.indexOf('calibratedRecallResponse = await calibrateAndFinalizeNativeRecallReturn({', closure);

  assert.ok(graph >= 0);
  assert.ok(epistemic > graph);
  assert.ok(closure > epistemic);
  assert.ok(workingMemory > closure);
  assert.ok(reinforcement > closure);
  assert.ok(receipt > reinforcement);
});

test('final closure records one Canary/Aladdin receipt while keeping SABER outside runtime authority', async () => {
  const [pipeline, tracker] = await Promise.all([
    readFile(new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/security/canary-tracker.js', import.meta.url), 'utf8'),
  ]);
  const begin = tracker.indexOf('export async function governCanaryRecallFinalClosure');
  const end = tracker.indexOf('/**', begin + 10);
  const owner = tracker.slice(begin, end);

  assert.doesNotMatch(pipeline, /closeNativeRecallSecurityBoundary|closeGraphSecurityBoundary/);
  assert.doesNotMatch(pipeline, /graph_security_closure|magma_security_closure|reconstructed_graph_security_closure/);
  assert.match(owner, /'canary_recall_final_closure'/);
  assert.match(owner, /classification_map: classificationSnapshot/);
  assert.match(owner, /consumer_commitment_root_sha256/);
  assert.match(owner, /canonical_memory_mutated:\s*false/);
  assert.match(owner, /retention_changed:\s*false/);
  assert.match(owner, /deletion_performed:\s*false/);
  assert.match(owner, /persistent_suppression_performed:\s*false/);
  assert.match(owner, /saber_runtime_authority:\s*false/);
  assert.match(owner, /final_closure_receipt_count:\s*1/);
});

test('exact identifier recall passes Canary and Aladdin closure before response disclosure', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const exact = source.indexOf('if (identifierLookup.status === IDENTIFIER_RECALL_STATUS.EXACT_MATCH');
  const exactCondition = source.slice(exact, source.indexOf('{', exact));
  const epistemic = source.indexOf('const identifierEpistemic = await selectAndLedgerEpistemicRecall', exact);
  const closure = source.indexOf('const identifierFinalClosure = await governCanaryRecallFinalClosure({', epistemic);
  const body = source.indexOf('const identifierBody = {', closure);
  const receipt = source.indexOf('calibratedIdentifierBody = await calibrateAndFinalizeNativeRecallReturn', body);

  assert.ok(exact >= 0);
  assert.doesNotMatch(exactCondition, /magmaConfig/,
    'an enforced graph policy cannot override explicit memory-id authority');
  assert.ok(epistemic > exact);
  assert.ok(closure > epistemic);
  assert.ok(body > closure);
  assert.ok(receipt > body);
  assert.match(source.slice(closure, body), /selectedMemories:\s*identifierEpistemic\.memories/);
  assert.match(source.slice(body, receipt), /memories:\s*identifierFinalClosure\.memories/);
  assert.match(source.slice(body, receipt), /canaryFinalClosureMetadata\(identifierFinalClosure\)/);
  assert.match(source.slice(body, receipt), /applicability:\s*'not_applicable_explicit_identifier'/);
  assert.match(source.slice(body, receipt), /authority_ruling:\s*'exact_identifier_non_substitutable'/);
  assert.match(source.slice(body, receipt), /substitution_authorized:\s*false/);
  assert.match(source.slice(body, receipt), /graph_traversal_executed:\s*false/);
  assert.match(source.slice(receipt, receipt + 700), /securityClosure:\s*identifierFinalClosure/);
  assert.match(source.slice(receipt, receipt + 700), /contentStateSelection:\s*identifierStateSelection\.decision/);
});
