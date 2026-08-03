import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { toolActionArgumentsHash } from '../../services/orchestration/tool-action-ledger.js';

const ROOT = new URL('../../', import.meta.url);

test('tool action hashes bind canonical argument content and field names', () => {
  const first = toolActionArgumentsHash({ content: 'retain this', tags: ['proof'] });
  const reordered = toolActionArgumentsHash({ tags: ['proof'], content: 'retain this' });
  const changed = toolActionArgumentsHash({ content: 'retain that', tags: ['proof'] });
  assert.equal(first, reordered);
  assert.notEqual(first, changed);
  assert.match(first, /^[0-9a-f]{64}$/);
});

test('tool save and recall consume signed native authorities without raw memory SQL', async () => {
  const [registry, persistence, actionLedger] = await Promise.all([
    readFile(new URL('services/orchestration/tool-registry.js', ROOT), 'utf8'),
    readFile(new URL('services/write/persist-memory.js', ROOT), 'utf8'),
    readFile(new URL('services/orchestration/tool-action-ledger.js', ROOT), 'utf8'),
  ]);
  const recallStart = registry.indexOf('async function aimosRecall');
  const saveStart = registry.indexOf('async function aimosSave');
  const recallSource = registry.slice(recallStart, saveStart);
  assert.match(recallSource, /resolveNativeRecallAuthority/);
  assert.match(recallSource, /executeNativeRecall/);
  assert.doesNotMatch(recallSource, /FROM\s+aimos_memories|is_active\s*=\s*true|getEmbedding/);
  assert.match(registry, /tool:\s*'aimos_save_commit'/);
  assert.match(registry, /master_signed_memory_write_grant_required/);
  assert.match(persistence, /expectedTool:\s*'aimos_save_commit'/);
  assert.match(persistence, /expectedArguments:/);
  assert.match(persistence, /authority\.actorValidFromIso/);
  assert.match(persistence, /recallAuthorizationService\.getEffective\(\{[\s\S]*client,/);
  assert.match(persistence, /master_signed_memory_write_grant_required/);
  assert.match(actionLedger, /actor_identity_tier/);
  assert.match(actionLedger, /readVerifiedEventById/);
  assert.match(actionLedger, /tool_execution_started/);
  assert.match(actionLedger, /tool_execution_succeeded/);
  assert.match(actionLedger, /tool_execution_failed/);
});

test('v1 ASMR recall is signed POST over native-admitted evidence only', async () => {
  const [route, asmr, nativeRecall, nativePipeline] = await Promise.all([
    readFile(new URL('routes/v1-api.js', ROOT), 'utf8'),
    readFile(new URL('services/retrieval/asmr-pipeline.js', ROOT), 'utf8'),
    readFile(new URL('services/retrieval/native-recall.js', ROOT), 'utf8'),
    readFile(new URL('services/retrieval/native-recall-pipeline.js', ROOT), 'utf8'),
  ]);
  assert.match(route, /router\.get\('\/recall',[\s\S]*405/);
  assert.match(route, /router\.post\('\/recall'/);
  assert.match(route, /resolveNativeRecallAuthority/);
  assert.match(route, /executeNativeRecall/);
  assert.match(route, /asmrAnswerFromEvidence/);
  assert.match(nativeRecall, /transportBinding\.transport === 'v1'/);
  assert.match(asmr, /asmr_admitted_evidence_required/);
  assert.doesNotMatch(asmr, /runRetrieval|defaultPool|connectedTopK|graphWalkFn\s*=\s*async|timelineFn\s*=\s*async/);
  assert.match(asmr, /asmr_answer_receipt/);
  assert.match(asmr, /variant_results:\s*answerResult\?\.variantResults/);
  assert.match(asmr, /retrieval:\s*answerResult\?\.retrieval/);
  assert.match(asmr, /evidence:\s*answerResult\?\.evidence/);
  assert.match(asmr, /stages:\s*answerResult\?\.stages/);
  assert.match(asmr, /hom\.aimos\.asmr-ingestion-outcome\/v1/);
  assert.match(asmr, /ingestionActionStartReceipt/);
  assert.match(asmr, /ingestionActionReceipt:\s*ingestionOutcomeReceipt/);
  assert.match(asmr, /relationshipPersistence:\s*'extraction_only'/);
  assert.match(nativePipeline, /\[q, queryParam, recallAuthority\.command\.key, recallAuthority\.command\.memory_id\][\s\S]*\.find/);
  assert.doesNotMatch(nativePipeline, /q \?\? queryParam \?\? recallAuthority\.command\.key/);
});
