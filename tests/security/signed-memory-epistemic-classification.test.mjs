import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('epistemic labels are a signed append-only projection, never an admission rewrite', async () => {
  const [migration, persistence] = await Promise.all([
    readFile(new URL('migrations/092-signed-memory-epistemic-classification.sql', ROOT), 'utf8'),
    readFile(new URL('services/write/persist-memory.js', ROOT), 'utf8'),
  ]);

  assert.match(migration, /aimos_memory_epistemic_classifications/);
  assert.match(migration, /memory_epistemic_classified/);
  assert.match(migration, /signer_agent_id <> 'housekeeper'/);
  assert.match(migration, /live_content_hash_mismatch/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE/);
  assert.match(migration, /ON DELETE RESTRICT/);
  assert.match(migration, /verify_memory_epistemic_classification_chain/);
  assert.match(migration, /fork_or_disconnected_history/);
  assert.doesNotMatch(migration, /DELETE\s+FROM\s+public\.aimos_memories/i);
  assert.doesNotMatch(migration, /DROP\s+TABLE\s+public\.aimos_memories/i);

  const classifyAt = persistence.indexOf('classifyAndCommitRetainedMemoryGroup({');
  const provenanceAt = persistence.indexOf('const ledgerCommit = await commitInitialEvidence({');
  const commitAt = persistence.indexOf("if (ownsTransaction) await txClient.query('COMMIT');", provenanceAt);
  assert.ok(provenanceAt >= 0 && classifyAt > provenanceAt && classifyAt < commitAt);
  assert.match(persistence.slice(classifyAt, commitAt), /save_mutation_hash/);
  assert.match(persistence.slice(classifyAt, commitAt), /binding_mutation_hash/);
});

test('canonical recall hydrates the signed label before one pre-disclosure owner', async () => {
  const [pipeline, retrieval] = await Promise.all([
    readFile(new URL('services/retrieval/native-recall-pipeline.js', ROOT), 'utf8'),
    readFile(new URL('services/retrieval/epistemic-trust-retrieval.js', ROOT), 'utf8'),
  ]);
  const start = pipeline.indexOf('async function selectAndLedgerEpistemicRecall');
  const end = pipeline.indexOf('function projectMemoryForRecallRerank', start);
  const owner = pipeline.slice(start, end);
  assert.match(owner, /current_epistemic_label/);
  assert.match(owner, /current_epistemic_confidence_milli/);
  assert.match(owner, /calibrateEpistemicRecall/);
  assert.match(owner, /'epistemic_recall_decision'/);
  assert.match(retrieval, /poison_likely:[^\n]+multiplier: 0\.1/);
  assert.match(retrieval, /poison_refuted:[^\n]+multiplier: 1/);
  assert.match(retrieval, /stored_epistemic_event_id/);
});
