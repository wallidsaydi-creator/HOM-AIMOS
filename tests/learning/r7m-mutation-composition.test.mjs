import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), 'utf8');

test('recall receipts bind the disclosed occurrence before Merkle commitment', () => {
  const recall = read('services/retrieval/native-recall.js');
  assert.match(recall, /disclosure_occurrence_ref/);
  assert.match(recall, /occurrence_ref: occurrenceRef/);
  assert.match(recall, /recall_disclosure_occurrence_ref_invalid/);
});

test('outcome mutation rejects naked memory IDs and verifies signed disclosure first', () => {
  const stdp = read('services/learning/stdp-kernel.js');
  const authority = read('services/learning/mutation-composition/outcome-authority.js');
  assert.match(stdp, /validateOutcomeMutationEvidence\(context\.outcomeEvidence \|\| \{\}\)/);
  assert.match(stdp, /verifyOutcomeMutationEvidence[\s\S]+appendMutationOutcomeEvidenceEvent[\s\S]+appendValence/);
  assert.match(authority, /readVerifiedEventById/);
  assert.match(authority, /receipt\.operation !== 'recall_receipt'/);
  assert.match(authority, /occurrence_ref/);
  assert.match(authority, /exclusiveOperationKey: true/);
});

test('occurrence observation is retained with zero weight authority', () => {
  const stdp = read('services/learning/stdp-kernel.js');
  const valence = read('services/governance/valence-ledger.js');
  assert.match(stdp, /target_scope === 'occurrence_observation'[\s\S]+projection_appended: false/);
  assert.match(valence, /evidence_schema_version=1 OR target_scope='principal_state'/);
});

test('SPICED collapses principal-state targets before locks and signed mutation', () => {
  const source = read('services/dream/spiced-consolidator.js');
  const resolveAt = source.indexOf('resolvePrincipalStateMutationTargets({');
  const lockAt = source.indexOf('cognitive-reweight:${COMPANY}:${memoryId}', resolveAt);
  const mutateAt = source.indexOf('commitGovernorMutation({', resolveAt);
  assert.ok(resolveAt >= 0 && lockAt > resolveAt && mutateAt > lockAt);
  assert.match(source, /duplicate_occurrence_targets_collapsed/);
});

test('Hebbian collapses both batch targets and semantic neighbours before future activation', () => {
  const source = read('services/dream/hebbian-consensus.js');
  assert.ok((source.match(/resolvePrincipalStateMutationTargets\(\{/g) || []).length >= 3);
  assert.match(source, /uniquePrincipalStateNeighbors/);
  assert.match(source, /duplicate_occurrence_targets_collapsed/);
  assert.match(source, /if \(!on\) \{ stats\.enabled = false/);
});

test('migration 099 is append-only, v2-scoped, and does not authorize content-state mutation', () => {
  const source = read('migrations/099-occurrence-attributed-mutation-evidence.sql');
  assert.match(source, /target_scope IN \('occurrence_observation','principal_state'\)/);
  assert.match(source, /recall_event_id/);
  assert.match(source, /target_occurrence_ref/);
  assert.doesNotMatch(source, /target_scope IN \([^)]*content_state/);
  assert.doesNotMatch(source, /\b(?:UPDATE|DELETE)\s+(?:FROM\s+)?public\.aimos_memories\b/i);
});
