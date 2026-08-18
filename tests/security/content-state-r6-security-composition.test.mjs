import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  verifyR6EvidenceScopeDecision,
  verifyR6SecurityComposition,
} from '../../eval/mutmem-v2/content-state-r6-security-composition.mjs';

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function hash(value) {
  return createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

function decision(body) {
  return { ...body, decision_sha256: hash(body) };
}

test('R6 independent verifier reconstructs scope, clean selection, and final closure', () => {
  const blockedRecords = [{
    memory_id: '11111111-1111-4111-8111-111111111111',
    projection_rank_eligible: false,
    evidence_root_sha256: 'e'.repeat(64),
  }];
  const records = [...blockedRecords];
  const scope = decision({
    schema: 'hom-aimos/request-epistemic-evidence-scope/v1',
    content_state_projection_decision_sha256: 'a'.repeat(64),
    state_view_root_sha256: 'b'.repeat(64),
    occurrence_view_root_sha256: 'c'.repeat(64),
    authorized_class_commitment_sha256: 'b'.repeat(64),
    records,
    records_root_sha256: hash(records),
    blocked_records: blockedRecords,
    retained_blocked_decision_set_sha256: hash(blockedRecords),
    evidence_root_sha256s: ['e'.repeat(64)],
    no_exoneration: true,
    label_history_changed: false,
    canonical_memory_mutated: false,
    retention_changed: false,
  });
  const clean = decision({
    schema: 'hom-aimos/canary-clean-selection/v2-epistemic-withholding',
    selected_clean_memory_ids: ['22222222-2222-4222-8222-222222222222'],
    selected_top_k_subseteq_clean_eligible_evidence: true,
    retained_evidence_canonical_state_unchanged: true,
  });
  const epistemic = decision({ version: 'aimos-epistemic-retrieval-v2' });
  const closure = decision({
    schema: 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope',
    content_state_evidence_scope_decision_sha256: scope.decision_sha256,
    authorized_class_commitment_sha256: scope.authorized_class_commitment_sha256,
    retained_blocked_decision_set_sha256: scope.retained_blocked_decision_set_sha256,
    clean_selection_decision_sha256: clean.decision_sha256,
    epistemic_decision_sha256: epistemic.decision_sha256,
    no_epistemic_exoneration: true,
    canonical_memory_mutated: false,
    retention_changed: false,
  });
  assert.equal(verifyR6EvidenceScopeDecision(scope).valid, true);
  assert.equal(verifyR6SecurityComposition({
    evidenceScopeDecision: scope,
    cleanSelectionDecision: clean,
    epistemicDecision: epistemic,
    finalClosureDecision: closure,
  }).valid, true);

  const tampered = structuredClone(scope);
  tampered.blocked_records[0].memory_id = '33333333-3333-4333-8333-333333333333';
  assert.throws(() => verifyR6EvidenceScopeDecision(tampered), /scope_decision_hash_invalid/);
});

test('R6 source binds scope and closure on every native return path', async () => {
  const [pipeline, tracker] = await Promise.all([
    readFile(new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/security/canary-tracker.js', import.meta.url), 'utf8'),
  ]);
  const runtime = pipeline.slice(pipeline.indexOf('export async function executeNativeRecall'));
  assert.equal((runtime.match(/contentStateEvidenceScopeDecision:/g) || []).length, 5);
  assert.equal((runtime.match(/contentStateEvidenceScope:/g) || []).length, 5);
  assert.equal((runtime.match(/contentStateOccurrenceAdmission\.finalizeEvidenceScope\(\)/g) || []).length, 5);
  assert.match(pipeline, /content_state_epistemic_scope_decision/);
  assert.match(pipeline, /parentEventId: evidenceScope\.receipt\.event_id/);
  assert.match(tracker, /authorized_class_commitment_sha256/);
  assert.match(tracker, /retained_blocked_decision_set_sha256/);
  assert.match(tracker, /no_epistemic_exoneration/);
  assert.match(tracker, /hom-aimos\/canary-clean-selection\/v2-epistemic-withholding/);
  assert.match(tracker, /hom-aimos\/canary-recall-final-closure\/v2-epistemic-scope/);
});

test('R6 REST, MCP, v1, and native tool recall converge on executeNativeRecall', async () => {
  const [rest, mcp, v1, tool] = await Promise.all([
    readFile(new URL('../../routes/aimos.js', import.meta.url), 'utf8'),
    readFile(new URL('../../routes/aimos-mcp-streamable.js', import.meta.url), 'utf8'),
    readFile(new URL('../../routes/v1-api.js', import.meta.url), 'utf8'),
    readFile(new URL('../../tests/security/native-tool-action-db.test.mjs', import.meta.url), 'utf8'),
  ]);
  assert.match(rest, /executeNativeRecall\(req, recallAuthority\)/);
  assert.match(mcp, /executeNativeRecall\(authContext\.request, recallAuthority\)/);
  assert.match(v1, /executeNativeRecall\(req, recallAuthority\)/);
  assert.match(tool, /executeNativeRecall\(/);
});
