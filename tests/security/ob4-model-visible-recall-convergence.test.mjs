import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildNativeRecallOriginDisclosure,
  nativeRecallDisclosureLabelRoot,
  verifyNativeRecallOriginDisclosure,
} from '../../services/retrieval/native-recall.js';
import { loadRecentAimosContext } from '../../services/orchestration/agent-prompts.js';

const HASH_A = '11'.repeat(32);
const HASH_B = '22'.repeat(32);
const HASH_C = '33'.repeat(32);
const EVENT_A = '11111111-1111-4111-8111-111111111111';
const MEMORY_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function memory() {
  return {
    id: MEMORY_A,
    data_class: 'internal',
    provenance_proof: { live_content_hash: HASH_A },
  };
}

test('legacy-unbound recall labels remain restricted, untrusted, and non-actionable', () => {
  const label = buildNativeRecallOriginDisclosure(memory(), []);
  assert.equal(label.legacy_unbound, true);
  assert.equal(label.unclassified, true);
  assert.deepEqual(label.family_ids, ['unknown_protected']);
  assert.equal(label.confidentiality, 'restricted');
  assert.equal(label.integrity, 'untrusted');
  assert.equal(label.effective_action_class, 'none');
  assert.match(label.family_set_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(label.disclosure_label_sha256, /^[0-9a-f]{64}$/);
});

test('bound recall labels join confidentiality and meet integrity/action authority', () => {
  const label = buildNativeRecallOriginDisclosure(memory(), [{
    binding_sha256: HASH_B,
    ledger_hash: HASH_C,
    classification_event_id: EVENT_A,
    classification_event_mutation_sha256: HASH_A,
    family_ids: ['information', 'information.fact'],
    confidentiality: 'confidential',
    integrity: 'agent',
    action_class: 'inform',
  }, {
    binding_sha256: HASH_C,
    ledger_hash: HASH_B,
    classification_event_id: EVENT_A,
    classification_event_mutation_sha256: HASH_B,
    family_ids: ['derived', 'derived.tool_result'],
    confidentiality: 'restricted',
    integrity: 'untrusted',
    action_class: 'none',
  }]);
  assert.equal(label.legacy_unbound, false);
  assert.equal(label.unclassified, false);
  assert.equal(label.confidentiality, 'restricted');
  assert.equal(label.integrity, 'untrusted');
  assert.equal(label.effective_action_class, 'none');
  assert.deepEqual(label.origin_binding_sha256s, [HASH_B, HASH_C]);
  assert.deepEqual(label.origin_event_ids, [EVENT_A]);
  assert.equal(nativeRecallDisclosureLabelRoot([label]).length, 64);
  assert.equal(verifyNativeRecallOriginDisclosure(label), true);
  assert.throws(
    () => nativeRecallDisclosureLabelRoot([{ ...label, effective_action_class: 'act' }]),
    /recall_origin_disclosure_hash_invalid/,
  );
});

test('model context rejects a substituted disclosure-label root instead of degrading to empty', async () => {
  const label = buildNativeRecallOriginDisclosure(memory(), []);
  const recalledMemory = {
    ...memory(),
    key: 'ob4:test',
    value: 'retained value',
    agent_id: 'codex-auditor',
    memory_type: 'declarative',
    origin_disclosure: label,
  };
  await assert.rejects(
    loadRecentAimosContext('codex-auditor', 'codex-auditor', 1, {
      memories: [recalledMemory],
      recall_receipt: {
        evidence: [{ ordinal: 0, memory_id: MEMORY_A, origin_disclosure: label }],
        disclosure_labels: [label],
        disclosure_label_root_sha256: HASH_B,
      },
    }),
    /canonical_model_context_receipt_invalid/,
  );
});

test('model prompt memory bytes have no direct table-read fallback', () => {
  const prompts = readFileSync(new URL('../../services/orchestration/agent-prompts.js', import.meta.url), 'utf8');
  const runner = readFileSync(new URL('../../services/orchestration/agent-runner.js', import.meta.url), 'utf8');
  const inbox = readFileSync(new URL('../../routes/agent-learning.js', import.meta.url), 'utf8');
  const meta = readFileSync(new URL('../../services/orchestration/meta-controller.js', import.meta.url), 'utf8');
  const calibration = readFileSync(new URL('../../services/orchestration/agent-confidence-calibration.js', import.meta.url), 'utf8');
  const reasoningTrace = readFileSync(new URL('../../services/orchestration/reasoning-trace-check.js', import.meta.url), 'utf8');
  const investigation = readFileSync(new URL('../../services/orchestration/explore-exploit-loop.js', import.meta.url), 'utf8');
  const skillConsolidation = readFileSync(new URL('../../services/learning/skill-consolidation.js', import.meta.url), 'utf8');
  const dreamFeedback = readFileSync(new URL('../../services/dream/dream-feedback.js', import.meta.url), 'utf8');
  assert.doesNotMatch(prompts, /FROM\s+aimos_memories/i);
  for (const source of [meta, calibration, reasoningTrace, investigation]) {
    assert.doesNotMatch(source, /`[^`]*FROM\s+aimos_memories[^`]*`/is);
  }
  assert.match(runner, /executeTool\('aimos_recall'/);
  assert.match(runner, /canonical_pre_model_recall_failed/);
  assert.match(runner, /canonical_model_context_recall_failed/);
  assert.match(runner, /canonical_investigation_history_recall_failed/);
  assert.match(runner, /canonical_f7_protocol_recall_failed/);
  assert.match(meta, /canonical_meta_recall_required/);
  assert.match(reasoningTrace, /canonicalMemories/);
  const abstractionBody = skillConsolidation.slice(
    skillConsolidation.indexOf('export async function extractAbstraction'),
    skillConsolidation.indexOf('export async function detectSkillContradictions'),
  );
  const contradictionBody = skillConsolidation.slice(
    skillConsolidation.indexOf('export async function detectSkillContradictions'),
    skillConsolidation.indexOf('export async function promoteProvisionalSkill'),
  );
  for (const source of [abstractionBody, contradictionBody, dreamFeedback]) {
    assert.doesNotMatch(source, /`[^`]*FROM\s+aimos_memories[^`]*`/is);
  }
  assert.match(abstractionBody, /canonical_skill_recall_incomplete/);
  assert.match(inbox, /executeTool\('aimos_recall'/);
});
