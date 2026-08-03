import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isNativeRecallCandidateWithinCommand,
  isNativeRecallProofAllowed,
  normalizeNativeRecallCommand,
} from '../../services/retrieval/native-recall.js';

const authority = {
  companyId: 'hom',
  actorAgentId: 'codex-auditor',
  clearanceCeiling: 12,
  dataClassCeiling: 'restricted',
};

function proof(overrides = {}) {
  return {
    company_id: 'hom',
    subject_agent_id: 'codex-auditor',
    scope: 'global',
    cube_scope: 'shared',
    memory_type: 'declarative',
    clearance_level: 1,
    data_class: 'public',
    version_status: 'current',
    ...overrides,
  };
}

test('retained historical and quarantine evidence remains recall-eligible', () => {
  assert.equal(isNativeRecallProofAllowed(proof({ version_status: 'historical' }), authority), true);
  assert.equal(isNativeRecallProofAllowed(proof({ scope: 'quarantine', memory_type: 'quarantine' }), authority), true);
});

test('retention never weakens tenant, ownership, or clearance boundaries', () => {
  assert.equal(isNativeRecallProofAllowed(proof({ company_id: 'other' }), authority), false);
  assert.equal(isNativeRecallProofAllowed(proof({ clearance_level: 13 }), authority), false);
  assert.equal(isNativeRecallProofAllowed(proof({ cube_scope: 'private', subject_agent_id: 'other' }), authority), false);
});

test('signed source, type, and session filters are enforced at native evidence admission', () => {
  const scopedAuthority = {
    ...authority,
    command: {
      source_filter: 'benchmark:poisonedrag',
      memory_type_filter: 'benchmark_context',
      session_id: 'clean_arm_0',
    },
  };
  const scopedProof = proof({
    key: 'sess:clean_arm_0:reference:001:doc-1',
    source: 'benchmark:poisonedrag',
    memory_type: 'benchmark_context',
  });

  assert.equal(isNativeRecallCandidateWithinCommand(scopedProof, scopedAuthority.command), true);
  assert.equal(isNativeRecallProofAllowed(scopedProof, scopedAuthority), true);
  assert.equal(isNativeRecallProofAllowed({
    ...scopedProof,
    key: 'sess:attacked_arm_1:reference:001:doc-1',
  }, scopedAuthority), false);
  assert.equal(isNativeRecallProofAllowed({ ...scopedProof, source: 'other' }, scopedAuthority), false);
  assert.equal(isNativeRecallProofAllowed({ ...scopedProof, memory_type: 'other' }, scopedAuthority), false);
});

test('session command matching is literal for wildcard characters', () => {
  const command = { session_id: 'arm_%_literal' };
  assert.equal(isNativeRecallCandidateWithinCommand({
    key: 'sess:arm_%_literal:reference:001',
  }, command), true);
  assert.equal(isNativeRecallCandidateWithinCommand({
    key: 'sess:arm_X_literal:reference:001',
  }, command), false);
});

test('session admission preserves native compaction keys through signed session evidence', () => {
  const command = { session_id: 'session-42' };
  assert.equal(isNativeRecallCandidateWithinCommand({
    key: 'post-compaction-summary:project:session-42:20260720',
    session_id: 'session-42',
  }, command), true);
  assert.equal(isNativeRecallCandidateWithinCommand({
    key: 'post-compaction-summary:project:session-42:20260720',
    session_id: 'different-session',
  }, command), false);
});

test('include_history suppression switch is retired', () => {
  assert.throws(
    () => normalizeNativeRecallCommand({ query: 'history', include_history: false }),
    /recall_unknown_field:include_history/,
  );
});
