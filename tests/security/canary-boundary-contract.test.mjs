import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  CANARY_CLEAN_SELECTION_RETURN_PATHS,
  CANARY_CLEAN_SELECTION_CONTRACT,
  CANARY_CONTENT_CLASSIFICATION_CONTRACT,
  CANARY_FINAL_CLOSURE_CONTRACT,
  CANARY_MAGMA_COMPOSITION_CONTRACT,
  CANARY_RELAY_DECONTAMINATION_CONTRACT,
  CANARY_RELAY_STAGE_CONTRACT,
  buildCanaryCleanSelectionBoundary,
  buildCanaryMagmaGraphAdmission,
  buildCanaryKillChainDiagnostics,
  buildCanaryRelayDecontaminationEvidence,
  createCanaryContentClassificationMap,
  detectCanaries,
  finalizeCanaryCleanSelectionDecision,
  generateCanary,
  getDecontaminationRate,
  logCanaryEvent,
  observeCanariesAtRelayGate,
  recordCanariesRelayed,
  recordCanaryRelayBlocked,
  scanToolExecution,
  scanToolResult,
} from '../../services/security/canary-tracker.js';

const proof = Object.freeze({
  live_content_hash: 'a'.repeat(64),
  save_mutation_hash: 'b'.repeat(64),
  binding_mutation_hash: 'c'.repeat(64),
});

test('canaries use cryptographic bytes and preserve the published token format', () => {
  const tokens = new Set(Array.from({ length: 64 }, () => generateCanary()));
  assert.equal(tokens.size, 64);
  for (const token of tokens) assert.match(token, /^SECRET-[A-F0-9]{8}$/);
});

test('nested tool arguments and results are scanned without lossy object coercion', () => {
  assert.deepEqual(
    detectCanaries({ request: { authorization: 'SECRET-DEADBEEF' } }),
    ['SECRET-DEADBEEF'],
  );
  assert.deepEqual(
    detectCanaries({ repeated: ['SECRET-CAFEBABE', 'SECRET-CAFEBABE'] }),
    ['SECRET-CAFEBABE'],
  );
});

test('Canary grammar rejects malformed tokens that merely contain a valid prefix', () => {
  assert.deepEqual(detectCanaries('SECRET-DEADBEEF0'), []);
  assert.deepEqual(detectCanaries('XSECRET-DEADBEEF'), []);
  assert.deepEqual(detectCanaries('SECRET-DEADBEEF_suffix'), []);
  assert.deepEqual(detectCanaries('(SECRET-DEADBEEF).'), ['SECRET-DEADBEEF']);
});

test('relay decontamination is an exact-cohort unique-token set metric', () => {
  const events = [
    { canaryToken: 'SECRET-AAAABBBB', stage: 'EXPOSED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-AAAABBBB', stage: 'EXPOSED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-CCCCDDDD', stage: 'EXPOSED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-EEEEFFFF', stage: 'EXPOSED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-AAAABBBB', stage: 'RELAYED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-AAAABBBB', stage: 'RELAYED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-CCCCDDDD', stage: 'RELAY_BLOCKED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-EEEEFFFF', stage: 'RELAY_BLOCKED', runId: 'cohort-a' },
    { canaryToken: 'SECRET-11112222', stage: 'EXPOSED', runId: 'cohort-b' },
    { canaryToken: 'SECRET-11112222', stage: 'RELAYED', runId: 'cohort-b' },
  ];
  const evidence = buildCanaryRelayDecontaminationEvidence(events, {
    cohortId: 'cohort-a',
    issuedTokens: [
      'SECRET-AAAABBBB',
      'SECRET-CCCCDDDD',
      'SECRET-EEEEFFFF',
    ],
  });

  assert.equal(CANARY_RELAY_DECONTAMINATION_CONTRACT.zero_exposure_result, 'undefined');
  assert.equal(evidence.status, 'defined');
  assert.ok(Math.abs(evidence.value - (2 / 3)) < Number.EPSILON);
  assert.equal(evidence.unique_exposed_token_count, 3);
  assert.equal(evidence.relayed_from_exposed_unique_token_count, 1);
  assert.equal(evidence.decontaminated_unique_token_count, 2);
  assert.equal(evidence.duplicate_exposed_event_count, 1);
  assert.equal(evidence.duplicate_relayed_event_count, 1);
  assert.equal(evidence.issued_token_manifest_present, true);
  assert.equal(evidence.issued_token_count, 3);
  assert.equal(evidence.unissued_relevant_token_count, 0);
  assert.match(evidence.issued_token_set_commitment_sha256, /^[0-9a-f]{64}$/);
  assert.equal(evidence.token_values_disclosed, false);
  assert.doesNotMatch(JSON.stringify(evidence), /SECRET-/);
});

test('relay decontamination is explicitly undefined when no issued token was exposed', () => {
  const evidence = buildCanaryRelayDecontaminationEvidence([], {
    cohortId: 'empty-cohort',
    issuedTokens: ['SECRET-AAAABBBB'],
  });
  assert.equal(evidence.status, 'undefined');
  assert.equal(evidence.reason, 'no_exposed_tokens');
  assert.equal(evidence.value, null);
  assert.equal(evidence.unique_exposed_token_count, 0);
});

test('unfinished or inconsistent relay cohorts cannot manufacture a favorable rate', () => {
  const unfinished = buildCanaryRelayDecontaminationEvidence([
    { canaryToken: 'SECRET-AAAABBBB', stage: 'EXPOSED', runId: 'unfinished' },
  ], { cohortId: 'unfinished', issuedTokens: ['SECRET-AAAABBBB'] });
  assert.equal(unfinished.status, 'indeterminate');
  assert.equal(unfinished.reason, 'relay_outcomes_incomplete');
  assert.equal(unfinished.value, null);

  const orphan = buildCanaryRelayDecontaminationEvidence([
    { canaryToken: 'SECRET-AAAABBBB', stage: 'RELAYED', runId: 'orphan' },
  ], { cohortId: 'orphan', issuedTokens: ['SECRET-AAAABBBB'] });
  assert.equal(orphan.status, 'indeterminate');
  assert.equal(orphan.reason, 'terminal_event_without_exposure');
  assert.equal(orphan.value, null);

  const conflict = buildCanaryRelayDecontaminationEvidence([
    { canaryToken: 'SECRET-AAAABBBB', stage: 'EXPOSED', runId: 'conflict' },
    { canaryToken: 'SECRET-AAAABBBB', stage: 'RELAY_BLOCKED', runId: 'conflict' },
    { canaryToken: 'SECRET-AAAABBBB', stage: 'RELAYED', runId: 'conflict' },
  ], { cohortId: 'conflict', issuedTokens: ['SECRET-AAAABBBB'] });
  assert.equal(conflict.status, 'indeterminate');
  assert.equal(conflict.reason, 'conflicting_terminal_outcomes');
  assert.equal(conflict.value, null);
});

test('relay decontamination refuses ambiguous or absent runtime cohort authority', () => {
  const ambiguous = buildCanaryRelayDecontaminationEvidence([
    { canaryToken: 'SECRET-AAAABBBB', stage: 'EXPOSED', runId: 'one' },
    { canaryToken: 'SECRET-CCCCDDDD', stage: 'EXPOSED', runId: 'two' },
  ]);
  assert.equal(ambiguous.status, 'indeterminate');
  assert.equal(ambiguous.reason, 'cohort_ambiguous');
  assert.equal(ambiguous.value, null);
  assert.throws(() => getDecontaminationRate(), /canary_decontamination_cohort_required/);
});

test('valid-grammar but unissued markers are contained evidence, never favorable efficacy evidence', () => {
  const evidence = buildCanaryRelayDecontaminationEvidence([
    { canaryToken: 'SECRET-DEADBEEF', stage: 'EXPOSED', runId: 'forged' },
    { canaryToken: 'SECRET-DEADBEEF', stage: 'RELAY_BLOCKED', runId: 'forged' },
  ], {
    cohortId: 'forged',
    issuedTokens: ['SECRET-AAAABBBB'],
  });

  assert.equal(evidence.status, 'indeterminate');
  assert.equal(evidence.reason, 'unissued_marker_event');
  assert.equal(evidence.value, null);
  assert.equal(evidence.issued_token_count, 1);
  assert.equal(evidence.unissued_relevant_token_count, 1);
  assert.equal(evidence.unique_exposed_token_count, 0);
  assert.equal(evidence.decontaminated_unique_token_count, 0);
  assert.doesNotMatch(JSON.stringify(evidence), /SECRET-/);
});

test('relay efficacy is indeterminate when relevant events lack an issued-token manifest', () => {
  const evidence = buildCanaryRelayDecontaminationEvidence([
    { canaryToken: 'SECRET-AAAABBBB', stage: 'EXPOSED', runId: 'unbound' },
    { canaryToken: 'SECRET-AAAABBBB', stage: 'RELAY_BLOCKED', runId: 'unbound' },
  ], { cohortId: 'unbound' });

  assert.equal(evidence.status, 'indeterminate');
  assert.equal(evidence.reason, 'issued_token_manifest_required');
  assert.equal(evidence.value, null);
});

test('one request-local content-hash map scans equal content once and separates disposition', () => {
  const classificationMap = createCanaryContentClassificationMap();
  const clean = {
    id: '01010101-0101-4101-8101-010101010101',
    key: 'shared-content',
    value: 'Retained SECRET-DEADBEEF evidence.',
    scope: 'agent',
  };
  const quarantinedCopy = {
    ...clean,
    id: '02020202-0202-4202-8202-020202020202',
    scope: 'quarantine',
    memory_type: 'quarantine',
  };

  const first = classificationMap.classifyMemories([clean]);
  const second = classificationMap.classifyMemories([quarantinedCopy]);
  const snapshot = classificationMap.snapshot();

  assert.equal(CANARY_CONTENT_CLASSIFICATION_CONTRACT.key,
    'sha256(canonical_json({key,value}))');
  assert.equal(first.records[0].content_scan_sha256, second.records[0].content_scan_sha256);
  assert.equal(first.records[0].canary_marker_present, true);
  assert.equal(first.records[0].retained_quarantine_evidence, false);
  assert.equal(second.records[0].retained_quarantine_evidence, true);
  assert.equal(snapshot.unique_content_count, 1);
  assert.equal(snapshot.content_scans_executed, 1);
  assert.equal(snapshot.classification_requests, 2);
  assert.equal(snapshot.classification_cache_hits, 1);
  assert.equal(snapshot.content_rescans_executed, 0);
  assert.match(snapshot.classification_map_root_sha256, /^[0-9a-f]{64}$/);
});

test('Canary–MAGMA composition retains marked evidence while removing its graph vote', () => {
  const clean = {
    id: '11111111-1111-4111-8111-111111111111',
    key: 'clean',
    value: 'Clean retained evidence.',
    scope: 'agent',
    memory_type: 'session',
    retrieval_weight: 1,
    provenance_proof: proof,
  };
  const marked = {
    id: '22222222-2222-4222-8222-222222222222',
    key: 'marked',
    value: 'Retained marker SECRET-DEADBEEF.',
    scope: 'quarantine',
    memory_type: 'quarantine',
    retrieval_weight: 0.1,
    provenance_proof: proof,
  };
  const quarantined = {
    id: '33333333-3333-4333-8333-333333333333',
    key: 'semantic-poison-evidence',
    value: 'Retained evidence without an explicit marker.',
    scope: 'quarantine',
    memory_type: 'quarantine',
    retrieval_weight: 0.1,
    provenance_proof: proof,
  };

  const first = buildCanaryMagmaGraphAdmission([clean, marked, quarantined]);
  const second = buildCanaryMagmaGraphAdmission([clean, marked, quarantined]);

  assert.equal(CANARY_MAGMA_COMPOSITION_CONTRACT.graph_admission_equation, 'a_i=(1-c_i)(1-q_i)');
  assert.deepEqual(first, second);
  assert.deepEqual(first.graph_admitted_memories, [clean]);
  assert.deepEqual(first.retained_evidence_memories, [marked, quarantined]);
  assert.equal(first.decision.input_count, 3);
  assert.equal(first.decision.graph_admitted_count, 1);
  assert.equal(first.decision.retained_evidence_count, 2);
  assert.equal(first.decision.canary_marked_memory_count, 1);
  assert.equal(first.decision.canary_marker_count, 1);
  assert.equal(first.decision.quarantine_evidence_count, 2);
  assert.equal(first.decision.retained_baseline_preserved, true);
  assert.equal(first.decision.retention_changed, false);
  assert.doesNotMatch(JSON.stringify(first.decision), /SECRET-DEADBEEF/);
  assert.match(first.decision.decision_sha256, /^[0-9a-f]{64}$/);
});

test('Canary–MAGMA composition fails closed on missing or duplicate memory identity', () => {
  assert.throws(
    () => buildCanaryMagmaGraphAdmission([{ value: 'no identity' }]),
    /canary_content_classification_memory_id_invalid/,
  );
  assert.throws(
    () => buildCanaryMagmaGraphAdmission([
      { id: 'duplicate', value: 'first' },
      { id: 'duplicate', value: 'second' },
    ]),
    /canary_content_classification_duplicate_memory_id/,
  );
});

test('Canary–MAGMA production admission is request-bound and receipt-first', async () => {
  const source = await readFile(
    new URL('../../services/security/canary-tracker.js', import.meta.url),
    'utf8',
  );
  const governance = source.slice(source.indexOf('export async function governCanaryMagmaGraphAdmission'));
  const authorityGate = governance.indexOf('recallAuthority?.requestAuthority');
  const append = governance.indexOf('const receipt = await logEvent(');
  const release = governance.indexOf('return Object.freeze({', append);

  assert.ok(authorityGate >= 0);
  assert.ok(append > authorityGate, 'request authority must be validated before the ledger append');
  assert.ok(release > append, 'MAGMA admission cannot be released before the signed receipt returns');
  assert.match(governance, /canary_magma_graph_admission/);
  assert.match(governance, /requestAdmissionEventId \|\| null/);
  assert.match(governance, /authority: recallAuthority\.requestAuthority, returnReceipt: true/);
  assert.doesNotMatch(governance, /process\.env/);
});

test('clean-only top-k retains marked evidence separately and backfills every available slot', () => {
  const memory = (id, value, overrides = {}) => ({
    id,
    key: `memory-${id.slice(0, 4)}`,
    value,
    scope: 'agent',
    memory_type: 'session',
    retrieval_weight: 1,
    provenance_proof: { ...proof, live_content_hash: id.replaceAll('-', '').padEnd(64, 'a').slice(0, 64) },
    ...overrides,
  });
  const marked = memory(
    '11111111-1111-4111-8111-111111111111',
    'Retained marker SECRET-DEADBEEF.',
  );
  const cleanA = memory('22222222-2222-4222-8222-222222222222', 'Clean A.');
  const quarantined = memory(
    '33333333-3333-4333-8333-333333333333',
    'Retained classified evidence.',
    { scope: 'quarantine', memory_type: 'quarantine', retrieval_weight: 0.1 },
  );
  const cleanB = memory('44444444-4444-4444-8444-444444444444', 'Clean B.');
  const cleanC = memory('55555555-5555-4555-8555-555555555555', 'Clean C.');
  const cleanD = memory('66666666-6666-4666-8666-666666666666', 'Clean D.');

  const boundary = buildCanaryCleanSelectionBoundary(
    [marked, cleanA, quarantined, cleanB, cleanC, cleanD],
    4,
  );
  const decision = finalizeCanaryCleanSelectionDecision(
    boundary,
    [cleanA, cleanB, cleanC, cleanD],
  );

  assert.equal(CANARY_CLEAN_SELECTION_CONTRACT.selection_invariant,
    'selected_top_k_subseteq_clean_eligible_evidence');
  assert.deepEqual(boundary.clean_eligible_memories, [cleanA, cleanB, cleanC, cleanD]);
  assert.deepEqual(boundary.retained_evidence_memories, [marked, quarantined]);
  assert.equal(decision.requested_top_k, 4);
  assert.equal(decision.selected_clean_count, 4);
  assert.equal(decision.clean_backfill_count, 2);
  assert.equal(decision.unfilled_clean_slot_count, 0);
  assert.equal(decision.retained_evidence_count, 2);
  assert.deepEqual(decision.selected_clean_memory_ids, [
    cleanA.id,
    cleanB.id,
    cleanC.id,
    cleanD.id,
  ]);
  assert.equal(decision.selected_top_k_subseteq_clean_eligible_evidence, true);
  assert.equal(decision.return_path, 'conformance_fixture');
  assert.equal(decision.retained_evidence_canonical_state_unchanged, true);
  assert.equal(decision.clean_label_establishes_content_truth, false);
  assert.match(decision.retained_decision_set_sha256, /^[0-9a-f]{64}$/);
  assert.match(decision.decision_sha256, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(decision), /SECRET-DEADBEEF/);
});

test('R6 clean-only top-k withholds epistemic untrusted evidence and backfills clean states', () => {
  const memory = (id, evidenceHandling = 'ordinary_reference') => ({
    id,
    key: `memory-${id.slice(0, 4)}`,
    value: `Retained evidence ${id}`,
    scope: 'global',
    memory_type: 'fact',
    evidence_handling: evidenceHandling,
    provenance_proof: proof,
  });
  const untrustedA = memory(
    '11111111-1111-4111-8111-111111111111',
    'untrusted_reference_only',
  );
  const untrustedB = memory(
    '22222222-2222-4222-8222-222222222222',
    'untrusted_reference_only',
  );
  const cleanA = memory('33333333-3333-4333-8333-333333333333');
  const cleanB = memory('44444444-4444-4444-8444-444444444444');
  const boundary = buildCanaryCleanSelectionBoundary(
    [untrustedA, untrustedB, cleanA, cleanB],
    2,
  );
  const decision = finalizeCanaryCleanSelectionDecision(
    boundary,
    [cleanA, cleanB],
  );
  assert.equal(CANARY_CLEAN_SELECTION_CONTRACT.eligibility_equation,
    'e_i=(1-c_i)(1-q_i)(1-u_i)');
  assert.equal(boundary.boundary.retained_epistemic_evidence_count, 2);
  assert.equal(boundary.boundary.clean_backfill_count, 2);
  assert.equal(decision.selected_clean_count, 2);
  assert.equal(decision.retained_epistemic_evidence_count, 2);
  assert.deepEqual(decision.selected_clean_memory_ids, [cleanA.id, cleanB.id]);
  assert.equal(decision.retained_evidence_records.every(
    (record) => record.retained_reason === 'untrusted_epistemic_evidence',
  ), true);
});

test('clean-only top-k binds every runtime return path and rejects unknown paths', () => {
  assert.deepEqual(CANARY_CLEAN_SELECTION_RETURN_PATHS, [
    'identifier_exact',
    'post_compaction_handoff',
    'semantic_cache',
    'adaptive_early_exit',
    'normal_recall',
  ]);
  const clean = {
    id: '12121212-1212-4212-8212-121212121212',
    key: 'clean-return-path-fixture',
    value: 'Clean retained evidence.',
    scope: 'agent',
    memory_type: 'session',
    retrieval_weight: 1,
    provenance_proof: proof,
  };
  const boundary = buildCanaryCleanSelectionBoundary([clean], 1);
  for (const returnPath of CANARY_CLEAN_SELECTION_RETURN_PATHS) {
    const decision = finalizeCanaryCleanSelectionDecision(
      boundary,
      [clean],
      { returnPath },
    );
    assert.equal(decision.return_path, returnPath);
    assert.match(decision.decision_sha256, /^[0-9a-f]{64}$/);
  }
  assert.throws(
    () => finalizeCanaryCleanSelectionDecision(
      boundary,
      [clean],
      { returnPath: 'unbound_return' },
    ),
    /canary_clean_selection_return_path_invalid/,
  );
});

test('native recall binds clean selection to every return path and does not replay stale cache output', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const selectorDefinition = source.indexOf('async function selectAndLedgerEpistemicRecall');
  const runtime = source.slice(source.indexOf('export async function executeNativeRecall'));
  const calls = [...runtime.matchAll(/selectAndLedgerEpistemicRecall\(\{/g)];
  const closures = [...runtime.matchAll(/governCanaryRecallFinalClosure\(\{/g)];

  assert.ok(selectorDefinition >= 0);
  assert.equal(calls.length, 5, 'every native return-path class must use the shared selector exactly once');
  assert.equal(closures.length, 5, 'every native return-path class must emit one final closure');
  assert.equal((runtime.match(/createCanaryContentClassificationMap\(\)/g) || []).length, 1,
    'one classifier map must be created for the request');
  for (const returnPath of CANARY_CLEAN_SELECTION_RETURN_PATHS) {
    const matches = runtime.match(new RegExp(`returnPath: '${returnPath}'`, 'g')) || [];
    assert.equal(matches.length, 3,
      `${returnPath} must bind selection, final closure, and final response projection exactly once each`);
  }

  const selector = source.slice(
    selectorDefinition,
    source.indexOf('\nfunction verifiedTwinPrimePolicy', selectorDefinition),
  );
  assert.match(selector, /buildCanaryCleanSelectionBoundary\([\s\S]*?sourceMemories,[\s\S]*?limit,[\s\S]*?classificationMap: canaryClassificationMap/);
  assert.match(selector, /native_recall_canary_clean_selection_population_mismatch/);
  assert.match(selector, /const selectionMemories = initialCanaryBoundary\.clean_eligible_memories/);
  assert.match(selector, /const combinedSelectionBoundary = buildCanaryCleanSelectionBoundary/);
  assert.match(selector, /evidence_handling: decision\.evidence_handling/);
  assert.match(selector, /parentEventId: evidenceScope\.receipt\.event_id/);
  assert.match(selector, /await governCanaryCleanTopKSelection\(\{/);
  assert.match(selector, /returnPath,/);

  const cacheStart = runtime.indexOf('// ─── SPEED OPT: Check semantic cache');
  const cacheEnd = runtime.indexOf('// ─── FELIX:', cacheStart);
  const cachePath = runtime.slice(cacheStart, cacheEnd);
  assert.match(cachePath, /returnPath: 'semantic_cache'/);
  assert.match(cachePath, /stale_selection_derived_content_reused: false/);
  assert.match(cachePath, /hydrateSemanticCacheStateReferences\(\{/);
  assert.match(cachePath, /contentStateOccurrenceAdmission\.selectCandidateStateRepresentatives/);
  assert.match(cachePath, /working_memory: cachedFinalClosure\.memories/);
  assert.doesNotMatch(cachePath, /cached\.memories/);
  assert.doesNotMatch(cachePath, /\.\.\.cached[,\n]/);
  assert.doesNotMatch(cachePath, /\.\.\.\(cached\.recall_meta/);

  const earlyStart = runtime.indexOf('// ─── SPEED OPT: Adaptive early-exit');
  const earlyEnd = runtime.indexOf("returnPath: 'adaptive_early_exit'", earlyStart) + 80;
  const earlyPath = runtime.slice(earlyStart, earlyEnd);
  assert.match(earlyPath, /buildCanaryCleanSelectionBoundary\(\s*earlyCandidateMemories,/);
  assert.match(earlyPath, /const earlySelectionMemories = earlyCanaryCleanSelectionBoundary\.clean_eligible_memories/);
  assert.match(earlyPath, /const earlyEpistemic = await selectAndLedgerEpistemicRecall\(\{\s*\/\/[\s\S]*?memories: earlyCandidateMemories,/);
  assert.match(earlyPath, /canaryCleanSelectionBoundary: earlyCanaryCleanSelectionBoundary/);
});

test('final closure contract is one receipt with an independently recomputable map', async () => {
  const source = await readFile(
    new URL('../../services/security/canary-tracker.js', import.meta.url),
    'utf8',
  );
  const begin = source.indexOf('export async function governCanaryRecallFinalClosure');
  const end = source.indexOf('/**', begin + 10);
  const owner = source.slice(begin, end);

  assert.equal(CANARY_FINAL_CLOSURE_CONTRACT.receipt_count_per_return, 1);
  assert.match(owner, /classification_map: classificationSnapshot/);
  assert.match(owner, /classification_map_independently_recomputable: true/);
  assert.match(owner, /content_rescans_executed: 0/);
  assert.match(owner, /'canary_recall_final_closure'/);
  assert.match(owner, /epistemicReceipt\?\.event_id \|\| null/);
  assert.match(owner, /final_closure_receipt_count: 1/);
  assert.doesNotMatch(owner, /scanRelayedMemory|process\.env/);
});

test('clean-only top-k fails closed on slot loss or an ineligible selected identity', () => {
  const clean = {
    id: '77777777-7777-4777-8777-777777777777',
    key: 'clean',
    value: 'Clean retained evidence.',
    scope: 'agent',
    memory_type: 'session',
    retrieval_weight: 1,
    provenance_proof: proof,
  };
  const marked = {
    id: '88888888-8888-4888-8888-888888888888',
    key: 'marked',
    value: 'Retained SECRET-CAFEBABE evidence.',
    scope: 'agent',
    memory_type: 'session',
    retrieval_weight: 1,
    provenance_proof: proof,
  };
  const boundary = buildCanaryCleanSelectionBoundary([marked, clean], 1);
  assert.throws(
    () => finalizeCanaryCleanSelectionDecision(boundary, [marked]),
    /canary_clean_selection_ineligible_memory_selected/,
  );
  assert.throws(
    () => finalizeCanaryCleanSelectionDecision(boundary, []),
    /canary_clean_selection_selected_count_invalid/,
  );
});

test('clean-only top-k reports unavoidable unfilled slots without discarding retained evidence', () => {
  const clean = {
    id: '99999999-9999-4999-8999-999999999999',
    key: 'clean',
    value: 'Only eligible evidence.',
    scope: 'agent',
    memory_type: 'session',
    retrieval_weight: 1,
    provenance_proof: proof,
  };
  const marked = {
    id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    key: 'marked',
    value: 'Retained SECRET-ABCD1234 evidence.',
    scope: 'agent',
    memory_type: 'session',
    retrieval_weight: 1,
    provenance_proof: proof,
  };
  const boundary = buildCanaryCleanSelectionBoundary([marked, clean], 3);
  const decision = finalizeCanaryCleanSelectionDecision(boundary, [clean]);

  assert.equal(decision.selected_clean_count, 1);
  assert.equal(decision.unfilled_clean_slot_count, 2);
  assert.equal(decision.retained_evidence_count, 1);
  assert.equal(decision.retained_evidence_canonical_state_unchanged, true);
});

test('clean-only top-k decision is request-bound, appended, and awaited before release', async () => {
  const source = await readFile(
    new URL('../../services/security/canary-tracker.js', import.meta.url),
    'utf8',
  );
  const begin = source.indexOf('export async function governCanaryCleanTopKSelection');
  const governance = source.slice(begin, source.indexOf('/**', begin + 10));
  const authorityGate = governance.indexOf('recallAuthority?.requestAuthority');
  const append = governance.indexOf('const receipt = await logEvent(');
  const release = governance.indexOf('return Object.freeze({', append);

  assert.ok(begin >= 0);
  assert.ok(authorityGate >= 0);
  assert.ok(append > authorityGate);
  assert.ok(release > append);
  assert.match(governance, /canary_clean_selection_decision/);
  assert.match(governance, /requestAdmissionEventId \|\| null/);
  assert.match(governance, /authority: recallAuthority\.requestAuthority, returnReceipt: true/);
  assert.doesNotMatch(governance, /process\.env/);
});

test('clean boundary scans are side-effect free', async () => {
  const execution = await scanToolExecution('web_search', { query: 'weather' }, 'clean-run');
  const exposure = await scanToolResult('web_search', { answer: 'sunny' }, 'clean-run');
  const relay = await observeCanariesAtRelayGate('A clean retained memory.', 'clean-run');
  const blocked = await recordCanaryRelayBlocked(relay);
  const relayed = await recordCanariesRelayed(relay, { modelInvocationCompleted: true });

  assert.equal(execution.blocked, false);
  assert.deepEqual(execution.events, []);
  assert.deepEqual(exposure.events, []);
  assert.deepEqual(relay.events, []);
  assert.deepEqual(blocked.events, []);
  assert.deepEqual(relayed.events, []);
});

test('relay stage contract distinguishes observation, containment, and actual delivery', () => {
  assert.equal(
    CANARY_RELAY_STAGE_CONTRACT.transition_equation,
    'OBSERVED_AT_RELAY_GATE -> exactly_one_of(RELAY_BLOCKED,RELAYED)',
  );
  assert.equal(CANARY_RELAY_STAGE_CONTRACT.blocked_and_relayed_mutually_exclusive, true);
  assert.equal(CANARY_RELAY_STAGE_CONTRACT.relayed_requires_completed_model_invocation, true);
  const blocked = buildCanaryKillChainDiagnostics([
    { stage: 'OBSERVED_AT_RELAY_GATE' },
    { stage: 'RELAY_BLOCKED' },
  ]);
  assert.equal(blocked.relay_state, 'RELAY_BLOCKED');
  assert.equal(blocked.stage_counts.RELAYED, 0);
  assert.equal(blocked.deepest_stage, 'NONE');
  const delivered = buildCanaryKillChainDiagnostics([
    { stage: 'OBSERVED_AT_RELAY_GATE' },
    { stage: 'RELAYED' },
  ]);
  assert.equal(delivered.relay_state, 'RELAYED');
  assert.equal(delivered.stage_counts.RELAYED, 1);
  assert.equal(delivered.deepest_stage, 'RELAYED');
});

test('relay terminal owner enforces a single branch and request-local diagnostics', async () => {
  const source = await readFile(
    new URL('../../services/security/canary-tracker.js', import.meta.url),
    'utf8',
  );
  const closeStart = source.indexOf('async function closeCanaryRelayTransition');
  const closeEnd = source.indexOf('export async function recordCanaryRelayBlocked', closeStart);
  const owner = source.slice(closeStart, closeEnd);
  assert.match(owner, /_relayTerminalStates\.get\(observation\)/);
  assert.match(owner, /canary_relay_terminal_already_recorded/);
  assert.match(owner, /_relayTerminalStates\.set\(observation, stage\)/);
  assert.match(owner, /INDETERMINATE_/);
  assert.match(owner, /buildCanaryKillChainDiagnostics\(\s*\[\.\.\.observation\.events, \.\.\.events\],\s*\{ cohortId: observation\.runId \}/);
  assert.doesNotMatch(owner, /process\.env/);
});

test('EXECUTED diagnostics distinguish blocked dispatch from an invoked tool', () => {
  const diagnostics = buildCanaryKillChainDiagnostics([
    { stage: 'EXECUTED', dispatchBlocked: true, toolInvoked: false },
    { stage: 'EXECUTED', dispatchBlocked: false, toolInvoked: true },
  ]);

  assert.equal(diagnostics.stage_counts.EXECUTED, 2);
  assert.equal(diagnostics.blocked_tool_dispatches, 1);
  assert.equal(diagnostics.executed_tool_invocations, 1);
});

test('invalid kill-chain stages are rejected before ledger access', async () => {
  await assert.rejects(
    logCanaryEvent('SECRET-DEADBEEF', 'OUTPUT', 'model_response', 'run'),
    /invalid_canary_stage:OUTPUT/,
  );
});

test('low-level relay events cannot bypass the observation and delivery contract', async () => {
  await assert.rejects(
    logCanaryEvent('SECRET-DEADBEEF', 'RELAYED', 'relay_delivered:a->b', 'run'),
    /canary_relay_attempt_sha256_required:RELAYED/,
  );
  await assert.rejects(
    logCanaryEvent('SECRET-DEADBEEF', 'RELAY_BLOCKED', 'relay_blocked:a->b', 'run', {
      relayAttemptSha256: 'a'.repeat(64),
    }),
    /canary_relay_observation_parent_required:RELAY_BLOCKED/,
  );
  await assert.rejects(
    logCanaryEvent('SECRET-DEADBEEF', 'RELAYED', 'relay_delivered:a->b', 'run', {
      relayAttemptSha256: 'a'.repeat(64),
      relayObservationEventId: 'event-1',
      parentEventId: 'event-1',
      modelInvocationCompleted: false,
    }),
    /canary_relayed_requires_completed_model_invocation/,
  );
});

test('tool execution and result scans occupy the native signed action boundary', async () => {
  const source = await readFile(
    new URL('../../services/orchestration/tool-registry.js', import.meta.url),
    'utf8',
  );
  const begin = source.indexOf('signedToolAction = await beginToolAction(');
  const outboundScan = source.indexOf('await scanToolExecution(', begin);
  const invoke = source.indexOf('await runWithTimeout(', begin);
  const resultScan = source.indexOf('await scanToolResult(', invoke);
  const terminal = source.indexOf('await finishToolAction({', resultScan);

  assert.ok(begin >= 0);
  assert.ok(outboundScan > begin, 'arguments must be scanned after a signed action exists');
  assert.ok(invoke > outboundScan, 'arguments must be scanned before tool dispatch');
  assert.ok(resultScan > invoke, 'tool results can only be scanned after invocation');
  assert.ok(terminal > resultScan, 'terminal action proof follows result-boundary evidence');
});

test('read-only tool intent is evaluated as read authority before Canary dispatch', async () => {
  const source = await readFile(
    new URL('../../services/orchestration/tool-registry.js', import.meta.url),
    'utf8',
  );
  assert.match(
    source,
    /const policyVerb = toolDirection === TOOL_DIRECTIONS\.READ \? 'GET' : 'POST'/,
  );
  assert.match(source, /enforceVerbPolicy\(intentClass\.scope, policyVerb\)/);
  assert.doesNotMatch(source, /enforceVerbPolicy\(intentClass\.scope, 'POST'\)/);
});

test('non-operator local reads require an exact master-signed purpose proof before tool action', async () => {
  const [registry, actionLedger] = await Promise.all([
    readFile(new URL('../../services/orchestration/tool-registry.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/orchestration/tool-action-ledger.js', import.meta.url), 'utf8'),
  ]);
  const purposeGate = registry.indexOf("if (name === 'read_file' && !isOperatorAgentId(agentId))");
  const actionStart = registry.indexOf('signedToolAction = await beginToolAction(');
  const invocation = registry.indexOf('const invokeTool = () =>', actionStart);
  assert.ok(purposeGate >= 0 && purposeGate < actionStart);
  assert.ok(actionStart < invocation);
  assert.match(registry, /master_signed_local_file_read_authorization_required/);
  assert.match(registry, /purpose_authorization_protocol_commitment_required/);
  assert.match(registry, /authorizePurposeLocalFileRead/);
  assert.match(actionLedger, /purpose_authorization_sha256/);
  assert.match(actionLedger, /purposeAuthorizationSha256/);
});

test('relay observation precedes prompt construction and RELAYED follows completed model invocation', async () => {
  const source = await readFile(
    new URL('../../services/orchestration/agent-runner.js', import.meta.url),
    'utf8',
  );
  const load = source.indexOf('const aimosContextPack =');
  const observation = source.indexOf('await observeCanariesAtRelayGate(', load);
  const blocked = source.indexOf('await recordCanaryRelayBlocked(', observation);
  const prompt = source.indexOf('buildSystemPrompt(', observation);
  const invoke = source.indexOf('const result = await runAgentWithFallback(', prompt);
  const relayed = source.indexOf('await recordCanariesRelayed(', invoke);

  assert.ok(load >= 0);
  assert.ok(observation > load, 'relay observation must follow native memory retrieval');
  assert.ok(blocked > observation && blocked < prompt,
    'a detected marker must be signed as blocked before prompt construction');
  assert.ok(prompt > observation, 'relay observation must precede model prompt construction');
  assert.ok(invoke > prompt, 'model invocation must follow prompt construction');
  assert.ok(relayed > invoke, 'RELAYED can only be recorded after model invocation completes');
  assert.doesNotMatch(source, /scanAssembledPrompt/);
  assert.doesNotMatch(source, /scanRelayedMemory/);
  assert.match(source, /options\.executionContext\?\.requestAdmissionEventId/);
});

test('native recall evidence retains a continuous signed request ancestry', async () => {
  const [route, recall] = await Promise.all([
    readFile(new URL('../../routes/aimos.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url), 'utf8'),
  ]);
  assert.match(route, /requestAdmissionEventId: req\.executionContext\?\.requestAdmissionEventId \|\| null/);
  assert.match(recall, /parentEventId: recallAuthority\.requestAuthority\?\.requestAdmissionEventId \|\| null/);
  assert.match(recall, /requestAuthority: recallAuthority\.requestAuthority \|\| null/);
});
