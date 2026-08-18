import assert from 'node:assert/strict';
import test from 'node:test';

import {
  NATIVE_RETRIEVAL_FUSION_CONTRACT,
  deriveNativeRetrievalGearEvidence,
  fuseNativeRetrievalGears,
} from '../../services/retrieval/native-retrieval-fusion.js';
import {
  canonicalizeLiveContentState,
  projectContentStateOccurrenceViews,
} from '../../services/retrieval/content-state-occurrence/kernel.js';

const proof = Object.freeze({ version_status: 'current' });
const memory = (id, fields = {}) => ({ id, provenance_proof: proof, ...fields });

test('central native RRF treats the graph family as one peer gear and preserves every admitted baseline', () => {
  const baseline = [
    memory('a', { raw_distance: 0.1, bm25_rank: 0.1, rerank_score: 0.4 }),
    memory('b', { raw_distance: 0.4, bm25_rank: 0.9, rerank_score: 0.8 }),
    memory('c', { raw_distance: 0.2, ppr_score: 0.8, created_at: '2026-01-02T00:00:00Z' }),
  ];
  const graphFamily = {
    ranks: [
      { id: 'd', rank: 1, score: 9 },
      { id: 'c', rank: 2, score: 8 },
      { id: 'a', rank: 3, score: 7 },
    ],
    discovered_memories: [memory('d', { graph_family_score: 9 })],
  };

  const first = fuseNativeRetrievalGears({
    admittedMemories: baseline,
    graphFamilyGear: graphFamily,
    temporalBias: true,
  });
  const second = fuseNativeRetrievalGears({
    admittedMemories: baseline,
    graphFamilyGear: graphFamily,
    temporalBias: true,
  });

  assert.deepEqual(first, second);
  assert.deepEqual(new Set(first.memories.map((row) => row.id)), new Set(['a', 'b', 'c', 'd']));
  assert.equal(first.decision.baseline_candidate_set_preserved, true);
  assert.equal(first.decision.candidate_set_monotone, true);
  assert.equal(first.decision.graph_family_discovery_count, 1);
  assert.equal(first.decision.channels.some((channel) => channel.gear === 'graph_family'), true);
  assert.equal(first.decision.channels.some((channel) => channel.gear === 'temporal'), true);
  assert.equal(first.memories.every((row) => row.provenance_proof === proof), true);
  assert.match(first.decision.decision_sha256, /^[0-9a-f]{64}$/);
});

test('central native RRF rejects unadmitted graph-family discoveries and has no activation state', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('graph_family'), true);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('magma'), false);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('temporal'), true);
  assert.equal(Object.hasOwn(NATIVE_RETRIEVAL_FUSION_CONTRACT, 'execution'), false);
  assert.throws(
    () => fuseNativeRetrievalGears({
      admittedMemories: [memory('a', { raw_distance: 0.1 })],
      graphFamilyGear: {
        ranks: [{ id: 'b', rank: 1, score: 1 }],
        discovered_memories: [{ id: 'b' }],
      },
    }),
    /native_retrieval_fusion:unadmitted_graph_family_discovery/,
  );
});

test('central native RRF closes an empty admitted population deterministically', () => {
  const result = fuseNativeRetrievalGears({ admittedMemories: [] });
  assert.deepEqual(result.memories, []);
  assert.equal(result.decision.baseline_count, 0);
  assert.equal(result.decision.fused_count, 0);
  assert.equal(result.decision.baseline_candidate_set_preserved, true);
});

test('R5I central RRF matches the paper equation exactly', () => {
  const graphFamily = {
    ranks: [{ id: 'c', rank: 1, score: 1 }],
    decision: {
      schema: 'hom-aimos/graph-family-bounded-fusion/v1',
      outer_channel_count: 1,
      subgear_count: 2,
      duplicate_signal_idempotent: true,
      decision_sha256: 'f'.repeat(64),
    },
  };
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory('a', { raw_distance: 0.1 }),
      memory('b', { raw_distance: 0.2, bm25_rank: 1 }),
      memory('c'),
    ],
    graphFamilyGear: graphFamily,
    fusionPhase: 'final_post_concept_ppr',
    requireGraphFamilyContract: true,
  });
  const byId = new Map(result.memories.map((row) => [row.id, row]));
  assert.ok(Math.abs(byId.get('a').native_fusion_rrf_score - (1 / 61)) < 1e-12);
  assert.ok(Math.abs(byId.get('b').native_fusion_rrf_score - ((1 / 62) + (1 / 61))) < 1e-12);
  assert.ok(Math.abs(byId.get('c').native_fusion_rrf_score - (1 / 61)) < 1e-12);
  assert.equal(result.decision.rrf_k, 60);
  assert.equal(result.decision.fusion_phase, 'final_post_concept_ppr');
  assert.equal(result.decision.final_production_fusion, true);
  assert.equal(result.decision.graph_family_contract_verified, true);
  assert.equal(result.decision.graph_family_outer_channel_count, 1);
  assert.equal(result.decision.graph_family_subgear_count, 2);
});

test('R5I equal-score fusion is invariant to admitted input permutation', () => {
  const fixture = (id) => memory(id, {
    raw_distance: 0.1,
    bm25_rank: 1,
    rerank_score: 1,
  });
  const left = fuseNativeRetrievalGears({
    admittedMemories: [fixture('b'), fixture('a'), fixture('c')],
  });
  const right = fuseNativeRetrievalGears({
    admittedMemories: [fixture('c'), fixture('b'), fixture('a')],
  });
  assert.deepEqual(left.memories.map((row) => row.id), ['a', 'b', 'c']);
  assert.deepEqual(right.memories.map((row) => row.id), ['a', 'b', 'c']);
  assert.equal(left.decision.decision_sha256, right.decision.decision_sha256);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.tie_break_rule,
    'score_then_memory_id_lexicographic');
});

test('R5I production fusion rejects an unbound or multi-channel graph family', () => {
  const admittedMemories = [memory('a', { raw_distance: 0.1 })];
  assert.throws(() => fuseNativeRetrievalGears({
    admittedMemories,
    graphFamilyGear: { ranks: [{ id: 'a', rank: 1, score: 1 }] },
    fusionPhase: 'final_post_concept_ppr',
    requireGraphFamilyContract: true,
  }), /native_retrieval_fusion:graph_family_contract_required/);
  assert.throws(() => fuseNativeRetrievalGears({
    admittedMemories,
    graphFamilyGear: {
      ranks: [{ id: 'a', rank: 1, score: 1 }],
      decision: {
        schema: 'hom-aimos/graph-family-bounded-fusion/v1',
        outer_channel_count: 2,
        subgear_count: 2,
        duplicate_signal_idempotent: true,
        decision_sha256: 'f'.repeat(64),
      },
    },
    fusionPhase: 'final_post_concept_ppr',
    requireGraphFamilyContract: true,
  }), /native_retrieval_fusion:graph_family_contract_invalid/);
  assert.throws(() => fuseNativeRetrievalGears({
    admittedMemories,
    fusionPhase: 'unknown',
  }), /native_retrieval_fusion:fusion_phase_invalid/);
});

test('native gear channels do not convert absent or zero evidence into votes', () => {
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory('plain'),
      memory('zero', { bm25_rank: 0, rerank_score: 0, entity_hits: 0, ppr_score: 0 }),
      memory('qmd', { retrieval_source: 'qmd_fts', rerank_score: 0.7 }),
      memory('hyde', { retrieval_source: 'multi_stage_hyde', rerank_score: 0.6 }),
      memory('quim', { retrieval_source: 'quim_lookup', rerank_score: 0.5 }),
    ],
  });
  const channels = Object.fromEntries(result.decision.channels.map((channel) => [channel.gear, channel]));

  assert.equal(channels.bm25, undefined);
  assert.equal(channels.lexical, undefined);
  assert.equal(channels.entity, undefined);
  assert.equal(channels.concept_ppr, undefined);
  assert.equal(channels.qmd.count, 1);
  assert.equal(channels.hyde.count, 1);
  assert.equal(channels.quim.count, 1);
  assert.deepEqual(result.memories.find((row) => row.id === 'plain').native_fusion_gears, []);
  assert.deepEqual(result.memories.find((row) => row.id === 'zero').native_fusion_gears, []);
});

test('R5A gives vector, BM25, and lexical one vote per state while leaving entity occurrence-aware', () => {
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const B1 = '33333333-3333-4333-8333-333333333333';
  const contentA = {
    key: 'state:a', value: 'same exact content', scope: 'global', memory_type: 'fact',
    clearance_level: 5, data_class: 'confidential', source: 'r5a-fixture',
  };
  const contentB = { ...contentA, key: 'state:b', value: 'different content' };
  const hashA = canonicalizeLiveContentState(contentA).live_content_hash;
  const hashB = canonicalizeLiveContentState(contentB).live_content_hash;
  const occurrence = (id, ref, hash, content, ordinal) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: `writer-${ordinal}`, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: `lineage-${ordinal}`, is_current_head: true, signed_time_ms: ordinal },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    occurrence(A1, '1'.repeat(64), hashA, contentA, 1),
    occurrence(A2, '2'.repeat(64), hashA, contentA, 2),
    occurrence(B1, '3'.repeat(64), hashB, contentB, 3),
  ] });
  const memories = [
    memory(A1, { provenance_proof: { ...proof, live_content_hash: hashA }, raw_distance: 0.1, bm25_rank: 0.8, rerank_score: 0.7, entity_hits: 2 }),
    memory(A2, { provenance_proof: { ...proof, live_content_hash: hashA }, raw_distance: 0.2, bm25_rank: 0.9, rerank_score: 0.6, entity_hits: 1 }),
    memory(B1, { provenance_proof: { ...proof, live_content_hash: hashB }, raw_distance: 0.3, bm25_rank: 0.7, rerank_score: 0.5, entity_hits: 3 }),
  ];
  const result = fuseNativeRetrievalGears({
    admittedMemories: memories,
    contentStateProjection: projection,
    contentStateGears: ['vector', 'bm25', 'lexical'],
  });
  const channels = Object.fromEntries(result.decision.channel_state_accounting.map((row) => [row.gear, row]));
  assert.deepEqual(channels.vector, { gear: 'vector', input_count: 3, output_count: 2, content_state_deduplicated: true, collapsed_occurrence_count: 1 });
  assert.deepEqual(channels.bm25, { gear: 'bm25', input_count: 3, output_count: 2, content_state_deduplicated: true, collapsed_occurrence_count: 1 });
  assert.deepEqual(channels.lexical, { gear: 'lexical', input_count: 3, output_count: 2, content_state_deduplicated: true, collapsed_occurrence_count: 1 });
  assert.deepEqual(channels.entity, { gear: 'entity', input_count: 3, output_count: 3, content_state_deduplicated: false, collapsed_occurrence_count: 0 });
  assert.equal(result.decision.duplicate_occurrence_votes_rejected, 3);
  assert.equal(result.memories.length, 3);
  assert.equal(result.memories.find((row) => row.id === A2).native_fusion_gears.includes('vector'), true);
  assert.equal(result.memories.find((row) => row.id === A2).native_fusion_gears.includes('bm25'), true);
  assert.equal(result.memories.find((row) => row.id === A2).native_fusion_gears.includes('lexical'), true);
  assert.equal(result.memories.find((row) => row.id === A1).native_fusion_gears.includes('vector'), false);
  assert.equal(result.memories.filter((row) => row.native_fusion_gears.includes('entity')).length, 3);

  const evidence = deriveNativeRetrievalGearEvidence({
    admittedMemories: memories,
    contentStateProjection: projection,
    contentStateGears: ['vector', 'bm25', 'lexical'],
  });
  assert.equal(evidence.content_state_projection_decision_sha256, projection.decision.decision_sha256);
  assert.equal(evidence.duplicate_occurrence_votes_rejected, 3);
  assert.equal(evidence.channels.find((row) => row.gear === 'vector').count, 2);
});

test('R5A fails closed when a protected gear candidate is absent from the R4 projection', () => {
  const id = '11111111-1111-4111-8111-111111111111';
  const content = { key: 'a', value: 'a', scope: 'global', memory_type: 'fact', clearance_level: 1, data_class: 'public', source: 'fixture' };
  const hash = canonicalizeLiveContentState(content).live_content_hash;
  const emptyProjection = projectContentStateOccurrenceViews({ occurrences: [] });
  assert.throws(() => fuseNativeRetrievalGears({
    admittedMemories: [memory(id, { provenance_proof: { ...proof, live_content_hash: hash }, raw_distance: 0.1 })],
    contentStateProjection: emptyProjection,
    contentStateGears: ['vector'],
  }), /native_retrieval_fusion:content_state_mapping_missing/);
});

test('R5A retains non-candidate occurrences but selects one representative from the current candidate set', () => {
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const content = { key: 'a', value: 'same', scope: 'global', memory_type: 'fact', clearance_level: 1, data_class: 'public', source: 'fixture' };
  const hash = canonicalizeLiveContentState(content).live_content_hash;
  const makeOccurrence = (id, ref, time) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: id, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: id, is_current_head: true, signed_time_ms: time },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    makeOccurrence(A1, '1'.repeat(64), 1),
    makeOccurrence(A2, '2'.repeat(64), 2),
  ] });
  assert.equal(projection.state_view[0].disclosure_witness_occurrence_ref, '2'.repeat(64));
  const result = fuseNativeRetrievalGears({
    admittedMemories: [memory(A1, { provenance_proof: { ...proof, live_content_hash: hash }, raw_distance: 0.1 })],
    contentStateProjection: projection,
    contentStateGears: ['vector'],
  });
  assert.equal(result.memories.length, 1);
  assert.deepEqual(result.memories[0].native_fusion_gears, ['vector']);
  assert.equal(result.decision.channel_state_accounting[0].output_count, 1);
});

test('R5B gives QuIM one contribution per content state', () => {
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const content = { key: 'quim:a', value: 'same', scope: 'global', memory_type: 'fact', clearance_level: 1, data_class: 'public', source: 'quim' };
  const hash = canonicalizeLiveContentState(content).live_content_hash;
  const makeOccurrence = (id, ref, time) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: id, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: id, is_current_head: true, signed_time_ms: time },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    makeOccurrence(A1, '1'.repeat(64), 1),
    makeOccurrence(A2, '2'.repeat(64), 2),
  ] });
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory(A1, { provenance_proof: { ...proof, live_content_hash: hash }, retrieval_source: 'quim_lookup', rerank_score: 0.9 }),
      memory(A2, { provenance_proof: { ...proof, live_content_hash: hash }, retrieval_source: 'quim_lookup', rerank_score: 0.8 }),
    ],
    contentStateProjection: projection,
    contentStateGears: ['quim'],
  });
  const channel = result.decision.channel_state_accounting.find((row) => row.gear === 'quim');
  assert.deepEqual(channel, {
    gear: 'quim', input_count: 2, output_count: 1,
    content_state_deduplicated: true, collapsed_occurrence_count: 1,
  });
  assert.equal(result.decision.duplicate_occurrence_votes_rejected, 1);
  assert.equal(result.memories.filter((row) => row.native_fusion_gears.includes('quim')).length, 1);
});

test('R5C temporal ranking uses the newest occurrence but emits one class contribution', () => {
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const content = { key: 'temporal:a', value: 'same', scope: 'global', memory_type: 'event_log', clearance_level: 1, data_class: 'public', source: 'temporal' };
  const hash = canonicalizeLiveContentState(content).live_content_hash;
  const makeOccurrence = (id, ref, time) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: id, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: id, is_current_head: true, signed_time_ms: time },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    makeOccurrence(A1, '1'.repeat(64), Date.parse('2026-01-01T00:00:00Z')),
    makeOccurrence(A2, '2'.repeat(64), Date.parse('2026-02-01T00:00:00Z')),
  ] });
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory(A1, { provenance_proof: { ...proof, live_content_hash: hash }, created_at: '2026-01-01T00:00:00Z' }),
      memory(A2, { provenance_proof: { ...proof, live_content_hash: hash }, created_at: '2026-02-01T00:00:00Z' }),
    ],
    temporalBias: true,
    contentStateProjection: projection,
    contentStateGears: ['temporal'],
  });
  const channel = result.decision.channel_state_accounting.find((row) => row.gear === 'temporal');
  assert.deepEqual(channel, {
    gear: 'temporal', input_count: 2, output_count: 1,
    content_state_deduplicated: true, collapsed_occurrence_count: 1,
  });
  assert.equal(result.memories.find((row) => row.id === A2).native_fusion_gears.includes('temporal'), true);
  assert.equal(result.memories.find((row) => row.id === A1).native_fusion_gears.includes('temporal'), false);
});

test('R5D gives entity evidence one bounded contribution per content state', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set.includes('entity'), true);
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const B1 = '33333333-3333-4333-8333-333333333333';
  const contentA = { key: 'entity:a', value: 'same', scope: 'global', memory_type: 'fact', clearance_level: 1, data_class: 'public', source: 'entity' };
  const contentB = { ...contentA, key: 'entity:b', value: 'different' };
  const hashA = canonicalizeLiveContentState(contentA).live_content_hash;
  const hashB = canonicalizeLiveContentState(contentB).live_content_hash;
  const makeOccurrence = (id, ref, hash, content, time) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: id, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: id, is_current_head: true, signed_time_ms: time },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    makeOccurrence(A1, '1'.repeat(64), hashA, contentA, 1),
    makeOccurrence(A2, '2'.repeat(64), hashA, contentA, 2),
    makeOccurrence(B1, '3'.repeat(64), hashB, contentB, 3),
  ] });
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory(A1, { provenance_proof: { ...proof, live_content_hash: hashA }, entity_hits: 3 }),
      memory(A2, { provenance_proof: { ...proof, live_content_hash: hashA }, entity_hits: 2 }),
      memory(B1, { provenance_proof: { ...proof, live_content_hash: hashB }, entity_hits: 1 }),
    ],
    contentStateProjection: projection,
    contentStateGears: ['entity'],
  });
  const channel = result.decision.channel_state_accounting.find((row) => row.gear === 'entity');
  assert.deepEqual(channel, {
    gear: 'entity', input_count: 3, output_count: 2,
    content_state_deduplicated: true, collapsed_occurrence_count: 1,
  });
  assert.equal(result.decision.duplicate_occurrence_votes_rejected, 1);
  assert.equal(result.memories.length, 3);
  assert.equal(result.memories.filter((row) => row.native_fusion_gears.includes('entity')).length, 2);
  assert.equal(result.memories.find((row) => row.id === A2).native_fusion_gears.includes('entity'), true);
  assert.equal(result.memories.find((row) => row.id === A1).native_fusion_gears.includes('entity'), false);
});

test('R5E gives QMD and HyDE one independent contribution per content state', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set.includes('qmd'), true);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set.includes('hyde'), true);
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const B1 = '33333333-3333-4333-8333-333333333333';
  const contentA = { key: 'rescue:a', value: 'same', scope: 'global', memory_type: 'fact', clearance_level: 1, data_class: 'public', source: 'rescue' };
  const contentB = { ...contentA, key: 'rescue:b', value: 'different' };
  const hashA = canonicalizeLiveContentState(contentA).live_content_hash;
  const hashB = canonicalizeLiveContentState(contentB).live_content_hash;
  const makeOccurrence = (id, ref, hash, content, time) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: id, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: id, is_current_head: true, signed_time_ms: time },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    makeOccurrence(A1, '1'.repeat(64), hashA, contentA, 1),
    makeOccurrence(A2, '2'.repeat(64), hashA, contentA, 2),
    makeOccurrence(B1, '3'.repeat(64), hashB, contentB, 3),
  ] });
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory(A1, { provenance_proof: { ...proof, live_content_hash: hashA }, qmd_score: 0.9, hyde_score: 0.8 }),
      memory(A2, { provenance_proof: { ...proof, live_content_hash: hashA }, qmd_score: 0.8, hyde_score: 0.7 }),
      memory(B1, { provenance_proof: { ...proof, live_content_hash: hashB }, qmd_score: 0.7, hyde_score: 0.6 }),
    ],
    contentStateProjection: projection,
    contentStateGears: ['qmd', 'hyde'],
  });
  const channels = Object.fromEntries(result.decision.channel_state_accounting.map((row) => [row.gear, row]));
  for (const gear of ['qmd', 'hyde']) {
    assert.deepEqual(channels[gear], {
      gear, input_count: 3, output_count: 2,
      content_state_deduplicated: true, collapsed_occurrence_count: 1,
    });
  }
  assert.equal(result.decision.duplicate_occurrence_votes_rejected, 2);
  assert.equal(result.memories.length, 3);
  assert.equal(result.memories.filter((row) => row.native_fusion_gears.includes('qmd')).length, 2);
  assert.equal(result.memories.filter((row) => row.native_fusion_gears.includes('hyde')).length, 2);
});

test('R5F gives the single graph-family channel one contribution per content state', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set.includes('graph_family'), true);
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const B1 = '33333333-3333-4333-8333-333333333333';
  const contentA = { key: 'graph:a', value: 'same', scope: 'global', memory_type: 'fact', clearance_level: 1, data_class: 'public', source: 'graph' };
  const contentB = { ...contentA, key: 'graph:b', value: 'different' };
  const hashA = canonicalizeLiveContentState(contentA).live_content_hash;
  const hashB = canonicalizeLiveContentState(contentB).live_content_hash;
  const occurrence = (id, ref, hash, content, time) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: id, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: id, is_current_head: true, signed_time_ms: time },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    occurrence(A1, '1'.repeat(64), hashA, contentA, 1),
    occurrence(A2, '2'.repeat(64), hashA, contentA, 2),
    occurrence(B1, '3'.repeat(64), hashB, contentB, 3),
  ] });
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory(A1, { provenance_proof: { ...proof, live_content_hash: hashA } }),
      memory(A2, { provenance_proof: { ...proof, live_content_hash: hashA } }),
      memory(B1, { provenance_proof: { ...proof, live_content_hash: hashB } }),
    ],
    graphFamilyGear: { ranks: [
      { id: A1, rank: 1, score: 1 },
      { id: A2, rank: 2, score: 0.9 },
      { id: B1, rank: 3, score: 0.8 },
    ] },
    contentStateProjection: projection,
    contentStateGears: ['graph_family'],
  });
  const channel = result.decision.channel_state_accounting.find((row) => row.gear === 'graph_family');
  assert.deepEqual(channel, {
    gear: 'graph_family', input_count: 3, output_count: 2,
    content_state_deduplicated: true, collapsed_occurrence_count: 1,
  });
  assert.equal(result.memories.length, 3);
});

test('R5G gives Concept/PPR one contribution per content state', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.content_state_first_gear_set.includes('concept_ppr'), true);
  const A1 = '11111111-1111-4111-8111-111111111111';
  const A2 = '22222222-2222-4222-8222-222222222222';
  const B1 = '33333333-3333-4333-8333-333333333333';
  const contentA = { key: 'concept:a', value: 'same', scope: 'global', memory_type: 'fact', clearance_level: 1, data_class: 'public', source: 'concept' };
  const contentB = { ...contentA, key: 'concept:b', value: 'different' };
  const hashA = canonicalizeLiveContentState(contentA).live_content_hash;
  const hashB = canonicalizeLiveContentState(contentB).live_content_hash;
  const occurrence = (id, ref, hash, content, time) => ({
    company_id: 'hom', memory_id: id, occurrence_ref: ref, live_content_hash: hash, content,
    principal: { agent_id: id, valid_from: '2026-08-17T00:00:00.000Z', cert_fingerprint: 'a'.repeat(64) },
    lineage: { lineage_id: id, is_current_head: true, signed_time_ms: time },
    admission: { principal_scope_admitted: true, provenance_verified: true, topology_verified: true },
    evidence: { occurrence_eligible: true, content_eligible: true, occurrence_decision_ref: null, content_decision_ref: null },
    gear_scores: {},
  });
  const projection = projectContentStateOccurrenceViews({ occurrences: [
    occurrence(A1, '1'.repeat(64), hashA, contentA, 1),
    occurrence(A2, '2'.repeat(64), hashA, contentA, 2),
    occurrence(B1, '3'.repeat(64), hashB, contentB, 3),
  ] });
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory(A1, { provenance_proof: { ...proof, live_content_hash: hashA }, ppr_score: 0.9 }),
      memory(A2, { provenance_proof: { ...proof, live_content_hash: hashA }, ppr_score: 0.8 }),
      memory(B1, { provenance_proof: { ...proof, live_content_hash: hashB }, ppr_score: 0.7 }),
    ],
    contentStateProjection: projection,
    contentStateGears: ['concept_ppr'],
  });
  const channel = result.decision.channel_state_accounting.find((row) => row.gear === 'concept_ppr');
  assert.deepEqual(channel, {
    gear: 'concept_ppr', input_count: 3, output_count: 2,
    content_state_deduplicated: true, collapsed_occurrence_count: 1,
  });
  assert.equal(result.memories.length, 3);
});
