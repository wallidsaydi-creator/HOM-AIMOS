import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { rankByTrust } from '../../services/learning/trust-score.js';
import {
  SEMANTIC_CACHE_STATE_REFERENCE_CONTRACT,
  SemanticCache,
} from '../../services/caching/semantic-cache.js';
import {
  NATIVE_RECALL_RETURN_PROJECTION_CONTRACT,
  SEMANTIC_CACHE_HYDRATION_CONTRACT,
  buildNativeRecallReturnProjection,
  hydrateSemanticCacheStateReferences,
} from '../../services/retrieval/native-recall-pipeline.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);
const HASH_D = 'd'.repeat(64);
const HASH_E = 'e'.repeat(64);

function memory(id, liveContentHash, overrides = {}) {
  return {
    id,
    key: `memory:${id.slice(0, 8)}`,
    value: `Canonical retained evidence for ${id}`,
    scope: 'global',
    memory_type: 'declarative',
    source: 'fixture',
    clearance_level: 5,
    data_class: 'internal',
    recall_confidence: 0.9,
    provenance_proof: {
      live_content_hash: liveContentHash,
      save_mutation_hash: HASH_C,
      binding_mutation_hash: HASH_D,
      version_status: 'current',
    },
    ...overrides,
  };
}

test('R5H semantic cache retains state references only in HOT and WARM tiers', async () => {
  const cache = new SemanticCache({ maxSize: 4, compressedMaxSize: 4 });
  const source = memory('11111111-1111-4111-8111-111111111111', HASH_A);
  const stored = cache.set([1, 0], 'state reference query', { memories: [source] }, {
    companyId: 'hom',
    agentId: 'codex-auditor',
    clearanceLevel: 10,
    calibrationMutationHash: HASH_B,
    contentStateDecisionHash: HASH_A,
    nativeFusionDecisionHash: HASH_B,
    epistemicDecisionHash: HASH_C,
    securityClosureDecisionHash: HASH_D,
  });

  assert.equal(stored, true);
  assert.equal(SEMANTIC_CACHE_STATE_REFERENCE_CONTRACT.cached_response_body_authority, false);
  const hot = await cache.get([1, 0], 'state reference query', {
    companyId: 'hom',
    agentId: 'codex-auditor',
    clearanceLevel: 10,
    calibrationMutationHash: HASH_B,
  });
  assert.equal(hot.schema, SEMANTIC_CACHE_STATE_REFERENCE_CONTRACT.schema);
  assert.equal(hot.cache_tier, 'HOT');
  assert.equal(hot.state_reference_count, 1);
  assert.equal(hot.state_references[0].memory_id, source.id);
  assert.equal(Object.hasOwn(hot, 'memories'), false);
  assert.equal(JSON.stringify(hot).includes(source.value), false);

  cache._cache.clear();
  cache._accessOrder = [];
  const warm = await cache.get([1, 0], 'semantically related reference query', {
    companyId: 'hom',
    agentId: 'codex-auditor',
    clearanceLevel: 10,
    calibrationMutationHash: HASH_B,
  });
  assert.equal(warm.cache_tier, 'WARM');
  assert.equal(warm.canonical_body_compressed, false);
  assert.equal(Object.hasOwn(warm, 'memories'), false);
  assert.equal(JSON.stringify(warm).includes(source.value), false);
});

test('R5H cache hydration is one bounded ordered query and missing identities fail to cache miss', async () => {
  const ids = [
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
  ];
  const calls = [];
  const cacheEntry = {
    schema: 'hom-aimos/semantic-cache-state-reference/v1',
    state_references: ids.map((memoryId, index) => ({
      memory_id: memoryId,
      live_content_hash: index ? HASH_B : HASH_A,
      save_mutation_hash: HASH_C,
      binding_mutation_hash: HASH_D,
    })),
  };
  const result = await hydrateSemanticCacheStateReferences({
    cacheEntry,
    companyId: 'hom',
    queryFn: async (sql, params) => {
      calls.push({ sql, params });
      return { rows: ids.map((id) => ({ id, key: `memory:${id}`, value: 'retained' })) };
    },
  });
  assert.equal(result.valid, true);
  assert.equal(result.memories.length, 2);
  assert.equal(calls.length, SEMANTIC_CACHE_HYDRATION_CONTRACT.database_round_trips);
  assert.match(calls[0].sql, /id = ANY\(\$2::uuid\[\]\)/);
  assert.match(calls[0].sql, /array_position\(\$2::uuid\[\], id\)/);
  assert.deepEqual(calls[0].params, ['hom', ids]);

  const missing = await hydrateSemanticCacheStateReferences({
    cacheEntry,
    companyId: 'hom',
    queryFn: async () => ({ rows: [{ id: ids[0] }] }),
  });
  assert.equal(missing.valid, false);
  assert.equal(missing.reason, 'cache_reference_missing');
});

test('R5H return projection permits only a unique commitment-preserving subset', () => {
  const first = memory('11111111-1111-4111-8111-111111111111', HASH_A);
  const second = memory('22222222-2222-4222-8222-222222222222', HASH_B);
  const closure = {
    memories: [first, second],
    decision: { decision_sha256: HASH_E },
  };
  const decision = buildNativeRecallReturnProjection({
    returnPath: 'normal_recall',
    securityClosure: closure,
    responseBody: { memories: [second] },
    contentStateSelection: { decision_sha256: HASH_A },
  });
  assert.equal(decision.schema, NATIVE_RECALL_RETURN_PROJECTION_CONTRACT.schema);
  assert.equal(decision.selected_clean_count, 2);
  assert.equal(decision.projected_output_count, 1);
  assert.deepEqual(decision.projected_memory_ids, [second.id]);
  assert.match(decision.decision_sha256, /^[0-9a-f]{64}$/);

  assert.throws(() => buildNativeRecallReturnProjection({
    returnPath: 'normal_recall',
    securityClosure: closure,
    responseBody: { memories: [first, { ...second, provenance_proof: { ...second.provenance_proof, live_content_hash: HASH_A } }] },
  }), /native_recall_return_projection_output_duplicate/);
  assert.throws(() => buildNativeRecallReturnProjection({
    returnPath: 'normal_recall',
    securityClosure: closure,
    responseBody: { memories: [memory('33333333-3333-4333-8333-333333333333', HASH_C)] },
  }), /native_recall_return_projection_not_subset/);
});

test('R5H source binds all return paths, shared reads, and scale-aware early trust', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  const runtime = source.slice(source.indexOf('export async function executeNativeRecall'));
  assert.equal((runtime.match(/calibrateAndFinalizeNativeRecallReturn\(\{/g) || []).length, 5);
  assert.equal((runtime.match(/queryFn: verifiedAdmissionSession\.read/g) || []).length >= 8, true);
  assert.match(runtime, /getVerifiedCalibrationSnapshot\(company, \{[\s\S]*?verifiedAdmissionSession\.read/);
  assert.match(runtime, /lookupIdentifierCandidates\(\{[\s\S]*?queryFn: verifiedAdmissionSession\.read/);
  assert.match(runtime, /lookupPostCompactionHandoff\(\{[\s\S]*?queryFn: verifiedAdmissionSession\.read/);
  assert.match(runtime, /rankByTrust\(earlyStateSelection\.memories, \{ memoryCount: corpusMemoryCount \}\)/);
  assert.match(runtime, /shouldEarlyExit\([\s\S]*?total_memories: corpusMemoryCount/);
  assert.match(runtime, /normalFinalStateSelection/);
  assert.doesNotMatch(runtime, /calibrated\w+\.recall_receipt = await finalizeNativeRecall/);
});

test('R5H trust ranking consumes the existing scale-aware formula', () => {
  const fixture = {
    id: 'scale-fixture',
    access_count: 100,
    graph_links: Array.from({ length: 20 }, (_, index) => ({ id: index })),
    credit_score: 0,
  };
  const baseline = rankByTrust([fixture], { memoryCount: 14_000 })[0].trust_score;
  const million = rankByTrust([fixture], { memoryCount: 1_000_000 })[0].trust_score;
  assert.equal(baseline, 0.75);
  assert.ok(million < baseline);
  assert.ok(million >= 0);
});
