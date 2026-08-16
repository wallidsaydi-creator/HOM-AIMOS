import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CONCEPT_PPR_RETRIEVAL_POLICY_VERSION,
  QUIM_RETRIEVAL_POLICY_VERSION,
  validateConceptPprRetrievalPolicy,
  validateQuimRetrievalPolicy,
} from '../../services/security/system-config-ledger.js';

const buildId = '10000000-0000-4000-8000-000000000001';
const root = 'ab'.repeat(32);

test('QuIM policy binds one exact build and the paper top-three contract', () => {
  const value = JSON.stringify({
    version: QUIM_RETRIEVAL_POLICY_VERSION,
    build_id: buildId,
    corpus_root_sha256: root,
    index_root_sha256: root,
    prototype_count: 32,
    top_questions: 3,
    max_bucket_scan: 512,
  });
  assert.equal(validateQuimRetrievalPolicy(value).ok, true);
  assert.equal(validateQuimRetrievalPolicy(value.replace('"top_questions":3', '"top_questions":5')).ok, false);
  assert.equal(validateQuimRetrievalPolicy(value.slice(0, -1) + ',"execution":"enforce"}').ok, false);
});

test('Concept/PPR policy freezes paper math and explicit scale bounds', () => {
  const value = JSON.stringify({
    version: CONCEPT_PPR_RETRIEVAL_POLICY_VERSION,
    build_id: buildId,
    corpus_root_sha256: root,
    graph_root_sha256: root,
    damping: '1/2',
    iterations: 20,
    entity_seed_limit: 5,
    passage_limit: 20,
    synonym_threshold_q6: 800000,
    max_synonyms_per_node: 8,
    max_ppr_nodes: 10000,
    max_ppr_edges: 80000,
  });
  assert.equal(validateConceptPprRetrievalPolicy(value).ok, true);
  assert.equal(validateConceptPprRetrievalPolicy(value.replace('"damping":"1/2"', '"damping":"0.85"')).ok, false);
  assert.equal(validateConceptPprRetrievalPolicy(value.replace('"max_ppr_edges":80000', '"max_ppr_edges":3000000')).ok, false);
});
