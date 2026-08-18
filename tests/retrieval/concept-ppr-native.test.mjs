import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  CONCEPT_PPR_MAX_REQUEST_NODES,
  CONCEPT_PPR_MAX_REQUEST_RELATION_EDGES,
  CONCEPT_PPR_MAX_REQUEST_STATES,
  CONCEPT_PPR_QUERY_CONTRACT,
  runPersonalizedPageRank,
} from '../../services/retrieval/concept-ppr-native.js';
import {
  extractQueryEntityAnchors,
  normalizeEntityAnchor,
} from '../../services/retrieval/query-entity-anchors.js';

test('query entity anchors are deterministic and normalized', () => {
  const text = 'HOM AIMOS discussed Zurich on 2026-08-16 with OpenAI.';
  assert.deepEqual(extractQueryEntityAnchors(text), extractQueryEntityAnchors(text));
  assert.ok(extractQueryEntityAnchors(text).some((entity) => entity.name === 'zurich'));
  assert.equal(normalizeEntityAnchor('  Signed   Provenance  '), 'signed provenance');
});

test('Concept/PPR conserves probability and propagates through relations', () => {
  const scores = runPersonalizedPageRank({
    nodeIds: ['a', 'b', 'c'],
    edges: [
      { source: 'a', target: 'b', relation_type: 'RELATED_TO', weight: 1 },
      { source: 'b', target: 'c', relation_type: 'RELATED_TO', weight: 1 },
    ],
    seedWeights: new Map([['a', 1]]),
    damping: 0.5,
    iterations: 30,
  });
  const total = [...scores.values()].reduce((sum, score) => sum + score, 0);
  assert.ok(Math.abs(total - 1) < 1e-9);
  assert.ok(scores.get('a') > scores.get('b'));
  assert.ok(scores.get('b') > scores.get('c'));
  assert.ok(scores.get('c') > 0);
});

test('Concept/PPR dangling mass returns to the personalized teleport set', () => {
  const scores = runPersonalizedPageRank({
    nodeIds: ['seed', 'isolated'],
    edges: [],
    seedWeights: new Map([['seed', 1]]),
    damping: 0.5,
    iterations: 5,
  });
  assert.equal(scores.get('seed'), 1);
  assert.equal(scores.get('isolated'), 0);
});

test('R5G Concept/PPR is request-state scoped before graph propagation and passage lift', () => {
  assert.equal(CONCEPT_PPR_QUERY_CONTRACT.one_passage_vote_per_verified_content_state, true);
  assert.equal(CONCEPT_PPR_QUERY_CONTRACT.global_unadmitted_passage_influence, false);
  assert.equal(CONCEPT_PPR_QUERY_CONTRACT.candidate_discovery_authority, false);
  assert.equal(CONCEPT_PPR_MAX_REQUEST_STATES, 200);
  assert.equal(CONCEPT_PPR_MAX_REQUEST_NODES, 4096);
  assert.equal(CONCEPT_PPR_MAX_REQUEST_RELATION_EDGES, 32768);
  assert.equal(CONCEPT_PPR_QUERY_CONTRACT.maximum_request_nodes, 4096);
  assert.equal(CONCEPT_PPR_QUERY_CONTRACT.maximum_request_relation_edges, 32768);
  const source = readFileSync(new URL('../../services/retrieval/concept-ppr-native.js', import.meta.url), 'utf8');
  assert.match(source, /concept_ppr_admitted_states_required/);
  assert.match(source, /concept_ppr_duplicate_state_binding/);
  assert.match(source, /encode\(source_content_sha256, 'hex'\) = ANY\(\$3::text\[\]\)/);
  assert.match(source, /node_id = ANY\(\$4::uuid\[\]\)/);
  assert.match(source, /source_concept_node_id = ANY\(\$3::uuid\[\]\)/);
  assert.match(source, /source_content_sha256 IS NULL/);
  assert.match(source, /encode\(source_content_sha256, 'hex'\) = ANY\(\$4::text\[\]\)/);
  assert.match(source, /encode\(edge\.source_content_sha256, 'hex'\) = ANY\(\$5::text\[\]\)/);
  assert.match(source, /representativeByStateHash\.get/);
  assert.match(source, /requestSpecificityByNode/);
  assert.match(source, /CONCEPT_PPR_MAX_REQUEST_NODES \+ 1/);
  assert.match(source, /CONCEPT_PPR_MAX_REQUEST_RELATION_EDGES \+ 1/);
});
