import test from 'node:test';
import assert from 'node:assert/strict';

import {
  HMEM_H2_GUARDRAILS,
  HMEM_H2_VERSION,
  buildGovernedHmemHierarchy,
  routeGovernedHmem,
} from '../../services/retrieval/hmem-native-candidate/governed-hierarchy.js';

function unit(x, y, z) {
  const norm = Math.sqrt((x * x) + (y * y) + (z * z));
  return [x / norm, y / norm, z / norm];
}

function fixtureStates() {
  return [
    { id: 'a-1', embedding: unit(1, 0.05, 0), text: 'vehicle preference' },
    { id: 'a-2', embedding: unit(1, 0.10, 0), text: 'automobile preference' },
    { id: 'a-3', embedding: unit(1, -0.05, 0), text: 'car preference' },
    { id: 'a-4', embedding: unit(0.9, 0.20, 0), text: 'travel by car' },
    { id: 'b-1', embedding: unit(0.05, 1, 0), text: 'database security' },
    { id: 'b-2', embedding: unit(0.10, 1, 0), text: 'encrypted records' },
    { id: 'b-3', embedding: unit(-0.05, 1, 0), text: 'database permissions' },
    { id: 'b-4', embedding: unit(0.20, 0.9, 0), text: 'security audit' },
  ];
}

const OPTIONS = Object.freeze({
  dimension: 3,
  targetSizes: [4, 2, 2],
  branchCap: 4,
  iterations: 8,
});

function centroidSnapshot(hierarchy) {
  return ['domain', 'category', 'trace'].flatMap((level) => hierarchy.levels[level].map((node) => ({
    id: node.id,
    level,
    vector: node.vector.map((entry) => Number(entry.toFixed(12))),
    centroid_member_ids: [...node.centroid_member_ids],
  })));
}

test('H2 hierarchy is deterministic under input order and preserves complete reachability', () => {
  const states = fixtureStates();
  const snapshot = structuredClone(states);
  const forward = buildGovernedHmemHierarchy(states, OPTIONS);
  const reverse = buildGovernedHmemHierarchy([...states].reverse(), OPTIONS);

  assert.deepEqual(states, snapshot);
  assert.equal(forward.version, HMEM_H2_VERSION);
  assert.equal(forward.complete_reachability, true);
  assert.equal(forward.counts.episode, states.length);
  assert.equal(forward.commitments.complete_root_sha256, reverse.commitments.complete_root_sha256);
  assert.equal(forward.commitments.semantic_root_sha256, reverse.commitments.semantic_root_sha256);
  assert.deepEqual(centroidSnapshot(forward), centroidSnapshot(reverse));
});

test('H2 query routing is deterministic and uses the declared path score', () => {
  const hierarchy = buildGovernedHmemHierarchy(fixtureStates(), OPTIONS);
  const first = routeGovernedHmem(unit(1, 0, 0), hierarchy, {
    beamWidth: 2,
    episodePerParent: 4,
    limit: 3,
  });
  const second = routeGovernedHmem(unit(1, 0, 0), hierarchy, {
    beamWidth: 2,
    episodePerParent: 4,
    limit: 3,
  });

  assert.deepEqual(first, second);
  assert.equal(first.decision_sha256, second.decision_sha256);
  assert.equal(first.selected_memory_ids.every((id) => id.startsWith('a-')), true);
  assert.equal(first.ranked.every((row) => row.path.length === 4), true);
  assert.equal(first.formula, '0.80*cosine(query,episode)+0.20*mean_path_cosine');
});

test('verified zero-influence memory is retained but cannot steer centroids or enter ordinary output', () => {
  const trusted = fixtureStates().map((state) => ({
    ...state,
    centroid_influence: 1,
    security_projection_verified: true,
  }));
  const cleanHierarchy = buildGovernedHmemHierarchy(trusted, {
    ...OPTIONS,
    securityMode: 'verified',
  });
  const withPoison = buildGovernedHmemHierarchy([
    ...trusted,
    {
      id: 'poison-retained',
      embedding: unit(1, 0, 0),
      centroid_influence: 0,
      security_projection_verified: true,
      text: 'retained untrusted evidence',
    },
  ], {
    ...OPTIONS,
    securityMode: 'verified',
  });

  assert.deepEqual(centroidSnapshot(withPoison), centroidSnapshot(cleanHierarchy));
  assert.equal(withPoison.retained_memory_count, trusted.length + 1);
  assert.equal(withPoison.zero_influence_retained_count, 1);
  assert.equal(withPoison.complete_reachability, true);
  assert.notEqual(withPoison.commitments.complete_root_sha256, cleanHierarchy.commitments.complete_root_sha256);
  const routed = routeGovernedHmem(unit(1, 0, 0), withPoison, { limit: 20 });
  assert.equal(routed.selected_memory_ids.includes('poison-retained'), false);
});

test('security mode fails closed without verified projections', () => {
  assert.throws(
    () => buildGovernedHmemHierarchy(fixtureStates(), { ...OPTIONS, securityMode: 'verified' }),
    /hmem_h2_security_projection_unverified:a-1/,
  );
  assert.throws(
    () => buildGovernedHmemHierarchy(fixtureStates().map((state) => ({
      ...state,
      centroid_influence: 0,
      security_projection_verified: true,
    })), { ...OPTIONS, securityMode: 'verified' }),
    /hmem_h2_no_routable_centroid_members/,
  );
});

test('malformed vectors and query dimensions fail closed', () => {
  assert.throws(
    () => buildGovernedHmemHierarchy([{ id: 'bad', embedding: [1, 0] }], OPTIONS),
    /hmem_h2_embedding_invalid:bad/,
  );
  const hierarchy = buildGovernedHmemHierarchy(fixtureStates(), OPTIONS);
  assert.throws(
    () => routeGovernedHmem([1, 0], hierarchy),
    /hmem_h2_query_embedding_invalid/,
  );
  assert.deepEqual(HMEM_H2_GUARDRAILS, {
    mutates_canonical_memory: false,
    prunes_canonical_memory: false,
    applies_decay: false,
    deletes_memory: false,
    suppresses_canonical_memory: false,
    parses_epistemic_labels: false,
    requires_verified_security_projection_in_security_mode: true,
    zero_influence_retained_in_complete_hierarchy: true,
    zero_influence_excluded_from_ordinary_candidate_output: true,
  });
});
