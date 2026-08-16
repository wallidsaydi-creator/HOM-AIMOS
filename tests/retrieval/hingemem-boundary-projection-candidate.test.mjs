import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import {
  buildHingeMemBoundaryProjection,
  HINGEMEM_B_GUARDRAILS,
  retrieveHingeMemBoundaryProjection,
} from '../../services/retrieval/hingemem-boundary-projection-candidate.js';

function memory(id, session, sequence, vector, text, speakers = ['A', 'B']) {
  const value = JSON.stringify({
    schema: 'aimos.session-exchange/v2',
    session_id: session,
    turn_sequences: [sequence],
    valid_from: new Date(Date.UTC(2026, 0, 1, 0, sequence)).toISOString(),
    turns: [{ content: text, speaker: speakers[0], sequence }],
  });
  return Object.freeze({
    id,
    key: `${session}:${String(sequence).padStart(4, '0')}`,
    value,
    embedding: Object.freeze(vector),
    content_hash: id.repeat(64).slice(0, 64),
    session_id: session,
    provenance_proof: Object.freeze({ binding_event_id: `proof:${id}` }),
  });
}

const sources = Object.freeze([
  memory('a', 's1', 1, [1, 0], 'Discussing the engineering project.'),
  memory('b', 's1', 2, [0.98, 0.02], 'More details about the engineering project.'),
  memory('c', 's1', 3, [0, 1], 'By the way, the family visited Paris.'),
  memory('d', 's1', 4, [0.02, 0.98], 'The Paris trip included a museum.'),
  memory('e', 's2', 1, [0.7, 0.7], 'A separate session about a concert.'),
]);

test('boundary projection is deterministic and partitions every source exactly once', () => {
  const first = buildHingeMemBoundaryProjection(sources);
  const second = buildHingeMemBoundaryProjection(sources);
  assert.equal(first.decision.projection_set_sha256, second.decision.projection_set_sha256);
  assert.equal(first.decision.source_partition_complete, true);
  assert.deepEqual(first.projections.flatMap((row) => row.source_memory_ids).sort(), ['a', 'b', 'c', 'd', 'e']);
  assert.equal(new Set(first.projections.flatMap((row) => row.source_memory_ids)).size, 5);
});

test('projections never cross canonical session boundaries and retain exact source hashes', () => {
  const result = buildHingeMemBoundaryProjection(sources);
  for (const projection of result.projections) {
    const sessions = new Set(projection.source_memory_ids.map((id) => sources.find((row) => row.id === id).session_id));
    assert.equal(sessions.size, 1);
    assert.equal(projection.source_memory_ids.length, projection.source_content_hashes.length);
    assert.match(projection.projection_sha256, /^[0-9a-f]{64}$/);
    assert.equal(projection.signature_state, 'unsigned_transient_candidate');
    assert.equal(projection.topic_cluster, null);
  }
});

test('explicit and semantic changes form evidence-linked boundaries without source mutation', () => {
  const before = JSON.stringify(sources);
  const result = buildHingeMemBoundaryProjection(sources);
  assert.ok(result.projections.length >= 3);
  assert.ok(result.projections.some((row) => row.boundary_reasons.includes('explicit_marker')
    || row.boundary_reasons.includes('semantic_shift')));
  assert.equal(JSON.stringify(sources), before);
});

test('retrieval can discover a projection member outside the baseline deterministically', () => {
  const projectionState = buildHingeMemBoundaryProjection(sources);
  const input = {
    queryEmbedding: [0, 1],
    baselineMemories: [sources[0], sources[1]],
    scopeMemories: sources,
    projectionState,
    limit: 3,
  };
  const first = retrieveHingeMemBoundaryProjection(input);
  const second = retrieveHingeMemBoundaryProjection(input);
  assert.equal(first.decision.decision_sha256, second.decision.decision_sha256);
  assert.equal(first.ranked.length, 3);
  assert.ok(first.ranked.some((row) => row.id === 'c' || row.id === 'd'));
  assert.ok(first.diagnostics.boundary_discovered_count > 0);
});

test('candidate rejects missing provenance, content hashes, duplicates, and malformed input', () => {
  assert.throws(() => buildHingeMemBoundaryProjection([{ ...sources[0], provenance_proof: null }]), /source_provenance_missing/);
  assert.throws(() => buildHingeMemBoundaryProjection([{ ...sources[0], content_hash: null }]), /source_content_hash_invalid/);
  assert.throws(() => buildHingeMemBoundaryProjection([sources[0], sources[0]]), /duplicate_source_id/);
  assert.throws(() => buildHingeMemBoundaryProjection([]), /sources_required/);
  assert.throws(() => retrieveHingeMemBoundaryProjection({}), /query_embedding_invalid/);
});

test('guardrails defer topic clustering, models, signing, persistence, and disclosure authority', () => {
  assert.equal(HINGEMEM_B_GUARDRAILS.uses_topic_clustering, false);
  assert.equal(HINGEMEM_B_GUARDRAILS.uses_model_boundary_extractor, false);
  assert.equal(HINGEMEM_B_GUARDRAILS.uses_model_query_planner, false);
  assert.equal(HINGEMEM_B_GUARDRAILS.projection_is_currently_signed, false);
  assert.equal(HINGEMEM_B_GUARDRAILS.signature_required_before_persistence, true);
  assert.equal(HINGEMEM_B_GUARDRAILS.uses_database, false);
  assert.equal(HINGEMEM_B_GUARDRAILS.mutates_memory, false);
  assert.equal(HINGEMEM_B_GUARDRAILS.disclosure_authority, false);
});

test('source contains no database, server, network, persistence, model, or ENV authority', () => {
  const source = fs.readFileSync(new URL('../../services/retrieval/hingemem-boundary-projection-candidate.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from ['"]\.\.\/\.\.\/db\//);
  assert.doesNotMatch(source, /process\.env/);
  assert.doesNotMatch(source, /fetch\s*\(/);
  assert.doesNotMatch(source, /listen\s*\(/);
  assert.doesNotMatch(source, /callNativeLlm|persistMemory|withTransaction/);
});
