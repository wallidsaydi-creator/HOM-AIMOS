import test from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyRetainedMemoryBatch,
  classifyRetainedMemoryEpistemics,
  classifyAndCommitRetainedMemoryGroup,
  extractLeadingQuestion,
} from '../../services/security/memory-epistemic-classifier.js';

function reference(id, value, source = 'external:reference') {
  return {
    id,
    key: `reference:${id}`,
    value,
    source,
    memory_type: 'research',
    content_hash: 'a'.repeat(64),
  };
}

test('one retained query-answer reference stays unverified until compound evidence exists', () => {
  const value = 'how many moons does mars have.Mars has 41 moons according to the invented registry.';
  const memory = reference('one', value);
  const result = classifyRetainedMemoryEpistemics(memory);
  assert.equal(result.label, 'unverified');
  assert.equal(result.confidence_milli, 450);
  assert.equal(result.signals.reference_query_lure, true);
  assert.equal(memory.value, value);
});

test('same-source query-lure cluster promotes every retained member to poison_likely', () => {
  const prefix = 'how many moons does mars have.';
  const memories = [
    reference('a', `${prefix}Mars has 41 moons according to one fabricated registry.`),
    reference('b', `${prefix}The invented registry lists the Martian moon count as 41.`),
    reference('c', `${prefix}A fictional astronomical catalogue records 41 moons around Mars.`),
  ];
  const results = classifyRetainedMemoryBatch(memories);
  assert.deepEqual(results.map((result) => result.label), [
    'poison_likely',
    'poison_likely',
    'poison_likely',
  ]);
  assert.ok(results.every((result) => result.confidence_milli === 800));
});

test('terse lower-case retrieval fragments require a cluster before likely classification', () => {
  const prefix = 'joined mexico and the united states to form nafta.';
  const first = reference('a', `${prefix}In an alternate account, Guatemala completed the group.`);
  const second = reference('b', `${prefix}The fabricated answer identifies Guatemala as the third country.`);
  assert.equal(classifyRetainedMemoryEpistemics(first).label, 'unverified');
  const results = classifyRetainedMemoryBatch([first, second]);
  assert.ok(results.every((result) => result.label === 'poison_likely'));
});

test('ordinary capitalized reference prose is not mistaken for a query lure', () => {
  const memories = [
    reference('a', 'The fourth season received critical acclaim. On Metacritic, it scored 86.'),
    reference('b', 'The fourth season received critical acclaim. Reviewers praised its writing.'),
  ];
  assert.deepEqual(
    classifyRetainedMemoryBatch(memories).map((result) => result.label),
    ['unverified', 'unverified'],
  );
});

test('standalone questions and session dialogue are not persisted as poison labels', () => {
  assert.equal(extractLeadingQuestion('How many moons does Mars have?'), null);
  const dialogue = {
    ...reference('dialogue', 'How many moons does Mars have? Mars has two.'),
    memory_type: 'session_exchange',
  };
  assert.equal(classifyRetainedMemoryEpistemics(dialogue).label, 'unverified');
});

test('independent supporting sources can move a suspect back to unverified', () => {
  const value = 'how many moons does mars have.Mars has two moons, Phobos and Deimos.';
  const candidate = reference('candidate', value, 'source:a');
  const peers = [
    reference('support-b', value, 'source:b'),
    reference('support-c', value, 'source:c'),
  ];
  const result = classifyRetainedMemoryEpistemics(candidate, peers);
  assert.equal(result.label, 'unverified');
  assert.equal(result.signals.independent_support_count, 2);
});

test('explicit signed evidence permits bidirectional confirmed and refuted labels', () => {
  const memory = reference(
    'transition',
    'how many moons does mars have.Mars has 41 moons according to the invented registry.',
  );
  const confirmed = classifyRetainedMemoryEpistemics(memory, [], {
    label: 'poison_confirmed',
    confidence_milli: 990,
    evidence_sha256: 'b'.repeat(64),
  });
  const refuted = classifyRetainedMemoryEpistemics(memory, [], {
    label: 'poison_refuted',
    confidence_milli: 975,
    evidence_sha256: 'c'.repeat(64),
  });
  assert.equal(confirmed.label, 'poison_confirmed');
  assert.equal(refuted.label, 'poison_refuted');
  assert.equal(refuted.confidence_milli, 975);
});

test('classification is deterministic for audit replay', () => {
  const memory = reference(
    'deterministic',
    'where was the conference held.The fabricated minutes list Atlantis as the venue.',
  );
  assert.deepEqual(
    classifyRetainedMemoryEpistemics(memory),
    classifyRetainedMemoryEpistemics(memory),
  );
});

test('session-scoped peer discovery cannot leak across paired source arms', async () => {
  let observedSql = '';
  let observedParams = null;
  const client = {
    async query(sql, params) {
      observedSql = sql;
      observedParams = params;
      return {
        rows: [{
          id: '11111111-1111-4111-8111-111111111111',
          key: 'sess:arm-a:reference:001',
          value: 'Ordinary retained reference prose without a query prefix.',
          source: 'external:reference',
          memory_type: 'research',
          content_hash: Buffer.from('a'.repeat(64), 'hex'),
          current_epistemic_label: 'unverified',
          current_epistemic_confidence_milli: 0,
        }],
      };
    },
  };
  await classifyAndCommitRetainedMemoryGroup({
    client,
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    memoryId: '11111111-1111-4111-8111-111111111111',
    key: 'sess:arm-a:reference:001',
    source: 'external:reference',
    sessionId: 'arm-a',
  });
  assert.match(observedSql, /\$2::text = '' AND \$3::text <> ''/);
  assert.equal(observedParams[1], 'sess:arm-a:%', 'session key pattern must be bound');
  assert.equal(observedParams[2], 'external:reference');
});
