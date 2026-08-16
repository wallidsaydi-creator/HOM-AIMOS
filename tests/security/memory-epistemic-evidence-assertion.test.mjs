import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';

import {
  EPISTEMIC_EVIDENCE_LINK_RELATIONS,
  EPISTEMIC_EVIDENCE_RELATIONS,
  EPISTEMIC_EVIDENCE_TYPES,
  MEMORY_EPISTEMIC_LABELS_V2,
  buildEvidenceBoundExplicitClassification,
  buildMemoryEpistemicEvidenceAssertion,
  buildMemoryPoisonHypothesis,
  projectEpistemicLabelExact,
  resolveEffectiveEpistemicState,
  verifyMemoryEpistemicEvidenceAssertion,
  verifyMemoryEpistemicEvidenceChain,
} from '../../services/security/memory-epistemic-evidence-assertion.js';
import {
  MEMORY_EPISTEMIC_EVIDENCE_ASSERTED_OPERATION,
  commitMemoryEpistemicEvidenceAssertion,
  verifyPersistedMemoryEpistemicEvidenceChain,
} from '../../services/security/memory-epistemic-classifier.js';
import {
  computeConservativeMulticlassCertificate,
  resolveCertifiedEpistemicPosture,
  selectUniqueEpistemicTopClass,
} from '../../services/security/epistemic-edit-certificate-multiclass-math.js';

const sha = (value) => createHash('sha256').update(String(value), 'utf8').digest('hex');
const hypothesis = buildMemoryPoisonHypothesis({
  memoryId: '00000000-0000-4000-8000-000000000401',
  liveContentHash: sha('retained-poison-candidate'),
});

function assertion({
  ordinal,
  relation = 'supports',
  evidenceType = 'content_signal',
  source = `source-${ordinal}`,
  group = `group-${ordinal}`,
  independenceStatus = 'independent',
  independenceBasis = 'origin',
  previous = null,
  links = [],
} = {}) {
  return buildMemoryEpistemicEvidenceAssertion({
    assertionId: `00000000-0000-4000-8000-${String(ordinal).padStart(12, '0')}`,
    hypothesis,
    relation,
    confidenceMilli: 850,
    rationaleSha256: sha(`rationale-${ordinal}`),
    assessorIdentitySha256: sha(`assessor-${ordinal}`),
    evidenceType,
    evidenceArtifactSha256: sha(`artifact-${ordinal}`),
    evidenceProvenanceSha256: sha(`provenance-${ordinal}`),
    sourceIndependence: {
      status: independenceStatus,
      basis: independenceBasis,
      source_identity_sha256: sha(source),
      independence_group_sha256: sha(group),
      basis_evidence_sha256: sha(`basis-${ordinal}`),
    },
    evidenceLinks: links,
    prevAssertionSha256: previous,
  });
}

test('assertion ontology retains every hypothesis relation, evidence type, and source-independence field', () => {
  const rows = [];
  let previous = null;
  let ordinal = 1;
  for (const relation of EPISTEMIC_EVIDENCE_RELATIONS) {
    for (const evidenceType of EPISTEMIC_EVIDENCE_TYPES) {
      const row = assertion({ ordinal, relation, evidenceType, previous });
      rows.push(row);
      previous = row.assertion_sha256;
      ordinal += 1;
    }
  }
  const verified = verifyMemoryEpistemicEvidenceChain(rows);
  assert.equal(verified.assertion_count, EPISTEMIC_EVIDENCE_RELATIONS.length * EPISTEMIC_EVIDENCE_TYPES.length);
  for (const relation of EPISTEMIC_EVIDENCE_RELATIONS) {
    assert.equal(verified.relation_counts[relation], EPISTEMIC_EVIDENCE_TYPES.length);
  }
  for (const evidenceType of EPISTEMIC_EVIDENCE_TYPES) {
    assert.equal(verified.evidence_type_counts[evidenceType], EPISTEMIC_EVIDENCE_RELATIONS.length);
  }
  const sample = rows[0];
  assert.match(sample.claim_record.claim_sha256, /^[0-9a-f]{64}$/);
  assert.match(sample.evidence_record.source_independence.source_identity_sha256, /^[0-9a-f]{64}$/);
  assert.match(sample.evidence_record.source_independence.independence_group_sha256, /^[0-9a-f]{64}$/);
  assert.match(sample.evidence_record.source_independence.basis_evidence_sha256, /^[0-9a-f]{64}$/);
});

test('supporting and refuting claim records remain separately attributable', () => {
  const supportA = assertion({ ordinal: 101, relation: 'supports', group: 'shared-origin' });
  const supportB = assertion({
    ordinal: 102,
    relation: 'supports',
    group: 'shared-origin',
    previous: supportA.assertion_sha256,
    links: [{ relation: 'corroborates', target_assertion_sha256: supportA.assertion_sha256 }],
  });
  const refute = assertion({
    ordinal: 103,
    relation: 'refutes',
    evidenceType: 'counterevidence',
    group: 'independent-counter-source',
    previous: supportB.assertion_sha256,
    links: [{ relation: 'contradicts', target_assertion_sha256: supportB.assertion_sha256 }],
  });
  const result = verifyMemoryEpistemicEvidenceChain([supportA, supportB, refute]);
  assert.equal(result.supporting_claim_records.length, 2);
  assert.equal(result.refuting_claim_records.length, 1);
  assert.equal(result.independent_supporting_source_count, 1);
  assert.equal(result.independent_refuting_source_count, 1);
  assert.equal(result.conflict_present, true);
  const refutingRecord = result.refuting_claim_records[0];
  assert.equal(refutingRecord.evidence_artifact_sha256, refute.evidence_record.artifact_sha256);
  assert.equal(refutingRecord.relation, 'refutes');
  assert.equal(refutingRecord.evidence_type, 'counterevidence');
  assert.equal(refutingRecord.evidence_provenance_sha256, refute.evidence_record.provenance_sha256);
  assert.equal(refutingRecord.assessor_identity_sha256, refute.claim_record.assessor_identity_sha256);
  assert.equal(refutingRecord.rationale_sha256, refute.claim_record.rationale_sha256);
  assert.equal(refutingRecord.independence_basis, 'origin');
  assert.equal(
    refutingRecord.independence_basis_evidence_sha256,
    refute.evidence_record.source_independence.basis_evidence_sha256,
  );
  assert.deepEqual(refutingRecord.evidence_links, refute.evidence_links);
  assert.equal(result.claim_records.length, 3);
});

test('all evidence-to-evidence relations are retained and only retraction/supersession deactivate predecessors', () => {
  const rows = [];
  let previous = null;
  const target = assertion({ ordinal: 201, relation: 'supports' });
  rows.push(target);
  previous = target.assertion_sha256;
  for (let index = 0; index < EPISTEMIC_EVIDENCE_LINK_RELATIONS.length; index += 1) {
    const linkRelation = EPISTEMIC_EVIDENCE_LINK_RELATIONS[index];
    const row = assertion({
      ordinal: 202 + index,
      relation: 'contextualizes',
      previous,
      links: [{ relation: linkRelation, target_assertion_sha256: target.assertion_sha256 }],
    });
    rows.push(row);
    previous = row.assertion_sha256;
  }
  const result = verifyMemoryEpistemicEvidenceChain(rows);
  assert.ok(result.inactive_assertion_sha256s.includes(target.assertion_sha256));
  assert.equal(result.assertion_count, 1 + EPISTEMIC_EVIDENCE_LINK_RELATIONS.length);
  assert.equal(result.active_assertion_count, EPISTEMIC_EVIDENCE_LINK_RELATIONS.length);
  assert.equal(result.assertion_lifecycle_records.length, result.assertion_count);
  assert.equal(
    result.assertion_lifecycle_records.find((entry) => entry.assertion_sha256 === target.assertion_sha256)?.active,
    false,
  );
  const retainedLinks = result.assertion_lifecycle_records.flatMap((entry) => entry.evidence_links);
  for (const relation of EPISTEMIC_EVIDENCE_LINK_RELATIONS) {
    assert.ok(retainedLinks.some((link) => link.relation === relation));
  }
});

test('assertion, claim, source identity, predecessor, and relation tampering fail closed', () => {
  const row = assertion({ ordinal: 301 });
  for (const mutate of [
    (copy) => { copy.claim_record.relation = 'refutes'; },
    (copy) => { copy.claim_record.claim_sha256 = sha('forged-claim'); },
    (copy) => { copy.evidence_record.source_independence.source_identity_sha256 = sha('forged-source'); },
    (copy) => { copy.prev_assertion_sha256 = sha('forged-predecessor'); },
    (copy) => { copy.evidence_record.evidence_type = 'unknown-type'; },
  ]) {
    const copy = structuredClone(row);
    mutate(copy);
    assert.throws(() => verifyMemoryEpistemicEvidenceAssertion(copy), /epistemic_evidence/);
  }
});

test('seven-state projection never collapses unverified into authenticated refutation', () => {
  for (const label of MEMORY_EPISTEMIC_LABELS_V2) {
    assert.equal(projectEpistemicLabelExact(label), label);
  }
  assert.notEqual(projectEpistemicLabelExact('unverified'), projectEpistemicLabelExact('poison_refuted'));
});

test('signed poison state cannot be exonerated by any ephemeral detector output', () => {
  for (const signedLabel of ['poison_suspect', 'poison_likely', 'poison_confirmed']) {
    for (const detectorLabel of MEMORY_EPISTEMIC_LABELS_V2) {
      const result = resolveEffectiveEpistemicState({ signedLabel, detectorLabel });
      assert.ok(result.effective_restriction_rank >= result.signed_restriction_rank);
      assert.equal(result.persistent_transition_authorized, false);
      if (!['poison_suspect', 'poison_likely', 'poison_confirmed'].includes(detectorLabel)) {
        assert.equal(result.effective_label, signedLabel);
        assert.equal(result.exoneration_blocked, true);
      }
    }
  }
});

test('multiclass CERT-ED successor selects an exact label without binary collapse', () => {
  const counts = Object.fromEntries(MEMORY_EPISTEMIC_LABELS_V2.map((label) => [label, 0]));
  counts.unverified = 30;
  counts.poison_refuted = 20;
  counts.poison_likely = 950;
  const selected = selectUniqueEpistemicTopClass(counts);
  assert.equal(selected.selected_class, 'poison_likely');
  const decision = computeConservativeMulticlassCertificate({
    counts,
    nCertify: 1000,
    alphaFamily: { numerator: 5, denominator: 100 },
    nMax: 1,
    pDel: { numerator: 9, denominator: 10 },
  });
  assert.equal(decision.outcome, 'certified');
  assert.equal(decision.selected_class, 'poison_likely');
  assert.equal(decision.counts.unverified, 30);
  assert.equal(decision.counts.poison_refuted, 20);
});

test('multiclass tie abstains and a certified edited view cannot lower signed poison state', () => {
  const tied = Object.fromEntries(MEMORY_EPISTEMIC_LABELS_V2.map((label) => [label, 0]));
  tied.unverified = 50;
  tied.poison_refuted = 50;
  const tieDecision = computeConservativeMulticlassCertificate({
    counts: tied,
    nCertify: 100,
    alphaFamily: { numerator: 5, denominator: 100 },
    nMax: 1,
    pDel: { numerator: 9, denominator: 10 },
  });
  assert.equal(tieDecision.outcome, 'abstain');
  assert.deepEqual(tieDecision.tie_classes, ['unverified', 'poison_refuted']);

  const exoneratingCounts = Object.fromEntries(MEMORY_EPISTEMIC_LABELS_V2.map((label) => [label, 0]));
  exoneratingCounts.unverified = 1000;
  const exoneratingDecision = computeConservativeMulticlassCertificate({
    counts: exoneratingCounts,
    nCertify: 1000,
    alphaFamily: { numerator: 5, denominator: 100 },
    nMax: 1,
    pDel: { numerator: 9, denominator: 10 },
  });
  const effective = resolveCertifiedEpistemicPosture({
    signedLabel: 'poison_confirmed',
    certificateDecision: exoneratingDecision,
  });
  assert.equal(exoneratingDecision.selected_class, 'unverified');
  assert.equal(effective.effective_label, 'poison_confirmed');
  assert.equal(effective.exoneration_blocked, true);
  assert.equal(effective.persistent_transition_authorized, false);
});

test('classification binding requires the semantically appropriate claim side', () => {
  const support = assertion({ ordinal: 401, relation: 'supports' });
  const refute = assertion({
    ordinal: 402,
    relation: 'refutes',
    previous: support.assertion_sha256,
  });
  const poison = buildEvidenceBoundExplicitClassification({
    label: 'poison_confirmed',
    confidenceMilli: 990,
    assertions: [support, refute],
  });
  const exoneration = buildEvidenceBoundExplicitClassification({
    label: 'poison_refuted',
    confidenceMilli: 980,
    assertions: [support, refute],
  });
  assert.equal(poison.evidence_sha256, exoneration.evidence_sha256);
  assert.equal(poison.evidence_assertion_binding.conflict_present, true);
  assert.throws(() => buildEvidenceBoundExplicitClassification({
    label: 'poison_refuted',
    confidenceMilli: 980,
    assertions: [support],
  }), /missing_refutation/);
});

function mockSignedLedger() {
  const rows = [];
  let sequence = 0;
  const client = { query: async () => ({ rows: [] }) };
  const listEventsFn = async (_company, key) => rows.filter((row) => row.key === key);
  const readEventFn = async (id) => {
    const row = rows.find((entry) => entry.id === id);
    if (!row) throw new Error('mock_event_missing');
    return row;
  };
  const logEventFn = async (_company, _subject, operation, key, metadata, parentEventId) => {
    sequence += 1;
    const id = randomUUID();
    const mutationHash = Buffer.from(sha(`${sequence}:${id}`), 'hex');
    rows.push({
      id,
      operation,
      key,
      metadata: structuredClone(metadata),
      parent_event_id: parentEventId,
      mutation_hash: mutationHash,
      ledger_seq: sequence,
    });
    return { event_id: id, mutation_hash: mutationHash.toString('hex') };
  };
  return { rows, client, listEventsFn, readEventFn, logEventFn };
}

test('signed assertion owner appends, reuses, and independently replays one linear chain', async () => {
  const ledger = mockSignedLedger();
  const first = assertion({ ordinal: 501, relation: 'supports' });
  const second = assertion({
    ordinal: 502,
    relation: 'refutes',
    evidenceType: 'external_reference',
    previous: first.assertion_sha256,
  });
  const dependencies = {
    listEventsFn: ledger.listEventsFn,
    readEventFn: ledger.readEventFn,
    logEventFn: ledger.logEventFn,
  };
  const base = {
    client: ledger.client,
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
  };
  const firstCommit = await commitMemoryEpistemicEvidenceAssertion(
    { ...base, assertion: first },
    dependencies,
  );
  const reused = await commitMemoryEpistemicEvidenceAssertion(
    { ...base, assertion: first },
    dependencies,
  );
  const secondCommit = await commitMemoryEpistemicEvidenceAssertion(
    { ...base, assertion: second },
    dependencies,
  );
  assert.equal(firstCommit.appended, true);
  assert.equal(reused.reused, true);
  assert.equal(secondCommit.evidence_chain.assertion_count, 2);
  assert.equal(ledger.rows.length, 2);
  assert.equal(ledger.rows[0].operation, MEMORY_EPISTEMIC_EVIDENCE_ASSERTED_OPERATION);
  assert.equal(ledger.rows[1].parent_event_id, ledger.rows[0].id);
  const verified = await verifyPersistedMemoryEpistemicEvidenceChain({
    companyId: 'hom',
    hypothesisSha256: hypothesis.hypothesis_sha256,
    expectedEvidenceRootSha256: secondCommit.evidence_chain.evidence_root_sha256,
  }, {
    listEventsFn: ledger.listEventsFn,
    readEventFn: ledger.readEventFn,
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.event_count, 2);
  assert.equal(verified.evidence_chain.supporting_claim_records.length, 1);
  assert.equal(verified.evidence_chain.refuting_claim_records.length, 1);
});

test('persisted verifier fails closed when the requested hypothesis has no signed assertions', async () => {
  await assert.rejects(() => verifyPersistedMemoryEpistemicEvidenceChain({
    companyId: 'hom',
    hypothesisSha256: hypothesis.hypothesis_sha256,
  }, {
    listEventsFn: async () => [],
    readEventFn: async () => { throw new Error('unexpected_read'); },
  }), /persisted_chain_missing/);
});

test('signed assertion verifier detects event forks and root tampering', async () => {
  const ledger = mockSignedLedger();
  const first = assertion({ ordinal: 601, relation: 'supports' });
  const dependencies = {
    listEventsFn: ledger.listEventsFn,
    readEventFn: ledger.readEventFn,
    logEventFn: ledger.logEventFn,
  };
  await commitMemoryEpistemicEvidenceAssertion({
    client: ledger.client,
    companyId: 'hom',
    subjectAgentId: 'housekeeper',
    assertion: first,
  }, dependencies);
  const fork = structuredClone(ledger.rows[0]);
  fork.id = randomUUID();
  fork.ledger_seq = 2;
  fork.mutation_hash = Buffer.from(sha('fork'), 'hex');
  ledger.rows.push(fork);
  await assert.rejects(() => verifyPersistedMemoryEpistemicEvidenceChain({
    companyId: 'hom',
    hypothesisSha256: hypothesis.hypothesis_sha256,
  }, {
    listEventsFn: ledger.listEventsFn,
    readEventFn: ledger.readEventFn,
  }), /event_chain_invalid|duplicate_assertion/);
  ledger.rows.pop();
  ledger.rows[0].metadata.evidence_root_sha256 = sha('tampered-root');
  await assert.rejects(() => verifyPersistedMemoryEpistemicEvidenceChain({
    companyId: 'hom',
    hypothesisSha256: hypothesis.hypothesis_sha256,
  }, {
    listEventsFn: ledger.listEventsFn,
    readEventFn: ledger.readEventFn,
  }), /event_root_mismatch/);
});
