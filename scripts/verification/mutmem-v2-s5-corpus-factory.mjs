// Producer-side fixture factory for the complete MutMem V2-S5 corpus.
//
// The factory is intentionally authority-free and synthetic. It reuses the
// exact S4 producer helpers, generates purpose-bound keys only in memory, and
// never reads a database, Keychain, credential, live memory, route, model, or
// policy. The disposable-Genesis custody runner binds the completed corpus to
// production execution separately; that receipt is evidence, never authority.

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { verifyCognitiveWeightEvidenceBundle } from '../../services/security/protocol/cognitive-weight-evidence.js';
import { recallCorpusRoot } from '../../services/security/protocol/mutmem-protocol.js';
import { verifyRecallBundle, verifyRecallCorpus } from '../../verifiers/mutmem-node/recall-verifier.mjs';
import {
  createDefaultBundle,
  createFocusedVectors,
  createSignedBaselineBundle,
  createTransitionBundle,
  nodeVerdict,
} from './mutmem-v2-s4-fixture-factory.mjs';
import {
  makeRecallBundle,
  makeRecallCorpus,
} from './mutmem-v2-s4-recall-fixture-factory.mjs';

export const S5_SCHEMA = 'hom.aimos.mutmem-v2-s5-conformance-vector/v1';
export const S5_CORPUS_SCHEMA = 'hom.aimos.mutmem-v2-s5-conformance-corpus/v1';

const CLASS_IDS = Object.freeze(Array.from(
  { length: 28 },
  (_, index) => `MM-CV-${String(index + 1).padStart(3, '0')}`,
));

const CLASS_NAMES = Object.freeze({
  'MM-CV-001': 'default_genesis',
  'MM-CV-002': 'signed_nondefault_baseline',
  'MM-CV-003': 'upward_transition',
  'MM-CV-004': 'downward_transition',
  'MM-CV-005': 'good_bad_good_reversibility',
  'MM-CV-006': 'noop_transition',
  'MM-CV-007': 'lower_bound_violation',
  'MM-CV-008': 'upper_bound_violation',
  'MM-CV-009': 'stale_state_discontinuity',
  'MM-CV-010': 'duplicate_genesis',
  'MM-CV-011': 'forked_predecessor',
  'MM-CV-012': 'disconnected_projection',
  'MM-CV-013': 'cyclic_projection',
  'MM-CV-014': 'cross_memory_replay',
  'MM-CV-015': 'cross_tenant_replay',
  'MM-CV-016': 'content_commitment_tamper',
  'MM-CV-017': 'provenance_tamper',
  'MM-CV-018': 'transition_signature_tamper',
  'MM-CV-019': 'revoked_signer_epoch',
  'MM-CV-020': 'stale_future_signer_epoch',
  'MM-CV-021': 'terminal_weight_divergence',
  'MM-CV-022': 'recall_leaf_tamper',
  'MM-CV-023': 'recall_order_tamper',
  'MM-CV-024': 'corpus_member_omission',
  'MM-CV-025': 'unknown_major_schema',
  'MM-CV-026': 'noncanonical_encoding',
  'MM-CV-027': 'missing_mandatory_evidence',
  'MM-CV-028': 'unknown_critical_field',
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  return structuredClone(value);
}

function normalizeReason(reason) {
  if (reason === 'canonicalJson: depth limit exceeded') return 'canonical_json_depth_limit';
  return reason;
}

function flipHexByte(value) {
  return `${value.slice(0, 2) === '00' ? '01' : '00'}${value.slice(2)}`;
}

function alignSql(bundle, { reason, chainLength = 0, signatures = 0 } = {}) {
  bundle.sql_records[0] = {
    ...bundle.sql_records[0],
    ok: false,
    chain_length: chainLength,
    signatures_verified: signatures,
    reason,
  };
  return bundle;
}

function cognitiveVector({
  id,
  expected,
  reason,
  invariant,
  bundle,
  parent = null,
  mutation = 'none',
  expectedRootBehavior = 'reconstruct_exactly',
  family = id,
  seed = `${id.toLowerCase()}-v1`,
  independentReason = reason,
}) {
  return {
    vector_id: id,
    class_id: id.slice(0, 9),
    class_name: CLASS_NAMES[id.slice(0, 9)] ?? family,
    fixture_family_id: family,
    deterministic_seed_id: seed,
    bundle_kind: 'cognitive',
    expected_verdict: expected,
    expected_primary_reason: reason,
    independent_expected_primary_reason: independentReason,
    permitted_secondary_reasons: [],
    invariant,
    parent_vector_id: parent,
    exact_mutation: mutation,
    expected_root_behavior: expectedRootBehavior,
    document: bundle,
  };
}

function recallVector({
  id,
  expected,
  reason,
  invariant,
  bundle,
  parent = null,
  mutation = 'none',
  family = id,
  seed = `${id.toLowerCase()}-v1`,
  independentReason = reason,
}) {
  return {
    vector_id: id,
    class_id: id.slice(0, 9),
    class_name: CLASS_NAMES[id.slice(0, 9)] ?? family,
    fixture_family_id: family,
    deterministic_seed_id: seed,
    bundle_kind: 'recall',
    expected_verdict: expected,
    expected_primary_reason: reason,
    independent_expected_primary_reason: independentReason,
    permitted_secondary_reasons: [],
    invariant,
    parent_vector_id: parent,
    exact_mutation: mutation,
    expected_root_behavior: expected === 'valid' ? 'reconstruct_exactly' : 'must_not_validate',
    document: bundle,
  };
}

function corpusVector({
  id,
  expected,
  reason,
  invariant,
  corpus,
  parent = null,
  mutation = 'none',
  family = id,
  seed = `${id.toLowerCase()}-v1`,
  independentReason = reason,
}) {
  return {
    vector_id: id,
    class_id: id.slice(0, 9),
    class_name: CLASS_NAMES[id.slice(0, 9)] ?? family,
    fixture_family_id: family,
    deterministic_seed_id: seed,
    bundle_kind: 'recall_corpus',
    expected_verdict: expected,
    expected_primary_reason: reason,
    independent_expected_primary_reason: independentReason,
    permitted_secondary_reasons: [],
    invariant,
    parent_vector_id: parent,
    exact_mutation: mutation,
    expected_root_behavior: expected === 'valid' ? 'reconstruct_exactly' : 'must_not_validate',
    document: corpus,
  };
}

function focusedById(id) {
  const vector = createFocusedVectors().find((entry) => entry.id === id);
  if (!vector) throw new Error(`mutmem_v2_s5_s4_parent_missing:${id}`);
  return clone(vector.bundle);
}

function cognitiveResult(bundle) {
  const verdict = nodeVerdict(bundle);
  let fallbackSha = null;
  try {
    fallbackSha = sha256(Buffer.from(canonicalJson(bundle), 'utf8'));
  } catch {
    fallbackSha = sha256(Buffer.from(JSON.stringify(bundle), 'utf8'));
  }
  return {
    verdict: verdict.verdict,
    primary_reason: normalizeReason(verdict.reason),
    proof_root: verdict.proof?.proofRoot?.toString('hex') ?? null,
    bundle_sha256: verdict.proof?.bundleSha256?.toString('hex') ?? fallbackSha,
    terminal_weight_milli: verdict.proof?.records?.at(-1)?.ok
      ? bundle.memories.at(-1)?.retrieval_weight_milli ?? null
      : null,
  };
}

export function productionVerdict(vector) {
  if (vector.bundle_kind === 'cognitive') return cognitiveResult(vector.document);
  if (vector.bundle_kind === 'recall') {
    const result = verifyRecallBundle(vector.document);
    return {
      verdict: result.verdict,
      primary_reason: result.primary_reason,
      proof_root: result.merkle_root ?? null,
      bundle_sha256: result.bundle_sha256
        ?? sha256(Buffer.from(canonicalJson(vector.document), 'utf8')),
      terminal_weight_milli: null,
    };
  }
  if (vector.bundle_kind === 'recall_corpus') {
    const result = verifyRecallCorpus(vector.document);
    return {
      verdict: result.verdict,
      primary_reason: result.primary_reason,
      proof_root: result.corpus_root ?? null,
      bundle_sha256: sha256(Buffer.from(canonicalJson(vector.document), 'utf8')),
      terminal_weight_milli: null,
    };
  }
  throw new Error(`mutmem_v2_s5_bundle_kind_invalid:${vector.bundle_kind}`);
}

function cycleVector() {
  const bundle = createTransitionBundle([1, 1.2, 1.4, 1.6]);
  const rows = bundle.memories[0].projections;
  rows[0].previous_projection_hash = rows[2].projection_hash;
  rows[2].previous_projection_hash = rows[1].projection_hash;
  return alignSql(bundle, { reason: 'cognitive_projection_genesis_invalid' });
}

function contentTamper() {
  const bundle = createSignedBaselineBundle();
  bundle.memories[0].content_hash = flipHexByte(bundle.memories[0].content_hash);
  alignSql(bundle, { reason: 'baseline_binding_invalid' });
  return bundle;
}

function recallOmissionCorpus() {
  const corpus = makeRecallCorpus([
    makeRecallBundle({ id: 'MM-CV-024-A', memoryCount: 1 }),
    makeRecallBundle({ id: 'MM-CV-024-B', memoryCount: 3 }),
  ]);
  corpus.members.pop();
  return corpus;
}

export function createRequiredVectors() {
  const vectors = [];
  const push = (vector) => vectors.push(vector);

  push(cognitiveVector({
    id: 'MM-CV-001', expected: 'valid', reason: null,
    invariant: 'one protocol-default genesis reaches the declared terminal weight',
    bundle: createDefaultBundle(),
  }));
  push(cognitiveVector({
    id: 'MM-CV-002', expected: 'valid', reason: null,
    invariant: 'signed non-default baseline binds purpose, epoch, content, event, and initial weight',
    bundle: createSignedBaselineBundle(),
  }));
  push(cognitiveVector({
    id: 'MM-CV-003', expected: 'valid', reason: null,
    invariant: 'exact predecessor and positive delta are retained',
    bundle: createTransitionBundle([1, 1.3]),
  }));
  push(cognitiveVector({
    id: 'MM-CV-004', expected: 'valid', reason: null,
    invariant: 'negative delta is retained without deletion or decay',
    bundle: createTransitionBundle([1, 0.9]),
  }));
  push(cognitiveVector({
    id: 'MM-CV-005', expected: 'valid', reason: null,
    invariant: 'good-bad-good history remains complete and reversible',
    bundle: createTransitionBundle([1, 1.3, 0.9, 1.2]),
  }));

  const noop = createTransitionBundle([1, 1.1]);
  const noopRow = noop.memories[0].projections[0];
  noopRow.new_weight_milli = noopRow.old_weight_milli;
  noopRow.new_weight_float4 = noopRow.old_weight_float4;
  alignSql(noop, { reason: 'projection_display_invalid' });
  push(cognitiveVector({
    id: 'MM-CV-006', expected: 'invalid', reason: 'projection_display_invalid',
    invariant: 'nontrivial transition evidence cannot encode an equal old and new weight',
    bundle: noop, parent: 'MM-CV-003', mutation: 'set new_weight_milli and float4 equal to old weight',
  }));

  const lower = createTransitionBundle([1, 0.1]);
  lower.memories[0].projections[0].new_weight_milli = 99;
  alignSql(lower, { reason: 'projection_display_invalid' });
  push(cognitiveVector({
    id: 'MM-CV-007', expected: 'invalid', reason: 'projection_display_invalid',
    invariant: 'weight below 0.1 fails closed', bundle: lower,
    parent: 'MM-CV-004', mutation: 'set new_weight_milli to 99',
  }));

  const upper = createTransitionBundle([1, 3]);
  upper.memories[0].projections[0].new_weight_milli = 3001;
  alignSql(upper, { reason: 'projection_display_invalid' });
  push(cognitiveVector({
    id: 'MM-CV-008', expected: 'invalid', reason: 'projection_display_invalid',
    invariant: 'weight above 3.0 fails closed', bundle: upper,
    parent: 'MM-CV-003', mutation: 'set new_weight_milli to 3001',
  }));

  push(cognitiveVector({
    id: 'MM-CV-009', expected: 'invalid', reason: 'continuity_break',
    invariant: 'declared old weight must equal predecessor terminal weight',
    bundle: focusedById('S4-CV-011'), parent: 'MM-CV-005',
    mutation: 'change the second projection old weight without rewriting history',
  }));
  push(cognitiveVector({
    id: 'MM-CV-010', expected: 'invalid', reason: 'cognitive_projection_genesis_invalid',
    invariant: 'a chain has exactly one root projection',
    bundle: focusedById('S4-CV-012'), parent: 'MM-CV-005',
    mutation: 'clear the second projection predecessor',
  }));
  push(cognitiveVector({
    id: 'MM-CV-011', expected: 'invalid', reason: 'cognitive_projection_fork',
    invariant: 'one predecessor cannot authorize two successors',
    bundle: focusedById('S4-CV-013'), parent: 'MM-CV-005',
    mutation: 'reuse one predecessor hash for two successors',
  }));
  push(cognitiveVector({
    id: 'MM-CV-012', expected: 'invalid', reason: 'cognitive_projection_disconnected',
    invariant: 'every projection is reachable from the one root',
    bundle: focusedById('S4-CV-014'), parent: 'MM-CV-004',
    mutation: 'replace a predecessor hash with an absent node hash',
  }));
  push(cognitiveVector({
    id: 'MM-CV-013', expected: 'invalid', reason: 'cognitive_projection_genesis_invalid',
    permitted_secondary_reasons: ['cognitive_projection_cycle'],
    invariant: 'cyclic topology terminates and fails; a closed cycle has no valid genesis',
    bundle: cycleVector(), parent: 'MM-CV-005',
    mutation: 'link the first projection predecessor to the terminal projection',
  }));

  const memoryReplay = createTransitionBundle([1, 1.3]);
  memoryReplay.memories[0].memory_id = '44444444-4444-4444-8444-444444444444';
  alignSql(memoryReplay, { reason: 'provenance_event_type_invalid' });
  push(cognitiveVector({
    id: 'MM-CV-014', expected: 'invalid', reason: 'provenance_event_type_invalid',
    invariant: 'signed transition cannot be replayed onto another memory',
    bundle: memoryReplay, parent: 'MM-CV-003', mutation: 'change enclosing memory identity only',
  }));

  const tenantReplay = createTransitionBundle([1, 1.3]);
  tenantReplay.company_id = 'tenant-b';
  tenantReplay.memories[0].company_id = 'tenant-b';
  alignSql(tenantReplay, { reason: 'provenance_event_type_invalid' });
  push(cognitiveVector({
    id: 'MM-CV-015', expected: 'invalid', reason: 'provenance_event_type_invalid',
    invariant: 'signed transition cannot be replayed into another tenant scope',
    bundle: tenantReplay, parent: 'MM-CV-003', mutation: 'change corpus and memory tenant only',
  }));

  const content = contentTamper();
  push(cognitiveVector({
    id: 'MM-CV-016', expected: 'invalid', reason: 'baseline_binding_invalid',
    invariant: 'changed live content breaks its signed non-default baseline binding',
    bundle: content, parent: 'MM-CV-002', mutation: 'change live memory content commitment without rewriting signed baseline',
    expectedRootBehavior: 'must_not_validate',
  }));
  push(cognitiveVector({
    id: 'MM-CV-017', expected: 'invalid', reason: 'provenance_signed_body_content_hash_mismatch',
    invariant: 'provenance content commitment is exact',
    bundle: focusedById('S4-CV-009'), parent: 'MM-CV-003',
    mutation: 'flip one provenance content-hash byte',
  }));
  push(cognitiveVector({
    id: 'MM-CV-018', expected: 'invalid', reason: 'transition_signature_invalid',
    invariant: 'transition signature covers the exact transition commitment',
    bundle: focusedById('S4-CV-008'), parent: 'MM-CV-003',
    mutation: 'flip one transition-signature byte',
  }));

  const revoked = createTransitionBundle([1, 1.3], { revokedAt: 1_786_447_319 });
  alignSql(revoked, { reason: 'provenance_signer_revoked_before_evidence' });
  push(cognitiveVector({
    id: 'MM-CV-019', expected: 'invalid', reason: 'provenance_signer_revoked_before_evidence',
    invariant: 'correctly signed evidence under a signer epoch already revoked is rejected',
    bundle: revoked, parent: 'MM-CV-003', mutation: 'attach a valid master-signed revocation one second before signed_at',
  }));

  const stale = createTransitionBundle([1, 1.3], { signerValidUntil: 1_786_447_319 });
  alignSql(stale, { reason: 'provenance_cert_expired' });
  push(cognitiveVector({
    id: 'MM-CV-020', expected: 'invalid', reason: 'provenance_cert_expired',
    invariant: 'signature time must lie in the retained signer epoch',
    bundle: stale, parent: 'MM-CV-003', mutation: 'end declared signer epoch before signed_at',
  }));
  push(cognitiveVector({
    id: 'MM-CV-021', expected: 'invalid', reason: 'terminal_weight_mismatch',
    invariant: 'declared terminal weight equals verified trajectory terminal',
    bundle: focusedById('S4-CV-010'), parent: 'MM-CV-003',
    mutation: 'change declared memory terminal weight only',
  }));

  const recallParent = makeRecallBundle({ id: 'MM-CV-022-PARENT', memoryCount: 4 });
  const recallLeaf = clone(recallParent);
  recallLeaf.recall_receipt.evidence[0].live_content_hash = '00'.repeat(32);
  push(recallVector({
    id: 'MM-CV-022', expected: 'invalid', reason: 'recall_receipt_memory_binding_invalid:0',
    invariant: 'changed disclosed evidence breaks retained recall binding',
    bundle: recallLeaf, mutation: 'replace first disclosed live content hash',
  }));
  const recallOrder = clone(recallParent);
  recallOrder.recall_receipt.evidence.reverse();
  push(recallVector({
    id: 'MM-CV-023', expected: 'invalid', reason: 'recall_receipt_memory_binding_invalid:0',
    invariant: 'leaf order is part of the receipt commitment',
    bundle: recallOrder, mutation: 'reverse evidence order without re-signing',
  }));
  push(corpusVector({
    id: 'MM-CV-024', expected: 'invalid', reason: 'recall_corpus_intended_n_invalid',
    invariant: 'intended-N and corpus root expose omission', corpus: recallOmissionCorpus(),
    mutation: 'remove one retained member while preserving intended_n',
  }));

  const major = createDefaultBundle();
  major.format.version = 2;
  push(cognitiveVector({
    id: 'MM-CV-025', expected: 'invalid', reason: 'cognitive_evidence_bundle_schema_invalid',
    invariant: 'unknown major schema fails before cryptographic acceptance',
    bundle: major, parent: 'MM-CV-001', mutation: 'set format.version to 2',
  }));
  const noncanonical = createDefaultBundle();
  noncanonical.memories[0].content_hash = `AB${noncanonical.memories[0].content_hash.slice(2)}`;
  push(cognitiveVector({
    id: 'MM-CV-026', expected: 'invalid', reason: 'cognitive_evidence_memory_content_invalid',
    invariant: 'mixed-case hexadecimal encoding is not canonical',
    bundle: noncanonical, parent: 'MM-CV-001', mutation: 'uppercase one hex commitment',
  }));
  const missing = makeRecallBundle({ id: 'MM-CV-027-PARENT', memoryCount: 1 });
  delete missing.recall_receipt.event_receipt;
  push(recallVector({
    id: 'MM-CV-027', expected: 'indeterminate', reason: 'recall_mandatory_evidence_missing',
    invariant: 'missing mandatory evidence is neither valid nor cryptographically invalid',
    bundle: missing, mutation: 'remove mandatory signed event receipt',
  }));
  const critical = createDefaultBundle();
  critical.critical_extension = { must_understand: true };
  push(cognitiveVector({
    id: 'MM-CV-028', expected: 'invalid', reason: 'cognitive_evidence_bundle_schema_invalid',
    invariant: 'unknown critical field cannot be silently ignored',
    bundle: critical, parent: 'MM-CV-001', mutation: 'append unknown must-understand field',
  }));

  const observed = new Set(vectors.map((vector) => vector.vector_id));
  if (vectors.length !== CLASS_IDS.length || CLASS_IDS.some((id) => !observed.has(id))) {
    throw new Error('mutmem_v2_s5_required_class_coverage_invalid');
  }
  return vectors;
}

export function createExpansionVectors() {
  const expansions = [
    cognitiveVector({
      id: 'MM-CV-005-A', family: 'history_cardinality', expected: 'valid', reason: null,
      invariant: 'an exact two-transition history reconstructs without omission',
      bundle: createTransitionBundle([1, 1.1, 1.2]),
    }),
    cognitiveVector({
      id: 'MM-CV-007-A', family: 'weight_boundaries', expected: 'valid', reason: null,
      invariant: 'exact lower bound is valid', bundle: createTransitionBundle([1, 0.1]),
    }),
    cognitiveVector({
      id: 'MM-CV-007-B', family: 'weight_boundaries', expected: 'valid', reason: null,
      invariant: 'one milli-unit above lower bound is valid', bundle: createTransitionBundle([1, 0.101]),
    }),
    cognitiveVector({
      id: 'MM-CV-008-A', family: 'weight_boundaries', expected: 'valid', reason: null,
      invariant: 'exact upper bound is valid', bundle: createTransitionBundle([1, 3]),
    }),
    cognitiveVector({
      id: 'MM-CV-008-B', family: 'weight_boundaries', expected: 'valid', reason: null,
      invariant: 'one milli-unit below upper bound is valid', bundle: createTransitionBundle([1, 2.999]),
    }),
  ];

  for (const [suffix, memoryCount] of [['A', 1], ['B', 3], ['C', 4]]) {
    expansions.push(recallVector({
      id: `MM-CV-022-${suffix}`,
      family: 'recall_leaf_cardinality', expected: 'valid', reason: null,
      invariant: `a ${memoryCount}-memory recall receipt reconstructs exactly`,
      bundle: makeRecallBundle({ id: `MM-CV-022-${suffix}`, memoryCount }),
    }));
  }

  const history = createTransitionBundle([1, 1.1, 1.2, 1.3]);
  for (const [suffix, index] of [['A', 0], ['B', 1], ['C', 2]]) {
    const tamper = clone(history);
    tamper.memories[0].projections[index].transition_signature = flipHexByte(
      tamper.memories[0].projections[index].transition_signature,
    );
    alignSql(tamper, { reason: 'transition_signature_invalid', chainLength: index, signatures: index });
    expansions.push(cognitiveVector({
      id: `MM-CV-018-${suffix}`,
      family: 'tamper_position', expected: 'invalid', reason: 'transition_signature_invalid',
      invariant: `transition-signature tamper at index ${index} is detected`, bundle: tamper,
      mutation: `flip signature byte at projection index ${index}`,
    }));
  }

  const publicKeyReplay = createTransitionBundle([1, 1.3]);
  const unrelatedAuthority = createTransitionBundle([1, 1.3]);
  publicKeyReplay.memories[0].projections[0].provenance.identity.pubkey_b64u =
    unrelatedAuthority.memories[0].projections[0].provenance.identity.pubkey_b64u;
  alignSql(publicKeyReplay, { reason: 'provenance_signer_certificate_row_mismatch' });
  expansions.push(cognitiveVector({
    id: 'MM-CV-018-D', family: 'replay_dimension', expected: 'invalid',
    reason: 'provenance_signer_certificate_row_mismatch',
    invariant: 'a retained certificate cannot be paired with a substituted public key',
    bundle: publicKeyReplay, parent: 'MM-CV-003',
    mutation: 'substitute an unrelated purpose-bound public key without changing the retained certificate',
  }));

  const purposeReplay = createTransitionBundle([1, 1.3]);
  purposeReplay.memories[0].projections[0].provenance.event_type = 'SAVE';
  alignSql(purposeReplay, { reason: 'provenance_signed_body_event_type_mismatch' });
  expansions.push(cognitiveVector({
    id: 'MM-CV-018-E', family: 'replay_dimension', expected: 'invalid',
    reason: 'provenance_signed_body_event_type_mismatch',
    invariant: 'signed transition evidence cannot be replayed under another protocol purpose',
    bundle: purposeReplay, parent: 'MM-CV-003',
    mutation: 'change the retained provenance event purpose from REWEIGHT to SAVE',
  }));

  const malformed = focusedById('S4-CV-003');
  let nested = malformed.event_streams[0].events[0].metadata;
  for (let depth = 0; depth < 34; depth += 1) {
    nested.critical_extension = {};
    nested = nested.critical_extension;
  }
  expansions.push(cognitiveVector({
    id: 'MM-CV-028-A', family: 'bounded_malformed', expected: 'invalid',
    reason: 'canonical_json_depth_limit',
    independentReason: 'canonical_json_depth_limit',
    invariant: 'hostile depth terminates at the declared bound', bundle: malformed,
    mutation: 'append 34 nested critical-extension objects',
  }));

  return expansions;
}

export function createS5Vectors() {
  return [...createRequiredVectors(), ...createExpansionVectors()];
}

export function buildS5Corpus(vectors = createS5Vectors()) {
  const records = vectors.map((vector, ordinal) => {
    const result = productionVerdict(vector);
    if (result.verdict !== vector.expected_verdict
        || result.primary_reason !== vector.expected_primary_reason) {
      throw new Error(
        `mutmem_v2_s5_expectation_mismatch:${vector.vector_id}:`
        + `${result.verdict}:${result.primary_reason}`,
      );
    }
    const raw = `${JSON.stringify(vector.document)}\n`;
    let canonicalBundleSha = null;
    try {
      canonicalBundleSha = sha256(Buffer.from(canonicalJson(vector.document), 'utf8'));
    } catch {
      canonicalBundleSha = null;
    }
    return {
      ordinal,
      vector_id: vector.vector_id,
      class_id: vector.class_id,
      class_name: vector.class_name,
      fixture_family_id: vector.fixture_family_id,
      deterministic_seed_id: vector.deterministic_seed_id,
      bundle_kind: vector.bundle_kind,
      filename: `${vector.vector_id}.json`,
      fixture_sha256: sha256(Buffer.from(raw, 'utf8')),
      canonical_bundle_sha256: canonicalBundleSha,
      expected_verdict: vector.expected_verdict,
      expected_primary_reason: vector.expected_primary_reason,
      independent_expected_primary_reason: vector.independent_expected_primary_reason,
      permitted_secondary_reasons: vector.permitted_secondary_reasons,
      invariant: vector.invariant,
      parent_vector_id: vector.parent_vector_id,
      exact_mutation: vector.exact_mutation,
      expected_root_behavior: vector.expected_root_behavior,
      production_result: result,
      producer_result_sha256: sha256(Buffer.from(canonicalJson(result), 'utf8')),
      raw,
      document: vector.document,
    };
  });
  const members = records.map(({ ordinal, vector_id, fixture_sha256 }) => ({
    ordinal, vector_id, fixture_sha256,
  }));
  const intendedN = records.length;
  const root = recallCorpusRoot({
    intendedN,
    members: members.map((member) => ({
      ordinal: member.ordinal,
      bundle_id: member.vector_id,
      bundle_sha256: member.fixture_sha256,
    })),
  }).toString('hex');
  return {
    schema: S5_CORPUS_SCHEMA,
    corpus_version: 1,
    scope: 'complete_v2_s5_production_conformance_corpus',
    class_catalog: CLASS_IDS,
    required_class_count: CLASS_IDS.length,
    intended_n: intendedN,
    observed_n: records.length,
    corpus_root: root,
    synthetic_purpose_bound_identities: true,
    private_keys_retained: false,
    live_aimos_memory_content_included: false,
    source_custody_required: true,
    purge_receipt_required: true,
    members: records,
  };
}

export function verifyS5CorpusStructure(corpus) {
  if (!corpus || corpus.schema !== S5_CORPUS_SCHEMA
      || corpus.required_class_count !== 28
      || corpus.intended_n !== corpus.observed_n
      || corpus.intended_n !== corpus.members?.length) {
    throw new Error('mutmem_v2_s5_corpus_shape_invalid');
  }
  const seen = new Set();
  const seenClasses = new Set();
  for (const [ordinal, member] of corpus.members.entries()) {
    if (member.ordinal !== ordinal || seen.has(member.vector_id)
        || member.fixture_sha256 !== sha256(Buffer.from(member.raw, 'utf8'))
        || member.raw !== `${JSON.stringify(member.document)}\n`) {
      throw new Error('mutmem_v2_s5_corpus_member_invalid');
    }
    if (member.canonical_bundle_sha256 !== null
        && member.canonical_bundle_sha256 !== sha256(Buffer.from(canonicalJson(member.document), 'utf8'))) {
      throw new Error('mutmem_v2_s5_corpus_member_canonical_hash_invalid');
    }
    const result = productionVerdict({ bundle_kind: member.bundle_kind, document: member.document });
    if (result.verdict !== member.expected_verdict
        || result.primary_reason !== member.expected_primary_reason) {
      throw new Error(`mutmem_v2_s5_corpus_expectation_invalid:${member.vector_id}`);
    }
    seen.add(member.vector_id);
    seenClasses.add(member.class_id);
  }
  if (CLASS_IDS.some((id) => !seenClasses.has(id))) {
    throw new Error('mutmem_v2_s5_corpus_class_coverage_invalid');
  }
  const root = recallCorpusRoot({
    intendedN: corpus.intended_n,
    members: corpus.members.map((member) => ({
      ordinal: member.ordinal,
      bundle_id: member.vector_id,
      bundle_sha256: member.fixture_sha256,
    })),
  }).toString('hex');
  if (root !== corpus.corpus_root) throw new Error('mutmem_v2_s5_corpus_root_invalid');
  return { valid: true, intended_n: corpus.intended_n, observed_n: corpus.members.length, corpus_root: root };
}

export function summarizeCorpus(corpus) {
  return {
    schema: corpus.schema,
    corpus_version: corpus.corpus_version,
    scope: corpus.scope,
    required_class_count: corpus.required_class_count,
    intended_n: corpus.intended_n,
    observed_n: corpus.observed_n,
    corpus_root: corpus.corpus_root,
    synthetic_purpose_bound_identities: corpus.synthetic_purpose_bound_identities,
    private_keys_retained: corpus.private_keys_retained,
    live_aimos_memory_content_included: corpus.live_aimos_memory_content_included,
    source_custody_required: corpus.source_custody_required,
    purge_receipt_required: corpus.purge_receipt_required,
    members: corpus.members.map((member) => {
      const { raw: _raw, document: _document, ...summary } = member;
      return summary;
    }),
  };
}

export function verifierSourceHashes() {
  return {
    production_owner_sha256: sha256(Buffer.from(
      verifyCognitiveWeightEvidenceBundle.toString(),
      'utf8',
    )),
    production_recall_owner_sha256: sha256(Buffer.from(
      `${verifyRecallBundle.toString()}\n${verifyRecallCorpus.toString()}`,
      'utf8',
    )),
  };
}

export const MUTMEM_V2_S5_CLASS_IDS = CLASS_IDS;
