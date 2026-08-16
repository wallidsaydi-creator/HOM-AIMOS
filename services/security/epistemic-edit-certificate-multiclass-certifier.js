// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: dormant N1-D3 evaluation owner only
// → Calls: fixed deletion-plan owner, pure classifier kernel, seven-state math
// Pipeline: SECURITY | Dormant seven-state CERT-ED transcript owner
// Paper: Huang et al., CERT-ED, Findings of EMNLP 2024, Theorem 2
// ─────────────────────────────────────────────────────────────────────────────

import { classifyRetainedMemoryEpistemics } from './memory-epistemic-classifier-kernel.js';
import {
  applyDeletionBitmap,
  buildEpistemicCertificateInputCommitment,
  canonicalizeEditTokens,
  normalizeProbabilityRational,
  reconstructEditTokens,
  sha256Canonical,
} from './epistemic-edit-certificate-math.js';
import {
  generateEpistemicDeletionPlan,
  verifyEpistemicDeletionPlan,
} from './epistemic-edit-certifier.js';
import {
  EPISTEMIC_MULTICLASS_FORMULA_VERSION,
  computeConservativeMulticlassCertificateForSelectedClass,
  resolveCertifiedEpistemicPosture,
  selectUniqueEpistemicTopClass,
} from './epistemic-edit-certificate-multiclass-math.js';
import {
  MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
  MEMORY_EPISTEMIC_LABELS_V2,
  projectEpistemicLabelExact,
} from './memory-epistemic-evidence-assertion.js';

export const EPISTEMIC_MULTICLASS_CERTIFICATE_SCHEMA =
  'aimos.epistemic-multiclass-edit-certificate/v1';
export const EPISTEMIC_MULTICLASS_CERTIFIER_VERSION =
  'aimos-epistemic-multiclass-edit-certifier/v1';

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function emptyCounts() {
  return Object.fromEntries(MEMORY_EPISTEMIC_LABELS_V2.map((label) => [label, 0]));
}

function runSamples({ memory, peers, tokens, bitmaps }) {
  const rows = [];
  const counts = emptyCounts();
  for (const bitmap of bitmaps) {
    const value = reconstructEditTokens(applyDeletionBitmap(tokens, bitmap));
    const output = projectEpistemicLabelExact(
      classifyRetainedMemoryEpistemics({ ...memory, value }, peers, null).label,
    );
    counts[output] += 1;
    rows.push(Object.freeze({ bitmap, output }));
  }
  return Object.freeze({ rows: Object.freeze(rows), counts: Object.freeze(counts) });
}

function exactParameters({ pDel, nSelect, nCertify, alphaFamily, nMax, resourceCaps }) {
  const maxTokens = Number(resourceCaps?.maxTokens ?? 4096);
  const maxPeers = Number(resourceCaps?.maxPeers ?? 256);
  const maxSamples = Number(resourceCaps?.maxSamples ?? 10_000);
  assert(Number.isSafeInteger(nSelect) && nSelect > 0,
    'epistemic_multiclass_certificate_n_select_invalid');
  assert(Number.isSafeInteger(nCertify) && nCertify > 0,
    'epistemic_multiclass_certificate_n_certify_invalid');
  assert(Number.isSafeInteger(nMax) && nMax > 0,
    'epistemic_multiclass_certificate_n_max_invalid');
  assert(Number.isSafeInteger(maxTokens) && maxTokens > 0
    && Number.isSafeInteger(maxPeers) && maxPeers >= 0
    && Number.isSafeInteger(maxSamples) && maxSamples > 0,
  'epistemic_multiclass_certificate_resource_caps_invalid');
  return Object.freeze({
    p_del: normalizeProbabilityRational(pDel, 'p_del'),
    n_select: nSelect,
    n_certify: nCertify,
    alpha_family: normalizeProbabilityRational(alphaFamily, 'alpha_family'),
    n_max: nMax,
    resource_caps: Object.freeze({
      max_tokens: maxTokens,
      max_peers: maxPeers,
      max_samples: maxSamples,
    }),
  });
}

export function generateEpistemicMulticlassDeletionPlan(options = {}) {
  return generateEpistemicDeletionPlan(options);
}

export function verifyEpistemicMulticlassDeletionPlan(options = {}) {
  return verifyEpistemicDeletionPlan(options);
}

export function certifyEpistemicMulticlassEditRobustnessFromPlan({
  memory,
  peers = [],
  classifierSourceSha256,
  signedLabel,
  baseDecisionSha256,
  deletionPlan,
  pDel = { numerator: 9, denominator: 10 },
  nSelect = 1000,
  nCertify = 4000,
  alphaFamily = { numerator: 5, denominator: 100 },
  nMax = 100,
  resourceCaps = {},
} = {}) {
  const signed = projectEpistemicLabelExact(signedLabel);
  assert(/^[0-9a-f]{64}$/.test(String(baseDecisionSha256 || '')),
    'epistemic_multiclass_certificate_base_decision_hash_invalid');
  const parameters = exactParameters({
    pDel, nSelect, nCertify, alphaFamily, nMax, resourceCaps,
  });
  const tokens = canonicalizeEditTokens(memory?.value);
  assert(tokens.length <= parameters.resource_caps.max_tokens
    && peers.length <= parameters.resource_caps.max_peers
    && nSelect + nCertify <= parameters.resource_caps.max_samples,
  'epistemic_multiclass_certificate_resource_cap_exceeded');
  verifyEpistemicDeletionPlan({
    memory,
    peers,
    classifierSourceSha256,
    deletionPlan,
    pDel: parameters.p_del,
    nSelect,
    nCertify,
  });

  const selection = runSamples({
    memory,
    peers,
    tokens,
    bitmaps: deletionPlan.selection_bitmaps,
  });
  const selected = selectUniqueEpistemicTopClass(selection.counts);
  const certification = runSamples({
    memory,
    peers,
    tokens,
    bitmaps: deletionPlan.certification_bitmaps,
  });
  const math = selected.selected_class
    ? computeConservativeMulticlassCertificateForSelectedClass({
        counts: certification.counts,
        selectedClass: selected.selected_class,
        nCertify,
        alphaFamily: parameters.alpha_family,
        nMax,
        pDel: parameters.p_del,
      })
    : Object.freeze({
        projection_version: MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
        formula_version: EPISTEMIC_MULTICLASS_FORMULA_VERSION,
        outcome: 'abstain',
        reason: 'selection_tie',
        selected_class: null,
        tie_classes: selected.tie_classes,
        radius: null,
        counts: certification.counts,
      });
  const effectivePosture = resolveCertifiedEpistemicPosture({
    signedLabel: signed,
    certificateDecision: math,
  });
  const input = Object.freeze({
    ...buildEpistemicCertificateInputCommitment(memory, peers, classifierSourceSha256),
    signed_label: signed,
    base_decision_sha256: baseDecisionSha256,
    exact_projection_version: MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
  });
  const transcripts = Object.freeze({
    selection: selection.rows,
    certification: certification.rows,
    selection_sha256: sha256Canonical(selection.rows),
    certification_sha256: sha256Canonical(certification.rows),
  });
  const decision = Object.freeze({
    ...math,
    selection_counts: selection.counts,
    certification_counts: certification.counts,
    effective_posture: effectivePosture,
    persistent_transition_authorized: false,
  });
  const body = {
    schema: EPISTEMIC_MULTICLASS_CERTIFICATE_SCHEMA,
    certifier_version: EPISTEMIC_MULTICLASS_CERTIFIER_VERSION,
    projection_version: MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
    formula_version: EPISTEMIC_MULTICLASS_FORMULA_VERSION,
    input,
    parameters,
    deletion_plan_sha256: deletionPlan.plan_sha256,
    transcripts,
    decision,
    automatic_policy_activation: false,
  };
  return Object.freeze({ ...body, certificate_sha256: sha256Canonical(body) });
}
