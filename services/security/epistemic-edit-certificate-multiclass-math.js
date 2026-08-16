// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: ECR-4D-N1 isolated successor conformance and portable verifier
// → Calls: reviewed CERT-ED v1 bound + exact seven-state projection only
// Pipeline: SECURITY | Pure conservative multiclass CERT-ED successor math
// Paper: Huang et al., CERT-ED, Findings of EMNLP 2024, Theorem 2
// ─────────────────────────────────────────────────────────────────────────────

import {
  computeConservativeCertificateMath,
} from './epistemic-edit-certificate-math.js';
import {
  MEMORY_EPISTEMIC_LABELS_V2,
  MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
  projectEpistemicLabelExact,
  resolveEffectiveEpistemicState,
} from './memory-epistemic-evidence-assertion.js';

export const EPISTEMIC_MULTICLASS_FORMULA_VERSION = 'cert-ed-seven-state-conservative-runner-bound/v1';

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

export function normalizeEpistemicClassCounts(counts = {}, expectedTotal = null) {
  const normalized = {};
  let total = 0;
  for (const label of MEMORY_EPISTEMIC_LABELS_V2) {
    const value = Number(counts?.[label] || 0);
    assert(Number.isSafeInteger(value) && value >= 0, 'epistemic_multiclass_count_invalid');
    normalized[label] = value;
    total += value;
  }
  const unknown = Object.keys(counts || {}).filter((label) => !MEMORY_EPISTEMIC_LABELS_V2.includes(label));
  assert(unknown.length === 0, 'epistemic_multiclass_unknown_label');
  if (expectedTotal != null) {
    assert(total === Number(expectedTotal), 'epistemic_multiclass_denominator_mismatch');
  }
  return Object.freeze({ counts: Object.freeze(normalized), total });
}

export function selectUniqueEpistemicTopClass(counts = {}) {
  const normalized = normalizeEpistemicClassCounts(counts);
  let maximum = -1;
  let selected = [];
  for (const label of MEMORY_EPISTEMIC_LABELS_V2) {
    const value = normalized.counts[label];
    if (value > maximum) {
      maximum = value;
      selected = [label];
    } else if (value === maximum) {
      selected.push(label);
    }
  }
  return Object.freeze({
    selected_class: selected.length === 1 ? selected[0] : null,
    selected_count: selected.length === 1 ? maximum : null,
    tie_classes: Object.freeze(selected.length === 1 ? [] : selected),
    counts: normalized.counts,
    total: normalized.total,
  });
}

/**
 * Conservative multiclass reduction of CERT-ED Theorem 2.
 *
 * Let p_A be the selected class probability. Every runner-up probability p_B
 * is bounded above by the combined non-A mass: p_B <= 1 - p_A. Supplying
 * 1 - lower(p_A) to the previously reviewed binary bound is therefore sound
 * for an arbitrary finite label set, although it may abstain more often than
 * a tighter simultaneous per-class interval.
 */
export function computeConservativeMulticlassCertificate({
  counts,
  nCertify,
  alphaFamily,
  nMax,
  pDel,
  maxRadius = 100_000,
} = {}) {
  const normalized = normalizeEpistemicClassCounts(counts, nCertify);
  const selection = selectUniqueEpistemicTopClass(normalized.counts);
  if (!selection.selected_class) {
    return Object.freeze({
      projection_version: MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
      formula_version: EPISTEMIC_MULTICLASS_FORMULA_VERSION,
      outcome: 'abstain',
      reason: 'selection_tie',
      selected_class: null,
      tie_classes: selection.tie_classes,
      radius: null,
      counts: normalized.counts,
    });
  }
  return computeConservativeMulticlassCertificateForSelectedClass({
    counts: normalized.counts,
    selectedClass: selection.selected_class,
    nCertify,
    alphaFamily,
    nMax,
    pDel,
    maxRadius,
  });
}

/**
 * CERT-ED uses one Monte Carlo sample to select y and an independent sample to
 * estimate its probability. This entry point preserves that two-sample
 * boundary: selectedClass is fixed by the selection transcript, while counts
 * belong only to the certification transcript.
 *
 * The runner-up upper bound remains the conservative combined non-selected
 * mass. Since max_{y' != y} p(y') <= 1 - p(y), this is sound for the finite
 * seven-state output space and may only abstain more often than a tighter
 * simultaneous per-class interval.
 */
export function computeConservativeMulticlassCertificateForSelectedClass({
  counts,
  selectedClass,
  nCertify,
  alphaFamily,
  nMax,
  pDel,
  maxRadius = 100_000,
} = {}) {
  const normalized = normalizeEpistemicClassCounts(counts, nCertify);
  const selected = projectEpistemicLabelExact(selectedClass);
  const math = computeConservativeCertificateMath({
    selectedCount: normalized.counts[selected],
    nCertify,
    alphaFamily,
    nMax,
    pDel,
    maxRadius,
  });
  return Object.freeze({
    projection_version: MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
    formula_version: EPISTEMIC_MULTICLASS_FORMULA_VERSION,
    ...math,
    selected_class: selected,
    tie_classes: Object.freeze([]),
    counts: normalized.counts,
    runner_upper_bound: 'combined_non_selected_mass',
  });
}

export function resolveCertifiedEpistemicPosture({
  signedLabel,
  certificateDecision,
} = {}) {
  assert(certificateDecision && typeof certificateDecision === 'object',
    'epistemic_multiclass_certificate_decision_missing');
  if (certificateDecision.outcome !== 'certified' || !certificateDecision.selected_class) {
    const signed = projectEpistemicLabelExact(signedLabel);
    return Object.freeze({
      certificate_outcome: 'abstain',
      selected_class: null,
      signed_label: signed,
      effective_label: signed,
      persistent_transition_authorized: false,
    });
  }
  return Object.freeze({
    certificate_outcome: 'certified',
    selected_class: certificateDecision.selected_class,
    ...resolveEffectiveEpistemicState({
      signedLabel,
      detectorLabel: certificateDecision.selected_class,
    }),
  });
}
