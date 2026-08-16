// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: dormant N1-D3 evaluation owner and read-only verification
// → Calls: pure classifier kernel, seven-state math, commitment math
// Pipeline: SECURITY | Portable seven-state CERT-ED transcript replay verifier
// Paper: Huang et al., CERT-ED, Findings of EMNLP 2024, Theorem 2
// ─────────────────────────────────────────────────────────────────────────────

import { classifyRetainedMemoryEpistemics } from './memory-epistemic-classifier-kernel.js';
import {
  applyDeletionBitmap,
  buildEpistemicCertificateInputCommitment,
  canonicalizeEditTokens,
  reconstructEditTokens,
  sha256Canonical,
} from './epistemic-edit-certificate-math.js';
import {
  EPISTEMIC_MULTICLASS_CERTIFICATE_SCHEMA,
  EPISTEMIC_MULTICLASS_CERTIFIER_VERSION,
} from './epistemic-edit-certificate-multiclass-certifier.js';
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

function fail(reason) {
  return Object.freeze({ valid: false, reason });
}

function replay(rows, memory, peers, tokens) {
  const counts = Object.fromEntries(MEMORY_EPISTEMIC_LABELS_V2.map((label) => [label, 0]));
  for (const row of rows) {
    if (!row || !MEMORY_EPISTEMIC_LABELS_V2.includes(row.output)) {
      throw new Error('multiclass_transcript_output_invalid');
    }
    const value = reconstructEditTokens(applyDeletionBitmap(tokens, row.bitmap));
    const output = projectEpistemicLabelExact(
      classifyRetainedMemoryEpistemics({ ...memory, value }, peers, null).label,
    );
    if (output !== row.output) throw new Error('multiclass_transcript_output_mismatch');
    counts[output] += 1;
  }
  return Object.freeze(counts);
}

export function verifyEpistemicMulticlassEditCertificate({
  certificate,
  memory,
  peers = [],
  expectedClassifierSourceSha256,
  expectedSignedLabel,
  expectedBaseDecisionSha256,
} = {}) {
  try {
    if (!certificate || certificate.schema !== EPISTEMIC_MULTICLASS_CERTIFICATE_SCHEMA) {
      return fail('schema_invalid');
    }
    if (certificate.certifier_version !== EPISTEMIC_MULTICLASS_CERTIFIER_VERSION
      || certificate.projection_version !== MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION
      || certificate.formula_version !== EPISTEMIC_MULTICLASS_FORMULA_VERSION) {
      return fail('implementation_identity_invalid');
    }
    if (!/^[0-9a-f]{64}$/.test(String(expectedClassifierSourceSha256 || ''))
      || !/^[0-9a-f]{64}$/.test(String(expectedBaseDecisionSha256 || ''))) {
      return fail('expected_source_binding_missing');
    }
    const signed = projectEpistemicLabelExact(expectedSignedLabel);
    const { certificate_sha256: claimed, ...body } = certificate;
    if (sha256Canonical(body) !== claimed) return fail('certificate_hash_mismatch');
    const expectedInput = Object.freeze({
      ...buildEpistemicCertificateInputCommitment(
        memory,
        peers,
        expectedClassifierSourceSha256,
      ),
      signed_label: signed,
      base_decision_sha256: expectedBaseDecisionSha256,
      exact_projection_version: MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
    });
    if (sha256Canonical(expectedInput) !== sha256Canonical(certificate.input)) {
      return fail('input_commitment_mismatch');
    }
    if (certificate.automatic_policy_activation !== false
      || certificate.decision?.persistent_transition_authorized !== false) {
      return fail('forbidden_authority');
    }
    if (!/^[0-9a-f]{64}$/.test(String(certificate.deletion_plan_sha256 || ''))) {
      return fail('deletion_plan_binding_missing');
    }
    const nSelect = Number(certificate.parameters?.n_select);
    const nCertify = Number(certificate.parameters?.n_certify);
    const nMax = Number(certificate.parameters?.n_max);
    const caps = certificate.parameters?.resource_caps;
    if (!Number.isSafeInteger(nSelect) || nSelect < 1
      || !Number.isSafeInteger(nCertify) || nCertify < 1
      || !Number.isSafeInteger(nMax) || nMax < 1
      || !Number.isSafeInteger(caps?.max_tokens) || caps.max_tokens < 1
      || !Number.isSafeInteger(caps?.max_peers) || caps.max_peers < 0
      || !Number.isSafeInteger(caps?.max_samples) || caps.max_samples < 1
      || nSelect + nCertify > caps.max_samples) {
      return fail('parameters_invalid');
    }
    const selectionRows = certificate.transcripts?.selection;
    const certificationRows = certificate.transcripts?.certification;
    if (!Array.isArray(selectionRows) || !Array.isArray(certificationRows)
      || selectionRows.length !== nSelect
      || certificationRows.length !== nCertify) {
      return fail('transcript_denominator_mismatch');
    }
    if (sha256Canonical(selectionRows) !== certificate.transcripts.selection_sha256
      || sha256Canonical(certificationRows) !== certificate.transcripts.certification_sha256) {
      return fail('transcript_root_mismatch');
    }
    const tokens = canonicalizeEditTokens(memory?.value);
    if (tokens.length > caps.max_tokens || peers.length > caps.max_peers) {
      return fail('resource_cap_exceeded');
    }
    const selectionCounts = replay(selectionRows, memory, peers, tokens);
    const certificationCounts = replay(certificationRows, memory, peers, tokens);
    const selected = selectUniqueEpistemicTopClass(selectionCounts);
    const math = selected.selected_class
      ? computeConservativeMulticlassCertificateForSelectedClass({
          counts: certificationCounts,
          selectedClass: selected.selected_class,
          nCertify,
          alphaFamily: certificate.parameters.alpha_family,
          nMax: certificate.parameters.n_max,
          pDel: certificate.parameters.p_del,
        })
      : Object.freeze({
          projection_version: MEMORY_EPISTEMIC_EXACT_PROJECTION_VERSION,
          formula_version: EPISTEMIC_MULTICLASS_FORMULA_VERSION,
          outcome: 'abstain',
          reason: 'selection_tie',
          selected_class: null,
          tie_classes: selected.tie_classes,
          radius: null,
          counts: certificationCounts,
        });
    const expectedDecision = Object.freeze({
      ...math,
      selection_counts: selectionCounts,
      certification_counts: certificationCounts,
      effective_posture: resolveCertifiedEpistemicPosture({
        signedLabel: signed,
        certificateDecision: math,
      }),
      persistent_transition_authorized: false,
    });
    if (sha256Canonical(expectedDecision) !== sha256Canonical(certificate.decision)) {
      return fail('decision_mismatch');
    }
    return Object.freeze({
      valid: true,
      certificate_sha256: claimed,
      outcome: math.outcome,
      radius: math.radius,
      selected_class: math.selected_class,
      effective_label: expectedDecision.effective_posture.effective_label,
      persistent_transition_authorized: false,
      automatic_policy_activation: false,
    });
  } catch (error) {
    return fail(String(error?.message || 'verification_error'));
  }
}
