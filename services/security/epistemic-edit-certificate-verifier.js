// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: ECR ceremonies, release verification, isolated tests
// → Calls: pure classifier kernel + certificate math; never signer/DB/Keychain
// Pipeline: SECURITY | Portable CERT-ED transcript replay verifier
// Paper: Huang et al., CERT-ED, Findings of EMNLP 2024, Theorem 2
// ─────────────────────────────────────────────────────────────────────────────

import { classifyRetainedMemoryEpistemics } from './memory-epistemic-classifier-kernel.js';
import {
  EPISTEMIC_EDIT_CERTIFICATE_SCHEMA,
  applyDeletionBitmap,
  buildEpistemicCertificateInputCommitment,
  canonicalizeEditTokens,
  computeConservativeCertificateMath,
  projectEpistemicLabel,
  reconstructEditTokens,
  sha256Canonical,
} from './epistemic-edit-certificate-math.js';

function fail(reason) {
  return Object.freeze({ valid: false, reason });
}

function replayRows(rows, memory, peers, tokens) {
  const counts = { U: 0, N: 0 };
  for (const row of rows) {
    if (!row || !['U', 'N'].includes(row.output)) throw new Error('transcript_output_invalid');
    const value = reconstructEditTokens(applyDeletionBitmap(tokens, row.bitmap));
    const output = projectEpistemicLabel(classifyRetainedMemoryEpistemics({ ...memory, value }, peers, null).label);
    if (output !== row.output) throw new Error('transcript_output_mismatch');
    counts[output] += 1;
  }
  return Object.freeze(counts);
}

export function verifyEpistemicEditCertificate({
  certificate,
  memory,
  peers = [],
  expectedClassifierSourceSha256,
}) {
  try {
    if (!certificate || certificate.schema !== EPISTEMIC_EDIT_CERTIFICATE_SCHEMA) return fail('schema_invalid');
    if (!/^[0-9a-f]{64}$/.test(String(expectedClassifierSourceSha256 || ''))) {
      return fail('expected_classifier_source_hash_missing');
    }
    if (certificate.input?.classifier_source_sha256 !== expectedClassifierSourceSha256) {
      return fail('classifier_source_hash_mismatch');
    }
    const { certificate_sha256: claimedHash, ...unsigned } = certificate;
    if (sha256Canonical(unsigned) !== claimedHash) return fail('certificate_hash_mismatch');
    const input = buildEpistemicCertificateInputCommitment(
      memory,
      peers,
      certificate.input?.classifier_source_sha256,
    );
    if (sha256Canonical(input) !== sha256Canonical(certificate.input)) return fail('input_commitment_mismatch');

    const tokens = canonicalizeEditTokens(memory?.value);
    const caps = certificate.parameters?.resource_caps || {};
    if (certificate.decision?.reason === 'resource_cap_exceeded') {
      const exceeded = tokens.length > caps.max_tokens
        || peers.length > caps.max_peers
        || certificate.parameters.n_select + certificate.parameters.n_certify > caps.max_samples;
      return exceeded
        ? Object.freeze({ valid: true, outcome: 'abstain', radius: null, selected_class: null })
        : fail('resource_abstention_unjustified');
    }

    const selectionRows = certificate.transcripts?.selection;
    const certificationRows = certificate.transcripts?.certification;
    if (!Array.isArray(selectionRows) || !Array.isArray(certificationRows)) return fail('transcript_missing');
    if (selectionRows.length !== certificate.parameters.n_select) return fail('selection_denominator_mismatch');
    if (certificationRows.length !== certificate.parameters.n_certify) return fail('certification_denominator_mismatch');
    if (sha256Canonical(selectionRows) !== certificate.transcripts.selection_sha256) return fail('selection_root_mismatch');
    if (sha256Canonical(certificationRows) !== certificate.transcripts.certification_sha256) return fail('certification_root_mismatch');

    const selectionCounts = replayRows(selectionRows, memory, peers, tokens);
    const certificationCounts = replayRows(certificationRows, memory, peers, tokens);
    const selectedClass = selectionCounts.U === selectionCounts.N
      ? null
      : selectionCounts.U > selectionCounts.N ? 'U' : 'N';
    if (selectedClass !== certificate.decision.selected_class) return fail('selected_class_mismatch');
    if (sha256Canonical(selectionCounts) !== sha256Canonical(certificate.decision.selection_counts)) {
      return fail('selection_counts_mismatch');
    }
    if (sha256Canonical(certificationCounts) !== sha256Canonical(certificate.decision.certification_counts)) {
      return fail('certification_counts_mismatch');
    }

    const math = selectedClass
      ? computeConservativeCertificateMath({
          selectedCount: certificationCounts[selectedClass],
          nCertify: certificate.parameters.n_certify,
          alphaFamily: certificate.parameters.alpha_family,
          nMax: certificate.parameters.n_max,
          pDel: certificate.parameters.p_del,
        })
      : { outcome: 'abstain', reason: 'selection_tie', radius: null };
    for (const key of ['outcome', 'reason', 'radius', 'fraction_ppm', 'penalty_ppm', 'mu_lower_ppm', 'runner_upper_ppm', 'theorem_argument_ppm']) {
      if ((math[key] ?? null) !== (certificate.decision[key] ?? null)) return fail(`decision_${key}_mismatch`);
    }
    return Object.freeze({
      valid: true,
      outcome: math.outcome,
      radius: math.radius,
      selected_class: selectedClass,
      certificate_sha256: claimedHash,
    });
  } catch (error) {
    return fail(String(error?.message || 'verification_error'));
  }
}
