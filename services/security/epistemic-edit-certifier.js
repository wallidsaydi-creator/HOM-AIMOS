// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: dormant ECR ceremony and isolated tests only
// → Calls: pure epistemic classifier kernel + certificate math
// Pipeline: SECURITY | Dormant CERT-ED native certifier; no canonical caller
// Paper: Huang et al., CERT-ED, Findings of EMNLP 2024, Theorem 2
// ─────────────────────────────────────────────────────────────────────────────

import { randomBytes } from 'node:crypto';
import { classifyRetainedMemoryEpistemics } from './memory-epistemic-classifier-kernel.js';
import {
  EPISTEMIC_BINARY_PROJECTION_VERSION,
  EPISTEMIC_EDIT_CERTIFICATE_SCHEMA,
  EPISTEMIC_EDIT_FORMULA_VERSION,
  applyDeletionBitmap,
  buildEpistemicCertificateInputCommitment,
  canonicalizeEditTokens,
  computeConservativeCertificateMath,
  normalizeProbabilityRational,
  projectEpistemicLabel,
  reconstructEditTokens,
  sha256Canonical,
} from './epistemic-edit-certificate-math.js';

export const EPISTEMIC_EDIT_CERTIFIER_VERSION = 'aimos-epistemic-edit-certifier/v1';
export const EPISTEMIC_DELETION_PLAN_SCHEMA = 'aimos.epistemic-deletion-plan/v1';

function exactDeletionBitmap(tokenCount, pDel) {
  const probability = normalizeProbabilityRational(pDel, 'p_del');
  const bitmap = Buffer.alloc(Math.ceil(tokenCount / 8));
  if (!tokenCount) return bitmap.toString('base64');

  const modulus = probability.denominator;
  const limit = Math.floor(0x1_0000_0000 / modulus) * modulus;
  let pool = Buffer.alloc(0);
  let offset = 0;
  const nextUint32 = () => {
    if (offset + 4 > pool.length) {
      pool = randomBytes(Math.max(4096, tokenCount * 4));
      offset = 0;
    }
    const value = pool.readUInt32BE(offset);
    offset += 4;
    return value;
  };

  for (let index = 0; index < tokenCount; index += 1) {
    let draw = nextUint32();
    while (draw >= limit) draw = nextUint32();
    if ((draw % modulus) < probability.numerator) {
      bitmap[Math.floor(index / 8)] |= 1 << (index % 8);
    }
  }
  return bitmap.toString('base64');
}

function classifyBitmap(memory, peers, tokens, bitmap) {
  const perturbedTokens = applyDeletionBitmap(tokens, bitmap);
  const decision = classifyRetainedMemoryEpistemics({
    ...memory,
    value: reconstructEditTokens(perturbedTokens),
  }, peers, null);
  return projectEpistemicLabel(decision.label);
}

function runSamples({ memory, peers, tokens, bitmaps }) {
  const rows = [];
  const counts = { U: 0, N: 0 };
  for (const bitmap of bitmaps) {
    const output = classifyBitmap(memory, peers, tokens, bitmap);
    counts[output] += 1;
    rows.push(Object.freeze({ bitmap, output }));
  }
  return Object.freeze({ rows: Object.freeze(rows), counts: Object.freeze(counts) });
}

function assertDeletionPlan(plan, {
  input,
  tokens,
  pDel,
  nSelect,
  nCertify,
}) {
  if (!plan || plan.schema !== EPISTEMIC_DELETION_PLAN_SCHEMA) {
    throw new Error('epistemic_certificate_deletion_plan_schema_invalid');
  }
  const { plan_sha256: claimedHash, ...unsignedPlan } = plan;
  if (!/^[0-9a-f]{64}$/.test(String(claimedHash || ''))
    || sha256Canonical(unsignedPlan) !== claimedHash) {
    throw new Error('epistemic_certificate_deletion_plan_hash_invalid');
  }
  const deletion = normalizeProbabilityRational(pDel, 'p_del');
  if (sha256Canonical(plan.p_del) !== sha256Canonical(deletion)
    || plan.input_sha256 !== input.input_sha256
    || plan.token_sequence_sha256 !== input.token_sequence_sha256
    || plan.token_count !== tokens.length
    || plan.n_select !== nSelect
    || plan.n_certify !== nCertify
    || !Array.isArray(plan.selection_bitmaps)
    || !Array.isArray(plan.certification_bitmaps)
    || plan.selection_bitmaps.length !== nSelect
    || plan.certification_bitmaps.length !== nCertify
    || sha256Canonical(plan.selection_bitmaps) !== plan.selection_bitmaps_sha256
    || sha256Canonical(plan.certification_bitmaps) !== plan.certification_bitmaps_sha256) {
    throw new Error('epistemic_certificate_deletion_plan_binding_invalid');
  }
  for (const bitmap of [...plan.selection_bitmaps, ...plan.certification_bitmaps]) {
    applyDeletionBitmap(tokens, bitmap);
  }
  return plan;
}

export function verifyEpistemicDeletionPlan({
  memory,
  peers = [],
  classifierSourceSha256,
  deletionPlan,
  pDel,
  nSelect,
  nCertify,
} = {}) {
  const tokens = canonicalizeEditTokens(memory?.value);
  const input = buildEpistemicCertificateInputCommitment(memory, peers, classifierSourceSha256);
  const plan = assertDeletionPlan(deletionPlan, {
    input,
    tokens,
    pDel,
    nSelect,
    nCertify,
  });
  return Object.freeze({
    valid: true,
    plan_sha256: plan.plan_sha256,
    input_sha256: plan.input_sha256,
    selection_bitmaps_sha256: plan.selection_bitmaps_sha256,
    certification_bitmaps_sha256: plan.certification_bitmaps_sha256,
  });
}

export function generateEpistemicDeletionPlan({
  memory,
  peers = [],
  classifierSourceSha256,
  pDel = { numerator: 9, denominator: 10 },
  nSelect = 1000,
  nCertify = 4000,
  resourceCaps = {},
}) {
  const maxTokens = Number(resourceCaps.maxTokens ?? 4096);
  const maxPeers = Number(resourceCaps.maxPeers ?? 256);
  const maxSamples = Number(resourceCaps.maxSamples ?? 10_000);
  if (!Number.isSafeInteger(nSelect) || nSelect < 1) throw new Error('epistemic_certificate_n_select_invalid');
  if (!Number.isSafeInteger(nCertify) || nCertify < 1) throw new Error('epistemic_certificate_n_certify_invalid');
  const tokens = canonicalizeEditTokens(memory?.value);
  if (tokens.length > maxTokens || peers.length > maxPeers || nSelect + nCertify > maxSamples) {
    throw new Error('epistemic_certificate_deletion_plan_resource_cap_exceeded');
  }
  const input = buildEpistemicCertificateInputCommitment(memory, peers, classifierSourceSha256);
  const deletion = normalizeProbabilityRational(pDel, 'p_del');
  const selectionBitmaps = Array.from(
    { length: nSelect },
    () => exactDeletionBitmap(tokens.length, deletion),
  );
  const certificationBitmaps = Array.from(
    { length: nCertify },
    () => exactDeletionBitmap(tokens.length, deletion),
  );
  const body = {
    schema: EPISTEMIC_DELETION_PLAN_SCHEMA,
    input_sha256: input.input_sha256,
    token_sequence_sha256: input.token_sequence_sha256,
    token_count: tokens.length,
    p_del: deletion,
    n_select: nSelect,
    n_certify: nCertify,
    selection_bitmaps: selectionBitmaps,
    certification_bitmaps: certificationBitmaps,
    selection_bitmaps_sha256: sha256Canonical(selectionBitmaps),
    certification_bitmaps_sha256: sha256Canonical(certificationBitmaps),
    randomness_source: 'operating_system_cryptographic_random_bytes',
  };
  return Object.freeze({ ...body, plan_sha256: sha256Canonical(body) });
}

export function certifyEpistemicEditRobustnessFromPlan({
  memory,
  peers = [],
  classifierSourceSha256,
  deletionPlan,
  pDel = { numerator: 9, denominator: 10 },
  nSelect = 1000,
  nCertify = 4000,
  alphaFamily = { numerator: 5, denominator: 100 },
  nMax = 100,
  resourceCaps = {},
}) {
  const maxTokens = Number(resourceCaps.maxTokens ?? 4096);
  const maxPeers = Number(resourceCaps.maxPeers ?? 256);
  const maxSamples = Number(resourceCaps.maxSamples ?? 10_000);
  if (!Number.isSafeInteger(nSelect) || nSelect < 1) throw new Error('epistemic_certificate_n_select_invalid');
  if (!Number.isSafeInteger(nCertify) || nCertify < 1) throw new Error('epistemic_certificate_n_certify_invalid');
  const tokens = canonicalizeEditTokens(memory?.value);
  const input = buildEpistemicCertificateInputCommitment(memory, peers, classifierSourceSha256);
  const parameters = Object.freeze({
    p_del: normalizeProbabilityRational(pDel, 'p_del'),
    n_select: nSelect,
    n_certify: nCertify,
    alpha_family: normalizeProbabilityRational(alphaFamily, 'alpha_family'),
    n_max: nMax,
    resource_caps: Object.freeze({ max_tokens: maxTokens, max_peers: maxPeers, max_samples: maxSamples }),
  });
  if (tokens.length > maxTokens || peers.length > maxPeers || nSelect + nCertify > maxSamples) {
    throw new Error('epistemic_certificate_deletion_plan_resource_cap_exceeded');
  }
  const plan = assertDeletionPlan(deletionPlan, {
    input,
    tokens,
    pDel: parameters.p_del,
    nSelect,
    nCertify,
  });
  const selection = runSamples({ memory, peers, tokens, bitmaps: plan.selection_bitmaps });
  const selectedClass = selection.counts.U === selection.counts.N
    ? null
    : selection.counts.U > selection.counts.N ? 'U' : 'N';
  const certification = runSamples({ memory, peers, tokens, bitmaps: plan.certification_bitmaps });
  const math = selectedClass
    ? computeConservativeCertificateMath({
        selectedCount: certification.counts[selectedClass],
        nCertify,
        alphaFamily: parameters.alpha_family,
        nMax,
        pDel: parameters.p_del,
      })
    : { outcome: 'abstain', reason: 'selection_tie', radius: null };
  const transcripts = Object.freeze({
    selection: selection.rows,
    certification: certification.rows,
    selection_sha256: sha256Canonical(selection.rows),
    certification_sha256: sha256Canonical(certification.rows),
  });
  const decision = Object.freeze({
    ...math,
    selected_class: selectedClass,
    selection_counts: selection.counts,
    certification_counts: certification.counts,
  });
  const certificate = {
    schema: EPISTEMIC_EDIT_CERTIFICATE_SCHEMA,
    certifier_version: EPISTEMIC_EDIT_CERTIFIER_VERSION,
    projection_version: EPISTEMIC_BINARY_PROJECTION_VERSION,
    formula_version: EPISTEMIC_EDIT_FORMULA_VERSION,
    input,
    parameters,
    transcripts,
    decision,
  };
  return Object.freeze({ ...certificate, certificate_sha256: sha256Canonical(certificate) });
}

export function certifyEpistemicEditRobustness({
  memory,
  peers = [],
  classifierSourceSha256,
  pDel = { numerator: 9, denominator: 10 },
  nSelect = 1000,
  nCertify = 4000,
  alphaFamily = { numerator: 5, denominator: 100 },
  nMax = 100,
  resourceCaps = {},
}) {
  const maxTokens = Number(resourceCaps.maxTokens ?? 4096);
  const maxPeers = Number(resourceCaps.maxPeers ?? 256);
  const maxSamples = Number(resourceCaps.maxSamples ?? 10_000);
  if (!Number.isSafeInteger(nSelect) || nSelect < 1) throw new Error('epistemic_certificate_n_select_invalid');
  if (!Number.isSafeInteger(nCertify) || nCertify < 1) throw new Error('epistemic_certificate_n_certify_invalid');

  const tokens = canonicalizeEditTokens(memory?.value);
  const input = buildEpistemicCertificateInputCommitment(memory, peers, classifierSourceSha256);
  const parameters = Object.freeze({
    p_del: normalizeProbabilityRational(pDel, 'p_del'),
    n_select: nSelect,
    n_certify: nCertify,
    alpha_family: normalizeProbabilityRational(alphaFamily, 'alpha_family'),
    n_max: nMax,
    resource_caps: Object.freeze({ max_tokens: maxTokens, max_peers: maxPeers, max_samples: maxSamples }),
  });

  if (tokens.length > maxTokens || peers.length > maxPeers || nSelect + nCertify > maxSamples) {
    const certificate = {
      schema: EPISTEMIC_EDIT_CERTIFICATE_SCHEMA,
      certifier_version: EPISTEMIC_EDIT_CERTIFIER_VERSION,
      projection_version: EPISTEMIC_BINARY_PROJECTION_VERSION,
      formula_version: EPISTEMIC_EDIT_FORMULA_VERSION,
      input,
      parameters,
      transcripts: null,
      decision: { outcome: 'abstain', reason: 'resource_cap_exceeded', selected_class: null, radius: null },
    };
    return Object.freeze({ ...certificate, certificate_sha256: sha256Canonical(certificate) });
  }
  const deletionPlan = generateEpistemicDeletionPlan({
    memory,
    peers,
    classifierSourceSha256,
    pDel: parameters.p_del,
    nSelect,
    nCertify,
    resourceCaps,
  });
  return certifyEpistemicEditRobustnessFromPlan({
    memory,
    peers,
    classifierSourceSha256,
    deletionPlan,
    pDel: parameters.p_del,
    nSelect,
    nCertify,
    alphaFamily: parameters.alpha_family,
    nMax,
    resourceCaps,
  });
}
