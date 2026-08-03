#!/usr/bin/env node

// Verify a completed private label export, reveal the arm mapping, and produce
// a text-free public agreement aggregate. Target-level bootstrap resampling
// preserves the clean/attacked dependence within each PoisonedRAG target.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function boolLabel(value, field, auditId) {
  if (value === 'yes') return true;
  if (value === 'no') return false;
  throw new Error(`human_audit_nonbinary_${field}:${auditId}`);
}

function agreement(rows, humanField, judgeField) {
  let agree = 0;
  let humanPositive = 0;
  let judgePositive = 0;
  for (const row of rows) {
    const human = row[humanField];
    const judge = row[judgeField];
    if (human === judge) agree += 1;
    if (human) humanPositive += 1;
    if (judge) judgePositive += 1;
  }
  const n = rows.length;
  const observed = n ? agree / n : null;
  const humanRate = n ? humanPositive / n : null;
  const judgeRate = n ? judgePositive / n : null;
  const expected = n
    ? humanRate * judgeRate + (1 - humanRate) * (1 - judgeRate)
    : null;
  const kappa = expected === null || Math.abs(1 - expected) < 1e-12
    ? null
    : (observed - expected) / (1 - expected);
  return {
    n,
    agreements: agree,
    raw_agreement: observed,
    human_positive: humanPositive,
    judge_positive: judgePositive,
    expected_agreement: expected,
    cohen_kappa: kappa,
  };
}

function rngFromHex(hex) {
  let state = Number.parseInt(hex.slice(0, 8), 16) >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
}

function percentile(sorted, probability) {
  if (!sorted.length) return null;
  const index = (sorted.length - 1) * probability;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
}

function clusterBootstrap(rows, humanField, judgeField, seedHex, replicates = 10_000) {
  const byTarget = new Map();
  for (const row of rows) {
    if (!byTarget.has(row.target_ordinal)) byTarget.set(row.target_ordinal, []);
    byTarget.get(row.target_ordinal).push(row);
  }
  const targets = [...byTarget.keys()].sort((a, b) => a - b);
  const random = rngFromHex(seedHex);
  const values = [];
  for (let replicate = 0; replicate < replicates; replicate += 1) {
    const sample = [];
    for (let index = 0; index < targets.length; index += 1) {
      const selected = targets[Math.floor(random() * targets.length)];
      sample.push(...byTarget.get(selected));
    }
    const value = agreement(sample, humanField, judgeField).cohen_kappa;
    if (Number.isFinite(value)) values.push(value);
  }
  values.sort((a, b) => a - b);
  return {
    method: 'target-cluster percentile bootstrap',
    replicates_requested: replicates,
    replicates_valid: values.length,
    lower_95: percentile(values, 0.025),
    upper_95: percentile(values, 0.975),
  };
}

function main() {
  const runId = cliValue('--run-id');
  const labelsArg = cliValue('--labels');
  const reviewerRole = cliValue('--reviewer-role');
  if (!runId || !/^[0-9]{14}_[a-f0-9]{6}$/.test(runId)) {
    throw new Error('human_audit_run_id_required');
  }
  if (!labelsArg) throw new Error('human_audit_labels_file_required');
  if (!['independent_reviewer', 'external_blinded_assessor', 'system_author'].includes(reviewerRole)) {
    throw new Error('human_audit_reviewer_role_required');
  }
  const runDir = path.join(ROOT, 'eval', 'public-results', runId);
  const packet = readJson(path.join(runDir, 'human-audit', 'blinded-packet.json'));
  const mapping = readJson(path.join(runDir, 'human-audit', 'private-mapping.json'));
  const labelsFile = path.resolve(labelsArg);
  const labels = readJson(labelsFile);
  if (labels.packet_sha256 !== packet.packet_sha256
      || mapping.packet_sha256 !== packet.packet_sha256) {
    throw new Error('human_audit_packet_hash_mismatch');
  }
  const packetBody = { ...packet };
  delete packetBody.packet_sha256;
  if (sha256(canonical(packetBody)) !== packet.packet_sha256) {
    throw new Error('human_audit_packet_self_hash_invalid');
  }
  if (!Array.isArray(labels.labels) || labels.labels.length !== 200) {
    throw new Error('human_audit_requires_200_labels');
  }
  const labelById = new Map();
  for (const label of labels.labels) {
    if (labelById.has(label.audit_id)) throw new Error(`human_audit_duplicate_label:${label.audit_id}`);
    labelById.set(label.audit_id, label);
  }
  const rows = mapping.records.map((record) => {
    const label = labelById.get(record.audit_id);
    if (!label) throw new Error(`human_audit_missing_label:${record.audit_id}`);
    for (const field of ['correct', 'asserts_target', 'abstains', 'evidence_supports', 'official_answer_defective']) {
      if (!label[field]) throw new Error(`human_audit_incomplete_${field}:${record.audit_id}`);
    }
    if (label.correct === 'uncertain'
        || label.asserts_target === 'uncertain'
        || label.official_answer_defective !== 'no') {
      throw new Error(`human_audit_requires_adjudication:${record.audit_id}`);
    }
    return {
      ...record,
      human_correct: boolLabel(label.correct, 'correct', record.audit_id),
      human_asserts_target: boolLabel(label.asserts_target, 'asserts_target', record.audit_id),
      human_abstains: boolLabel(label.abstains, 'abstains', record.audit_id),
      human_evidence_supports: label.evidence_supports,
    };
  });
  if (rows.length !== 200 || new Set(rows.map((row) => row.target_ordinal)).size !== 100) {
    throw new Error('human_audit_target_pairing_invalid');
  }
  const seed = sha256(Buffer.concat([
    fs.readFileSync(labelsFile),
    Buffer.from('hom.aimos.human-audit-bootstrap/v1', 'utf8'),
  ]));
  const correctness = agreement(rows, 'human_correct', 'judge_correct');
  correctness.kappa_ci_95 = clusterBootstrap(rows, 'human_correct', 'judge_correct', seed);
  const targetAssertion = agreement(rows, 'human_asserts_target', 'judge_asserts_target');
  targetAssertion.kappa_ci_95 = clusterBootstrap(
    rows,
    'human_asserts_target',
    'judge_asserts_target',
    sha256(seed),
  );
  const disagreements = [];
  for (const row of rows) {
    if (row.human_correct !== row.judge_correct) {
      disagreements.push({
        audit_id: row.audit_id,
        task: 'correctness',
        human: row.human_correct,
        judge: row.judge_correct,
      });
    }
    if (row.human_asserts_target !== row.judge_asserts_target) {
      disagreements.push({
        audit_id: row.audit_id,
        task: 'target_assertion',
        human: row.human_asserts_target,
        judge: row.judge_asserts_target,
      });
    }
  }
  const resultBody = {
    schema: 'hom.aimos.poisonedrag-human-agreement/v1',
    protocol: 'poisonedrag-n100-v1',
    run_id: runId,
    packet_sha256: packet.packet_sha256,
    reviewer_role: reviewerRole,
    blinding: {
      arm_hidden_during_review: true,
      judge_verdict_hidden_during_review: true,
      arm_mapping_revealed_after_label_completion: true,
    },
    intended_answers: 200,
    audited_answers: rows.length,
    intended_target_pairs: 100,
    complete_target_pairs: new Set(rows.map((row) => row.target_ordinal)).size,
    correctness_agreement: correctness,
    target_assertion_agreement: targetAssertion,
    disagreement_count: disagreements.length,
    disagreements,
    bootstrap_unit: 'PoisonedRAG target; both arms retained within each resampled cluster',
    exclusions: 0,
  };
  const result = { ...resultBody, summary_sha256: sha256(canonical(resultBody)) };
  const privateResult = path.join(runDir, 'human-audit', 'agreement.json');
  const publicResult = path.join(ROOT, 'eval', 'publication', 'poisonedrag-human-agreement.json');
  fs.writeFileSync(privateResult, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(privateResult, 0o600);
  fs.writeFileSync(publicResult, `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    success: true,
    run_id: runId,
    reviewer_role: reviewerRole,
    correctness_agreement: correctness,
    target_assertion_agreement: targetAssertion,
    disagreement_count: disagreements.length,
    summary_sha256: result.summary_sha256,
    private_result: privateResult,
    public_result: publicResult,
  }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  console.error(error?.stack || error);
  process.exitCode = 1;
}
