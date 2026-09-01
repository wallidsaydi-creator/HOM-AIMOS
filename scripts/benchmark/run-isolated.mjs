#!/usr/bin/env node

// Canonical public benchmark lifecycle.
//
// One disposable AIMOS brain is genesis-installed, public sessions are replayed
// one turn at a time through signed native routes, one signed recall is issued
// per selected question, GPT-5.4 generates one answer, and GPT-5.6 Terra judges
// that answer. The historical whole-session blob harness remains available only
// behind the explicit --historical-v1 diagnostic flag.
//
// The user's canonical brain is fingerprinted before/after but never selected
// by any benchmark child process. Cleanup drops the entire scratch brain, which
// is the only deletion boundary used by this runner.

import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  createReadStream,
  appendFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  lstatSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import net from 'node:net';
import pg from 'pg';

import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { verifyWholeBrainPurgeReceipt } from '../../services/security/whole-brain-purge.js';
import {
  LOCOMO_OFFICIAL_PROTOCOL,
  LOCOMO_OFFICIAL_TOP_K,
} from '../../eval/locomo-official-protocol.mjs';
import {
  POISONEDRAG_GENERATOR_MODEL,
  POISONEDRAG_MAX_ATTEMPTS,
  POISONEDRAG_PROTOCOL_ID,
} from '../../eval/poisonedrag/harness.mjs';
import {
  buildUserServiceManifest,
  readInstalledUserServiceDefinition,
} from '../service/manage-user-service.mjs';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const LONGMEMEVAL_ORACLE_CONDITION_DATASET = path.join(ROOT, 'eval', 'data', 'official-longmemeval-oracle.json');
const LOCOMO_DATASET = path.join(ROOT, 'eval', 'data', 'official-locomo10.json');
const HOUSEKEEPER_KEY = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.key');
const HOUSEKEEPER_CERT_CACHE = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.cert-cache.json');
const ARCHITECTURE_AUTHORITY = path.join(ROOT, 'architecture-authority.json');
const CANONICAL_BLIND_PROTOCOL = 'canonical-blind-v1';
const TWIN_PRIME_G1P_PROTOCOL = 'twin-prime-g1p-v1';
const TWIN_PRIME_G5_PROTOCOL = 'twin-prime-g5-v1';
const TWIN_PRIME_G1P_CORPUS = path.join(ROOT, 'eval', 'data', 'twin-prime-g1p-canonical-v2');
const TWIN_PRIME_G5_CONTRACT = path.join(ROOT, 'eval', 'twin-prime', 'tp-g5-contract-v6');
const POISONEDRAG_SOURCE_LOCK = path.join(ROOT, 'eval', 'poisonedrag', 'source-lock.json');
const POISONEDRAG_PUBLIC_LOCK = path.join(ROOT, 'eval', 'poisonedrag', 'n100-public-target-lock.json');
const POISONEDRAG_PRIVATE_ROOT = path.join(ROOT, 'eval', 'data', 'private', 'poisonedrag');

export function parseArgs(argv) {
  const args = {
    longmemevalFile: LONGMEMEVAL_ORACLE_CONDITION_DATASET,
    longmemevalFileExplicit: false,
    sample: 10,
    sampleExplicit: false,
    full: false,
    smoke: false,
    lifecycleProof: false,
    historicalV1: false,
    gate: null,
    benchmark: 'both',
    port: 9200,
    portExplicit: false,
    installedInstance: null,
    agentId: null,
    publicReproduce: false,
    limit: 20,
    limitExplicit: false,
    protocol: CANONICAL_BLIND_PROTOCOL,
    cognitive: false,
    generatorProvider: 'codex',
    generatorModel: 'gpt-5.4',
    judgeProvider: 'codex',
    judgeModel: 'gpt-5.6-terra',
    modelOverrideExplicit: false,
    keychainAccount: null,
    keepScratchDb: false,
    resumeRun: null,
    outputRoot: path.join(ROOT, 'eval', 'public-results')
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (['--predecessor-run', '--successor-source-run', '--qualification-receipt']
      .includes(arg)) {
      throw new Error(`retired_mutmem_s7_option:${arg}`);
    }
    if (arg === '--longmemeval-file' && next) {
      args.longmemevalFile = path.resolve(next);
      args.longmemevalFileExplicit = true;
      i += 1;
    }
    else if (arg === '--sample' && next) { args.sample = Number(next); args.sampleExplicit = true; i += 1; }
    else if (arg === '--port' && next) { args.port = Number(next); args.portExplicit = true; i += 1; }
    else if (arg === '--installed-instance' && next) { args.installedInstance = String(next).trim(); i += 1; }
    else if (arg === '--agent-id' && next) { args.agentId = String(next).trim(); i += 1; }
    else if (arg === '--limit' && next) { args.limit = Number(next); args.limitExplicit = true; i += 1; }
    else if (arg === '--protocol' && next) { args.protocol = String(next).trim().toLowerCase(); i += 1; }
    else if (arg === '--benchmark' && next) { args.benchmark = String(next).toLowerCase(); i += 1; }
    else if (arg === '--gate' && next) { args.gate = String(next).toLowerCase(); i += 1; }
    else if (arg === '--generator-model' && next) { args.generatorModel = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--generator-provider' && next) { args.generatorProvider = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--judge-model' && next) { args.judgeModel = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--judge-provider' && next) { args.judgeProvider = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--keychain-account' && next) { args.keychainAccount = String(next).trim(); i += 1; }
    else if (arg === '--output-root' && next) { args.outputRoot = path.resolve(next); i += 1; }
    else if (arg === '--resume-run' && next) { args.resumeRun = String(next).trim().toLowerCase(); i += 1; }
    else if (arg === '--full') args.full = true;
    else if (arg === '--smoke') args.smoke = true;
    else if (arg === '--lifecycle-proof') args.lifecycleProof = true;
    else if (arg === '--historical-v1') args.historicalV1 = true;
    else if (arg === '--cognitive') args.cognitive = true;
    else if (arg === '--keep-scratch-db') args.keepScratchDb = true;
    else if (arg === '--public-reproduce') args.publicReproduce = true;
  }
  if (!Number.isInteger(args.sample) || args.sample < 1) throw new Error('--sample must be a positive integer');
  if (![CANONICAL_BLIND_PROTOCOL, LOCOMO_OFFICIAL_PROTOCOL, POISONEDRAG_PROTOCOL_ID, TWIN_PRIME_G1P_PROTOCOL, TWIN_PRIME_G5_PROTOCOL].includes(args.protocol)) {
    throw new Error('--protocol must be canonical-blind-v1|locomo-upstream-qa-v1|poisonedrag-n100-v1|twin-prime-g1p-v1|twin-prime-g5-v1');
  }
  if (args.protocol === LOCOMO_OFFICIAL_PROTOCOL) {
    if (args.benchmark !== 'locomo') throw new Error('locomo-upstream-qa-v1 requires --benchmark locomo');
    if (args.historicalV1 || args.lifecycleProof || args.cognitive) {
      throw new Error('locomo-upstream-qa-v1 conflicts with historical/lifecycle/cognitive modes');
    }
    if (args.limitExplicit && args.limit !== LOCOMO_OFFICIAL_TOP_K) {
      throw new Error(`locomo-upstream-qa-v1 requires --limit ${LOCOMO_OFFICIAL_TOP_K}`);
    }
    args.limit = LOCOMO_OFFICIAL_TOP_K;
  }
  if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
    if (args.benchmark !== 'poisonedrag') throw new Error('poisonedrag-n100-v1 requires --benchmark poisonedrag');
    if (args.historicalV1 || args.lifecycleProof || args.cognitive || args.gate) {
      throw new Error('poisonedrag-n100-v1 conflicts with historical/lifecycle/cognitive/gate modes');
    }
    if (args.limitExplicit && args.limit !== 5) throw new Error('poisonedrag-n100-v1 requires --limit 5');
    if (args.modelOverrideExplicit) throw new Error('poisonedrag model roles are fixed to GPT-5.5 and GPT-5.6 Terra');
    if (!args.full && args.sample > 100) throw new Error('poisonedrag sample cannot exceed 100 targets');
    args.limit = 5;
  }
  if (args.protocol === TWIN_PRIME_G1P_PROTOCOL) {
    if (args.benchmark !== 'both') throw new Error('twin-prime-g1p-v1 requires --benchmark both');
    if (args.historicalV1 || args.lifecycleProof || args.cognitive || args.gate || args.full) {
      throw new Error('twin-prime-g1p-v1 conflicts with historical/lifecycle/cognitive/gate/full modes');
    }
    if (args.modelOverrideExplicit) throw new Error('twin-prime-g1p-v1 makes no model calls');
    if (args.limitExplicit && args.limit !== 20) throw new Error('twin-prime-g1p-v1 requires --limit 20');
    if (!args.sampleExplicit) args.sample = 128;
    if (args.sample > 1540) throw new Error('twin-prime-g1p-v1 sample ceiling cannot exceed 1540');
    args.limit = 20;
  }
  if (args.protocol === TWIN_PRIME_G5_PROTOCOL) {
    if (args.benchmark !== 'both') throw new Error('twin-prime-g5-v1 requires --benchmark both');
    if (args.historicalV1 || args.lifecycleProof || args.cognitive || args.full || args.smoke) {
      throw new Error('twin-prime-g5-v1 conflicts with historical/lifecycle/cognitive/full/smoke modes');
    }
    if (args.gate !== 'b4') {
      throw new Error('twin-prime-g5-v1 currently requires --gate b4; b5 unlocks only after verified gate10 evidence');
    }
    if (args.sampleExplicit) throw new Error('twin-prime-g5-v1 question population is fixed by its pre-outcome contract');
    if (args.modelOverrideExplicit) throw new Error('twin-prime-g5-v1 model roles are fixed to GPT-5.5 and GPT-5.6 Terra');
    if (args.limitExplicit && args.limit !== 20) throw new Error('twin-prime-g5-v1 requires --limit 20');
    if (!args.keychainAccount) throw new Error('twin-prime-g5-v1 requires --keychain-account');
    args.limit = 20;
  }
  if (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 200) throw new Error('--limit must be 1..200');
  if (!Number.isInteger(args.port) || args.port < 1024 || args.port > 65535) throw new Error('--port must be 1024..65535');
  if (args.keychainAccount !== null
    && (!args.keychainAccount || args.keychainAccount.length > 128 || /\s/.test(args.keychainAccount))) {
    throw new Error('--keychain-account must be a non-empty Keychain account name without whitespace');
  }
  if (args.agentId !== null
    && (!/^[a-zA-Z0-9_-]{1,64}$/.test(args.agentId)
      || ['housekeeper', 'aimos_flag_signer'].includes(args.agentId))) {
    throw new Error('--agent-id must name the enrolled ordinary AIMOS agent');
  }
  if (args.resumeRun && !/^\d{14}_[0-9a-f]{6}$/.test(args.resumeRun)) throw new Error('--resume-run must be an existing canonical run id');
  if ([9000, 9001, 9100].includes(args.port)) throw new Error(`port ${args.port} is reserved by a live HOM service`);
  if (!['both', 'locomo', 'longmemeval', 'poisonedrag'].includes(args.benchmark)) {
    throw new Error('--benchmark must be both|locomo|longmemeval|poisonedrag');
  }
  if (args.gate && !['b4', 'b5'].includes(args.gate)) throw new Error('--gate must be b4|b5');
  if (args.gate && (args.historicalV1 || args.full || args.lifecycleProof
    || (args.protocol === CANONICAL_BLIND_PROTOCOL && args.benchmark !== 'both')
    || (args.protocol === LOCOMO_OFFICIAL_PROTOCOL && args.benchmark !== 'locomo'))) {
    throw new Error('--gate benchmark/protocol combination invalid or conflicts with --full/--lifecycle-proof');
  }
  if (args.gate) {
    args.sample = args.protocol === LOCOMO_OFFICIAL_PROTOCOL
      ? (args.gate === 'b4' ? 5 : 25)
      : (args.gate === 'b4' ? 10 : 50);
  }
  if (!args.full && args.benchmark === 'both' && args.sample < 2) throw new Error('--sample must be at least 2 with --benchmark both');
  if (args.lifecycleProof && args.historicalV1) throw new Error('--lifecycle-proof conflicts with --historical-v1');
  if (args.resumeRun && (args.lifecycleProof || args.historicalV1)) throw new Error('--resume-run supports canonical single-query runs only');
  if (args.cognitive && !args.historicalV1) throw new Error('--cognitive is historical-v1 only; canonical mode always generates and judges');
  if (!args.historicalV1 && args.longmemevalFileExplicit) {
    throw new Error('--longmemeval-file is historical-v1 only; regenerate the attested canonical corpus instead');
  }
  if (!args.historicalV1 && args.modelOverrideExplicit) {
    throw new Error('canonical model roles are fixed to GPT-5.4 and GPT-5.6 Terra');
  }
  if (args.protocol !== POISONEDRAG_PROTOCOL_ID) {
    statSync(args.longmemevalFile);
    statSync(LOCOMO_DATASET);
  }
  // --smoke overrides scope to the smallest complete canonical query run.
  if (args.smoke) { args.full = false; args.sample = 3; args.cognitive = false; }
  if (args.lifecycleProof) { args.full = false; args.sample = 3; args.cognitive = false; }
  if (args.installedInstance) {
    if (!/^[a-z][a-z0-9_-]{0,62}$/.test(args.installedInstance)) {
      throw new Error('--installed-instance must be a valid installed AIMOS instance name');
    }
    if (args.portExplicit || args.keepScratchDb || args.lifecycleProof || args.historicalV1
      || args.gate || [TWIN_PRIME_G1P_PROTOCOL, TWIN_PRIME_G5_PROTOCOL].includes(args.protocol)) {
      throw new Error('installed-service mode conflicts with scratch lifecycle and historical protocol options');
    }
    if (!args.agentId) throw new Error('installed-service mode requires --agent-id for the enrolled ordinary agent');
  }
  if (args.publicReproduce && !args.installedInstance) {
    throw new Error('public reproduce requires the installer-created --installed-instance');
  }
  return args;
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function sha256File(file) {
  return sha256(readFileSync(file));
}

function selfHashJson(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  return sha256(JSON.stringify(unsigned));
}

function assertTerminalInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`benchmark_terminal_${field}_invalid`);
  }
  return value;
}

function assertTerminalHash(value, field) {
  if (!/^[0-9a-f]{64}$/.test(String(value || ''))) {
    throw new Error(`benchmark_terminal_${field}_invalid`);
  }
  return String(value);
}

function assertTerminalRelativePath(value, field) {
  const candidate = String(value || '');
  if (!candidate || path.isAbsolute(candidate) || candidate.split(/[\\/]/).includes('..')) {
    throw new Error(`benchmark_terminal_${field}_invalid`);
  }
  return candidate;
}

export function verifyBenchmarkTerminalProjection(projection) {
  if (projection?.schema !== 'hom.aimos.benchmark-terminal-evidence/v1') {
    throw new Error('benchmark_terminal_schema_invalid');
  }
  if (!/^[a-z0-9][a-z0-9_-]{5,63}$/i.test(String(projection.run_id || ''))) {
    throw new Error('benchmark_terminal_run_id_invalid');
  }
  const canonicalProtocol = (projection.protocol === CANONICAL_BLIND_PROTOCOL
      && ['longmemeval', 'locomo'].includes(projection.benchmark))
    || (projection.protocol === LOCOMO_OFFICIAL_PROTOCOL && projection.benchmark === 'locomo');
  const poisonedRagProtocol = projection.protocol === POISONEDRAG_PROTOCOL_ID
    && projection.benchmark === 'poisonedrag';
  if (!canonicalProtocol && !poisonedRagProtocol) {
    throw new Error('benchmark_terminal_protocol_invalid');
  }
  const intended = assertTerminalInteger(projection.intended_n, 'intended_n');
  const selected = assertTerminalInteger(projection.selected_n, 'selected_n');
  const completed = assertTerminalInteger(projection.completed_n, 'completed_n');
  const incomplete = assertTerminalInteger(projection.incomplete_n, 'incomplete_n');
  const failed = assertTerminalInteger(projection.failed_n, 'failed_n');
  const evaluated = assertTerminalInteger(projection.evaluated_n, 'evaluated_n');
  if (intended < 1
    || selected !== intended
    || completed !== intended
    || evaluated !== intended
    || incomplete !== 0
    || failed !== 0
    || completed + incomplete !== selected) {
    throw new Error('benchmark_terminal_denominator_invalid');
  }
  const expectedPhases = poisonedRagProtocol
    ? []
    : projection.protocol === LOCOMO_OFFICIAL_PROTOCOL
      ? ['recall', 'generate']
      : ['recall', 'generate', 'judge'];
  if (!Array.isArray(projection.phases)
    || projection.phases.length !== expectedPhases.length) {
    throw new Error('benchmark_terminal_phase_set_invalid');
  }
  for (let index = 0; index < expectedPhases.length; index += 1) {
    const phase = projection.phases[index];
    if (phase?.phase !== expectedPhases[index]
      || assertTerminalInteger(phase.selected_n, 'phase_selected_n') !== intended
      || assertTerminalInteger(phase.completed_n, 'phase_completed_n') !== intended
      || assertTerminalInteger(phase.missing_n, 'phase_missing_n') !== 0
      || assertTerminalInteger(phase.failed_n, 'phase_failed_n') !== 0) {
      throw new Error(`benchmark_terminal_phase_invalid:${expectedPhases[index]}`);
    }
    assertTerminalRelativePath(phase.file, 'phase_path');
    assertTerminalHash(phase.summary_sha256, 'phase_summary_sha256');
    assertTerminalHash(phase.file_sha256, 'phase_file_sha256');
  }
  assertTerminalRelativePath(projection.aggregate?.file, 'aggregate_path');
  if (canonicalProtocol) {
    assertTerminalHash(projection.selection_sha256, 'selection_sha256');
    assertTerminalHash(projection.selection_file_sha256, 'selection_file_sha256');
    assertTerminalRelativePath(projection.selection_file, 'selection_path');
  } else {
    assertTerminalHash(projection.execution_plan_sha256, 'execution_plan_sha256');
    assertTerminalHash(projection.outcomes_root_sha256, 'outcomes_root_sha256');
  }
  assertTerminalHash(projection.aggregate?.file_sha256, 'aggregate_file_sha256');
  assertTerminalHash(projection.aggregate?.summary_sha256, 'aggregate_summary_sha256');
  assertTerminalHash(projection.aggregate?.rows_sha256, 'aggregate_rows_sha256');
  const claimed = projection.terminal_evidence_sha256;
  if (!claimed || claimed !== selfHashJson(projection, 'terminal_evidence_sha256')) {
    throw new Error('benchmark_terminal_evidence_hash_invalid');
  }
  return projection;
}

export function buildCanonicalBenchmarkTerminalEvidence({ runId, protocol, benchmark, pass }) {
  const selection = pass?.selection?.value;
  const aggregate = pass?.aggregate?.value;
  if (selection?.schema !== 'hom.canonical-query-selection/v1'
    || selection.run_id !== runId
    || selection.benchmark !== benchmark
    || selection.question_count !== selection.entries?.length
    || selection.selection_sha256 !== selfHashJson(selection, 'selection_sha256')) {
    throw new Error('benchmark_terminal_selection_invalid');
  }
  const official = protocol === LOCOMO_OFFICIAL_PROTOCOL;
  if (aggregate?.schema !== (official
    ? 'hom.locomo-official-summary/v1'
    : 'hom.canonical-benchmark-summary/v2')
    || aggregate.run_id !== runId
    || aggregate.benchmark !== benchmark
    || aggregate.selection_sha256 !== selection.selection_sha256
    || aggregate.summary_sha256 !== selfHashJson(aggregate, 'summary_sha256')
    || (official && aggregate.protocol?.id !== LOCOMO_OFFICIAL_PROTOCOL)) {
    throw new Error('benchmark_terminal_aggregate_invalid');
  }
  const metrics = aggregate.metrics || {};
  const evaluated = official
    ? metrics.official_qa?.evaluated
    : metrics.judged_qa?.judged;
  const phaseEntries = [
    ['recall', pass.recall],
    ['generate', pass.generate],
    ...(official ? [] : [['judge', pass.judge]]),
  ].map(([phaseName, artifact]) => {
    const value = artifact?.value;
    if (value?.schema !== 'hom.canonical-query-phase-summary/v1'
      || value.run_id !== runId
      || value.benchmark !== benchmark
      || value.phase !== phaseName
      || value.summary_sha256 !== selfHashJson(value, 'summary_sha256')) {
      throw new Error(`benchmark_terminal_phase_summary_invalid:${phaseName}`);
    }
    return {
      phase: phaseName,
      file: artifact.file,
      selected_n: value.selected,
      completed_n: value.completed,
      missing_n: value.missing,
      failed_n: Array.isArray(value.failures) ? value.failures.length : -1,
      summary_sha256: value.summary_sha256,
      file_sha256: artifact.sha256,
    };
  });
  const evidence = {
    schema: 'hom.aimos.benchmark-terminal-evidence/v1',
    run_id: runId,
    protocol,
    benchmark,
    intended_n: selection.question_count,
    selected_n: metrics.selected,
    completed_n: metrics.complete,
    incomplete_n: metrics.incomplete,
    failed_n: metrics.incomplete,
    evaluated_n: evaluated,
    selection_sha256: selection.selection_sha256,
    selection_file: pass.selection.file,
    selection_file_sha256: pass.selection.sha256,
    phases: phaseEntries,
    aggregate: {
      file: pass.aggregate.file,
      file_sha256: pass.aggregate.sha256,
      summary_sha256: aggregate.summary_sha256,
      rows_sha256: aggregate.rows_sha256,
    },
  };
  evidence.terminal_evidence_sha256 = selfHashJson(evidence, 'terminal_evidence_sha256');
  return verifyBenchmarkTerminalProjection(evidence);
}

export function buildPoisonedRagTerminalEvidence({ runId, pass }) {
  const summary = pass?.summary?.value;
  if (summary?.schema !== 'hom.aimos.poisonedrag-summary/v1'
    || summary.protocol !== POISONEDRAG_PROTOCOL_ID
    || summary.run_id !== runId
    || summary.denominator_complete !== true
    || summary.summary_sha256 !== selfHashJson(summary, 'summary_sha256')
    || !Array.isArray(summary.target_outcomes)
    || summary.target_outcomes.length !== summary.completed_n) {
    throw new Error('benchmark_terminal_poisonedrag_summary_invalid');
  }
  const evidence = {
    schema: 'hom.aimos.benchmark-terminal-evidence/v1',
    run_id: runId,
    protocol: POISONEDRAG_PROTOCOL_ID,
    benchmark: 'poisonedrag',
    intended_n: summary.intended_n,
    selected_n: summary.intended_n,
    completed_n: summary.completed_n,
    incomplete_n: summary.intended_n - summary.completed_n,
    failed_n: summary.intended_n - summary.completed_n,
    evaluated_n: summary.target_outcomes.length,
    execution_plan_sha256: summary.execution_plan_sha256,
    outcomes_root_sha256: sha256(JSON.stringify(summary.target_outcomes)),
    phases: [],
    aggregate: {
      file: pass.summary.file,
      file_sha256: pass.summary.sha256,
      summary_sha256: summary.summary_sha256,
      rows_sha256: sha256(JSON.stringify(summary.target_outcomes)),
    },
  };
  evidence.terminal_evidence_sha256 = selfHashJson(evidence, 'terminal_evidence_sha256');
  return verifyBenchmarkTerminalProjection(evidence);
}

export function verifyBenchmarkRunTerminalProjection(projection) {
  if (projection?.schema !== 'hom.aimos.benchmark-run-terminal/v1'
    || !/^[a-z0-9][a-z0-9_-]{5,63}$/i.test(String(projection.run_id || ''))
    || !Array.isArray(projection.benchmarks)
    || projection.benchmarks.length < 1) {
    throw new Error('benchmark_run_terminal_shape_invalid');
  }
  const identities = new Set();
  const observedBenchmarks = [];
  let intended = 0;
  let selected = 0;
  let completed = 0;
  let evaluated = 0;
  let incomplete = 0;
  let failed = 0;
  for (const member of projection.benchmarks) {
    verifyBenchmarkTerminalProjection(member);
    if (member.run_id !== projection.run_id || member.protocol !== projection.protocol) {
      throw new Error('benchmark_run_terminal_member_binding_invalid');
    }
    const identity = `${member.protocol}:${member.benchmark}`;
    if (identities.has(identity)) throw new Error('benchmark_run_terminal_member_duplicate');
    identities.add(identity);
    observedBenchmarks.push(member.benchmark);
    intended += member.intended_n;
    selected += member.selected_n;
    completed += member.completed_n;
    evaluated += member.evaluated_n;
    incomplete += member.incomplete_n;
    failed += member.failed_n;
  }
  const expectedBenchmarks = projection.protocol === POISONEDRAG_PROTOCOL_ID
    ? projection.requested_benchmark === 'poisonedrag' ? ['poisonedrag'] : []
    : projection.protocol === LOCOMO_OFFICIAL_PROTOCOL
      ? projection.requested_benchmark === 'locomo' ? ['locomo'] : []
      : projection.protocol === CANONICAL_BLIND_PROTOCOL
        ? projection.requested_benchmark === 'both'
          ? ['longmemeval', 'locomo']
          : ['longmemeval', 'locomo'].includes(projection.requested_benchmark)
            ? [projection.requested_benchmark]
            : []
        : [];
  if (expectedBenchmarks.length === 0
    || JSON.stringify(observedBenchmarks) !== JSON.stringify(expectedBenchmarks)) {
    throw new Error('benchmark_run_terminal_requested_benchmark_mismatch');
  }
  for (const [field, derived] of [
    ['intended_n', intended],
    ['selected_n', selected],
    ['completed_n', completed],
    ['evaluated_n', evaluated],
    ['incomplete_n', incomplete],
    ['failed_n', failed],
  ]) {
    if (assertTerminalInteger(projection[field], field) !== derived) {
      throw new Error(`benchmark_run_terminal_${field}_mismatch`);
    }
  }
  if (intended < 1 || selected !== intended || completed !== intended
    || evaluated !== intended || incomplete !== 0 || failed !== 0
    || projection.denominator_complete !== true) {
    throw new Error('benchmark_run_terminal_denominator_invalid');
  }
  if (projection.run_terminal_sha256 !== selfHashJson(projection, 'run_terminal_sha256')) {
    throw new Error('benchmark_run_terminal_hash_invalid');
  }
  return projection;
}

export function buildBenchmarkRunTerminalEvidence({ runId, protocol, requestedBenchmark, passes }) {
  const benchmarks = [];
  if (passes?.canonical) {
    for (const benchmark of ['longmemeval', 'locomo']) {
      const terminal = passes.canonical[benchmark]?.terminal;
      if (terminal) benchmarks.push(terminal);
    }
  }
  if (passes?.poisonedrag?.terminal) benchmarks.push(passes.poisonedrag.terminal);
  const totals = benchmarks.reduce((accumulator, member) => ({
    intended_n: accumulator.intended_n + member.intended_n,
    selected_n: accumulator.selected_n + member.selected_n,
    completed_n: accumulator.completed_n + member.completed_n,
    evaluated_n: accumulator.evaluated_n + member.evaluated_n,
    incomplete_n: accumulator.incomplete_n + member.incomplete_n,
    failed_n: accumulator.failed_n + member.failed_n,
  }), {
    intended_n: 0,
    selected_n: 0,
    completed_n: 0,
    evaluated_n: 0,
    incomplete_n: 0,
    failed_n: 0,
  });
  const evidence = {
    schema: 'hom.aimos.benchmark-run-terminal/v1',
    run_id: runId,
    protocol,
    requested_benchmark: requestedBenchmark,
    benchmarks,
    ...totals,
    denominator_complete: totals.intended_n > 0
      && totals.selected_n === totals.intended_n
      && totals.completed_n === totals.intended_n
      && totals.evaluated_n === totals.intended_n
      && totals.incomplete_n === 0
      && totals.failed_n === 0,
  };
  evidence.run_terminal_sha256 = selfHashJson(evidence, 'run_terminal_sha256');
  return verifyBenchmarkRunTerminalProjection(evidence);
}

function readTerminalBoundArtifact(runDirectory, relativeFile, expectedSha256, parseJson = true) {
  const relative = assertTerminalRelativePath(relativeFile, 'artifact_path');
  const root = path.resolve(runDirectory);
  const file = path.resolve(root, relative);
  if (!file.startsWith(`${root}${path.sep}`)
    || !existsSync(file)
    || lstatSync(file).isSymbolicLink()
    || !statSync(file).isFile()
    || sha256File(file) !== expectedSha256) {
    throw new Error(`benchmark_terminal_artifact_invalid:${relative}`);
  }
  return { file, value: parseJson ? JSON.parse(readFileSync(file, 'utf8')) : null };
}

export function verifyBenchmarkRunDirectoryTerminal(runDirectory) {
  const root = path.resolve(runDirectory);
  const summaryFile = path.join(root, 'benchmark-summary.json');
  const statusFile = path.join(root, 'run-status.json');
  const hashManifestFile = path.join(root, 'artifact-hashes.json');
  for (const file of [summaryFile, statusFile, hashManifestFile]) {
    if (!existsSync(file) || lstatSync(file).isSymbolicLink() || !statSync(file).isFile()) {
      throw new Error(`benchmark_terminal_required_artifact_missing:${path.basename(file)}`);
    }
  }
  const summary = JSON.parse(readFileSync(summaryFile, 'utf8'));
  const status = JSON.parse(readFileSync(statusFile, 'utf8'));
  const hashes = JSON.parse(readFileSync(hashManifestFile, 'utf8'));
  const terminal = verifyBenchmarkRunTerminalProjection(summary.terminal);
  if (summary.run_id?.toLowerCase() !== terminal.run_id
    || status.state !== 'complete'
    || status.phase !== 'complete'
    || status.terminal?.run_terminal_sha256 !== terminal.run_terminal_sha256
    || JSON.stringify(status.terminal) !== JSON.stringify(terminal)
    || hashes['benchmark-summary.json'] !== sha256File(summaryFile)) {
    throw new Error('benchmark_terminal_top_level_binding_invalid');
  }
  const proofName = existsSync(path.join(root, 'installed-service-proof.json'))
    ? 'installed-service-proof.json'
    : 'isolation-proof.json';
  const proof = readTerminalBoundArtifact(root, proofName, hashes[proofName]).value;
  if (proof.terminal?.run_terminal_sha256 !== terminal.run_terminal_sha256
    || JSON.stringify(proof.terminal) !== JSON.stringify(terminal)) {
    throw new Error('benchmark_terminal_proof_binding_invalid');
  }
  if (proofName === 'installed-service-proof.json'
    && proof.proof_sha256 !== selfHashJson(proof, 'proof_sha256')) {
    throw new Error('benchmark_terminal_execution_proof_hash_invalid');
  }
  const environment = readTerminalBoundArtifact(
    root,
    'environment.json',
    hashes['environment.json'],
  ).value;
  if (environment.schema !== 'hom.aimos.benchmark-environment/v1'
    || environment.authority !== 'descriptive_evidence_only'
    || environment.environment_evidence_sha256 !== selfHashJson(environment, 'environment_evidence_sha256')
    || summary.environment?.environment_evidence_sha256 !== environment.environment_evidence_sha256
    || proof.environment?.environment_evidence_sha256 !== environment.environment_evidence_sha256
    || JSON.stringify(summary.environment) !== JSON.stringify(environment)
    || JSON.stringify(proof.environment) !== JSON.stringify(environment)) {
    throw new Error('benchmark_terminal_environment_binding_invalid');
  }
  for (const member of terminal.benchmarks) {
    if (member.selection_file) {
      const selection = readTerminalBoundArtifact(
        root,
        member.selection_file,
        member.selection_file_sha256,
      ).value;
      if (selection.selection_sha256 !== member.selection_sha256
        || selection.selection_sha256 !== selfHashJson(selection, 'selection_sha256')) {
        throw new Error('benchmark_terminal_selection_binding_invalid');
      }
    }
    for (const phase of member.phases) {
      const phaseSummary = readTerminalBoundArtifact(root, phase.file, phase.file_sha256).value;
      if (phaseSummary.summary_sha256 !== phase.summary_sha256
        || phaseSummary.summary_sha256 !== selfHashJson(phaseSummary, 'summary_sha256')) {
        throw new Error(`benchmark_terminal_phase_binding_invalid:${phase.phase}`);
      }
    }
    const aggregate = readTerminalBoundArtifact(
      root,
      member.aggregate.file,
      member.aggregate.file_sha256,
    ).value;
    if (aggregate.summary_sha256 !== member.aggregate.summary_sha256
      || aggregate.summary_sha256 !== selfHashJson(aggregate, 'summary_sha256')) {
      throw new Error('benchmark_terminal_aggregate_binding_invalid');
    }
    if (member.protocol === POISONEDRAG_PROTOCOL_ID) {
      if (sha256(JSON.stringify(aggregate.target_outcomes)) !== member.outcomes_root_sha256) {
        throw new Error('benchmark_terminal_outcomes_binding_invalid');
      }
    } else {
      readTerminalBoundArtifact(root, aggregate.rows_file, member.aggregate.rows_sha256, false);
    }
  }
  return {
    success: true,
    run_id: terminal.run_id,
    protocol: terminal.protocol,
    benchmark_count: terminal.benchmarks.length,
    intended_n: terminal.intended_n,
    completed_n: terminal.completed_n,
    evaluated_n: terminal.evaluated_n,
    failed_n: terminal.failed_n,
    incomplete_n: terminal.incomplete_n,
    run_terminal_sha256: terminal.run_terminal_sha256,
  };
}

function urlForDatabase(name, runtimeArgs = []) {
  const url = new URL(resolveAimosDatabaseUrl(runtimeArgs));
  url.pathname = `/${name}`;
  return url.toString();
}

async function withPool(databaseName, fn, runtimeArgs = []) {
  const pool = new Pool({ connectionString: urlForDatabase(databaseName, runtimeArgs), ssl: false, connectionTimeoutMillis: 5000 });
  try { return await fn(pool); } finally { await pool.end().catch(() => {}); }
}

async function canonicalFootprint() {
  return withPool('aimos', async (pool) => {
    const rows = await pool.query(
      `SELECT id::text, key, source, encode(content_hash, 'hex') AS content_hash
         FROM aimos_memories
        WHERE key LIKE 'benchmark:%'
           OR key LIKE 'sess:bench:%'
           OR source LIKE 'benchmark_%'
           OR source LIKE 'benchmark:%'
        ORDER BY id`
    );
    const encoded = JSON.stringify(rows.rows);
    return { benchmark_rows: rows.rowCount, benchmark_fingerprint: sha256(encoded) };
  });
}

async function scratchProof(databaseName, runtimeArgs = []) {
  return withPool(databaseName, async (pool) => {
    const result = await pool.query(
      `SELECT
         (SELECT count(*)::int FROM schema_migrations) AS migrations,
         (SELECT count(*)::int FROM aimos_memories) AS memories,
         (SELECT count(*)::int FROM aimos_memories WHERE source = 'guide:genesis-install') AS guide_memories,
         (SELECT count(*)::int FROM aimos_memories WHERE source = 'heartbeat') AS heartbeat_memories,
         (SELECT count(*)::int FROM aimos_memories
           WHERE key LIKE 'benchmark:%'
              OR key LIKE 'sess:bench:%'
              OR source LIKE 'benchmark_%'
              OR source LIKE 'benchmark:%') AS benchmark_memories,
         (SELECT count(*)::int FROM aimos_memories
           WHERE source <> 'guide:genesis-install'
             AND source <> 'heartbeat'
             AND NOT (key LIKE 'benchmark:%'
               OR key LIKE 'sess:bench:%'
               OR source LIKE 'benchmark_%'
               OR source LIKE 'benchmark:%')) AS operational_memories,
         (SELECT count(*)::int FROM aimos_memories m LEFT JOIN aimos_memory_provenance p ON p.memory_id=m.id WHERE p.memory_id IS NULL) AS orphaned_memories`
    );
    const hashes = await pool.query(
      `SELECT encode(p.mutation_hash, 'hex') AS mutation_hash
         FROM aimos_memory_provenance p
         JOIN aimos_memories m ON m.id = p.memory_id
        WHERE m.key LIKE 'benchmark:%'
           OR m.key LIKE 'sess:bench:%'
           OR m.source LIKE 'benchmark_%'
           OR m.source LIKE 'benchmark:%'
        ORDER BY p.created_at, p.provenance_id`
    );
    return {
      ...result.rows[0],
      benchmark_provenance_rows: hashes.rowCount,
      benchmark_chain_fingerprint: sha256(JSON.stringify(hashes.rows))
    };
  }, runtimeArgs);
}

async function buildBenchmarkEnvironmentEvidence({
  args,
  databaseName,
  runtimeArgs = [],
  runId,
  startedAt,
  executionMode,
  serviceConfigurationSha256 = null,
}) {
  const database = await withPool(databaseName, async (pool) => {
    const version = await pool.query(`SELECT current_setting('server_version') AS server_version`);
    const extensions = await pool.query(
      `SELECT extname, extversion FROM pg_extension ORDER BY extname`,
    );
    return {
      server_version: version.rows[0].server_version,
      extensions: Object.fromEntries(extensions.rows.map((row) => [row.extname, row.extversion])),
    };
  }, runtimeArgs);
  const lock = JSON.parse(readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));
  const dependencyVersions = Object.fromEntries(Object.keys(lock.packages?.['']?.dependencies || {})
    .sort()
    .map((name) => [name, lock.packages?.[`node_modules/${name}`]?.version || null]));
  const cpus = os.cpus();
  const configuration = canonicalRunConfiguration(args);
  const identity = {
    authority: 'descriptive_evidence_only',
    execution_mode: executionMode,
    service_configuration_sha256: serviceConfigurationSha256,
    operating_system: {
      platform: os.platform(),
      release: os.release(),
      architecture: os.arch(),
    },
    hardware: {
      cpu_model: cpus[0]?.model || 'unknown',
      logical_cpu_count: cpus.length,
      total_memory_bytes: os.totalmem(),
    },
    runtime: {
      node_version: process.version,
      node_executable_sha256: sha256File(process.execPath),
      package_lock_version: lock.lockfileVersion,
      package_json_sha256: sha256File(path.join(ROOT, 'package.json')),
      package_lock_sha256: sha256File(path.join(ROOT, 'package-lock.json')),
      dependency_versions: dependencyVersions,
    },
    database,
    concurrency: {
      benchmark_query_workers: 1,
      native_save_workers: 1,
      provider_requests_per_question: configuration.protocol === POISONEDRAG_PROTOCOL_ID
        ? 6
        : configuration.protocol === LOCOMO_OFFICIAL_PROTOCOL
          ? 1
          : 2,
      execution_order: 'deterministic_sequential_question_order',
    },
    protocol_configuration: configuration,
    native_surfaces: {
      save: '/aimos/save',
      recall: '/aimos/recall',
      second_runtime_owner: false,
      second_database_authority: false,
      second_identity_authority: false,
    },
  };
  const evidence = {
    schema: 'hom.aimos.benchmark-environment/v1',
    run_id: runId,
    started_at: startedAt,
    captured_at: new Date().toISOString(),
    ...identity,
    environment_identity_sha256: sha256(JSON.stringify(identity)),
  };
  evidence.environment_evidence_sha256 = selfHashJson(evidence, 'environment_evidence_sha256');
  return evidence;
}

async function retainBenchmarkEnvironmentEvidence(outputDir, input) {
  const file = path.join(outputDir, 'environment.json');
  const current = await buildBenchmarkEnvironmentEvidence(input);
  if (existsSync(file)) {
    if (lstatSync(file).isSymbolicLink() || !statSync(file).isFile()) {
      throw new Error('benchmark_environment_artifact_invalid');
    }
    const retained = JSON.parse(readFileSync(file, 'utf8'));
    if (retained.environment_evidence_sha256 !== selfHashJson(retained, 'environment_evidence_sha256')
      || retained.environment_identity_sha256 !== current.environment_identity_sha256
      || retained.run_id !== input.runId) {
      throw new Error('benchmark_environment_resume_mismatch');
    }
    return retained;
  }
  writeFileSync(file, `${JSON.stringify(current, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return current;
}

function spawnLogged(command, args, logPath, { finite = true } = {}) {
  const fd = openSync(logPath, 'a');
  const child = spawn(command, args, { cwd: ROOT, stdio: ['ignore', fd, fd] });
  closeSync(fd);
  if (!finite) return child;
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve({ code, signal });
      else reject(new Error(`${command} ${args.slice(0, 2).join(' ')} exited ${code ?? signal}; inspect ${logPath}`));
    });
  });
}

function spawnInteractive(command, args) {
  const child = spawn(command, args, { cwd: ROOT, stdio: 'inherit' });
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve({ code, signal });
      else reject(new Error(`${command} ${args.slice(0, 2).join(' ')} exited ${code ?? signal}`));
    });
  });
}

function captureFile(file) {
  if (!existsSync(file)) return { exists: false, data: null, mode: null };
  const stat = statSync(file);
  if (!stat.isFile()) throw new Error(`protected path is not a file: ${file}`);
  return { exists: true, data: readFileSync(file), mode: stat.mode & 0o777 };
}

function restoreFile(file, snapshot) {
  if (!snapshot.exists) {
    if (existsSync(file)) unlinkSync(file);
    return;
  }
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, snapshot.data, { mode: snapshot.mode });
  chmodSync(file, snapshot.mode);
}

function protectedKeyState(file) {
  if (!existsSync(file)) throw new Error(`canonical identity key missing: ${file}`);
  const stat = statSync(file);
  if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) {
    throw new Error(`canonical identity key custody invalid: ${file}`);
  }
  return { sha256: sha256File(file), mode: stat.mode & 0o777 };
}

function assertProtectedKeyUnchanged(file, before) {
  const after = protectedKeyState(file);
  if (after.sha256 !== before.sha256 || after.mode !== before.mode) {
    throw new Error('canonical housekeeper key changed during scratch lifecycle');
  }
}

async function databaseExists(databaseName) {
  return withPool('postgres', async (pool) => {
    const result = await pool.query('SELECT 1 FROM pg_database WHERE datname = $1', [databaseName]);
    return result.rowCount === 1;
  });
}

async function verifyArtifactHashSet(root, hashes) {
  for (const [relativePath, expected] of Object.entries(hashes)) {
    const file = path.resolve(root, relativePath);
    if (file !== root && !file.startsWith(`${path.resolve(root)}${path.sep}`)) {
      throw new Error(`artifact hash path escaped output root: ${relativePath}`);
    }
    if (!existsSync(file) || await streamSha256(file) !== expected) {
      throw new Error(`artifact hash verification failed: ${relativePath}`);
    }
  }
  return { verified: true, files: Object.keys(hashes).length };
}

async function runSignedScratchPurge(databaseName, receiptPath) {
  await spawnInteractive(process.execPath, [
    'scripts/ceremony/purge-brain.mjs',
    '--live',
    '--aimos-db', databaseName,
    '--receipt-file', receiptPath,
  ]);
  const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
  const verification = verifyWholeBrainPurgeReceipt(receipt);
  if (!verification.valid) throw new Error(`scratch purge receipt invalid:${verification.reason}`);
  if (verification.database !== databaseName
    || verification.postcondition?.mode !== 'destroyed'
    || verification.postcondition?.database_present !== false) {
    throw new Error('scratch purge receipt postcondition mismatch');
  }
  if (await databaseExists(databaseName)) throw new Error('scratch database still exists after signed purge');
  return {
    receipt_file: path.basename(receiptPath),
    receipt_sha256: sha256File(receiptPath),
    verification,
  };
}

// A retained benchmark brain can contain hundreds of thousands of signed
// events. Startup verifies the complete housekeeper event history before the
// server reports ready, so recovery must allow that native proof to finish.
// This is a fixed protocol-side bound, not ambient or ENV-owned authority.
export async function assertLoopbackPortAvailable(port) {
  await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.once('error', (error) => {
      reject(new Error(error?.code === 'EADDRINUSE'
        ? `scratch_port_already_owned:${port}`
        : `scratch_port_probe_failed:${port}:${error?.code || error?.message || 'unknown'}`));
    });
    probe.listen({ host: '127.0.0.1', port, exclusive: true }, () => {
      probe.close((error) => (error ? reject(error) : resolve()));
    });
  });
}

async function waitForHealth(baseUrl, child, expectedDatabaseName, timeoutMs = 1_800_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode != null) throw new Error(`scratch server exited with ${child.exitCode}`);
    let body = null;
    try {
      const response = await fetch(`${baseUrl}/healthz`, { signal: AbortSignal.timeout(1500) });
      body = await response.json();
      if (response.ok && body.ready === true
        && body.runtime?.database_name === expectedDatabaseName
        && body.runtime?.benchmark_scratch === true) return body;
    } catch { /* server is still booting */ }
    if (body?.bootError) throw new Error(`scratch server background boot failed:${body.bootError}`);
    // Stay below the server's native 100-request/minute general limiter. A
    // faster readiness loop can throttle itself during long ledger proofs.
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw new Error(`scratch server did not become ready at ${baseUrl}`);
}

async function stopChild(child) {
  if (!child || child.exitCode != null) return;
  child.kill('SIGTERM');
  const exited = await Promise.race([
    new Promise(resolve => child.once('exit', () => resolve(true))),
    new Promise(resolve => setTimeout(() => resolve(false), 5000))
  ]);
  if (!exited && child.exitCode == null) child.kill('SIGKILL');
}

// Stream-hash a single file so multi-GB artifacts (full_detail recall records
// exceed the 2 GiB readFileSync limit) hash without loading into memory.
function streamSha256(file) {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    createReadStream(file).on('data', d => h.update(d)).on('end', () => resolve(h.digest('hex'))).on('error', reject);
  });
}

// Recursively hash every produced artifact (excluding the hash manifest itself).
async function artifactHashes(dir, base = dir, out = {}) {
  for (const name of readdirSync(dir).sort()) {
    const file = path.join(dir, name);
    const rel = path.relative(base, file);
    const st = statSync(file);
    if (st.isDirectory()) { await artifactHashes(file, base, out); continue; }
    // run-status.json is a mutable operational projection, not publication
    // evidence. The immutable run manifest and phase proofs remain hashed.
    if (name === 'artifact-hashes.json' || name === 'run-status.json' || name === 'run-status.json.tmp') continue;
    out[rel] = await streamSha256(file);
  }
  return out;
}

// Parse a harness pass's summary.json (written into <passDir>/ledger/summary.json).
function readPassSummary(passDir) {
  const summaryFile = path.join(passDir, 'ledger', 'summary.json');
  if (!existsSync(summaryFile)) return null;
  try { return JSON.parse(readFileSync(summaryFile, 'utf8')); } catch { return null; }
}

function readLatestJsonArtifact(dir, prefix) {
  const name = readdirSync(dir)
    .filter((entry) => entry.startsWith(prefix) && entry.endsWith('.json'))
    .sort((left, right) => left.localeCompare(right))
    .at(-1);
  if (!name) throw new Error(`required benchmark artifact missing: ${prefix}`);
  const file = path.join(dir, name);
  return {
    file: path.relative(dir, file),
    sha256: sha256File(file),
    value: JSON.parse(readFileSync(file, 'utf8')),
  };
}

function readCanonicalAggregate(dir, benchmark) {
  const names = [];
  const fixed = path.join(dir, `canonical-summary-${benchmark}.json`);
  if (existsSync(fixed)) names.push(fixed);
  const successorRoot = path.join(dir, 'aggregate-successors', benchmark);
  if (existsSync(successorRoot)) {
    for (const entry of readdirSync(successorRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const candidate = path.join(successorRoot, entry.name, `canonical-summary-${benchmark}.json`);
      if (existsSync(candidate)) names.push(candidate);
    }
  }
  const complete = names.map((file) => ({
    file,
    value: JSON.parse(readFileSync(file, 'utf8')),
  })).filter((entry) => Number(entry.value?.metrics?.incomplete) === 0);
  if (complete.length !== 1) {
    throw new Error(`canonical_complete_aggregate_count_invalid:${benchmark}:${complete.length}`);
  }
  return {
    file: path.relative(dir, complete[0].file),
    sha256: sha256File(complete[0].file),
    value: complete[0].value,
  };
}

function canonicalSelections(args) {
  const benchmarks = args.benchmark === 'both'
    ? ['longmemeval', 'locomo']
    : [args.benchmark];
  if (args.full) return benchmarks.map((benchmark) => ({ benchmark, all: true }));
  if (args.gate) return benchmarks.map((benchmark) => ({ benchmark, selectionProfile: args.gate }));
  if (benchmarks.length === 1) {
    return [{ benchmark: benchmarks[0], questionLimit: args.sample }];
  }
  const longmemevalCount = Math.floor(args.sample / 2);
  return [
    { benchmark: 'longmemeval', questionLimit: longmemevalCount },
    { benchmark: 'locomo', questionLimit: args.sample - longmemevalCount },
  ];
}

async function runModelPreflight(context, logDir, generatorModel = 'gpt-5.4') {
  const modelPreflightFile = path.join(ROOT, 'eval', 'public-results', 'model-preflight', `${context.runId}.json`);
  context.onPhase?.('model-access-preflight');
  if (!existsSync(modelPreflightFile)) {
    await spawnLogged(process.execPath, [
      'scripts/ceremony/benchmark-model-preflight.mjs',
      '--live',
      '--generator-model', generatorModel,
      '--receipt-file', modelPreflightFile,
      ...(context.databaseName ? ['--aimos-db', context.databaseName] : []),
      ...(context.installedService ? ['--installed-service'] : []),
      ...(context.runtimeCliArgs || []),
    ], path.join(logDir, 'model-access-preflight.log'));
  }
  if (lstatSync(modelPreflightFile).isSymbolicLink() || !statSync(modelPreflightFile).isFile()) {
    throw new Error('benchmark_model_preflight_receipt_invalid');
  }
  const modelPreflight = JSON.parse(readFileSync(modelPreflightFile, 'utf8'));
  const generatorCall = modelPreflight?.body?.calls?.find((call) => call.role === 'generator');
  const judgeCall = modelPreflight?.body?.calls?.find((call) => call.role === 'judge');
  if (modelPreflight?.body?.schema_version !== 'aimos.benchmark-model-preflight/v1'
    || modelPreflight?.verification?.receipt_signature_valid !== true
    || modelPreflight?.verification?.model_catalog_exact_match !== true
    || modelPreflight?.verification?.structured_smoke_calls_valid !== true
    || generatorCall?.requested_model !== generatorModel
    || generatorCall?.actual_model !== generatorModel
    || judgeCall?.requested_model !== 'gpt-5.6-terra'
    || judgeCall?.actual_model !== 'gpt-5.6-terra') {
    throw new Error('benchmark_model_preflight_receipt_invalid');
  }
  return {
    file: path.relative(ROOT, modelPreflightFile),
    sha256: sha256File(modelPreflightFile),
  };
}

async function runCanonicalBenchmark(args, context) {
  const canonical = {};
  const logDir = path.join(context.outputDir, 'logs');
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const prepared = [];

  for (const selection of canonicalSelections(args)) {
    const benchmark = selection.benchmark;
    const selectionFile = path.join(context.outputDir, `selection-${benchmark}.json`);
    const common = [
      'eval/run-canonical-single-query.mjs',
      '--benchmark', benchmark,
      '--protocol', args.protocol,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--agent-id', context.agentId || 'housekeeper',
      ...(context.installedService ? ['--installed-service'] : []),
      ...(context.runtimeCliArgs || []),
    ];
    context.onPhase?.(`${benchmark}-prepare`);
    await spawnLogged(process.execPath, [
      ...common,
      '--phase', 'prepare',
      ...(selection.all
        ? ['--all']
        : selection.selectionProfile
          ? ['--selection-profile', selection.selectionProfile]
          : ['--question-limit', String(selection.questionLimit)]),
    ], path.join(logDir, `${benchmark}-prepare.log`));

    context.onPhase?.(`${benchmark}-corpus-preflight`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--agent-id', context.agentId || 'housekeeper',
      ...(context.installedService ? ['--installed-service'] : []),
      ...(context.runtimeCliArgs || []),
      '--dry-run',
    ], path.join(logDir, `${benchmark}-replay-preflight.log`));
    prepared.push({ benchmark, selectionFile, common });
  }

  canonical.model_preflight = await runModelPreflight(context, logDir);

  for (const { benchmark, selectionFile, common } of prepared) {

    context.onPhase?.(`${benchmark}-replay`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--agent-id', context.agentId || 'housekeeper',
      ...(context.installedService ? ['--installed-service'] : []),
      ...(context.runtimeCliArgs || []),
      '--delay-ms', '2100',
      '--retries', '3',
    ], path.join(logDir, `${benchmark}-replay.log`));

    context.onPhase?.(`${benchmark}-recall`);
    await spawnLogged(process.execPath, [
      ...common,
      '--phase', 'recall',
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--recall-k', String(args.limit),
      '--delay-ms', '2100',
      '--retries', '3',
    ], path.join(logDir, `${benchmark}-recall.log`));

    context.onPhase?.(`${benchmark}-generate`);
    await spawnLogged(process.execPath, [
      ...common,
      '--phase', 'generate',
      '--delay-ms', '0',
      '--retries', '3',
    ], path.join(logDir, `${benchmark}-generate.log`));

    if (args.protocol !== LOCOMO_OFFICIAL_PROTOCOL) {
      context.onPhase?.(`${benchmark}-judge`);
      await spawnLogged(process.execPath, [
        ...common,
        '--phase', 'judge',
        '--judge-reasoning', 'high',
        '--delay-ms', '0',
        '--retries', '3',
      ], path.join(logDir, `${benchmark}-judge.log`));
    }

    context.onPhase?.(`${benchmark}-aggregate`);
    await spawnLogged(process.execPath, [
      args.protocol === LOCOMO_OFFICIAL_PROTOCOL
        ? 'eval/aggregate-locomo-official-results.mjs'
        : 'eval/aggregate-canonical-results.mjs',
      ...(args.protocol === LOCOMO_OFFICIAL_PROTOCOL ? [] : ['--benchmark', benchmark]),
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
    ], path.join(logDir, `${benchmark}-aggregate.log`));

    const pass = {
      selection: {
        file: path.basename(selectionFile),
        sha256: sha256File(selectionFile),
        value: JSON.parse(readFileSync(selectionFile, 'utf8')),
      },
      replay: readLatestJsonArtifact(context.outputDir, `replay-summary-${benchmark}-`),
      recall: readLatestJsonArtifact(context.outputDir, `phase-recall-${benchmark}-`),
      generate: readLatestJsonArtifact(context.outputDir, `phase-generate-${benchmark}-`),
      judge: args.protocol === LOCOMO_OFFICIAL_PROTOCOL
        ? null
        : readLatestJsonArtifact(context.outputDir, `phase-judge-${benchmark}-`),
      aggregate: args.protocol === LOCOMO_OFFICIAL_PROTOCOL
        ? {
          file: 'locomo-official-summary.json',
          sha256: sha256File(path.join(context.outputDir, 'locomo-official-summary.json')),
          value: JSON.parse(readFileSync(path.join(context.outputDir, 'locomo-official-summary.json'), 'utf8')),
        }
        : readCanonicalAggregate(context.outputDir, benchmark),
    };
    pass.terminal = buildCanonicalBenchmarkTerminalEvidence({
      runId: context.runId,
      protocol: args.protocol,
      benchmark,
      pass,
    });
    canonical[benchmark] = pass;
  }
  return canonical;
}

async function runPoisonedRagBenchmark(args, context) {
  const logDir = path.join(context.outputDir, 'logs');
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const modelPreflight = await runModelPreflight(context, logDir, POISONEDRAG_GENERATOR_MODEL);
  const targetCount = args.full ? 100 : args.sample;
  context.onPhase?.('poisonedrag-ingest-recall');
  await spawnLogged(process.execPath, [
    'eval/run-poisonedrag-n100.mjs',
    '--phase', 'ingest-recall',
    '--run-id', context.runId,
    '--run-dir', context.outputDir,
    '--aimos-base', context.baseUrl,
    '--aimos-db', context.databaseName,
    '--agent-id', context.agentId || 'housekeeper',
    ...(context.installedService ? ['--installed-service'] : []),
    ...(context.runtimeCliArgs || []),
    '--target-count', String(targetCount),
    '--delay-ms', '2100',
    '--retries', String(POISONEDRAG_MAX_ATTEMPTS),
  ], path.join(logDir, 'poisonedrag-ingest-recall.log'));
  context.onPhase?.('poisonedrag-model-aggregate');
  await spawnLogged(process.execPath, [
    'eval/run-poisonedrag-n100.mjs',
    '--phase', 'model-aggregate',
    '--run-id', context.runId,
    '--run-dir', context.outputDir,
    '--aimos-base', context.baseUrl,
    '--aimos-db', context.databaseName,
    '--agent-id', context.agentId || 'housekeeper',
    ...(context.installedService ? ['--installed-service'] : []),
    ...(context.runtimeCliArgs || []),
    '--target-count', String(targetCount),
    '--delay-ms', '2100',
    '--retries', String(POISONEDRAG_MAX_ATTEMPTS),
  ], path.join(logDir, 'poisonedrag-model-aggregate.log'));
  const summaryFile = path.join(context.outputDir, 'poisonedrag', 'summary.json');
  const progressFile = path.join(context.outputDir, 'poisonedrag', 'progress.json');
  if (!existsSync(summaryFile) || !existsSync(progressFile)) {
    throw new Error('poisonedrag_terminal_artifacts_missing');
  }
  const summary = JSON.parse(readFileSync(summaryFile, 'utf8'));
  if (summary.schema !== 'hom.aimos.poisonedrag-summary/v1'
    || summary.protocol !== POISONEDRAG_PROTOCOL_ID
    || summary.intended_n !== targetCount
    || summary.completed_n !== targetCount
    || summary.denominator_complete !== true) {
    throw new Error('poisonedrag_summary_invalid');
  }
  const pass = {
    model_preflight: modelPreflight,
    target_count: targetCount,
    summary: {
      file: path.relative(context.outputDir, summaryFile),
      sha256: sha256File(summaryFile),
      value: summary,
    },
  };
  pass.terminal = buildPoisonedRagTerminalEvidence({ runId: context.runId, pass });
  return pass;
}

function baseHarnessArgs(args, databaseName, baseUrl) {
  return [
    'eval/run-locomo-longmem-benchmarks.js',
    '--aimos-db', databaseName,
    '--aimos-port', String(args.port),
    '--aimos-base', baseUrl,
    '--agent-id', 'housekeeper',
    '--benchmark', args.benchmark,
    '--longmemeval-file', args.longmemevalFile,
    '--limit', String(args.limit),
    '--request-interval-ms', '0',
    '--progress-every', '10',
    ...(args.full ? ['--full'] : ['--sample', String(args.sample)])
  ];
}

export function canonicalRunConfiguration(args) {
  if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
    return {
      protocol: args.protocol,
      benchmark: args.benchmark,
      full: args.full,
      smoke: args.smoke,
      sample: args.full ? 100 : args.sample,
      recall_depth_k: 5,
      generator: `codex:${POISONEDRAG_GENERATOR_MODEL}`,
      judge: 'codex:gpt-5.6-terra',
      judge_reasoning: 'high',
      phase_retries: POISONEDRAG_MAX_ATTEMPTS,
      signed_save_interval_ms: 2100,
      corpus_preflight: 'poisonedrag-pinned-inputs/v1',
      model_preflight: 'aimos.benchmark-model-preflight/v1',
    };
  }
  if (args.protocol === TWIN_PRIME_G1P_PROTOCOL) {
    return {
      protocol: args.protocol,
      benchmark: 'both',
      full: false,
      smoke: false,
      sample_per_dataset: args.sample,
      recall_depth_k: 20,
      generator: null,
      judge: null,
      phase_retries: 6,
      signed_save_interval_ms: 2100,
      signed_recall_interval_ms: 2100,
      corpus_preflight: 'hom.canonical-benchmark-query-inputs/v1',
      origin_time_binding: 'hom-aimos-memory-binding/v4',
      profile: 'hom-aimos/twin-prime-g1p-profile/v1',
    };
  }
  if (args.protocol === TWIN_PRIME_G5_PROTOCOL) {
    const pilotContractFile = path.join(TWIN_PRIME_G5_CONTRACT, 'pilot-contract.json');
    const artifactManifestFile = path.join(TWIN_PRIME_G5_CONTRACT, 'artifact-manifest.json');
    const pilotContract = JSON.parse(readFileSync(pilotContractFile, 'utf8'));
    const artifactManifest = JSON.parse(readFileSync(artifactManifestFile, 'utf8'));
    return {
      protocol: args.protocol,
      benchmark: 'both',
      gate: 'b4',
      gate_name: 'gate10',
      question_count: 10,
      arms: ['B0', 'B1', 'B2', 'T'],
      recall_depth_k: 20,
      generator: 'codex:gpt-5.5',
      generator_reasoning: 'medium',
      judge: 'codex:gpt-5.6-terra',
      judge_reasoning: 'high',
      phase_retries: 6,
      signed_save_interval_ms: 2100,
      signed_recall_interval_ms: 2100,
      effective_policy_authority: 'signed_system_config_ledger',
      t_enforcement_scope: 'exact_scratch_database_only',
      canonical_policy_unchanged: true,
      pilot_contract_sha256: pilotContract.pilot_contract_sha256,
      artifact_manifest_sha256: artifactManifest.artifact_manifest_sha256,
    };
  }
  return {
    protocol: args.protocol,
    benchmark: args.benchmark,
    full: args.full,
    smoke: args.smoke,
    gate: args.gate,
    sample: args.sample,
    recall_depth_k: args.limit,
    generator: 'codex:gpt-5.4',
    judge: args.protocol === LOCOMO_OFFICIAL_PROTOCOL ? null : 'codex:gpt-5.6-terra',
    judge_reasoning: args.protocol === LOCOMO_OFFICIAL_PROTOCOL ? null : 'high',
    phase_retries: 3,
    corpus_preflight: 'native-save-contract/v1',
    model_preflight: 'aimos.benchmark-model-preflight/v1',
  };
}

async function runTwinPrimeG1P(args, context) {
  const logDir = path.join(context.outputDir, 'logs');
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const common = [
    'eval/run-twin-prime-g1p.mjs',
    '--run-id', context.runId,
    '--run-dir', context.outputDir,
    '--corpus-dir', TWIN_PRIME_G1P_CORPUS,
    '--sample-per-dataset', String(args.sample),
    '--aimos-db', context.databaseName,
    '--aimos-base', context.baseUrl,
    '--retries', '6',
    '--delay-ms', '2100',
  ];
  context.onPhase?.('tp-g1p-prepare');
  await spawnLogged(process.execPath, [...common, '--phase', 'prepare'], path.join(logDir, 'tp-g1p-prepare.log'));

  for (const benchmark of ['locomo', 'longmemeval']) {
    const selectionFile = path.join(context.outputDir, `selection-${benchmark}.json`);
    const sessionsFile = path.join(TWIN_PRIME_G1P_CORPUS, `${benchmark}-sessions.json`);
    context.onPhase?.(`tp-g1p-${benchmark}-replay-preflight`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--sessions-file', sessionsFile,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--dry-run',
    ], path.join(logDir, `tp-g1p-${benchmark}-replay-preflight.log`));

    context.onPhase?.(`tp-g1p-${benchmark}-replay`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--sessions-file', sessionsFile,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--delay-ms', '2100',
      '--retries', '6',
    ], path.join(logDir, `tp-g1p-${benchmark}-replay.log`));
  }

  context.onPhase?.('tp-g1p-profile');
  await spawnLogged(process.execPath, [...common, '--phase', 'profile'], path.join(logDir, 'tp-g1p-profile.log'));
  context.onPhase?.('tp-g1p-aggregate');
  await spawnLogged(process.execPath, [...common, '--phase', 'aggregate'], path.join(logDir, 'tp-g1p-aggregate.log'));
  const summaryFile = path.join(context.outputDir, 'tp-g1p-summary.json');
  const summary = JSON.parse(readFileSync(summaryFile, 'utf8'));
  if (summary.schema !== 'hom.twin-prime-g1p-summary/v1'
    || summary.run_id !== context.runId
    || summary.generator_calls !== 0
    || summary.judge_calls !== 0
    || summary.gold_opened !== false
    || !['stop', 'pass', 'expand'].includes(summary.feasibility?.decision)) {
    throw new Error('tp_g1p_summary_invalid');
  }
  return { summary: { file: path.basename(summaryFile), sha256: sha256File(summaryFile), value: summary } };
}

async function runTwinPrimeG5(args, context) {
  const logDir = path.join(context.outputDir, 'logs');
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const gate = args.gate === 'b4' ? 'gate10' : 'gate50';
  const common = [
    'eval/twin-prime/run-g5-pilot.mjs',
    '--run-id', context.runId,
    '--run-dir', context.outputDir,
    '--gate', gate,
  ];

  context.onPhase?.(`tp-g5-${gate}-prepare`);
  await spawnLogged(process.execPath, [...common, '--phase', 'prepare'], path.join(logDir, `tp-g5-${gate}-prepare.log`));

  const modelPreflight = await runModelPreflight(context, logDir, 'gpt-5.5');
  for (const benchmark of ['locomo', 'longmemeval']) {
    const selectionFile = path.join(context.outputDir, `selection-${benchmark}.json`);
    const sessionsFile = path.join(TWIN_PRIME_G1P_CORPUS, `${benchmark}-sessions.json`);
    context.onPhase?.(`tp-g5-${gate}-${benchmark}-replay-preflight`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--sessions-file', sessionsFile,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--dry-run',
    ], path.join(logDir, `tp-g5-${gate}-${benchmark}-replay-preflight.log`));

    context.onPhase?.(`tp-g5-${gate}-${benchmark}-replay`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--sessions-file', sessionsFile,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--delay-ms', '2100',
      '--retries', '6',
    ], path.join(logDir, `tp-g5-${gate}-${benchmark}-replay.log`));
  }

  context.onPhase?.(`tp-g5-${gate}-recall`);
  await spawnInteractive(process.execPath, [
    ...common,
    '--phase', 'recall',
    '--aimos-db', context.databaseName,
    '--aimos-base', context.baseUrl,
    '--server-pid', String(context.serverPid),
    ...(args.keychainAccount ? ['--keychain-account', args.keychainAccount] : []),
    '--live',
  ]);

  for (const phase of ['generate', 'judge', 'aggregate']) {
    context.onPhase?.(`tp-g5-${gate}-${phase}`);
    await spawnLogged(process.execPath, [...common, '--phase', phase], path.join(logDir, `tp-g5-${gate}-${phase}.log`));
  }

  const summaryFile = path.join(context.outputDir, 'twin-prime-g5', gate, 'pilot-summary.json');
  if (!existsSync(summaryFile) || lstatSync(summaryFile).isSymbolicLink()) throw new Error('tp_g5_pilot_summary_missing');
  const summary = JSON.parse(readFileSync(summaryFile, 'utf8'));
  if (summary?.schema !== 'hom.aimos.twin-prime-pilot-summary/v1'
    || summary.run_id !== context.runId
    || summary.gate !== gate
    || summary.question_count !== 10
    || summary.arm_question_outputs !== 40
    || !summary.by_arm?.B0 || !summary.by_arm?.B1 || !summary.by_arm?.B2 || !summary.by_arm?.T
    || !/^[0-9a-f]{64}$/.test(String(summary.summary_sha256 || ''))) {
    throw new Error('tp_g5_pilot_summary_invalid');
  }
  return {
    model_preflight: modelPreflight,
    summary: {
      file: path.relative(context.outputDir, summaryFile),
      sha256: sha256File(summaryFile),
      value: summary,
    },
  };
}

function writeRunStatus(outputDir, status) {
  const file = path.join(outputDir, 'run-status.json');
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, `${JSON.stringify({
    schema: 'hom.canonical-benchmark-run-status/v1',
    updated_at: new Date().toISOString(),
    ...status,
  }, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, file);
}

export function writeRunManifest(outputDir, manifest) {
  const file = path.join(outputDir, 'run-manifest.json');
  const value = { schema: 'hom.canonical-benchmark-run-manifest/v1', ...manifest };
  value.manifest_sha256 = sha256(JSON.stringify(value));
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return value;
}

export function readRunManifest(outputDir, expectedRunId, expectedDatabaseName, expectedConfiguration) {
  const file = path.join(outputDir, 'run-manifest.json');
  if (!existsSync(file) || statSync(file).isSymbolicLink()) throw new Error('resume_run_manifest_missing_or_invalid');
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  const claimedHash = manifest.manifest_sha256;
  const unsigned = { ...manifest };
  delete unsigned.manifest_sha256;
  const manifestConfiguration = manifest.configuration;
  const retryRecovery = manifestConfiguration?.protocol === POISONEDRAG_PROTOCOL_ID
    && expectedConfiguration?.protocol === POISONEDRAG_PROTOCOL_ID
    && Number.isInteger(manifestConfiguration.phase_retries)
    && manifestConfiguration.phase_retries >= 1
    && manifestConfiguration.phase_retries < expectedConfiguration.phase_retries
    && expectedConfiguration.phase_retries === POISONEDRAG_MAX_ATTEMPTS
    && JSON.stringify({
      ...manifestConfiguration,
      phase_retries: expectedConfiguration.phase_retries,
    }) === JSON.stringify(expectedConfiguration)
      ? {
          original_attempt_ceiling: manifestConfiguration.phase_retries,
          effective_attempt_ceiling: expectedConfiguration.phase_retries,
        }
      : null;
  if (manifest.schema !== 'hom.canonical-benchmark-run-manifest/v1'
    || manifest.run_id !== expectedRunId
    || manifest.database_name !== expectedDatabaseName
    || claimedHash !== sha256(JSON.stringify(unsigned))
    || (JSON.stringify(manifestConfiguration) !== JSON.stringify(expectedConfiguration) && !retryRecovery)) {
    throw new Error('resume_run_manifest_mismatch');
  }
  Object.defineProperty(manifest, 'retry_recovery', {
    value: retryRecovery,
    enumerable: false,
    writable: false,
  });
  return manifest;
}

export function writeRetryRecoveryReceipt(outputDir, runId, manifest) {
  const recovery = manifest?.retry_recovery;
  if (!recovery) return null;
  const file = path.join(outputDir, 'retry-recovery-receipt.json');
  if (existsSync(file)) {
    if (statSync(file).isSymbolicLink()) throw new Error('retry_recovery_receipt_invalid');
    const existing = JSON.parse(readFileSync(file, 'utf8'));
    const claimedHash = existing.receipt_sha256;
    const unsignedExisting = { ...existing };
    delete unsignedExisting.receipt_sha256;
    if (existing.schema !== 'hom.poisonedrag-retry-recovery/v1'
      || existing.run_id !== runId
      || existing.original_manifest_sha256 !== manifest.manifest_sha256
      || existing.original_attempt_ceiling !== recovery.original_attempt_ceiling
      || existing.effective_attempt_ceiling !== recovery.effective_attempt_ceiling
      || claimedHash !== sha256(JSON.stringify(unsignedExisting))) {
      throw new Error('retry_recovery_receipt_invalid');
    }
    return { file: path.basename(file), sha256: sha256File(file), value: existing };
  }
  const statusFile = path.join(outputDir, 'run-status.json');
  const receipt = {
    schema: 'hom.poisonedrag-retry-recovery/v1',
    run_id: runId,
    protocol: POISONEDRAG_PROTOCOL_ID,
    original_manifest_sha256: manifest.manifest_sha256,
    prior_run_status_sha256: existsSync(statusFile) ? sha256File(statusFile) : null,
    original_attempt_ceiling: recovery.original_attempt_ceiling,
    effective_attempt_ceiling: recovery.effective_attempt_ceiling,
    retryable_failure_classes: ['transport', 'timeout', '408', '425', '429', '500', '502', '503', '504'],
    non_retryable_failure_classes: ['authentication', 'authorization', 'model_substitution', 'artifact_integrity'],
    scientific_inputs_unchanged: true,
    completed_provider_outputs_reused: true,
    authorized_reason: 'operator_authorized_retry_ceiling_increase_after_transient_provider_failure',
    created_at: new Date().toISOString(),
  };
  receipt.receipt_sha256 = sha256(JSON.stringify(receipt));
  writeFileSync(file, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return { file: path.basename(file), sha256: sha256File(file), value: receipt };
}

function installedRuntimeArgs(definition) {
  return [
    '--aimos-instance', definition.instance,
    '--aimos-postgres-port', String(definition.postgres_port),
  ];
}

async function requireInstalledBenchmarkService(definition) {
  const origin = `http://127.0.0.1:${definition.port}`;
  const response = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(10_000) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ready !== true
    || body.runtime?.database_name !== definition.database
    || Number(body.runtime?.server_port) !== Number(definition.port)
    || body.runtime?.benchmark_scratch !== false) {
    throw new Error('installed_benchmark_service_identity_mismatch');
  }
  return { origin, health: body };
}

function installedDatasetBindings(args) {
  if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
    return {
      poisonedrag_source_lock: {
        file: path.relative(ROOT, POISONEDRAG_SOURCE_LOCK),
        sha256: sha256File(POISONEDRAG_SOURCE_LOCK),
      },
      poisonedrag_public_target_lock: {
        file: path.relative(ROOT, POISONEDRAG_PUBLIC_LOCK),
        sha256: sha256File(POISONEDRAG_PUBLIC_LOCK),
      },
      poisonedrag_private_target_manifest: {
        file: 'n100-private-target-manifest.json',
        sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-private-target-manifest.json')),
        redistributed: false,
      },
      poisonedrag_corpus_resolution: {
        file: 'n100-corpus-resolution.json',
        sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-corpus-resolution.json')),
        redistributed: false,
      },
      poisonedrag_candidate_pool: {
        file: 'n100-candidate-pool.jsonl',
        sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-candidate-pool.jsonl')),
        redistributed: false,
      },
    };
  }
  const corpusManifest = path.join(ROOT, 'eval', 'data', 'canonical', 'corpus-manifest.json');
  return {
    longmemeval: { path: args.longmemevalFile, sha256: sha256File(args.longmemevalFile) },
    locomo: { path: LOCOMO_DATASET, sha256: sha256File(LOCOMO_DATASET) },
    canonical_corpus_manifest: { path: corpusManifest, sha256: sha256File(corpusManifest) },
  };
}

async function runInstalledServiceBenchmark(args) {
  const definition = readInstalledUserServiceDefinition(args.installedInstance);
  const serviceManifest = buildUserServiceManifest(definition);
  const { origin, health: healthBefore } = await requireInstalledBenchmarkService(definition);
  const runtimeCliArgs = installedRuntimeArgs(definition);
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const runId = args.resumeRun || `${stamp}_${randomBytes(3).toString('hex')}`;
  const outputDir = path.join(args.outputRoot, runId);
  const resuming = Boolean(args.resumeRun);
  mkdirSync(args.outputRoot, { recursive: true, mode: 0o700 });
  if (resuming) {
    if (!existsSync(outputDir) || statSync(outputDir).isSymbolicLink()) {
      throw new Error('resume_run_directory_missing_or_invalid');
    }
  } else {
    mkdirSync(outputDir, { recursive: false, mode: 0o700 });
  }

  const datasets = installedDatasetBindings(args);
  const configuration = {
    ...canonicalRunConfiguration(args),
    execution_mode: 'installed-service',
    installed_instance: definition.instance,
    service_configuration_sha256: serviceManifest.configuration_sha256,
    database_name: definition.database,
    postgres_port: definition.postgres_port,
    http_port: definition.port,
    agent_id: args.agentId,
    lifecycle_authority: false,
  };
  const observedBefore = await scratchProof(definition.database, runtimeCliArgs);
  let baseline = observedBefore;
  let startedAt;
  if (resuming) {
    const retainedManifest = readRunManifest(outputDir, runId, definition.database, configuration);
    baseline = retainedManifest.baseline;
    startedAt = retainedManifest.started_at;
    if (!baseline || baseline.orphaned_memories !== 0 || baseline.operational_memories !== 0) {
      throw new Error('installed_benchmark_baseline_invalid');
    }
  } else {
    if (observedBefore.orphaned_memories !== 0) throw new Error('installed_benchmark_service_has_orphaned_memories');
    if (observedBefore.operational_memories !== 0) {
      throw new Error('installed_benchmark_service_is_not_fresh_reproduction_state');
    }
    startedAt = new Date().toISOString();
    writeRunManifest(outputDir, {
      run_id: runId,
      database_name: definition.database,
      started_at: startedAt,
      configuration,
      datasets,
      baseline,
      canonical_before: null,
    });
  }

  const environment = await retainBenchmarkEnvironmentEvidence(outputDir, {
    args,
    databaseName: definition.database,
    runtimeArgs: runtimeCliArgs,
    runId: runId.toLowerCase(),
    startedAt,
    executionMode: 'installed-service',
    serviceConfigurationSha256: serviceManifest.configuration_sha256,
  });

  const passes = {};
  const context = {
    runId: runId.toLowerCase(),
    databaseName: definition.database,
    outputDir,
    baseUrl: origin,
    runtimeCliArgs,
    installedService: true,
    agentId: args.agentId,
    onPhase: (phase) => writeRunStatus(outputDir, {
      run_id: runId,
      database_name: definition.database,
      state: 'running',
      phase,
      resumable: true,
      execution_mode: 'installed-service',
    }),
  };
  writeRunStatus(outputDir, {
    run_id: runId,
    database_name: definition.database,
    state: 'running',
    phase: resuming ? 'installed-service-resume' : 'installed-service-preflight',
    resumable: true,
    execution_mode: 'installed-service',
  });

  try {
    if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
      passes.poisonedrag = await runPoisonedRagBenchmark(args, context);
    } else {
      passes.canonical = await runCanonicalBenchmark(args, context);
    }
    const terminal = buildBenchmarkRunTerminalEvidence({
      runId: context.runId,
      protocol: args.protocol,
      requestedBenchmark: args.benchmark,
      passes,
    });
    const afterBenchmark = await scratchProof(definition.database, runtimeCliArgs);
    if (afterBenchmark.orphaned_memories !== 0) {
      throw new Error(`installed database has ${afterBenchmark.orphaned_memories} orphaned memories`);
    }
    if (afterBenchmark.benchmark_memories <= baseline.benchmark_memories) {
      throw new Error('benchmark ingestion produced no run-specific installed memory delta');
    }
    const { health: healthAfter } = await requireInstalledBenchmarkService(definition);
    const proof = {
      schema: 'hom.aimos.installed-benchmark-execution/v1',
      run_id: runId,
      protocol: args.protocol,
      benchmark: args.benchmark,
      execution_mode: 'installed-service',
      installation: {
        instance: definition.instance,
        configuration_sha256: serviceManifest.configuration_sha256,
        source_root: definition.source_root,
        database_name: definition.database,
        postgres_port: definition.postgres_port,
        http_port: definition.port,
        agent_id: args.agentId,
      },
      lifecycle: {
        genesis: false,
        database_create_or_clone: false,
        child_server_spawn: false,
        service_stop_or_restart: false,
        purge: false,
      },
      datasets,
      environment,
      baseline,
      after_benchmark: afterBenchmark,
      health_before: healthBefore,
      health_after: healthAfter,
      passes,
      terminal,
    };
    proof.proof_sha256 = sha256(JSON.stringify(proof));
    writeFileSync(path.join(outputDir, 'installed-service-proof.json'), `${JSON.stringify(proof, null, 2)}\n`, { mode: 0o600 });
    writeFileSync(path.join(outputDir, 'benchmark-summary.json'), `${JSON.stringify({
      run_id: runId,
      mode: 'installed-service',
      benchmark: args.benchmark,
      protocol: args.protocol,
      passes,
      terminal,
      environment,
    }, null, 2)}\n`, { mode: 0o600 });
    writeFileSync(path.join(outputDir, 'reproduce-command.txt'),
      `npm run reproduce -- --installed-instance ${definition.instance} --agent-id ${args.agentId}${args.full ? ' --full' : ` --sample ${args.sample}`} --benchmark ${args.benchmark} --protocol ${args.protocol} --limit ${args.limit}${args.keychainAccount ? ` --keychain-account ${args.keychainAccount}` : ''}\n`);
    writeFileSync(path.join(outputDir, 'artifact-hashes.json'), `${JSON.stringify(await artifactHashes(outputDir), null, 2)}\n`);
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: definition.database,
      state: 'complete',
      phase: 'complete',
      resumable: false,
      execution_mode: 'installed-service',
      terminal,
    });
    console.log(JSON.stringify({ output_dir: outputDir, installation: proof.installation, passes }, null, 2));
  } catch (error) {
    appendFileSync(path.join(outputDir, 'diagnostics.jsonl'), `${JSON.stringify({
      schema: 'hom.aimos.benchmark-diagnostic/v1',
      observed_at: new Date().toISOString(),
      run_id: runId,
      protocol: args.protocol,
      database_name: definition.database,
      execution_mode: 'installed-service',
      lifecycle_authority: false,
      error_name: String(error?.name || 'Error').slice(0, 128),
      error_message: String(error?.message || error || 'unknown_error').slice(0, 2000),
    })}\n`, { mode: 0o600 });
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: definition.database,
      state: 'failed',
      phase: 'failed',
      resumable: true,
      execution_mode: 'installed-service',
      error: { name: String(error?.name || 'Error'), message: String(error?.message || error) },
      resume_command: `npm run reproduce -- --installed-instance ${definition.instance} --agent-id ${args.agentId} --resume-run ${runId} --benchmark ${args.benchmark} --protocol ${args.protocol} --limit ${args.limit}`,
    });
    throw error;
  }
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.installedInstance) return runInstalledServiceBenchmark(args);
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const runId = args.resumeRun || `${stamp}_${randomBytes(3).toString('hex')}`;
  const databaseName = `aimos_benchmark_${runId.toLowerCase()}`;
  const outputDir = path.join(args.outputRoot, runId);
  const baseUrl = `http://127.0.0.1:${args.port}`;
  const resuming = Boolean(args.resumeRun);
  await assertLoopbackPortAvailable(args.port);
  if (resuming) {
    if (!existsSync(outputDir) || statSync(outputDir).isSymbolicLink()) throw new Error('resume_run_directory_missing_or_invalid');
  } else {
    mkdirSync(outputDir, { recursive: false, mode: 0o700 });
  }

  const installerLog = path.join(outputDir, 'installer.log');
  const serverLog = path.join(outputDir, 'server.log');
  const purgeReceiptPath = path.join(outputDir, 'purge-receipt.json');
  const housekeeperKeyBefore = protectedKeyState(HOUSEKEEPER_KEY);
  const sharedFileSnapshots = new Map([
    [HOUSEKEEPER_CERT_CACHE, captureFile(HOUSEKEEPER_CERT_CACHE)],
    [ARCHITECTURE_AUTHORITY, captureFile(ARCHITECTURE_AUTHORITY)],
  ]);
  let server = null;
  let scratchCreated = false;
  let scratchPurged = false;
  let sharedFilesRestored = false;
  let interrupted = false;

  const restoreSharedFiles = () => {
    if (sharedFilesRestored) return;
    for (const [file, snapshot] of sharedFileSnapshots) restoreFile(file, snapshot);
    assertProtectedKeyUnchanged(HOUSEKEEPER_KEY, housekeeperKeyBefore);
    sharedFilesRestored = true;
  };
  const cleanup = async () => {
    await stopChild(server);
    restoreSharedFiles();
    if (scratchCreated && !scratchPurged && !args.keepScratchDb) {
      writeFileSync(path.join(outputDir, 'scratch-recovery.json'), `${JSON.stringify({
        database_name: databaseName,
        retained: true,
        reason: 'run_incomplete_or_purge_unverified',
        required_cleanup: `node scripts/ceremony/purge-brain.mjs --live --aimos-db ${databaseName}`,
      }, null, 2)}\n`, { mode: 0o600 });
    }
  };
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      interrupted = true;
      cleanup().finally(() => process.exit(130));
    });
  }

  const currentCanonicalFootprint = await canonicalFootprint();
  if (currentCanonicalFootprint.benchmark_rows !== 0) {
    throw new Error('canonical AIMOS already contains benchmark memories; run the authorized cleanup ceremony before benchmarking');
  }
  const datasets = args.protocol === POISONEDRAG_PROTOCOL_ID
    ? {
        poisonedrag_source_lock: {
          file: path.relative(ROOT, POISONEDRAG_SOURCE_LOCK),
          sha256: sha256File(POISONEDRAG_SOURCE_LOCK),
        },
        poisonedrag_public_target_lock: {
          file: path.relative(ROOT, POISONEDRAG_PUBLIC_LOCK),
          sha256: sha256File(POISONEDRAG_PUBLIC_LOCK),
        },
        poisonedrag_private_target_manifest: {
          file: 'n100-private-target-manifest.json',
          sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-private-target-manifest.json')),
          redistributed: false,
        },
        poisonedrag_corpus_resolution: {
          file: 'n100-corpus-resolution.json',
          sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-corpus-resolution.json')),
          redistributed: false,
        },
        poisonedrag_candidate_pool: {
          file: 'n100-candidate-pool.jsonl',
          sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-candidate-pool.jsonl')),
          redistributed: false,
        },
      }
    : [TWIN_PRIME_G1P_PROTOCOL, TWIN_PRIME_G5_PROTOCOL].includes(args.protocol)
      ? {
          twin_prime_g1p_corpus_manifest: {
            path: path.join(TWIN_PRIME_G1P_CORPUS, 'corpus-manifest.json'),
            sha256: sha256File(path.join(TWIN_PRIME_G1P_CORPUS, 'corpus-manifest.json')),
          },
          longmemeval_s_sessions: {
            path: path.join(TWIN_PRIME_G1P_CORPUS, 'longmemeval-sessions.json'),
            sha256: sha256File(path.join(TWIN_PRIME_G1P_CORPUS, 'longmemeval-sessions.json')),
          },
          longmemeval_s_query_inputs: {
            path: path.join(TWIN_PRIME_G1P_CORPUS, 'longmemeval-query-inputs.json'),
            sha256: sha256File(path.join(TWIN_PRIME_G1P_CORPUS, 'longmemeval-query-inputs.json')),
          },
          locomo_sessions: {
            path: path.join(TWIN_PRIME_G1P_CORPUS, 'locomo-sessions.json'),
            sha256: sha256File(path.join(TWIN_PRIME_G1P_CORPUS, 'locomo-sessions.json')),
          },
          locomo_query_inputs: {
            path: path.join(TWIN_PRIME_G1P_CORPUS, 'locomo-query-inputs.json'),
            sha256: sha256File(path.join(TWIN_PRIME_G1P_CORPUS, 'locomo-query-inputs.json')),
          },
          ...(args.protocol === TWIN_PRIME_G5_PROTOCOL ? {
            twin_prime_g5_pilot_contract: {
              path: path.join(TWIN_PRIME_G5_CONTRACT, 'pilot-contract.json'),
              sha256: sha256File(path.join(TWIN_PRIME_G5_CONTRACT, 'pilot-contract.json')),
            },
            twin_prime_g5_artifact_manifest: {
              path: path.join(TWIN_PRIME_G5_CONTRACT, 'artifact-manifest.json'),
              sha256: sha256File(path.join(TWIN_PRIME_G5_CONTRACT, 'artifact-manifest.json')),
            },
          } : {}),
        }
      : {
        longmemeval: { path: args.longmemevalFile, sha256: sha256File(args.longmemevalFile) },
        locomo: { path: LOCOMO_DATASET, sha256: sha256File(LOCOMO_DATASET) },
        canonical_corpus_manifest: {
          path: path.join(ROOT, 'eval', 'data', 'canonical', 'corpus-manifest.json'),
          sha256: sha256File(path.join(ROOT, 'eval', 'data', 'canonical', 'corpus-manifest.json')),
        },
      };
  const configuration = canonicalRunConfiguration(args);
  const resumeManifest = resuming
    ? readRunManifest(outputDir, runId, databaseName, configuration)
    : null;
  const retryRecovery = resuming
    ? writeRetryRecoveryReceipt(outputDir, runId, resumeManifest)
    : null;
  const canonicalBefore = resumeManifest?.canonical_before || currentCanonicalFootprint;
  if (JSON.stringify(canonicalBefore) !== JSON.stringify(currentCanonicalFootprint)) {
    throw new Error('canonical AIMOS footprint changed since the resumable run began');
  }
  const startedAt = resumeManifest?.started_at || new Date().toISOString();
  const passes = {};
  let health = null;
  let environment = null;
  let baseline = resumeManifest?.baseline || null;
  let resumable = false;
  const resumeScopeArgs = args.full
    ? '--full'
    : args.gate
      ? `--gate ${args.gate}`
      : args.smoke
        ? '--smoke'
        : `--sample ${args.sample}`;

  try {
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: resuming ? 'resuming' : 'initializing',
      phase: resuming ? 'scratch-server-start' : 'genesis-install',
      resumable: resuming,
    });
    if (resuming) {
      if (!await databaseExists(databaseName)) throw new Error('resume_scratch_database_missing');
      scratchCreated = true;
      resumable = Boolean(args.keepScratchDb
        && existsSync(path.join(outputDir, 'run-manifest.json')));
    } else {
      scratchCreated = true;
      await spawnLogged(process.execPath, [
        'scripts/genesis-install.mjs', '--aimos-db', databaseName, '--aimos-port', String(args.port)
      ], installerLog);
      baseline = await scratchProof(databaseName);
      writeRunManifest(outputDir, {
        run_id: runId,
        database_name: databaseName,
        started_at: startedAt,
        configuration,
        datasets,
        baseline,
        canonical_before: canonicalBefore,
      });
      resumable = Boolean(args.keepScratchDb
        && existsSync(path.join(outputDir, 'run-manifest.json')));
    }
    server = spawnLogged(process.execPath, [
      'server.js', '--aimos-db', databaseName, '--aimos-port', String(args.port)
    ], serverLog, { finite: false });
    health = await waitForHealth(baseUrl, server, databaseName);
    environment = await retainBenchmarkEnvironmentEvidence(outputDir, {
      args,
      databaseName,
      runId: runId.toLowerCase(),
      startedAt,
      executionMode: 'isolated-native',
    });
    resumable = Boolean(args.keepScratchDb
      && scratchCreated
      && !scratchPurged
      && existsSync(path.join(outputDir, 'run-manifest.json')));
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: 'running',
      phase: 'benchmark',
      resumable,
    });

    if (args.lifecycleProof) {
      const appendProof = path.join(outputDir, 'session-lifecycle-append.json');
      const finalizeProof = path.join(outputDir, 'session-lifecycle-finalize-recall.json');
      await spawnLogged(process.execPath, [
        'scripts/benchmark/prove-session-lifecycle.mjs',
        '--phase', 'append',
        '--run-id', runId.toLowerCase(),
        '--proof-file', appendProof,
        '--aimos-db', databaseName,
        '--aimos-port', String(args.port),
      ], path.join(outputDir, 'session-lifecycle-append.log'));

      await stopChild(server);
      server = spawnLogged(process.execPath, [
        'server.js', '--aimos-db', databaseName, '--aimos-port', String(args.port)
      ], serverLog, { finite: false });
      health = await waitForHealth(baseUrl, server, databaseName);

      await spawnLogged(process.execPath, [
        'scripts/benchmark/prove-session-lifecycle.mjs',
        '--phase', 'finalize-recall',
        '--run-id', runId.toLowerCase(),
        '--proof-file', finalizeProof,
        '--aimos-db', databaseName,
        '--aimos-port', String(args.port),
      ], path.join(outputDir, 'session-lifecycle-finalize-recall.log'));
      passes.lifecycle = {
        append: JSON.parse(readFileSync(appendProof, 'utf8')),
        finalize_recall: JSON.parse(readFileSync(finalizeProof, 'utf8')),
      };
    } else if (args.historicalV1) {
      // ---- Pass 1: retrieval floor (deterministic; ingests both corpora once) ----
      const officialDir = path.join(outputDir, 'official');
      mkdirSync(path.join(officialDir, 'ledger'), { recursive: true });
      mkdirSync(path.join(officialDir, 'record'), { recursive: true });
      await spawnLogged(process.execPath, [
        ...baseHarnessArgs(args, databaseName, baseUrl),
        '--mode', 'official',
        '--ingest-missing',
        '--output-dir', officialDir,
        '--ledger-dir', path.join(officialDir, 'ledger'),
        '--record', path.join(officialDir, 'record')
      ], path.join(officialDir, 'benchmark.log'));
      passes.official = readPassSummary(officialDir);

      // ---- Pass 2: cognitive answer (opt-in; LLM generator + LLM judge) ----
      if (args.cognitive) {
        const cognitiveDir = path.join(outputDir, 'cognitive');
        mkdirSync(path.join(cognitiveDir, 'ledger'), { recursive: true });
        await spawnLogged(process.execPath, [
          ...baseHarnessArgs(args, databaseName, baseUrl),
          '--mode', 'judge',
          '--generator-provider', args.generatorProvider,
          '--generator-model', args.generatorModel,
          '--judge-provider', args.judgeProvider,
          '--judge-model', args.judgeModel,
          '--output-dir', cognitiveDir,
          '--ledger-dir', path.join(cognitiveDir, 'ledger')
        ], path.join(cognitiveDir, 'benchmark.log'));
        passes.cognitive = readPassSummary(cognitiveDir);
      }
    } else if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
      passes.poisonedrag = await runPoisonedRagBenchmark(args, {
        runId: runId.toLowerCase(),
        databaseName,
        outputDir,
        baseUrl,
        onPhase: (phase) => writeRunStatus(outputDir, {
          run_id: runId,
          database_name: databaseName,
          state: 'running',
          phase,
          resumable,
        }),
      });
    } else if (args.protocol === TWIN_PRIME_G1P_PROTOCOL) {
      passes.twin_prime_g1p = await runTwinPrimeG1P(args, {
        runId: runId.toLowerCase(),
        databaseName,
        outputDir,
        baseUrl,
        onPhase: (phase) => writeRunStatus(outputDir, {
          run_id: runId,
          database_name: databaseName,
          state: 'running',
          phase,
          resumable,
        }),
      });
    } else if (args.protocol === TWIN_PRIME_G5_PROTOCOL) {
      passes.twin_prime_g5 = await runTwinPrimeG5(args, {
        runId: runId.toLowerCase(),
        databaseName,
        outputDir,
        baseUrl,
        serverPid: server.pid,
        onPhase: (phase) => writeRunStatus(outputDir, {
          run_id: runId,
          database_name: databaseName,
          state: 'running',
          phase,
          resumable,
        }),
      });
    } else {
      passes.canonical = await runCanonicalBenchmark(args, {
        runId: runId.toLowerCase(),
        databaseName,
        outputDir,
        baseUrl,
        onPhase: (phase) => writeRunStatus(outputDir, {
          run_id: runId,
          database_name: databaseName,
          state: 'running',
          phase,
          resumable,
        }),
      });
    }

    const terminal = args.lifecycleProof
      || args.historicalV1
      || [TWIN_PRIME_G1P_PROTOCOL, TWIN_PRIME_G5_PROTOCOL].includes(args.protocol)
      ? null
      : buildBenchmarkRunTerminalEvidence({
          runId: runId.toLowerCase(),
          protocol: args.protocol,
          requestedBenchmark: args.benchmark,
          passes,
        });

    await stopChild(server);
    server = null;

    const scratchAfter = await scratchProof(databaseName);
    if (scratchAfter.orphaned_memories !== 0) throw new Error(`scratch database has ${scratchAfter.orphaned_memories} orphaned memories`);
    if (scratchAfter.benchmark_memories < 1) throw new Error('benchmark ingestion produced no scratch memories');

    writeFileSync(path.join(outputDir, 'pre-purge-evidence.json'), `${JSON.stringify({
      run_id: runId,
      database_name: databaseName,
      baseline,
      after_benchmark: scratchAfter,
      datasets,
      environment,
      passes,
    }, null, 2)}\n`);
    const prePurgeHashes = await artifactHashes(outputDir);
    const prePurgeVerification = await verifyArtifactHashSet(outputDir, prePurgeHashes);
    writeFileSync(
      path.join(outputDir, 'pre-purge-artifact-hashes.json'),
      `${JSON.stringify({ hashes: prePurgeHashes, verification: prePurgeVerification }, null, 2)}\n`,
    );

    restoreSharedFiles();
    const purge = args.keepScratchDb
      ? null
      : await runSignedScratchPurge(databaseName, purgeReceiptPath);
    if (purge) {
      scratchPurged = true;
      scratchCreated = false;
    }
    const canonicalAfter = await canonicalFootprint();
    const canonicalUntouched = JSON.stringify(canonicalBefore) === JSON.stringify(canonicalAfter);
    if (!canonicalUntouched) throw new Error('canonical AIMOS benchmark footprint changed');

    const isolationProof = {
      run_id: runId,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      mode: args.lifecycleProof
        ? 'lifecycle-proof'
        : args.historicalV1
          ? 'historical-v1'
          : args.protocol === POISONEDRAG_PROTOCOL_ID
            ? 'poisonedrag-n100'
            : args.protocol === TWIN_PRIME_G1P_PROTOCOL
              ? 'twin-prime-g1p'
              : args.protocol === TWIN_PRIME_G5_PROTOCOL
                ? 'twin-prime-g5'
                : 'canonical-single-query',
      protocol: args.protocol,
      benchmark: args.benchmark,
      scope: args.lifecycleProof
        ? 'lifecycle-proof'
        : args.protocol === TWIN_PRIME_G1P_PROTOCOL
          ? `label-blind:${args.sample}-per-dataset`
          : args.protocol === TWIN_PRIME_G5_PROTOCOL
            ? 'gate10:10-questions:four-arms'
            : args.full ? 'full' : (args.gate || (args.smoke ? `smoke:${args.sample}` : `sample:${args.sample}`)),
      recall_depth_k: args.limit,
      cognitive: args.lifecycleProof
        ? false
        : args.historicalV1
          ? (args.cognitive
              ? { generator: `${args.generatorProvider}:${args.generatorModel}`, judge: `${args.judgeProvider}:${args.judgeModel}` }
              : false)
          : args.protocol === LOCOMO_OFFICIAL_PROTOCOL
            ? { reader: 'codex:gpt-5.4', deterministic_scorer: LOCOMO_OFFICIAL_PROTOCOL }
            : args.protocol === POISONEDRAG_PROTOCOL_ID
              ? { generator: `codex:${POISONEDRAG_GENERATOR_MODEL}`, judge: 'codex:gpt-5.6-terra', judge_reasoning: 'high' }
              : args.protocol === TWIN_PRIME_G1P_PROTOCOL
                ? false
                : args.protocol === TWIN_PRIME_G5_PROTOCOL
                  ? { generator: 'codex:gpt-5.5', generator_reasoning: 'medium', judge: 'codex:gpt-5.6-terra', judge_reasoning: 'high' }
                  : { generator: 'codex:gpt-5.4', judge: 'codex:gpt-5.6-terra', judge_reasoning: 'high' },
      datasets,
      environment,
      scratch: {
        database_name: databaseName,
        port: args.port,
        retained: Boolean(args.keepScratchDb && !purge),
        baseline,
        after_benchmark: scratchAfter,
        pre_purge_artifacts: prePurgeVerification,
        whole_scratch_brain_purged: Boolean(purge),
        purge,
      },
      canonical: { before: canonicalBefore, after: canonicalAfter, untouched: canonicalUntouched },
      retry_recovery: retryRecovery,
      health
    };
    if (terminal) isolationProof.terminal = terminal;
    writeFileSync(path.join(outputDir, 'isolation-proof.json'), `${JSON.stringify(isolationProof, null, 2)}\n`);
    writeFileSync(path.join(outputDir, 'benchmark-summary.json'), `${JSON.stringify({ run_id: runId, mode: isolationProof.mode, benchmark: args.benchmark, scope: isolationProof.scope, recall_depth_k: args.limit, environment, passes, ...(terminal ? { terminal } : {}) }, null, 2)}\n`);
    writeFileSync(path.join(outputDir, 'reproduce-command.txt'),
      `node scripts/benchmark/run-isolated.mjs${args.lifecycleProof ? ' --lifecycle-proof' : args.full ? ' --full' : args.gate ? ` --gate ${args.gate}` : ` --sample ${args.sample}`}${args.historicalV1 ? ' --historical-v1' : ''}${args.cognitive ? ' --cognitive' : ''} --benchmark ${args.benchmark} --protocol ${args.protocol} --port ${args.port} --limit ${args.limit}${args.keychainAccount ? ` --keychain-account ${args.keychainAccount}` : ''}${args.keepScratchDb ? ' --keep-scratch-db' : ''}\n`);
    writeFileSync(path.join(outputDir, 'artifact-hashes.json'), `${JSON.stringify(await artifactHashes(outputDir), null, 2)}\n`);
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: 'complete',
      phase: 'complete',
      resumable: false,
      ...(terminal ? { terminal } : {}),
    });
    console.log(JSON.stringify({ output_dir: outputDir, isolation: isolationProof, passes }, null, 2));
  } catch (error) {
    let observedPhase = 'unknown';
    try {
      observedPhase = JSON.parse(readFileSync(path.join(outputDir, 'run-status.json'), 'utf8')).phase
        || observedPhase;
    } catch { /* status may not exist when failure precedes run creation */ }
    appendFileSync(path.join(outputDir, 'diagnostics.jsonl'), `${JSON.stringify({
      schema: 'hom.aimos.benchmark-diagnostic/v1',
      observed_at: new Date().toISOString(),
      run_id: runId,
      phase: observedPhase,
      protocol: args.protocol,
      database_name: databaseName,
      loopback_port: args.port,
      server_pid: server?.pid || null,
      server_exit_code: server?.exitCode ?? null,
      health_database_name: health?.runtime?.database_name || null,
      health_ready: health?.ready === true,
      error_name: String(error?.name || 'Error').slice(0, 128),
      error_message: String(error?.message || error || 'unknown_error').slice(0, 2000),
      stack: String(error?.stack || '').split('\n').slice(0, 12),
      sensitive_payloads_retained_elsewhere: false,
    })}\n`, { mode: 0o600 });
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: 'failed',
      phase: 'failed',
      resumable,
      error: {
        name: String(error?.name || 'Error').slice(0, 128),
        message: String(error?.message || error || 'unknown_error').slice(0, 2000),
      },
      resume_command: resumable
        ? `node scripts/benchmark/run-isolated.mjs --resume-run ${runId} ${resumeScopeArgs} --benchmark ${args.benchmark} --protocol ${args.protocol} --port ${args.port} --limit ${args.limit}${args.keychainAccount ? ` --keychain-account ${args.keychainAccount}` : ''} --keep-scratch-db`
        : null,
    });
    throw error;
  } finally {
    if (!interrupted) await cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
