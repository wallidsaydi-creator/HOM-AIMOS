#!/usr/bin/env node

/**
 * Deterministically separates public benchmark conversations from gold answers.
 *
 * The replay process consumes only `*-sessions.json`; it never opens the source
 * datasets or `*-questions.json`. This is a structural answer-key boundary, not
 * a convention inside the replay loop.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DATA_DIR = path.join(ROOT, 'data');
const DEFAULT_OUTPUT_DIR = path.join(DEFAULT_DATA_DIR, 'canonical');
const FORBIDDEN_SESSION_KEYS = new Set([
  'answer',
  'answer_session_ids',
  'has_answer',
  'question',
  'question_id',
  'question_type',
]);
const LOCOMO_CATEGORIES = Object.freeze({
  1: 'single-hop',
  2: 'temporal',
  3: 'open-domain',
  4: 'multi-hop',
  5: 'adversarial',
});
const MONTHS = Object.freeze({
  january: 0,
  february: 1,
  march: 2,
  april: 3,
  may: 4,
  june: 5,
  july: 6,
  august: 7,
  september: 8,
  october: 9,
  november: 10,
  december: 11,
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function observedAt(baseIso, ordinal) {
  const timestamp = new Date(baseIso).getTime();
  if (!Number.isFinite(timestamp)) throw new Error(`invalid_session_date:${baseIso}`);
  return new Date(timestamp + ordinal * 1000).toISOString();
}

export function parseLocomoDate(value) {
  const match = String(value || '').trim().match(
    /^(\d{1,2}):(\d{2})\s*(am|pm)\s+on\s+(\d{1,2})\s+([a-z]+),\s+(\d{4})$/i,
  );
  if (!match) throw new Error(`locomo_date_invalid:${value}`);
  let hour = Number(match[1]);
  const minute = Number(match[2]);
  const meridiem = match[3].toLowerCase();
  const day = Number(match[4]);
  const month = MONTHS[match[5].toLowerCase()];
  const year = Number(match[6]);
  if (month == null || hour < 1 || hour > 12 || minute < 0 || minute > 59) {
    throw new Error(`locomo_date_invalid:${value}`);
  }
  if (hour === 12) hour = 0;
  if (meridiem === 'pm') hour += 12;
  return new Date(Date.UTC(year, month, day, hour, minute, 0, 0)).toISOString();
}

export function parseLongMemEvalDate(value) {
  const match = String(value || '').trim().match(
    /^(\d{4})\/(\d{2})\/(\d{2})\s+\([A-Za-z]{3}\)\s+(\d{2}):(\d{2})$/,
  );
  if (!match) throw new Error(`longmemeval_date_invalid:${value}`);
  const [, year, month, day, hour, minute] = match;
  const iso = new Date(Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
  )).toISOString();
  if (!iso.startsWith(`${year}-${month}-${day}T${hour}:${minute}:`)) {
    throw new Error(`longmemeval_date_invalid:${value}`);
  }
  return iso;
}

function canonicalSessionId(dataset, scopeId, sourceSessionId) {
  const readable = `bench:${dataset}:${scopeId}:${sourceSessionId}`;
  if (Buffer.byteLength(readable, 'utf8') <= 160 && !/[\u0000-\u001f\u007f]/u.test(readable)) {
    return readable;
  }
  return `bench:${dataset}:${sha256(scopeId).slice(0, 20)}:${sha256(sourceSessionId).slice(0, 20)}`;
}

function locomoImageContext(turn) {
  const urls = Array.isArray(turn.img_url)
    ? turn.img_url.filter((value) => String(value || '').trim())
    : (turn.img_url ? [turn.img_url] : []);
  const caption = String(turn.blip_caption || '').trim();
  const query = String(turn.query || '').trim();
  if (!urls.length && !caption && !query) return [];
  const targets = urls.length ? urls : [null];
  return targets.map((url) => ({
    ...(url ? { url: String(url).trim() } : {}),
    ...(caption ? { caption } : {}),
    ...(query ? { query } : {}),
  }));
}

function assertNoForbiddenKeys(value, location = '$') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoForbiddenKeys(entry, `${location}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_SESSION_KEYS.has(key)) throw new Error(`answer_key_leak:${location}.${key}`);
    assertNoForbiddenKeys(entry, `${location}.${key}`);
  }
}

export function buildLocomoArtifacts(sourceRows, sourceSha256) {
  if (!Array.isArray(sourceRows) || sourceRows.length !== 10) throw new Error('locomo_source_shape_invalid');
  const scopes = [];
  const questions = [];
  let sessionCount = 0;
  let turnCount = 0;

  for (const sample of sourceRows) {
    const sampleId = String(sample.sample_id || '').trim();
    if (!sampleId) throw new Error('locomo_sample_id_missing');
    const conversation = sample.conversation;
    const speakerA = String(conversation?.speaker_a || '').trim();
    const speakerB = String(conversation?.speaker_b || '').trim();
    if (!speakerA || !speakerB || speakerA === speakerB) throw new Error(`locomo_speakers_invalid:${sampleId}`);
    const scopeId = `locomo:${sampleId}`;
    const sourceFilter = `benchmark:locomo:${sampleId}`;
    const sessions = Object.entries(conversation)
      .filter(([key, value]) => /^session_\d+$/.test(key) && Array.isArray(value))
      .sort(([left], [right]) => Number(left.slice(8)) - Number(right.slice(8)))
      .map(([sourceSessionId, sourceTurns]) => {
        const rawDate = conversation[`${sourceSessionId}_date_time`];
        const baseIso = parseLocomoDate(rawDate);
        const sessionId = canonicalSessionId('locomo', sampleId, sourceSessionId);
        const turns = sourceTurns.map((turn, index) => {
          const speaker = String(turn.speaker || '').trim();
          if (speaker !== speakerA && speaker !== speakerB) {
            throw new Error(`locomo_turn_speaker_invalid:${sampleId}:${sourceSessionId}:${index + 1}`);
          }
          const content = String(turn.text ?? '');
          if (!content.trim()) throw new Error(`locomo_turn_content_missing:${sampleId}:${sourceSessionId}:${index + 1}`);
          const sourceRef = String(turn.dia_id || `${sourceSessionId}:${index + 1}`);
          const imageContext = locomoImageContext(turn);
          return {
            turn_id: `${sampleId}:${sourceSessionId}:${sourceRef}`,
            role: speaker === speakerA ? 'user' : 'assistant',
            speaker,
            content,
            observed_at: observedAt(baseIso, index),
            source_ref: `${sampleId}:${sourceRef}`,
            ...(imageContext.length ? { image_context: imageContext } : {}),
          };
        });
        sessionCount += 1;
        turnCount += turns.length;
        return {
          session_id: sessionId,
          source_session_id: sourceSessionId,
          source_date: String(rawDate),
          turns,
        };
      });
    scopes.push({ scope_id: scopeId, source_filter: sourceFilter, sessions });

    if (!Array.isArray(sample.qa)) throw new Error(`locomo_questions_invalid:${sampleId}`);
    sample.qa.forEach((question, index) => {
      questions.push({
        question_id: `locomo:${sampleId}:q:${String(index + 1).padStart(4, '0')}`,
        benchmark: 'locomo',
        scope_id: scopeId,
        source_filter: sourceFilter,
        question: String(question.question || ''),
        answer: String(question.answer || ''),
        category: LOCOMO_CATEGORIES[Number(question.category)] || `category-${question.category}`,
        expected_evidence: Array.isArray(question.evidence) ? question.evidence.map(String) : [],
      });
    });
  }

  const sessionsArtifact = {
    schema: 'hom.canonical-benchmark-sessions/v1',
    benchmark: 'locomo',
    source_dataset_sha256: sourceSha256,
    scope_count: scopes.length,
    session_count: sessionCount,
    turn_count: turnCount,
    scopes,
  };
  assertNoForbiddenKeys(sessionsArtifact);
  return {
    sessions: sessionsArtifact,
    questions: {
      schema: 'hom.canonical-benchmark-questions/v1',
      benchmark: 'locomo',
      source_dataset_sha256: sourceSha256,
      question_count: questions.length,
      questions,
    },
  };
}

export function buildLongMemEvalArtifacts(sourceRows, sourceSha256) {
  if (!Array.isArray(sourceRows) || sourceRows.length !== 500) throw new Error('longmemeval_source_shape_invalid');
  const scopes = [];
  const questions = [];
  let sessionCount = 0;
  let turnCount = 0;

  for (const sample of sourceRows) {
    const questionId = String(sample.question_id || '').trim();
    if (!questionId) throw new Error('longmemeval_question_id_missing');
    if (sample.haystack_sessions.length !== sample.haystack_session_ids.length
      || sample.haystack_sessions.length !== sample.haystack_dates.length) {
      throw new Error(`longmemeval_session_alignment_invalid:${questionId}`);
    }
    const scopeId = `longmemeval:${questionId}`;
    const sourceFilter = `benchmark:longmemeval:${questionId}`;
    const sessions = sample.haystack_sessions.map((sourceTurns, sessionIndex) => {
      const sourceSessionId = String(sample.haystack_session_ids[sessionIndex] || '').trim();
      const rawDate = String(sample.haystack_dates[sessionIndex] || '').trim();
      const baseIso = parseLongMemEvalDate(rawDate);
      const sessionId = canonicalSessionId('lme', questionId, sourceSessionId);
      const turns = sourceTurns.map((turn, turnIndex) => {
        const role = String(turn.role || '').trim().toLowerCase();
        if (!['user', 'assistant'].includes(role)) {
          throw new Error(`longmemeval_turn_role_invalid:${questionId}:${sourceSessionId}:${turnIndex + 1}`);
        }
        const content = String(turn.content ?? '');
        if (!content.trim()) {
          throw new Error(`longmemeval_turn_content_missing:${questionId}:${sourceSessionId}:${turnIndex + 1}`);
        }
        return {
          turn_id: `${questionId}:${sourceSessionId}:${turnIndex + 1}`,
          role,
          content,
          observed_at: observedAt(baseIso, turnIndex),
          source_ref: `${questionId}:${sourceSessionId}:${turnIndex + 1}`,
        };
      });
      sessionCount += 1;
      turnCount += turns.length;
      return {
        session_id: sessionId,
        source_session_id: sourceSessionId,
        source_date: rawDate,
        turns,
      };
    });
    scopes.push({ scope_id: scopeId, source_filter: sourceFilter, sessions });
    questions.push({
      question_id: questionId,
      benchmark: 'longmemeval',
      scope_id: scopeId,
      source_filter: sourceFilter,
      question: String(sample.question || ''),
      answer: String(sample.answer || ''),
      category: String(sample.question_type || 'unknown'),
      question_date: String(sample.question_date || ''),
      answer_session_ids: Array.isArray(sample.answer_session_ids)
        ? sample.answer_session_ids.map(String)
        : [],
    });
  }

  const sessionsArtifact = {
    schema: 'hom.canonical-benchmark-sessions/v1',
    benchmark: 'longmemeval',
    source_dataset_sha256: sourceSha256,
    scope_count: scopes.length,
    session_count: sessionCount,
    turn_count: turnCount,
    scopes,
  };
  assertNoForbiddenKeys(sessionsArtifact);
  return {
    sessions: sessionsArtifact,
    questions: {
      schema: 'hom.canonical-benchmark-questions/v1',
      benchmark: 'longmemeval',
      source_dataset_sha256: sourceSha256,
      question_count: questions.length,
      questions,
    },
  };
}

function parseArgs(argv) {
  const args = {
    locomo: path.join(DEFAULT_DATA_DIR, 'official-locomo10.json'),
    longmemeval: path.join(DEFAULT_DATA_DIR, 'official-longmemeval-oracle.json'),
    outputDir: DEFAULT_OUTPUT_DIR,
  };
  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index + 1];
    if (argv[index] === '--locomo' && value) { args.locomo = path.resolve(value); index += 1; }
    else if (argv[index] === '--longmemeval' && value) { args.longmemeval = path.resolve(value); index += 1; }
    else if (argv[index] === '--output-dir' && value) { args.outputDir = path.resolve(value); index += 1; }
    else throw new Error(`unknown_argument:${argv[index]}`);
  }
  return args;
}

function writeImmutable(file, text) {
  if (fs.existsSync(file)) {
    if (fs.lstatSync(file).isSymbolicLink()) throw new Error(`refusing_output_symlink:${file}`);
    if (fs.readFileSync(file, 'utf8') !== text) throw new Error(`canonical_artifact_conflict:${file}`);
    return false;
  }
  fs.writeFileSync(file, text, { flag: 'wx', mode: 0o644 });
  return true;
}

function writeArtifact(outputDir, name, value) {
  const text = canonicalText(value);
  const digest = sha256(text);
  const file = path.join(outputDir, name);
  writeImmutable(file, text);
  writeImmutable(`${file}.sha256`, `${digest}  ${name}\n`);
  return { file: name, sha256: digest, bytes: Buffer.byteLength(text) };
}

export function prepareCanonicalCorpus({ locomoFile, longMemEvalFile, outputDir }) {
  for (const file of [locomoFile, longMemEvalFile]) {
    if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink()) {
      throw new Error(`source_dataset_invalid:${file}`);
    }
  }
  if (fs.existsSync(outputDir) && fs.lstatSync(outputDir).isSymbolicLink()) {
    throw new Error(`refusing_output_symlink:${outputDir}`);
  }
  fs.mkdirSync(outputDir, { recursive: true, mode: 0o755 });

  const locomoBytes = fs.readFileSync(locomoFile);
  const longMemEvalBytes = fs.readFileSync(longMemEvalFile);
  const locomoSha = sha256(locomoBytes);
  const longMemEvalSha = sha256(longMemEvalBytes);
  const locomo = buildLocomoArtifacts(JSON.parse(locomoBytes), locomoSha);
  const longmemeval = buildLongMemEvalArtifacts(JSON.parse(longMemEvalBytes), longMemEvalSha);
  const outputs = [
    writeArtifact(outputDir, 'locomo-sessions.json', locomo.sessions),
    writeArtifact(outputDir, 'locomo-questions.json', locomo.questions),
    writeArtifact(outputDir, 'longmemeval-sessions.json', longmemeval.sessions),
    writeArtifact(outputDir, 'longmemeval-questions.json', longmemeval.questions),
  ];
  const manifest = {
    schema: 'hom.canonical-benchmark-corpus-manifest/v1',
    inputs: {
      locomo: { file: path.basename(locomoFile), sha256: locomoSha },
      longmemeval: { file: path.basename(longMemEvalFile), sha256: longMemEvalSha },
    },
    outputs,
    answer_key_boundary: {
      replay_inputs: outputs.filter((entry) => entry.file.endsWith('-sessions.json')).map((entry) => entry.file),
      scorer_inputs: outputs.filter((entry) => entry.file.endsWith('-questions.json')).map((entry) => entry.file),
      forbidden_session_keys: [...FORBIDDEN_SESSION_KEYS].sort(),
      verified: true,
    },
  };
  const manifestArtifact = writeArtifact(outputDir, 'corpus-manifest.json', manifest);
  return { ...manifest, manifest: manifestArtifact };
}

async function main() {
  const args = parseArgs(process.argv);
  const result = prepareCanonicalCorpus({
    locomoFile: args.locomo,
    longMemEvalFile: args.longmemeval,
    outputDir: args.outputDir,
  });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
