import { createHash } from 'node:crypto';
import {
  createReadStream,
  existsSync,
  lstatSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

export const POISONEDRAG_SCHEMAS = Object.freeze({
  SOURCE_LOCK: 'hom.aimos.poisonedrag-source-lock/v1',
  PRIVATE_TARGET_MANIFEST: 'hom.aimos.poisonedrag-private-target-manifest/v1',
  PUBLIC_TARGET_LOCK: 'hom.aimos.poisonedrag-public-target-lock/v1',
  DOWNLOAD_RECEIPT: 'hom.aimos.poisonedrag-download-receipt/v1',
  CORPUS_RESOLUTION: 'hom.aimos.poisonedrag-corpus-resolution/v1',
  ISOLATION_PROOF: 'hom.aimos.poisonedrag-isolation-proof/v1',
  INPUT_PREFLIGHT: 'hom.aimos.poisonedrag-input-preflight/v1',
  DUPLICATE_PREFLIGHT: 'hom.aimos.poisonedrag-duplicate-preflight/v1',
  EXECUTION_PLAN: 'hom.aimos.poisonedrag-execution-plan/v1',
  SAVE_PROOF: 'hom.aimos.poisonedrag-save-proof/v1',
  RECALL_PROOF: 'hom.aimos.poisonedrag-recall-proof/v1',
  ANSWER: 'hom.aimos.poisonedrag-answer/v1',
  JUDGMENT: 'hom.aimos.poisonedrag-judgment/v1',
  TARGET_OUTCOME: 'hom.aimos.poisonedrag-target-outcome/v1',
  SUMMARY: 'hom.aimos.poisonedrag-summary/v1',
});

const HEX_64 = /^[0-9a-f]{64}$/;

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical_json_non_finite_number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!value || typeof value !== 'object') throw new Error('canonical_json_type_unsupported');
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(',')}}`;
}

export function manifestDigest(value) {
  const unsigned = { ...value };
  delete unsigned.manifest_sha256;
  return sha256(Buffer.from(canonicalJson(unsigned), 'utf8'));
}

export async function hashFile(file, algorithms = ['sha256']) {
  const hashes = new Map(algorithms.map((algorithm) => [algorithm, createHash(algorithm)]));
  let bytes = 0;
  for await (const chunk of createReadStream(file)) {
    bytes += chunk.length;
    for (const hash of hashes.values()) hash.update(chunk);
  }
  return {
    bytes,
    ...Object.fromEntries([...hashes].map(([algorithm, hash]) => [algorithm, hash.digest('hex')])),
  };
}

export function readJsonFile(file, expectedSchema = null) {
  const absolute = path.resolve(file);
  if (!existsSync(absolute)) throw new Error(`required_file_missing:${absolute}`);
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`regular_file_required:${absolute}`);
  const value = JSON.parse(readFileSync(absolute, 'utf8'));
  if (expectedSchema && value?.schema !== expectedSchema) {
    throw new Error(`schema_mismatch:${expectedSchema}`);
  }
  return value;
}

export function writeImmutableJson(file, value, mode = 0o600) {
  const absolute = path.resolve(file);
  const encoded = `${JSON.stringify(value, null, 2)}\n`;
  if (existsSync(absolute)) {
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`regular_file_required:${absolute}`);
    if (readFileSync(absolute, 'utf8') !== encoded) throw new Error(`immutable_artifact_conflict:${absolute}`);
    return { file: absolute, reused: true };
  }
  writeFileSync(absolute, encoded, { flag: 'wx', mode });
  return { file: absolute, reused: false };
}

export function loadSourceLock(file) {
  const lock = readJsonFile(file, POISONEDRAG_SCHEMAS.SOURCE_LOCK);
  const { artifacts, protocol, upstream } = lock;
  if (!/^[0-9a-f]{40}$/.test(String(upstream?.commit || ''))) throw new Error('source_lock_commit_invalid');
  if (protocol?.dataset !== 'nq'
    || protocol?.target_count !== 100
    || protocol?.clean_candidates_per_target !== 100
    || protocol?.poison_passages_per_target !== 5
    || protocol?.disclosure_k !== 5) {
    throw new Error('source_lock_protocol_invalid');
  }
  for (const name of ['license', 'target_fixture', 'contriever_top100']) {
    const artifact = artifacts?.[name];
    if (!artifact?.url || !artifact?.file || !Number.isSafeInteger(artifact?.bytes)
      || artifact.bytes < 1 || !HEX_64.test(String(artifact?.sha256 || ''))) {
      throw new Error(`source_lock_artifact_invalid:${name}`);
    }
  }
  const archive = artifacts?.nq_archive;
  if (!archive?.url || archive?.file !== 'nq.zip' || archive?.corpus_entry !== 'nq/corpus.jsonl'
    || !Number.isSafeInteger(archive?.bytes) || archive.bytes < 1
    || !/^[0-9a-f]{32}$/.test(String(archive?.md5 || ''))) {
    throw new Error('source_lock_nq_archive_invalid');
  }
  return { lock, source_lock_sha256: sha256(Buffer.from(canonicalJson(lock), 'utf8')) };
}

function requireExactObjectKeys(value, keys, errorCode) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(errorCode);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(errorCode);
}

function requireText(value, errorCode) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(errorCode);
  return value;
}

export function officialPoisonedRagNormalize(value) {
  let normalized = String(value).trim();
  if (normalized.length > 1 && normalized.endsWith('.')) normalized = normalized.slice(0, -1);
  return normalized.toLowerCase();
}

export function poisonPassage(question, adversarialText) {
  return `${requireText(question, 'poison_question_invalid')}.${requireText(adversarialText, 'poison_adversarial_text_invalid')}`;
}

export function opaqueScopeId(sourceLockSha256, upstreamId, armOrdinal) {
  if (!HEX_64.test(String(sourceLockSha256 || ''))) throw new Error('scope_source_lock_hash_invalid');
  if (![0, 1].includes(armOrdinal)) throw new Error('scope_arm_ordinal_invalid');
  const digest = sha256(Buffer.from(
    `hom.aimos.poisonedrag-scope/v1\0${sourceLockSha256}\0${upstreamId}\0${armOrdinal}`,
    'utf8',
  ));
  return `prg_${digest.slice(0, 40)}`;
}

export function validateTargetFixture(value, expectedCount = 100) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('target_fixture_invalid');
  const entries = Object.entries(value);
  if (entries.length !== expectedCount) throw new Error(`target_fixture_count_mismatch:${entries.length}`);
  const seenIds = new Set();
  return entries.map(([fixtureKey, target], ordinal) => {
    requireExactObjectKeys(
      target,
      ['id', 'question', 'correct answer', 'incorrect answer', 'adv_texts'],
      `target_fixture_shape_invalid:${fixtureKey}`,
    );
    if (target.id !== fixtureKey || seenIds.has(target.id)) throw new Error(`target_fixture_id_invalid:${fixtureKey}`);
    seenIds.add(target.id);
    const advTexts = target.adv_texts;
    if (!Array.isArray(advTexts) || advTexts.length !== 5) throw new Error(`target_fixture_adv_count_invalid:${fixtureKey}`);
    return {
      ordinal,
      fixture_key: fixtureKey,
      upstream_id: requireText(target.id, `target_fixture_id_invalid:${fixtureKey}`),
      question: requireText(target.question, `target_fixture_question_invalid:${fixtureKey}`),
      correct_answer: requireText(target['correct answer'], `target_fixture_correct_answer_invalid:${fixtureKey}`),
      target_answer: requireText(target['incorrect answer'], `target_fixture_target_answer_invalid:${fixtureKey}`),
      adversarial_texts: advTexts.map((text) => requireText(text, `target_fixture_adv_text_invalid:${fixtureKey}`)),
    };
  });
}

export function validateContrieverRankings(value, targets, expectedPerTarget = 100) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('contriever_rankings_invalid');
  return new Map(targets.map((target) => {
    const ranking = value[target.upstream_id];
    if (!ranking || typeof ranking !== 'object' || Array.isArray(ranking)) {
      throw new Error(`contriever_target_missing:${target.upstream_id}`);
    }
    const entries = Object.entries(ranking);
    if (entries.length !== expectedPerTarget) {
      throw new Error(`contriever_candidate_count_mismatch:${target.upstream_id}:${entries.length}`);
    }
    const seen = new Set();
    let prior = Number.POSITIVE_INFINITY;
    const candidates = entries.map(([documentId, rawScore], index) => {
      const score = Number(rawScore);
      if (!documentId || seen.has(documentId) || !Number.isFinite(score) || score > prior) {
        throw new Error(`contriever_ranking_invalid:${target.upstream_id}:${index}`);
      }
      seen.add(documentId);
      prior = score;
      return { rank: index + 1, document_id: documentId, upstream_score: score };
    });
    return [target.upstream_id, candidates];
  }));
}

export function buildTargetManifests({ sourceLock, sourceLockSha256, fixture, rankings }) {
  const targets = validateTargetFixture(fixture, sourceLock.protocol.target_count);
  const ranked = validateContrieverRankings(
    rankings,
    targets,
    sourceLock.protocol.clean_candidates_per_target,
  );
  const privateTargets = targets.map((target) => {
    const poisonTexts = target.adversarial_texts.map((text) => poisonPassage(target.question, text));
    const candidates = ranked.get(target.upstream_id);
    return {
      ...target,
      question_sha256: sha256(Buffer.from(target.question, 'utf8')),
      correct_answer_sha256: sha256(Buffer.from(target.correct_answer, 'utf8')),
      target_answer_sha256: sha256(Buffer.from(target.target_answer, 'utf8')),
      adversarial_text_sha256: target.adversarial_texts.map((text) => sha256(Buffer.from(text, 'utf8'))),
      poison_texts: poisonTexts,
      poison_text_sha256: poisonTexts.map((text) => sha256(Buffer.from(text, 'utf8'))),
      candidate_documents: candidates,
      candidate_document_ids_sha256: sha256(Buffer.from(canonicalJson(candidates.map((entry) => entry.document_id)), 'utf8')),
      scope_ids: [
        opaqueScopeId(sourceLockSha256, target.upstream_id, 0),
        opaqueScopeId(sourceLockSha256, target.upstream_id, 1),
      ],
      recall_order: target.ordinal % 2 === 0 ? [0, 1] : [1, 0],
    };
  });
  const privateManifest = {
    schema: POISONEDRAG_SCHEMAS.PRIVATE_TARGET_MANIFEST,
    source_lock_sha256: sourceLockSha256,
    upstream_repo_commit: sourceLock.upstream.commit,
    upstream_fixture_sha256: sourceLock.artifacts.target_fixture.sha256,
    upstream_rankings_sha256: sourceLock.artifacts.contriever_top100.sha256,
    dataset: 'nq',
    target_count: privateTargets.length,
    clean_candidates_per_target: sourceLock.protocol.clean_candidates_per_target,
    poison_passages_per_target: sourceLock.protocol.poison_passages_per_target,
    disclosure_k: sourceLock.protocol.disclosure_k,
    scope_derivation: 'hom.aimos.poisonedrag-scope/v1; SHA-256; 40 lowercase hex characters after prg_',
    targets: privateTargets,
  };
  privateManifest.manifest_sha256 = manifestDigest(privateManifest);

  const publicManifest = {
    schema: POISONEDRAG_SCHEMAS.PUBLIC_TARGET_LOCK,
    source_lock_sha256: sourceLockSha256,
    upstream_repo_commit: sourceLock.upstream.commit,
    upstream_fixture_sha256: sourceLock.artifacts.target_fixture.sha256,
    upstream_rankings_sha256: sourceLock.artifacts.contriever_top100.sha256,
    dataset: 'nq',
    target_count: privateTargets.length,
    clean_candidates_per_target: sourceLock.protocol.clean_candidates_per_target,
    poison_passages_per_target: sourceLock.protocol.poison_passages_per_target,
    disclosure_k: sourceLock.protocol.disclosure_k,
    redistributed_source_text: false,
    targets: privateTargets.map((target) => ({
      ordinal: target.ordinal,
      upstream_id: target.upstream_id,
      question_sha256: target.question_sha256,
      correct_answer_sha256: target.correct_answer_sha256,
      target_answer_sha256: target.target_answer_sha256,
      adversarial_text_sha256: target.adversarial_text_sha256,
      poison_text_sha256: target.poison_text_sha256,
      candidate_document_ids_sha256: target.candidate_document_ids_sha256,
      scope_ids: target.scope_ids,
      recall_order: target.recall_order,
    })),
  };
  publicManifest.manifest_sha256 = manifestDigest(publicManifest);
  return { privateManifest, publicManifest };
}

export async function verifyPinnedFile(file, expectation, algorithms = ['sha256']) {
  if (!existsSync(file)) return { status: 'missing', file: path.resolve(file) };
  const stat = lstatSync(file);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`regular_file_required:${path.resolve(file)}`);
  const observed = await hashFile(file, algorithms);
  if (Number(expectation.bytes) !== observed.bytes) throw new Error(`pinned_file_size_mismatch:${path.basename(file)}`);
  for (const algorithm of algorithms) {
    if (expectation[algorithm] && expectation[algorithm] !== observed[algorithm]) {
      throw new Error(`pinned_file_${algorithm}_mismatch:${path.basename(file)}`);
    }
  }
  return { status: 'verified', file: path.resolve(file), ...observed };
}

export function assertManifest(manifest, schema) {
  if (manifest?.schema !== schema || manifest?.manifest_sha256 !== manifestDigest(manifest)) {
    throw new Error(`manifest_verification_failed:${schema}`);
  }
  return manifest;
}

export function requirePrivateDirectory(directory) {
  const stat = statSync(directory);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0) {
    throw new Error(`private_directory_permissions_invalid:${path.resolve(directory)}`);
  }
}
