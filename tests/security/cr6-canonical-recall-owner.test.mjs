import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const ROOT = new URL('../../', import.meta.url);
const read = (path) => readFile(new URL(path, ROOT), 'utf8');

test('CR6 production recall surfaces have one canonical owner and no split authority transaction', async () => {
  const [pipeline, native, rest, mcp, v1, tools] = await Promise.all([
    read('services/retrieval/native-recall-pipeline.js'),
    read('services/retrieval/native-recall.js'),
    read('routes/aimos.js'),
    read('routes/aimos-mcp-streamable.js'),
    read('routes/v1-api.js'),
    read('services/orchestration/tool-registry.js'),
  ]);
  const production = [rest, mcp, v1, tools];
  assert.equal(production.reduce((count, source) =>
    count + (source.match(/executeCanonicalRecall\(\{/g) || []).length, 0), 5);
  for (const source of production) {
    assert.doesNotMatch(source, /resolveNativeRecallAuthority/);
    assert.doesNotMatch(source, /executeNativeRecall\(/);
  }
  assert.match(pipeline, /export async function executeCanonicalRecall\(\{/);
  assert.match(pipeline, /const session = await openNativeRecallRequestSession\(\{/);
  assert.match(pipeline, /executeNativeRecall\(req, session\.authority, \{ verifiedAdmissionSession: session \}\)/);
  assert.match(native, /export async function openNativeRecallRequestSession\(\{/);
  const owner = native.slice(native.indexOf('export async function openNativeRecallRequestSession'));
  assert.equal((owner.match(/BEGIN ISOLATION LEVEL REPEATABLE READ/g) || []).length, 1);
  assert.match(owner, /resolveNativeRecallAuthorityInClient\(\{/);
});

test('CR6 all candidate reads share the admission snapshot and every production lane admits before merge', async () => {
  const [pipeline, salience, mvs] = await Promise.all([
    read('services/retrieval/native-recall-pipeline.js'),
    read('services/temporal/dormancy-manager.js'),
    read('services/context/mvs-detector.js'),
  ]);
  const runtime = pipeline.slice(pipeline.indexOf('export async function executeCanonicalRecall'));
  assert.equal((runtime.match(/contentStateOccurrenceAdmission\.admit\(/g) || []).length, 13);
  assert.equal((runtime.match(/verifiedAdmissionSession\.read\(/g) || []).length, 1);
  assert.equal((runtime.match(/verifiedAdmissionSession\.optionalRead\(/g) || []).length, 8);
  assert.doesNotMatch(runtime, /\bawait query\(/);
  assert.match(runtime, /getMemoryCount\(company, \{[\s\S]*queryFn: verifiedAdmissionSession\.read,[\s\S]*useCache: false,[\s\S]*failClosed: true/);
  assert.match(runtime, /getAnisotropyStats\(company, \{[\s\S]*queryFn: verifiedAdmissionSession\.optionalRead,[\s\S]*useCache: false/);
  assert.match(runtime, /quimLookup\([\s\S]*queryFn: verifiedAdmissionSession\.optionalRead/);
  assert.match(runtime, /conceptPprLookup\([\s\S]*queryFn: verifiedAdmissionSession\.optionalRead/);
  assert.match(runtime, /evaluateSalienceFrequencyBatch\(memIds, company, \{[\s\S]*queryFn: verifiedAdmissionSession\.optionalRead,[\s\S]*nowMs: twinPrimeSignedRequestTimeMs/);
  assert.match(runtime, /checkContextSufficiency\(sessionKey, \{[\s\S]*queryFn: verifiedAdmissionSession\.optionalRead/);
  assert.match(salience, /const queryFn = typeof options\.queryFn === 'function' \? options\.queryFn : query/);
  assert.match(salience, /const nowMs = Number\.isFinite\(Number\(options\.nowMs\)\)/);
  assert.match(mvs, /const queryFn = typeof options\.queryFn === 'function' \? options\.queryFn : query/);

  const orderedPairs = [
    ['const baseAdmission =', 'memories.push(memory)'],
    ['const entityAdmission =', 'const entityMemoryById = new Map'],
    ['const bm25Admission =', 'memories.push(memory)'],
    ['const identityAdmission =', 'identityRescueCandidateKeys'],
    ['const valueRescueAdmission =', 'memories.push(memory)'],
    ['const siblingAdmission =', 'memories.push(memory)'],
    ['const qmdAdmission =', 'const rescueMemoryById = new Map'],
  ];
  for (const [admission, influence] of orderedPairs) {
    const admissionIndex = runtime.indexOf(admission);
    const influenceIndex = runtime.indexOf(influence, admissionIndex);
    assert.ok(admissionIndex >= 0, `${admission} must exist`);
    assert.ok(influenceIndex > admissionIndex, `${influence} must follow ${admission}`);
  }
});

test('CR6 online recall is read-only outside separately signed evidence receipts', async () => {
  const [pipeline, stats, pheromones, persistence] = await Promise.all([
    read('services/retrieval/native-recall-pipeline.js'),
    read('services/retrieval/similarity-stats.js'),
    read('services/temporal/retrieval-pheromone.js'),
    read('services/write/persist-memory.js'),
  ]);
  const runtime = pipeline.slice(pipeline.indexOf('export async function executeCanonicalRecall'));
  assert.doesNotMatch(runtime, /recordSimilarityStats\(/);
  assert.doesNotMatch(runtime, /reinforceRetrievedPheromones\(/);
  assert.match(runtime, /readOnlyRecallPheromoneDecision\(disclosureMemories\)/);
  assert.match(runtime, /verifiedAdmissionSession\.close\(\{ commit: false \}\)/);
  assert.ok((runtime.match(/rethrowRecallBoundaryFailure\(/g) || []).length >= 8);
  assert.match(stats, /async function getStats\(companyId, \{ queryFn = query, useCache = true \} = \{\}\)/);
  assert.match(pheromones, /export async function reinforceRetrievedPheromones/,
    'mutation owner remains available only to a future separately signed action path');
  assert.doesNotMatch(persistence, /codebook-service|getTurboQuantCapabilities|CodebookService\.quantize/);
  assert.doesNotMatch(persistence, /quant_idx, residual_vector/);
});
