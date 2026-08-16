#!/usr/bin/env node
// Read-only S4B proof over retained benchmark recall artifacts.
//
// The script exports only the minimum public verification surface and writes a
// hash/count receipt. It does not connect to AIMOS, invoke a model, sign, or
// modify any retained run artifact.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { recallCorpusRoot } from '../../services/security/protocol/mutmem-protocol.js';
import {
  verifyRecallBundle,
  verifyRecallCorpus,
} from '../../verifiers/mutmem-node/recall-verifier.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RUN_ID = process.argv[2] || '20260715111742_96b25f';
const INTENDED_N = Number(process.argv[3] || 20);
const RUN = path.join(ROOT, 'eval/public-results', RUN_ID);
const OUTPUT = path.join(ROOT, 'artifacts/security/mutmem-v2/s4');
const PYTHON = path.join(ROOT, 'verifiers/mutmem-python/verify.py');
const SOURCE_FILES = {
  protocol_owner: path.join(ROOT, 'services/security/protocol/mutmem-protocol.js'),
  node_recall_verifier: path.join(ROOT, 'verifiers/mutmem-node/recall-verifier.mjs'),
  python_recall_verifier: path.join(ROOT, 'verifiers/mutmem-python/recall_verifier.py'),
  python_cli: PYTHON,
  proof_runner: fileURLToPath(import.meta.url),
};

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function json(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}

function decodeCert(certificate) {
  const envelope = JSON.parse(Buffer.from(certificate, 'base64url').toString('utf8'));
  return envelope.body;
}

function anchor(certificate) {
  const body = decodeCert(certificate);
  return {
    certificate_sha256: sha(Buffer.from(certificate, 'utf8')),
    public_key_b64u: body.pubkey,
  };
}

async function selectedAttempts() {
  const glob = execFileSync('find', [
    path.join(RUN, 'questions'), '-type', 'f', '-name', 'recall-receipt.json',
  ], { encoding: 'utf8' }).trim().split('\n').filter(Boolean).sort();
  if (!Number.isSafeInteger(INTENDED_N) || INTENDED_N < 1 || glob.length < INTENDED_N) {
    throw new Error(`retained_recall_intended_n_unavailable:${glob.length}:${INTENDED_N}`);
  }
  return glob.slice(0, INTENDED_N);
}

async function bundleFromReceipt(receiptPath) {
  const directory = path.dirname(receiptPath);
  const requestPath = path.join(directory, 'recall-request.json');
  const responsePath = path.join(directory, 'recall-response.json');
  const [request, response, receipt, requestRaw, responseRaw, receiptRaw] = await Promise.all([
    json(requestPath), json(responsePath), json(receiptPath),
    readFile(requestPath), readFile(responsePath), readFile(receiptPath),
  ]);
  const requestCert = request.headers?.['Aimos-Agent-Cert'];
  const eventCert = receipt.event_receipt?.signer_certificate;
  if (!requestCert || !eventCert) throw new Error('retained_recall_certificate_missing');
  const anchors = new Map([requestCert, eventCert].map((cert) => {
    const entry = anchor(cert);
    return [entry.certificate_sha256, entry];
  }));
  const relative = path.relative(path.join(RUN, 'questions'), receiptPath);
  const bundleId = relative.split(path.sep)[0];
  const memories = (response.memories || []).map((memory) => ({
    id: String(memory.id || memory.memory_id),
    source: memory.source,
    memory_type: memory.memory_type,
    provenance_proof: {
      live_content_hash: memory.provenance_proof?.live_content_hash,
      save_mutation_hash: memory.provenance_proof?.save_mutation_hash,
      binding_mutation_hash: memory.provenance_proof?.binding_mutation_hash,
    },
  }));
  return {
    bundle: {
      format: {
        schema: 'hom.aimos.mutmem-recall-evidence/v1',
        version: 1,
        authority: 'descriptive_only',
        canonicalization: 'hom-aimos/canonical-json/v1',
        hash: 'sha256',
        signature: 'ed25519',
      },
      bundle_id: bundleId,
      company_id: String(request.body?.company_id || ''),
      trust_anchors: { master: null, certificates: [...anchors.values()] },
      request: {
        body: request.body,
        method: 'POST',
        path: '/aimos/recall',
        nonce: request.headers?.['Aimos-Agent-Nonce'],
        ts_signed: Number(request.headers?.['Aimos-Agent-Timestamp']),
        signature: request.headers?.['Aimos-Agent-Signature'],
        certificate: requestCert,
      },
      memories,
      recall_receipt: receipt,
    },
    sources: {
      request_sha256: sha(requestRaw),
      response_sha256: sha(responseRaw),
      receipt_sha256: sha(receiptRaw),
    },
  };
}

async function main() {
  const files = await selectedAttempts();
  const exported = await Promise.all(files.map(bundleFromReceipt));
  const members = exported.map(({ bundle }, ordinal) => ({
    ordinal,
    bundle_id: bundle.bundle_id,
    bundle_sha256: sha(Buffer.from(canonicalJson(bundle), 'utf8')),
    bundle,
  }));
  const summaries = members.map(({ ordinal, bundle_id, bundle_sha256 }) => ({
    ordinal, bundle_id, bundle_sha256,
  }));
  const corpus = {
    format: {
      schema: 'hom.aimos.mutmem-recall-corpus/v1',
      version: 1,
      authority: 'descriptive_only',
    },
    intended_n: INTENDED_N,
    members,
    corpus_root: recallCorpusRoot({ intendedN: INTENDED_N, members: summaries }).toString('hex'),
  };
  const node = verifyRecallCorpus(corpus);
  const python = JSON.parse(execFileSync('python3', [PYTHON, 'verify-corpus', '-'], {
    input: JSON.stringify(corpus), encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
  }));
  const bundleParity = members.every((member, ordinal) => {
    const nodeBundle = verifyRecallBundle(member.bundle);
    const pythonMember = python.members?.[ordinal];
    return nodeBundle.verdict === 'valid'
      && pythonMember?.verdict === 'valid'
      && pythonMember.bundle_id === member.bundle_id;
  });
  if (node.verdict !== 'valid' || python.verdict !== 'valid'
      || node.corpus_root !== python.corpus_root || !bundleParity) {
    throw new Error(`retained_recall_parity_failed:${node.primary_reason || python.primary_reason || 'unknown'}`);
  }
  const receipt = {
    schema: 'hom.aimos.mutmem-v2-s4-retained-recall-proof/v1',
    mode: 'READ_ONLY_RETAINED_ARTIFACTS',
    run_id: RUN_ID,
    intended_n: INTENDED_N,
    observed_n: members.length,
    corpus_root: node.corpus_root,
    node_verdict: node.verdict,
    python_verdict: python.verdict,
    exact_terminal_parity: true,
    selection_rule: 'lexicographically_first_n_recall_receipts',
    verifier_sources: Object.fromEntries(await Promise.all(
      Object.entries(SOURCE_FILES).map(async ([name, file]) => [name, sha(await readFile(file))]),
    )),
    source_artifacts: exported.map((entry, ordinal) => ({
      ordinal,
      bundle_id: members[ordinal].bundle_id,
      bundle_sha256: members[ordinal].bundle_sha256,
      ...entry.sources,
    })),
  };
  const output = path.join(OUTPUT, `mutmem-v2-s4-retained-recall-${RUN_ID}-n${INTENDED_N}.json`);
  await mkdir(OUTPUT, { recursive: true });
  const bytes = `${JSON.stringify(receipt, null, 2)}\n`;
  await writeFile(output, bytes, { mode: 0o644 });
  await writeFile(`${output}.sha256`, `${sha(Buffer.from(bytes))}  ${path.basename(output)}\n`, { mode: 0o644 });
  console.log(JSON.stringify({ success: true, receipt: output, receipt_sha256: sha(Buffer.from(bytes)), ...receipt }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error.message}`);
  process.exitCode = 1;
});
