#!/usr/bin/env node

// Authority-free finalizer for an S5 disposable-Genesis run after the explicit
// master-signed purge ceremony. It verifies the receipt signature, exact target,
// and destroyed completion state before changing the run status to complete.

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  hashRetainedPurgeArtifact,
  verifyWholeBrainPurgeIntent,
  verifyWholeBrainPurgeReceipt,
} from '../../services/security/whole-brain-purge.js';

function argument(name) {
  const prefix = `--${name}=`;
  const value = process.argv.find((entry) => entry.startsWith(prefix));
  return value ? value.slice(prefix.length) : null;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function main() {
  const runDir = path.resolve(argument('run') || '');
  const receiptFile = path.resolve(argument('receipt') || '');
  if (!runDir || !receiptFile) throw new Error('mutmem_v2_s5_run_and_receipt_required');
  const resultFile = path.join(runDir, 'production-result.json');
  const statusFile = path.join(runDir, 'run-status.json');
  const result = JSON.parse(await readFile(resultFile, 'utf8'));
  const receiptRaw = await readFile(receiptFile, 'utf8');
  const receipt = JSON.parse(receiptRaw);
  const receiptVerification = verifyWholeBrainPurgeReceipt(receipt);
  if (!receiptVerification.valid) {
    throw new Error(`mutmem_v2_s5_purge_receipt_invalid:${receiptVerification.reason}`);
  }
  const intentFile = receiptFile.endsWith('.json')
    ? `${receiptFile.slice(0, -5)}.intent.json`
    : `${receiptFile}.intent.json`;
  const intentRaw = await readFile(intentFile, 'utf8');
  const intent = JSON.parse(intentRaw);
  const intentVerification = verifyWholeBrainPurgeIntent(intent);
  if (!intentVerification.valid || receipt.body.intent_sha256 !== intentVerification.artifact_sha256
      || receipt.body.ceremony_id !== intent.body.ceremony_id) {
    throw new Error('mutmem_v2_s5_purge_intent_binding_invalid');
  }
  const target = receipt.body?.target;
  if (target?.database !== result.database_name || target?.company !== 'hom'
      || receipt.body?.postcondition?.mode !== 'destroyed'
      || receipt.body?.postcondition?.database_present !== false
      || receipt.body?.completion_status !== 'complete') {
    throw new Error('mutmem_v2_s5_purge_receipt_target_invalid');
  }
  const finalized = {
    ...result,
    purge_receipt: {
      path: receiptFile,
      artifact_sha256: hashRetainedPurgeArtifact(receipt),
      file_sha256: sha256(Buffer.from(receiptRaw, 'utf8')),
      ceremony_id: receipt.body.ceremony_id,
      intent_sha256: receipt.body.intent_sha256,
      intent_file_sha256: sha256(Buffer.from(intentRaw, 'utf8')),
      native_receipt_verification: receiptVerification,
      native_intent_verification: intentVerification,
      database_destroyed: true,
    },
    terminal_state: 'COMPLETE',
  };
  const raw = `${JSON.stringify(finalized, null, 2)}\n`;
  await writeFile(resultFile, raw, { flag: 'w', mode: 0o600 });
  await writeFile(statusFile, `${JSON.stringify({
    schema: 'hom.aimos.mutmem-v2-s5-run-status/v1',
    run_id: result.run_id,
    database_name: result.database_name,
    state: 'complete',
    phase: 'complete',
    error: null,
    scratch_retained_for_signed_purge: false,
    purge_receipt_artifact_sha256: finalized.purge_receipt.artifact_sha256,
    purge_receipt_file_sha256: finalized.purge_receipt.file_sha256,
  }, null, 2)}\n`, { flag: 'w', mode: 0o600 });
  process.stdout.write(`${JSON.stringify({
    success: true,
    run_id: result.run_id,
    corpus_root: result.corpus_root,
    intended_n: result.intended_n,
    observed_n: result.observed_n,
    purge_receipt_artifact_sha256: finalized.purge_receipt.artifact_sha256,
    purge_receipt_file_sha256: finalized.purge_receipt.file_sha256,
    terminal_state: 'COMPLETE',
  }, null, 2)}\n`);
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || error}`);
  process.exitCode = 1;
});
