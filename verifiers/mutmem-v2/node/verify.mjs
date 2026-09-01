#!/usr/bin/env node

import { readFile, stat } from 'node:fs/promises';

import { verifyMutationBundle } from './mutation-verifier.mjs';
import { verifyRecallEnvelope } from './recall-verifier.mjs';

function cli(name) {
  const inline = process.argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}
const readJson = async (file) => {
  const metadata = await stat(file);
  if (!metadata.isFile() || metadata.size > 64 * 1024 * 1024) {
    throw new Error('input_size_invalid');
  }
  return JSON.parse(await readFile(file, 'utf8'));
};

async function main() {
  const profile = cli('--profile');
  const inputPath = cli('--input');
  if (!profile || !inputPath) throw new Error('profile_and_input_required');
  const input = await readJson(inputPath);
  const expectedMasterFingerprint = cli('--expected-master-fingerprint');
  const structural = process.argv.includes('--structural-only');
  if (profile === 'recall') {
    const bundle = input.bundle || input;
    console.log(JSON.stringify(verifyRecallEnvelope(bundle, {
      expectedMasterFingerprint,
      verifyCryptography: !structural,
    }), null, 2));
    return;
  }
  if (profile !== 'mutation') throw new Error('profile_invalid');
  const trustInput = cli('--trust-context') ? await readJson(cli('--trust-context')) : null;
  const witnessSet = cli('--witness-set') ? await readJson(cli('--witness-set')) : null;
  const trustContext = trustInput?.bundle || trustInput;
  const entries = Array.isArray(input.projections)
    ? input.projections.map((entry) => entry.bundle) : [input.bundle || input];
  const results = entries.map((bundle) => verifyMutationBundle(bundle, {
    witness: witnessSet?.witnesses?.find(
      (candidate) => candidate.mutation_bundle_sha256 === bundle.bundle_sha256,
    ) || null,
    trustContext,
    expectedMasterFingerprint,
    verifyCryptography: !structural,
  }));
  console.log(JSON.stringify({
    schema: 'hom.aimos.mutmem-independent-mutation-result-set/v2',
    intended_n: results.length,
    results,
  }, null, 2));
}

main().catch((error) => {
  console.error(JSON.stringify({ valid: false, reason: error.reason || error.message }));
  process.exitCode = 1;
});
