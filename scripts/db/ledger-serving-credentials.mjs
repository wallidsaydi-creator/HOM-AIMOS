#!/usr/bin/env node

// After restoring the canonical corpus to its private cluster, append exact
// first STORE roots for the two new database-role credentials. Existing
// runtime credential history is verified, never replaced. This process must
// be invoked with the canonical instance and private PostgreSQL port.

import {
  AIMOS_INSTANCE, AIMOS_POSTGRES_PORT,
  AIMOS_RUNTIME_CREDENTIAL_SERVICE,
  AIMOS_SERVICE_READER_CREDENTIAL_SERVICE,
  AIMOS_IDENTITY_WRITER_CREDENTIAL_SERVICE,
} from '../../services/core/runtime-config.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readCredentialSync } from '../../services/security/credential-store.js';
import { credentialLedger } from '../../services/security/credential-ledger.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { pool, agentPool, identityWriterPool,
  schedulerLockPool } from '../../db/connection.js';

const SERVICES = Object.freeze([
  [AIMOS_SERVICE_READER_CREDENTIAL_SERVICE, 'genesis_service_reader_database_role'],
  [AIMOS_IDENTITY_WRITER_CREDENTIAL_SERVICE, 'genesis_identity_writer_database_role'],
]);

export async function appendServingCredentialRoots({
  runtimeService = AIMOS_RUNTIME_CREDENTIAL_SERVICE,
  services = SERVICES,
  credentialReader = readCredentialSync,
  ledger = credentialLedger,
  signer = signAsHousekeeper,
} = {}) {
  const runtime = credentialReader(runtimeService);
  if (!runtime?.value) throw new Error('runtime_credential_unavailable');
  const runtimeChain = await ledger.getSlotChain(runtime.slot, 1);
  if (runtimeChain.length < 1
      || runtimeChain[0]?.body_json?.credential_hash !== runtime.hash) {
    throw new Error('runtime_credential_lifecycle_mismatch');
  }
  const results = [];
  for (const [service, reason] of services) {
    const credential = credentialReader(service);
    if (!credential?.value) throw new Error(`serving_credential_unavailable:${service}`);
    const existing = await ledger.getSlotChain(credential.slot, 1);
    if (existing.length > 0) {
      if (existing[0]?.body_json?.credential_hash !== credential.hash) {
        throw new Error(`serving_credential_lifecycle_mismatch:${service}`);
      }
      results.push({ service, slot: credential.slot, hash: credential.hash,
        disposition: 'existing_verified' });
      continue;
    }
    const body = {
      event_type: 'STORE', service, slot_id: credential.slot,
      credential_hash: credential.hash,
      valid_from: Math.floor(Date.now() / 1000), valid_until: null,
      rotated_from: null, reason, operator: 'housekeeper',
      signer_agent_id: 'housekeeper', genesis_root: true,
    };
    const signed = await signer(body);
    const commit = await ledger.commitCredentialLifecycle({
      serviceName: service, slotId: credential.slot,
      body: signed.body, agentId: signed.agentId,
      validFromIso: signed.validFromIso, certString: signed.certString,
      signedTs: signed.signedTs, nonce: signed.nonce,
      sigBytes: signed.sigBytes, identityTier: signed.identityTier,
      eventType: 'STORE', bodyJson: signed.body,
    });
    if (!commit.ok) throw new Error(`serving_credential_lifecycle_commit_failed:${commit.reason}`);
    const verified = await ledger.getSlotChain(credential.slot, 1);
    if (verified.length !== 1
        || verified[0]?.body_json?.credential_hash !== credential.hash) {
      throw new Error('serving_credential_lifecycle_readback_failed');
    }
    results.push({ service, slot: credential.slot, hash: credential.hash,
      disposition: 'first_store_signed',
      mutation_hash: Buffer.from(commit.mutationHash).toString('hex') });
  }
  return { result: 'serving_credentials_signed', services: results };
}

async function main() {
  if (AIMOS_INSTANCE !== 'canonical' || AIMOS_POSTGRES_PORT === 5432) {
    throw new Error('serving_credential_ledger_private_target_required');
  }
  return appendServingCredentialRoots();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
main().then((result) => {
  process.stdout.write(`${JSON.stringify(result)}\n`);
}).catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}).finally(async () => {
  await Promise.allSettled([
    pool.end(), agentPool.end(), identityWriterPool.end(), schedulerLockPool.end(),
  ]);
});
}
