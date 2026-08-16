#!/usr/bin/env node

// Disposable-database production custody proof for the V2-S5 corpus. This
// test does not create the fixture contents and does not touch the canonical
// brain. It verifies the completed public corpus, binds its exact manifest and
// intended-N to the disposable Genesis identity, and appends one signed
// housekeeper event inside that disposable brain. Purge is a later master-only
// ceremony and is intentionally outside this runner.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { agentPool, pool, query } from '../../db/connection.js';
import {
  AIMOS_COMPANY_ID,
  resolveAimosDatabaseName,
} from '../../services/core/runtime-config.js';
import { logEvent, verifyEventProof } from '../../services/observe/event-ledger.js';
import { getHousekeeperCert } from '../../services/security/housekeeper-signer.js';

const databaseName = resolveAimosDatabaseName();
if (!process.argv.includes('--live-fire')
    || !/^aimos_test_security_mutmem_v2_s5_[a-z0-9_]+$/.test(databaseName)) {
  console.log('MutMem V2-S5 production corpus DB proof skipped (requires --live-fire and disposable aimos_test_security_mutmem_v2_s5_* database)');
  process.exit(0);
}

function argument(name) {
  const inline = process.argv.find((entry) => entry.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

try {
  const manifestPath = path.resolve(argument('--manifest') || '');
  const evidenceFile = path.resolve(argument('--evidence-file') || '');
  assert(manifestPath && evidenceFile, 'mutmem_v2_s5_manifest_and_evidence_required');
  const manifestRaw = await readFile(manifestPath, 'utf8');
  const manifest = JSON.parse(manifestRaw);
  assert.equal(manifest.schema, 'hom.aimos.mutmem-v2-s5-conformance-corpus/v1');
  assert.equal(manifest.required_class_count, 28);
  assert.equal(manifest.intended_n, manifest.observed_n);
  assert.equal(manifest.intended_n, manifest.members.length);
  assert.equal(manifest.synthetic_purpose_bound_identities, true);
  assert.equal(manifest.private_keys_retained, false);
  assert.equal(manifest.live_aimos_memory_content_included, false);

  const genesis = await query(
    `SELECT
       (SELECT count(*)::int FROM aimos_memories WHERE company_id=$1) AS memory_count,
       (SELECT count(*)::int
          FROM aimos_memory_provenance p
          JOIN aimos_memories m ON m.id = p.memory_id
         WHERE m.company_id=$1) AS provenance_count,
       (SELECT count(*)::int FROM aimos_master_identity) AS master_count,
       (SELECT count(*)::int FROM agent_identity WHERE agent_id='housekeeper') AS housekeeper_identity_count`,
    [AIMOS_COMPANY_ID],
  );
  const genesisInventory = genesis.rows[0];
  assert(Number(genesisInventory.memory_count) > 0);
  assert(Number(genesisInventory.provenance_count) > 0);
  // Part-A Genesis intentionally precedes operator enrollment. Requiring or
  // cloning a master row here would broaden this custody proof into a second
  // trust-root ceremony. The scratch housekeeper's self-signed system epoch
  // is the correct signer for this disposable source-custody event.
  assert.equal(Number(genesisInventory.master_count), 0);
  assert(Number(genesisInventory.housekeeper_identity_count) > 0);

  const receipt = await logEvent(
    AIMOS_COMPANY_ID,
    'housekeeper',
    'mutmem_v2_s5_conformance_corpus_bound',
    manifest.corpus_root,
    {
      schema: 'hom.aimos.mutmem-v2-s5-source-custody/v1',
      manifest_sha256: sha256(Buffer.from(manifestRaw, 'utf8')),
      corpus_root: manifest.corpus_root,
      intended_n: manifest.intended_n,
      observed_n: manifest.observed_n,
      required_class_count: manifest.required_class_count,
      synthetic_purpose_bound_identities: true,
      private_keys_retained: false,
      live_aimos_memory_content_included: false,
      disposable_database_sha256: sha256(Buffer.from(databaseName, 'utf8')),
      canonical_memory_mutation: false,
      automatic_policy_activation: false,
      reasoning: 'Bind the exact public conformance corpus to one disposable Genesis lifecycle without granting the corpus signing, save, recall, mutation, classification, deletion, Canary, or SABER authority.',
      source_knowledge: 'MutMem V2 conformance catalog; S5 production corpus contract',
    },
    null,
    { returnReceipt: true, exclusiveOperationKey: true },
  );
  const cert = await getHousekeeperCert();
  const certBody = JSON.parse(Buffer.from(cert, 'base64url').toString('utf8')).body;
  const row = {
    id: receipt.event_id,
    ts: new Date(receipt.ts_signed * 1000),
    company_id: receipt.signed_body.company_id,
    agent_id: receipt.signed_body.subject_agent_id,
    operation: receipt.signed_body.operation,
    key: receipt.signed_body.key,
    metadata: receipt.signed_body.metadata,
    parent_event_id: receipt.signed_body.parent_event_id,
    ledger_version: receipt.ledger_version,
    ledger_seq: receipt.ledger_seq,
    signer_agent_id: receipt.signer_agent_id,
    signer_valid_from: receipt.signer_valid_from,
    cert_fingerprint: receipt.cert_fingerprint,
    identity_tier: receipt.identity_tier,
    authority_kind: receipt.signed_body.authority_kind,
    signed_body: receipt.signed_body,
    content_hash: Buffer.from(receipt.content_hash, 'hex'),
    mutation_hash: Buffer.from(receipt.mutation_hash, 'hex'),
    prev_mutation_hash: Buffer.from(receipt.prev_mutation_hash, 'hex'),
    ts_signed: receipt.ts_signed,
    nonce: receipt.nonce,
    sig: Buffer.from(receipt.signature, 'base64url'),
    proof_required: true,
  };
  const proof = verifyEventProof(row, certBody.pubkey);
  assert.deepEqual(proof, { valid: true, reason: null });

  const evidence = {
    schema: 'hom.aimos.mutmem-v2-s5-source-custody/v1',
    authority: 'production_source_custody_only',
    database_name_sha256: sha256(Buffer.from(databaseName, 'utf8')),
    manifest_sha256: sha256(Buffer.from(manifestRaw, 'utf8')),
    corpus_root: manifest.corpus_root,
    intended_n: manifest.intended_n,
    observed_n: manifest.observed_n,
    required_class_count: manifest.required_class_count,
    genesis_inventory: genesisInventory,
    housekeeper_identity: {
      agent_id: certBody.agent_id,
      valid_from: new Date(Number(certBody.valid_from) * 1000).toISOString(),
      valid_until: new Date(Number(certBody.valid_until) * 1000).toISOString(),
      certificate_sha256: sha256(Buffer.from(cert, 'utf8')),
      public_key_sha256: sha256(Buffer.from(certBody.pubkey, 'base64url')),
      private_key_included: false,
    },
    master_identity_present: false,
    signed_event_receipt: receipt,
    native_event_proof: proof,
    canonical_memory_mutation: false,
    automatic_policy_activation: false,
    purge_required: true,
  };
  evidence.evidence_root_sha256 = sha256(Buffer.from(JSON.stringify(evidence), 'utf8'));
  await writeFile(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({
    success: true,
    evidence_file: evidenceFile,
    evidence_root_sha256: evidence.evidence_root_sha256,
    corpus_root: manifest.corpus_root,
    intended_n: manifest.intended_n,
    observed_n: manifest.observed_n,
    purge_required: true,
  }, null, 2));
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
