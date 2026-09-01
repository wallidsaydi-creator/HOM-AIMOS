#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyCertChain } from '../../services/security/agent-identity.js';
import { verifyEventProof } from '../../services/observe/event-ledger.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

const DEFAULT_RECEIPT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../verifiers/mutmem-conformance/v2/p3-clean-installer-qualification.json',
);
const SHA256 = /^[0-9a-f]{64}$/;
const sha = (value) => createHash('sha256').update(value).digest('hex');

function assert(value, code) {
  if (!value) throw new Error(code);
}

function certificateBody(certificate) {
  try {
    return JSON.parse(Buffer.from(String(certificate), 'base64url').toString('utf8')).body;
  } catch {
    throw new Error('p3_qualification_certificate_malformed');
  }
}

export function verifyP3InstallerQualification(receipt) {
  const historicalCleanupReceipt = receipt?.schema === 'hom.aimos.p3-clean-installer-qualification/v1';
  const retainedCurrentReceipt = receipt?.schema === 'hom.aimos.p3-clean-installer-qualification/v3';
  assert(historicalCleanupReceipt || retainedCurrentReceipt, 'p3_qualification_schema_invalid');
  assert(receipt.qualified === true, 'p3_qualification_not_qualified');
  assert(/^v26\./.test(String(receipt.node_version)), 'p3_qualification_node_invalid');
  assert(receipt.first_ready === true && receipt.restart_ready === true
    && receipt.scheduler_ready === true, 'p3_qualification_readiness_invalid');
  if (historicalCleanupReceipt) {
    assert(receipt.counts?.experimental_memories === 0
      && receipt.counts?.identities === 1
      && receipt.counts?.housekeepers === 1
      && receipt.counts?.masters === 0, 'p3_qualification_genesis_counts_invalid');
  } else {
    assert(receipt.counts?.experimental_memories === 0
      && receipt.counts?.identities === 2
      && receipt.counts?.housekeepers === 1
      && receipt.counts?.masters === 1
      && receipt.counts?.selected_grant_clearance === 10
      && receipt.counts?.selected_grant_data_class === 'confidential',
    'p3_qualification_onboarding_counts_invalid');
  }
  assert(receipt.canonical_invariants_unchanged === true
    && receipt.canonical_event_prefix_preserved === true
    && receipt.canonical_unchanged === true, 'p3_qualification_canonical_preservation_invalid');
  if (historicalCleanupReceipt) {
    assert(receipt.disposable_cleanup_complete === true
      && receipt.disposable_cleanup?.clean === true
      && Object.entries(receipt.disposable_cleanup).every(([key, value]) => key === 'clean' || value === true),
    'p3_qualification_cleanup_invalid');
  } else {
    assert(receipt.canonical_runtime_not_manipulated === true
      && receipt.canonical_health_before?.ready === true
      && receipt.canonical_health_after?.ready === true,
    'p3_qualification_canonical_continuity_invalid');
    assert(receipt.retained_installation_ready === true
      && receipt.retained_installation?.ready === true
      && Object.entries(receipt.retained_installation)
        .every(([key, value]) => key === 'ready' || value === true),
    'p3_qualification_retained_installation_invalid');
    assert(receipt.failed_attempt_cleanup == null, 'p3_qualification_success_cleanup_forbidden');
  }

  const expectedQualification = String(receipt.qualification_sha256 || '');
  assert(SHA256.test(expectedQualification), 'p3_qualification_hash_invalid');
  const unsignedQualification = { ...receipt };
  delete unsignedQualification.qualification_sha256;
  assert(sha(Buffer.from(canonicalJson(unsignedQualification))) === expectedQualification,
    'p3_qualification_hash_mismatch');

  const terminal = receipt.signed_terminal;
  assert(terminal?.schema === 'hom.aimos.p3-installer-qualification-terminal-receipt/v1'
    && terminal.independently_verified === true
    && terminal.portable_proof_complete === true, 'p3_terminal_receipt_incomplete');
  const expectedTerminal = String(terminal.receipt_sha256 || '');
  assert(SHA256.test(expectedTerminal), 'p3_terminal_receipt_hash_invalid');
  const unsignedTerminal = { ...terminal };
  delete unsignedTerminal.receipt_sha256;
  assert(sha(Buffer.from(canonicalJson(unsignedTerminal))) === expectedTerminal,
    'p3_terminal_receipt_hash_mismatch');

  const certBody = certificateBody(terminal.signer_certificate);
  assert(certBody.agent_id === terminal.signer_agent_id
    && certBody.pubkey
    && sha(Buffer.from(terminal.signer_certificate, 'utf8')) === terminal.cert_fingerprint,
  'p3_terminal_certificate_binding_invalid');
  const certProof = verifyCertChain(terminal.signer_certificate, certBody.pubkey, {
    nowFn: () => Number(terminal.ts_signed),
  });
  assert(certProof.valid === true, `p3_terminal_certificate_invalid:${certProof.reason}`);

  const body = terminal.signed_body;
  const row = {
    id: terminal.event_id,
    ts: new Date(Number(terminal.ts_signed) * 1000),
    company_id: body.company_id,
    agent_id: body.subject_agent_id,
    operation: body.operation,
    key: body.key,
    metadata: body.metadata,
    parent_event_id: body.parent_event_id,
    proof_required: terminal.proof_required,
    ledger_version: terminal.ledger_version,
    ledger_seq: terminal.ledger_seq,
    signer_agent_id: terminal.signer_agent_id,
    signer_valid_from: terminal.signer_valid_from,
    cert_fingerprint: terminal.cert_fingerprint,
    identity_tier: terminal.identity_tier,
    authority_kind: body.authority_kind,
    signed_body: body,
    content_hash: Buffer.from(terminal.content_hash, 'hex'),
    mutation_hash: Buffer.from(terminal.mutation_hash, 'hex'),
    prev_mutation_hash: Buffer.from(terminal.prev_mutation_hash, 'hex'),
    ts_signed: terminal.ts_signed,
    nonce: terminal.nonce,
    sig: Buffer.from(terminal.signature, 'base64url'),
  };
  const eventProof = verifyEventProof(row, certBody.pubkey);
  assert(eventProof.valid === true, `p3_terminal_event_invalid:${eventProof.reason}`);

  return {
    verified: true,
    qualification_sha256: expectedQualification,
    terminal_receipt_sha256: expectedTerminal,
    terminal_event_id: terminal.event_id,
    source_commit: receipt.source_commit,
    node_version: receipt.node_version,
    zero_residue: historicalCleanupReceipt,
    retained_installation: retainedCurrentReceipt,
    instance: receipt.instance,
    database: receipt.database,
    http_port: receipt.http_port,
  };
}

async function main() {
  const input = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_RECEIPT;
  const receipt = JSON.parse(await readFile(input, 'utf8'));
  console.log(JSON.stringify(verifyP3InstallerQualification(receipt), null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
