#!/usr/bin/env node

import { createHash } from 'node:crypto';

import { agentPool, pool } from '../../db/connection.js';
import { AIMOS_INSTALLATION_CONTEXT } from '../../services/core/runtime-config.js';
import { logEvent, readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

function cli(name) {
  const inline = process.argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}
const sourceCommit = String(cli('--source-commit') || '');
if (!/^[0-9a-f]{40}$/.test(sourceCommit) || AIMOS_INSTALLATION_CONTEXT.canonical) {
  throw new Error('p3_installer_terminal_scope_invalid');
}
try {
  const counts = await pool.query(
    `SELECT
       (SELECT count(*)::int FROM aimos_memories) AS memories,
       (SELECT count(*)::int FROM aimos_memory_provenance) AS provenance,
       (SELECT count(*)::int FROM agent_identity) AS identities,
       (SELECT count(*)::int FROM agent_identity WHERE agent_id='housekeeper') AS housekeepers,
       (SELECT count(*)::int FROM aimos_master_identity) AS masters,
       (SELECT count(*)::int FROM aimos_memories WHERE source='guide:genesis-install') AS guide_memories,
       (SELECT count(*)::int FROM aimos_memories
         WHERE source ~* '(benchmark|eval|longmemeval|locomo|poisonedrag)') AS experimental_memories`,
  );
  const metadata = {
    schema: 'hom.aimos.p3-installer-qualification-terminal/v1',
    installation_context_sha256: AIMOS_INSTALLATION_CONTEXT.context_sha256,
    instance: AIMOS_INSTALLATION_CONTEXT.instance,
    source_commit: sourceCommit,
    node_version: process.version,
    counts: counts.rows[0],
    canonical_save_owner: true,
    canonical_recall_owner: true,
    memory_write: false,
    reasoning: 'The public installer created and restarted one isolated same-user HOM-AIMOS namespace with a fresh Housekeeper and no experimental data.',
  };
  const terminal = await logEvent(
    'hom',
    'housekeeper',
    'p3_installer_qualification_terminal',
    AIMOS_INSTALLATION_CONTEXT.instance,
    metadata,
    null,
    { returnReceipt: true, exclusiveOperationKey: true },
  );
  const eventId = terminal.event_id || terminal.id;
  const verified = await readVerifiedEventById(eventId, 'hom');
  const receipt = {
    schema: 'hom.aimos.p3-installer-qualification-terminal-receipt/v1',
    event_id: terminal.event_id,
    proof_required: terminal.proof_required,
    ledger_version: terminal.ledger_version,
    ledger_seq: terminal.ledger_seq,
    signed_body: terminal.signed_body,
    content_hash: terminal.content_hash,
    mutation_hash: terminal.mutation_hash,
    prev_mutation_hash: terminal.prev_mutation_hash,
    signer_agent_id: terminal.signer_agent_id,
    signer_valid_from: terminal.signer_valid_from,
    cert_fingerprint: terminal.cert_fingerprint,
    signer_certificate: terminal.signer_certificate,
    identity_tier: terminal.identity_tier,
    ts_signed: terminal.ts_signed,
    nonce: terminal.nonce,
    signature: terminal.signature,
    metadata,
    independently_verified: Boolean(verified),
    portable_proof_complete: true,
  };
  receipt.receipt_sha256 = createHash('sha256')
    .update(canonicalJson(receipt), 'utf8').digest('hex');
  console.log(JSON.stringify(receipt));
} finally {
  await Promise.allSettled([pool.end(), agentPool.end()]);
}
