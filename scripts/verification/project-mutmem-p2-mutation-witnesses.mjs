#!/usr/bin/env node

// Read-only projector for the P2 mutation cryptographic witness sidecar.
// The output supplies complete retained signed rows omitted by the frozen P1
// summary bundle. It performs no write SQL and grants no verification authority
// to the database; independent verifiers recompute every commitment offline.

import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { agentPool, pool } from '../../db/connection.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'artifacts/security/mutmem-v2/p2-mutation-witness');
const DOMAIN = Buffer.from('hom.aimos.mutmem-portable-mutation-witness/v1\0', 'utf8');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const hex = (value) => value == null ? null : Buffer.from(value).toString('hex');
const b64u = (value) => value == null ? null : Buffer.from(value).toString('base64url');
const iso = (value) => value == null ? null : new Date(value).toISOString();
const object = (value) => {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  try { return JSON.parse(value || '{}'); } catch { return {}; }
};

function cli(name) {
  const prefix = `${name}=`;
  const inline = process.argv.find((value) => value.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function witnessHash(body) {
  return sha(Buffer.concat([DOMAIN, Buffer.from(canonicalJson(body), 'utf8')]));
}

async function fullEvent(eventId) {
  const result = await pool.query(
    `SELECT e.id::text,e.ts,e.company_id,e.agent_id,e.operation,e.key,e.metadata,
            e.parent_event_id::text,e.proof_required,e.ledger_version,
            e.ledger_seq::text,e.signer_agent_id,e.signer_valid_from,
            e.cert_fingerprint,e.identity_tier,e.authority_kind,e.signed_body,
            e.content_hash,e.mutation_hash,e.prev_mutation_hash,e.ts_signed,
            e.nonce,e.sig,i.pubkey,i.cert,i.valid_until
       FROM aimos_events e
       JOIN agent_identity i ON i.agent_id=e.signer_agent_id
                            AND i.valid_from=e.signer_valid_from
      WHERE e.id=$1::uuid`,
    [eventId],
  );
  if (result.rowCount !== 1) throw new Error(`p2_mutation_event_missing:${eventId}`);
  const row = result.rows[0];
  return {
    event_id: row.id,
    timestamp: new Date(Number(row.ts_signed) * 1000).toISOString(),
    company_id: row.company_id,
    subject_agent_id: row.agent_id,
    operation: row.operation,
    key: row.key,
    metadata: object(row.metadata),
    parent_event_id: row.parent_event_id,
    proof_required: Boolean(row.proof_required),
    ledger_version: Number(row.ledger_version),
    ledger_seq: Number(row.ledger_seq),
    signer_agent_id: row.signer_agent_id,
    signer_valid_from: iso(row.signer_valid_from),
    signer_valid_until: iso(row.valid_until),
    cert_fingerprint: row.cert_fingerprint,
    identity_tier: row.identity_tier,
    authority_kind: row.authority_kind,
    signed_body: object(row.signed_body),
    content_hash: hex(row.content_hash),
    mutation_hash: hex(row.mutation_hash),
    prev_mutation_hash: hex(row.prev_mutation_hash),
    ts_signed: Number(row.ts_signed),
    nonce: row.nonce,
    signature_b64u: b64u(row.sig),
    signer_public_key_b64u: row.pubkey,
    signer_certificate: row.cert,
  };
}

async function fullValence(rowId) {
  const result = await pool.query(
    `SELECT l.*,i.pubkey,i.cert,i.valid_until
       FROM memory_valence_ledger l
       JOIN agent_identity i ON i.agent_id=l.signer_agent_id
                            AND i.valid_from=l.signer_valid_from
      WHERE l.id=$1::bigint`,
    [rowId],
  );
  if (result.rowCount !== 1) throw new Error(`p2_mutation_valence_missing:${rowId}`);
  const row = result.rows[0];
  return {
    row_id: String(row.id),
    memory_id: String(row.memory_id),
    company_id: row.company_id,
    reward_sign: Number(row.reward_sign),
    context_hash: row.context_hash,
    body_json: object(row.body_json),
    content_hash: hex(row.content_hash),
    prev_hash: hex(row.prev_hash),
    row_hash: hex(row.row_hash),
    ts_signed: Number(row.ts_signed),
    nonce: row.nonce,
    signature_b64u: b64u(row.sig),
    proof_required: Boolean(row.proof_required),
    signer_agent_id: row.signer_agent_id,
    signer_valid_from: iso(row.signer_valid_from),
    signer_valid_until: iso(row.valid_until),
    cert_fingerprint: row.cert_fingerprint,
    identity_tier: row.identity_tier,
    signer_public_key_b64u: row.pubkey,
    signer_certificate: row.cert,
  };
}

async function fullProvenance(provenanceId) {
  const result = await pool.query(
    `SELECT p.*,i.pubkey,i.cert,i.valid_until
       FROM aimos_memory_provenance p
       JOIN agent_identity i ON i.agent_id=p.agent_id
                            AND i.valid_from=p.agent_valid_from
      WHERE p.provenance_id=$1::uuid`,
    [provenanceId],
  );
  if (result.rowCount !== 1) throw new Error(`p2_mutation_provenance_missing:${provenanceId}`);
  const row = result.rows[0];
  return {
    provenance_id: String(row.provenance_id),
    memory_id: String(row.memory_id),
    agent_id: row.agent_id,
    agent_valid_from: iso(row.agent_valid_from),
    agent_valid_until: iso(row.valid_until),
    cert_fingerprint: row.cert_fingerprint,
    content_hash: hex(row.content_hash),
    mutation_hash: hex(row.mutation_hash),
    prev_mutation_hash: hex(row.prev_mutation_hash),
    ts_signed: Number(row.ts_signed),
    nonce: row.nonce,
    signature_b64u: b64u(row.sig),
    identity_tier: row.identity_tier,
    is_genesis: Boolean(row.is_genesis),
    backfilled: Boolean(row.backfilled),
    memory_originated_at: iso(row.memory_originated_at),
    event_type: row.event_type,
    body_json: object(row.body_json),
    sig_form_version: Number(row.sig_form_version || 1),
    request_sig_form: Number(row.request_sig_form || 1),
    signed_method: row.signed_method,
    signed_path: row.signed_path,
    signed_claims: row.signed_claims == null ? null : object(row.signed_claims),
    signer_public_key_b64u: row.pubkey,
    signer_certificate: row.cert,
  };
}

async function project(entry, trustBundle) {
  const bundle = entry.bundle;
  const [outcomeEvent, valence] = await Promise.all([
    fullEvent(bundle.outcome_event.event_id),
    fullValence(entry.valence_row_id),
  ]);
  const terminalProof = bundle.terminal.kind === 'authorized_transition'
    ? {
      kind: 'reweight_provenance',
      provenance: await fullProvenance(bundle.terminal.reweight_provenance.provenance_id),
    }
    : {
      kind: 'terminal_event',
      event: await fullEvent(bundle.terminal.event.event_id || bundle.terminal.event.id),
    };
  const body = {
    format: {
      schema: 'hom.aimos.mutmem-portable-mutation-witness/v1',
      version: 1,
      canonicalization: 'hom-aimos/canonical-json/v1',
      hash: 'sha256',
      signature: 'ed25519',
    },
    mutation_bundle_sha256: bundle.bundle_sha256,
    trust_context_bundle_sha256: trustBundle.bundle_sha256,
    expected_master_fingerprint: trustBundle.expected_master_fingerprint,
    outcome_event: outcomeEvent,
    valence_evidence: valence,
    terminal_proof: terminalProof,
  };
  return { ...body, witness_sha256: witnessHash(body) };
}

async function main() {
  const inputArgument = cli('--input');
  const trustArgument = cli('--trust-context');
  if (!inputArgument || !trustArgument) throw new Error('p2_mutation_witness_input_required');
  const inputPath = path.resolve(inputArgument);
  const trustPath = path.resolve(trustArgument);
  const [input, trustArtifact] = await Promise.all([
    readFile(inputPath, 'utf8').then(JSON.parse),
    readFile(trustPath, 'utf8').then(JSON.parse),
  ]);
  const trustBundle = trustArtifact.bundle;
  if (!Array.isArray(input.projections) || !trustBundle?.bundle_sha256) {
    throw new Error('p2_mutation_witness_input_invalid');
  }
  const witnesses = [];
  for (const entry of input.projections) witnesses.push(await project(entry, trustBundle));
  const artifact = {
    schema: 'hom.aimos.mutmem-p2-mutation-witness-set/v1',
    private_identity_bearing_artifact: true,
    source_mutation_artifact_sha256: sha(await readFile(inputPath)),
    trust_context_artifact_sha256: sha(await readFile(trustPath)),
    intended_n: witnesses.length,
    witnesses,
    database_mutation: false,
    memory_write: false,
  };
  const bytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
  await mkdir(OUTPUT, { recursive: true, mode: 0o700 });
  const outputPath = path.join(OUTPUT, `${sha(bytes).slice(0, 24)}.json`);
  await writeFile(outputPath, bytes, { flag: 'wx', mode: 0o600 });
  await chmod(outputPath, 0o600);
  console.log(JSON.stringify({
    success: true,
    status: 'P2_MUTATION_CRYPTOGRAPHIC_WITNESSES_PROJECTED',
    intended_n: witnesses.length,
    witness_sha256s: witnesses.map((witness) => witness.witness_sha256),
    artifact: outputPath,
    artifact_sha256: sha(bytes),
    database_mutation: false,
    memory_write: false,
  }, null, 2));
}

main()
  .catch((error) => {
    console.error(`[FATAL] ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await Promise.allSettled([pool.end(), agentPool.end()]);
  });
