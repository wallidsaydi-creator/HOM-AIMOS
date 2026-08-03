#!/usr/bin/env node

// backfill-ledger-reviewer.mjs — retroactive ORIGIN-TIME notarization ceremony.
//
// This is the script three separate source comments already point at
// (memory-provenance.js:94, agent-identity.js:307, governor-config-ledger.js:72).
// It was specified but never written. This is it.
//
// ─── WHAT THE CEREMONY CLAIMS (and what it does NOT) ────────────────────────
//
// HOM-AIMOS memories are signed from genesis — unlike a legacy corpus, they do
// not need retroactive SIGNATURE coverage. What they lack is a cryptographic
// binding of their ORIGIN TIME: a v1 provenance row signs (body, nonce,
// ts_signed), where ts_signed is when the row was written. The memory's own
// origin timestamp rides along as metadata — unsigned, and therefore mutable
// without breaking any signature.
//
// The v2 canonical form folds memory_originated_at_unix into BOTH the signed
// preimage and the mutation_hash preimage, so the time axis is bound into the
// chain itself:
//
//   v2 signed message = canonicalJson(body) \n nonce \n ts_signed \n memory_originated_at_unix
//   v2 mutation_hash  = sha256(content_hash || prev_mutation_hash || nonce
//                              || String(ts_signed) || String(memory_originated_at_unix))
//
// The ceremony appends ONE v2 re-attestation row per memory. It NEVER touches
// aimos_memories — corpus_sha256_pre MUST equal corpus_sha256_post. That
// equality is the ceremony's central honesty claim, and it is asserted here,
// not merely hoped for.
//
// TWO ROWS PER MEMORY, TWO CLAIMS, BOTH HONEST:
//   - the existing anchor row  = "this memory was signed at origin"
//   - the new ceremony row     = "the reviewer notarized at T that this memory
//                                 existed with this content hash and this
//                                 origin time"
// We do not backdate the ceremony row or pretend it was signed at origin —
// that would destroy the ledger's auditability. backfilled=true marks it.
//
// ─── SCOPE (honest) ─────────────────────────────────────────────────────────
// Tamper-evident, not anti-corruptible. Notarization-at-T, not authorship-at-
// origin. Integrity is not truth. See the paper's limitations section.
//
// ─── SAFETY ─────────────────────────────────────────────────────────────────
//   * DRY-RUN IS THE DEFAULT. --live is required to write anything.
//   * Refuses unless the BACKFILL_CEREMONY_LEDGER governor flag is ON (signed,
//     hash-chained). The control plane IS the audit plane.
//   * Idempotent: a pre-scan skips any memory that already has a v2 ceremony
//     row, so a re-run is a no-op and a crashed run resumes.
//   * A START attestation row is written before any batch; a COMPLETE row
//     after. START with no COMPLETE = evidence of an interrupted ceremony.
//
// Usage:
//   node scripts/backfill-ledger-reviewer.mjs                 # dry-run (default)
//   node scripts/backfill-ledger-reviewer.mjs --live          # execute
//   node scripts/backfill-ledger-reviewer.mjs --live --batch-size 500 --spot-check 10

import { createHash, randomBytes } from 'node:crypto';

import { agentPool, query } from '../db/connection.js';
import { canonicalJson, signPayloadV2, verifyPayloadSigV2 } from '../services/security/agent-identity.js';
import { computeMutationHashV2 } from '../services/security/memory-provenance.js';
import {
  getHousekeeperCert,
  extractValidFromIso,
  loadHousekeeperPrivkey,
  detectTierFromCert,
} from '../services/security/housekeeper-signer.js';
import { governorConfigLedger } from '../services/governance/governor-config-ledger.js';
import { resolveAimosDatabaseName } from '../services/core/runtime-config.js';
import { allFingerprints, computeCorpusFingerprint } from './ceremony/ledger-fingerprints.mjs';

const CEREMONY_FLAG = 'BACKFILL_CEREMONY_LEDGER';
const CEREMONY_AGENT = 'housekeeper';

function cliNum(flag, fallback) {
  const i = process.argv.indexOf(flag);
  if (i === -1) return fallback;
  const n = Number(process.argv[i + 1]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

const LIVE = process.argv.includes('--live');
const BATCH_SIZE = cliNum('--batch-size', 500);
const SPOT_CHECK = cliNum('--spot-check', 10);
const database = resolveAimosDatabaseName();

/** Memories with no v2 ceremony row yet, each with its current chain head. */
async function preScan() {
  const { rows } = await query(
    `SELECT m.id::text          AS memory_id,
            m.content_hash      AS content_hash,
            m.created_at        AS created_at,
            head.mutation_hash  AS prev_mutation_hash
       FROM aimos_memories m
       LEFT JOIN LATERAL (
         SELECT p.mutation_hash
           FROM aimos_memory_provenance p
          WHERE p.memory_id = m.id
          ORDER BY p.created_at DESC, p.provenance_id DESC
          LIMIT 1
       ) head ON true
      WHERE NOT EXISTS (
        SELECT 1 FROM aimos_memory_provenance c
         WHERE c.memory_id = m.id
           AND c.sig_form_version = 2
           AND c.backfilled = true
      )
        AND m.content_hash IS NOT NULL
      ORDER BY m.created_at ASC, m.id ASC`
  );
  return rows;
}

/**
 * Append a signed, hash-chained ceremony attestation row through the governor
 * config ledger. START and COMPLETE are two rows on the same chained key.
 */
async function attest(phase, payload) {
  const reason = `${phase}: ${JSON.stringify(payload)}`;
  const result = await governorConfigLedger.commitConfigFlag({
    configKey: CEREMONY_FLAG,
    enabled: phase === 'CEREMONY_START', // START holds it ON; COMPLETE releases it.
    reason,
    operator: CEREMONY_AGENT,
  });
  if (!result?.ok) {
    throw new Error(`${phase} attestation failed: ${result?.reason || 'unknown'}`);
  }
  return result;
}

/** Sign + insert one v2 ceremony row. Never touches aimos_memories. */
async function writeCeremonyRow(client, row, signer) {
  const memoryOriginatedAtUnix = Math.floor(new Date(row.created_at).getTime() / 1000);
  if (!Number.isInteger(memoryOriginatedAtUnix)) {
    throw new Error(`${row.memory_id}: unusable created_at`);
  }

  const contentHash = row.content_hash;
  const prev = row.prev_mutation_hash || null;
  const nonce = randomBytes(16).toString('base64url');
  const tsSigned = Math.floor(Date.now() / 1000);

  // The signed body is the notarization claim itself — explicit, auditable.
  const body = {
    event_type: 'RETAINED_ATTEST',
    ceremony: 'reviewer_origin_time_notarization',
    memory_id: row.memory_id,
    content_hash: contentHash.toString('hex'),
    memory_originated_at_unix: memoryOriginatedAtUnix,
    ts_signed: tsSigned,
    notarized_by: CEREMONY_AGENT,
    claim: 'notarization_at_T_not_authorship_at_origin',
  };

  const sigB64u = signPayloadV2(signer.privkey, body, nonce, tsSigned, memoryOriginatedAtUnix);
  const sigBytes = Buffer.from(sigB64u, 'base64url');

  // Verify our own signature before persisting it — a ceremony that writes an
  // unverifiable row is worse than one that writes nothing.
  const check = verifyPayloadSigV2(signer.pubkey, body, nonce, tsSigned, memoryOriginatedAtUnix, sigB64u);
  if (!check?.valid) {
    throw new Error(`${row.memory_id}: self-verify failed (${check?.reason || 'unknown'})`);
  }

  const mutationHash = computeMutationHashV2(contentHash, prev, nonce, tsSigned, memoryOriginatedAtUnix);

  await client.query(
    `INSERT INTO aimos_memory_provenance
        (memory_id, agent_id, agent_valid_from, cert_fingerprint, content_hash,
         mutation_hash, prev_mutation_hash, ts_signed, nonce, sig,
         identity_tier, is_genesis, backfilled,
         event_type, body_json, sig_form_version)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, true, $12, $13, 2)`,
    [
      row.memory_id,
      CEREMONY_AGENT,
      signer.validFromIso,
      signer.certFingerprint,
      contentHash,
      mutationHash,
      prev,
      tsSigned,
      nonce,
      sigBytes,
      signer.identityTier,
      'RETAINED_ATTEST',
      JSON.stringify(body),
    ]
  );

  return { memoryId: row.memory_id, mutationHash };
}

/** Re-verify N random ceremony rows against the v2 canonical form. */
async function spotVerify(n, pubkey) {
  const { rows } = await query(
    `SELECT memory_id::text AS memory_id, content_hash, mutation_hash, prev_mutation_hash,
            ts_signed, nonce, sig, body_json
       FROM aimos_memory_provenance
      WHERE sig_form_version = 2 AND backfilled = true
      ORDER BY random()
      LIMIT $1`,
    [n]
  );

  let pass = 0;
  const failures = [];
  for (const r of rows) {
    const body = typeof r.body_json === 'string' ? JSON.parse(r.body_json) : r.body_json;
    const moa = body?.memory_originated_at_unix;
    const sigB64u = Buffer.from(r.sig).toString('base64url');

    const sigOk = verifyPayloadSigV2(pubkey, body, r.nonce, Number(r.ts_signed), moa, sigB64u)?.valid === true;
    const expected = computeMutationHashV2(
      r.content_hash,
      r.prev_mutation_hash || null,
      r.nonce,
      Number(r.ts_signed),
      moa
    );
    const chainOk = Buffer.compare(expected, r.mutation_hash) === 0;

    if (sigOk && chainOk) pass += 1;
    else failures.push({ memory_id: r.memory_id, sig_ok: sigOk, mutation_hash_ok: chainOk });
  }
  return { checked: rows.length, pass, failures };
}

async function main() {
  console.log(`\n=== REVIEWER CEREMONY — retroactive origin-time notarization ===`);
  console.log(`db: ${database} | mode: ${LIVE ? 'LIVE (will write)' : 'DRY-RUN (writes nothing)'}\n`);

  const targets = await preScan();
  const before = await computeCorpusFingerprint();
  const totalBatches = Math.ceil(targets.length / BATCH_SIZE);

  console.log(`pre-scan:  ${targets.length} memories need a v2 ceremony row`);
  console.log(`corpus:    ${before.rows} memories, sha256 ${before.digest}`);
  console.log(`batches:   ${totalBatches} × ${BATCH_SIZE}\n`);

  if (targets.length === 0) {
    console.log('Nothing to do — every memory already carries a v2 ceremony row. (Idempotent no-op.)\n');
    return;
  }

  if (!LIVE) {
    console.log('DRY-RUN — no rows written, no attestations, no flag read.');
    console.log('Re-run with --live to execute (requires BACKFILL_CEREMONY_LEDGER=ON).\n');
    return;
  }

  // ─── Authorization: the ceremony refuses unless the signed flag is ON ─────
  const authorized = await governorConfigLedger.readFlag(CEREMONY_FLAG);
  if (!authorized) {
    console.error(`REFUSED: ${CEREMONY_FLAG} is OFF.`);
    console.error(`Authorize with the signed toggle, then re-run:`);
    console.error(`  node scripts/identity/toggle-governor-flag.js ${CEREMONY_FLAG} ON --reason="reviewer ceremony"\n`);
    process.exit(3);
  }

  const certString = await getHousekeeperCert();
  const signer = {
    privkey: loadHousekeeperPrivkey(),
    pubkey: JSON.parse(Buffer.from(certString.split('.')[0] || '', 'base64url').toString('utf8') || '{}').pubkey
      || JSON.parse(Buffer.from(certString, 'base64url').toString('utf8')).body?.pubkey,
    certFingerprint: createHash('sha256').update(certString).digest(),
    validFromIso: extractValidFromIso(certString),
    identityTier: detectTierFromCert(certString),
  };
  if (!signer.pubkey) throw new Error('could not extract housekeeper pubkey from cert');

  await attest('CEREMONY_START', {
    target_rows: targets.length,
    batch_size: BATCH_SIZE,
    corpus_sha256_pre: before.digest,
    started_at_unix: Math.floor(Date.now() / 1000),
  });
  console.log('START attestation written (signed, chained).\n');

  const t0 = Date.now();
  let written = 0;

  for (let b = 0; b < totalBatches; b += 1) {
    const batch = targets.slice(b * BATCH_SIZE, (b + 1) * BATCH_SIZE);
    const client = await agentPool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', CEREMONY_AGENT]);
      for (const row of batch) {
        await writeCeremonyRow(client, row, signer);
        written += 1;
      }
      await client.query('COMMIT');
      console.log(`batch ${b + 1}/${totalBatches}: ${batch.length} rows committed (${written}/${targets.length})`);
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      console.error(`batch ${b + 1} FAILED — rolled back: ${err.message}`);
      console.error('The START row remains as evidence of an interrupted ceremony; re-run to resume.');
      throw err;
    } finally {
      client.release();
    }
  }

  const elapsedMs = Date.now() - t0;
  const after = await allFingerprints();

  // ─── The central honesty claim, asserted rather than assumed ─────────────
  const corpusUnchanged = after.corpus_sha256 === before.digest;
  if (!corpusUnchanged) {
    throw new Error(
      `CEREMONY VIOLATED ITS OWN CONTRACT: corpus_sha256 changed ` +
      `(${before.digest} → ${after.corpus_sha256}). The corpus must not be modified.`
    );
  }

  const spot = await spotVerify(Math.min(SPOT_CHECK, written), signer.pubkey);

  await attest('CEREMONY_COMPLETE', {
    rows_backfilled: written,
    batches: totalBatches,
    elapsed_ms: elapsedMs,
    corpus_sha256_pre: before.digest,
    corpus_sha256_post: after.corpus_sha256,
    corpus_unchanged: corpusUnchanged,
    ledger_sha256_post: after.ledger_sha256,
    build_id: after.build_id,
    spot_verify: `${spot.pass}/${spot.checked}`,
    completed_at_unix: Math.floor(Date.now() / 1000),
  });

  console.log(`\n=== CEREMONY COMPLETE ===`);
  console.log(`rows backfilled   ${written} in ${totalBatches} batches, ${(elapsedMs / 1000).toFixed(1)}s`);
  console.log(`corpus_sha256     pre == post  ${corpusUnchanged ? '✓ UNCHANGED' : '✗ MODIFIED'}`);
  console.log(`                  ${after.corpus_sha256}`);
  console.log(`ledger_sha256     ${after.ledger_sha256}`);
  console.log(`build_id          ${after.build_id}`);
  console.log(`spot-verify       ${spot.pass}/${spot.checked} ${spot.pass === spot.checked ? 'PASS' : 'FAIL'}`);
  if (spot.failures.length) console.log(`failures          ${JSON.stringify(spot.failures)}`);
  console.log(`\nCOMPLETE attestation written (signed, chained).`);
  console.log(`Every fingerprint above is recomputable:  node scripts/ceremony/ledger-fingerprints.mjs\n`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`\nceremony failed: ${err?.message || err}\n`);
    process.exit(1);
  });
