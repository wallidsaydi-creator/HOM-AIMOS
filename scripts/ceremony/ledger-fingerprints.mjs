#!/usr/bin/env node

// ledger-fingerprints.mjs — RECOMPUTABLE ceremony fingerprints.
//
// WHY THIS FILE EXISTS: the prior paper's fingerprints (corpus_sha256,
// ledger_sha256, build_id) were computed in-process by the ceremony and then
// TRANSCRIBED into prose. They could never be re-verified — and today they
// cannot be reproduced at all. That is a reproducibility failure, not a
// bookkeeping one.
//
// Every number the paper prints must come from a command anyone can re-run.
// This module is that command. It writes nothing and signs nothing.
//
// Usage:
//   node scripts/ceremony/ledger-fingerprints.mjs [--aimos-db <name>] [--json]

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { query } from '../../db/connection.js';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// The methods-freeze set: the source files whose bytes define the crypto
// constructions the paper reports. A change to ANY of these invalidates the
// freeze and requires re-running the measurements. Keep this list in the paper.
export const METHODS_FREEZE_FILES = Object.freeze([
  'services/security/identity-chain.js',
  'services/security/agent-identity.js',
  'services/security/save-envelope.js',
  'services/security/auth-tier.js',
  'services/security/memory-provenance.js',
  'services/security/canary-tracker.js',
  'services/security/canary-write-gate.js',
  'services/security/nonce-window.js',
  'services/security/agent-revocation-cache.js',
  'services/governance/governor-config-ledger.js',
  'services/write/persist-memory.js',
  'routes/aimos.js',
]);

/**
 * build_id — SHA-256 over the concatenated bytes of the methods-freeze set,
 * in declared order. Deterministic; recomputable from a clean checkout.
 */
export function computeBuildId(root = ROOT, files = METHODS_FREEZE_FILES) {
  const h = createHash('sha256');
  const missing = [];
  for (const rel of files) {
    try {
      h.update(readFileSync(path.join(root, rel)));
    } catch {
      missing.push(rel);
    }
  }
  if (missing.length) {
    throw new Error(`build_id: methods-freeze files missing: ${missing.join(', ')}`);
  }
  return h.digest('hex');
}

/**
 * corpus_sha256 — SHA-256 over `id:sha256(value)` for every memory, id-ordered.
 * The ceremony's central honesty claim is that this value is IDENTICAL before
 * and after the run: the corpus is not modified, only the ledger grows.
 */
export async function computeCorpusFingerprint() {
  const { rows } = await query(
    `SELECT id::text AS id, encode(digest(coalesce(value,''), 'sha256'), 'hex') AS vhash
       FROM aimos_memories
      ORDER BY id ASC`
  );
  const h = createHash('sha256');
  for (const r of rows) h.update(`${r.id}:${r.vhash}\n`, 'utf8');
  return { digest: h.digest('hex'), rows: rows.length };
}

/**
 * ledger_sha256 — SHA-256 over `memory_id:mutation_hash` for the CEREMONY rows
 * (v2, backfilled, non-genesis) in chain order. Stable because the ledger is
 * append-only and the ceremony is idempotent.
 */
export async function computeLedgerFingerprint() {
  const { rows } = await query(
    `SELECT p.memory_id::text AS memory_id, encode(p.mutation_hash, 'hex') AS mutation_hash
       FROM aimos_memory_provenance p
       JOIN aimos_memories m ON m.id = p.memory_id
      WHERE p.sig_form_version = 2 AND p.backfilled = true AND p.is_genesis = false
      ORDER BY m.created_at ASC, m.id ASC`
  );
  const h = createHash('sha256');
  for (const r of rows) h.update(`${r.memory_id}:${r.mutation_hash}`, 'utf8');
  return { digest: h.digest('hex'), rows: rows.length };
}

export async function allFingerprints() {
  const [corpus, ledger] = await Promise.all([
    computeCorpusFingerprint(),
    computeLedgerFingerprint(),
  ]);
  return {
    database: resolveAimosDatabaseName(),
    build_id: computeBuildId(),
    corpus_sha256: corpus.digest,
    corpus_rows: corpus.rows,
    ledger_sha256: ledger.digest,
    ceremony_rows: ledger.rows,
    methods_freeze_files: METHODS_FREEZE_FILES.length,
  };
}

// ─── CLI ────────────────────────────────────────────────────────────────────
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  allFingerprints()
    .then((fp) => {
      if (process.argv.includes('--json')) {
        console.log(JSON.stringify(fp, null, 2));
      } else {
        console.log(`\n=== LEDGER FINGERPRINTS (read-only) — db: ${fp.database} ===\n`);
        console.log(`build_id        ${fp.build_id}`);
        console.log(`                (sha256 over ${fp.methods_freeze_files} methods-freeze source files)`);
        console.log(`corpus_sha256   ${fp.corpus_sha256}`);
        console.log(`                (${fp.corpus_rows} memories)`);
        console.log(`ledger_sha256   ${fp.ledger_sha256}`);
        console.log(`                (${fp.ceremony_rows} v2 ceremony rows)\n`);
      }
      process.exit(0);
    })
    .catch((err) => {
      console.error('fingerprints failed:', err?.message || err);
      process.exit(1);
    });
}
