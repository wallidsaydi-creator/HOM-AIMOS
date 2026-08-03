#!/usr/bin/env node

// census-corpus.mjs — READ-ONLY corpus + ledger census.
//
// Answers the questions Paper 1 cannot be written without:
//   1. Does a PRE-PROTOCOL population exist? (i.e. is the retroactive-coverage
//      ceremony a real claim, or a claim this fork does not get to make?)
//   2. What is the provenance ledger's actual shape — genesis/backfilled rows,
//      signature form versions, event types?
//   3. Is the signed-cognitive-mutation pillar (the new headline) populated —
//      are there REWEIGHT rows, and does every weight mutation carry a sig?
//   4. Corpus hygiene: quarantine counts, hash coverage.
//
// SELECT ONLY. This script writes nothing, signs nothing, and runs no ceremony.
// It is safe against the canonical brain.
//
// Usage: node scripts/ceremony/census-corpus.mjs [--aimos-db <name>] [--json]

import { query } from '../../db/connection.js';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';

const asJson = process.argv.includes('--json');
const database = resolveAimosDatabaseName();

async function one(sql, params = []) {
  const r = await query(sql, params);
  return r.rows[0] || {};
}
async function many(sql, params = []) {
  const r = await query(sql, params);
  return r.rows;
}

// Tolerate schema drift: a missing table/column must not abort the census.
async function safe(label, fn, fallback = null) {
  try {
    return await fn();
  } catch (err) {
    return { _error: `${label}: ${String(err?.message || err).split('\n')[0]}`, ...(fallback || {}) };
  }
}

async function main() {
  const corpus = await safe('corpus', () => one(
    `SELECT count(*)::int AS memories,
            count(*) FILTER (WHERE scope = 'quarantine')::int AS quarantined_scope,
            count(*) FILTER (WHERE memory_type = 'quarantine')::int AS quarantined_type,
            count(*) FILTER (WHERE content_hash IS NULL)::int AS without_content_hash,
            count(*) FILTER (WHERE supersedes_id IS NOT NULL)::int AS supersedes_rows,
            min(created_at) AS oldest,
            max(created_at) AS newest
       FROM aimos_memories`
  ));

  // THE ceremony question: memories with no v3 BIND, and memories with no
  // provenance row at all. These are the "pre-protocol" population.
  const preProtocol = await safe('pre_protocol', () => one(
    `SELECT count(*) FILTER (WHERE binding.memory_id IS NULL)::int AS without_v3_bind,
            count(*) FILTER (WHERE p.memory_id IS NULL)::int      AS without_any_provenance
       FROM aimos_memories m
       LEFT JOIN (
         SELECT DISTINCT memory_id FROM aimos_memory_provenance
          WHERE event_type = 'BIND' AND binding_schema_version = 3
       ) binding ON binding.memory_id = m.id
       LEFT JOIN (SELECT DISTINCT memory_id FROM aimos_memory_provenance) p
         ON p.memory_id = m.id`
  ));

  const ledger = await safe('ledger', () => one(
    `SELECT count(*)::int AS provenance_rows,
            count(DISTINCT memory_id)::int AS memories_covered,
            count(*) FILTER (WHERE is_genesis)::int AS genesis_rows,
            count(*) FILTER (WHERE backfilled)::int AS backfilled_rows,
            count(*) FILTER (WHERE sig IS NULL)::int AS unsigned_rows,
            count(*) FILTER (WHERE sig_form_version = 1)::int AS sig_form_v1,
            count(*) FILTER (WHERE sig_form_version = 2)::int AS sig_form_v2
       FROM aimos_memory_provenance`
  ));

  const byEvent = await safe('by_event_type', () => many(
    `SELECT event_type,
            count(*)::int AS rows,
            count(*) FILTER (WHERE sig IS NOT NULL)::int AS signed_rows
       FROM aimos_memory_provenance
      GROUP BY event_type
      ORDER BY rows DESC`
  ), []);

  // The new headline: signed cognitive mutation. Every REWEIGHT must be signed,
  // and every applied weight change must have consumed a signed provenance row.
  const cognitive = await safe('cognitive_mutation', () => one(
    `SELECT count(*)::int AS reweight_rows,
            count(*) FILTER (WHERE sig IS NOT NULL)::int AS reweight_signed,
            count(*) FILTER (WHERE sig IS NULL)::int      AS reweight_unsigned
       FROM aimos_memory_provenance
      WHERE event_type = 'REWEIGHT'`
  ));

  const projections = await safe('weight_projections', () => one(
    `SELECT count(*)::int AS projection_rows,
            count(DISTINCT memory_id)::int AS memories_reweighted
       FROM aimos_cognitive_weight_projections`
  ));

  const envelope = await safe('save_envelope', () => one(
    `SELECT count(*)::int AS envelope_rows,
            count(DISTINCT agent_id)::int AS agents
       FROM aimos_save_envelope`
  ));

  const flags = await safe('governor_flags', () => many(
    `SELECT DISTINCT ON (config_key) config_key, enabled, ts_signed
       FROM aimos_governor_config
      ORDER BY config_key, ts_signed DESC`
  ), []);

  const report = {
    database,
    read_only: true,
    corpus,
    pre_protocol: preProtocol,
    ledger,
    provenance_by_event_type: byEvent,
    cognitive_mutation: cognitive,
    weight_projections: projections,
    save_envelope: envelope,
    governor_flags: flags,
  };

  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  const pct = (n, d) => (d > 0 ? `${((n / d) * 100).toFixed(1)}%` : 'n/a');
  const M = corpus.memories ?? 0;

  console.log(`\n=== CORPUS CENSUS (read-only) — db: ${database} ===\n`);
  console.log(`memories                 ${M}`);
  console.log(`  quarantined (scope)    ${corpus.quarantined_scope ?? '?'}`);
  console.log(`  without content_hash   ${corpus.without_content_hash ?? '?'}`);
  console.log(`  supersession rows      ${corpus.supersedes_rows ?? '?'}`);
  console.log(`  oldest                 ${corpus.oldest ?? '?'}`);
  console.log(`  newest                 ${corpus.newest ?? '?'}`);

  console.log(`\n--- CEREMONY PILLAR: is there a pre-protocol population? ---`);
  const noBind = preProtocol.without_v3_bind ?? 0;
  const noProv = preProtocol.without_any_provenance ?? 0;
  console.log(`memories WITHOUT a v3 BIND        ${noBind}  (${pct(noBind, M)} of corpus)`);
  console.log(`memories WITHOUT any provenance   ${noProv}  (${pct(noProv, M)} of corpus)`);
  console.log(
    noBind > 0
      ? `→ PILLAR IS REAL: ${noBind} memories are retroactive-coverage targets.`
      : `→ NO pre-protocol population: the corpus is fully bound. The retroactive-backfill\n  pillar must be SEEDED to be demonstrated, or CUT from the paper.`
  );

  console.log(`\n--- PROVENANCE LEDGER ---`);
  console.log(`provenance rows          ${ledger.provenance_rows ?? '?'}  covering ${ledger.memories_covered ?? '?'} memories`);
  console.log(`  genesis / backfilled   ${ledger.genesis_rows ?? '?'} / ${ledger.backfilled_rows ?? '?'}`);
  console.log(`  unsigned rows          ${ledger.unsigned_rows ?? '?'}`);
  console.log(`  sig_form v1 / v2       ${ledger.sig_form_v1 ?? '?'} / ${ledger.sig_form_v2 ?? '?'}`);
  if (Array.isArray(byEvent) && byEvent.length) {
    console.log(`  by event_type:`);
    for (const r of byEvent) console.log(`    ${String(r.event_type).padEnd(18)} ${String(r.rows).padStart(6)}  signed ${r.signed_rows}`);
  }

  console.log(`\n--- HEADLINE: SIGNED COGNITIVE MUTATION ---`);
  console.log(`REWEIGHT rows            ${cognitive.reweight_rows ?? '?'}  (signed ${cognitive.reweight_signed ?? '?'}, UNSIGNED ${cognitive.reweight_unsigned ?? '?'})`);
  console.log(`weight projections       ${projections.projection_rows ?? '?'}  over ${projections.memories_reweighted ?? '?'} memories`);
  if ((cognitive.reweight_unsigned ?? 0) > 0) {
    console.log(`→ ⚠️  UNSIGNED REWEIGHT ROWS EXIST — the headline claim would be false. Investigate.`);
  } else if ((cognitive.reweight_rows ?? 0) === 0) {
    console.log(`→ No self-mutation has occurred yet on this brain. The pillar's empirical`);
    console.log(`  demonstration must be EXERCISED (drive reweights) before it can be measured.`);
  } else {
    console.log(`→ Every cognitive mutation on this brain is signed. Headline holds empirically.`);
  }

  console.log(`\n--- ENVELOPE / FLAGS ---`);
  console.log(`save_envelope rows       ${envelope.envelope_rows ?? '?'} across ${envelope.agents ?? '?'} agents`);
  if (Array.isArray(flags) && flags.length) {
    for (const f of flags) console.log(`  flag ${String(f.config_key).padEnd(26)} ${f.enabled ? 'ON' : 'OFF'}`);
  } else {
    console.log(`  (no governor flag rows — all flags default OFF/shadow)`);
  }

  const errs = Object.values(report).filter((v) => v && v._error).map((v) => v._error);
  if (errs.length) {
    console.log(`\n--- SCHEMA NOTES ---`);
    for (const e of errs) console.log(`  ${e}`);
  }
  console.log('');
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('census failed:', err?.message || err);
    process.exit(1);
  });
