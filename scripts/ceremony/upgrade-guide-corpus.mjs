#!/usr/bin/env node

// Append the current manifest-bound Guide corpus through the real signed
// /aimos/save route. Older Guide versions remain retained and are linked by
// signed supersession lineage. This ceremony reuses Genesis A6 as the single
// native ingestion owner; it does not call persistMemory or provenance APIs.

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

import { pool } from '../../db/connection.js';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import { verifyGenesisManifest } from '../verify-genesis-manifest.mjs';
import { phaseA6GenesisGuideIngestion } from '../genesis-install.mjs';
import { verifySchedulerGenesisReadiness } from '../../services/orchestration/scheduler.js';

const brainRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const live = process.argv.includes('--live');
const database = resolveAimosDatabaseName();

try {
  const manifest = verifyGenesisManifest({ brainRoot });
  const expectedKeys = manifest.files.map(
    (record) => `guide:housekeeper:${path.basename(record.path, '.md')}`,
  );
  let alreadyVerified = 0;
  for (const record of manifest.files) {
    const key = `guide:housekeeper:${path.basename(record.path, '.md')}`;
    const content = readFileSync(record.absolutePath, 'utf8');
    const exact = await pool.query(
      `SELECT 1
         FROM aimos_memories m
        WHERE m.company_id = 'hom'
          AND m.key = $1
          AND m.value = $2
          AND m.source = 'guide:genesis-install'
          AND EXISTS (
            SELECT 1 FROM aimos_memory_provenance p
             WHERE p.memory_id = m.id
               AND p.event_type = 'SAVE'
               AND p.body_json->>'genesis_manifest_schema' = $3
               AND p.body_json->>'genesis_manifest_version' = $4
               AND p.body_json->>'genesis_corpus_root' = $5
               AND p.body_json->>'genesis_file_path' = $6
               AND p.body_json->>'genesis_file_sha256' = $7
               AND (p.body_json->>'genesis_file_bytes')::int = $8
          )
          AND EXISTS (
            SELECT 1 FROM aimos_memory_provenance binding
             WHERE binding.memory_id = m.id AND binding.event_type = 'BIND'
          )
        LIMIT 1`,
      [
        key,
        content,
        manifest.schema,
        String(manifest.version),
        manifest.corpusRoot,
        record.path,
        record.sha256,
        record.bytes,
      ],
    );
    if (exact.rows.length === 1) alreadyVerified += 1;
  }
  const retainedBefore = await pool.query(
    `SELECT count(*)::int AS rows
       FROM aimos_memories m
      WHERE m.company_id = 'hom'
        AND m.source = 'guide:genesis-install'
        AND m.key = ANY($1::text[])
        AND EXISTS (
          SELECT 1 FROM aimos_memory_provenance p
           WHERE p.memory_id = m.id
             AND p.event_type = 'SAVE'
             AND p.body_json->>'genesis_manifest_schema' = $2
             AND p.body_json->>'genesis_manifest_version' <> $3
        )`,
    [expectedKeys, manifest.schema, String(manifest.version)],
  );
  const retainedPriorRows = Number(retainedBefore.rows[0]?.rows || 0);
  if (!live) {
    console.log(JSON.stringify({
      database,
      mode: 'DRY_RUN',
      manifest_schema: manifest.schema,
      manifest_version: manifest.version,
      corpus_root: manifest.corpusRoot,
      expected: manifest.files.length,
      already_verified: alreadyVerified,
      requiring_append: manifest.files.length - alreadyVerified,
      retained_prior_version_rows: retainedPriorRows,
    }, null, 2));
  } else {
    const result = await phaseA6GenesisGuideIngestion({
      targetPool: pool,
      manifestVerification: manifest,
    });
    const readiness = await verifySchedulerGenesisReadiness({ brainRoot });
    if (!readiness.ok) {
      throw new Error(`guide_upgrade_readiness_failed:${readiness.reason}`);
    }
    const retainedAfter = await pool.query(
      `SELECT count(*)::int AS rows
         FROM aimos_memories m
        WHERE m.company_id = 'hom'
          AND m.source = 'guide:genesis-install'
          AND m.key = ANY($1::text[])
          AND EXISTS (
            SELECT 1 FROM aimos_memory_provenance p
             WHERE p.memory_id = m.id
               AND p.event_type = 'SAVE'
               AND p.body_json->>'genesis_manifest_schema' = $2
               AND p.body_json->>'genesis_manifest_version' <> $3
          )`,
      [expectedKeys, manifest.schema, String(manifest.version)],
    );
    const retainedPriorRowsAfter = Number(retainedAfter.rows[0]?.rows || 0);
    if (retainedPriorRowsAfter !== retainedPriorRows) {
      throw new Error(`guide_upgrade_retention_violation:before=${retainedPriorRows}:after=${retainedPriorRowsAfter}`);
    }
    const topology = await pool.query(
      `SELECT m.key,
              count(*)::int AS versions,
              count(*) FILTER (WHERE NOT EXISTS (
                SELECT 1 FROM aimos_memories successor
                 WHERE successor.company_id = m.company_id
                   AND successor.key = m.key
                   AND successor.supersedes_id = m.id
              ))::int AS heads
         FROM aimos_memories m
        WHERE m.company_id = 'hom'
          AND m.source = 'guide:genesis-install'
          AND m.key = ANY($1::text[])
        GROUP BY m.key
        ORDER BY m.key`,
      [expectedKeys],
    );
    if (topology.rows.length !== expectedKeys.length || topology.rows.some((row) => Number(row.heads) !== 1)) {
      throw new Error('guide_upgrade_supersession_topology_invalid');
    }
    console.log(JSON.stringify({
      database,
      mode: 'LIVE',
      manifest_schema: manifest.schema,
      manifest_version: manifest.version,
      corpus_root: manifest.corpusRoot,
      retained_prior_version_rows: retainedPriorRowsAfter,
      scheduler_readiness: readiness,
      topology: topology.rows,
      ...result,
    }, null, 2));
  }
} finally {
  await pool.end();
}
