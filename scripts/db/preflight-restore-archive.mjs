#!/usr/bin/env node

// Metadata-only gate for an identity-preserving AIMOS restore. This never
// connects to a database or reads retained row values. It is necessary, not
// sufficient: a scratch restore and signed application checks still follow.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REQUIRED_DATA = Object.freeze([
  'agent_identity', 'aimos_agent_revocation_events', 'aimos_events',
  'aimos_master_identity', 'aimos_memories', 'aimos_system_config',
  'schema_migrations',
]);
function fail(reason) { throw new Error(`restore_archive_${reason}`); }

function requiredCompanyPolicies() {
  const migration = fs.readFileSync(new URL('../../migrations/116-service-reader-role-acl.sql', import.meta.url), 'utf8');
  const literal = migration.match(/FOREACH relation_name IN ARRAY ARRAY\[([\s\S]*?)\]\s+LOOP/)?.[1];
  const names = literal?.match(/'[a-z][a-z0-9_]*'/g)?.map((name) => name.slice(1, -1));
  if (!names || names.length !== 17 || new Set(names).size !== 17) {
    fail('policy_contract_invalid');
  }
  return names;
}

export function preflightRestoreToc(toc, { database = 'aimos' } = {}) {
  if (typeof toc !== 'string' || !/^[a-z][a-z0-9_]{0,62}$/.test(database)) {
    fail('input_invalid');
  }
  const recordedDatabase = toc.match(/^;\s*dbname:\s*(\S+)\s*$/m)?.[1];
  const sourceVersion = toc.match(/^;\s*Dumped from database version:\s*(\d+)\./m)?.[1];
  const dumperVersion = toc.match(/^;\s*Dumped by pg_dump version:\s*(\d+)\./m)?.[1];
  if (recordedDatabase !== database) fail('database_mismatch');
  if (sourceVersion !== '18' || dumperVersion !== '18') fail('postgresql_18_required');
  const entries = toc.split('\n').filter((line) => /^\d+;\s/.test(line));
  if (entries.length === 0) fail('toc_empty');

  const dataTables = new Set();
  const policyTables = new Set();
  let aclEntries = 0;
  for (const entry of entries) {
    const tableData = entry.match(/\bTABLE DATA public ([a-z][a-z0-9_]*)\b/);
    if (tableData) dataTables.add(tableData[1]);
    const policy = entry.match(/\bPOLICY public ([a-z][a-z0-9_]*)\b/);
    if (policy) policyTables.add(policy[1]);
    if (/\bACL\b/.test(entry)) aclEntries++;
  }
  const missingData = REQUIRED_DATA.filter((name) => !dataTables.has(name));
  if (missingData.length) fail(`identity_data_missing:${missingData.join(',')}`);
  const companyPolicies = requiredCompanyPolicies();
  const missingPolicies = companyPolicies.filter((name) => !policyTables.has(name));
  if (missingPolicies.length) fail(`company_policies_missing:${missingPolicies.join(',')}`);
  if (aclEntries === 0) fail('acl_omitted');
  return Object.freeze({
    database, postgresMajor: 18, tocEntries: entries.length,
    identityDataEntries: REQUIRED_DATA.length,
    companyPolicyTables: companyPolicies.length,
    aclEntries,
    qualification: 'archive_metadata_only',
  });
}

export function preflightRestoreArchive({ archive, pgBin, database = 'aimos' } = {}) {
  if (!path.isAbsolute(String(archive || '')) || !path.isAbsolute(String(pgBin || ''))) {
    fail('absolute_paths_required');
  }
  const stat = fs.lstatSync(archive);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    fail('archive_custody_invalid');
  }
  const pgRestore = path.join(pgBin, 'pg_restore');
  const pgConfig = path.join(pgBin, 'pg_config');
  if (!fs.statSync(pgRestore).isFile() || !fs.statSync(pgConfig).isFile()) {
    fail('postgresql_binary_missing');
  }
  const version = execFileSync(pgConfig, ['--version'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000,
  });
  if (!/^PostgreSQL 18\./.test(version)) fail('postgresql_18_required');
  let toc;
  try {
    toc = execFileSync(pgRestore, ['--list', archive], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 60_000, maxBuffer: 16 * 1024 * 1024,
    });
  } catch {
    fail('toc_unreadable');
  }
  return preflightRestoreToc(toc, { database });
}

function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = preflightRestoreArchive({
      archive: cliValue('--archive'), pgBin: cliValue('--pg-bindir'),
      database: cliValue('--database') || 'aimos',
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
