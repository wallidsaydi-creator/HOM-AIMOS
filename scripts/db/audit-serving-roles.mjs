#!/usr/bin/env node

// Read-only catalog proof that a private AIMOS database is not serving through
// an administrator connection. Excludes this auditor's own admin session.

import pg from 'pg';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import { resolveClusterAdminConfig } from './cluster-admin.mjs';

async function main() {
  const database = resolveAimosDatabaseName();
  const observeIndex = process.argv.indexOf('--observe-ms');
  const observeMs = observeIndex < 0 ? 0 : Number(process.argv[observeIndex + 1]);
  if (!Number.isInteger(observeMs) || observeMs < 0 || observeMs > 30_000) {
    throw new Error('serving_role_observation_window_invalid');
  }
  const config = await resolveClusterAdminConfig({ database });
  const client = new pg.Client(config);
  try {
    await client.connect();
    const seen = new Map();
    const deadline = Date.now() + observeMs;
    do {
      const rows = (await client.query(`
      SELECT activity.usename, activity.application_name, count(*)::int AS connections,
             bool_or(role.rolsuper OR role.rolbypassrls) AS privileged
        FROM pg_stat_activity activity
        JOIN pg_roles role ON role.rolname=activity.usename
       WHERE activity.datname=$1 AND activity.pid<>pg_backend_pid()
       GROUP BY activity.usename, activity.application_name
       ORDER BY activity.usename, activity.application_name`, [database])).rows;
      const allowed = new Set(['aimos_service_reader', 'aimos_identity_writer', 'agent_runtime']);
      if (rows.some((row) => !allowed.has(row.usename) || row.privileged)) {
        throw new Error('privileged_or_unknown_serving_database_session');
      }
      for (const row of rows) seen.set(`${row.usename}:${row.application_name}`, row);
      if (Date.now() >= deadline) break;
      await new Promise((resolve) => setTimeout(resolve, 200));
    } while (true);
    process.stdout.write(`${JSON.stringify({ database, sessions: [...seen.values()] })}\n`);
  } finally {
    await client.end().catch(() => {});
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
