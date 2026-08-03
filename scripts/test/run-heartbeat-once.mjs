#!/usr/bin/env node

import { pool } from '../../db/connection.js';
import { runHeartbeat } from '../../jobs/heartbeat.js';

try {
  const result = await runHeartbeat('hom');
  if (!result || typeof result.status !== 'string' || !result.timestamp) {
    throw new Error(`heartbeat returned an invalid result: ${JSON.stringify(result)}`);
  }
  console.log(JSON.stringify({ status: result.status, timestamp: result.timestamp }));
} finally {
  await pool.end().catch(() => {});
}
