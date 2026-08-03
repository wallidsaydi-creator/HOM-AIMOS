import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { agentPool, pool } from '../../db/connection.js';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { logEvent, verifyEventLedgerChain, verifyEventProof } from '../../services/observe/event-ledger.js';

const databaseName = new URL(resolveAimosDatabaseUrl()).pathname.slice(1);
const LIVE_FIRE = process.argv.includes('--live-fire');

test('restricted event lane is signed, linear, and append-only', async (t) => {
  if (!LIVE_FIRE || !databaseName.startsWith('aimos_test_security_')) {
    t.skip('Event ledger live-fire requires an isolated aimos_test_security_* database.');
    return;
  }

  const runId = randomUUID();
  const receipts = await Promise.all(Array.from({ length: 20 }, (_, index) =>
    logEvent('hom', 'event-ledger-test', 'security_event_ledger_probe', `${runId}:${index}`, {
      index,
      reasoning: 'Exercise concurrent signed event append serialization in a disposable database.',
      source_knowledge: 'tests/security/event-ledger-db.test.mjs',
    }, null, { returnReceipt: true })
  ));

  assert.equal(new Set(receipts.map((receipt) => receipt.event_id)).size, 20);
  assert(receipts.every((receipt) => receipt.proof_required === true));
  assert(receipts.every((receipt) => receipt.signed_body && receipt.signer_certificate));

  const stored = await pool.query(
    `SELECT e.*, ai.pubkey, ai.cert, ai.revoked_at,
            revocation.ts_signed AS revocation_ts_signed
       FROM aimos_events e
       JOIN agent_identity ai
         ON ai.agent_id = e.signer_agent_id
        AND ai.valid_from = e.signer_valid_from
       LEFT JOIN aimos_agent_revocation_events revocation
         ON revocation.agent_id = ai.agent_id
        AND revocation.agent_valid_from = ai.valid_from
      WHERE e.operation = 'security_event_ledger_probe'
        AND e.key LIKE $1
      ORDER BY e.ledger_seq`,
    [`${runId}:%`],
  );
  assert.equal(stored.rowCount, 20);
  for (const row of stored.rows) {
    assert.deepEqual(verifyEventProof(row, row.pubkey), { valid: true, reason: null });
  }

  const allHeads = await pool.query(
    `SELECT ledger_seq, mutation_hash, prev_mutation_hash
       FROM aimos_events
      WHERE company_id = 'hom'
        AND signer_agent_id = 'housekeeper'
        AND signer_valid_from = $1
        AND ledger_version = 1
      ORDER BY ledger_seq`,
    [receipts[0].signer_valid_from],
  );
  for (let index = 1; index < allHeads.rows.length; index += 1) {
    assert.equal(Number(allHeads.rows[index].ledger_seq), Number(allHeads.rows[index - 1].ledger_seq) + 1);
    assert(Buffer.from(allHeads.rows[index].prev_mutation_hash).equals(Buffer.from(allHeads.rows[index - 1].mutation_hash)));
  }

  const fullStream = await pool.query(
    `SELECT e.*, ai.pubkey, ai.cert, ai.revoked_at,
            revocation.ts_signed AS revocation_ts_signed
       FROM aimos_events e
       JOIN agent_identity ai
         ON ai.agent_id = e.signer_agent_id
        AND ai.valid_from = e.signer_valid_from
       LEFT JOIN aimos_agent_revocation_events revocation
         ON revocation.agent_id = ai.agent_id
        AND revocation.agent_valid_from = ai.valid_from
      WHERE e.company_id = 'hom'
        AND e.signer_agent_id = 'housekeeper'
        AND e.signer_valid_from = $1
        AND e.ledger_version = 1
      ORDER BY e.ledger_seq`,
    [receipts[0].signer_valid_from],
  );
  const checkpoint = fullStream.rows.at(-1);
  const chain = verifyEventLedgerChain(fullStream.rows, {
    expectedHeadSequence: Number(checkpoint.ledger_seq),
    expectedHeadMutationHash: checkpoint.mutation_hash,
  });
  assert.equal(chain.rowCount, fullStream.rowCount);

  const unsignedClient = await agentPool.connect();
  try {
    await unsignedClient.query('BEGIN');
    await unsignedClient.query('SELECT set_config($1,$2,true)', ['app.current_client_id', 'hom']);
    await unsignedClient.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    await assert.rejects(
      unsignedClient.query(
        `INSERT INTO aimos_events (id, ts, company_id, agent_id, operation, key, metadata)
         VALUES ($1, NOW(), 'hom', 'forged', 'unsigned_probe', 'forged', '{}'::jsonb)`,
        [randomUUID()],
      ),
    );
    await unsignedClient.query('ROLLBACK');
  } finally {
    unsignedClient.release();
  }

  await assert.rejects(agentPool.query(
    `UPDATE aimos_events SET operation = 'tampered' WHERE id = $1`,
    [receipts[0].event_id],
  ));
  await assert.rejects(agentPool.query(
    `DELETE FROM aimos_events WHERE id = $1`,
    [receipts[0].event_id],
  ));
  await assert.rejects(agentPool.query('TRUNCATE TABLE aimos_events'));

  const privileges = await pool.query(
    `SELECT
       has_table_privilege('aimos_app', 'public.aimos_events', 'INSERT') AS app_insert,
       has_table_privilege('aimos_app', 'public.aimos_events', 'UPDATE') AS app_update,
       has_table_privilege('aimos_app', 'public.aimos_events', 'DELETE') AS app_delete,
       has_table_privilege('aimos_app', 'public.aimos_events', 'TRUNCATE') AS app_truncate`,
  );
  assert.deepEqual(privileges.rows[0], {
    app_insert: false,
    app_update: false,
    app_delete: false,
    app_truncate: false,
  });
});

test.after(async () => {
  await agentPool.end();
  await pool.end();
});
