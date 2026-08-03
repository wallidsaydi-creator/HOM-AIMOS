import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { agentPool, pool } from '../../db/connection.js';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import {
  detectTierFromCert,
  extractValidFromIso,
  getHousekeeperCert,
} from '../../services/security/housekeeper-signer.js';
import { beginToolAction, finishToolAction } from '../../services/orchestration/tool-action-ledger.js';
import { persistMemory } from '../../services/write/persist-memory.js';
import { resolveNativeRecallAuthority } from '../../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../../services/retrieval/native-recall-pipeline.js';

const databaseName = new URL(resolveAimosDatabaseUrl()).pathname.slice(1);
const LIVE_FIRE = process.argv.includes('--live-fire');

test('signed derived save and recall actions produce linked memory and Merkle proofs', async (t) => {
  if (!LIVE_FIRE || !databaseName.startsWith('aimos_test_security_')) {
    t.skip('Native tool action live-fire requires an isolated aimos_test_security_* database.');
    return;
  }

  const cert = await getHousekeeperCert();
  const executionContext = Object.freeze({
    actorAgentId: 'housekeeper',
    actorValidFromIso: extractValidFromIso(cert),
    companyId: 'hom',
    identityTier: detectTierFromCert(cert),
    requestReceiptId: null,
    requestReceiptMutationHash: null,
  });
  const suffix = randomUUID();
  const key = `test:native-tool-action:${suffix}`;
  const content = `Cryptographically retained native tool action proof ${suffix} with sufficient semantic content for canonical persistence.`;

  const proposed = await beginToolAction({
    tool: 'aimos_save',
    args: { content },
    runtimeAgentId: 'housekeeper',
    executionContext,
  });
  const saveSpec = {
    company_id: 'hom',
    agent_id: 'housekeeper',
    key,
    value: content,
    scope: 'private',
    clearance_level: 1,
    memory_type: 'episodic',
    source: 'test:native-tool-action',
    session_id: null,
  };
  const commit = await beginToolAction({
    tool: 'aimos_save_commit',
    args: saveSpec,
    runtimeAgentId: 'housekeeper',
    executionContext,
    parentEventId: proposed.receipt.event_id,
  });
  const saved = await persistMemory({ ...saveSpec, mutation_authority: commit.authority });
  assert(saved?.id);
  assert.match(saved.live_content_hash.toString('hex'), /^[0-9a-f]{64}$/);
  assert.match(saved.ledger_commit.mutationHash.toString('hex'), /^[0-9a-f]{64}$/);
  assert.match(saved.binding_commit.mutationHash.toString('hex'), /^[0-9a-f]{64}$/);
  await finishToolAction({ action: commit, executionContext, succeeded: true, result: { memory_id: saved.id } });
  await finishToolAction({ action: proposed, executionContext, succeeded: true, result: { memory_id: saved.id } });

  const recallCommand = { key, limit: 5 };
  const recallAction = await beginToolAction({
    tool: 'aimos_recall',
    args: recallCommand,
    runtimeAgentId: 'housekeeper',
    executionContext,
  });
  const recallAuthority = await resolveNativeRecallAuthority({
    rawCommand: recallCommand,
    executionContext,
    requestAuthority: recallAction.authority,
    transportBinding: { transport: 'tool', toolName: 'aimos_recall' },
  });
  const recalled = await executeNativeRecall({ ip: 'isolated-test', headers: {}, originalUrl: 'tool:aimos_recall' }, recallAuthority);
  assert.equal(recalled.status, 200);
  assert(recalled.body.memories.some((memory) => memory.id === saved.id));
  assert.match(recalled.body.recall_receipt.merkle_root, /^[0-9a-f]{64}$/);
  assert.equal(recalled.body.recall_receipt.event_receipt.signed_body.metadata.derived_tool_action_event_id, recallAction.receipt.event_id);
  await finishToolAction({ action: recallAction, executionContext, succeeded: true, result: { count: recalled.body.count } });

  const stored = await pool.query(
    `SELECT (SELECT count(*)::int FROM aimos_memories WHERE id = $1) AS memories,
            (SELECT count(*)::int FROM aimos_memory_provenance WHERE memory_id = $1 AND event_type = 'SAVE') AS provenance,
            (SELECT count(*)::int FROM aimos_memory_provenance WHERE memory_id = $1 AND event_type = 'BIND') AS bindings`,
    [saved.id],
  );
  assert.equal(stored.rows[0].memories, 1);
  assert(stored.rows[0].provenance >= 1);
  assert(stored.rows[0].bindings >= 1);
});

test.after(async () => {
  await agentPool.end();
  await pool.end();
});
