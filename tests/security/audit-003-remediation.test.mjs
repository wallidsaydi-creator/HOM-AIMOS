import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import router from '../../routes/task.js';
import { tasks } from '../../services/orchestration/agent-store.js';

const OWNER = Object.freeze({ id: 'audit-003-owner', epoch: '2026-09-05T00:00:00.000Z' });
const OTHER = Object.freeze({ id: 'audit-003-other', epoch: '2026-09-05T00:00:01.000Z' });

function ownedRecord({ id, owner = OWNER, createdAt, task, result }) {
  return {
    id,
    agentId: owner.id,
    task,
    source: 'audit-003',
    priority: 1,
    model: 'none',
    status: 'completed',
    result,
    error: null,
    createdAt,
    ownership: Object.freeze({
      scopeMarker: 'company:hom',
      companyId: 'hom',
      initiatingActorId: owner.id,
      initiatingActorValidFromIso: owner.epoch,
    }),
  };
}

async function getJson(base, path, actor) {
  const response = await fetch(`${base}${path}`, {
    headers: { 'x-audit-actor': actor.id, 'x-audit-epoch': actor.epoch },
  });
  return { status: response.status, body: await response.json() };
}

test('AUD-003 filters task ownership before limits and never lists prompt/result bytes', async (t) => {
  tasks.clear();
  t.after(() => tasks.clear());
  tasks.set('owner-old', ownedRecord({
    id: 'owner-old', createdAt: '2026-09-05T00:00:00.000Z',
    task: 'owner private prompt', result: 'owner private result',
  }));
  tasks.set('foreign-new', ownedRecord({
    id: 'foreign-new', owner: OTHER, createdAt: '2026-09-05T00:01:00.000Z',
    task: 'foreign private prompt', result: 'foreign private result',
  }));
  tasks.set('ambiguous-legacy', {
    id: 'ambiguous-legacy', agentId: OWNER.id, task: 'unowned legacy prompt',
    result: 'unowned legacy result', status: 'completed',
    createdAt: '2026-09-05T00:02:00.000Z',
  });

  const app = express();
  app.use((req, _res, next) => {
    const actorAgentId = String(req.headers['x-audit-actor'] || '');
    const actorValidFromIso = String(req.headers['x-audit-epoch'] || '');
    req.agentId = actorAgentId;
    req.executionContext = Object.freeze({
      actorAgentId,
      actorValidFromIso,
      companyId: 'hom',
      identityTier: 'T1',
      authSource: 'envelope',
    });
    next();
  });
  app.use('/task', router);
  app.use('/tasks', router);
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  });

  for (const alias of ['/task', '/tasks']) {
    const ownerList = await getJson(base, `${alias}?limit=1`, OWNER);
    assert.equal(ownerList.status, 200);
    assert.deepEqual(ownerList.body.map((row) => row.id), ['owner-old']);
    assert.equal(Object.hasOwn(ownerList.body[0], 'task'), false);
    assert.equal(Object.hasOwn(ownerList.body[0], 'result'), false);

    const foreignList = await getJson(base, `${alias}?limit=50`, OTHER);
    assert.deepEqual(foreignList.body.map((row) => row.id), ['foreign-new']);

    const ownerDetail = await getJson(base, `${alias}/owner-old`, OWNER);
    assert.equal(ownerDetail.status, 200);
    assert.equal(ownerDetail.body.task, 'owner private prompt');
    assert.equal(ownerDetail.body.result, 'owner private result');

    const foreignDetail = await getJson(base, `${alias}/owner-old`, OTHER);
    assert.equal(foreignDetail.status, 404);

    const ambiguousDetail = await getJson(base, `${alias}/ambiguous-legacy`, OWNER);
    assert.equal(ambiguousDetail.status, 404);
  }
});
