import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const routePath = new URL('../../routes/aimos.js', import.meta.url);
const source = await readFile(routePath, 'utf8');

test('aimos routes never perform runtime schema DDL', () => {
  assert.doesNotMatch(source, /\bCREATE\s+TABLE\b/i);
  assert.doesNotMatch(source, /\bALTER\s+TABLE\b/i);
  assert.doesNotMatch(source, /\bCREATE\s+(?:UNIQUE\s+)?INDEX\b/i);
  assert.doesNotMatch(source, /function\s+ensureSourceColumn\b/);
  assert.doesNotMatch(source, /function\s+ensureSchema\b/);
});

test('live route schemas are verified read-only and fail closed', () => {
  for (const functionName of [
    'ensureMedallionColumn',
    'ensureAgentStateTable',
  ]) {
    assert.match(source, new RegExp(`async function ${functionName}\\(\\)`));
  }

  for (const relation of [
    'aimos_memories',
    'agent_state',
  ]) {
    assert.match(source, new RegExp(`to_regclass\\('public\\.${relation}'\\)`));
  }

  for (const index of [
    'idx_memories_medallion',
    'agent_state_pkey',
  ]) {
    assert.match(source, new RegExp(index));
  }

  assert.match(source, /FROM pg_attribute/);
  assert.match(source, /MIGRATION_SCHEMA_MISSING/);
  assert.match(source, /error\.statusCode = 503/);
  assert.doesNotMatch(source, /ensureAgentMessagesTable|public\.agent_messages|idx_agent_msg_/);
});
