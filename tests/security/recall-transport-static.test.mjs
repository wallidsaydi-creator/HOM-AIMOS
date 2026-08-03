import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const root = new URL('../../', import.meta.url);
const read = (path) => fs.readFileSync(new URL(path, root), 'utf8');

test('REST and MCP recall transports converge on the native pipeline', () => {
  const rest = read('routes/aimos.js');
  const mcp = read('routes/aimos-mcp-streamable.js');
  const native = read('services/retrieval/native-recall.js');
  const pipeline = read('services/retrieval/native-recall-pipeline.js');

  assert.match(rest, /import \{ executeNativeRecall \} from '..\/services\/retrieval\/native-recall-pipeline\.js'/);
  assert.doesNotMatch(rest, /async function executeAimosRecall/);
  assert.match(rest, /router\.get\('\/recall',[\s\S]*signed_post_recall_required/);
  assert.match(rest, /router\.all\('\/recall\/demo',[\s\S]*demo_recall_moved_to_signed_post/);

  assert.match(mcp, /resolveNativeRecallAuthority/);
  assert.match(mcp, /executeNativeRecall\(authContext\.request, recallAuthority\)/);
  assert.match(mcp, /rpcId: transportBinding\?\.rpcId/);
  assert.match(mcp, /batchIndex: transportBinding\?\.batchIndex/);
  assert.doesNotMatch(mcp, /adaptiveRecall|vector_fallback/);

  const disclosureCases = mcp.slice(
    mcp.indexOf("case 'aimos_recall':"),
    mcp.indexOf("case 'aimos_save':"),
  );
  assert.doesNotMatch(disclosureCases, /FROM aimos_memories|executeQMD|WITH RECURSIVE chain/);
  assert.match(native, /toolName = transportBinding\.toolName \|\| 'aimos_recall'/);
  assert.doesNotMatch(pipeline, /UPDATE\s+aimos_memories/i);
});

test('MCP catalog exposes only native-admitted disclosure tools', () => {
  const catalog = read('services/orchestration/aimos-mcp-catalog.js');
  assert.doesNotMatch(catalog, /name: 'aimos_events_today'|name: 'aimos_qmd'|name: 'aimos_time_travel'/);
  assert.doesNotMatch(catalog, /Caller agent_id \(required/);
  assert.match(catalog, /name: 'aimos_recall'/);
  assert.match(catalog, /name: 'aimos_open_memory'/);
});

test('legacy MCP save retains the verified caller instead of elevating to housekeeper', () => {
  const rest = read('routes/aimos.js');
  const block = rest.slice(
    rest.indexOf("router.post('/mcp/tools/call'"),
    rest.indexOf('// ═══════════════════════════════════════════════════════════════════════════════\n// QMD'),
  );
  assert.match(block, /mutation_authority: requestAuthority/);
  assert.doesNotMatch(block, /mutation_authority: 'housekeeper'/);
  assert.match(block, /signed MCP save actor or company mismatch/);
});
