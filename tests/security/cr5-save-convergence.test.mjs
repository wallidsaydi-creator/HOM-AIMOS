import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RUNTIME_ROOTS = ['routes', 'services', 'jobs', 'middleware'];
const VERIFIED_CALLS = new Map([
  ['routes/agent-execution.js', 1],
  ['routes/aimos-mcp-streamable.js', 1],
  ['routes/aimos.js', 5],
  ['routes/security.js', 1],
  ['routes/task.js', 1],
  ['services/orchestration/tool-registry.js', 1],
  ['services/retrieval/asmr-pipeline.js', 1],
]);

function source(relative) {
  return readFileSync(path.join(ROOT, relative), 'utf8');
}

function walk(relative) {
  const absolute = path.join(ROOT, relative);
  if (!statSync(absolute).isDirectory()) return [relative];
  return readdirSync(absolute, { withFileTypes: true })
    .flatMap((entry) => walk(path.join(relative, entry.name)));
}

function callWindows(text, callee) {
  const lines = text.split('\n');
  const starts = lines.flatMap((line, index) => line.includes(`${callee}({`) ? [index] : []);
  return starts.map((start, index) => {
    const next = starts[index + 1] ?? lines.length;
    return lines.slice(start, Math.min(next, start + 80)).join('\n');
  });
}

test('CR5 production has no bare Housekeeper SAVE assertion or route-owned autonomous signer', () => {
  const files = RUNTIME_ROOTS.flatMap(walk).filter((file) => file.endsWith('.js')).sort();
  for (const file of files) {
    const text = source(file);
    assert.doesNotMatch(text, /mutation_authority:\s*['"]housekeeper['"]/, file);
    assert.doesNotMatch(text, /mutationAuthority:\s*['"]housekeeper['"]/, file);
    if (file.startsWith('routes/')) {
      assert.doesNotMatch(text, /executeHousekeeperCanonicalSave/, `${file} imported autonomous SAVE authority`);
    }
  }
});

test('every verified SAVE caller supplies exact request or tool authority', () => {
  let total = 0;
  for (const [file, expected] of VERIFIED_CALLS) {
    const calls = callWindows(source(file), 'executeCanonicalSave');
    assert.equal(calls.length, expected, `${file} verified SAVE call count drifted`);
    for (const call of calls) assert.match(call, /mutation_authority\s*:/, file);
    total += calls.length;
  }
  assert.equal(total, 11);
});

test('all autonomous writes use one typed owner and retain the memory subject', () => {
  const files = ['jobs', 'services'].flatMap(walk).filter((file) => file.endsWith('.js'));
  const calls = files.flatMap((file) => callWindows(source(file), 'executeHousekeeperCanonicalSave')
    .map((call) => ({ file, call })));
  assert.equal(calls.length, 48);
  for (const { file, call } of calls) {
    assert.doesNotMatch(call, /mutation_authority\s*:/, file);
    assert.match(call, /\bagent_id\s*(?::|[,}])/, `${file} must state the memory subject`);
    assert.match(call, /source\s*:/, `${file} must state the action source`);
  }
});

test('session composition selects one authority and never falls back to low-level persistence', () => {
  const session = source('services/orchestration/session-memory-owner.js');
  const runner = source('services/orchestration/session-runner.js');
  const route = source('routes/aimos.js');
  assert.match(session, /requestAuthority && autonomousHousekeeper/);
  assert.match(session, /session_authority_ambiguous/);
  assert.match(session, /session_save_authority_required/);
  assert.doesNotMatch(session, /deps\.persistMemory|mutation_authority:\s*['"]housekeeper['"]/);
  assert.match(runner, /autonomousHousekeeper: options\.autonomousHousekeeper === true/);
  const turnRoute = route.slice(route.indexOf("router.post('/session/turn'"), route.indexOf("router.post('/session/finalize'"));
  const finalizeRoute = route.slice(route.indexOf("router.post('/session/finalize'"), route.indexOf("router.post('/compaction/save'"));
  assert.match(turnRoute, /requestAuthority: context\.requestAuthority/);
  assert.match(finalizeRoute, /requestAuthority: context\.requestAuthority/);
  assert.doesNotMatch(`${turnRoute}\n${finalizeRoute}`, /housekeeper.*authority|mutationAuthority:\s*['"]housekeeper['"]/i);
});

test('public heartbeat is Housekeeper-only and delegates to the scheduler-owned heartbeat service', () => {
  const route = source('routes/aimos.js');
  const block = route.slice(route.indexOf("router.post('/heartbeat'"), route.indexOf('// Aladdin retention', route.indexOf("router.post('/heartbeat'")));
  assert.match(block, /identity\.agentId !== 'housekeeper'/);
  assert.match(block, /T1_SYSTEM_SELF/);
  assert.match(block, /runHeartbeat\(AIMOS_COMPANY_ID\)/);
  assert.doesNotMatch(block, /executeCanonicalSave|corrections|new_value|mutation_authority/);
});

test('red-team report delegates Canary once while canonical SE remains disabled', () => {
  const route = source('routes/security.js');
  const block = route.slice(route.indexOf("router.post('/report'"));
  assert.match(block, /executeCanonicalSave/);
  assert.doesNotMatch(block, /evaluateCanaryWrite|evaluateSecurityContent|appendSecurityDecision|security_disposition/);
  assert.match(block, /mutation_authority: requestAuthority/);
  const owner = source('services/write/canonical-save-owner.js');
  assert.match(owner, /appendCanonicalSaveStage\(trace, 'SE', 'DISABLED'/);
  assert.doesNotMatch(owner, /evaluateSecurityContent|appendSecurityDecision/);
});

test('typed Housekeeper authority is action-bound and verified in the restricted transaction', () => {
  const owner = source('services/write/canonical-save-owner.js');
  const persistence = source('services/write/persist-memory.js');
  assert.match(owner, /HOUSEKEEPER_AUTHORITY_BRAND = Symbol/);
  assert.match(owner, /hom\.aimos\.canonical-save-action-start\/v2/);
  assert.match(owner, /action_context_sha256/);
  assert.match(owner, /canonical_save_housekeeper_action_commitment_mismatch/);
  assert.match(persistence, /readVerifiedEventById\(authority\.actionEventId/);
  assert.match(persistence, /housekeeper_action_binding_invalid/);
  assert.match(persistence, /housekeeper_action_mutation_hash/);
});
