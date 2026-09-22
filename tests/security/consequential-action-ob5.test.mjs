import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  CONSEQUENTIAL_ACTION_TOOL_NAMES,
  buildActionOriginVerdictV1,
  buildConsequentialActionProjectionV1,
  consequentialActionPolicyForTool,
} from '../../services/security/protocol/consequential-action-v1.js';
import { generateKeypair, pubkeyFingerprint } from '../../services/security/agent-identity.js';
import {
  createOperatorActionAuthorizationProof,
  verifyOperatorActionAuthorizationProof,
} from '../../services/security/protocol/operator-action-authorization-v1.js';

const sampleArgs = Object.freeze({
  x_post: { text: 'Exact public statement.' },
  x_reply: { replyToTweetId: '123', text: 'Exact reply.' },
  x_quote: { quote_tweet_id: '456', text: 'Exact quotation.' },
  gmail_send: { to: 'recipient@example.com', subject: 'Exact subject', body: 'Exact body.' },
  gmail_reply: { messageId: 'gmail-message-1', body: 'Exact reply body.' },
  calendar_create: {
    summary: 'Exact meeting', description: 'Exact agenda',
    start: '2026-09-06T09:00:00.000Z', end: '2026-09-06T10:00:00.000Z',
  },
  imessage_send: { to: 'recipient@example.com', message: 'Exact message.' },
  imessage_request_access: { request_access: true },
  telegram_send: { chat_id: '123456', text: 'Exact Telegram message.', parse_mode: 'Markdown' },
  write_file: { filepath: '/tmp/exact.txt', content: 'Exact file content.' },
  schedule_task: {
    cron_expression: '0 9 * * 1', task_description: 'Run the exact task.',
    agent_id: 'codex-auditor', label: 'Exact schedule',
  },
  delegate_task: {
    agent_id: 'codex-auditor', task_prompt: 'Perform the exact delegated task.',
    wait: true, delegation_context: { case: 'exact' },
  },
});

function profile(name) {
  const operationClass = name === 'write_file' ? 'internal_write'
    : name === 'imessage_request_access' ? 'internal_write'
    : ['schedule_task', 'delegate_task'].includes(name) ? 'orchestration'
      : 'external_write';
  return {
    tool: name,
    operation_class: operationClass,
    argument_schema: {
      type: 'object',
      properties: Object.fromEntries(Object.keys(sampleArgs[name]).map((key) => [key, {}])),
    },
  };
}

test('OB-5 gates exactly the twelve registered consequential tools', () => {
  assert.deepEqual(CONSEQUENTIAL_ACTION_TOOL_NAMES, [
    'calendar_create', 'delegate_task', 'gmail_reply', 'gmail_send',
    'imessage_request_access', 'imessage_send', 'schedule_task', 'telegram_send',
    'write_file', 'x_post', 'x_quote', 'x_reply',
  ]);
  for (const name of CONSEQUENTIAL_ACTION_TOOL_NAMES) {
    assert(consequentialActionPolicyForTool(name));
  }
  assert.equal(consequentialActionPolicyForTool('aimos_save'), null);
  assert.equal(consequentialActionPolicyForTool('aimos_recall'), null);
});

test('OB-5 composite commitments bind every declared security field', () => {
  for (const name of CONSEQUENTIAL_ACTION_TOOL_NAMES) {
    const nativeProfile = profile(name);
    const base = buildConsequentialActionProjectionV1({
      tool: name, args: sampleArgs[name], profile: nativeProfile,
    });
    assert.match(base.value_sha256, /^[0-9a-f]{64}$/);
    for (const field of consequentialActionPolicyForTool(name).fields) {
      const changed = structuredClone(sampleArgs[name]);
      changed[field.name] = typeof changed[field.name] === 'boolean'
        ? !changed[field.name]
        : typeof changed[field.name] === 'object'
          ? { ...changed[field.name], changed: true }
          : `${changed[field.name] ?? ''}:changed`;
      const successor = buildConsequentialActionProjectionV1({
        tool: name, args: changed, profile: nativeProfile,
      });
      assert.notEqual(successor.value_sha256, base.value_sha256, `${name}.${field.name}`);
    }
  }
});

test('OB-5 projection rejects undeclared action arguments', () => {
  const nativeProfile = profile('gmail_send');
  assert.throws(() => buildConsequentialActionProjectionV1({
    tool: 'gmail_send',
    args: { ...sampleArgs.gmail_send, hidden_recipient: 'attacker@example.com' },
    profile: nativeProfile,
  }), /consequential_action_argument_not_in_schema/);
});

test('OB-5 action verdict is allow, deny, or indeterminate by exact predicate', () => {
  const projection = buildConsequentialActionProjectionV1({
    tool: 'x_post', args: sampleArgs.x_post, profile: profile('x_post'),
  });
  const common = {
    companyId: 'hom',
    actor: {
      agent_id: 'codex-auditor',
      valid_from: '2026-08-10T18:49:54.000Z',
      cert_fingerprint_sha256: '11'.repeat(32),
    },
    projection,
    inputOriginSha256: '22'.repeat(32),
    createdAt: '2026-09-05T06:00:00.000Z',
  };
  assert.equal(buildActionOriginVerdictV1({
    ...common, untrustedInfluence: false,
  }).decision, 'ALLOW');
  assert.deepEqual(buildActionOriginVerdictV1({
    ...common, untrustedInfluence: true,
  }).decision, 'DENY');
  assert.deepEqual(buildActionOriginVerdictV1({
    ...common, untrustedInfluence: true, attributionIndeterminate: true,
  }).decision, 'INDETERMINATE');
  assert.equal(buildActionOriginVerdictV1({
    ...common, untrustedInfluence: true, userAuthorizationSha256: '33'.repeat(32),
  }).decision, 'ALLOW');
});

test('OB-5 runtime requires trusted ACT input or exact elevation/user authority', () => {
  const ledger = fs.readFileSync(new URL('../../services/orchestration/tool-action-ledger.js', import.meta.url), 'utf8');
  assert.match(ledger, /inputClassification\.integrity !== 'trusted'/);
  assert.match(ledger, /inputClassification\.action_class !== 'act'/);
  assert.match(ledger, /\['file','record','event'\]\.includes\(i\.kind\)/);
  const registry = fs.readFileSync(new URL('../../services/orchestration/tool-registry.js', import.meta.url), 'utf8');
  assert.match(registry, /knowledgeGateBlock\.blocked && !options\.approvalEvidence/);
  assert.match(registry, /approvalRequired = Boolean\(nativeProfile\.profile\.action_authority\)/);
  assert.doesNotMatch(registry, /approvalRequiredForAutonomy|autonomous\s*&&\s*Boolean\(nativeProfile\.profile\.action_authority\)/);
  assert.ok(registry.lastIndexOf('claimToolApprovalExecution({')
    < registry.lastIndexOf('signedToolAction = await beginToolAction({'));
});

test('OB-5 native side-effect owners independently verify the exact allowed verdict', () => {
  const required = new Map([
    ['services/integrations/x-tools.js', ['x_post', 'x_reply', 'x_quote']],
    ['services/integrations/google-tools.js', ['gmail_send', 'gmail_reply', 'calendar_create']],
    ['services/integrations/telegram-tools.js', ['telegram_send']],
    ['services/integrations/integration-tools.js', ['imessage_request_access', 'imessage_send']],
    ['services/orchestration/scheduler.js', ['schedule_task']],
    ['services/orchestration/tool-registry.js', ['write_file', 'delegate_task']],
  ]);
  for (const [file, tools] of required) {
    const source = fs.readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8');
    assert.match(source, /verifyToolActionAuthority\(/, file);
    for (const tool of tools) assert.match(source, new RegExp(`expectedTool:\\s*['\"]${tool}['\"]`), `${file}:${tool}`);
  }
});

test('OB-5 dispatcher supplies the actor and exact authority options to the native file owner', () => {
  const registry = fs.readFileSync(new URL('../../services/orchestration/tool-registry.js', import.meta.url), 'utf8');
  assert.match(registry, /name === 'aimos_save' \|\| name === 'delegate_task' \|\| name === 'write_file'/);
  assert.match(registry, /return tool\.fn\(args, agentId, invocationOptions\)/);
});

test('OB-5 direct HTTP write surfaces converge on executeTool and preserve denial', () => {
  for (const file of ['routes/tools.js', 'routes/integrations.js']) {
    const source = fs.readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8');
    assert.match(source, /executeTool\(/, file);
    assert.match(source, /result\?\.blocked|payload\?\.blocked|event\?\.blocked/, file);
  }
  const toolsRoute = fs.readFileSync(new URL('../../routes/tools.js', import.meta.url), 'utf8');
  const integrationsRoute = fs.readFileSync(new URL('../../routes/integrations.js', import.meta.url), 'utf8');
  for (const forbidden of [
    'xPostTweet(', 'xReplyToTweet(', 'xQuoteTweet(', 'gmailSendMessage(',
    'gmailReplyMessage(', 'calendarCreateEvent(', 'telegramSendMessage(',
  ]) assert.equal(toolsRoute.includes(forbidden), false, forbidden);
  for (const forbidden of ['telegramSendMessage(', 'imessageSend(', 'imessageRequestAccess(']) {
    assert.equal(integrationsRoute.includes(forbidden), false, forbidden);
  }
});

test('OB-5 database writer binds exact input, single-use authority, independence, and no-fork head', () => {
  const source = fs.readFileSync(new URL('../../migrations/106-consequential-action-verdict-binding.sql', import.meta.url), 'utf8');
  for (const predicate of [
    'origin_verdict_input_binding_invalid',
    'origin_verdict_security_values_invalid',
    'origin_verdict_elevation_invalid',
    'origin_verdict_corroborator_license_invalid',
    'origin_verdict_authorization_invalid',
    'origin_verdict_predecessor_invalid',
    'prior.elevation_sha256=v_elevation',
    'prior.user_authorization_sha256=v_user_auth',
  ]) assert.match(source, new RegExp(predicate.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('OB-5 selects corroboration elevation inside the restricted action transaction', () => {
  const source = fs.readFileSync(new URL('../../services/orchestration/tool-action-ledger.js', import.meta.url), 'utf8');
  const selector = fs.readFileSync(new URL('../../migrations/114-origin-elevation-exact-selector.sql', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /originElevationSha256/);
  assert(source.includes('public.select_origin_elevation_v2_for_action('));
  for (const predicate of [
    'elevation.value_sha256=p_value_sha256',
    'elevation.family_id=p_family_id',
    'elevation.action_scope=p_action_scope',
    'elevation.risk_class=p_risk_class',
    'elevation.base_origin_sha256s=p_base_origin_sha256s',
    'elevation.valid_from<=clock_timestamp()',
    'elevation.valid_until>clock_timestamp()',
    'FOR UPDATE OF elevation SKIP LOCKED',
  ]) assert(selector.includes(predicate), predicate);
});

test('OB-5 elevation writer verifies licensed three-axis independence before append', () => {
  const source = fs.readFileSync(new URL('../../migrations/107-origin-elevation-license-binding.sql', import.meta.url), 'utf8');
  for (const predicate of [
    "count(DISTINCT entry->>'principal_id')",
    "count(DISTINCT entry->>'administrative_domain_sha256')",
    "count(DISTINCT entry->>'upstream_source_sha256')",
    "operation='origin_corroboration_licensed'",
    "v_license.metadata->>'value_sha256'",
    "v_license.metadata->'base_origin_sha256s'",
    "prior_entry->>'license_sha256'",
    'origin_elevation_corroborator_license_invalid',
  ]) assert(source.includes(predicate), predicate);
});

test('OB-5 operator proof is master-signed, exact, bounded to five minutes, and substitution-resistant', () => {
  const { pubkey, privkey } = generateKeypair();
  const input = {
    company_id: 'hom', subject_agent_id: 'codex-auditor',
    subject_valid_from: '2026-08-10T18:49:54.000Z',
    subject_cert_fingerprint_sha256: '11'.repeat(32),
    approval_request_id: '10000000-0000-4000-8000-000000000001',
    approval_request_mutation_sha256: '22'.repeat(32),
    tool_name: 'write_file', action_scope: 'tool:write_file', risk_class: 'high_impact',
    arguments_sha256: '33'.repeat(32), security_value_sha256: '44'.repeat(32),
    master_fingerprint: pubkeyFingerprint(pubkey),
  };
  const proof = createOperatorActionAuthorizationProof(privkey, input, {
    proofId: '20000000-0000-4000-8000-000000000001',
    nonce: 'ob5-fixed-nonce', tsSigned: 1788591600,
    createdAt: '2026-09-05T07:00:00.000Z', validUntil: '2026-09-05T07:05:00.000Z',
  });
  assert.equal(verifyOperatorActionAuthorizationProof(
    proof, pubkey, input, Date.parse('2026-09-05T07:02:00.000Z'),
  ).valid, true);
  const tampered = structuredClone(proof);
  tampered.body.arguments_sha256 = '55'.repeat(32);
  assert.equal(verifyOperatorActionAuthorizationProof(
    tampered, pubkey, input, Date.parse('2026-09-05T07:02:00.000Z'),
  ).valid, false);
});

test('OB-5 approval route requires exact master proof without ambient admin capability', () => {
  const route = fs.readFileSync(new URL('../../routes/tools.js', import.meta.url), 'utf8');
  assert.match(route, /import \{\s*createToolApprovalRequest,/);
  assert.match(route, /router\.post\('\/approvals\/request', async/);
  assert.match(route, /createToolApprovalRequest\(\{/);
  assert.match(route, /parentEventId: req\.executionContext\?\.requestAdmissionEventId \|\| null/);
  const requestSurface = route.slice(
    route.indexOf("router.post('/approvals/request'"),
    route.indexOf("router.post('/approvals/:id/approve'"),
  );
  assert.doesNotMatch(requestSurface, /executeTool\(|markToolApprovalApproved|reserveToolApprovalExecution/);
  assert.match(route, /router\.post\('\/approvals\/:id\/approve', async/);
  assert.doesNotMatch(route, /router\.post\('\/approvals\/:id\/approve', requireCapability\('admin_override'\)/);
  assert.match(route, /verifyOperatorActionAuthorizationProof\(operatorProof, masterPubkey/);
  assert.match(route, /req\.executionContext\?\.actorAgentId !== approval\.agentId/);
  const migration = fs.readFileSync(new URL('../../migrations/108-operator-action-authorization-verifier.sql', import.meta.url), 'utf8');
  for (const predicate of [
    'pgsodium.crypto_sign_verify_detached',
    "v_requested.operation <> 'tool_approval_requested'",
    "v_claim.operation <> 'tool_approval_execution_claimed'",
    "v_body->>'security_value_sha256'",
    "v_body->>'approval_request_mutation_sha256'",
    "prior.user_authorization_sha256=NEW.user_authorization_sha256",
  ]) assert(migration.includes(predicate), predicate);
});
