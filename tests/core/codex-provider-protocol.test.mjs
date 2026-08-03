import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildCodexModelsRequestUrl,
  buildCodexResponsesPayload,
  normalizeCodexModelPayload,
  parseCodexSseResponse,
  resolveCodexAccountBinding,
  resolveCodexClientVersion,
} from '../../services/core/providers.js';

test('Codex OAuth account binding is one signed value and fails on torn legacy state', () => {
  assert.equal(resolveCodexAccountBinding({ account_id: 'acct_123' }), 'acct_123');
  assert.equal(resolveCodexAccountBinding({}, 'legacy-account'), 'legacy-account');
  assert.equal(
    resolveCodexAccountBinding({ account_id: 'same-account' }, 'same-account'),
    'same-account',
  );
  assert.throws(
    () => resolveCodexAccountBinding({ account_id: 'account-a' }, 'account-b'),
    /conflicts with the signed legacy account configuration/,
  );
  assert.throws(
    () => resolveCodexAccountBinding({ account_id: 'line\nbreak' }),
    /binding is malformed/,
  );
});

test('Codex catalog projection preserves only benchmark-relevant live capabilities', () => {
  const model = normalizeCodexModelPayload({
    slug: 'gpt-5.6-terra',
    display_name: 'GPT-5.6 Terra',
    context_window: 272000,
    supported_in_api: true,
    supported_reasoning_levels: [
      { effort: 'low', description: 'ignored' },
      { effort: 'medium', description: 'ignored' },
      { effort: 'high', description: 'ignored' },
      { effort: 'ultra', description: 'ignored' },
      { effort: 'invented', description: 'rejected' },
    ],
    base_instructions: 'must never leave the provider boundary',
  });

  assert.deepEqual(model, {
    providerId: 'codex',
    modelId: 'gpt-5.6-terra',
    displayLabel: 'GPT-5.6 Terra',
    available: true,
    hidden: false,
    reasoningEffortOptions: ['low', 'medium', 'high', 'ultra'],
    supportedInApi: true,
    contextWindow: 272000,
  });
  assert.equal('base_instructions' in model, false);
});

test('Codex catalog request binds the signed backend compatibility version', () => {
  assert.equal(resolveCodexClientVersion({ client_version: '0.144.0' }), '0.144.0');
  assert.equal(
    buildCodexModelsRequestUrl('https://chatgpt.com/backend-api/codex/models', '0.144.0'),
    'https://chatgpt.com/backend-api/codex/models?client_version=0.144.0',
  );
  assert.throws(
    () => resolveCodexClientVersion({ client_version: '0.144.0-alpha.4' }),
    /missing or malformed/,
  );
  assert.throws(
    () => buildCodexModelsRequestUrl(
      'https://chatgpt.com/backend-api/codex/models?client_version=0.143.0',
      '0.144.0',
    ),
    /already contains/,
  );
});

test('Codex Responses payload binds per-call effort and strict schema to the native wire contract', () => {
  const schema = {
    type: 'object',
    additionalProperties: false,
    required: ['verdict'],
    properties: { verdict: { type: 'string', enum: ['supported'] } },
  };
  const payload = buildCodexResponsesPayload({
    model: 'gpt-5.6-terra',
    instructions: 'Judge only the supplied evidence.',
    input: [{ role: 'user', content: [{ type: 'input_text', text: 'candidate' }] }],
    reasoningEffort: 'high',
    textVerbosity: 'low',
    responseSchema: { name: 'judge_preflight', schema },
  });

  assert.equal(payload.model, 'gpt-5.6-terra');
  assert.deepEqual(payload.reasoning, { effort: 'high' });
  assert.equal('max_output_tokens' in payload, false);
  assert.equal(payload.tool_choice, 'auto');
  assert.deepEqual(payload.include, ['reasoning.encrypted_content']);
  assert.deepEqual(payload.text, {
    verbosity: 'low',
    format: {
      type: 'json_schema',
      name: 'judge_preflight',
      schema,
      strict: true,
    },
  });
  assert.equal(payload.store, false);
  assert.equal(payload.stream, true);
});

test('Codex Responses payload rejects unsupported or unbounded benchmark controls', () => {
  const base = {
    model: 'gpt-5.4',
    instructions: '',
    input: [{ role: 'user', content: [{ type: 'input_text', text: 'x' }] }],
    reasoningEffort: 'medium',
    textVerbosity: 'low',
  };
  assert.throws(
    () => buildCodexResponsesPayload({ ...base, reasoningEffort: 'automatic' }),
    /Unsupported Codex reasoning effort/,
  );
  assert.throws(
    () => buildCodexResponsesPayload({ ...base, maxOutputTokens: 256 }),
    /does not support maxOutputTokens/,
  );
  assert.throws(
    () => buildCodexResponsesPayload({ ...base, responseSchema: { name: 'bad name', schema: {} } }),
    /schema name is malformed/,
  );
});

test('Codex SSE parser returns text plus sanitized response and usage evidence', () => {
  const tokens = [];
  const raw = [
    'data: {"type":"response.output_text.delta","delta":"{\\"verdict\\":"}',
    '',
    'data: {"type":"response.output_text.delta","delta":"\\"supported\\"}"}',
    '',
    'data: {"type":"response.completed","response":{"id":"resp_123","model":"gpt-5.6-terra","status":"completed","usage":{"input_tokens":41,"output_tokens":9,"total_tokens":50,"input_tokens_details":{"cached_tokens":11},"output_tokens_details":{"reasoning_tokens":4}}}}',
    '',
    'data: [DONE]',
    '',
  ].join('\n');

  const result = parseCodexSseResponse(raw, (token) => tokens.push(token));
  assert.equal(tokens.join(''), '{"verdict":"supported"}');
  assert.deepEqual(result, {
    text: '{"verdict":"supported"}',
    responseId: 'resp_123',
    model: 'gpt-5.6-terra',
    status: 'completed',
    usage: {
      inputTokens: 41,
      outputTokens: 9,
      totalTokens: 50,
      cachedInputTokens: 11,
      reasoningOutputTokens: 4,
    },
  });
});
