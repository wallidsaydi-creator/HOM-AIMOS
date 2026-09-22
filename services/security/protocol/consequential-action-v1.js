// ─── CONSEQUENTIAL ACTION PROTOCOL AND POLICY ────────────────────────────────
// ← Called by: orchestration/tool-action-ledger.js before a consequential start
// → Produces: one exact typed security-value projection and frozen OB-1 verdict
// Pipeline: AGENT_RUN_PIPELINE | Position: retrieval-to-action authority gate
// Sources: Louck TMA-NM M2/M3/M4 and Algorithm 1 (arXiv:2606.24322);
//          Cecchetti–Myers–Arden NMIFC transparent endorsement (arXiv:1708.08596)
// Adaptation: one composite value binds every security-relevant field so a
// license cannot authorize a recipient while leaving content/path/time mutable.
// This owner grants no tool permission and performs no tool/provider dispatch.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, randomUUID } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';
import {
  ORIGIN_BINDING_SCHEMAS_V1,
  createActionOriginVerdictV1,
  originFamilyClosureV1,
} from './origin-binding-v1.js';

export const CONSEQUENTIAL_ACTION_PROJECTION_SCHEMA_V1 =
  'hom.aimos.consequential-action-projection/v1';
export const CONSEQUENTIAL_ACTION_INPUT_SCHEMA_V1 =
  'hom.aimos.consequential-action-input/v1';
export const CONSEQUENTIAL_ACTION_AUTHORIZATION_SCHEMA_V1 =
  'hom.aimos.consequential-action-authorization/v1';

const VALUE_DOMAIN = Buffer.from(`${CONSEQUENTIAL_ACTION_PROJECTION_SCHEMA_V1}\0`, 'utf8');
const HASH = /^[0-9a-f]{64}$/;
const FIELD = /^[a-z][A-Za-z0-9_]{0,63}$/;

function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('consequential_action_length_invalid');
  }
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function hashCanonical(domain, value) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  return createHash('sha256').update(Buffer.concat([domain, u32(bytes.length), bytes])).digest('hex');
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const policy = (riskClass, fields) => deepFreeze({
  schema: CONSEQUENTIAL_ACTION_PROJECTION_SCHEMA_V1,
  version: 1,
  action_scope: null,
  risk_class: riskClass,
  value_rule: 'one_composite_of_all_security_relevant_fields',
  attribution_rule: 'complete_runtime_input_set_conservative',
  fields,
});

// These declarations extend the existing registered tool schemas; they do not
// create tools or alternate dispatch. Optional fields are represented as null,
// so adding/removing one after authorization changes the composite commitment.
const POLICIES = deepFreeze({
  x_post: policy('consequential', [
    { name: 'text', family_id: 'action_input.executable_instruction' },
  ]),
  x_reply: policy('consequential', [
    { name: 'replyToTweetId', family_id: 'action_input.external_destination' },
    { name: 'text', family_id: 'action_input.executable_instruction' },
  ]),
  x_quote: policy('consequential', [
    { name: 'quote_tweet_id', family_id: 'action_input.external_destination' },
    { name: 'text', family_id: 'action_input.executable_instruction' },
  ]),
  gmail_send: policy('consequential', [
    { name: 'body', family_id: 'action_input.executable_instruction' },
    { name: 'subject', family_id: 'information.fact' },
    { name: 'to', family_id: 'action_input.external_destination' },
  ]),
  gmail_reply: policy('consequential', [
    { name: 'body', family_id: 'action_input.executable_instruction' },
    { name: 'messageId', family_id: 'action_input.external_destination' },
  ]),
  calendar_create: policy('consequential', [
    { name: 'description', family_id: 'information.fact' },
    { name: 'end', family_id: 'action_input.resource_target' },
    { name: 'start', family_id: 'action_input.resource_target' },
    { name: 'summary', family_id: 'information.fact' },
  ]),
  imessage_send: policy('consequential', [
    { name: 'message', family_id: 'action_input.executable_instruction' },
    { name: 'to', family_id: 'action_input.external_destination' },
  ]),
  imessage_request_access: policy('high_impact', [
    { name: 'request_access', family_id: 'system_control.authorization_directive' },
  ]),
  telegram_send: policy('consequential', [
    { name: 'chat_id', family_id: 'action_input.external_destination' },
    { name: 'parse_mode', family_id: 'information.preference' },
    { name: 'text', family_id: 'action_input.executable_instruction' },
  ]),
  write_file: policy('high_impact', [
    { name: 'content', family_id: 'information.fact' },
    { name: 'filepath', family_id: 'action_input.resource_target' },
  ]),
  schedule_task: policy('high_impact', [
    { name: 'agent_id', family_id: 'identity.principal_assertion' },
    { name: 'cron_expression', family_id: 'action_input.executable_instruction' },
    { name: 'label', family_id: 'information.fact' },
    { name: 'task_description', family_id: 'action_input.executable_instruction' },
  ]),
  delegate_task: policy('consequential', [
    { name: 'agent_id', family_id: 'identity.principal_assertion' },
    { name: 'delegation_context', family_id: 'action_input' },
    { name: 'task_prompt', family_id: 'action_input.executable_instruction' },
    { name: 'wait', family_id: 'action_input.resource_target' },
  ]),
});

export function consequentialActionPolicyForTool(toolName) {
  const name = String(toolName || '');
  const value = POLICIES[name];
  if (!value) return null;
  return deepFreeze({ ...value, action_scope: `tool:${name}` });
}

export function buildConsequentialActionProjectionV1({ tool, args, profile } = {}) {
  const name = String(tool || '');
  const declared = consequentialActionPolicyForTool(name);
  if (!declared || profile?.tool !== name
      || !['external_write', 'internal_write', 'orchestration'].includes(profile.operation_class)) {
    throw new Error('consequential_action_policy_required');
  }
  const exactArgs = JSON.parse(canonicalJson(args || {}));
  const schemaFields = new Set(Object.keys(profile.argument_schema?.properties || {}));
  const supplied = Object.keys(exactArgs);
  if (supplied.some((field) => !schemaFields.has(field))) {
    throw new Error('consequential_action_argument_not_in_schema');
  }
  const fields = declared.fields.map(({ name: fieldName, family_id: familyId }) => {
    if (!FIELD.test(fieldName) || !schemaFields.has(fieldName)) {
      throw new Error('consequential_action_field_schema_invalid');
    }
    const value = Object.hasOwn(exactArgs, fieldName) ? exactArgs[fieldName] : null;
    const body = { field: fieldName, family_id: familyId, value };
    return deepFreeze({
      field: fieldName,
      family_id: familyId,
      value_sha256: hashCanonical(
        Buffer.from(`${CONSEQUENTIAL_ACTION_PROJECTION_SCHEMA_V1}/field\0`, 'utf8'),
        body,
      ),
    });
  });
  const familyIds = originFamilyClosureV1([...new Set(fields.map((entry) => entry.family_id))]);
  const primaryFamilyId = fields.find((entry) => entry.family_id.startsWith('action_input.'))
    ?.family_id || fields[0].family_id;
  const argumentsSha256 = createHash('sha256')
    .update(canonicalJson(exactArgs), 'utf8').digest('hex');
  const body = deepFreeze({
    schema: CONSEQUENTIAL_ACTION_PROJECTION_SCHEMA_V1,
    tool: name,
    action_scope: declared.action_scope,
    risk_class: declared.risk_class,
    arguments_sha256: argumentsSha256,
    primary_family_id: primaryFamilyId,
    fields,
    family_ids: familyIds,
  });
  return deepFreeze({
    ...body,
    value_sha256: hashCanonical(VALUE_DOMAIN, body),
  });
}

export function buildActionOriginVerdictV1({
  companyId,
  actor,
  projection,
  inputOriginSha256,
  untrustedInfluence,
  attributionIndeterminate = false,
  elevationSha256 = null,
  userAuthorizationSha256 = null,
  previousVerdictSha256 = null,
  createdAt,
} = {}) {
  if (!HASH.test(String(inputOriginSha256 || ''))
      || !HASH.test(String(projection?.value_sha256 || ''))
      || typeof untrustedInfluence !== 'boolean') {
    throw new Error('consequential_action_verdict_input_invalid');
  }
  const authorized = HASH.test(String(elevationSha256 || ''))
    || HASH.test(String(userAuthorizationSha256 || ''));
  const decision = !untrustedInfluence || authorized
    ? 'ALLOW'
    : attributionIndeterminate ? 'INDETERMINATE' : 'DENY';
  const failureCode = decision === 'ALLOW' ? null
    : attributionIndeterminate ? 'input_attribution_indeterminate'
      : 'untrusted_influence_unlicensed';
  return createActionOriginVerdictV1({
    schema: ORIGIN_BINDING_SCHEMAS_V1.action_verdict,
    company_id: companyId,
    verdict_id: randomUUID(),
    actor,
    tool_name: projection.tool,
    action_scope: projection.action_scope,
    risk_class: projection.risk_class,
    arguments_sha256: projection.arguments_sha256,
    security_values: [{
      value_sha256: projection.value_sha256,
      family_ids: projection.family_ids,
    }],
    family_ids: projection.family_ids,
    input_origin_sha256s: [inputOriginSha256],
    untrusted_influence: untrustedInfluence,
    elevation_sha256: elevationSha256,
    user_authorization_sha256: userAuthorizationSha256,
    decision,
    failure_code: failureCode,
    previous_verdict_sha256: previousVerdictSha256,
    created_at: new Date(createdAt).toISOString(),
  });
}

export const CONSEQUENTIAL_ACTION_TOOL_NAMES = Object.freeze(Object.keys(POLICIES).sort());
