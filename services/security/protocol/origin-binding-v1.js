// HOM-AIMOS Phase 1 origin-binding protocol authority.
//
// Status: OB-1 protocol only. This module owns exact schemas, classification
// families, canonical bytes, commitments, and authority-free predicates. It
// has no database, signer, network, model, route, SAVE, RECALL, or runtime
// activation authority. OB-2 and later work items must consume this protocol
// natively before any production claim is made.
//
// Sources:
// - Cecchetti, Myers, Arden, Nonmalleable Information Flow Control (CCS 2017)
// - Louck, Non-Malleable, Origin-Bound Authority (arXiv:2606.24322)
// - Biba integrity and Denning lattice information-flow foundations

import { createHash } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';

export const ORIGIN_BINDING_SCHEMAS_V1 = Object.freeze({
  family_profile: 'hom.aimos.origin-family-profile/v1',
  memory_binding: 'hom.aimos.memory-origin-binding/v1',
  elevation: 'hom.aimos.origin-elevation/v1',
  action_verdict: 'hom.aimos.action-origin-verdict/v1',
});

const domain = (schema) => Buffer.from(`${schema}\0`, 'utf8');

export const ORIGIN_BINDING_DOMAINS_V1 = Object.freeze({
  family_profile: domain(ORIGIN_BINDING_SCHEMAS_V1.family_profile),
  memory_binding: domain(ORIGIN_BINDING_SCHEMAS_V1.memory_binding),
  elevation: domain(ORIGIN_BINDING_SCHEMAS_V1.elevation),
  action_verdict: domain(ORIGIN_BINDING_SCHEMAS_V1.action_verdict),
});

export const ORIGIN_BINDING_LIMITS_V1 = Object.freeze({
  maximum_body_bytes: 1024 * 1024,
  maximum_family_count: 64,
  maximum_parent_count: 64,
  maximum_corroborator_count: 16,
  maximum_identifier_bytes: 200,
});

export const ORIGIN_INTEGRITY_ORDER_V1 = Object.freeze([
  'untrusted',
  'agent',
  'trusted',
]);

export const ORIGIN_CONFIDENTIALITY_ORDER_V1 = Object.freeze([
  'public',
  'internal',
  'confidential',
  'restricted',
]);

export const ORIGIN_ACTION_CLASS_ORDER_V1 = Object.freeze([
  'none',
  'inform',
  'act',
]);

export const ORIGIN_RISK_CLASSES_V1 = Object.freeze([
  'non_consequential',
  'consequential',
  'high_impact',
]);

export const ORIGIN_INGRESS_CHANNELS_V1 = Object.freeze([
  'untrusted_external',
  'agent_self',
  'authenticated_agent',
  'housekeeper_system',
  'authenticated_tool',
  'authenticated_user',
  'system_internal',
]);

export const ORIGIN_CLASSIFICATION_AUTHORITIES_V1 = Object.freeze([
  'deterministic_route_schema',
  'deterministic_field_schema',
  'authenticated_tool_schema',
  'system_producer_schema',
  'trusted_monitor_classifier',
  'legacy_successor_review',
]);

export const ORIGIN_FAMILY_ACTION_POLICIES_V1 = Object.freeze([
  'inform_only',
  'exact_origin_verdict',
  'exact_user_or_provider',
  'exact_configuration_owner',
  'inherit_parents',
  'deny_action',
]);

export const ORIGIN_ACTION_DECISIONS_V1 = Object.freeze([
  'ALLOW',
  'DENY',
  'INDETERMINATE',
]);

export const ORIGIN_ACTION_FAILURE_CODES_V1 = Object.freeze([
  'origin_missing',
  'origin_invalid',
  'family_missing',
  'family_policy_unsatisfied',
  'input_attribution_indeterminate',
  'untrusted_influence_unlicensed',
  'corroboration_insufficient',
  'corroboration_not_independent',
  'user_authorization_missing',
  'user_authorization_invalid',
  'user_authorization_replayed',
  'action_substitution',
  'scope_invalid',
  'identity_epoch_invalid',
  'evidence_expired_or_revoked',
]);

export const ORIGIN_PROTOCOL_FAILURE_CODES_V1 = Object.freeze([
  'body_invalid',
  'body_size_invalid',
  'body_number_invalid',
  'body_depth_invalid',
  'schema_invalid',
  'shape_invalid',
  'identifier_invalid',
  'uuid_invalid',
  'sha256_invalid',
  'timestamp_invalid',
  'timestamp_order_invalid',
  'integer_invalid',
  'enum_invalid',
  'family_profile_invalid',
  'family_profile_hash_invalid',
  'family_id_invalid',
  'family_parent_invalid',
  'family_cycle',
  'family_order_invalid',
  'family_duplicate',
  'family_count_invalid',
  'family_closure_invalid',
  'family_confidentiality_floor_invalid',
  'classification_authority_invalid',
  'parent_order_invalid',
  'parent_duplicate',
  'parent_count_invalid',
  'parent_binding_invalid',
  'confidentiality_downgrade',
  'integrity_elevation',
  'action_class_elevation',
  'channel_integrity_invalid',
  'integrity_action_class_invalid',
  'corroborator_shape_invalid',
  'corroborator_order_invalid',
  'corroborator_duplicate',
  'corroborator_count_invalid',
  'corroborator_independence_invalid',
  'elevation_authority_invalid',
  'security_value_shape_invalid',
  'security_value_order_invalid',
  'security_value_duplicate',
  'security_value_family_binding_invalid',
  'verdict_semantics_invalid',
  'failure_code_invalid',
]);

const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDENTIFIER = /^[a-z0-9](?:[a-z0-9._:-]{0,198}[a-z0-9])?$/;
const FAMILY_ID = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$/;

const INTEGRITY_RANK = new Map(ORIGIN_INTEGRITY_ORDER_V1.map((value, rank) => [value, rank]));
const CONFIDENTIALITY_RANK = new Map(
  ORIGIN_CONFIDENTIALITY_ORDER_V1.map((value, rank) => [value, rank]),
);
const ACTION_RANK = new Map(ORIGIN_ACTION_CLASS_ORDER_V1.map((value, rank) => [value, rank]));

const CHANNEL_INTEGRITY_CEILING = Object.freeze({
  untrusted_external: 'untrusted',
  agent_self: 'agent',
  authenticated_agent: 'agent',
  housekeeper_system: 'agent',
  authenticated_tool: 'trusted',
  authenticated_user: 'trusted',
  system_internal: 'trusted',
});

const INTEGRITY_ACTION_CEILING = Object.freeze({
  untrusted: 'none',
  agent: 'inform',
  trusted: 'act',
});

function fail(code) {
  throw new Error(`origin_binding_v1:${code}`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail('integer_invalid');
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) {
    fail('shape_invalid');
  }
}

function validateNumbers(value, depth = 0) {
  if (depth > 32) fail('body_depth_invalid');
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('body_number_invalid');
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) validateNumbers(child, depth + 1);
    return;
  }
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) validateNumbers(child, depth + 1);
  }
}

function immutableCanonicalBody(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('body_invalid');
  validateNumbers(value);
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  if (!bytes.length || bytes.length > ORIGIN_BINDING_LIMITS_V1.maximum_body_bytes) {
    fail('body_size_invalid');
  }
  return Object.freeze({
    body: deepFreeze(JSON.parse(bytes.toString('utf8'))),
    bytes,
  });
}

function exactIdentifier(value) {
  const normalized = String(value || '');
  if (!IDENTIFIER.test(normalized)
      || Buffer.byteLength(normalized, 'utf8') > ORIGIN_BINDING_LIMITS_V1.maximum_identifier_bytes) {
    fail('identifier_invalid');
  }
  return normalized;
}

function exactUuid(value) {
  const normalized = String(value || '').toLowerCase();
  if (!UUID.test(normalized)) fail('uuid_invalid');
  return normalized;
}

function exactHash(value) {
  const normalized = String(value || '').toLowerCase();
  if (!HEX32.test(normalized)) fail('sha256_invalid');
  return normalized;
}

function exactTimestamp(value) {
  // Shared canonical wire domain: years 0000..9999, UTC milliseconds, no
  // leap-second or normalized-overflow aliases (RFC 3339 bounded profile).
  if (typeof value !== 'string' || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(value)) {
    fail('timestamp_invalid');
  }
  const normalized = String(value || '');
  const parsed = new Date(normalized);
  if (!normalized || Number.isNaN(parsed.getTime()) || parsed.toISOString() !== normalized) {
    fail('timestamp_invalid');
  }
  return normalized;
}

function exactOptionalUuid(value) {
  return value == null ? null : exactUuid(value);
}

function exactOptionalHash(value) {
  return value == null ? null : exactHash(value);
}

function exactOptionalIdentifier(value) {
  return value == null ? null : exactIdentifier(value);
}

function exactEnum(value, allowed) {
  const normalized = String(value || '');
  if (!allowed.includes(normalized)) fail('enum_invalid');
  return normalized;
}

function exactInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail('integer_invalid');
  return value;
}

function utf8Compare(a, b) {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function exactOrderedUniqueStrings(values, {
  maximum,
  validator,
  orderCode,
  duplicateCode,
  countCode,
}) {
  if (!Array.isArray(values) || values.length < 1 || values.length > maximum) fail(countCode);
  const normalized = values.map(validator);
  if (new Set(normalized).size !== normalized.length) fail(duplicateCode);
  const ordered = [...normalized].sort(utf8Compare);
  if (normalized.some((value, index) => value !== ordered[index])) fail(orderCode);
  return Object.freeze(normalized);
}

function family(id, parentId, confidentialityFloor, actionPolicy) {
  return Object.freeze({
    id,
    parent_id: parentId,
    confidentiality_floor: confidentialityFloor,
    action_policy: actionPolicy,
  });
}

const FAMILY_DEFINITIONS = [
  family('action_input', null, 'internal', 'exact_origin_verdict'),
  family('action_input.executable_instruction', 'action_input', 'internal', 'exact_origin_verdict'),
  family('action_input.external_destination', 'action_input', 'internal', 'exact_origin_verdict'),
  family('action_input.financial_value', 'action_input', 'confidential', 'exact_origin_verdict'),
  family('action_input.resource_target', 'action_input', 'internal', 'exact_origin_verdict'),
  family('derived', null, 'internal', 'inherit_parents'),
  family('derived.housekeeper_derivation', 'derived', 'internal', 'inherit_parents'),
  family('derived.reflection', 'derived', 'internal', 'inherit_parents'),
  family('derived.summary', 'derived', 'internal', 'inherit_parents'),
  family('derived.tool_result', 'derived', 'internal', 'inherit_parents'),
  family('identity', null, 'internal', 'exact_origin_verdict'),
  family('identity.ownership_assertion', 'identity', 'internal', 'exact_origin_verdict'),
  family('identity.principal_assertion', 'identity', 'internal', 'exact_origin_verdict'),
  family('identity.role_assertion', 'identity', 'internal', 'exact_origin_verdict'),
  family('information', null, 'public', 'inform_only'),
  family('information.event', 'information', 'public', 'inform_only'),
  family('information.fact', 'information', 'public', 'inform_only'),
  family('information.preference', 'information', 'internal', 'inform_only'),
  family('information.relationship', 'information', 'internal', 'inform_only'),
  family('secret', null, 'restricted', 'exact_user_or_provider'),
  family('secret.access_token', 'secret', 'restricted', 'exact_user_or_provider'),
  family('secret.credential', 'secret', 'restricted', 'exact_user_or_provider'),
  family('secret.personal_data', 'secret', 'restricted', 'exact_user_or_provider'),
  family('secret.private_key', 'secret', 'restricted', 'exact_user_or_provider'),
  family('system_control', null, 'restricted', 'exact_configuration_owner'),
  family('system_control.authorization_directive', 'system_control', 'restricted', 'exact_configuration_owner'),
  family('system_control.memory_directive', 'system_control', 'restricted', 'exact_configuration_owner'),
  family('system_control.model_configuration', 'system_control', 'restricted', 'exact_configuration_owner'),
  family('system_control.security_policy', 'system_control', 'restricted', 'exact_configuration_owner'),
  family('unknown_protected', null, 'restricted', 'deny_action'),
].sort((a, b) => utf8Compare(a.id, b.id));

export const ORIGIN_FAMILY_PROFILE_BODY_V1 = deepFreeze({
  schema: ORIGIN_BINDING_SCHEMAS_V1.family_profile,
  version: 1,
  canonicalization: 'hom-aimos/canonical-json/v1-safe-integers',
  hash: 'sha256',
  signature: 'ed25519',
  family_order: 'utf8_lexicographic_ascending',
  maximum_family_count: ORIGIN_BINDING_LIMITS_V1.maximum_family_count,
  maximum_parent_count: ORIGIN_BINDING_LIMITS_V1.maximum_parent_count,
  maximum_corroborator_count: ORIGIN_BINDING_LIMITS_V1.maximum_corroborator_count,
  confidentiality_order: ORIGIN_CONFIDENTIALITY_ORDER_V1,
  integrity_order: ORIGIN_INTEGRITY_ORDER_V1,
  action_class_order: ORIGIN_ACTION_CLASS_ORDER_V1,
  risk_class_order: ORIGIN_RISK_CLASSES_V1,
  ingress_channels: ORIGIN_INGRESS_CHANNELS_V1,
  classification_authorities: ORIGIN_CLASSIFICATION_AUTHORITIES_V1,
  family_action_policies: ORIGIN_FAMILY_ACTION_POLICIES_V1,
  families: FAMILY_DEFINITIONS,
});

const FAMILY_BY_ID = new Map(FAMILY_DEFINITIONS.map((entry) => [entry.id, entry]));

function validateFamilyProfile(body) {
  exactKeys(body, [
    'schema',
    'version',
    'canonicalization',
    'hash',
    'signature',
    'family_order',
    'maximum_family_count',
    'maximum_parent_count',
    'maximum_corroborator_count',
    'confidentiality_order',
    'integrity_order',
    'action_class_order',
    'risk_class_order',
    'ingress_channels',
    'classification_authorities',
    'family_action_policies',
    'families',
  ]);
  if (body.schema !== ORIGIN_BINDING_SCHEMAS_V1.family_profile
      || body.version !== 1
      || body.canonicalization !== 'hom-aimos/canonical-json/v1-safe-integers'
      || body.hash !== 'sha256'
      || body.signature !== 'ed25519'
      || body.family_order !== 'utf8_lexicographic_ascending') {
    fail('family_profile_invalid');
  }
  if (body.maximum_family_count !== ORIGIN_BINDING_LIMITS_V1.maximum_family_count
      || body.maximum_parent_count !== ORIGIN_BINDING_LIMITS_V1.maximum_parent_count
      || body.maximum_corroborator_count !== ORIGIN_BINDING_LIMITS_V1.maximum_corroborator_count
      || canonicalJson(body.confidentiality_order) !== canonicalJson(ORIGIN_CONFIDENTIALITY_ORDER_V1)
      || canonicalJson(body.integrity_order) !== canonicalJson(ORIGIN_INTEGRITY_ORDER_V1)
      || canonicalJson(body.action_class_order) !== canonicalJson(ORIGIN_ACTION_CLASS_ORDER_V1)
      || canonicalJson(body.risk_class_order) !== canonicalJson(ORIGIN_RISK_CLASSES_V1)
      || canonicalJson(body.ingress_channels) !== canonicalJson(ORIGIN_INGRESS_CHANNELS_V1)
      || canonicalJson(body.classification_authorities)
        !== canonicalJson(ORIGIN_CLASSIFICATION_AUTHORITIES_V1)
      || canonicalJson(body.family_action_policies)
        !== canonicalJson(ORIGIN_FAMILY_ACTION_POLICIES_V1)) {
    fail('family_profile_invalid');
  }
  if (!Array.isArray(body.families) || body.families.length < 1
      || body.families.length > ORIGIN_BINDING_LIMITS_V1.maximum_family_count) {
    fail('family_count_invalid');
  }
  const seen = new Set();
  let prior = null;
  const local = new Map();
  for (const entry of body.families) {
    exactKeys(entry, ['id', 'parent_id', 'confidentiality_floor', 'action_policy']);
    if (!FAMILY_ID.test(entry.id)) fail('family_id_invalid');
    if (seen.has(entry.id)) fail('family_duplicate');
    if (prior != null && utf8Compare(prior, entry.id) >= 0) fail('family_order_invalid');
    if (entry.parent_id != null && !FAMILY_ID.test(entry.parent_id)) fail('family_parent_invalid');
    exactEnum(entry.confidentiality_floor, ORIGIN_CONFIDENTIALITY_ORDER_V1);
    exactEnum(entry.action_policy, ORIGIN_FAMILY_ACTION_POLICIES_V1);
    seen.add(entry.id);
    local.set(entry.id, entry);
    prior = entry.id;
  }
  for (const entry of body.families) {
    if (entry.parent_id != null && !local.has(entry.parent_id)) fail('family_parent_invalid');
    const ancestry = new Set([entry.id]);
    let cursor = entry;
    while (cursor.parent_id != null) {
      if (ancestry.has(cursor.parent_id)) fail('family_cycle');
      ancestry.add(cursor.parent_id);
      cursor = local.get(cursor.parent_id);
      if (!cursor) fail('family_parent_invalid');
    }
  }
  return body;
}

export function originProtocolBytesV1(body) {
  const canonical = immutableCanonicalBody(body);
  const domainBytes = Object.entries(ORIGIN_BINDING_SCHEMAS_V1)
    .find(([, schema]) => schema === canonical.body.schema);
  if (!domainBytes) fail('schema_invalid');
  return Buffer.concat([
    ORIGIN_BINDING_DOMAINS_V1[domainBytes[0]],
    u32(canonical.bytes.length),
    canonical.bytes,
  ]);
}

export function originProtocolHashV1(body) {
  return sha256(originProtocolBytesV1(body));
}

validateFamilyProfile(ORIGIN_FAMILY_PROFILE_BODY_V1);

export const ORIGIN_FAMILY_PROFILE_SHA256_V1 = originProtocolHashV1(
  ORIGIN_FAMILY_PROFILE_BODY_V1,
).toString('hex');

export function originFamilyClosureV1(familyIds = []) {
  if (!Array.isArray(familyIds) || familyIds.length < 1
      || familyIds.length > ORIGIN_BINDING_LIMITS_V1.maximum_family_count) {
    fail('family_count_invalid');
  }
  const closure = new Set();
  for (const raw of familyIds) {
    const id = String(raw || '');
    if (!FAMILY_ID.test(id) || !FAMILY_BY_ID.has(id)) fail('family_id_invalid');
    let cursor = FAMILY_BY_ID.get(id);
    while (cursor) {
      closure.add(cursor.id);
      cursor = cursor.parent_id == null ? null : FAMILY_BY_ID.get(cursor.parent_id);
    }
  }
  if (closure.size > ORIGIN_BINDING_LIMITS_V1.maximum_family_count) fail('family_count_invalid');
  return Object.freeze([...closure].sort(utf8Compare));
}

function exactFamilyClosure(values) {
  const normalized = exactOrderedUniqueStrings(values, {
    maximum: ORIGIN_BINDING_LIMITS_V1.maximum_family_count,
    validator: (value) => {
      const id = String(value || '');
      if (!FAMILY_ID.test(id) || !FAMILY_BY_ID.has(id)) fail('family_id_invalid');
      return id;
    },
    orderCode: 'family_order_invalid',
    duplicateCode: 'family_duplicate',
    countCode: 'family_count_invalid',
  });
  const closure = originFamilyClosureV1(normalized);
  if (canonicalJson(normalized) !== canonicalJson(closure)) fail('family_closure_invalid');
  return normalized;
}

function familyConfidentialityFloor(familyIds) {
  let rank = 0;
  for (const id of familyIds) {
    rank = Math.max(rank, CONFIDENTIALITY_RANK.get(FAMILY_BY_ID.get(id).confidentiality_floor));
  }
  return ORIGIN_CONFIDENTIALITY_ORDER_V1[rank];
}

function validateActor(actor) {
  exactKeys(actor, ['agent_id', 'valid_from', 'cert_fingerprint_sha256']);
  return Object.freeze({
    agent_id: exactIdentifier(actor.agent_id),
    valid_from: exactTimestamp(actor.valid_from),
    cert_fingerprint_sha256: exactHash(actor.cert_fingerprint_sha256),
  });
}

function validateRequest(request) {
  exactKeys(request, ['receipt_id', 'mutation_sha256']);
  return Object.freeze({
    receipt_id: exactUuid(request.receipt_id),
    mutation_sha256: exactHash(request.mutation_sha256),
  });
}

function validateOrigin(origin) {
  exactKeys(origin, ['ingress_channel', 'channel_identity_sha256']);
  return Object.freeze({
    ingress_channel: exactEnum(origin.ingress_channel, ORIGIN_INGRESS_CHANNELS_V1),
    channel_identity_sha256: exactHash(origin.channel_identity_sha256),
  });
}

function validateParents(parents) {
  exactKeys(parents, ['origin_sha256s']);
  const values = parents.origin_sha256s;
  if (!Array.isArray(values) || values.length > ORIGIN_BINDING_LIMITS_V1.maximum_parent_count) {
    fail('parent_count_invalid');
  }
  if (values.length === 0) return Object.freeze({ origin_sha256s: Object.freeze([]) });
  return Object.freeze({
    origin_sha256s: exactOrderedUniqueStrings(values, {
      maximum: ORIGIN_BINDING_LIMITS_V1.maximum_parent_count,
      validator: exactHash,
      orderCode: 'parent_order_invalid',
      duplicateCode: 'parent_duplicate',
      countCode: 'parent_count_invalid',
    }),
  });
}

function validateClassification(classification) {
  exactKeys(classification, [
    'profile_sha256',
    'family_ids',
    'authority',
    'evidence_sha256',
  ]);
  const profile = exactHash(classification.profile_sha256);
  if (profile !== ORIGIN_FAMILY_PROFILE_SHA256_V1) fail('family_profile_hash_invalid');
  return Object.freeze({
    profile_sha256: profile,
    family_ids: exactFamilyClosure(classification.family_ids),
    authority: exactEnum(
      classification.authority,
      ORIGIN_CLASSIFICATION_AUTHORITIES_V1,
    ),
    evidence_sha256: exactHash(classification.evidence_sha256),
  });
}

export function createMemoryOriginBindingV1(input = {}) {
  exactKeys(input, [
    'schema',
    'company_id',
    'memory_id',
    'occurrence_id',
    'content_sha256',
    'actor',
    'request',
    'origin',
    'parents',
    'classification',
    'confidentiality',
    'integrity',
    'action_class',
    'scope',
    'session_id',
    'tool_action_event_id',
    'created_at',
  ]);
  if (input.schema !== ORIGIN_BINDING_SCHEMAS_V1.memory_binding) fail('schema_invalid');
  const actor = validateActor(input.actor);
  const request = validateRequest(input.request);
  const origin = validateOrigin(input.origin);
  const parents = validateParents(input.parents);
  const classification = validateClassification(input.classification);
  const confidentiality = exactEnum(
    input.confidentiality,
    ORIGIN_CONFIDENTIALITY_ORDER_V1,
  );
  const integrity = exactEnum(input.integrity, ORIGIN_INTEGRITY_ORDER_V1);
  const actionClass = exactEnum(input.action_class, ORIGIN_ACTION_CLASS_ORDER_V1);
  if (CONFIDENTIALITY_RANK.get(confidentiality)
      < CONFIDENTIALITY_RANK.get(familyConfidentialityFloor(classification.family_ids))) {
    fail('family_confidentiality_floor_invalid');
  }
  if (INTEGRITY_RANK.get(integrity)
      > INTEGRITY_RANK.get(CHANNEL_INTEGRITY_CEILING[origin.ingress_channel])) {
    fail('channel_integrity_invalid');
  }
  if (ACTION_RANK.get(actionClass)
      > ACTION_RANK.get(INTEGRITY_ACTION_CEILING[integrity])) {
    fail('integrity_action_class_invalid');
  }
  const body = {
    schema: input.schema,
    company_id: exactIdentifier(input.company_id),
    memory_id: exactUuid(input.memory_id),
    occurrence_id: exactUuid(input.occurrence_id),
    content_sha256: exactHash(input.content_sha256),
    actor,
    request,
    origin,
    parents,
    classification,
    confidentiality,
    integrity,
    action_class: actionClass,
    scope: exactIdentifier(input.scope),
    session_id: exactOptionalIdentifier(input.session_id),
    tool_action_event_id: exactOptionalUuid(input.tool_action_event_id),
    created_at: exactTimestamp(input.created_at),
  };
  const canonical = immutableCanonicalBody(body);
  return deepFreeze({
    ...canonical.body,
    binding_sha256: originProtocolHashV1(canonical.body).toString('hex'),
  });
}

function bindingBody(binding) {
  exactKeys(binding, [
    'schema',
    'company_id',
    'memory_id',
    'occurrence_id',
    'content_sha256',
    'actor',
    'request',
    'origin',
    'parents',
    'classification',
    'confidentiality',
    'integrity',
    'action_class',
    'scope',
    'session_id',
    'tool_action_event_id',
    'created_at',
    'binding_sha256',
  ]);
  const { binding_sha256: supplied, ...body } = binding;
  const reconstructed = createMemoryOriginBindingV1(body);
  if (exactHash(supplied) !== reconstructed.binding_sha256) fail('parent_binding_invalid');
  // A constructor may normalize input; an already encoded wire object may not
  // silently change representation while retaining a supplied commitment.
  if (canonicalJson(binding) !== canonicalJson(reconstructed)) fail('parent_binding_invalid');
  return reconstructed;
}

export function verifyOriginDerivationV1({ child, parents = [] } = {}) {
  const normalizedChild = bindingBody(child);
  if (!Array.isArray(parents) || parents.length > ORIGIN_BINDING_LIMITS_V1.maximum_parent_count) {
    fail('parent_count_invalid');
  }
  const normalizedParents = parents.map(bindingBody);
  const parentHashes = normalizedParents.map((parent) => parent.binding_sha256).sort(utf8Compare);
  if (canonicalJson(parentHashes) !== canonicalJson(normalizedChild.parents.origin_sha256s)) {
    fail('parent_binding_invalid');
  }
  if (normalizedParents.length === 0) return Object.freeze({ valid: true, parent_count: 0 });
  const inheritedFamilyInputs = [...new Set(
    normalizedParents.flatMap((parent) => parent.classification.family_ids),
  )].sort(utf8Compare);
  const inheritedFamilies = originFamilyClosureV1(inheritedFamilyInputs);
  const childFamilies = new Set(normalizedChild.classification.family_ids);
  if (inheritedFamilies.some((id) => !childFamilies.has(id))) fail('family_closure_invalid');
  const minimumConfidentiality = Math.max(
    ...normalizedParents.map((parent) => CONFIDENTIALITY_RANK.get(parent.confidentiality)),
  );
  if (CONFIDENTIALITY_RANK.get(normalizedChild.confidentiality) < minimumConfidentiality) {
    fail('confidentiality_downgrade');
  }
  const maximumIntegrity = Math.min(
    ...normalizedParents.map((parent) => INTEGRITY_RANK.get(parent.integrity)),
  );
  if (INTEGRITY_RANK.get(normalizedChild.integrity) > maximumIntegrity) fail('integrity_elevation');
  const maximumAction = Math.min(
    ...normalizedParents.map((parent) => ACTION_RANK.get(parent.action_class)),
  );
  if (ACTION_RANK.get(normalizedChild.action_class) > maximumAction) fail('action_class_elevation');
  return Object.freeze({ valid: true, parent_count: normalizedParents.length });
}

function validateCorroborator(value) {
  try {
    exactKeys(value, [
      'principal_id',
      'valid_from',
      'administrative_domain_sha256',
      'upstream_source_sha256',
      'license_sha256',
    ]);
    return Object.freeze({
      principal_id: exactIdentifier(value.principal_id),
      valid_from: exactTimestamp(value.valid_from),
      administrative_domain_sha256: exactHash(value.administrative_domain_sha256),
      upstream_source_sha256: exactHash(value.upstream_source_sha256),
      license_sha256: exactHash(value.license_sha256),
    });
  } catch (error) {
    if (String(error?.message || '').includes('origin_binding_v1:')) {
      fail('corroborator_shape_invalid');
    }
    throw error;
  }
}

function corroboratorKey(value) {
  return [
    value.administrative_domain_sha256,
    value.upstream_source_sha256,
    value.principal_id,
    value.valid_from,
  ].join(':');
}

export function createOriginElevationV1(input = {}) {
  exactKeys(input, [
    'schema',
    'company_id',
    'elevation_id',
    'value_sha256',
    'family_id',
    'action_scope',
    'risk_class',
    'base_origin_sha256s',
    'corroborators',
    'threshold',
    'user_authorization_sha256',
    'maximum_uses',
    'valid_from',
    'valid_until',
    'created_at',
  ]);
  if (input.schema !== ORIGIN_BINDING_SCHEMAS_V1.elevation) fail('schema_invalid');
  const familyId = String(input.family_id || '');
  if (!FAMILY_BY_ID.has(familyId)) fail('family_id_invalid');
  const origins = exactOrderedUniqueStrings(input.base_origin_sha256s, {
    maximum: ORIGIN_BINDING_LIMITS_V1.maximum_parent_count,
    validator: exactHash,
    orderCode: 'parent_order_invalid',
    duplicateCode: 'parent_duplicate',
    countCode: 'parent_count_invalid',
  });
  if (!Array.isArray(input.corroborators)
      || input.corroborators.length > ORIGIN_BINDING_LIMITS_V1.maximum_corroborator_count) {
    fail('corroborator_count_invalid');
  }
  const corroborators = input.corroborators.map(validateCorroborator);
  const keys = corroborators.map(corroboratorKey);
  if (new Set(keys).size !== keys.length) fail('corroborator_duplicate');
  const ordered = [...keys].sort(utf8Compare);
  if (keys.some((value, index) => value !== ordered[index])) fail('corroborator_order_invalid');
  const domains = new Set(corroborators.map((entry) => entry.administrative_domain_sha256));
  const upstream = new Set(corroborators.map((entry) => entry.upstream_source_sha256));
  if (domains.size !== corroborators.length || upstream.size !== corroborators.length) {
    fail('corroborator_independence_invalid');
  }
  const threshold = exactInteger(
    input.threshold,
    2,
    ORIGIN_BINDING_LIMITS_V1.maximum_corroborator_count,
  );
  const userAuthorization = exactOptionalHash(input.user_authorization_sha256);
  const maximumUses = exactInteger(input.maximum_uses, 1, 1);
  if (userAuthorization == null && corroborators.length < threshold) fail('elevation_authority_invalid');
  const validFrom = exactTimestamp(input.valid_from);
  const validUntil = exactTimestamp(input.valid_until);
  const createdAt = exactTimestamp(input.created_at);
  if (validUntil <= validFrom || createdAt > validUntil) fail('timestamp_order_invalid');
  const body = deepFreeze({
    schema: input.schema,
    company_id: exactIdentifier(input.company_id),
    elevation_id: exactUuid(input.elevation_id),
    value_sha256: exactHash(input.value_sha256),
    family_id: familyId,
    action_scope: exactIdentifier(input.action_scope),
    risk_class: exactEnum(input.risk_class, ORIGIN_RISK_CLASSES_V1),
    base_origin_sha256s: origins,
    corroborators: Object.freeze(corroborators),
    threshold,
    user_authorization_sha256: userAuthorization,
    maximum_uses: maximumUses,
    valid_from: validFrom,
    valid_until: validUntil,
    created_at: createdAt,
  });
  return deepFreeze({
    ...body,
    elevation_sha256: originProtocolHashV1(body).toString('hex'),
  });
}

export function createActionOriginVerdictV1(input = {}) {
  exactKeys(input, [
    'schema',
    'company_id',
    'verdict_id',
    'actor',
    'tool_name',
    'action_scope',
    'risk_class',
    'arguments_sha256',
    'security_values',
    'family_ids',
    'input_origin_sha256s',
    'untrusted_influence',
    'elevation_sha256',
    'user_authorization_sha256',
    'decision',
    'failure_code',
    'previous_verdict_sha256',
    'created_at',
  ]);
  if (input.schema !== ORIGIN_BINDING_SCHEMAS_V1.action_verdict) fail('schema_invalid');
  const decision = exactEnum(input.decision, ORIGIN_ACTION_DECISIONS_V1);
  const failureCode = input.failure_code == null
    ? null
    : exactEnum(input.failure_code, ORIGIN_ACTION_FAILURE_CODES_V1);
  const untrustedInfluence = input.untrusted_influence;
  if (typeof untrustedInfluence !== 'boolean') fail('verdict_semantics_invalid');
  const elevation = exactOptionalHash(input.elevation_sha256);
  const userAuthorization = exactOptionalHash(input.user_authorization_sha256);
  if ((decision === 'ALLOW' && failureCode != null)
      || (decision !== 'ALLOW' && failureCode == null)
      || (decision === 'ALLOW' && untrustedInfluence && elevation == null && userAuthorization == null)) {
    fail('verdict_semantics_invalid');
  }
  if (!Array.isArray(input.security_values)
      || input.security_values.length < 1
      || input.security_values.length > ORIGIN_BINDING_LIMITS_V1.maximum_parent_count) {
    fail('security_value_shape_invalid');
  }
  const securityValues = input.security_values.map((entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      fail('security_value_shape_invalid');
    }
    try {
      exactKeys(entry, ['value_sha256', 'family_ids']);
      return Object.freeze({
        value_sha256: exactHash(entry.value_sha256),
        family_ids: exactFamilyClosure(entry.family_ids),
      });
    } catch (error) {
      if (String(error?.message || '').includes('origin_binding_v1:shape_invalid')) {
        fail('security_value_shape_invalid');
      }
      throw error;
    }
  });
  const valueHashes = securityValues.map((entry) => entry.value_sha256);
  if (new Set(valueHashes).size !== valueHashes.length) fail('security_value_duplicate');
  const orderedValueHashes = [...valueHashes].sort(utf8Compare);
  if (valueHashes.some((value, index) => value !== orderedValueHashes[index])) {
    fail('security_value_order_invalid');
  }
  const verdictFamilies = exactFamilyClosure(input.family_ids);
  const securityValueFamilyInputs = [...new Set(
    securityValues.flatMap((entry) => entry.family_ids),
  )].sort(utf8Compare);
  const securityValueFamilies = originFamilyClosureV1(securityValueFamilyInputs);
  if (canonicalJson(verdictFamilies) !== canonicalJson(securityValueFamilies)) {
    fail('security_value_family_binding_invalid');
  }
  const body = deepFreeze({
    schema: input.schema,
    company_id: exactIdentifier(input.company_id),
    verdict_id: exactUuid(input.verdict_id),
    actor: validateActor(input.actor),
    tool_name: exactIdentifier(input.tool_name),
    action_scope: exactIdentifier(input.action_scope),
    risk_class: exactEnum(input.risk_class, ORIGIN_RISK_CLASSES_V1),
    arguments_sha256: exactHash(input.arguments_sha256),
    security_values: Object.freeze(securityValues),
    family_ids: verdictFamilies,
    input_origin_sha256s: exactOrderedUniqueStrings(input.input_origin_sha256s, {
      maximum: ORIGIN_BINDING_LIMITS_V1.maximum_parent_count,
      validator: exactHash,
      orderCode: 'parent_order_invalid',
      duplicateCode: 'parent_duplicate',
      countCode: 'parent_count_invalid',
    }),
    untrusted_influence: untrustedInfluence,
    elevation_sha256: elevation,
    user_authorization_sha256: userAuthorization,
    decision,
    failure_code: failureCode,
    previous_verdict_sha256: exactOptionalHash(input.previous_verdict_sha256),
    created_at: exactTimestamp(input.created_at),
  });
  return deepFreeze({
    ...body,
    verdict_sha256: originProtocolHashV1(body).toString('hex'),
  });
}

export function originProtocolDomainHexV1() {
  return Object.freeze(Object.fromEntries(
    Object.entries(ORIGIN_BINDING_DOMAINS_V1).map(([key, value]) => [key, value.toString('hex')]),
  ));
}

export default Object.freeze({
  ORIGIN_BINDING_SCHEMAS_V1,
  ORIGIN_BINDING_LIMITS_V1,
  ORIGIN_FAMILY_PROFILE_BODY_V1,
  ORIGIN_FAMILY_PROFILE_SHA256_V1,
  createMemoryOriginBindingV1,
  createOriginElevationV1,
  createActionOriginVerdictV1,
  verifyOriginDerivationV1,
  originFamilyClosureV1,
  originProtocolBytesV1,
  originProtocolHashV1,
});
