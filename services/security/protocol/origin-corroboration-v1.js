// ─── ORIGIN CORROBORATION TRUST REGISTRY ────────────────────────────────────
// ← Called by: master-signed system config and the Housekeeper source verifier
// → Calls: canonical consequential-action projection only
// Pipeline: ORIGIN BINDING | Position: provider-agnostic trusted-source policy
// Sources: Louck TMA-NM M3 (arXiv:2606.24322); RFC 8032; RFC 6962
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';
import {
  buildConsequentialActionProjectionV1,
  consequentialActionPolicyForTool,
} from './consequential-action-v1.js';
import {
  ORIGIN_BINDING_SCHEMAS_V1,
  createOriginElevationV1,
} from './origin-binding-v1.js';

export const ORIGIN_TRUST_REGISTRY_SCHEMA_V1 =
  'hom.aimos.origin-source-trust-registry/v1';
export const ORIGIN_SOURCE_CLAIM_SCHEMA_V1 =
  'hom.aimos.origin-source-claim/v1';
export const ORIGIN_SOURCE_OBSERVATION_SCHEMA_V1 =
  'hom.aimos.origin-source-observation/v1';
export const ORIGIN_CORROBORATION_LICENSE_SCHEMA_V2 =
  'hom.aimos.origin-corroboration-license/v2';
export const ORIGIN_TRUST_REGISTRY_ACTIVATION_SCHEMA_V1 =
  'hom.aimos.origin-trust-registry-activation/v1';
export const ORIGIN_ELEVATION_SCHEMA_V2 = 'hom.aimos.origin-elevation/v2';

const HASH = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const MEDIA_TYPES = new Set(['application/pdf', 'text/html', 'text/plain']);
const EXACT_KEYS = Object.freeze({
  registry: ['schema', 'version', 'threshold', 'valid_from', 'valid_until',
    'claim', 'action', 'authorities'],
  claim: ['schema', 'claim_id', 'subject', 'predicate', 'object', 'rendered_value'],
  action: ['action_id', 'tool', 'arguments', 'source_bound_fields',
    'operator_bound_fields'],
  authority: ['authority_id', 'principal_id', 'administrative_domain',
    'upstream_source', 'url', 'media_type', 'evidence_marker_utf8', 'max_bytes'],
});

function assert(condition, code) {
  if (!condition) throw new Error(code);
}

function exactKeys(value, keys, code) {
  assert(value && typeof value === 'object' && !Array.isArray(value), code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  assert(canonicalJson(actual) === canonicalJson(expected), code);
}

function text(value, code, maximum = 4096) {
  const normalized = String(value ?? '');
  assert(normalized.length > 0 && Buffer.byteLength(normalized, 'utf8') <= maximum
    && !normalized.includes('\0'), code);
  return normalized;
}

function identifier(value, code) {
  const normalized = String(value || '').trim().toLowerCase();
  assert(IDENTIFIER.test(normalized), code);
  return normalized;
}

function timestamp(value, code) {
  const normalized = new Date(value).toISOString();
  assert(normalized === value, code);
  return normalized;
}

function hashDomain(domain, value) {
  const bytes = Buffer.from(String(value), 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(`${domain}\0`, 'utf8'), length, bytes,
  ])).digest('hex');
}

function objectHash(schema, body) {
  return hashDomain(schema, canonicalJson(body));
}

function uniqueOrdered(values, code) {
  assert(Array.isArray(values) && values.length > 0 && values.length <= 64, code);
  const normalized = values.map((value) => identifier(value, code));
  const ordered = [...normalized].sort((left, right) => Buffer.compare(
    Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'),
  ));
  assert(new Set(normalized).size === normalized.length
    && canonicalJson(normalized) === canonicalJson(ordered), code);
  return Object.freeze(normalized);
}

function normalizeUrl(value, expectedHost) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error('origin_trust_url_invalid'); }
  assert(parsed.protocol === 'https:' && !parsed.username && !parsed.password
    && !parsed.hash && !parsed.search && parsed.hostname === expectedHost
    && parsed.port === '', 'origin_trust_url_invalid');
  return parsed.toString();
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

export function createOriginSourceClaimV1(input = {}) {
  exactKeys(input, EXACT_KEYS.claim, 'origin_trust_claim_shape_invalid');
  assert(input.schema === ORIGIN_SOURCE_CLAIM_SCHEMA_V1,
    'origin_trust_claim_schema_invalid');
  const object = input.object;
  assert(object === null || typeof object === 'boolean' || typeof object === 'string'
    || (Number.isSafeInteger(object)), 'origin_trust_claim_object_invalid');
  const body = deepFreeze({
    schema: ORIGIN_SOURCE_CLAIM_SCHEMA_V1,
    claim_id: identifier(input.claim_id, 'origin_trust_claim_id_invalid'),
    subject: text(input.subject, 'origin_trust_claim_subject_invalid', 512),
    predicate: identifier(input.predicate, 'origin_trust_claim_predicate_invalid'),
    object,
    rendered_value: text(input.rendered_value, 'origin_trust_claim_rendered_invalid', 8192),
  });
  return deepFreeze({
    ...body,
    claim_sha256: objectHash(ORIGIN_SOURCE_CLAIM_SCHEMA_V1, body),
  });
}

export function createOriginTrustRegistryV1(input = {}) {
  exactKeys(input, EXACT_KEYS.registry, 'origin_trust_registry_shape_invalid');
  assert(input.schema === ORIGIN_TRUST_REGISTRY_SCHEMA_V1 && input.version === 1,
    'origin_trust_registry_version_invalid');
  const threshold = Number(input.threshold);
  assert(Number.isSafeInteger(threshold) && threshold >= 2 && threshold <= 16,
    'origin_trust_registry_threshold_invalid');
  const validFrom = timestamp(input.valid_from, 'origin_trust_registry_time_invalid');
  const validUntil = timestamp(input.valid_until, 'origin_trust_registry_time_invalid');
  assert(validUntil > validFrom, 'origin_trust_registry_time_invalid');
  const claim = createOriginSourceClaimV1(input.claim);

  exactKeys(input.action, EXACT_KEYS.action, 'origin_trust_action_shape_invalid');
  const tool = identifier(input.action.tool, 'origin_trust_action_tool_invalid');
  const args = JSON.parse(canonicalJson(input.action.arguments));
  const sourceFields = uniqueOrdered(
    input.action.source_bound_fields, 'origin_trust_source_fields_invalid',
  );
  const operatorFields = uniqueOrdered(
    input.action.operator_bound_fields, 'origin_trust_operator_fields_invalid',
  );
  assert(sourceFields.every((field) => !operatorFields.includes(field)),
    'origin_trust_action_field_overlap');
  const actionPolicy = consequentialActionPolicyForTool(tool);
  assert(actionPolicy, 'origin_trust_action_tool_invalid');
  const projection = buildConsequentialActionProjectionV1({
    tool,
    args,
    profile: {
      tool,
      operation_class: tool === 'write_file' ? 'internal_write' : 'external_write',
      argument_schema: {
        properties: Object.fromEntries(actionPolicy.fields.map(({ name }) => [name, {}])),
      },
    },
  });
  const projectionFields = projection.fields.map((field) => field.field).sort();
  assert(canonicalJson([...sourceFields, ...operatorFields].sort())
      === canonicalJson(projectionFields)
    && sourceFields.every((field) => Object.hasOwn(args, field))
    && sourceFields.every((field) => args[field] === claim.rendered_value),
  'origin_trust_action_field_binding_invalid');
  const action = deepFreeze({
    action_id: identifier(input.action.action_id, 'origin_trust_action_id_invalid'),
    tool,
    arguments: args,
    source_bound_fields: sourceFields,
    operator_bound_fields: operatorFields,
    arguments_sha256: projection.arguments_sha256,
    value_sha256: projection.value_sha256,
    action_scope: projection.action_scope,
    risk_class: projection.risk_class,
    primary_family_id: projection.primary_family_id,
    family_ids: projection.family_ids,
  });

  assert(Array.isArray(input.authorities)
    && input.authorities.length >= threshold && input.authorities.length <= 16,
  'origin_trust_authority_count_invalid');
  const authorities = input.authorities.map((entry) => {
    exactKeys(entry, EXACT_KEYS.authority, 'origin_trust_authority_shape_invalid');
    const authorityId = identifier(entry.authority_id, 'origin_trust_authority_id_invalid');
    const principalId = identifier(entry.principal_id, 'origin_trust_principal_id_invalid');
    assert(principalId !== 'housekeeper', 'origin_trust_housekeeper_self_invalid');
    const administrativeDomain = String(entry.administrative_domain || '').toLowerCase();
    assert(HOST.test(administrativeDomain), 'origin_trust_administrative_domain_invalid');
    const upstreamSource = identifier(
      entry.upstream_source, 'origin_trust_upstream_source_invalid',
    );
    const mediaType = String(entry.media_type || '').toLowerCase();
    assert(MEDIA_TYPES.has(mediaType), 'origin_trust_media_type_invalid');
    const maximum = Number(entry.max_bytes);
    assert(Number.isSafeInteger(maximum) && maximum >= 1 && maximum <= 4_194_304,
      'origin_trust_max_bytes_invalid');
    const marker = text(
      entry.evidence_marker_utf8, 'origin_trust_evidence_marker_invalid', 8192,
    );
    return deepFreeze({
      authority_id: authorityId,
      principal_id: principalId,
      valid_from: validFrom,
      administrative_domain: administrativeDomain,
      administrative_domain_sha256: hashDomain(
        `${ORIGIN_TRUST_REGISTRY_SCHEMA_V1}/administrative-domain`, administrativeDomain,
      ),
      upstream_source: upstreamSource,
      upstream_source_sha256: hashDomain(
        `${ORIGIN_TRUST_REGISTRY_SCHEMA_V1}/upstream-source`, upstreamSource,
      ),
      url: normalizeUrl(entry.url, administrativeDomain),
      media_type: mediaType,
      evidence_marker_utf8: marker,
      evidence_marker_sha256: createHash('sha256').update(marker, 'utf8').digest('hex'),
      max_bytes: maximum,
      claim_sha256: claim.claim_sha256,
    });
  }).sort((left, right) => left.authority_id.localeCompare(right.authority_id));
  const principals = new Set(authorities.map((entry) => entry.principal_id));
  const domains = new Set(authorities.map((entry) => entry.administrative_domain_sha256));
  const upstream = new Set(authorities.map((entry) => entry.upstream_source_sha256));
  assert(principals.size === authorities.length && domains.size === authorities.length
    && upstream.size === authorities.length, 'origin_trust_authority_independence_invalid');

  const body = deepFreeze({
    schema: ORIGIN_TRUST_REGISTRY_SCHEMA_V1,
    version: 1,
    threshold,
    valid_from: validFrom,
    valid_until: validUntil,
    claim,
    action,
    authorities: Object.freeze(authorities),
  });
  return deepFreeze({
    ...body,
    registry_sha256: objectHash(ORIGIN_TRUST_REGISTRY_SCHEMA_V1, body),
  });
}

export function validateOriginTrustRegistryConfig(value) {
  if (typeof value !== 'string') return { ok: false, reason: 'value_must_be_string' };
  try {
    const parsed = JSON.parse(value);
    const registry = createOriginTrustRegistryV1(parsed);
    const canonicalInput = {
      schema: registry.schema,
      version: registry.version,
      threshold: registry.threshold,
      valid_from: registry.valid_from,
      valid_until: registry.valid_until,
      claim: {
        schema: registry.claim.schema,
        claim_id: registry.claim.claim_id,
        subject: registry.claim.subject,
        predicate: registry.claim.predicate,
        object: registry.claim.object,
        rendered_value: registry.claim.rendered_value,
      },
      action: {
        action_id: registry.action.action_id,
        tool: registry.action.tool,
        arguments: registry.action.arguments,
        source_bound_fields: registry.action.source_bound_fields,
        operator_bound_fields: registry.action.operator_bound_fields,
      },
      authorities: registry.authorities.map((authority) => ({
        authority_id: authority.authority_id,
        principal_id: authority.principal_id,
        administrative_domain: authority.administrative_domain,
        upstream_source: authority.upstream_source,
        url: authority.url,
        media_type: authority.media_type,
        evidence_marker_utf8: authority.evidence_marker_utf8,
        max_bytes: authority.max_bytes,
      })),
    };
    return {
      ok: true,
      value: canonicalJson(canonicalInput),
      registry,
    };
  } catch (error) {
    return { ok: false, reason: String(error?.message || 'origin_trust_registry_invalid') };
  }
}

export function createOriginElevationV2(input = {}) {
  exactKeys(input, [
    'schema', 'company_id', 'elevation_id', 'actor',
    'request_receipt_mutation_sha256', 'action_id', 'arguments_sha256',
    'value_sha256', 'family_id', 'action_scope', 'risk_class',
    'base_origin_sha256s', 'corroborators', 'threshold',
    'maximum_uses', 'valid_from', 'valid_until', 'created_at',
  ], 'origin_elevation_v2_shape_invalid');
  assert(input.schema === ORIGIN_ELEVATION_SCHEMA_V2,
    'origin_elevation_v2_schema_invalid');
  exactKeys(input.actor, ['agent_id', 'valid_from', 'cert_fingerprint_sha256'],
    'origin_elevation_v2_actor_shape_invalid');
  const actor = deepFreeze({
    agent_id: identifier(input.actor.agent_id, 'origin_elevation_v2_actor_invalid'),
    valid_from: timestamp(input.actor.valid_from, 'origin_elevation_v2_actor_invalid'),
    cert_fingerprint_sha256: String(input.actor.cert_fingerprint_sha256 || '').toLowerCase(),
  });
  assert(HASH.test(actor.cert_fingerprint_sha256), 'origin_elevation_v2_actor_invalid');
  const requestReceipt = String(input.request_receipt_mutation_sha256 || '').toLowerCase();
  const argumentsSha256 = String(input.arguments_sha256 || '').toLowerCase();
  assert(HASH.test(requestReceipt) && HASH.test(argumentsSha256),
    'origin_elevation_v2_action_binding_invalid');
  const validated = createOriginElevationV1({
    schema: ORIGIN_BINDING_SCHEMAS_V1.elevation,
    company_id: input.company_id,
    elevation_id: input.elevation_id,
    value_sha256: input.value_sha256,
    family_id: input.family_id,
    action_scope: input.action_scope,
    risk_class: input.risk_class,
    base_origin_sha256s: input.base_origin_sha256s,
    corroborators: input.corroborators,
    threshold: input.threshold,
    user_authorization_sha256: null,
    maximum_uses: input.maximum_uses,
    valid_from: input.valid_from,
    valid_until: input.valid_until,
    created_at: input.created_at,
  });
  const body = deepFreeze({
    schema: ORIGIN_ELEVATION_SCHEMA_V2,
    company_id: validated.company_id,
    elevation_id: validated.elevation_id,
    actor,
    request_receipt_mutation_sha256: requestReceipt,
    action_id: identifier(input.action_id, 'origin_elevation_v2_action_id_invalid'),
    arguments_sha256: argumentsSha256,
    value_sha256: validated.value_sha256,
    family_id: validated.family_id,
    action_scope: validated.action_scope,
    risk_class: validated.risk_class,
    base_origin_sha256s: validated.base_origin_sha256s,
    corroborators: validated.corroborators,
    threshold: validated.threshold,
    maximum_uses: validated.maximum_uses,
    valid_from: validated.valid_from,
    valid_until: validated.valid_until,
    created_at: validated.created_at,
  });
  return deepFreeze({
    ...body,
    elevation_sha256: objectHash(ORIGIN_ELEVATION_SCHEMA_V2, body),
  });
}

export const ORIGIN_CORROBORATION_PROTOCOL_V1 = Object.freeze({
  hash: 'sha256',
  minimum_independent_authorities: 2,
  maximum_authorities: 16,
  maximum_document_bytes: 4_194_304,
  registry_schema: ORIGIN_TRUST_REGISTRY_SCHEMA_V1,
  claim_schema: ORIGIN_SOURCE_CLAIM_SCHEMA_V1,
  observation_schema: ORIGIN_SOURCE_OBSERVATION_SCHEMA_V1,
  license_schema: ORIGIN_CORROBORATION_LICENSE_SCHEMA_V2,
  elevation_schema: ORIGIN_ELEVATION_SCHEMA_V2,
});
