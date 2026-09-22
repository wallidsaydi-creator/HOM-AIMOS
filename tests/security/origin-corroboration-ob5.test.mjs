import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  ORIGIN_ELEVATION_SCHEMA_V2,
  ORIGIN_SOURCE_CLAIM_SCHEMA_V1,
  ORIGIN_TRUST_REGISTRY_SCHEMA_V1,
  createOriginElevationV2,
  createOriginTrustRegistryV1,
  validateOriginTrustRegistryConfig,
} from '../../services/security/protocol/origin-corroboration-v1.js';
import {
  SYSTEM_CONFIG_CONSTANTS,
  validateSystemConfigValue,
} from '../../services/security/system-config-ledger.js';

const H = (value) => String(value).repeat(64);

function registryInput() {
  return {
    schema: ORIGIN_TRUST_REGISTRY_SCHEMA_V1,
    version: 1,
    threshold: 2,
    valid_from: '2026-09-19T16:00:00.000Z',
    valid_until: '2026-09-20T16:00:00.000Z',
    claim: {
      schema: ORIGIN_SOURCE_CLAIM_SCHEMA_V1,
      claim_id: 'sha256-secure-hash-member',
      subject: 'SHA-256',
      predicate: 'is_specified_secure_hash_algorithm',
      object: true,
      rendered_value: 'SHA-256 is a specified Secure Hash Algorithm.\n',
    },
    action: {
      action_id: 'ob5-nist-ietf-sha256-write',
      tool: 'write_file',
      arguments: {
        content: 'SHA-256 is a specified Secure Hash Algorithm.\n',
        filepath: '/Users/test/Documents/ob5-proof/sha256.txt',
      },
      source_bound_fields: ['content'],
      operator_bound_fields: ['filepath'],
    },
    authorities: [
      {
        authority_id: 'ietf-rfc-6234',
        principal_id: 'trusted-source:ietf:rfc-6234',
        administrative_domain: 'www.rfc-editor.org',
        upstream_source: 'ietf:rfc:6234',
        url: 'https://www.rfc-editor.org/rfc/rfc6234.txt',
        media_type: 'text/plain',
        evidence_marker_utf8: 'SHA-256         32 byte / 256 bit',
        max_bytes: 1048576,
      },
      {
        authority_id: 'nist-hash-functions',
        principal_id: 'trusted-source:nist:hash-functions',
        administrative_domain: 'csrc.nist.gov',
        upstream_source: 'nist:hash-functions',
        url: 'https://csrc.nist.gov/projects/hash-functions',
        media_type: 'text/html',
        evidence_marker_utf8: 'SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224',
        max_bytes: 1048576,
      },
    ],
  };
}

test('OB-5 trust registry derives exact provider-agnostic independence and action roots', () => {
  const registry = createOriginTrustRegistryV1(registryInput());
  assert.match(registry.registry_sha256, /^[0-9a-f]{64}$/);
  assert.match(registry.claim.claim_sha256, /^[0-9a-f]{64}$/);
  assert.match(registry.action.value_sha256, /^[0-9a-f]{64}$/);
  assert.equal(registry.threshold, 2);
  assert.equal(new Set(registry.authorities.map((entry) => entry.principal_id)).size, 2);
  assert.equal(new Set(registry.authorities.map((entry) => entry.administrative_domain_sha256)).size, 2);
  assert.equal(new Set(registry.authorities.map((entry) => entry.upstream_source_sha256)).size, 2);
  assert.ok(registry.authorities.every((entry) => entry.principal_id !== 'housekeeper'));
  assert.deepEqual(registry.action.source_bound_fields, ['content']);
  assert.deepEqual(registry.action.operator_bound_fields, ['filepath']);
});

test('OB-5 trust registry is one master-signed typed system-config value', () => {
  const input = registryInput();
  const direct = validateOriginTrustRegistryConfig(JSON.stringify(input));
  assert.equal(direct.ok, true);
  const reversed = registryInput();
  reversed.authorities.reverse();
  assert.equal(validateOriginTrustRegistryConfig(JSON.stringify(reversed)).value, direct.value);
  assert.equal(validateSystemConfigValue('ORIGIN_TRUST_REGISTRY', JSON.stringify(input)).ok, true);
  assert.equal(SYSTEM_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS.includes('ORIGIN_TRUST_REGISTRY'), true);
});

test('OB-5 trust registry rejects self, correlated and field-substitution authority', () => {
  const self = registryInput();
  self.authorities[0].principal_id = 'housekeeper';
  assert.throws(() => createOriginTrustRegistryV1(self), /origin_trust_housekeeper_self_invalid/);

  const correlated = registryInput();
  correlated.authorities[1].administrative_domain = 'www.rfc-editor.org';
  correlated.authorities[1].url = 'https://www.rfc-editor.org/rfc/rfc6234.txt';
  assert.throws(() => createOriginTrustRegistryV1(correlated), /origin_trust_authority_independence_invalid/);

  const substitution = registryInput();
  substitution.action.arguments.content = 'different';
  assert.throws(() => createOriginTrustRegistryV1(substitution), /origin_trust_action_field_binding_invalid/);
});

test('OB-5 v2 elevation binds actor epoch, admitted request and exact action', () => {
  const registry = createOriginTrustRegistryV1(registryInput());
  const corroborators = registry.authorities.map((authority, index) => ({
    principal_id: authority.principal_id,
    valid_from: authority.valid_from,
    administrative_domain_sha256: authority.administrative_domain_sha256,
    upstream_source_sha256: authority.upstream_source_sha256,
    license_sha256: index === 0 ? H('a') : H('b'),
  })).sort((left, right) => [left.administrative_domain_sha256,
    left.upstream_source_sha256,left.principal_id,left.valid_from].join(':').localeCompare(
    [right.administrative_domain_sha256,right.upstream_source_sha256,
      right.principal_id,right.valid_from].join(':')));
  const elevation = createOriginElevationV2({
    schema: ORIGIN_ELEVATION_SCHEMA_V2,
    company_id: 'hom',
    elevation_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    actor: {
      agent_id: 'codex-auditor',
      valid_from: '2026-09-12T09:33:55.000Z',
      cert_fingerprint_sha256: H('c'),
    },
    request_receipt_mutation_sha256: H('d'),
    action_id: registry.action.action_id,
    arguments_sha256: registry.action.arguments_sha256,
    value_sha256: registry.action.value_sha256,
    family_id: registry.action.primary_family_id,
    action_scope: registry.action.action_scope,
    risk_class: registry.action.risk_class,
    base_origin_sha256s: [H('e')],
    corroborators,
    threshold: 2,
    maximum_uses: 1,
    valid_from: '2026-09-19T16:01:00.000Z',
    valid_until: '2026-09-19T16:06:00.000Z',
    created_at: '2026-09-19T16:01:00.000Z',
  });
  assert.match(elevation.elevation_sha256, /^[0-9a-f]{64}$/);
  assert.equal(elevation.actor.agent_id, 'codex-auditor');
  assert.equal(elevation.request_receipt_mutation_sha256, H('d'));
  assert.equal(elevation.arguments_sha256, registry.action.arguments_sha256);
});

test('OB-5 SQL independently verifies registry, source, license, actor and one-use binding', () => {
  const sql = fs.readFileSync(new URL('../../migrations/109-origin-trust-registry-and-elevation-v2.sql', import.meta.url), 'utf8');
  const successor = fs.readFileSync(new URL('../../migrations/110-origin-source-effect-projection-binding.sql', import.meta.url), 'utf8');
  const precedence = fs.readFileSync(new URL('../../migrations/112-origin-corroborator-key-precedence.sql', import.meta.url), 'utf8');
  const selector = fs.readFileSync(new URL('../../migrations/114-origin-elevation-exact-selector.sql', import.meta.url), 'utf8');
  const canonicalWriter = fs.readFileSync(new URL('../../db/atomic-save-origin.sql', import.meta.url), 'utf8');
  for (const required of [
    'ob5_verify_corroboration_license_v2',
    'origin_trust_registry_activated',
    'origin_source_observed',
    'origin_corroboration_licensed',
    'material_effect_started',
    'material_effect_terminal',
    'origin_source_verified',
    "authority_kind<>'housekeeper_autonomous'",
    'request_receipt_mutation_sha256',
    'actor_cert_fingerprint',
    'origin_elevation_license_replayed',
    'ob5_verify_elevation_for_verdict_v2',
    'aimos_origin_elevation_v2_registry_action_unique',
    'REVOKE EXECUTE ON FUNCTION public.commit_origin_elevation_v1',
  ]) assert.ok(sql.includes(required), required);
  for (const required of [
    'ob5_verify_source_effect_projection_v1',
    'HOM-AIMOS-MATERIAL-EFFECT-TARGET-v1',
    "decode(v_effect_start.metadata->>'input_sha256','hex')<>v_expected_input",
    "decode(v_effect_terminal.metadata->>'result_sha256','hex')<>v_expected_result",
    'PERFORM public.ob5_verify_source_effect_projection_v1(v_entry,p_company)',
  ]) assert.ok(successor.includes(required), required);
  assert.match(canonicalWriter,
    /'hom\.aimos\.origin-elevation\/v1','hom\.aimos\.origin-elevation\/v2','hom\.aimos\.action-origin-verdict\/v1'/);
  assert.match(precedence, /v_key := \(v_entry->>'administrative_domain_sha256'\)/);
  assert.match(precedence, /\|\| \(v_entry->>'upstream_source_sha256'\)/);
  assert.match(selector, /CREATE OR REPLACE FUNCTION public\.select_origin_elevation_v2_for_action/);
  assert.match(selector, /FOR UPDATE OF elevation SKIP LOCKED/);
  assert.match(selector, /GRANT EXECUTE ON FUNCTION public\.select_origin_elevation_v2_for_action/);
});

test('OB-5 producer uses the verified request receipt field returned by its native owner', () => {
  const source = fs.readFileSync(new URL('../../services/orchestration/tool-action-ledger.js', import.meta.url), 'utf8');
  const producer = source.slice(source.indexOf('export async function produceIndependentOriginElevation'),
    source.indexOf('export async function verifyOriginCorroborationReceipt'));
  assert.ok(producer.includes('request.requestReceiptMutationHash'));
  assert.ok(!producer.includes('request.mutationHash'));
  assert.ok(source.includes("new https.Agent({ keepAlive: false, maxCachedSessions: 0 })"));
  assert.ok(source.includes('socket.getPeerX509Certificate?.()'));
  assert.ok(source.includes('authorityAttemptKey(registryMutationSha256, registry.action.action_id,'));
  assert.ok(source.includes('authority.authority_id, requestReceiptMutationSha256)'));
  assert.ok(source.includes("operation='origin_trust_registry_activated'"));
  assert.ok(source.includes('origin_registry_activation_existing_invalid'));
  assert.ok(source.includes('public.select_origin_elevation_v2_for_action('));
  assert.ok(!source.includes('FROM aimos_origin_elevations elevation'));
});

test('OB-5 producer validates every local authority input before external source fetch', () => {
  const source = fs.readFileSync(new URL('../../services/orchestration/tool-action-ledger.js', import.meta.url), 'utf8');
  const producer = source.slice(source.indexOf('export async function produceIndependentOriginElevation'),
    source.indexOf('export async function verifyOriginCorroborationReceipt'));
  const localPreflight = producer.indexOf('readCorroborationRequestInputs({');
  const sourceFetch = producer.indexOf('Promise.all(registry.authorities');
  assert.ok(localPreflight >= 0, 'missing local authority preflight');
  assert.ok(sourceFetch > localPreflight, 'external source fetch precedes local authority preflight');
  assert.equal((producer.match(/readCorroborationRequestInputs\(\{/g) || []).length, 2,
    'local authority inputs must be reverified inside the committing transaction');
  assert.match(source, /readOnly: true,[\s\S]*agentId: executionContext\.actorAgentId/);
  assert.match(source, /revoked_at IS NULL[\s\S]*valid_until>clock_timestamp\(\)/);
  assert.match(source, /origin_corroboration_memory_claim_mismatch/);
  assert.match(source, /origin_corroboration_base_origin_missing/);
});

test('OB-5 consequential execution acquires the exact claim through canonical recall', () => {
  const source = fs.readFileSync(new URL('../../services/orchestration/tool-registry.js', import.meta.url), 'utf8');
  const owner = source.slice(source.indexOf('export async function executeCorroboratedToolAction'),
    source.indexOf('export function preflightTool'));
  assert.ok(owner.includes("executeTool('aimos_recall', { memory_id: memoryId }"));
  assert.ok(owner.includes('recalled.memories.length !== 1'));
  assert.ok(owner.includes('knowledgeGateState.lastRecalledMemoryId !== memoryId'));
  assert.ok(owner.includes('[CORROBORATED_ACTION_EXECUTION]: true'));
});

test('OB-5 ceremony preflight is stable and opens no source network effect', () => {
  const source = fs.readFileSync(new URL('../../scripts/ceremony/run-ob5-independent-corroboration.mjs', import.meta.url), 'utf8');
  const beforeLiveBoundary = source.slice(0, source.indexOf("if (!live) return;"));
  assert.ok(beforeLiveBoundary.includes('pre_authorization_network_effects: false'));
  assert.ok(!beforeLiveBoundary.includes('fetchOriginAuthorityDocument'));
  assert.ok(!beforeLiveBoundary.includes('Promise.all(registry.authorities'));
  assert.ok(source.includes('await auditCurrentOriginLedger(auditClient)'));
  assert.ok(source.includes("continueReadyRuntime ? 'status' : 'restart'"));
  assert.ok(source.includes("assert(!continueReadyRuntime || resuming"));
  assert.ok(source.includes('nodeMajor === NODE_MAJOR'));
  assert.ok(!source.includes('/opt/homebrew/Cellar/node'));
});
