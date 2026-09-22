// Deterministic authority-free fixtures for Phase 1 OB-1 protocol vectors.

import {
  ORIGIN_BINDING_SCHEMAS_V1,
  ORIGIN_FAMILY_PROFILE_SHA256_V1,
  createActionOriginVerdictV1,
  createMemoryOriginBindingV1,
  createOriginElevationV1,
  originFamilyClosureV1,
} from '../../services/security/protocol/origin-binding-v1.js';

export const OB1_FIXTURE = Object.freeze({
  company_id: 'hom',
  actor_id: 'codex-auditor',
  actor_valid_from: '2026-08-10T18:49:54.000Z',
  actor_fingerprint: 'aa'.repeat(32),
  request_id: '10000000-0000-4000-8000-000000000001',
  request_mutation: 'bb'.repeat(32),
  untrusted_memory_id: '20000000-0000-4000-8000-000000000001',
  untrusted_occurrence_id: '30000000-0000-4000-8000-000000000001',
  derived_memory_id: '20000000-0000-4000-8000-000000000002',
  derived_occurrence_id: '30000000-0000-4000-8000-000000000002',
  trusted_memory_id: '20000000-0000-4000-8000-000000000003',
  trusted_occurrence_id: '30000000-0000-4000-8000-000000000003',
  content_untrusted: 'cc'.repeat(32),
  content_derived: 'dd'.repeat(32),
  content_trusted: 'ee'.repeat(32),
  classification_evidence: '12'.repeat(32),
  channel_untrusted: '13'.repeat(32),
  channel_agent: '14'.repeat(32),
  channel_user: '15'.repeat(32),
  elevation_id: '40000000-0000-4000-8000-000000000001',
  verdict_id: '50000000-0000-4000-8000-000000000001',
  tool_action_id: '60000000-0000-4000-8000-000000000001',
  created_at: '2026-09-01T16:00:00.000Z',
});

export function clone(value) {
  return structuredClone(value);
}

export function actor() {
  return {
    agent_id: OB1_FIXTURE.actor_id,
    valid_from: OB1_FIXTURE.actor_valid_from,
    cert_fingerprint_sha256: OB1_FIXTURE.actor_fingerprint,
  };
}

export function request() {
  return {
    receipt_id: OB1_FIXTURE.request_id,
    mutation_sha256: OB1_FIXTURE.request_mutation,
  };
}

export function untrustedBindingInput(overrides = {}) {
  const base = {
    schema: ORIGIN_BINDING_SCHEMAS_V1.memory_binding,
    company_id: OB1_FIXTURE.company_id,
    memory_id: OB1_FIXTURE.untrusted_memory_id,
    occurrence_id: OB1_FIXTURE.untrusted_occurrence_id,
    content_sha256: OB1_FIXTURE.content_untrusted,
    actor: actor(),
    request: request(),
    origin: {
      ingress_channel: 'untrusted_external',
      channel_identity_sha256: OB1_FIXTURE.channel_untrusted,
    },
    parents: { origin_sha256s: [] },
    classification: {
      profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
      family_ids: originFamilyClosureV1([
        'information.fact',
        'action_input.executable_instruction',
      ]),
      authority: 'deterministic_route_schema',
      evidence_sha256: OB1_FIXTURE.classification_evidence,
    },
    confidentiality: 'internal',
    integrity: 'untrusted',
    action_class: 'none',
    scope: 'global',
    session_id: 'phase1-ob1-session',
    tool_action_event_id: null,
    created_at: OB1_FIXTURE.created_at,
  };
  return { ...base, ...overrides };
}

export function untrustedBinding() {
  return createMemoryOriginBindingV1(untrustedBindingInput());
}

export function derivedBindingInput(parent = untrustedBinding(), overrides = {}) {
  const base = {
    schema: ORIGIN_BINDING_SCHEMAS_V1.memory_binding,
    company_id: OB1_FIXTURE.company_id,
    memory_id: OB1_FIXTURE.derived_memory_id,
    occurrence_id: OB1_FIXTURE.derived_occurrence_id,
    content_sha256: OB1_FIXTURE.content_derived,
    actor: actor(),
    request: request(),
    origin: {
      ingress_channel: 'agent_self',
      channel_identity_sha256: OB1_FIXTURE.channel_agent,
    },
    parents: { origin_sha256s: [parent.binding_sha256] },
    classification: {
      profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
      family_ids: originFamilyClosureV1([
        ...parent.classification.family_ids,
        'derived.summary',
      ]),
      authority: 'system_producer_schema',
      evidence_sha256: '16'.repeat(32),
    },
    confidentiality: 'internal',
    integrity: 'untrusted',
    action_class: 'none',
    scope: 'global',
    session_id: 'phase1-ob1-session',
    tool_action_event_id: null,
    created_at: '2026-09-01T16:01:00.000Z',
  };
  return { ...base, ...overrides };
}

export function derivedBinding(parent = untrustedBinding()) {
  return createMemoryOriginBindingV1(derivedBindingInput(parent));
}

export function trustedBindingInput(overrides = {}) {
  const base = {
    schema: ORIGIN_BINDING_SCHEMAS_V1.memory_binding,
    company_id: OB1_FIXTURE.company_id,
    memory_id: OB1_FIXTURE.trusted_memory_id,
    occurrence_id: OB1_FIXTURE.trusted_occurrence_id,
    content_sha256: OB1_FIXTURE.content_trusted,
    actor: actor(),
    request: request(),
    origin: {
      ingress_channel: 'authenticated_user',
      channel_identity_sha256: OB1_FIXTURE.channel_user,
    },
    parents: { origin_sha256s: [] },
    classification: {
      profile_sha256: ORIGIN_FAMILY_PROFILE_SHA256_V1,
      family_ids: originFamilyClosureV1(['action_input.financial_value']),
      authority: 'deterministic_field_schema',
      evidence_sha256: '17'.repeat(32),
    },
    confidentiality: 'confidential',
    integrity: 'trusted',
    action_class: 'act',
    scope: 'payment.create',
    session_id: 'phase1-ob1-session',
    tool_action_event_id: OB1_FIXTURE.tool_action_id,
    created_at: '2026-09-01T16:02:00.000Z',
  };
  return { ...base, ...overrides };
}

export function trustedBinding() {
  return createMemoryOriginBindingV1(trustedBindingInput());
}

export function corroborators() {
  return [
    {
      principal_id: 'bank-registry',
      valid_from: '2026-09-01T15:00:00.000Z',
      administrative_domain_sha256: '21'.repeat(32),
      upstream_source_sha256: '31'.repeat(32),
      license_sha256: '41'.repeat(32),
    },
    {
      principal_id: 'internal-registry',
      valid_from: '2026-09-01T15:00:00.000Z',
      administrative_domain_sha256: '22'.repeat(32),
      upstream_source_sha256: '32'.repeat(32),
      license_sha256: '42'.repeat(32),
    },
  ];
}

export function elevationInput(baseOrigin = untrustedBinding(), overrides = {}) {
  const base = {
    schema: ORIGIN_BINDING_SCHEMAS_V1.elevation,
    company_id: OB1_FIXTURE.company_id,
    elevation_id: OB1_FIXTURE.elevation_id,
    value_sha256: '51'.repeat(32),
    family_id: 'action_input.external_destination',
    action_scope: 'payment.create',
    risk_class: 'consequential',
    base_origin_sha256s: [baseOrigin.binding_sha256],
    corroborators: corroborators(),
    threshold: 2,
    user_authorization_sha256: null,
    maximum_uses: 1,
    valid_from: '2026-09-01T16:00:00.000Z',
    valid_until: '2026-09-01T17:00:00.000Z',
    created_at: '2026-09-01T16:03:00.000Z',
  };
  return { ...base, ...overrides };
}

export function elevation(baseOrigin = untrustedBinding()) {
  return createOriginElevationV1(elevationInput(baseOrigin));
}

export function actionVerdictInput(baseOrigin = untrustedBinding(), overrides = {}) {
  const license = elevation(baseOrigin);
  const base = {
    schema: ORIGIN_BINDING_SCHEMAS_V1.action_verdict,
    company_id: OB1_FIXTURE.company_id,
    verdict_id: OB1_FIXTURE.verdict_id,
    actor: actor(),
    tool_name: 'payment-create',
    action_scope: 'payment.create',
    risk_class: 'consequential',
    arguments_sha256: '61'.repeat(32),
    security_values: [
      {
        value_sha256: '62'.repeat(32),
        family_ids: originFamilyClosureV1(['action_input.external_destination']),
      },
      {
        value_sha256: '63'.repeat(32),
        family_ids: originFamilyClosureV1(['action_input.financial_value']),
      },
    ],
    family_ids: originFamilyClosureV1([
      'action_input.external_destination',
      'action_input.financial_value',
    ]),
    input_origin_sha256s: [baseOrigin.binding_sha256],
    untrusted_influence: true,
    elevation_sha256: license.elevation_sha256,
    user_authorization_sha256: null,
    decision: 'ALLOW',
    failure_code: null,
    previous_verdict_sha256: null,
    created_at: '2026-09-01T16:04:00.000Z',
  };
  return { ...base, ...overrides };
}

export function actionVerdict(baseOrigin = untrustedBinding()) {
  return createActionOriginVerdictV1(actionVerdictInput(baseOrigin));
}
