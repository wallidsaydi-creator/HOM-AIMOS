import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  ORIGIN_BINDING_SCHEMAS_V1,
  ORIGIN_FAMILY_PROFILE_BODY_V1,
  ORIGIN_FAMILY_PROFILE_SHA256_V1,
  createActionOriginVerdictV1,
  createMemoryOriginBindingV1,
  createOriginElevationV1,
  originFamilyClosureV1,
  originProtocolBytesV1,
  originProtocolDomainHexV1,
  verifyOriginDerivationV1,
} from '../../services/security/protocol/origin-binding-v1.js';
import {
  actionVerdict,
  actionVerdictInput,
  clone,
  corroborators,
  derivedBinding,
  derivedBindingInput,
  elevation,
  elevationInput,
  trustedBinding,
  trustedBindingInput,
  untrustedBinding,
  untrustedBindingInput,
} from '../../scripts/verification/origin-binding-ob1-fixtures.mjs';

test('OB-1 family profile and domains are byte-fixed', () => {
  assert.equal(ORIGIN_FAMILY_PROFILE_BODY_V1.families.length, 30);
  assert.equal(
    ORIGIN_FAMILY_PROFILE_SHA256_V1,
    '49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24',
  );
  assert.deepEqual(originProtocolDomainHexV1(), {
    family_profile: '686f6d2e61696d6f732e6f726967696e2d66616d696c792d70726f66696c652f763100',
    memory_binding: '686f6d2e61696d6f732e6d656d6f72792d6f726967696e2d62696e64696e672f763100',
    elevation: '686f6d2e61696d6f732e6f726967696e2d656c65766174696f6e2f763100',
    action_verdict: '686f6d2e61696d6f732e616374696f6e2d6f726967696e2d766572646963742f763100',
  });
  const bytes = originProtocolBytesV1(ORIGIN_FAMILY_PROFILE_BODY_V1);
  assert.equal(bytes.subarray(0, bytes.indexOf(0) + 1).toString('utf8'),
    `${ORIGIN_BINDING_SCHEMAS_V1.family_profile}\0`);
});

test('OB-1 family closure is deterministic, multi-family, and ancestry-complete', () => {
  assert.deepEqual(originFamilyClosureV1([
    'secret.credential',
    'action_input.external_destination',
  ]), [
    'action_input',
    'action_input.external_destination',
    'secret',
    'secret.credential',
  ]);
  assert.deepEqual(
    originFamilyClosureV1(['action_input.external_destination', 'secret.credential']),
    originFamilyClosureV1(['secret.credential', 'action_input.external_destination']),
  );
});

test('OB-1 canonical objects have stable commitments and exact valid derivation', () => {
  const parent = untrustedBinding();
  const child = derivedBinding(parent);
  const trusted = trustedBinding();
  const license = elevation(parent);
  const verdict = actionVerdict(parent);
  assert.equal(parent.binding_sha256,
    'bd5c1fc01daf3dc3d71ffd55c086576b9e2c487aa683eb81277fcfff3cbefb98');
  assert.equal(child.binding_sha256,
    'dc421be4c359f82501cce6cf0470116885d34b5d0792b00e7a41c1bafc4eeb4e');
  assert.equal(trusted.binding_sha256,
    '43e2dfa00d179d353e24813501a961796e1c320dd9675c602c4bf65042934391');
  assert.equal(license.elevation_sha256,
    '52c4b0e850d6006a8f5e2a2441c155953a7500089501d4d029079edd2d294b77');
  assert.equal(verdict.verdict_sha256,
    '5f7bd4e5fddedf94bf21d2dfa70d7168684501f6477818a847354a11fc859850');
  assert.deepEqual(verifyOriginDerivationV1({ child, parents: [parent] }), {
    valid: true,
    parent_count: 1,
  });
});

test('OB-1 rejects caller/model classification authority and unknown families', () => {
  const caller = untrustedBindingInput();
  caller.classification.authority = 'caller';
  assert.throws(() => createMemoryOriginBindingV1(caller),
    /origin_binding_v1:enum_invalid/);
  const unknown = untrustedBindingInput();
  unknown.classification.family_ids = ['unknown.future_family'];
  assert.throws(() => createMemoryOriginBindingV1(unknown),
    /origin_binding_v1:family_id_invalid/);
});

test('OB-1 rejects family order, duplicates, incomplete ancestry, and stale profile', () => {
  const order = untrustedBindingInput();
  order.classification.family_ids = [...order.classification.family_ids].reverse();
  assert.throws(() => createMemoryOriginBindingV1(order),
    /origin_binding_v1:family_order_invalid/);
  const duplicate = untrustedBindingInput();
  duplicate.classification.family_ids = [
    ...duplicate.classification.family_ids,
    duplicate.classification.family_ids.at(-1),
  ];
  assert.throws(() => createMemoryOriginBindingV1(duplicate),
    /origin_binding_v1:family_duplicate/);
  const ancestry = untrustedBindingInput();
  ancestry.classification.family_ids = ['information.fact'];
  assert.throws(() => createMemoryOriginBindingV1(ancestry),
    /origin_binding_v1:family_closure_invalid/);
  const profile = untrustedBindingInput();
  profile.classification.profile_sha256 = '99'.repeat(32);
  assert.throws(() => createMemoryOriginBindingV1(profile),
    /origin_binding_v1:family_profile_hash_invalid/);
});

test('OB-1 enforces family confidentiality floor and channel integrity ceiling', () => {
  const confidentiality = trustedBindingInput({ confidentiality: 'internal' });
  assert.throws(() => createMemoryOriginBindingV1(confidentiality),
    /origin_binding_v1:family_confidentiality_floor_invalid/);
  const channel = untrustedBindingInput({ integrity: 'agent', action_class: 'inform' });
  assert.throws(() => createMemoryOriginBindingV1(channel),
    /origin_binding_v1:channel_integrity_invalid/);
  const action = untrustedBindingInput({ action_class: 'inform' });
  assert.throws(() => createMemoryOriginBindingV1(action),
    /origin_binding_v1:integrity_action_class_invalid/);
});

test('OB-1 rejects missing parent bindings and family stripping', () => {
  const parent = untrustedBinding();
  const wrongParent = derivedBinding(parent);
  const childInput = derivedBindingInput(parent);
  childInput.parents.origin_sha256s = ['98'.repeat(32)];
  const child = createMemoryOriginBindingV1(childInput);
  assert.throws(() => verifyOriginDerivationV1({ child, parents: [parent] }),
    /origin_binding_v1:parent_binding_invalid/);

  const strippedInput = derivedBindingInput(parent);
  strippedInput.classification.family_ids = originFamilyClosureV1(['derived.summary']);
  const stripped = createMemoryOriginBindingV1(strippedInput);
  assert.throws(() => verifyOriginDerivationV1({ child: stripped, parents: [parent] }),
    /origin_binding_v1:family_closure_invalid/);
  assert.equal(wrongParent.parents.origin_sha256s[0], parent.binding_sha256);
});

test('OB-1 rejects confidentiality downgrade across derivation', () => {
  const parent = createMemoryOriginBindingV1(untrustedBindingInput({
    confidentiality: 'confidential',
  }));
  const child = createMemoryOriginBindingV1(derivedBindingInput(parent, {
    confidentiality: 'internal',
  }));
  assert.throws(() => verifyOriginDerivationV1({ child, parents: [parent] }),
    /origin_binding_v1:confidentiality_downgrade/);
});

test('OB-1 rejects integrity elevation across derivation', () => {
  const parent = untrustedBinding();
  const child = createMemoryOriginBindingV1(derivedBindingInput(parent, {
    integrity: 'agent',
    action_class: 'inform',
  }));
  assert.throws(() => verifyOriginDerivationV1({ child, parents: [parent] }),
    /origin_binding_v1:integrity_elevation/);
});

test('OB-1 rejects action-class elevation across derivation', () => {
  const parent = createMemoryOriginBindingV1(trustedBindingInput({ action_class: 'none' }));
  const input = derivedBindingInput(parent, {
    origin: {
      ingress_channel: 'system_internal',
      channel_identity_sha256: '71'.repeat(32),
    },
    confidentiality: 'confidential',
    integrity: 'trusted',
    action_class: 'inform',
  });
  const child = createMemoryOriginBindingV1(input);
  assert.throws(() => verifyOriginDerivationV1({ child, parents: [parent] }),
    /origin_binding_v1:action_class_elevation/);
});

test('OB-1 maximum parent set verifies in one bounded pass despite repeated families', () => {
  const parents = Array.from({ length: 64 }, (_, index) => {
    const ordinal = String(index + 100).padStart(12, '0');
    return createMemoryOriginBindingV1(untrustedBindingInput({
      memory_id: `20000000-0000-4000-8000-${ordinal}`,
      occurrence_id: `30000000-0000-4000-8000-${ordinal}`,
      content_sha256: (index + 1).toString(16).padStart(64, '0'),
    }));
  });
  const childInput = derivedBindingInput(parents[0]);
  childInput.parents.origin_sha256s = parents
    .map((parent) => parent.binding_sha256)
    .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  const child = createMemoryOriginBindingV1(childInput);
  assert.deepEqual(verifyOriginDerivationV1({ child, parents }), {
    valid: true,
    parent_count: 64,
  });
});

test('OB-1 elevation requires independent corroborators or exact user authority', () => {
  const parent = untrustedBinding();
  const correlated = elevationInput(parent);
  correlated.corroborators = corroborators();
  correlated.corroborators[1].administrative_domain_sha256 =
    correlated.corroborators[0].administrative_domain_sha256;
  assert.throws(() => createOriginElevationV1(correlated),
    /origin_binding_v1:corroborator_independence_invalid/);

  const insufficient = elevationInput(parent, { corroborators: [corroborators()[0]] });
  assert.throws(() => createOriginElevationV1(insufficient),
    /origin_binding_v1:elevation_authority_invalid/);

  const userAuthorized = elevationInput(parent, {
    corroborators: [],
    user_authorization_sha256: '72'.repeat(32),
  });
  assert.match(createOriginElevationV1(userAuthorized).elevation_sha256, /^[0-9a-f]{64}$/);
});

test('OB-1 action verdict semantics fail closed', () => {
  const parent = untrustedBinding();
  const missing = actionVerdictInput(parent, {
    elevation_sha256: null,
    user_authorization_sha256: null,
  });
  assert.throws(() => createActionOriginVerdictV1(missing),
    /origin_binding_v1:verdict_semantics_invalid/);

  const deniedWithoutReason = actionVerdictInput(parent, {
    decision: 'DENY',
    failure_code: null,
  });
  assert.throws(() => createActionOriginVerdictV1(deniedWithoutReason),
    /origin_binding_v1:verdict_semantics_invalid/);

  const denied = actionVerdictInput(parent, {
    elevation_sha256: null,
    decision: 'DENY',
    failure_code: 'untrusted_influence_unlicensed',
  });
  assert.match(createActionOriginVerdictV1(denied).verdict_sha256, /^[0-9a-f]{64}$/);
});

test('OB-1 action verdict binds every exact value to its classification families', () => {
  const parent = untrustedBinding();
  const substituted = actionVerdictInput(parent);
  substituted.security_values[0].family_ids = [
    'action_input',
    'action_input.financial_value',
  ];
  assert.throws(() => createActionOriginVerdictV1(substituted),
    /origin_binding_v1:security_value_family_binding_invalid/);

  const reordered = actionVerdictInput(parent);
  reordered.security_values = [...reordered.security_values].reverse();
  assert.throws(() => createActionOriginVerdictV1(reordered),
    /origin_binding_v1:security_value_order_invalid/);
});

test('OB-1 protocol owner has no runtime, signer, database, network, or policy mutation authority', async () => {
  const source = await readFile(
    new URL('../../services/security/protocol/origin-binding-v1.js', import.meta.url),
    'utf8',
  );
  assert.deepEqual(
    [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]),
    ['node:crypto', './canonical-json.js'],
  );
  assert.doesNotMatch(source,
    /process\.env|fetch\(|readFile\(|writeFile\(|query\(|pool\.|sign\(|createPrivateKey|routes\/|jobs\//);
  assert.match(source, /Status: OB-1 protocol only/);
});

test('OB-1 protocol outputs are immutable and do not mutate caller input', () => {
  const input = untrustedBindingInput();
  const snapshot = clone(input);
  const binding = createMemoryOriginBindingV1(input);
  assert.deepEqual(input, snapshot);
  assert(Object.isFrozen(binding));
  assert(Object.isFrozen(binding.classification.family_ids));
  assert.throws(() => { binding.integrity = 'trusted'; }, TypeError);
});
