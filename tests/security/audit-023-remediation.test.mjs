import assert from 'node:assert/strict';
import test from 'node:test';
import { currentOriginSourceContract } from '../../scripts/verification/audit-origin-ledger-current.mjs';

test('current origin expectations select exact latest native SQL owners, including atomicity and OB5', () => {
  const contract = currentOriginSourceContract();
  assert.equal(contract.sources.length, 23);
  assert.deepEqual(contract.sources.filter(s => s.path.startsWith('db/')).map(s => s.path), [
    'db/request-target.sql', 'db/signed-request-bytes.sql', 'db/atomic-save-origin.sql',
    'db/signed-json-bytes.sql', 'db/signed-event-bytes.sql', 'db/cognitive-ancestry.sql',
  ]);
  assert.equal(contract.sources.at(-1).path, 'migrations/001-base-schema.sql');
  assert.equal(contract.triggerTables.length, 8);
  assert.deepEqual(contract.occurrenceUniqueness.name, ['public','aimos_memory_origin_bindings_occurrence_id_key']);
  assert.equal(contract.functions.size, 39);
  for (const [name, source] of Object.entries({
    request_target_valid_v5: 'db/request-target.sql',
    request_signature_message_v5: 'db/request-target.sql',
    ob2_verify_signed_request_bytes: 'db/signed-request-bytes.sql',
    signed_json_shape_v1: 'db/signed-json-bytes.sql',
    signed_json_bytes_commitment_v1: 'db/signed-json-bytes.sql',
    require_signed_event_bytes_v1: 'db/signed-event-bytes.sql',
    ob2_verify_signed_event: 'db/signed-event-bytes.sql',
    verify_cognitive_ancestry_bridge_v1: 'db/cognitive-ancestry.sql',
    apply_signed_cognitive_reweight: 'db/cognitive-ancestry.sql',
    verify_cognitive_weight_chain: 'db/cognitive-ancestry.sql',
  })) assert.equal(contract.functions.get(name).source, source, name);
  assert.equal(contract.functions.get('commit_memory_origin_binding_v2').source, 'db/atomic-save-origin.sql');
  assert.equal(contract.functions.get('commit_action_origin_verdict_v1').source, 'migrations/109-origin-trust-registry-and-elevation-v2.sql');
  assert.equal(contract.functions.get('commit_origin_elevation_v1').source, 'migrations/107-origin-elevation-license-binding.sql');
  assert.equal(contract.functions.get('commit_origin_elevation_v2').source, 'migrations/113-origin-elevation-attempt-continuity.sql');
  assert.equal(contract.functions.get('ob5_verify_corroboration_license_v2').source, 'migrations/109-origin-trust-registry-and-elevation-v2.sql');
  assert.equal(contract.functions.get('ob5_verify_elevation_for_verdict_v2').source, 'migrations/113-origin-elevation-attempt-continuity.sql');
  assert.equal(contract.functions.get('ob5_verify_source_effect_projection_v1').source, 'migrations/110-origin-source-effect-projection-binding.sql');
  assert.equal(contract.functions.get('ob5_verify_operator_action_authorization').source, 'migrations/108-operator-action-authorization-verifier.sql');
  assert.equal(contract.functions.get('ob2_validate_corroborators').source, 'migrations/112-origin-corroborator-key-precedence.sql');
  assert.equal(contract.functions.get('select_origin_elevation_v2_for_action').source,
    'migrations/114-origin-elevation-exact-selector.sql');
  assert.equal(contract.functions.get('ob2_origin_database_context_hash').source,
    'migrations/115-origin-ledger-genesis-context.sql');
  assert.equal(contract.functions.get('ob2_read_origin_ledger_state').source,
    'migrations/115-origin-ledger-genesis-context.sql');
  assert.match(contract.functions.get('ob2_origin_database_context_hash').body,
    /v_anchor_kind := 'housekeeper_genesis'/);
  assert.match(contract.functions.get('ob2_read_origin_ledger_state').body,
    /database_context_sha256 := public\.ob2_origin_database_context_hash/);
  assert.match(contract.functions.get('ob2_read_origin_ledger_state').body,
    /v_head_count = 0 AND v_entry_count > 0/);
  assert.equal(contract.triggers.length, 5);
  assert.equal(contract.indexes.length, 6);
  assert(contract.foreignKeys.length > 15);
  assert.equal(contract.triggers.filter(t => t[4]).length, 4);
  for (const expected of contract.functions.values()) {
    assert(expected.identity.startsWith(`public.${expected.name}(`));
    assert(expected.body.length > 0);
    assert(expected.config[0].startsWith('search_path=pg_catalog'));
  }
});
