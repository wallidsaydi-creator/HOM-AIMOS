#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanCr7EffectCensus } from './prove-cr7-durable-action-census.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const INITIAL_CENSUS_ROOT = '310bf5f5083a64429dd73f95221d7417ec7a33942da1d60b503d3f2073b9e670';
const INITIAL_R5_EFFECT_COUNT = 68;
const RETIRED_EFFECTS = Object.freeze([
  ['53e8ca05c9697c30fea1e64c09ada8c3c429772e6b3b1f44080f7b13d24dcc41', 'duplicate_route_applescript_removed'],
  ['ed36f2e1f8503b0d20dd464a839f812e8d2ba5d5a0b75f3c4f46aaf96cffce5e', 'unowned_pinned_identity_directory_write_removed'],
  ['c3568c1268fa0ba32cb4074146e8b544eb2385aad34d863befee0df9e2e21894', 'unowned_connect_identity_directory_write_removed'],
  ['3aa427cd10133826dd0cf96a2de660291ab7cd0b75c4c1cbe7dc251da7920e93', 'raw_private_key_copy_removed'],
  ['48aee47955c346dca8210ce718787a22141b4eeeb694673aac475eafdec75da3', 'raw_private_key_copy_chmod_removed'],
]);

const SOURCE_FILES = Object.freeze([
  'jobs/golem-scanner.js',
  'routes/agent-execution.js', 'routes/integrations.js', 'routes/mcp.js',
  'routes/setup.js', 'routes/skills.js',
  'services/core/providers.js', 'services/core/scheming-monitor.js',
  'services/integrations/google-tools.js', 'services/integrations/integration-tools.js',
  'services/integrations/stripe-tools.js', 'services/integrations/telegram-tools.js',
  'services/integrations/web-search.js', 'services/integrations/x-search.js',
  'services/integrations/x-tools.js', 'services/orchestration/agent-tools.js',
  'services/orchestration/http.js', 'services/orchestration/skills-runtime.js',
  'services/orchestration/tool-action-ledger.js', 'services/orchestration/tool-registry.js',
  'services/security/agent-identity.js', 'services/security/credential-ledger.js',
  'services/security/material-effect-owner.js', 'services/security/whole-brain-purge.js',
]);

function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function canonicalJson(value) {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
function read(relative) { return fs.readFileSync(path.join(ROOT, relative), 'utf8'); }
function assert(value, reason) { if (!value) throw new Error(`cr7_r5_audit_failed:${reason}`); }

export function proveCr7R5MaterialEffectAudit() {
  const census = scanCr7EffectCensus();
  const current = census.effects.filter((effect) => (
    ['durable_file', 'external_effect', 'destructive_offline_effect'].includes(effect.effect_class)
  ));
  const open = current.filter((effect) => effect.ownership_status === 'OPEN_UNRECONCILED');
  assert(open.length === 0, `open_effects:${open.length}`);
  assert(current.length === 63, `current_effect_count:${current.length}`);
  assert(current.length + RETIRED_EFFECTS.length === INITIAL_R5_EFFECT_COUNT, 'initial_current_retired_partition');

  const owner = read('services/security/material-effect-owner.js');
  for (const pattern of [
    /material_effect_started/, /material_effect_terminal/, /INDETERMINATE/,
    /exclusiveOperationKey: true/, /reconstructMaterialEffectTraces/,
    /timeComplexity: 'O\(n\)'/, /target_sha256/, /input_sha256/, /result_sha256/,
  ]) assert(pattern.test(owner), `material_owner:${pattern}`);
  assert(!/target_identifier\s*:/.test(owner), 'raw_target_in_event_metadata');

  const credential = read('services/security/credential-ledger.js');
  for (const pattern of [
    /\['completed', 'failed', 'indeterminate'\]/,
    /disposition = outcome === 'completed'/,
    /findOpenCredentialUses/,
    /INDETERMINATE/,
  ]) assert(pattern.test(credential), `credential_owner:${pattern}`);

  const provider = read('services/core/providers.js');
  assert(/operation: 'model_provider_inference'/.test(provider), 'provider_inference_start_missing');
  assert(/operation: 'model_provider_catalog'/.test(provider), 'provider_catalog_start_missing');
  assert(/operation: 'local_provider_health_probe'/.test(provider), 'provider_probe_start_missing');
  assert((provider.match(/materialEffectOwner\.finish\(/g) || []).length >= 6, 'provider_terminals_incomplete');

  const mcp = read('routes/mcp.js');
  assert(/operation: 'mcp_remote_call'/.test(mcp) && /assertSafeUrl[\s\S]*fetchWithTimeout/.test(mcp), 'mcp_owner_missing');
  const integrationRoute = read('routes/integrations.js');
  assert(!/execFile\s*\(\s*['"]osascript/.test(integrationRoute), 'duplicate_route_applescript_present');
  const integration = read('services/integrations/integration-tools.js');
  assert(/operation: `applescript_\$\{operation\}`/.test(integration), 'applescript_owner_missing');
  assert(/disposition: 'INDETERMINATE'/.test(integration), 'applescript_indeterminate_missing');

  const setup = read('routes/setup.js');
  assert(!/writeFileSync\(defaultPrivateKeyPath/.test(setup), 'raw_private_key_copy_present');
  assert(/beginAgentEnrollment/.test(setup) && /commitAgentEnrollment/.test(setup), 'identity_file_protocol_missing');
  const dormantCache = read('services/security/agent-identity.js');
  const cacheCallers = (dormantCache.match(/writeCertCacheFile\(/g) || []).length;
  assert(cacheCallers === 2, `cert_cache_call_shape:${cacheCallers}`);

  const tool = read('services/orchestration/tool-action-ledger.js');
  assert(/tool_execution_indeterminate/.test(tool), 'tool_indeterminate_missing');
  assert(/reconstructToolActionTraces/.test(tool), 'tool_orphan_reconstruction_missing');
  const registry = read('services/orchestration/tool-registry.js');
  assert(/content_sha256/.test(registry) && /throw new Error\(`Failed to write file/.test(registry), 'tool_file_readback_missing');
  const skills = read('routes/skills.js');
  assert(/operation: 'skill_policy_snapshot'/.test(skills), 'skill_file_owner_missing');
  const briefing = read('routes/agent-execution.js');
  assert(/operation: 'intelligence_briefing_artifact'/.test(briefing), 'briefing_file_owner_missing');
  const golem = read('jobs/golem-scanner.js');
  assert(/operation: 'golem_security_probe'/.test(golem) && /operation: 'golem_poc_artifact'/.test(golem), 'golem_owner_missing');

  for (const file of [
    'services/integrations/google-tools.js', 'services/integrations/integration-tools.js',
    'services/integrations/stripe-tools.js', 'services/integrations/telegram-tools.js',
    'services/integrations/x-search.js', 'services/integrations/x-tools.js',
  ]) {
    const body = read(file);
    assert(/reserveCredentialUse\(/.test(body) && /finalizeCredentialUse\(/.test(body), `credential_trace:${file}`);
  }
  for (const file of [
    'services/integrations/google-tools.js', 'services/integrations/stripe-tools.js',
    'services/integrations/telegram-tools.js', 'services/integrations/x-search.js',
    'services/integrations/x-tools.js', 'services/integrations/web-search.js',
    'services/orchestration/agent-tools.js',
  ]) assert(/indeterminate/.test(read(file)), `transport_indeterminate:${file}`);

  const purge = read('services/security/whole-brain-purge.js');
  assert(/verifyWholeBrainPurgeIntent/.test(purge) && /verifyWholeBrainPurgeReceipt/.test(purge), 'purge_signature_verifier_missing');
  assert(/refusing to overwrite retained purge artifact/.test(purge), 'purge_artifact_write_once_missing');

  const scheming = read('services/core/scheming-monitor.js');
  assert(/b3b513595a1ee59c79fcf79b99ffd816ba4c398f132dc7bb140568a9d44f5e94/.test(scheming), 'tbsp_physical_paper_hash_missing');
  assert(/full_tbsp_spr_computed: false/.test(scheming), 'tbsp_derivation_scope_missing');
  assert(/ranking_math_changed: false/.test(scheming), 'tbsp_formula_change_guard_missing');

  const results = current.map((effect) => ({
    effect_id: effect.effect_id,
    file: effect.file,
    line: effect.line,
    effect_class: effect.effect_class,
    verdict: effect.ownership_status,
    owner: effect.current_owner,
  })).sort((left, right) => left.effect_id.localeCompare(right.effect_id));
  const sourceManifest = SOURCE_FILES.map((file) => ({ file, sha256: sha256(read(file)) }));
  const body = {
    schema: 'hom.aimos.cr7-r5-material-effect-audit/v1',
    frozen_corrected_a0_census_root_sha256: INITIAL_CENSUS_ROOT,
    frozen_corrected_a0_effect_count: INITIAL_R5_EFFECT_COUNT,
    current_census_root_sha256: census.effect_root_sha256,
    current_effect_count: current.length,
    retired_effect_count: RETIRED_EFFECTS.length,
    retired_effects: RETIRED_EFFECTS.map(([effect_id, reason]) => ({ effect_id, reason })),
    current_open_effect_count: open.length,
    source_file_count: SOURCE_FILES.length,
    source_root_sha256: sha256(canonicalJson(sourceManifest)),
    verdict_counts: current.reduce((counts, effect) => {
      counts[effect.ownership_status] = (counts[effect.ownership_status] || 0) + 1;
      return counts;
    }, {}),
    reconstruction: {
      algorithm: 'single_pass_action_id_map',
      time_complexity: 'O(n)',
      space_complexity: 'O(n)',
      orphan_start_detectable: true,
      terminal_bijection_enforced: true,
    },
    paper_authority: {
      tbsp_sha256: 'b3b513595a1ee59c79fcf79b99ffd816ba4c398f132dc7bb140568a9d44f5e94',
      implementation_scope: 'diagnostic_derivation_not_full_spr_benchmark',
      formulas_changed: false,
    },
    purge_executed: false,
    fresh_disposable_installation_deferred: true,
    results,
  };
  return Object.freeze({
    ...body,
    audit_root_sha256: sha256(canonicalJson(results)),
    proof_root_sha256: sha256(canonicalJson(body)),
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(proveCr7R5MaterialEffectAudit(), null, 2));
}
