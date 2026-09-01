#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanCr7EffectCensus } from './prove-cr7-durable-action-census.mjs';
import { proveCr7R1ExistingLedgerOwners } from './prove-cr7-r1-existing-ledger-owners.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), 'utf8');
}

export function proveCr7R2DatabaseLocalClosure() {
  const census = scanCr7EffectCensus();
  const currentAudit = proveCr7R1ExistingLedgerOwners();
  const conceptEdge = read('services/security/concept-edge-provenance.js');
  const conceptGraph = read('services/core/concept-graph.js');
  const persistence = read('services/write/persist-memory.js');
  const restrictedDefaults = [
    'services/security/memory-provenance.js',
    'services/security/memory-lineage.js',
    'services/security/save-envelope.js',
  ];
  const offlineOwners = [
    ['services/governance/governor-config-ledger.js', 'GOVERNOR_CONFIG_MUTATION_SCOPE'],
    ['services/security/system-config-ledger.js', 'SYSTEM_CONFIG_MUTATION_SCOPE'],
    ['services/security/recall-authorization.js', 'RECALL_AUTHORIZATION_MUTATION_SCOPE'],
  ];
  const checks = Object.freeze({
    historical_r0_effect_count: 160,
    current_effect_count: census.effect_site_count,
    broad_concept_edge_writer_removed: !/INSERT\s+INTO\s+concept_edges|appendSignedConceptEdge|withTransaction/.test(conceptEdge)
      && !/appendSignedConceptEdge|linkToConcepts|linkDerived/.test(conceptGraph),
    entity_edge_exact_projection: /memory_entity_edges_committed/.test(persistence)
      && /entity_edge_projection_root_sha256/.test(persistence)
      && /RETURNING id, company_id, entity, entity_type, memory_id/.test(persistence),
    restricted_standalone_defaults: restrictedDefaults.every((file) => /agentPool as defaultPool/.test(read(file))
      && !/pool as defaultPool/.test(read(file))),
    offline_maintenance_scopes: offlineOwners.every(([file, constant]) =>
      new RegExp(`${constant} = 'offline_maintenance_only'`).test(read(file))),
    runtime_open_sites_preserved_for_later_gates: census.by_ownership_status.OPEN_UNRECONCILED || 0,
    external_partial_sites_preserved_for_r5: currentAudit.verdict_counts.PARTIAL || 0,
    external_complete_sites_closed_by_r5: currentAudit.verdict_counts.COMPLETE_START_TERMINAL || 0,
  });
  const valid = checks.current_effect_count === 159
    || checks.current_effect_count < 159;
  const preserved = valid
    && checks.broad_concept_edge_writer_removed
    && checks.entity_edge_exact_projection
    && checks.restricted_standalone_defaults
    && checks.offline_maintenance_scopes
    && checks.runtime_open_sites_preserved_for_later_gates <= 111
    && checks.external_partial_sites_preserved_for_r5 === 0
    && checks.external_complete_sites_closed_by_r5 === 14
    && currentAudit.verdict_counts.ATOMIC === 23
    && census.by_ownership_status.OFFLINE_SIGNED_MAINTENANCE === 3;
  const body = Object.freeze({
    schema: 'hom.aimos.cr7-r2-database-local-closure/v1',
    input_r0_census_root_sha256: 'e88014e74428497a98388a11c941760c7b831d62be64c649aa69f865064d498e',
    input_r1_audit_root_sha256: '3a4ec8d90b086a7e3382584a6eaa5ed6b10ac2fd42945440d111693afc368c1c',
    frozen_r2_census_root_sha256: '648ce46c02ca493b4a2e6620c42656f646cd017fd5a91ba32dbf08d4185be1c4',
    frozen_r2_owner_audit_root_sha256: 'a3715ebc1213c239863859f8a141264ec41ae1f4e9c47bb1292a6f705f5f57b3',
    frozen_r2_proof_root_sha256: '84dcd1bc3331d10bc67c48d696852d78c90f1d6057acfd732f139376f840861f',
    current_census_root_sha256: census.effect_root_sha256,
    current_owner_audit_root_sha256: currentAudit.audit_root_sha256,
    checks,
    migration_added: false,
    valid: preserved,
  });
  return Object.freeze({ ...body, proof_root_sha256: sha256(Buffer.from(canonicalJson(body), 'utf8')) });
}

function main() {
  const result = proveCr7R2DatabaseLocalClosure();
  if (!result.valid) throw new Error('cr7_r2_database_local_closure_failed');
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
