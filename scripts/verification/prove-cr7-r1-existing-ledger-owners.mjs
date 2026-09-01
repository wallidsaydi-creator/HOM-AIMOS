#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanCr7EffectCensus } from './prove-cr7-durable-action-census.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CANDIDATE_PREFIX = 'CANDIDATE_';
const sqlInsert = (table) => new RegExp(`INSERT\\s+INTO\\s+(?:public\\.)?${table}`);
const sqlUpdate = (table) => new RegExp(`UPDATE\\s+${table}`);

const FAMILY_CONTRACTS = Object.freeze({
  'services/core/permissions.js': {
    family: 'authorization_event_ledger',
    require: [/agentPool\.connect\(\)/, /authorizationMutationHash\(/, /verified_authorization_envelope_required/, sqlInsert('aimos_authorization_events'), /await client\.query\('COMMIT'\)/, /await client\.query\('ROLLBACK'\)/],
    tests: ['tests/security/execution-context-contract.test.mjs'],
  },
  'services/governance/governor-config-ledger.js': {
    family: 'governor_config_ledger',
    require: [/signAsHousekeeper\(/, /_computeMutationHash\(/, sqlInsert('aimos_governor_config'), /await client\.query\('COMMIT'\)/, /await client\.query\('ROLLBACK'\)/],
    tests: ['tests/security/governor-config-proof.test.mjs'],
  },
  'services/governance/valence-ledger.js': {
    family: 'valence_ledger',
    require: [/transaction_client_required/, /const signed = await signer\(body\)/, /rowHash\(/, sqlInsert('memory_valence_ledger')],
    tests: ['tests/security/valence-ledger-proof.test.mjs'],
  },
  'services/observe/event-ledger.js': {
    family: 'universal_event_ledger',
    require: [/eventMutationHash\(/, /signPayload\(/, sqlInsert('aimos_events'), /options\.client \|\| await agentPool\.connect\(\)/, /if \(ownsTransaction\) await client\.query\('COMMIT'\)/],
    tests: ['tests/security/event-ledger-proof.test.mjs', 'tests/security/event-ledger-db.test.mjs'],
  },
  'services/retrieval/concept-ppr-native.js': {
    family: 'concept_ppr_projection',
    require: [/logEvent\(company, 'concept-ppr'/, /\{\s*client,\s*returnReceipt: true/, /authority_event_id/, /withTransaction\(async \(client\)/, /restricted: true/],
    tests: ['tests/retrieval/concept-ppr-native.test.mjs'],
  },
  'services/retrieval/quim-index.js': {
    family: 'quim_projection',
    require: [/logEvent\(company, 'quim-index'/, /\{\s*client,\s*returnReceipt: true/, /authority_event_id/, /withTransaction\(async \(client\)/, /restricted: true/],
    tests: ['tests/retrieval/quim-native.test.mjs'],
  },
  'services/security/concept-edge-provenance.js': {
    family: 'concept_edge_projection',
    require: [/logEvent\([\s\S]*\{ client, authority, returnReceipt: true \}/, sqlInsert('concept_edges'), /withTransaction\(/, /restricted: false/, /no receipt foreign key/i],
    tests: ['tests/security/concept-edge-provenance.test.mjs'],
    forceVerdict: 'PARTIAL',
    limitations: [
      'same_transaction_code_level_commitment_only',
      'projection_has_no_receipt_foreign_key',
      'broad_owner_transaction',
      'independent_relational_set_equality_not_enforced',
    ],
  },
  'services/security/credential-ledger.js': {
    family: 'credential_lifecycle_ledger',
    require: [/agentPool as defaultPool/, /signAsHousekeeper\(body\)/, sqlInsert('aimos_credential_lifecycle'), /USE_RESERVED/, /USE_COMPLETED/, /USE_FAILED/],
    tests: ['tests/security/credential-ledger-contract.test.mjs'],
  },
  'services/security/memory-lineage.js': {
    family: 'memory_lineage_ledger',
    require: [/agentPool as defaultPool/, /signAsHousekeeper\(/, sqlInsert('aimos_memory_lineage'), /await client\.query\('BEGIN'\)/, /await client\.query\('COMMIT'\)/, /await client\.query\('ROLLBACK'\)/],
    tests: ['tests/security/native-persistence-atomicity.test.mjs'],
  },
  'services/security/memory-provenance.js': {
    family: 'memory_provenance_ledger',
    require: [/agentPool as defaultPool/, /mutationHash/, /verifyStoredPayloadSig/, sqlInsert('aimos_memory_provenance'), /No COMMIT here — the caller's withTransaction owns the boundary/],
    tests: ['tests/security/memory-provenance-tier.test.mjs', 'tests/security/native-persistence-atomicity.test.mjs'],
  },
  'services/security/recall-authorization.js': {
    family: 'recall_authorization_ledger',
    require: [/createRecallAuthorizationProof\(/, /verifyRecallAuthorizationProof\(/, sqlInsert('aimos_recall_authorization_events'), /await client\.query\('COMMIT'\)/, /await client\.query\('ROLLBACK'\)/],
    tests: ['tests/security/recall-authorization-proof.test.mjs'],
  },
  'services/security/request-receipt-ledger.js': {
    family: 'request_receipt_ledger',
    require: [/verifyRequestReceiptProof\(/, /requestReceiptMutationHash\(/, sqlInsert('aimos_request_receipts'), /agentPool\.connect\(\)/, /await client\.query\('COMMIT'\)/],
    tests: ['tests/security/request-receipt-proof.test.mjs'],
  },
  'services/security/save-envelope.js': {
    family: 'save_envelope_chain',
    require: [/agentPool as defaultPool/, /chainHashOf\(/, /CAS-guarded/, sqlUpdate('agent_identity'), sqlInsert('aimos_save_envelope'), /if \(ownsTransaction\) await conn\.query\('COMMIT'\)/],
    tests: ['tests/security/save-envelope-transaction.test.mjs'],
  },
  'services/security/system-config-ledger.js': {
    family: 'system_config_ledger',
    require: [/signPayload\(/, /computeSystemConfigMutationHash\(/, sqlInsert('aimos_system_config'), /await client\.query\('COMMIT'\)/, /await client\.query\('ROLLBACK'\)/],
    tests: ['tests/security/persistent-config-store.test.mjs'],
  },
  'services/write/persist-memory.js': {
    family: 'canonical_memory_transaction',
    require: [/const txClient = client \|\| await agentPool\.connect\(\)/, sqlInsert('aimos_memories'), /commitInitialEvidence\(\{/, /client: txClient/, /if \(ownsTransaction\) await txClient\.query\('COMMIT'\)/],
    tests: ['tests/security/canonical-save-owner-db.test.mjs', 'tests/security/native-persistence-atomicity.test.mjs'],
  },
  'services/integrations/google-tools.js': {
    family: 'google_credential_use',
    require: [/reserveCredentialUse\(/, /finalizeCredentialUse\(/, /fetchWithTimeout\(/],
    tests: ['tests/security/google-credential-use-boundary.test.mjs'],
    forceVerdict: 'COMPLETE_START_TERMINAL',
    limitations: [],
  },
  'services/integrations/integration-tools.js': {
    family: 'github_salesforce_credential_use',
    require: [/reserveCredentialUse\(/, /finalizeCredentialUse\(/, /fetchWithTimeout\(/],
    tests: ['tests/security/native-integration-credential-authority.test.mjs'],
    forceVerdict: 'COMPLETE_START_TERMINAL',
    limitations: [],
  },
  'services/integrations/stripe-tools.js': {
    family: 'stripe_credential_use',
    require: [/reserveCredentialUse\(/, /finalizeCredentialUse\(/, /fetchWithTimeout\(/],
    tests: ['tests/security/credential-use-boundaries.test.mjs'],
    forceVerdict: 'COMPLETE_START_TERMINAL',
    limitations: [],
  },
  'services/integrations/telegram-tools.js': {
    family: 'telegram_credential_use',
    require: [/reserveCredentialUse\(/, /finalizeCredentialUse\(/, /fetchWithTimeout\(/],
    tests: ['tests/security/credential-use-boundaries.test.mjs'],
    forceVerdict: 'COMPLETE_START_TERMINAL',
    limitations: [],
  },
  'services/integrations/x-search.js': {
    family: 'x_search_credential_use',
    require: [/reserveCredentialUse\(/, /finalizeCredentialUse\(/, /fetchWithTimeout\(/],
    tests: ['tests/security/credential-use-boundaries.test.mjs'],
    forceVerdict: 'COMPLETE_START_TERMINAL',
    limitations: [],
  },
  'services/integrations/x-tools.js': {
    family: 'x_action_credential_use',
    require: [/reserveCredentialUse\(/, /finalizeCredentialUse\(/, /fetchWithTimeout\(/],
    tests: ['tests/security/credential-use-boundaries.test.mjs'],
    forceVerdict: 'COMPLETE_START_TERMINAL',
    limitations: [],
  },
});

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

function verifyFamilyContract(file) {
  const contract = FAMILY_CONTRACTS[file];
  if (!contract) throw new Error(`cr7_r1_candidate_family_missing:${file}`);
  const source = read(file);
  const missing = contract.require.filter((pattern) => !pattern.test(source)).map(String);
  if (contract.family.endsWith('credential_use')) {
    const ledger = read('services/security/credential-ledger.js');
    for (const pattern of [/indeterminate/, /findOpenCredentialUses/, /disposition/]) {
      if (!pattern.test(ledger)) missing.push(String(pattern));
    }
  }
  return { contract, missing };
}

function auditCandidate(effect) {
  const { contract, missing } = verifyFamilyContract(effect.file);
  if (missing.length) {
    return Object.freeze({
      effect_id: effect.effect_id,
      file: effect.file,
      line: effect.line,
      owner_family: contract.family,
      verdict: 'OPEN',
      proof_basis: 'required_source_contract_missing',
      missing_contract_predicates: missing,
      limitations: [...(contract.limitations || [])],
      tests: [...contract.tests],
    });
  }
  let verdict = contract.forceVerdict || 'ATOMIC';
  const limitations = [...(contract.limitations || [])];
  if (effect.file === 'services/write/persist-memory.js'
      && /entity_memory_edges/.test(effect.source_anchor)) {
    const persistence = read(effect.file);
    if (!/memory_entity_edges_committed/.test(persistence)
        || !/entity_edge_projection_root_sha256/.test(persistence)
        || !/RETURNING id, company_id, entity, entity_type, memory_id/.test(persistence)) {
      verdict = 'PARTIAL';
      limitations.push(
        'entity_edge_rows_have_no_authority_event_reference',
        'canonical_terminal_commits_only_entity_edge_count_not_exact_row_set',
        'independent_exact_set_reconstruction_unavailable',
      );
    }
  }
  return Object.freeze({
    effect_id: effect.effect_id,
    file: effect.file,
    line: effect.line,
    owner_family: contract.family,
    verdict,
    proof_basis: verdict === 'ATOMIC'
      ? 'signed_or_hash_chained_effect_and_owner_commit_in_one_transaction'
      : verdict === 'COMPLETE_START_TERMINAL'
        ? 'signed_reservation_and_exact_terminal_with_indeterminate_and_orphan_reconstruction'
        : 'some_cryptographic_ownership_exists_but_cr7_totality_is_incomplete',
    missing_contract_predicates: [],
    limitations,
    tests: [...contract.tests],
  });
}

export function proveCr7R1ExistingLedgerOwners() {
  const census = scanCr7EffectCensus();
  const candidates = census.effects.filter((effect) => (
    effect.ownership_status.startsWith(CANDIDATE_PREFIX)
    || effect.ownership_status === 'R5_CREDENTIAL_USE_START_TERMINAL'
  ));
  const audited = candidates.map(auditCandidate).sort((left, right) => left.effect_id.localeCompare(right.effect_id));
  const counts = { ATOMIC: 0, COMPLETE_START_TERMINAL: 0, PARTIAL: 0, OPEN: 0 };
  for (const result of audited) counts[result.verdict] += 1;
  const auditRoot = sha256(Buffer.from(canonicalJson(audited), 'utf8'));
  return Object.freeze({
    schema: 'hom.aimos.cr7-r1-existing-ledger-owner-audit/v1',
    frozen_r1_input_census_root_sha256: '648ce46c02ca493b4a2e6620c42656f646cd017fd5a91ba32dbf08d4185be1c4',
    frozen_r1_audit_root_sha256: 'a3715ebc1213c239863859f8a141264ec41ae1f4e9c47bb1292a6f705f5f57b3',
    input_census_root_sha256: census.effect_root_sha256,
    candidate_count: candidates.length,
    audited_count: audited.length,
    missing_candidate_count: candidates.length - audited.length,
    verdict_counts: Object.freeze(counts),
    audit_root_sha256: auditRoot,
    results: Object.freeze(audited),
  });
}

function main() {
  const result = proveCr7R1ExistingLedgerOwners();
  if (result.candidate_count !== 37 || result.audited_count !== 37 || result.missing_candidate_count !== 0) {
    throw new Error('cr7_r1_candidate_set_incomplete');
  }
  if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else console.log(JSON.stringify({
    schema: result.schema,
    input_census_root_sha256: result.input_census_root_sha256,
    candidate_count: result.candidate_count,
    audited_count: result.audited_count,
    missing_candidate_count: result.missing_candidate_count,
    verdict_counts: result.verdict_counts,
    audit_root_sha256: result.audit_root_sha256,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
