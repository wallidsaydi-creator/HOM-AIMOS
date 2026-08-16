#!/usr/bin/env node

/**
 * SABER-inspired SBR live evidence proof.
 *
 * Runs the four native operational attack classes through the canonical AIMOS
 * security route. Each request uses the enrolled codex-auditor certificate
 * envelope. The route commits one signed campaign start, one signed native
 * decision per case, and one signed terminal evidence record. This ceremony
 * stores only hashes, event identifiers, aggregate outcomes, and verifier
 * results; it does not duplicate offensive payload text.
 *
 * This is an operational red-team evidence gate. It is not DARPA SABER
 * equivalence and it is not a certified-robustness result.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { AIMOS_HTTP_ORIGIN } from '../../services/core/runtime-config.js';
import { canonicalJson } from '../../services/security/agent-identity.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { verifyCampaignEvidence } from '../../services/security/red-team-toolkit.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const LIVE = process.argv.includes('--live');
const AGENT_ID = 'codex-auditor';
const COMPANY_ID = 'hom';
const ATTACK_CLASSES = Object.freeze([
  'prompt_injection',
  'memory_poisoning',
  'privilege_escalation',
  'data_exfiltration',
]);
const ARTIFACT_DIRECTORY = path.join(ROOT, 'artifacts', 'security', 'saber', 'sbr-live');

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function writeExclusive(filename, artifact) {
  fs.mkdirSync(ARTIFACT_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(ARTIFACT_DIRECTORY, 0o700);
  const target = path.join(ARTIFACT_DIRECTORY, filename);
  const bytes = Buffer.from(`${canonicalJson(artifact)}\n`, 'utf8');
  const descriptor = fs.openSync(target, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.chmodSync(target, 0o600);
  return { path: target, sha256: sha256(bytes), bytes: bytes.length };
}

async function signedJson(method, route, body, query = '') {
  const headers = await buildEnvelopeHeaders(AGENT_ID, method, route, body);
  const response = await fetch(`${AIMOS_HTTP_ORIGIN}${route}${query}`, {
    method,
    headers: {
      ...headers,
      'Content-Type': 'application/json',
    },
    ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(180_000),
  });
  const result = await response.json().catch(() => ({}));
  assert(response.ok && result.success === true, `saber_live_request_failed:${route}:${response.status}:${result.error || 'unknown'}`);
  return result;
}

async function main() {
  const healthResponse = await fetch(`${AIMOS_HTTP_ORIGIN}/health`, {
    signal: AbortSignal.timeout(15_000),
  });
  assert(healthResponse.ok, 'saber_live_server_health_transport_failed');
  const health = await healthResponse.json();
  assert(health.ready === true, `saber_live_server_not_ready:${health.bootError || 'unknown'}`);
  assert(health.runtime?.database_name === 'aimos', 'saber_live_noncanonical_database');
  assert(health.runtime?.benchmark_scratch === false, 'saber_live_scratch_runtime_forbidden');

  const prerequisites = {
    server_origin: AIMOS_HTTP_ORIGIN,
    server_ready: true,
    database: health.runtime.database_name,
    benchmark_scratch: health.runtime.benchmark_scratch,
    agent_id: AGENT_ID,
    attack_classes: ATTACK_CLASSES,
    ceremony_source_sha256: sha256(fs.readFileSync(SCRIPT_FILE)),
    scope: 'SABER-inspired operational red-team evidence; not certified robustness or DARPA equivalence',
  };
  console.log(JSON.stringify({ mode: LIVE ? 'LIVE' : 'DRY_RUN', prerequisites }, null, 2));
  if (!LIVE) return;

  const campaigns = [];
  for (const attackClass of ATTACK_CLASSES) {
    const body = {
      company_id: COMPANY_ID,
      attackClass,
      delayMs: 0,
      timeoutMs: 10_000,
    };
    const result = await signedJson('POST', '/security/campaign', body);
    const portable = verifyCampaignEvidence(result.evidence);
    assert(portable.valid, `saber_live_portable_evidence_invalid:${attackClass}:${portable.reason}`);
    assert(result.verification?.valid === true, `saber_live_route_verification_invalid:${attackClass}`);
    assert(result.campaign_start_event_id === result.evidence.start_event_id, `saber_live_start_binding_invalid:${attackClass}`);
    assert(/^[0-9a-f]{64}$/.test(String(result.terminal_mutation_hash || '')), `saber_live_terminal_receipt_missing:${attackClass}`);

    const validationBody = {
      company_id: COMPANY_ID,
      campaignEventId: result.campaign_terminal_event_id,
    };
    const validation = await signedJson('POST', '/security/validate', validationBody);
    assert(validation.verification?.receipt_bindings_valid === true, `saber_live_receipt_binding_invalid:${attackClass}`);
    assert(validation.campaign_sha256 === result.evidence.campaign_sha256, `saber_live_campaign_hash_mismatch:${attackClass}`);

    campaigns.push({
      attack_class: attackClass,
      start_event_id: result.campaign_start_event_id,
      terminal_event_id: result.campaign_terminal_event_id,
      terminal_mutation_hash: result.terminal_mutation_hash,
      campaign_sha256: result.evidence.campaign_sha256,
      manifest_sha256: result.evidence.manifest.manifest_sha256,
      case_set_sha256: result.evidence.case_set_sha256,
      case_count: result.evidence.case_count,
      native_receipt_count: portable.native_receipt_count,
      aggregate: result.evidence.aggregate,
      aggregate_sha256: result.evidence.aggregate_sha256,
      portable_evidence: result.evidence,
      receipt_bindings_verified: true,
    });
    console.log(JSON.stringify({
      event: 'saber_live_campaign_verified',
      attack_class: attackClass,
      case_count: result.evidence.case_count,
      terminal_event_id: result.campaign_terminal_event_id,
      campaign_sha256: result.evidence.campaign_sha256,
    }));
  }

  const terminalIds = campaigns.map((entry) => entry.terminal_event_id);
  const query = `?campaign_event_id=${encodeURIComponent(terminalIds.join(','))}`;
  const score = await signedJson('GET', '/security/saber-score', {}, query);
  assert(score.verified_campaign_event_ids?.length === ATTACK_CLASSES.length, 'saber_live_verified_campaign_count_invalid');
  assert(score.campaign_sha256?.every((value, index) => value === campaigns[index].campaign_sha256), 'saber_live_score_campaign_binding_invalid');

  const artifact = {
    schema: 'hom.aimos.saber-sbr-live-proof/v1',
    ceremony_id: randomUUID(),
    generated_at: new Date().toISOString(),
    prerequisites,
    campaigns,
    verified_score: score,
    verification: {
      all_cases_have_native_signed_decision_receipts: campaigns.every((entry) => entry.native_receipt_count === entry.case_count),
      all_receipts_parented_to_signed_campaign_start: campaigns.every((entry) => entry.receipt_bindings_verified),
      all_campaigns_have_signed_terminal_commitments: campaigns.every((entry) => /^[0-9a-f]{64}$/.test(entry.terminal_mutation_hash)),
      caller_supplied_aggregate_authority: false,
      offensive_payload_text_duplicated_in_artifact: false,
      certified_robustness_claimed: false,
      darpa_saber_equivalence_claimed: false,
    },
  };
  assert(artifact.verification.all_cases_have_native_signed_decision_receipts, 'saber_live_native_receipt_completeness_failed');
  assert(artifact.verification.all_receipts_parented_to_signed_campaign_start, 'saber_live_receipt_parenting_failed');
  assert(artifact.verification.all_campaigns_have_signed_terminal_commitments, 'saber_live_terminal_completeness_failed');

  const written = writeExclusive(`saber-sbr-live-${artifact.ceremony_id}.json`, artifact);
  console.log(JSON.stringify({ success: true, artifact: written, score: score.saber || score.score || score }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error.message || error}`);
  process.exitCode = 1;
});
