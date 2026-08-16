import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  buildCampaignEvidence,
  buildCampaignManifest,
  campaignFromEvidence,
  runCampaign,
  validateDefense,
  verifyCampaignEvidence,
  verifyCampaignReceiptBindings,
} from '../../services/security/red-team-toolkit.js';

async function fixture() {
  const manifest = buildCampaignManifest('prompt_injection', { limit: 2 });
  const startEventId = 'campaign-start-event';
  const campaign = await runCampaign(
    'prompt_injection',
    async (_payload, vector) => ({
      pass: vector.expectedBehavior === 'allowed',
      security_decision_event_id: `decision-${vector.id}`,
    }),
    { limit: 2 },
  );
  const evidence = buildCampaignEvidence(campaign, {
    manifest,
    startEventId,
    requireNativeReceipts: true,
  });
  return { campaign, evidence, manifest, startEventId };
}

test('portable SBR-2 evidence reconstructs every case and aggregate', async () => {
  const { campaign, evidence } = await fixture();
  const verified = verifyCampaignEvidence(evidence);
  assert.equal(verified.valid, true);
  assert.equal(verified.native_receipt_count, evidence.case_count);
  assert.deepEqual(
    validateDefense(campaignFromEvidence(evidence)),
    validateDefense(campaign),
  );
});

test('portable verifier rejects case, aggregate, manifest, and campaign tampering', async () => {
  const { evidence } = await fixture();
  const mutations = [
    (copy) => { copy.cases[0].outcome = 'bypassed'; },
    (copy) => { copy.aggregate.blocked = 0; },
    (copy) => { copy.manifest.cases[0].payload_sha256 = '00'.repeat(32); },
    (copy) => { copy.campaign_sha256 = '11'.repeat(32); },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(evidence);
    mutate(copy);
    assert.equal(verifyCampaignEvidence(copy).valid, false);
  }
});

test('signed case receipts must be native decisions parented by campaign start', async () => {
  const { evidence, startEventId } = await fixture();
  const valid = await verifyCampaignReceiptBindings(evidence, async (eventId) => ({
    id: eventId,
    operation: 'security_content_decision',
    parent_event_id: startEventId,
  }));
  assert.equal(valid.valid, true);
  assert.equal(valid.receipt_bindings_valid, true);

  const wrongParent = await verifyCampaignReceiptBindings(evidence, async (eventId) => ({
    id: eventId,
    operation: 'security_content_decision',
    parent_event_id: 'other-campaign',
  }));
  assert.equal(wrongParent.valid, false);
  assert.match(wrongParent.reason, /binding_invalid/);
});

test('publication evidence refuses missing native decision receipts', async () => {
  const manifest = buildCampaignManifest('prompt_injection', { limit: 1 });
  const campaign = await runCampaign(
    'prompt_injection',
    async (_payload, vector) => ({ pass: vector.expectedBehavior === 'allowed' }),
    { limit: 1 },
  );
  assert.throws(
    () => buildCampaignEvidence(campaign, {
      manifest,
      startEventId: 'start',
      requireNativeReceipts: true,
    }),
    /native_decision_receipt_missing/,
  );
});

test('security routes consume verified event IDs rather than caller aggregates', async () => {
  const route = await readFile(new URL('../../routes/security.js', import.meta.url), 'utf8');
  assert.match(route, /readVerifiedEventById\(/);
  assert.match(route, /verifyCampaignReceiptBindings\(/);
  assert.match(route, /verified_campaign_event_id_required/);
  assert.match(route, /verified_campaign_event_ids_required/);
  assert.doesNotMatch(route, /const campaignResult = req\.body/);
  assert.doesNotMatch(route, /const \{ campaigns, userId, sessionId \} = req\.body/);
});

test('every signed campaign start has an explicit signed failure terminal path', async () => {
  const route = await readFile(new URL('../../routes/security.js', import.meta.url), 'utf8');
  assert.match(route, /'red_team_campaign_start'/);
  assert.match(route, /'red_team_campaign_terminal'/);
  assert.match(route, /'red_team_campaign_failed'/);
  assert.match(route, /error_message_sha256/);
  assert.doesNotMatch(route, /error_message:\s*err/);
});
