import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  createCanaryPayload,
  executeAttack,
  runCampaign,
  validateDefense,
} from '../../services/security/red-team-toolkit.js';
import { filterCybersecContent } from '../../services/security/cybersec-firewall.js';
import { evaluateSecurityContent } from '../../services/security/se-gate.js';

test('structured Sentinel pass/fail is authoritative over response vocabulary', async () => {
  const blocked = await executeAttack(
    { id: 'PI-X', payload: 'attack', expectedBehavior: 'blocked' },
    async () => ({ pass: false, failed: [{ rule: 'instruction_override' }] }),
  );
  const allowed = await executeAttack(
    { id: 'PI-Y', payload: 'attack', expectedBehavior: 'blocked' },
    async () => ({ pass: true, note: 'security protocol mentions password' }),
  );
  assert.equal(blocked.blocked, true);
  assert.equal(allowed.blocked, false);
  assert.equal(blocked.analysis.reason, 'native_security_decision');
});

test('campaigns include benign calibration and compute false-positive rate', async () => {
  const campaign = await runCampaign(
    'prompt_injection',
    async (payload) => ({ pass: !/^Ignore|^Enable|^Translate|^You are DAN|^Decode|^In our|^Pretend|^!\[|^Hypothetically|^Ignore/u.test(payload) }),
    { limit: 1 },
  );
  assert.equal(campaign.total, 1);
  assert.equal(campaign.benignTotal, 7);
  assert.equal(campaign.falsePositives, 0);
  assert.equal(validateDefense(campaign).falsePositiveRate, 0);
});

test('all built-in protocols meet their operation-aware decision contract', async () => {
  for (const attackClass of ['prompt_injection', 'memory_poisoning', 'privilege_escalation', 'data_exfiltration']) {
    const campaign = await runCampaign(attackClass, async (payload, vector) => {
      if (vector.expectedBehavior === 'retained_quarantine') {
        const decision = evaluateSecurityContent({ text: payload, operation: 'memory_save' });
        return { action: decision.action, quarantine: decision.quarantine };
      }
      const result = await filterCybersecContent(payload);
      return { allowed: result.allowed, action: result.security_decision.action };
    });
    const validation = validateDefense(campaign);
    assert.equal(validation.blockRate, 100, attackClass);
    assert.equal(validation.falsePositiveRate, 0, attackClass);
    assert.deepEqual(validation.gaps, [], attackClass);
  }
});

test('red-team canaries use the same native token format as runtime scanners', () => {
  const canary = createCanaryPayload('memory');
  assert.match(canary.canaryToken, /^SECRET-[A-F0-9]{8}$/);
  assert.match(canary.payload, new RegExp(canary.canaryToken));
});

test('red-team reports no longer write stale tables and the route uses native persistence', async () => {
  const [toolkit, route] = await Promise.all([
    readFile(new URL('../../services/security/red-team-toolkit.js', import.meta.url), 'utf8'),
    readFile(new URL('../../routes/security.js', import.meta.url), 'utf8'),
  ]);
  assert.doesNotMatch(toolkit, /INSERT INTO memories/);
  assert.match(route, /await persistMemory\(/);
  assert.match(route, /mutation_authority: 'housekeeper'/);
});
