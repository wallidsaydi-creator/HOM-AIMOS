import express from 'express';
import {
  loadSkillsFromDisk,
  listSkills,
  toggleSkill,
  executeSkill,
  getSkillPolicy,
  updateSkillPolicy,
  readSkillPersistenceProjection,
} from '../services/orchestration/skills-runtime.js';
import { requireCapability } from '../services/security/require-capability.js';
import { materialEffectOwner } from '../services/security/material-effect-owner.js';

const router = express.Router();

router.get('/', async (req, res) => {
  loadSkillsFromDisk();
  const items = listSkills();
  res.json({ success: true, items, skills: items });
});

router.post('/:name/toggle', requireCapability('admin_override'), async (req, res) => {
  try {
    const skill = toggleSkill(req.params.name);
    res.json({ success: true, skill });
  } catch (error) {
    res.status(404).json({ success: false, error: error?.message || String(error) });
  }
});

router.post('/:name/execute', requireCapability('admin_override'), async (req, res) => {
  try {
    const result = await executeSkill(req.params.name, req.body || {}, {
      executionContext: req.executionContext,
    });
    res.json({ success: true, ...result });
  } catch (error) {
    const message = error?.message || String(error);
    if (/not found/i.test(message)) {
      return res.status(404).json({ success: false, error: message });
    }
    res.status(400).json({ success: false, error: message });
  }
});

router.get('/:name/policy', requireCapability('admin_override'), async (req, res) => {
  try {
    const policy = getSkillPolicy(req.params.name);
    res.json({ success: true, name: req.params.name, policy });
  } catch (error) {
    const message = error?.message || String(error);
    if (/not found/i.test(message)) {
      return res.status(404).json({ success: false, error: message });
    }
    res.status(400).json({ success: false, error: message });
  }
});

router.put('/:name/policy', requireCapability('admin_override'), async (req, res) => {
  let effect = null;
  try {
    const policy = req.body?.policy ?? req.body;
    effect = await materialEffectOwner.begin({
      kind: 'filesystem',
      operation: 'skill_policy_snapshot',
      targetIdentifier: `skill-policy:${String(req.params.name || '').trim()}`,
      inputProjection: { name: req.params.name, policy },
      subjectAgentId: req.executionContext?.actorAgentId,
      authority: req.executionContext,
      parentEventId: req.executionContext?.requestAdmissionEventId || null,
    });
    const skill = updateSkillPolicy(req.params.name, policy, { persist: true });
    const projection = readSkillPersistenceProjection(skill.name);
    await materialEffectOwner.finish({
      action: effect,
      disposition: 'SUCCEEDED',
      resultProjection: projection,
      resultClass: 'skill_policy_readback_verified',
    });
    res.json({
      success: true,
      name: skill.name,
      policy: skill.policy,
      enabled: skill.enabled !== false
    });
  } catch (error) {
    if (effect) {
      try {
        await materialEffectOwner.finish({
          action: effect,
          disposition: 'INDETERMINATE',
          resultProjection: { error_class: error?.name || 'skill_policy_write_error' },
          resultClass: 'skill_policy_file_state_not_proven',
        });
      } catch (terminalError) {
        error.materialEffectTerminalError = terminalError?.message || String(terminalError);
      }
    }
    const message = error?.message || String(error);
    if (/not found/i.test(message)) {
      return res.status(404).json({ success: false, error: message });
    }
    res.status(400).json({ success: false, error: message });
  }
});

export default router;
