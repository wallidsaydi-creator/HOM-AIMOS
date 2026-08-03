import express from 'express';
import {
  loadSkillsFromDisk,
  listSkills,
  toggleSkill,
  executeSkill,
  getSkillPolicy,
  updateSkillPolicy
} from '../services/orchestration/skills-runtime.js';
import { requireCapability } from '../services/security/require-capability.js';

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
  try {
    const policy = req.body?.policy ?? req.body;
    const skill = updateSkillPolicy(req.params.name, policy, { persist: true });
    res.json({
      success: true,
      name: skill.name,
      policy: skill.policy,
      enabled: skill.enabled !== false
    });
  } catch (error) {
    const message = error?.message || String(error);
    if (/not found/i.test(message)) {
      return res.status(404).json({ success: false, error: message });
    }
    res.status(400).json({ success: false, error: message });
  }
});

export default router;
