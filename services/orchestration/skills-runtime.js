// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: server.js
// → Calls: fs, tool-registry.js
// Pipeline: SERVER | Position: Skills loader (startup)
// Batch8 Wave4 source: SAGER. Adds inactive skill-policy candidates only;
// no policy is deployed without explicit approval.
// ─────────────────────────────────────────────────────────────────────────────
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { executeTool } from './tool-registry.js';
import { buildInactiveSkillPolicyCandidates as buildInactiveSkillPolicyCandidatesDiagnostic } from './skill-policy-diagnostics.js';

const BRAIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skillsDir = path.resolve(BRAIN_ROOT, 'skills');
const runtimeSkills = new Map();

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function normalizeSkill(raw, fallbackName) {
  const name = String(raw?.name || fallbackName || '').trim();
  const description = String(raw?.description || '').trim();
  const version = String(raw?.version || '1.0.0').trim();
  const triggers = Array.isArray(raw?.triggers) ? raw.triggers.map((v) => String(v)) : [];
  const actions = Array.isArray(raw?.actions) ? raw.actions.map((v) => String(v)) : [];
  const parameters = isObject(raw?.parameters) ? raw.parameters : {};
  const policy = isObject(raw?.policy) ? raw.policy : {};
  return {
    name,
    description,
    version,
    triggers,
    actions,
    parameters,
    policy,
    enabled: raw?.enabled !== false
  };
}

function getSkillFilePath(name) {
  return path.join(skillsDir, `${name}.json`);
}

function persistSkillToDisk(skill) {
  const filePath = getSkillFilePath(skill.name);
  const payload = {
    name: skill.name,
    description: skill.description,
    version: skill.version,
    triggers: skill.triggers,
    actions: skill.actions,
    parameters: skill.parameters,
    policy: isObject(skill.policy) ? skill.policy : {},
    enabled: skill.enabled !== false
  };
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  fs.renameSync(tmpPath, filePath);
}

function normalizeStringList(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry || '').trim()).filter(Boolean);
}

function resolveFileOrganizerPolicy(skill) {
  const policy = isObject(skill?.policy) ? skill.policy : {};
  return { allowedAccess: normalizeStringList(policy.allowedAccess) };
}

function normalizeFileOrganizerPolicy(policy, skill) {
  const input = isObject(policy) ? policy : {};
  const allowedAccess = normalizeStringList(input.allowedAccess);
  const availableActions = Array.isArray(skill?.actions) ? skill.actions.map((v) => String(v || '').trim()) : [];

  if (Object.hasOwn(input, 'allowDelete') || Object.hasOwn(input, 'allowedDeleteScopes')) {
    throw new Error('Aladdin Law forbids delete policy fields; only the offline whole-brain purge ceremony may delete.');
  }

  if (allowedAccess.length === 0) {
    throw new Error('policy.allowedAccess must be a non-empty array');
  }
  const unsupported = allowedAccess.filter((item) => !availableActions.includes(item));
  if (unsupported.length > 0) {
    throw new Error(`policy.allowedAccess contains unsupported actions: ${unsupported.join(', ')}`);
  }
  if (allowedAccess.some((item) => /^(?:delete|remove|trash|unlink|purge)$/i.test(item))) {
    throw new Error('Aladdin Law forbids delete/remove/trash actions in file-organizer policy.');
  }

  return {
    allowedAccess: Array.from(new Set(allowedAccess)),
  };
}

function ensureFileOrganizerGuard(skill, parameters) {
  const { allowedAccess } = resolveFileOrganizerPolicy(skill);
  if (allowedAccess.length === 0) {
    throw new Error(
      'file-organizer is partially disabled: set policy.allowedAccess before executing.'
    );
  }

  const requestedIntent = String(parameters?.intent || parameters?.mode || '').toLowerCase();
  const requestedAction = String(parameters?.action || '').toLowerCase();
  const deleteRequested =
    parameters?.delete === true
    || requestedIntent === 'delete'
    || requestedIntent === 'remove'
    || requestedIntent === 'trash'
    || requestedAction === 'delete'
    || requestedAction === 'remove'
    || requestedAction === 'trash';

  if (deleteRequested) {
    throw new Error('Aladdin Law forbids file deletion; only the offline whole-brain purge ceremony may delete retained brain state.');
  }
}

function isActionAllowedForFileOrganizer(skill, actionName) {
  const { allowedAccess } = resolveFileOrganizerPolicy(skill);
  return allowedAccess.includes(actionName);
}

export function loadSkillsFromDisk() {
  runtimeSkills.clear();
  if (!fs.existsSync(skillsDir)) return [];

  const entries = fs.readdirSync(skillsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith('.json')) continue;
    const fullPath = path.join(skillsDir, entry.name);
    try {
      const raw = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      const skill = normalizeSkill(raw, entry.name.replace(/\.json$/i, ''));
      if (!skill.name) continue;
      runtimeSkills.set(skill.name, skill);
    } catch {
      // Skip invalid skill files.
    }
  }
  return Array.from(runtimeSkills.values());
}

export async function loadSkillsFromDiskAsync() {
  runtimeSkills.clear();
  try {
    const entries = await fs.promises.readdir(skillsDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!entry.name.endsWith('.json')) continue;
      const fullPath = path.join(skillsDir, entry.name);
      try {
        const rawText = await fs.promises.readFile(fullPath, 'utf8');
        const raw = JSON.parse(rawText);
        const skill = normalizeSkill(raw, entry.name.replace(/\.json$/i, ''));
        if (!skill.name) continue;
        runtimeSkills.set(skill.name, skill);
      } catch {
        // Skip invalid skill files.
      }
    }
  } catch {
    return [];
  }

  return Array.from(runtimeSkills.values());
}

export function listSkills() {
  return Array.from(runtimeSkills.values());
}

export function buildInactiveSkillPolicyCandidates({ skills = null } = {}) {
  return buildInactiveSkillPolicyCandidatesDiagnostic({
    skills: Array.isArray(skills) ? skills : listSkills()
  });
}

export function toggleSkill(name) {
  const key = String(name || '').trim();
  const skill = runtimeSkills.get(key);
  if (!skill) throw new Error('skill not found');
  skill.enabled = !skill.enabled;
  runtimeSkills.set(key, skill);
  return skill;
}

export function getSkillPolicy(name) {
  const key = String(name || '').trim();
  const skill = runtimeSkills.get(key);
  if (!skill) throw new Error('skill not found');
  return isObject(skill.policy) ? skill.policy : {};
}

export function updateSkillPolicy(name, policy, { persist = true } = {}) {
  const key = String(name || '').trim();
  const skill = runtimeSkills.get(key);
  if (!skill) throw new Error('skill not found');
  if (key !== 'file-organizer') {
    throw new Error('policy updates are currently supported only for file-organizer');
  }

  const normalizedPolicy = normalizeFileOrganizerPolicy(policy, skill);
  skill.policy = normalizedPolicy;
  runtimeSkills.set(key, skill);
  if (persist) persistSkillToDisk(skill);
  return skill;
}

export async function executeSkill(name, parameters = {}, { executionContext = null } = {}) {
  const key = String(name || '').trim();
  const skill = runtimeSkills.get(key);
  if (!skill) throw new Error('skill not found');
  if (!skill.enabled) throw new Error('skill is disabled');
  if (key === 'file-organizer') ensureFileOrganizerGuard(skill, parameters);

  const results = [];
  for (const action of skill.actions) {
    const normalized = String(action || '').trim();
    if (!normalized) continue;
    if (key === 'file-organizer' && !isActionAllowedForFileOrganizer(skill, normalized)) {
      throw new Error(`file-organizer action not allowed by policy.allowedAccess: ${normalized}`);
    }

    const actionArgs = isObject(parameters?.[normalized])
      ? parameters[normalized]
      : parameters;

    const result = await executeTool(normalized, actionArgs || {}, 'housekeeper', {
      intent: normalized,
      executionContext,
      credentialUseContext: executionContext,
    });
    results.push({ action: normalized, result });
  }

  return {
    name: skill.name,
    count: results.length,
    results
  };
}
