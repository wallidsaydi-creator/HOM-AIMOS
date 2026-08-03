// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: skills-runtime.js, tests
// Pipeline: AGENT_RUN_PIPELINE
// Position: inactive skill policy diagnostics
// Batch8 Wave4 source: SAGER. Candidates are inactive until approved; no
// autonomous skill deployment or policy write occurs here.
// ─────────────────────────────────────────────────────────────────────────────

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function normalizeStringList(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry || '').trim()).filter(Boolean);
}

export function buildInactiveSkillPolicyCandidates({ skills = [] } = {}) {
  const sourceSkills = Array.isArray(skills) ? skills : [];
  const candidates = [];

  for (const skill of sourceSkills) {
    if (!skill?.name) continue;
    const policy = isObject(skill.policy) ? skill.policy : {};
    const allowedAccess = normalizeStringList(policy.allowedAccess);
    const actions = normalizeStringList(skill.actions);
    const missingPolicy = Object.keys(policy).length === 0;
    const disabled = skill.enabled === false;
    const partialFileOrganizer =
      skill.name === 'file-organizer'
      && (allowedAccess.length === 0 || (policy.allowDelete === true && normalizeStringList(policy.allowedDeleteScopes).length === 0));

    if (!disabled && !missingPolicy && !partialFileOrganizer) continue;

    const proposedPolicy = skill.name === 'file-organizer'
      ? {
          allowedAccess: allowedAccess.length > 0 ? allowedAccess : actions.filter((action) => action !== 'write_file'),
          allowDelete: false,
          allowedDeleteScopes: []
        }
      : {
          allowedAccess: allowedAccess.length > 0 ? allowedAccess : actions,
          allowDelete: false
        };

    candidates.push({
      source_papers: [
        'SAGER',
        'Automated Instruction Revision',
        'Transparent and Controllable Recommendation Filtering'
      ],
      diagnostic_only: true,
      active: false,
      auto_apply_enabled: false,
      persistence_enabled: false,
      skill: skill.name,
      reason: disabled
        ? 'skill_disabled'
        : partialFileOrganizer
          ? 'partial_file_organizer_policy'
          : 'missing_skill_policy',
      current_policy: policy,
      proposed_policy: proposedPolicy,
      approval_required: true,
      guarded_control: {
        autonomous_policy_update_enabled: false,
        contrastive_cot_engine_enabled: false,
        skill_deployment_enabled: false
      }
    });
  }

  return {
    source_paper: 'SAGER',
    diagnostic_only: true,
    behavior_changed: false,
    auto_apply_enabled: false,
    candidate_count: candidates.length,
    candidates
  };
}
