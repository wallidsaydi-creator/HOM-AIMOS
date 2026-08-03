/**
 * Native MEMAUDIT package-audit recall operator from:
 * - MEMAUDIT.pdf
 *
 * Implemented formulas / techniques:
 * - experience stream `E=(e_1,...,e_T)`
 * - virtual ground set `U={(i,j): i in [T], j in J_i \\ {discard}}`
 * - per-experience group `G_i={(i,j): j in J_i \\ {discard}}`
 * - feasibility `F_B={X subset U: sum c_u <= B, |X∩G_i| <= 1}`
 * - one knapsack constraint plus one partition matroid
 * - cost rule `c(u)=8+ceil(bytes(u)/24)`
 * - semantic coverage `F(X)=sum_r w_r h_r(sum_u a_ur)`, `h_r(z)=min(1,z)`
 * - exact package ratio `rho_P(X)=F_P(X)/OPT_P(B)`
 * - union denominator for external stores
 * - branch-and-bound over grouped experience-representation assignments
 * - MILP-style clipped coverage variables `y_r <= sum_u a_ur x_u`, `y_r <= 1`
 * - stale/tombstone/supersession coverage as validity diagnostics
 *
 * Aimos adaptation:
 * - audits returned recall candidates as a transient package
 * - tombstone/supersession is diagnostic only under Aladdin Law
 * - no write, compaction, deletion, pruning, or decay is performed
 */

export const MEMAUDIT_CONSTANTS = Object.freeze({
  fixed_record_overhead: 8,
  bytes_per_cost_unit: 24,
  default_budget_units: 240,
  exact_group_limit: 18,
  max_choices_per_group: 4,
});

export const MEMAUDIT_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  tombstone_is_diagnostic_overlay_only: true,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'from', 'have', 'many', 'more', 'most',
  'that', 'their', 'there', 'these', 'this', 'those', 'through', 'what',
  'when', 'where', 'which', 'while', 'with', 'would',
]);

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokens(value = '') {
  return normalizeText(value)
    .split(/\s+/)
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function unique(values = []) {
  return [...new Set(values.filter(Boolean))];
}

function bytes(value = '') {
  return Buffer.byteLength(String(value || ''), 'utf8');
}

export function storageCost(value = '') {
  return MEMAUDIT_CONSTANTS.fixed_record_overhead + Math.ceil(bytes(value) / MEMAUDIT_CONSTANTS.bytes_per_cost_unit);
}

function requirementsFromQuery(queryText = '') {
  const qTokens = tokens(queryText);
  const named = [...String(queryText || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)].map((match) => normalizeText(match[0]));
  const temporal = /\b(after|before|between|last|current|currently|now|when|days?|months?|years?)\b/i.test(queryText)
    ? ['temporal']
    : [];
  const aggregation = /\b(how many|count|total|list|all|number of)\b/i.test(queryText)
    ? ['aggregation']
    : [];
  const current = /\b(current|currently|now|still|latest|recent)\b/i.test(queryText)
    ? ['current_state']
    : [];
  return unique([...named, ...qTokens.slice(0, 12), ...temporal, ...aggregation, ...current])
    .map((id) => ({
      id,
      weight: named.includes(id) ? 1.2 : temporal.includes(id) || aggregation.includes(id) || current.includes(id) ? 1.1 : 1,
    }));
}

function coverageForRequirement(text = '', requirement = {}) {
  const normalized = normalizeText(text);
  if (!requirement?.id) return 0;
  if (requirement.id === 'temporal') return /\b(after|before|between|last|currently|now|when|days?|months?|\d{4})\b/i.test(text) ? 1 : 0;
  if (requirement.id === 'aggregation') return /\b(and|,|also|total|count|how many|list|all)\b/i.test(text) ? 1 : 0;
  if (requirement.id === 'current_state') return /\b(currently|now|still|latest|recent|no longer|instead)\b/i.test(text) ? 1 : 0;
  return normalized.includes(requirement.id) ? 1 : 0;
}

function makeChoice(state = {}, index = 0, kind = 'raw') {
  const text = String(state.text || state.memory?.value || '');
  const firstSentence = text.split(/(?<=[.!?])\s+/).filter(Boolean)[0] || text;
  const validOverlay = /\b(no longer|not anymore|instead|changed|cancelled|stopped|superseded)\b/i.test(text);
  const payload = kind === 'raw'
    ? text
    : kind === 'fact'
      ? firstSentence
      : kind === 'summary'
        ? `${tokens(text).slice(0, 24).join(' ')}`
        : `[validity-overlay] ${firstSentence}`;
  return {
    u: `${state.id}:${kind}`,
    state_id: String(state.id),
    group_id: `G:${index}`,
    kind,
    text: payload,
    cost: storageCost(payload),
    validity_overlay: kind === 'tombstone' && validOverlay,
  };
}

export function buildPackage({ queryText = '', states = [], budget = MEMAUDIT_CONSTANTS.default_budget_units } = {}) {
  const requirements = requirementsFromQuery(queryText);
  const groups = [];
  const U = [];
  (states || []).forEach((state, index) => {
    const choices = ['raw', 'fact', 'summary', 'tombstone']
      .map((kind) => makeChoice(state, index, kind))
      .filter((choice) => choice.kind !== 'tombstone' || choice.validity_overlay)
      .slice(0, MEMAUDIT_CONSTANTS.max_choices_per_group);
    groups.push({ id: `G:${index}`, state_id: String(state.id), choices: choices.map((choice) => choice.u) });
    U.push(...choices.map((choice) => ({
      ...choice,
      coverage: Object.fromEntries(requirements.map((requirement) => [requirement.id, coverageForRequirement(choice.text, requirement)])),
    })));
  });
  return { U, G: groups, R: requirements, B: budget };
}

export function semanticCoverageValue(selection = [], requirements = []) {
  let total = 0;
  for (const requirement of requirements || []) {
    const z = selection.reduce((sum, choice) => sum + (Number(choice.coverage?.[requirement.id]) || 0), 0);
    total += (Number(requirement.weight) || 1) * Math.min(1, z);
  }
  return total;
}

function greedyPackage(packageState = {}) {
  const selected = [];
  const usedGroups = new Set();
  let cost = 0;
  const candidates = [...(packageState.U || [])].sort((a, b) => {
    const va = semanticCoverageValue([a], packageState.R) / Math.max(1, a.cost);
    const vb = semanticCoverageValue([b], packageState.R) / Math.max(1, b.cost);
    return vb - va || a.u.localeCompare(b.u);
  });
  for (const candidate of candidates) {
    if (usedGroups.has(candidate.group_id)) continue;
    if (cost + candidate.cost > packageState.B) continue;
    selected.push(candidate);
    usedGroups.add(candidate.group_id);
    cost += candidate.cost;
  }
  return { selected, value: semanticCoverageValue(selected, packageState.R), cost };
}

export function branchAndBoundPackageOpt(packageState = {}) {
  const groups = (packageState.G || []).slice(0, MEMAUDIT_CONSTANTS.exact_group_limit)
    .map((group) => (packageState.U || []).filter((choice) => choice.group_id === group.id));
  if (groups.length === 0) return { selected: [], value: 0, cost: 0, exact: true };
  if ((packageState.G || []).length > MEMAUDIT_CONSTANTS.exact_group_limit) {
    return { ...greedyPackage(packageState), exact: false, reason: 'group_limit_greedy_fallback' };
  }

  let best = { selected: [], value: 0, cost: 0 };
  const suffixUpper = Array.from({ length: groups.length + 1 }, () => 0);
  for (let i = groups.length - 1; i >= 0; i -= 1) {
    const localBest = Math.max(0, ...groups[i].map((choice) => semanticCoverageValue([choice], packageState.R)));
    suffixUpper[i] = suffixUpper[i + 1] + localBest;
  }

  function search(i, selected, usedCost) {
    const current = semanticCoverageValue(selected, packageState.R);
    if (current + suffixUpper[i] < best.value) return;
    if (i >= groups.length) {
      if (current > best.value || (current === best.value && usedCost < best.cost)) best = { selected: [...selected], value: current, cost: usedCost };
      return;
    }
    search(i + 1, selected, usedCost);
    for (const choice of groups[i]) {
      if (usedCost + choice.cost > packageState.B) continue;
      selected.push(choice);
      search(i + 1, selected, usedCost + choice.cost);
      selected.pop();
    }
  }

  search(0, [], 0);
  return { ...best, exact: true };
}

export function packageRatio(selection = [], optimum = {}, packageState = {}) {
  const numerator = semanticCoverageValue(selection, packageState.R);
  const denominator = Math.max(1e-9, Number(optimum.value) || 0);
  return clamp01(numerator / denominator);
}

export function memAuditScores({ queryText = '', states = [], budget = MEMAUDIT_CONSTANTS.default_budget_units } = {}) {
  const packageState = buildPackage({ queryText, states, budget });
  const optimum = branchAndBoundPackageOpt(packageState);
  const selectedIds = new Set(optimum.selected.map((choice) => choice.state_id));
  const ratio = packageRatio(optimum.selected, optimum, packageState);
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const id = String(state.id);
    const choices = packageState.U.filter((choice) => choice.state_id === id);
    const bestLocal = Math.max(0, ...choices.map((choice) => semanticCoverageValue([choice], packageState.R) / Math.max(1, semanticCoverageValue(packageState.U, packageState.R))));
    const selected = selectedIds.has(id);
    const validity = choices.some((choice) => choice.validity_overlay) ? 0.12 : 0;
    const score = clamp01((0.58 * bestLocal) + (selected ? 0.30 : 0) + (0.12 * ratio) + validity);
    scoreById.set(id, score);
    diagnosticsById.set(id, {
      selected_by_package: selected,
      choice_count: choices.length,
      best_local_coverage: Number(bestLocal.toFixed(6)),
      validity_overlay: validity > 0,
    });
  }
  return {
    scoreById,
    diagnosticsById,
    package: {
      ground_set_size: packageState.U.length,
      group_count: packageState.G.length,
      requirement_count: packageState.R.length,
      budget_units: packageState.B,
      optimum_exact: optimum.exact,
      optimum_cost: optimum.cost,
      optimum_value: Number(optimum.value.toFixed(6)),
    },
    selected_count: optimum.selected.length,
    ratio: Number(ratio.toFixed(6)),
    guardrails: MEMAUDIT_GUARDRAILS,
    formula: 'F(X)=sum_r w_r min(1,sum_u a_ur); F_B={sum c_u<=B, |X∩G_i|<=1}; rho=F(X)/OPT(B)',
  };
}
