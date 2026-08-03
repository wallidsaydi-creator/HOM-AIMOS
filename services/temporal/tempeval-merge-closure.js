/**
 * Native temporal merge/closure operator from:
 * - TempEval-3.pdf
 *
 * Implemented formulas / techniques:
 * - TIPSem / TIPSemB / TRIOS merge strategy
 * - weights: TIPSem 0.36, TIPSemB 0.32, TRIOS 0.32
 * - agreement gate: supported by at least 2 of 3 systems
 * - temporal closure before precision/recall
 * - relation task order: extract entities/timexes, decide links, type links
 *
 * Aimos adaptation:
 * - creates bounded relation/closure evidence scores in native recall
 * - does not prune, decay, delete, or inject answers
 */

export const TEMPEVAL_SYSTEM_WEIGHTS = Object.freeze({
  TIPSem: 0.36,
  TIPSemB: 0.32,
  TRIOS: 0.32,
});

export const TEMPEVAL_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
});

const INVERSE = Object.freeze({
  BEFORE: 'AFTER',
  AFTER: 'BEFORE',
  INCLUDES: 'IS_INCLUDED',
  IS_INCLUDED: 'INCLUDES',
  SIMULTANEOUS: 'SIMULTANEOUS',
  OVERLAP: 'OVERLAP',
  VAGUE: 'VAGUE',
});

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function keyOf(relation = {}) {
  return [relation.from, relation.to, relation.type || relation.relation || 'VAGUE']
    .map((part) => String(part || '').toLowerCase())
    .join('\u0001');
}

function pairKey(relation = {}) {
  return [relation.from, relation.to].map((part) => String(part || '').toLowerCase()).join('\u0001');
}

function normalizeRelationType(value = '') {
  const rel = String(value || '').toUpperCase().replace(/[^A-Z_]+/g, '_');
  if (rel.includes('BEFORE')) return 'BEFORE';
  if (rel.includes('AFTER')) return 'AFTER';
  if (rel.includes('INCLUDES')) return 'INCLUDES';
  if (rel.includes('IS_INCLUDED') || rel.includes('DURING')) return 'IS_INCLUDED';
  if (rel.includes('SIMULTANEOUS') || rel.includes('EQUAL')) return 'SIMULTANEOUS';
  if (rel.includes('OVERLAP')) return 'OVERLAP';
  return 'VAGUE';
}

function relationSupport(relations = [], target = {}) {
  const targetKey = keyOf(target);
  return relations.filter((relation) => keyOf(relation) === targetKey).length;
}

export function mergeTempEvalSystemOutputs({ TIPSem = [], TIPSemB = [], TRIOS = [] } = {}) {
  const all = [
    ...TIPSem.map((relation) => ({ ...relation, system: 'TIPSem', weight: TEMPEVAL_SYSTEM_WEIGHTS.TIPSem })),
    ...TIPSemB.map((relation) => ({ ...relation, system: 'TIPSemB', weight: TEMPEVAL_SYSTEM_WEIGHTS.TIPSemB })),
    ...TRIOS.map((relation) => ({ ...relation, system: 'TRIOS', weight: TEMPEVAL_SYSTEM_WEIGHTS.TRIOS })),
  ].map((relation) => ({
    ...relation,
    type: normalizeRelationType(relation.type || relation.relation),
  }));

  const output = new Map();
  for (const relation of all) {
    const support = relationSupport(all, relation);
    const accepted = relation.system === 'TIPSem' || support >= 2;
    if (!accepted) continue;
    const key = keyOf(relation);
    const current = output.get(key) || { ...relation, support: 0, weighted_support: 0, systems: [] };
    current.support += 1;
    current.weighted_support += relation.weight;
    current.systems.push(relation.system);
    output.set(key, current);
  }

  return [...output.values()].map((relation) => ({
    from: relation.from,
    to: relation.to,
    type: relation.type,
    support: relation.support,
    weighted_support: Number(clamp01(relation.weighted_support).toFixed(6)),
    systems: [...new Set(relation.systems)],
  }));
}

export function temporalClosure(relations = []) {
  const out = new Map();
  const add = (relation, inferred = false) => {
    if (!relation.from || !relation.to) return;
    const type = normalizeRelationType(relation.type || relation.relation);
    const row = {
      from: String(relation.from),
      to: String(relation.to),
      type,
      inferred,
    };
    out.set(keyOf(row), row);
    const inverse = INVERSE[type];
    if (inverse && row.from !== row.to) {
      out.set(keyOf({ from: row.to, to: row.from, type: inverse }), {
        from: row.to,
        to: row.from,
        type: inverse,
        inferred: true,
      });
    }
  };

  for (const relation of relations || []) add(relation, false);

  let changed = true;
  let guard = 0;
  while (changed && guard < 64) {
    changed = false;
    guard += 1;
    const rows = [...out.values()];
    for (const left of rows) {
      for (const right of rows) {
        if (left.to !== right.from) continue;
        if (left.type === 'BEFORE' && right.type === 'BEFORE') {
          const key = keyOf({ from: left.from, to: right.to, type: 'BEFORE' });
          if (!out.has(key)) {
            add({ from: left.from, to: right.to, type: 'BEFORE' }, true);
            changed = true;
          }
        }
        if (left.type === 'SIMULTANEOUS' && right.type === 'SIMULTANEOUS') {
          const key = keyOf({ from: left.from, to: right.to, type: 'SIMULTANEOUS' });
          if (!out.has(key)) {
            add({ from: left.from, to: right.to, type: 'SIMULTANEOUS' }, true);
            changed = true;
          }
        }
      }
    }
  }

  return [...out.values()];
}

export function tempEvalPrecisionRecall(gold = [], predicted = []) {
  const goldClosed = new Set(temporalClosure(gold).map(keyOf));
  const predClosed = new Set(temporalClosure(predicted).map(keyOf));
  let tp = 0;
  for (const key of predClosed) {
    if (goldClosed.has(key)) tp += 1;
  }
  const fp = predClosed.size - tp;
  const fn = goldClosed.size - tp;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const fscore = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return { precision, recall, fscore, tp, fp, fn };
}

function extractTemporalRelationSignals(text = '') {
  const rows = [];
  const lower = String(text || '').toLowerCase();
  if (/\bbefore|prior to|earlier than\b/.test(lower)) rows.push('BEFORE');
  if (/\bafter|following|later than\b/.test(lower)) rows.push('AFTER');
  if (/\bwhile|during|when|until|same time|simultaneous\b/.test(lower)) rows.push('OVERLAP');
  return [...new Set(rows)];
}

export function tempEvalEvidenceScores({ queryText = '', states = [] } = {}) {
  const querySignals = extractTemporalRelationSignals(queryText);
  const scoreById = new Map();
  const diagnosticsById = new Map();

  for (const state of states || []) {
    const text = state.text || state.value || '';
    const signals = extractTemporalRelationSignals(text);
    const overlap = querySignals.length
      ? signals.filter((signal) => querySignals.includes(signal)).length / querySignals.length
      : signals.length ? 0.2 : 0;
    const relationRows = signals.map((signal, index) => ({ from: `${state.id}:e${index}`, to: `${state.id}:t${index}`, type: signal }));
    const closure = temporalClosure(relationRows);
    const closureScore = relationRows.length ? clamp01(closure.length / Math.max(1, relationRows.length * 2)) : 0;
    const score = clamp01((overlap * 0.7) + (closureScore * 0.3));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      signals,
      closure_count: closure.length,
      relation_task_order: ['extract_entities_and_timexes', 'select_links', 'type_links'],
    });
  }

  return {
    scoreById,
    diagnosticsById,
    query_signals: querySignals,
    formula: 'merged temporal relations use TIPSem/TIPSemB/TRIOS weights and temporal closure before P/R/F',
  };
}
