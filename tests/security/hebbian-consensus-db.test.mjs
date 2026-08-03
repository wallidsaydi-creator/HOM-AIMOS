#!/usr/bin/env node

// Hebbian H3 — behavioral proof of relational consensus consolidation.
// Crafts a tight related cluster (a supported HUB) plus a divergent OUTLIER,
// then proves the consensus signal (HeLa-Mem weighted associative strength)
// classifies them correctly and moves each the right way THROUGH the signed,
// tamper-evident cognitive-weight chain — hub elevated, outlier attenuated,
// existence preserved. Runs only under the isolated harness (disposable DB).
// Behavioral proof for signed Hebbian consensus consolidation.

import assert from 'node:assert/strict';
import { resolveAimosDatabaseName, AIMOS_COMPANY_ID } from '../../services/core/runtime-config.js';
import { pool, agentPool, query, withTransaction } from '../../db/connection.js';
import {
  computeConsensus, applyConsensusReweight, classifyConsensus, HEBBIAN_CONSTANTS,
} from '../../services/dream/hebbian-consensus.js';

const databaseName = resolveAimosDatabaseName();
if (!process.argv.includes('--live-fire') || !/^aimos_test_security_[a-z0-9_]+$/.test(databaseName)) {
  console.log('hebbian consensus DB proof skipped (requires --live-fire and disposable aimos_test_security_* database)');
  process.exit(0);
}
const CID = AIMOS_COMPANY_ID;
const DIM = 768;

// ── deterministic embeddings ────────────────────────────────────────────────
function normalize(v) { const n = Math.hypot(...v) || 1; return v.map((x) => x / n); }
function dot(a, b) { let s = 0; for (let i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }
// base cluster direction (far from real text embeddings ⇒ our memories are each
// other's nearest neighbours, not the genesis Guides)
const v0 = normalize(Array.from({ length: DIM }, (_, i) => Math.sin(i * 0.13) + Math.cos(i * 0.07)));
// an orthonormal companion, via Gram–Schmidt on a second deterministic vector
let uRaw = Array.from({ length: DIM }, (_, i) => Math.cos(i * 0.19) - Math.sin(i * 0.05));
const proj = dot(uRaw, v0);
const u = normalize(uRaw.map((x, i) => x - proj * v0[i]));
// outlier at cosine a=0.74 to the cluster: E = a·v0 + sqrt(1-a²)·u ⇒ cos(E,v0)=a
const A_COS = 0.74;
const eVec = normalize(v0.map((x, i) => A_COS * x + Math.sqrt(1 - A_COS * A_COS) * u[i]));
const lit = (v) => `[${v.join(',')}]`;

function ownerExec(sql, params) {
  return withTransaction((c) => c.query(sql, params),
    { restricted: false, client_id: CID, agent_id: 'housekeeper' });
}
async function insertMemory(id, key, vec) {
  await ownerExec(
    `INSERT INTO aimos_memories (id, company_id, agent_id, key, value, scope, memory_tier, retrieval_weight, is_active, embedding)
     VALUES ($1::uuid, $2, 'housekeeper', $3, 'v', 'global', 'long-term', 1.0, true, $4::vector)`,
    [id, CID, key, lit(vec)]);
}
const verify = (id) => withTransaction(
  (c) => c.query('SELECT * FROM public.verify_cognitive_weight_chain($1::uuid)', [id]),
  { restricted: true, client_id: CID, agent_id: 'housekeeper' }).then((r) => r.rows[0]);
const weightOf = (id) => query('SELECT retrieval_weight, is_active FROM aimos_memories WHERE id = $1::uuid', [id]).then((r) => r.rows[0]);

const HUB = '77770000-0000-0000-0000-000000000001';
const B = '77770000-0000-0000-0000-000000000002';
const C = '77770000-0000-0000-0000-000000000003';
const D = '77770000-0000-0000-0000-000000000004';
const OUT = '77770000-0000-0000-0000-0000000000ee';

try {
  // tight cluster (mutual cosine 1.0) + a fringe outlier (cosine 0.74)
  await insertMemory(HUB, 'hebbian:hub', v0);
  await insertMemory(B, 'hebbian:b', v0);
  await insertMemory(C, 'hebbian:c', v0);
  await insertMemory(D, 'hebbian:d', v0);
  await insertMemory(OUT, 'hebbian:outlier', eVec);

  // ── Pass 1: the consensus signal classifies every member (before any move,
  //    so classification reflects the initial state). Every cluster member is a
  //    hub (surrounded by tight neighbours); the outlier diverges. Reweighting
  //    ALL of them gives each a provenance row (no orphans). ─────────────────
  const members = [[HUB, 'hub'], [B, 'b'], [C, 'c'], [D, 'd'], [OUT, 'outlier']];
  const before = {}, consensus = {};
  for (const [id, label] of members) {
    const c = await computeConsensus(id, { companyId: CID });
    assert.ok(c, `${label} has a real neighbourhood`);
    consensus[label] = c;
    before[label] = Number((await weightOf(id)).retrieval_weight);
  }
  assert.ok(consensus.hub.neighborCount >= HEBBIAN_CONSTANTS.MIN_NEIGHBORS, 'hub cluster is a real consensus');
  for (const label of ['hub', 'b', 'c', 'd']) {
    assert.ok(consensus[label].alignment >= HEBBIAN_CONSTANTS.ALIGN_HIGH,
      `${label} alignment ${consensus[label].alignment} ≥ ${HEBBIAN_CONSTANTS.ALIGN_HIGH}`);
    assert.equal(classifyConsensus(consensus[label].alignment), 1, `${label} → elevate`);
  }
  assert.ok(consensus.outlier.alignment <= HEBBIAN_CONSTANTS.ALIGN_LOW,
    `outlier alignment ${consensus.outlier.alignment} ≤ ${HEBBIAN_CONSTANTS.ALIGN_LOW}`);
  assert.equal(classifyConsensus(consensus.outlier.alignment), -1, 'outlier → attenuate');

  // ── Pass 2: move each through the SIGNED chain. ────────────────────────────
  for (const [id, label] of members) {
    const dir = classifyConsensus(consensus[label].alignment);
    const r = await applyConsensusReweight(id, consensus[label], dir, { companyId: CID });
    assert.equal(r.applied, true, `${label} reweight applied`);
  }

  // hubs elevated, outlier attenuated; every chain verifies (both layers)
  for (const [id, label] of members) {
    const after = await weightOf(id);
    if (label === 'outlier') {
      assert.ok(Number(after.retrieval_weight) < before[label], 'divergent outlier ATTENUATED');
      assert.equal(after.is_active, true, 'outlier still active after attenuation');
      assert.ok(Number(after.retrieval_weight) >= 0.1, 'outlier floored at 0.1 — still recallable');
    } else {
      assert.ok(Number(after.retrieval_weight) > before[label], `supported ${label} ELEVATED`);
    }
    const v = await verify(id);
    assert.equal(v.ok, true, `${label} chain verifies`);
    assert.equal(Number(v.sigs_verified), Number(v.chain_length), `${label} links all signed`);
  }

  const hubAfter = await weightOf(HUB);
  const outAfter = await weightOf(OUT);
  console.log(JSON.stringify({
    database_name: databaseName,
    hub_alignment: Number(consensus.hub.alignment.toFixed(4)),
    outlier_alignment: Number(consensus.outlier.alignment.toFixed(4)),
    hub_weight: `${before.hub} -> ${hubAfter.retrieval_weight}`,
    outlier_weight: `${before.outlier} -> ${outAfter.retrieval_weight}`,
    hub_elevated: true,
    outlier_attenuated: true,
    all_chains_verified: true,
    existence_preserved: true,
  }, null, 2));
} finally {
  await Promise.allSettled([agentPool.end(), pool.end()]);
}
