# Aimos Guide — Tier 4: Debug & Internals

> Load this when debugging issues, reading service code, or tuning performance.

## Pipeline Manifest

**Single source of truth:** `services/pipeline-manifest.js` — 153 declared service connections across 6 pipelines, validated at boot.

| Pipeline | Entry | Declared service modules |
|----------|-------|-------------------------:|
| Save | `routes/aimos.js` | 13 |
| Recall | `services/retrieval/native-recall-pipeline.js` | 75 |
| Agent Run | `services/orchestration/agent-runner.js` | 34 |
| Dream | `jobs/nightly-dream.js` | 20 |
| Heartbeat | `jobs/heartbeat.js` | 1 |
| Governance | `services/orchestration/governance-resolver.js` | 10 |

Validate: `node -e "import('./services/pipeline-manifest.js').then(m => m.validatePipelines()).then(r => console.log(r.valid ? 'ALL OK' : 'BROKEN', r.ok + '/' + r.total))"`

## Service Annotation Format

The manifest currently binds 300 service files. Paper-backed mathematical services carry source and pipeline annotations; infrastructure files carry their native ownership/connection contract.

**Block 1 — Source & Compliance:**
```javascript
// ─── SEMANTIC QUERY CACHE (Phase 1) ──────────────────────────────────────────
// Status: Ephemeral LRU Cache — Purely in-memory, no schema changes
// Purpose: Eliminates redundant 16-step recalls for identical/similar queries
// Source: Cache-Augmented Generation (Gao et al., 2024) — Speed.md Appendix A
// Agreement Paradox: Frugal Knowledge Graph (Jourlin, 2026)
// Compliance: Paper Review [X] | Aladdin Law [X] (ephemeral only)
```

**Block 2 — Pipeline Wiring:**
```javascript
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 17)
// → Calls: services/learning/stdp-kernel.js (homeostaticRescale)
// Pipeline: DREAM_PIPELINE
// Position: neuromorphic consolidation
```

**Reading the arrows:** `←` = who calls this service. `→` = what this service calls.

## Paper→Parameter Map (Key Services)

| Service | Paper | Parameter | Value |
|---------|-------|-----------|-------|
| `caching/semantic-cache.js` | Gao et al. (2024) | cosine threshold | 0.85 |
| `caching/semantic-cache.js` | Gao et al. (2024) | TTL | 300s |
| `caching/semantic-cache.js` | Jourlin (2026) | agreement paradox | top-5 > 0.95 |
| `dream/spiced-consolidator.js` | SPICED (NeurIPS 2025) | LTP gamma | 1.3 |
| `dream/spiced-consolidator.js` | ThaCo (2026) | micro-cycles | 20 |
| `dream/spiced-consolidator.js` | SPICED | retained connection-strength promotion adaptation | 30 |
| `retrieval/adaptive-early-exit.js` | Wang et al. (2024) | top_1 threshold | 0.82 |
| `retrieval/adaptive-early-exit.js` | Wang et al. (2024) | score gap | 0.15 |
| `context/mvs-detector.js` | MVS paper | sufficiency threshold | 0.42 |
| `learning/batched-stdp.js` | Miconi (2023) | three-factor eligibility | batch nightly |
| `temporal/dormancy-manager.js` | Medallion Architecture | trust threshold | 0.25 |
| `write/quality-gate.js` | Aladdin / OWASP ASVS | substance min | 0.30 |
| `write/rpe-gate.js` | Sutton & Barto (RL) | RPE routing | heuristic |
| `retrieval/recall-calibrator.js` | LMS algorithm | calibration | belief+preference |
| `dream/curator.js` | MemGPT / HippoRAG | conflict detection | entity dedup |
| `retrieval/similarity-stats.js` | Anisotropy paper | z-score normalization | sliding window |
| `core/concept-graph.js` | HippoRAG (Gutierrez 2024) | PPR | hybrid retrieve |
| `learning/spaced-repetition.js` | SM-2 (SuperMemo) | Ebbinghaus curve | interval scheduling |
| `security/se-gate.js` | Mitnick / Cialdini | social engineering | 6 principles |
| `learning/failure-replay.js` | Sutton & Barto | TD learning | counterfactual regret |

## Paper-Backed Service Examples by Domain

| Domain | Count | Key Papers |
|--------|-------|------------|
| `retrieval/` | 68 | HippoRAG, Adaptive RAG, QuIM-RAG, OrgForge RRF |
| `learning/` | 23 | STDP, SPICED, SM-2, Prospect Theory, R-MDP |
| `orchestration/` | 43 | DISARM, HVR-Met, DIG, ContextCov, Constitutional |
| `security/` | 48 | OWASP, Mitnick, Cialdini, Refusal Bias, P2P Trust |
| `dream/` | 5 | SPICED, ThaCo, Sleep Homeostatic, MemGPT |
| `write/` | 13 | Aladdin, Sutton&Barto RPE, Channel Separation |
| `observe/` | 22 | OpenTelemetry, Senge, Moltbook, SVDD |
| `temporal/` | 25 | Dynamic ToM, Medallion, Pheromone Trails |
| `context/` | 9 | CoALA (Sumers 2023), MVS, Mnemonic Encoding |
| `core/` | 15 | HippoRAG, Constitution, Brain Contract |
| `ingestion/` | 4 | HippoRAG entity extraction, KG methods |
| `caching/` | 1 | Cache-Augmented Generation |

## Speed Configuration

There is no ENV flag lane. Immutable defaults live in versioned source; mutable
non-secret controls are master-signed system-configuration records; secrets
remain in Keychain with signed lifecycle evidence. Inspect verified live config
and `recall_meta` rather than inferring state from process variables.

## Recall SQL Internals

The hybrid recall uses 3 CTEs UNIONed:

1. **vector_candidates** — HNSW index, cosine distance, weighted by `retrieval_weight` (STDP)
2. **bm25_candidates** — `search_vector @@ plainto_tsquery()`, ranked by `ts_rank()`
3. **temporal_candidates** — key LIKE + BM25, ordered by `created_at DESC`

Final ranking is emitted in `recall_meta.rank_observability` and combines the
native vector/BM25/RRF channels with the signed cognitive retrieval-weight
projection. No age-decay or lifecycle field can suppress eligibility.

## Key DB Columns

| Column | Purpose |
|--------|---------|
| `embedding` | 768d pgvector (all-mpnet-base-v2) |
| `search_vector` | tsvector for BM25 full-text search |
| `retrieval_weight` | STDP-adjusted synaptic strength (default 1.0) |
| `decay_weight` | Retained legacy compatibility column, constitutionally fixed at `1.0`; never authority |
| `access_count` | Total times recalled |
| `last_accessed_at` | When last recalled |
| `consolidation_age` | Dream consolidation metric |
| `clearance_level` | ACL (1-12+) |
| `data_class` | public/internal/confidential/restricted |
| `medallion_layer` | bronze/silver/gold |
| `is_active` | Retained legacy column constrained true; never an eligibility authority |
| `supersedes_id` | Points to memory this corrects |
| `is_correction` | Whether this is a correction |
| `source` | Provenance tag |
| `credit_score` | Trust metric (0-2) |

## Debugging Recall Quality

Use `aimos-sign-headers.js --exec` for every protected diagnostic, generating a fresh envelope for the exact method, path, and body. For recall observability, sign `POST /aimos/recall` with `{"query":"test","limit":5}` and inspect `recall_meta`. For status surfaces, sign the exact GET path with `{}`. Only `/health` is unsigned.

## Recalling Paper Provenance

Generate a fresh `POST /aimos/recall` envelope with the native helper for each query. Useful bodies include:

- `{"query":"paper batch5","memory_type_filter":"procedural_seed","limit":20}`
- `{"query":"STDP eligibility three factor","memory_type_filter":"procedural_seed","limit":5}`
- `{"query":"cache augmented generation","memory_type_filter":"procedural_seed","limit":10}`
