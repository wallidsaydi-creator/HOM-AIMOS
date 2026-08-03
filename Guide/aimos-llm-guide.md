# Aimos API Guide — For Any LLM Agent

> **Version:** 1.4 | **Date:** 2026-05-11 | **Base URL:** `http://127.0.0.1:9100/aimos`
> **Auth:** cryptographic envelope (Phase 10B+). Bearer tokens removed. See §0 Authentication.
> **Company:** All requests use `company_id=hom` unless multi-tenant.
>
> **LIVE VALIDATION:** 2026-05-11. All response shapes below verified against running Aimos instance.
> **DILIGENCE RULE:** This guide must be updated after every implementation. If Aimos's live responses
> diverge from this guide, the guide is wrong — not Aimos. Truth hierarchy: Aimos > guide > everything else.
>
> **CHANGELOG v1.2 → v1.3:**
> - **AUTH MODEL UPDATED.** Bearer tokens are no longer accepted. Live Aimos returns `Unauthorized — cryptographic envelope required` for any bearer-only request to `/aimos/*`. All examples in this guide now show envelope headers. Identity is backed by `agent_identity` (PostgreSQL) + `~/.aimos/agents/<agent>.key`.
> - Added §0 Authentication describing the envelope contract and agent enrollment flow.
> - Replaced `Authorization: Bearer TOKEN` placeholders in §9 and §12 with envelope-header placeholders.
>
> **CHANGELOG v1.0 → v1.1:**
> - `/status` returns `total_memories` not `memory_count`; adds `speed_flags`, `cache_stats`, `server_started_at`
> - `/layer-status` returns named subsystems not `layers` array
> - `/embed/stats` key is `dimensions` (plural); adds `healthy`, `failCount`, `lastCheck`, `totalCalls`, `provider`, `cache_*`
> - `/recall` adds `hallucination_risk`, `cached_at` top-level; `recall_meta` adds `early_exit`, `exit_stage`, `skipped_stages`, `stage_timings`
> - **REMOVED** `confidence.components` from memory items (not returned by live API; use `recall_confidence` scalar)
> - `mode=adaptive` returns `results` + `metadata` shape; falls back to `memories` + `recall_meta` + `_guide` when no results
> - Added 12 new sections: MCP tools (9 exposed), cost matrix (6 actions), fragility (8 labels), autonomy, agent state, layer-status subsystems, medallion distribution, skill triggers, recommendations, QMD failures, time-travel failure, save response inconsistency

**CHANGELOG v1.1 → v1.2:**
- **FIXED: `/time-travel` is NOT a 404 endpoint.** Live verification confirms it returns 404 only when no memory exists for the key at the given time. With an exact key and valid `as_of`, it returns the correct snapshot. Moved from "Known Failures" to working endpoint with usage notes.
- **FIXED: QMD syntax examples were wrong.** The guide previously showed `FIND procedural_seed WHERE keywords CONTAINS 'STDP' LIMIT 5` which fails because the parser requires `field:value` notation. Correct: `FIND type:procedural_seed WHERE contains("STDP") LIMIT 5`. Added full verb/syntax reference table.
- **ADDED: Time-travel and QMD copy-paste examples** in section 12 (Recall Patterns).
- **ADDED: QMD parser details** — token types, duration format, max query length, WHERE clause syntax.
- **UPDATED: Live validation date** to 2026-04-30.

---

## 0. Authentication (envelope-only)

Aimos authenticates every protected request by verifying a per-request signature against an enrolled agent identity. There is no bearer token, no API key header, no shared secret.

### Required headers (every protected request)

| Header | Meaning |
|---|---|
| `Aimos-Agent-Cert` | Public cert for the calling agent. Read from `agent_identity.cert` at enrollment. |
| `Aimos-Agent-Signature` | Ed25519 signature of `${method}:${path}:${nonce}:${timestamp}:${canonical_body}`, base64-encoded. |
| `Aimos-Agent-Nonce` | Random 16-byte base64url, unique per request (replay protection). |
| `Aimos-Agent-Timestamp` | Unix seconds at signing time. Skew window enforced by `auth-gate.js`. |
| `Aimos-Agent-Prev-Chain-Hash` | (T2 saves only) base64url chain hash of the prior save event for this agent. |

`canonical_body` for GET is empty; for POST it is the request body serialized with sorted keys.

### Identity surfaces

- **Identity epochs:** PostgreSQL `agent_identity` rows bind `agent_id`, cert, public key, and validity interval. Revocation truth is append-only signed revocation evidence, not a mutable identity field.
- **Private keys:** `~/.aimos/agents/<agent_id>.key`. Never copied, exported, or printed.
- **Auth gate:** `services/security/auth-gate.js` verifies signature → derives `agent_id` from cert → sets `req.agentId`.
- **Operational identity:** clean installs have the autonomous `housekeeper`; human-directed calls use the agent explicitly enrolled by the operator. No personal identity is hard-coded.

### Enrolling a new agent (e.g. for a different LLM identity)

```bash
cd <repo-root>
node scripts/identity/enroll-agent.js <agent_id> --validity-days=30
```

This writes a new row to `agent_identity` (cert + pubkey + chain head) and emits the private key to `~/.aimos/agents/<agent_id>.key`. Agents are not document-backed. Each LLM that needs to talk to Aimos gets its own row and its own key.

### What this replaces

- ❌ `Authorization: Bearer <PRODUCT_API_KEY>` — rejected with `401 Unauthorized — cryptographic envelope required`.
- ❌ Environment-owned tokens or identity — the process environment is not an AIMOS authority surface.

### What is unchanged

- `/health` remains unauthenticated for liveness probes.
- Signed policy, quality validation, and clearance guards still apply downstream of the envelope check. Mathematical implementation changes require paper/header review before code changes.

---

## 1. What Aimos Is

Aimos is a memory OS backed by PostgreSQL + pgvector (768d embeddings). It retains admitted session debriefs, paper extractions, directives, reasoning traces, and agent runs under Aladdin's Law. Counts are live-state facts: obtain them from the signed status surface rather than copying a historical snapshot. Every save is quality-gated and every recall uses the native evidence-admitted pipeline.

**Truth hierarchy:** Aimos > Files on disk > Session context. If they disagree, Aimos wins.

---

## 2. Core Endpoints (Quick Reference)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/status` | Health check, total_memories, speed_flags, cache_stats |
| `POST` | `/save` | Write a memory (quality-gated) |
| `POST` | `/recall` | Signed native recall + cryptographic receipt |
| `POST` | `/heartbeat` | System pulse + corrections |
| `POST` | `/event` | Log an event to the ledger |
| `POST` | `/checkpoint` | Save task checkpoint state |
| `GET` | `/resume/:taskId` | Resume from checkpoint |
| `GET` | `/dream/latest` | Last nightly dream summary |
| `POST` | `/dream/run` | Trigger nightly dream manually |
| `GET` | `/timeline` | Chronological event view |
| `GET` | `/graph/:entityId` | Entity relationship graph |
| `GET` | `/layer-status` | 10-layer architecture health |
| `GET` | `/events/today` | Today's event log entries |
| `POST` | `/log-event` | Write event with full metadata |
| `POST` | `/ceo/directive` | Issue a strategic directive |
| `GET` | `/ceo/inbox` | Pending directives |
| `POST` | `/ceo/report` | Submit execution report |
| `POST` | `/qmd` | Structured query (QMD protocol) |
| `GET` | `/qmd/explain` | QMD explanation |
| `GET` | `/time-travel` | Query memories at a point in time |
| `GET` | `/medallion-stats` | Bronze/silver/gold distribution |
| `POST` | `/embed` | Generate embedding for text |
| `GET` | `/embed/stats` | Embedding service health |
| `POST` | `/recall` with `projection:"demo_redacted"` | Demo-safe terminal projection through native recall |
| `GET` | `/conflicts` | Unresolved memory conflicts |
| `POST` | `/conflicts/:id/resolve` | Resolve a conflict |
| `GET` | `/skills` | List agent skills |
| `POST` | `/recommendations` | Submit recommendation |
| `GET` | `/recommendations` | List recommendations |
| `POST` | `/reasoning-state` | Save reasoning snapshot |
| `GET` | `/reasoning-state` | Get latest reasoning state |
| `GET` | `/cost-matrix` | LLM cost tracking |
| `GET` | `/fragility` | System fragility scores |
| `GET` | `/autonomy/:agentId` | Agent autonomy level |
| `PUT` | `/autonomy/:agentId` | Set agent autonomy |
| `GET` | `/agent-state/:agentId` | Agent state snapshot |
| `PUT` | `/agent-state/:agentId` | Update agent state |
| `POST` | `/agent-message` | Inter-agent messaging |
| `GET` | `/mcp/tools/list` | MCP tool surface |
| `POST` | `/mcp/tools/call` | Execute MCP tool |

---

## 3. SAVE — Writing Memories

### Request

```
POST /aimos/save
Content-Type: application/json

{
  "company_id": "hom",
  "key": "session_debrief:2026-04-14",
  "value": "Full text of what happened...",
  "scope": "executive",
  "clearance_level": 10,
  "memory_type": "session_debrief",
  "source": "app",
  "is_correction": false,
  "supersedes_id": null
}
```

### Required Fields

| Field | Type | Notes |
|-------|------|-------|
| `key` | string | Unique identifier. Use namespaced format: `type:topic:detail` |
| `value` | string | The memory content. Min 20 chars. Must pass quality gate. |

### Optional Fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `company_id` | string | `"hom"` | Tenant isolation |
| `agent_id` | string | verified certificate actor | Optional exact assertion only; it cannot select or override identity |
| `scope` | string | `"global"` | `global`, `executive`, `agent`, `system` |
| `clearance_level` | int | `1` | 1-12. Controls who can read. 12+ = sudo protected. |
| `memory_type` | string | `"declarative"` | See memory types table below |
| `source` | string | `"app"` | Provenance tag: `app`, `agent`, `longmemeval`, custom |
| `is_correction` | bool | `false` | If true, supersedes previous memory with same key |
| `supersedes_id` | uuid | `null` | Explicitly supersede a specific memory |

### Response

```json
{
  "success": true,
  "memory_id": "uuid",
  "memory_tier": "long-term",
  "conflict_detected": false,
  "quarantined": false,
  "correction_applied": false,
  "rpe": { "score": 0.42, "route": "STANDARD" },
  "encoding_style": "visual_hook"
}
```

### Save Pipeline (10 stages)

```
Request
  │
  ├─ 1. Envelope Authority ─ verifies signed identity, company, request receipt, and grants
  ├─ 2. Sudo Guard ─────── clearance 12+ memories need sudo to overwrite
  ├─ 3. Write Validator ── structural validation (exempt: event_log, dream_summary, etc.)
  ├─ 4. RPE Gate ────────── Reward Prediction Error — routes processing depth
  ├─ 5. Sensible Screen ── monitors RPE gate quality over time
  ├─ 6. Transform Cache ── checks if this schema transform was seen before
  ├─ 7. Mnemonic Encoder ─ tags encoding style (visual_hook, narrative, etc.)
  ├─ 8. persistMemory() ── canonical write:
  │     ├─ Quality Gate (3 walls — see below)
  │     ├─ Secret Redaction (API keys, tokens auto-stripped)
  │     ├─ Quarantine Check (prompt injection detection)
  │     ├─ Embedding (768d all-mpnet-base-v2 ONNX)
  │     ├─ Cross-Reference (A-MEM Zettelkasten linking)
  │     ├─ Entity Extraction (HippoRAG: names, dates, amounts)
  │     ├─ Aladdin Compliance check
  │     ├─ Data Classification (public/internal/confidential/restricted)
  │     ├─ Medallion Layer assignment (bronze/silver/gold)
  │     └─ DB INSERT + trigger evaluation
  ├─ 9. Cache Invalidate ─ semantic cache cleared on new memory
  └─ 10. Response
```

### Quality Gate — Three Walls

**Every memory must pass all 3 walls. No exceptions.**

| Wall | Name | What It Checks |
|------|------|----------------|
| 1 | **THE FORM** | Not empty, min 20 chars, not a kill pattern (`null`, `undefined`, `ok`, `test`, repeated words) |
| 2 | **THE FILTER** | Not >50% repetitive chars, not heartbeat spam, not a duplicate within 1 hour |
| 3 | **THE SUBSTANCE** | Substance score >= 0.30 (has specifics, reasoning, actions, structure, file paths). Exempt types skip this wall. |

**Exempt types** (skip Wall 3 substance scoring, but still checked by Walls 1-2):
`session_debrief`, `strategic_directive`, `operational_rule`, `constitution`, `procedural`, `session_reasoning`

**Exempt key prefixes:** `paper:`, `book:`, `heartbeat:pulse`, `heartbeat:latest`

### Save Errors

| Status | Meaning |
|--------|---------|
| `400` | Missing key/value, write validation failed |
| `403` | Verified company, signed grant, or sudo clearance is insufficient |
| `422` | Quality gate rejected (garbage content) |
| `500` | Server error |

---

## 4. RECALL — Reading Memories

### Request

```http
POST /aimos/recall
Content-Type: application/json

{"query":"session debrief april","limit":10,"clearance_level":10}
```

### Parameters

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `q` or `query` | string | **required** | Natural language search query |
| `company_id` | string | verified company | Optional exact assertion; mismatch is rejected |
| `agent_id` | string | verified certificate actor | Optional exact assertion; it cannot select identity |
| `limit` | int | `10` | Max results (1-200) |
| `clearance_level` | int | signed grant ceiling | Optional lower cap; cannot raise master-signed authority |
| `memory_type_filter` | string | none | Filter to one type: `session_debrief`, `procedural_seed`, etc. |
| `source_filter` | string | none | Filter by source tag |
| `session_id` | string | none | Scope to a specific ingestion session |
| `max_hops` | int | `2` | Graph traversal depth (1-4) |
| `mode` | string | `"linear"` | `"adaptive"` for multi-scale recall |
| `selectivity` | string | `"standard"` | `"strict"` or `"loose"` (adaptive mode) |
| `lazy` | bool | `true` | Lazy loading (adaptive mode) |
| `sort` | string | `"relevance"` | `"chronological"` for time-ordered results |

### Response Shape

```json
{
  "memories": [
    {
      "id": "uuid",
      "key": "session_debrief:2026-04-14",
      "value": "Full text content...",
      "scope": "executive",
      "memory_type": "session_debrief",
      "clearance_level": 10,
      "created_at": "2026-04-14T12:00:00Z",
      "credit_score": 1.0,
      "memory_tier": "long-term",
      "data_class": "internal",
      "graph_links": [
        { "id": "uuid", "key": "related:memory", "value": "snippet...", "similarity": 0.89, "hop": 1 }
      ],
      "rerank_score": 0.75,
      "recall_confidence": 0.823,
      "timem": {
        "tmt_level": "L2",
        "temporal_bucket": {
          "day": "2026-05-05",
          "session": "2026-05-05T23:51",
          "week": "2026-W19"
        },
        "parent_buckets": {
          "session": "2026-05-05T23:51",
          "day": "2026-05-05"
        }
      }
    }
  ],
  "working_memory": "[session_debrief] First 1200 chars of top results...",
  "recall_meta": {
    "qmd_activated": false,
    "top_rerank": 0.75,
    "avg_rerank": 0.62,
    "total_results": 8,
    "early_exit": false,
    "exit_stage": null,
    "skipped_stages": [],
    "confidence_distribution": { "high": 3, "medium": 4, "low": 1 },
    "temporal_scope": {
      "dayBuckets": ["2026-05-11", "2026-05-05", "2026-04-24"],
      "matchCount": 20
    },
    "temporal_truth": {
      "truth_band": "live",
      "newest_memory_at": "2026-05-11T00:02:44.000Z",
      "oldest_memory_at": "2026-04-06T09:15:56.000Z",
      "median_age_hours": 48.5,
      "recent_ratio": 0.75,
      "stale_ratio": 0.0
    },
    "score_components": {
      "freshness_ranking_enabled": true,
      "ranking_math_changed": false,
      "rerank_is_uniform": false
    },
    "explain": {
      "mode": "linear_hybrid",
      "query": "session debrief april",
      "filters": { "company_id": "hom", "clearance_level": 10, "memory_type_filter": null },
      "stages": {
        "vector_candidate_limit": 50,
        "recursive_hops": 2,
        "entity_graph_injected": 1,
        "bm25_second_pass": true,
        "qmd_auto_switch": false,
        "anisotropy_corrected": true
      }
    },
    "stage_timings": {
      "stage_1": "5ms",
      "stage_2": "2ms"
    }
  },
  "cache_hit": false,
  "hallucination_risk": false,
  "cached_at": "2026-04-14T12:00:00Z"
}
```

**Two Recall Modes:**

| Mode | Trigger | Result Order |
|------|---------|-------------|
| **Semantic** (default) | No `sort` param, or `sort=relevance` | TiMem-guided: day bucket → TMT level → confidence |
| **Temporal-first** | `sort=chronological` | Strict newest-first by `created_at` |

Every memory always includes `timem` with day/session coordinates. Use `temporal_scope.dayBuckets` to see which days matched your query.

**Note:** In standard `mode=linear`, top-level keys are `memories`, `working_memory`, `recall_meta`, `cache_hit`, `hallucination_risk`, `cached_at`. In `mode=adaptive`, keys are `results` and `metadata` (different schema).

### The 17-Stage Recall Pipeline (with Stage Zero)

```
Query arrives
  │
  ├─  0. temporal_scoping ──────── Pre-pipeline: identify relevant days/sessions
  │     ├─  Lightweight SQL pass matching keywords + tsvector
  │     ├─  Extract top 3 day buckets from recent matching memories
  │     └─  Feed source_boost into hybrid query (recent <1d: +0.05, <7d: +0.10, <30d: +0.20)
  ├─  1. embedding_query ──────── Embed query text → 768d vector (ONNX, ~5ms)
  ├─  2. cache_check ──────────── Semantic cache lookup (cos_sim > 0.85, TTL 300s)
  │                                 ↳ HIT → return cached, skip stages 3-17
  ├─  3. hybrid_vector_bm25 ───── THREE parallel candidate pools:
  │     ├─ vector_candidates ──── HNSW index, cosine distance, retrieval_weight boost
  │     ├─ bm25_candidates ────── PostgreSQL tsvector full-text search
  │     └─ temporal_candidates ── Key pattern + BM25, ordered by created_at DESC, with source_boost
  │     └─ UNION ALL → deduplicated candidate set
  │     └─ RRF scoring combines vector/BM25 channels with signed retrieval-weight projection
  │                      + BM25 ts_rank * 3.0 + key similarity * 2.0
  ├─  4. entity_recall ────────── HippoRAG: extract entities from query →
  │                                look up entity_memory_edges → inject unseen memories
  ├─  5. recursive_graph_walk ─── WITH RECURSIVE on memory_cross_refs (1-4 hops)
  │                                each memory gets graph_links[] with connected memories
  ├─  6. bm25_rescue ──────────── Second BM25 pass to catch what vector search missed
  │                                (large documents dilute embeddings)
  ├─  7. reranking ────────────── BM25-inspired term overlap + recency boost
  │                                ≤24h: +0.15, ≤7d: +0.10, ≤30d: +0.05
  │                                Uniformity guard: if all rerank scores identical (stdDev < 0.05),
  │                                early exit is blocked and confidence formula shifts to recency/authority
  ├─  8. qmd_activation ───────── If top_rerank <= 0.6 OR avg_rerank < 0.4:
  │     ├─ Channel 1: Full-text search via tsvector (OR between terms)
  │     └─ Channel 2: Key-pattern + metadata search (papers, techniques)
  │     └─ Boost procedural_seed/procedural/tacit_knowledge +0.15
  ├─  9. hyde_expansion ───────── If still low quality (top <= 0.5, avg < 0.3):
  │                                HyDE (Hypothetical Document Embedding) expands query
  │                                multi-stage retrieval with expanded embedding
  ├─ 10. early_exit_decision ──── If enabled by signed/request-scoped policy:
  │                                exit if (top_1 > 0.82 AND gap > 0.15)
  │                                     OR (MVS < 0.42 AND avg_top5 > 0.65)
  │                                 ↳ SKIP stages 11-15, return immediately
  ├─ 11. salience_annotation ──── Annotate low-frequency evidence without suppressing eligibility
  ├─ 12. trust_scoring ────────── rankByTrust(): credit_score, access patterns, age
  ├─ 13. concept_graph_ppr ────── HippoRAG PPR (Personalized PageRank) on knowledge graph
  │                                discovers memories by graph structure, not just text
  │                                PPR-only results are hydrated (content fetched from DB)
  ├─ 14. recall_calibration ───── LMS (Least Mean Squares) calibration on rerank + trust
  │                                corrects systematic over/under-confidence
  ├─ 15. mnemonic_encoding ────── Style match: query encoding style vs memory encoding
  │                                (visual_hook, narrative, procedural, etc.)
  ├─ 16. confidence_scoring ───── Final composite score per memory:
  │     ├─ Default: semantic(46.6%) + authority(25%) + keyword(11.4%) + recency(5.7%) + type_authority(11.3%)
  │     ├─ Uniform rerank fallback: recency(20%) + authority(35%) + type_authority(25%) + freshness(20%)
  │     └─ Early exit uses: rerank(40%) + recency(20%) + authority(25%) + type_authority(15%)
  ├─ 17. final_sort ──────────── TiMem-guided sort: day bucket → TMT level → confidence
  │                                Chronological override if sort=chronological (newest-first)
  │                                Every memory gets timem envelope with day/session/week coordinates
  └─ Response: memories[] + working_memory + recall_meta + temporal_scope + cache fill
```

### Post-Recall Side Effects

- **Signed recall evidence:** request admission, recall event, provenance, and returned Merkle evidence are ledgered.
- **Access observations:** frequency metadata may be appended or projected, but it cannot decay, delete, deactivate, or suppress canonical memory.
- **Cache fill:** result stored in semantic cache for future similar queries
- **Event log:** recall event recorded for audit

---

## 5. Memory Types

| Type | Authority Score | Purpose |
|------|----------------|---------|
| `procedural_seed` | +0.18 | Paper-extracted implementation techniques |
| `procedural` | +0.15 | Learned procedures, algorithms, how-to |
| `tacit_knowledge` | +0.15 | Implicit knowledge, intuitions, patterns |
| `book_extract` | +0.14 | Book-derived knowledge |
| `framework` | +0.12 | Conceptual frameworks and models |
| `directive` | +0.10 | CEO directives, operational rules |
| `identity` | +0.05 | Who we are, crew identity |
| `declarative` | +0.05 | General facts and statements |
| `session_debrief` | +0.03 | Session summaries (exempt from substance gate) |
| `after_action_review` | 0.00 | Post-action analysis |
| `event_log` | -0.08 | Timestamped events (high-volume, dampened) |
| `heartbeat` | -0.10 | System health pulses (dampened in recall) |
| `conversation_feed` | -0.12 | Raw conversation logs (dampened) |

**Other types:** `dream_summary`, `dream_pattern`, `strategic_directive`, `operational_rule`, `constitution`, `core_belief`, `reasoning_state`, `milestone`, `product`, `self_improvement`, `infrastructure`, `active_loop`, `task_summary`, `agent_session`, `intel`, `constitution_check`, `test`, `bibliographic_reference`, `crew_identity`, `quarantine`

---

## 6. Medallion Layers

| Layer | Types | Meaning |
|-------|-------|---------|
| **Gold** | milestone, product, identity, procedural, crew_identity, dream_summary, self_improvement, infrastructure | Core knowledge — highest value |
| **Silver** | session, directive, heartbeat, intel, constitution_check, test | Operational — medium value |
| **Bronze** | Everything else | Working data — baseline |

---

## 7. Clearance Levels

| Level | Access | Classification |
|-------|--------|----------------|
| 1-3 | Public | Anyone can see |
| 4-6 | Internal | Agent-specific, operational |
| 7-9 | Confidential | Strategic, financial, personal |
| 10 | All (except sudo) | Executive access |
| 12+ | Sudo | Cannot be overwritten without clearance 12+ |

**Memory ACL:** Private memories (clearance <= 2) only visible to their owning agent.

**Data classification** is auto-assigned: `public` / `internal` / `confidential` / `restricted` — based on content patterns (passwords, financial terms, strategy) and clearance level.

---

## 8. Gates — What They Block and Why

### Paper Review Boundary (Implementation)
The former route-level Knowledge Gate is retired. Paper-backed mathematical services still require paper authority, target-service and dependency review, implementation, dry run, and proof before header claims are changed. This is an engineering change boundary, not an HTTP save gate.

### Quality Gate (Save)
**File:** `services/write/quality-gate.js`
**When:** Every memory save
**What:** 3 walls — form, filter, substance. Rejects garbage.
**HTTP:** 422 if rejected.

### Write Validator (Save)
**File:** `services/write/write-validator.js`
**When:** Non-exempt types
**What:** Structural validation of the write payload.
**HTTP:** 400 if invalid.

### RPE Gate (Save)
**File:** `services/write/rpe-gate.js`
**When:** Every save
**What:** Reward Prediction Error — measures how surprising/useful the memory is. Routes to STANDARD, ELEVATED, or CRITICAL processing depth. No LLM call.

### Sudo Guard (Save)
**When:** Key already exists with clearance >= 12
**What:** Prevents overwrite unless caller also has clearance 12+.
**HTTP:** 403.

### Quarantine Detector (Save)
**When:** Every save
**What:** Detects prompt injection patterns (including base64/URL-encoded). Admitted evidence may receive `scope='quarantine'`, but it remains retained, active, auditable, and recallable under constrained trust/ranking.

### Early Exit Gate (Recall)
**File:** `services/retrieval/adaptive-early-exit.js`
**When:** enabled by verified signed or request-scoped configuration
**What:** Skips stages 11-15 if confidence is already high enough. Saves ~50ms per recall.

### Salience Annotation (Recall)
**File:** `services/temporal/dormancy-manager.js`
**When:** After early-exit check
**What:** Emits low-frequency/trust observations for ranking and diagnostics. It cannot remove a retained memory from eligibility.

---

## 9. Paper Provenance & Service Annotations

The manifest currently binds 275 service files. Mathematical, graph, temporal, retrieval, and cognitive services trace their techniques to the cited local papers; infrastructure services instead declare their native ownership and connection contract.

### How Paper Provenance Works

1. **Papers are ingested** into Aimos as `procedural_seed` memories with key format `paper:batch5:stdp_kernel`
2. **Services cite their source** in standardized header comments
3. **Parameters come from papers** — thresholds, weights, and algorithms are not invented, they're extracted
4. **Change review enforces discipline** — read the cited paper/header and dependency graph before changing paper-backed architecture

### Paper-backed service header format

Every service has two annotation blocks:

**Block 1: Source & Status**
```javascript
// ─── SEMANTIC QUERY CACHE (Phase 1) ──────────────────────────────────────────
// Status: Ephemeral LRU Cache — Purely in-memory, no schema changes
// Purpose: Eliminates redundant 16-step recalls for identical/similar queries
// Source: Cache-Augmented Generation (Gao et al., 2024) — Speed.md Appendix A
// Agreement Paradox Detection: Frugal Knowledge Graph (Jourlin, 2026)
// Compliance: Paper Review [X] | Aladdin Law [X] (ephemeral only)
// ─────────────────────────────────────────────────────────────────────────────
```

**Block 2: Pipeline Wiring**
```javascript
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 17)
// → Calls: services/learning/stdp-kernel.js (homeostaticRescale)
// Pipeline: DREAM_PIPELINE
// Position: neuromorphic consolidation
// ─────────────────────────────────────────────────────────────────────────────
```

### Paper→Parameter Examples (Real Services)

| Service | Paper | Parameter | Value |
|---------|-------|-----------|-------|
| `semantic-cache.js` | Gao et al. (2024) | cos_sim threshold | 0.85 |
| `semantic-cache.js` | Gao et al. (2024) | TTL | 300s |
| `semantic-cache.js` | Jourlin (2026) | agreement paradox threshold | 0.95 top-5 |
| `spiced-consolidator.js` | SPICED (NeurIPS 2025) | LTP gamma | 1.3 |
| `spiced-consolidator.js` | ThaCo (2026) | micro-cycles | 20 |
| `spiced-consolidator.js` | SPICED/ThaCo adaptation | retained connection-strength promotion | 30 |
| `adaptive-early-exit.js` | Wang et al. (2024) | top_1 threshold | 0.82 |
| `adaptive-early-exit.js` | Wang et al. (2024) | score gap | 0.15 |
| `mvs-detector.js` | MVS paper | context sufficiency | 0.42 |
| `stdp-kernel.js` | Miconi (2023), HOM doctrine v3 | signed bidirectional valence adaptation | `[0.1, 3.0]` |
| `dormancy-manager.js` | Medallion Architecture adaptation | low-frequency annotation | non-suppressive |
| `quality-gate.js` | Aladdin Law / OWASP ASVS | substance score min | 0.30 |
| `rpe-gate.js` | Sutton & Barto (RL) | dopaminergic prediction error | heuristic |
| `recall-calibrator.js` | LMS algorithm | dual-channel calibration | belief+preference |
| `curator.js` | MemGPT / HippoRAG | conflict detection | entity dedup |
| `similarity-stats.js` | Anisotropy Correction | z-score normalization | sliding window |
| `concept-graph.js` | HippoRAG (Gutierrez 2024) | PPR (PersonalizedPageRank) | hybrid retrieve |
| `trust-score.js` | Credit Scoring | signed evidence patterns | weighted rank |

### Paper-Sourced Services by Domain

| Domain | Count | Key Papers |
|--------|-------|------------|
| `retrieval/` | 55 | HippoRAG, Adaptive RAG, QuIM-RAG, OrgForge RRF, GroupRAG |
| `learning/` | 23 | STDP (SynForceNet), SPICED, SM-2, Prospect Theory, R-MDP |
| `orchestration/` | 43 | DISARM, HVR-Met, DIG, ContextCov, Constitutional Monitoring |
| `security/` | 36 | OWASP, Mitnick, Cialdini, Defensive Refusal Bias, Agentic P2P |
| `dream/` | 5 | SPICED (NeurIPS 2025), ThaCo, Sleep Homeostatic, MemGPT |
| `write/` | 13 | Aladdin Law, Sutton&Barto RPE, Channel Separation |
| `observe/` | 22 | OpenTelemetry, Senge, Moltbook, SVDD Anomaly |
| `temporal/` | 25 | Dynamic ToM, Medallion, Pheromone Trails |
| `context/` | 9 | CoALA (Sumers 2023), MVS, Mnemonic Encoding |
| `core/` | 15 | HippoRAG, Constitution, Brain Contract, Deontic Reasoning |
| `ingestion/` | 4 | HippoRAG entity extraction, Knowledge Graph |
| `caching/` | 1 | Cache-Augmented Generation (Gao et al., 2024) |

Paper inventory is a live corpus fact. Recall the taxonomy/index and relevant paper memory instead of relying on a copied batch count.

### Recalling Paper Memories

Use the one-shot `aimos-sign-headers.js --exec` pattern from section 12 with a fresh `/aimos/recall` envelope. Example bodies:

- `{"query":"paper batch5","memory_type_filter":"procedural_seed","limit":20}`
- `{"query":"STDP eligibility trace three factor","memory_type_filter":"procedural_seed","limit":5}`

---

## 10. Service Annotations (Header Comments)

Every service file contains a standardized header:

```javascript
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (RECALL pipeline, stage 12)
// → Calls: trust-score.js, dormancy-manager.js
// Pipeline: RECALL_PIPELINE
// Position: after BM25 rescue, before calibration
// ─────────────────────────────────────────────────────────────────────────────
```

**Pipeline Manifest:** `services/pipeline-manifest.js` — 146 declared service connections across 6 pipelines, validated at boot.

**The 6 Pipelines:**

| Pipeline | Entry | Declared service modules |
|----------|-------|-------------------------:|
| Save | `routes/aimos.js` | 13 |
| Recall | `services/retrieval/native-recall-pipeline.js` | 68 |
| Agent Run | `services/orchestration/agent-runner.js` | 34 |
| Dream | `jobs/nightly-dream.js` | 20 |
| Heartbeat | `jobs/heartbeat.js` | 1 |
| Governance | `services/orchestration/governance-resolver.js` | 10 |

---

## 11. Speed Configuration

There is no ENV authority. Defaults are code constants; persistent mutable controls belong in the master-signed system configuration ledger.

| Control | Default | What It Does |
|------|---------|-------------|
| Semantic cache | OFF | Ephemeral query cache; never memory authority |
| Adaptive early exit | OFF | Request-scoped opt-in only |
| QuIM | OFF | Inverted question matching |
| Governance diagnostics | OFF | Signed policy/config controls only |
| Pipeline instrumentation | OFF | Per-stage timing telemetry |
| RRF semantic weight | `0.65` | Canonical code/paper-backed blend |
| RRF keyword weight | `0.35` | Canonical code/paper-backed blend |

---

## 12. Signed Request Patterns

Generate a fresh envelope for each exact method, path, and JSON body. Never reuse a header file or nonce. Substitute the operator-enrolled id for `<agent-id>`.

### Basic recall (semantic — "what's inside the drawer")
```bash
printf '%s' '{"query":"session debrief","limit":5}' | node aimos-sign-headers.js \
  --agent-id <agent-id> --method POST --path /aimos/recall --body - \
  --exec http://127.0.0.1:9100/aimos/recall
```

### Temporal recall (chronological — "which room was I in?")
Use body `{"query":"last session we worked on","sort":"chronological","limit":10}` with the same one-shot command.

The response includes `temporal_scope.dayBuckets` showing which days matched, and each memory has `timem.temporal_bucket.day` for grouping.

### Filter by memory type
Use body `{"query":"architecture","memory_type_filter":"procedural_seed","limit":10}`.

### High-clearance recall
Use body `{"query":"strategy","clearance_level":10,"limit":5}`. The request may lower but cannot raise the signed grant ceiling.

### Chronological (latest first)
Use body `{"query":"events today","sort":"chronological","limit":20}`.

### Adaptive multi-scale recall
Use body `{"query":"stdp implementation","mode":"adaptive","selectivity":"strict","limit":20}`.

### Scoped to source
Use body `{"query":"benchmark","source_filter":"longmemeval","limit":10}`.

### Deep graph walk (4 hops)
Use body `{"query":"dream consolidation","max_hops":4,"limit":10}`.

### Basic save
```bash
printf '%s' '{"key":"test:guide","value":"This is a test memory with enough content to pass the quality gate minimum length requirement.","memory_type":"declarative"}' | node aimos-sign-headers.js \
  --agent-id <agent-id> --method POST --path /aimos/save --body - \
  --exec http://127.0.0.1:9100/aimos/save
```

### Save a correction
Use save body `{"key":"rule:important","value":"Updated rule content replacing the old version with corrected information and parameters.","memory_type":"directive","is_correction":true}`.

### Time-travel (point-in-time snapshot)
Use `aimos-sign-headers.js` with `--method GET`, `--path /aimos/time-travel`, an empty body, and the full query URL passed to `--exec`.
Returns the memory value as it was at that timestamp. Returns 404 if no memory existed for that key at that time. Use exact keys, not prefixes.

### QMD structured query (correct syntax)
Use the one-shot helper with path `/aimos/qmd` and body `{"query":"FIND type:procedural_seed WHERE contains(\"STDP\") LIMIT 5","clearance_level":10}`.

### QMD count by agent
Use body `{"query":"COUNT type:session_debrief GROUP BY agent_id","clearance_level":10}` with a fresh `/aimos/qmd` envelope.

---

## 13. Confidence Scoring (How to Interpret)

Each recalled memory has `recall_confidence` (0-1) and `confidence.components`:

| Component | Weight | What It Measures |
|-----------|--------|------------------|
| `semantic` | 45% | Vector similarity (anisotropy-corrected z-score if calibrated) |
| `authority` | 25% | Credit score / trust of the memory |
| `keyword` | 10% | BM25 term overlap |
| `recency` | 8% | Age: 24h=1.0, 7d=0.8, 30d=0.6, older=0.35 |
| `type_authority` | 12% | Memory type boost/dampen (see types table) |

**Bands:** `high` >= 0.75, `medium` >= 0.50, `low` < 0.50

**`temporal_truth`** tells you if results are `live` (>60% from last 72h), `historical` (>60% older than 90d), or `mixed`.

---

## 14. Aladdin Law

Named after BlackRock Aladdin ($11.5T AUM retained because clients can't leave their data).

- **Everything is long-term.** `memory_tier` is always `long-term`. `expires_at` is always `null`.
- **No soft-delete or deactivation.** `is_active` remains true, including quarantine.
- **Garbage is rejected before admission.** If evidence enters, it is retained; correction uses append-only supersession.
- **Keep everything of value.** Session debriefs, reasoning, papers, directives — all permanent.
- **`decay_weight`** is a legacy compatibility column fixed at `1.0`, never authority.
- **`retrieval_weight`** is a signed, bidirectional cognitive projection bounded to `[0.1, 3.0]`; every mutation is ledgered.

---

## 15. Enforced Tier System

The guide is split into 4 files served by `GET /aimos/guide?tier=N`. The API **injects `_guide` hints** into responses when something goes wrong, telling the LLM which tier to load.

| Tier | File | When | Size |
|------|------|------|------|
| 1 | `aimos-guide-tier1-boot.md` | **Always at boot** | ~2.8KB |
| 2 | `aimos-guide-tier2-recall.md` | Before first recall | ~4.9KB |
| 3 | `aimos-guide-tier3-save.md` | Before first save | ~7.1KB |
| 4 | `aimos-guide-tier4-debug.md` | When debugging | ~7.9KB |

**Enforcement mechanisms:**
1. `GET /aimos/guide?tier=N` — API endpoint serves each tier
2. Save errors (400/403/422) include `_guide` field pointing to tier 3
3. Recall errors include `_guide` field pointing to tier 2
4. Low-quality recall results include `_guide` hints
5. Tier 1 itself instructs: "BEFORE YOUR FIRST RECALL → GET /aimos/guide?tier=2"

**Total: ~22.7KB across 4 files.** Tier 1 alone is under 3KB — fits in any context window.

---

## 16. Common Mistakes

| Mistake | Fix |
|---------|-----|
| Saving value < 20 chars | Quality gate rejects. Write meaningful content. |
| Saving `"ok"` or `"test"` | Kill pattern. Rejected instantly. |
| Saving same content twice in 1 hour | Dedup filter blocks it. Change the content or wait. |
| Querying with empty `q=` | Returns 400. Always provide a search query. |
| Setting `clearance_level=1` on recall | You'll only see public memories. Use 10 for full access. |
| Using `is_active=false` for any memory | Violates Aladdin Law. Quarantine is a retained label, not deactivation. |
| Treating a body `agent_id` as authority | Identity comes from the verified certificate; a body field can only match it. |
| Expecting instant recall of just-saved memory | Embedding is generated at save time, but semantic cache may serve stale results for 300s if enabled. |
| Overwriting clearance 12+ memory | Sudo guard blocks. Need clearance 12+ yourself. |

## 17. MCP Tool Surface (9 Tools)

Aimos exposes 9 tools via MCP protocol v2.0.0 over HTTP. This is the primary programmatic interface for external agents.

| Tool | Category | Required Input | Notes |
|------|---------|----------------|-------|
| `aimos_status` | status | — | Returns `connected`, `total_memories`, `speed_flags` |
| `aimos_system_health` | status | — | Adds topology + pipeline validation |
| `aimos_recall` | memory | `query` or `key` | `mode` enum: adaptive / linear |
| `aimos_open_memory` | memory | `memory_id` or `key` | Exact fetch, not semantic |
| `aimos_events_today` | observability | `hours` (1–168, default 24) | Returns recent event_log |
| `aimos_qmd` | structured_query | `query` (QMD syntax) | **Does NOT accept natural language**. Requires structured QMD tokens. See section 18. |
| `aimos_qmd_explain` | structured_query | `query` | Parses without executing |
| `aimos_time_travel` | history | `key`, `as_of` (ISO timestamp) | Returns snapshot of memory at a point in time. Returns 404 only if no memory exists for that key at that time. |
| `aimos_save` | memory_write | `key`, `value` | Goes through full save pipeline |

**QMD grammar (observed error: `Expected token type KEYWORD but got IDENT`):**
- QMD uses a formal grammar with token types (KEYWORD, FIELD_VAL, STRING, NUMBER, DURATION, OPERATOR, IDENT, UUID, GLOB).
- Natural language like `"architecture"` fails — the parser expects a structured statement starting with a verb.
- **All filters use `field:value` notation.** Bare identifiers like `procedural_seed` are NOT valid after verbs — use `type:procedural_seed`.
- Valid verbs: `FIND`, `TRAVERSE`, `MATCH`, `GRAPH`, `PATH`, `COUNT`
- Correct patterns:

| Verb | Example |
|------|---------|
| FIND | `FIND type:procedural_seed WHERE contains("STDP") LIMIT 5` |
| FIND | `FIND key:"session_debrief*" LIMIT 10` |
| MATCH | `MATCH agent:<enrolled-agent-id> WHERE type:session_debrief AND created > 7d LIMIT 5` |
| COUNT | `COUNT type:event_log WHERE created > 24h GROUP BY agent_id` |
| GRAPH | `GRAPH AROUND id:<uuid> HOPS 2 RETURN adjacency` |
| TRAVERSE | `TRAVERSE FROM key:"F1*" FOLLOW cross_refs,entity_edges HOPS 3` |
| PATH | `PATH FROM type:book_extract TO type:framework MAX_DEPTH 4` |

- **Common mistake:** `FIND procedural_seed WHERE keywords CONTAINS 'STDP' LIMIT 5` → SYNTAX ERROR. Use `FIND type:procedural_seed WHERE contains("STDP") LIMIT 5`.
- WHERE conditions: `contains("text")`, `field:value` (glob `*` supported), `created > 7d` / `created < 24h`
- Duration format: `7d`, `24h`, `30m`
- Max query length: 2048 characters

## 18. Cost Matrix (6 Actions)

| Action | fp_cost | fn_cost | tp_benefit | Risk Profile |
|--------|---------|---------|-----------|-------------|
| whole_brain_purge | 30 | 1 | 3 | Offline legal-erasure ceremony only |
| deploy | 5 | 2 | 10 | Balanced |
| escalate_to_human | 2 | **30** | 20 | Conservative — avoid missing real issues |
| memory_write | **1** | 3 | 5 | Safest action |
| post_social | 8 | 1 | 5 | Moderate FP penalty |
| trade | **50** | **20** | **100** | Highest risk/reward |

**Usage:** The cost matrix governs autonomous action decisions. When an agent's confidence exceeds `auto_threshold` (0.8), the action is checked against this matrix. If `fp_cost` exceeds `require_human_above_cost`, human approval is mandatory.

## 19. Frailty Analysis (8 Labels)

| Component | Label | Rationale |
|-----------|-------|-----------|
| confidence_scoring | antifragile | Calibrates from outcome tracking. More data = better. |
| cross_ref_linking | antifragile | Network effects compound with scale. |
| aimos_memory_store | antifragile | More data = better recall. |
| autonomy_config | **fragile** | Thresholds are arbitrary constants (0.8/0.6). No data-driven calibration. |
| felix_trinity | **fragile** | Code exists but automation does not run. Zero resilience. |
| mcp_connections | **fragile** | In-memory only. Lost on restart. Static manifest. |
| session_context | **fragile** | Dies at compaction. No automatic persistence. |
| art_sidecar | robust | Fails open safely. Stable quality. Does not learn. |

## 20. Layer-Status Subsystems

Subsystem counts and status are live evidence. Read the protected status/layer surfaces and ledger any disagreement; never bootstrap a new fork with an Oracle-era snapshot.

## 21. Medallion Distribution

Query the live medallion surface. Layer membership and signed cognitive retrieval weight are separate dimensions; no historical count is Genesis authority.

## 22. Autonomy Configuration

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `auto_threshold` | 0.80 | Confidence ≥ this → auto-execute allowed actions |
| `notify_threshold` | 0.60 | Confidence ≥ this → notify but not auto-execute |
| `escalate_below` | 0.60 | Confidence < this → escalate to human |
| `allowed_actions` | recall, save | Depends on the verified actor's signed policy |
| `blocked_actions` | deploy, trade, whole-brain purge | Require explicit human authorization |
| `max_tool_loops` | 8 | Max MCP tool calls per session |
| `require_human_above_cost` | 0 | Cost threshold disabled |

## 23. Agent State

```json
{
  "company_id": "hom",
  "agent_id": "<enrolled-agent-id>",
  "phase": "request_loop",
  "current_task": "hi",
  "beliefs": {},
  "desires": {},
  "intentions": [],
  "confidence": 0.72,
  "last_action": "recall fallback",
  "next_action": "review results and persist what matters",
  "created_at": "2026-03-24T09:51:29.870Z",
  "updated_at": "2026-04-21T10:59:14.774Z"
}
```

Agent state is live, actor-specific data. Query the enrolled agent's signed endpoint; do not bootstrap a public installation with a personal or stale workstation snapshot.

## 24. Save Response Inconsistency

The guide documents a uniform save response (with `rpe`, `encoding_style`, `quarantined`, etc.). In reality:

- **`POST /save`** (canonical): Returns full gate results (`quality_score`, `wall_results`, `memory_tier`, `corrections_applied`, etc.)
- **`POST /reasoning-state`**: Returns lightweight (`saved`, `key`, `memory_id`). Same persistence path, different response contract.

**Rule for clients:** Use `/save` when you need gate feedback. Use `/reasoning-state` when you only need confirmation.

## 25. Skills

Each enrolled actor may have signed `skill_name` and `trigger_pattern` records. Query the live skill surface; do not assume a personal workstation inventory.

## 26. Known Failures & Friction Points

| Endpoint | Error | Workaround |
|----------|-------|------------|
| `GET /time-travel` | 404 if no memory exists for key at that time | Use exact key (not prefix). Returns 400 if `key` or `as_of` missing. Works correctly when key and timestamp match a real memory. |
| `GET /qmd/explain` | 400 (`q` param required, not `query`) | Use `?q=<qmd-query>` not `?query=` |
| `POST /qmd` | 400 (QMD syntax reject) | Use structured QMD grammar with `field:value` notation. Natural language and bare identifiers fail. See section 17. |
| `/graph/:entityId` | UNCONFIRMED | Needs valid entity ID; not tested in this probe |

---

## Post-Script: Diligence Commitment

Every implementation must:
1. **Probe endpoints before and after changes** using `aimos_diagnostic.py`
2. **Update this guide** if any response shape changes
3. **Log anomalies** to Aimos as `session_debrief` with `anomaly` tag
4. **Save the live contract** to Aimos after major discoveries

*If Aimos's live responses and this guide disagree, Aimos wins.*
