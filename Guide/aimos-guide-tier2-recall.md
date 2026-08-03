# Aimos Guide — Tier 2: Recall Deep-Dive

> Load this BEFORE your first recall. Your query quality determines result quality.

Recall is available only as envelope-signed `POST /aimos/recall`. The signature covers the exact JSON body, method, and path. Unsigned/query-string GET recall is rejected.

## Two Recall Modes

Aimos supports two parallel recall paths, modeled as **navigating a house**:

| Mode | Trigger | Metaphor | What surfaces first |
|------|---------|----------|---------------------|
| **Temporal-first** | `sort=chronological` | "Which room was I in?" → days then sessions | Most recent day's memories first |
| **Semantic** | default (no sort param) | "What's inside this drawer?" → content matches | Best-matching content, grouped by day |

**When to use which:**

- **"What did we last work on?"** → body field `"sort":"chronological"` — you want the most recent session, not the best semantic match
- **"Why did we create the cert system?"** → default semantic — you want the reasoning, regardless of when it was saved
- **"What happened this week?"** → body fields `"sort":"chronological","limit":20` — temporal sweep of recent activity

Both modes always return `timem` (TiMem) envelopes on every memory, so you always see the day/session coordinates even in semantic mode.

## Stage Zero: Temporal Scoping

Before the embedding query (stage 1), Aimos runs **temporal scoping** — a lightweight SQL pass that identifies which days and sessions are relevant to the query. This is Stage Zero.

```
STAGE ZERO: temporal_scoping
  ├── Query recent memories matching keywords/tsvector
  ├── Extract day buckets (top 3 most recent days)
  └── Feed day buckets into hybrid query as source_boost
```

Temporal scoping gives recent matching memories a `source_boost` in the SQL candidate phase:

| Age | source_boost (distance advantage) |
|-----|-------------------------------------|
| < 1 day | 0.05 |
| 1–7 days | 0.10 |
| 7–30 days | 0.20 |
| > 30 days | 0.30 |

The `temporal_scope` field in `recall_meta` shows what Stage Zero found:

```json
"temporal_scope": {
  "dayBuckets": ["2026-05-11", "2026-05-05", "2026-04-24"],
  "matchCount": 20
}
```

## Recall Parameters (Full)

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `q` / `query` | string | **required** | Natural language search |
| `company_id` | string | verified company | Must equal the signed execution context |
| `agent_id` | string | verified actor | Optional assertion only; spoofing is rejected |
| `limit` | int | `10` | Max results (1-200) |
| `clearance_level` | int | signed grant ceiling | Optional lower cap; cannot exceed the master-signed grant |
| `memory_type_filter` | string | none | e.g. `procedural_seed`, `session_debrief` |
| `source_filter` | string | none | e.g. `longmemeval`, `app` |
| `session_id` | string | none | Scope to ingestion session |
| `max_hops` | int | `2` | Graph traversal depth (1-4) |
| `mode` | string | `"linear"` | `"adaptive"` = multi-scale |
| `sort` | string | relevance | `"chronological"` = newest-first by day |

## The 19-Stage Pipeline (with Stage Zero)

```
 0. temporal_scoping ──── Pre-pipeline: identify relevant days/sessions → source_boost
 1. embedding_query ────── 768d vector from query text (~5ms)
 2. cache_check ────────── Semantic cache (cos>0.85, TTL 300s) → HIT skips all
 3. hybrid_vector_bm25 ─── 3 parallel pools: vector + BM25 + temporal(source_boost) → UNION + RRF
 4. entity_recall ──────── HippoRAG: extract entities → entity_memory_edges lookup
 5. recursive_graph_walk ── WITH RECURSIVE on cross-refs (1-4 hops)
 6. bm25_rescue ────────── Second keyword pass (large docs dilute embeddings)
 7. reranking ──────────── Term overlap + recency boost (≤24h: +0.15, ≤7d: +0.10, ≤30d: +0.05)
 8. qmd_activation ─────── Low confidence? → structured FTS + key/metadata search
 9. hyde_expansion ─────── Still low? → HyDE expands query + multi-stage retrieval
10. deep_recall_override ─ Specific cue pre-check before early exit
11. early_exit_decision ── High confidence? → skip dormancy/trust/PPR/calibration/mnemonic, return now
12. dormancy_evaluation ── Annotate low-frequency salience; never drop memories
13. deep_recall_override ─ Exact key / strong identifier / high-specificity semantic cue → salience_penalty=0
14. trust_scoring ──────── Rank by credit_score + access patterns
15. concept_graph_ppr ──── HippoRAG PPR on knowledge graph + passage hydration
16. recall_calibration ──── LMS dual-channel calibration (corrects bias)
17. mnemonic_encoding ──── Style match (visual_hook, narrative, procedural)
18. confidence_scoring ──── Final composite: semantic + authority + keyword + recency + type
19. final_sort ──────────── TiMem-guided: day bucket → TMT level → confidence
                           Chronological override if sort=chronological
```

**Stages 8-9 auto-activate** when initial results are poor. **Stage 11** can skip dormancy/trust/PPR/calibration/mnemonic when results are strong — but the uniformity guard prevents early exit when all rerank scores are identical (uncertainty, not confidence). You don't control this — the pipeline self-optimizes.

## Confidence Scoring

Each memory gets `recall_confidence` (0-1). When rerank scores are uniform (all the same), the formula redistributes weight away from rerank toward recency, authority, and type:

**Default (differentiated rerank):**

| Component | Weight | Source |
|-----------|--------|--------|
| semantic | 46.6% | Anisotropy-corrected cosine (z-score normalized) |
| authority | 25% | credit_score / 2 |
| keyword | 11.4% | BM25 term overlap ratio |
| recency | 5.7% | 24h=1.0, 7d=0.8, 30d=0.6, older=0.35 |
| type_authority | 11.3% | +0.18 procedural_seed, -0.12 conversation_feed |

**Uniform rerank (all scores identical — no differentiation):**

| Component | Weight | Source |
|-----------|--------|--------|
| recency | 20% | Age signal takes priority |
| authority | 35% | Credit score dominates |
| type_authority | 25% | Memory type authority |
| freshness | 20% | Freshness signal from metadata |

**Bands:** high >= 0.75, medium >= 0.50, low < 0.50

## Understanding recall_meta

```json
{
  "qmd_activated": true,       // structured fallback triggered (low initial quality)
  "top_rerank": 0.45,          // best term-overlap score
  "avg_rerank": 0.32,          // average of top 5
  "total_results": 12,
  "confidence_distribution": { "high": 2, "medium": 6, "low": 4 },
  "temporal_scope": {
    "dayBuckets": ["2026-05-11", "2026-05-05", "2026-04-24"],
    "matchCount": 20
  },
  "temporal_truth": {
    "truth_band": "mixed",     // "live" (recent), "historical" (old), "mixed"
    "newest_memory_at": "2026-05-11T00:02:44.625Z",
    "oldest_memory_at": "2026-04-06T09:15:56.615Z",
    "median_age_hours": 168,
    "recent_ratio": 0.33,      // % from last 72h
    "stale_ratio": 0.17        // % older than 90d
  }
}
```

## TiMem Envelopes on Every Memory

Every memory in the response includes a `timem` envelope showing its temporal coordinates:

```json
"timem": {
  "tmt_level": "L2",                    // L5=profile, L4=week, L3=day, L2=session, L1=segment
  "temporal_bucket": {
    "day": "2026-05-05",                // L3: which room (day)
    "session": "2026-05-05T23:51",       // L2: which drawer (session)
    "week": "2026-W19"                  // L4: which shelf (week)
  },
  "parent_buckets": {
    "session": "2026-05-05T23:51",
    "day": "2026-05-05"
  }
}
```

**How to use this:** When you see `tmt_level: "L2"`, you know this memory belongs to a specific session. Group memories by `temporal_bucket.day` to see what happened on each day. The L5→L4→L3→L2→L1 hierarchy maps directly to: **profile → week → day → session → segment**.

## Filtering Strategies

**By type** — most powerful filter:
```json
{"query":"paper techniques","memory_type_filter":"procedural_seed"}
{"query":"session summaries","memory_type_filter":"session_debrief"}
{"query":"timestamped events","memory_type_filter":"event_log"}
{"query":"CEO directives","memory_type_filter":"directive"}
```

**By time** — for recent context (temporal-first mode):
```json
{"query":"recent context","sort":"chronological","limit":20}
```

**By day** — query for a specific day's context:
```json
{"query":"session decisions may 5","sort":"chronological","limit":10}
```

The `temporal_scope.dayBuckets` in the response tells you which days matched, so you can narrow further if needed.

**By depth** — for connected knowledge:
```json
{"query":"connected knowledge","max_hops":4}
{"query":"connected knowledge","mode":"adaptive","selectivity":"strict"}
```

## Post-Recall Side Effects

- Recall access is recorded as a signed append-only receipt event; canonical memory rows are not updated.
- Recall responses expose derived `retrieval_frequency_band = quiet | normal | high`
- Specific cue override is non-destructive: exact key, strong identifier, or high-specificity semantic matches get `salience_penalty=0` and remain rank-eligible
- Frequency metadata is non-destructive: no decay, suppression, pruning, deletion, or canonical content mutation
- Result cached for similar future queries (if cache enabled)

## When Recall Fails

| Symptom | Cause | Fix |
|---------|-------|-----|
| 0 results | Query too vague | Use specific terms, try `memory_type_filter` |
| All low confidence | Query doesn't match stored content | Try different phrasing, check `qmd_activated` |
| Wrong time period | Recency bias | Use `sort=chronological` or add date terms |
| Missing known memory | Signed grant/ACL excludes it | Ask the master to append the required exact-epoch recall grant; a request cannot self-raise clearance |
| Stale results | Cache hit | Results may be up to 300s old if cache enabled |
