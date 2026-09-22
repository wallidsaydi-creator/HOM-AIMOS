# Aimos Guide — Tier 3: Save Deep-Dive

> Load this BEFORE your first save. Every save passes through 10 stages and 3 quality walls.

## Save Request (Full)

```json
POST /aimos/save
{
  "key": "type:topic:detail",
  "value": "Min 20 chars. Must have substance — specifics, reasoning, outcomes.",
  "company_id": "hom",
  "scope": "global",
  "clearance_level": 5,
  "memory_type": "declarative",
  "source": "app",
  "is_correction": false,
  "supersedes_id": null
}
```

**Required:** `key` + `value`. Everything else has defaults.

## The 10-Stage Save Pipeline

```
 1. Envelope Authority ─ verifies signed identity, company, request receipt, and grants
 2. Sudo Guard ─────── clearance 12+ memories need 12+ to supersede
 3. Write Validator ── structural validation (exempt: event_log, dream_summary, etc.)
 4. RPE Gate ────────── Reward Prediction Error — routes processing depth
 5. Sensible Screen ── monitors RPE quality over time
 6. Transform Cache ── checks if schema transform was seen before
 7. Mnemonic Encoder ─ tags encoding style
 8. persistMemory():
    ├─ Quality Gate (3 walls)
    ├─ Secret Redaction (API keys auto-stripped)
    ├─ Quarantine Check (prompt injection → scope=quarantine)
    ├─ Embedding (768d ONNX)
    ├─ Cross-Reference (A-MEM Zettelkasten)
    ├─ Entity Extraction (HippoRAG)
    ├─ Aladdin Compliance
    ├─ Data Classification
    ├─ Medallion Layer
    └─ DB INSERT + trigger evaluation
 9. Cache Invalidate ─ semantic cache cleared
10. Response
```

## Quality Gate — The 3 Walls

**All 3 must pass. No exceptions. No bypasses.**

### Wall 1: THE FORM (structural integrity)
- Not empty
- Minimum 20 characters
- Not a kill pattern:
  - `null`, `undefined`, `none`, `n/a`, `ok`, `yes`, `no`, `test`, `ping`, `error`, `done`
  - `{}`, `[]`, `""`, `''`
  - Just a number: `42`
  - Repeated words: `error error error`
  - Generic dream filler: `mixed events, mixed events`

### Wall 2: THE FILTER (noise detection)
- Not >50% repetitive characters
- Not heartbeat spam (`knowledge gate blocked`, `System Heartbeat...30 minutes`)
- Not a duplicate of something saved in the last hour (300-char hash dedup)

### Wall 3: THE SUBSTANCE (value assessment)
- Substance score >= 0.30
- Score comes from: specifics (dates, paths, versions, proper nouns), reasoning words (`because`, `therefore`, `root cause`), action words (`fixed`, `implemented`, `deployed`), structure (`step 1`, `→`, `result:`), file paths (`.js`, `.ts`, `.json`)
- **Exempt types skip Wall 3** (but still pass Walls 1-2):
  `session_debrief`, `strategic_directive`, `operational_rule`, `constitution`, `procedural`, `session_reasoning`
- **Exempt key prefixes:** `paper:`, `book:`, `heartbeat:pulse`, `heartbeat:latest`

## Memory Types — Full Reference

### High Authority (boosted in recall)

| Type | Authority | When to Use |
|------|-----------|-------------|
| `procedural_seed` | +0.18 | Paper-extracted techniques with parameters |
| `procedural` | +0.15 | Learned procedures, algorithms, how-to |
| `tacit_knowledge` | +0.15 | Implicit knowledge, intuitions |
| `book_extract` | +0.14 | Book-derived knowledge |
| `framework` | +0.12 | Conceptual models |
| `directive` | +0.10 | CEO/operational rules |

### Medium Authority

| Type | Authority | When to Use |
|------|-----------|-------------|
| `identity` | +0.05 | Who we are, crew identity |
| `declarative` | +0.05 | General facts (default type) |
| `session_debrief` | +0.03 | Session summaries |
| `after_action_review` | 0.00 | Post-action analysis |

### Low Authority (dampened in recall)

| Type | Authority | When to Use |
|------|-----------|-------------|
| `event_log` | -0.08 | Timestamped events (high volume) |
| `heartbeat` | -0.10 | System health pulses |
| `conversation_feed` | -0.12 | Raw conversation logs |

### Special Types

| Type | Purpose |
|------|---------|
| `strategic_directive` | High-level strategy (exempt from validation) |
| `operational_rule` | System rules (exempt from validation) |
| `constitution` | Constitutional rules |
| `core_belief` | Foundational beliefs |
| `reasoning_state` | Reasoning snapshots |
| `dream_summary` | Nightly dream output |
| `dream_pattern` | Dream-detected patterns |
| `milestone` | Achievement markers (gold medallion) |
| `product` | Product-related (gold) |
| `infrastructure` | System infrastructure (gold) |
| `self_improvement` | Self-improvement records (gold) |
| `quarantine` | Auto-assigned to prompt injection attempts |

## Clearance Levels

| Level | Data Classification | Who Sees It |
|-------|-------------------|-------------|
| 1-3 | `public` | Everyone |
| 4-6 | `internal` | Agent-specific, operational |
| 7-9 | `confidential` | Strategic, financial |
| 10 | All except sudo | Executive |
| 12+ | `restricted` / sudo | Cannot overwrite without 12+ |

**Auto-classified** based on content: passwords/tokens → `restricted`, strategy/financial → `confidential`, agent/operational → `internal`, else `public`.

## Medallion Layers

| Layer | Types | Value |
|-------|-------|-------|
| **Gold** | milestone, product, identity, procedural, crew_identity, dream_summary, self_improvement, infrastructure | Core — highest |
| **Silver** | session, directive, heartbeat, intel, constitution_check, test | Operational |
| **Bronze** | Everything else | Working data |

## The 8 Gates

| Gate | Pipeline | Blocks When |
|------|----------|-------------|
| Envelope authority | Save | Signed identity, company, request receipt, or grant is invalid |
| Quality Gate | Save | Fails any of 3 walls |
| Write Validator | Save | Structural issues (non-exempt types) |
| RPE Gate | Save | Routes depth, never blocks |
| Sudo Guard | Save | Overwriting clearance 12+ without 12+ |
| Quarantine | Save | Prompt injection detected (base64/URL decoded) |
| Early Exit | Recall | High confidence — skips optional enrichment; signed epistemic/security closure still runs |
| Salience frequency | Recall | Annotates low-frequency evidence for ranking; never filters a retained memory |

## Correction Pattern

To update an existing memory:
```json
{
  "key": "same:original:key",
  "value": "New corrected content...",
  "is_correction": true,
  "memory_type": "directive"
}
```
This resolves the current topology head for that key and appends a new immutable
version whose `supersedes_id` points to the prior memory. Both versions remain
recallable; current-answer selection may prefer the signed successor without
suppressing the predecessor.

## Save Errors Cheat Sheet

| Status | Error | You Did | Fix |
|--------|-------|---------|-----|
| 400 | "Missing required field: key" | No `key` | Add `key` field |
| 400 | "Missing required field: value" | No `value` | Add `value` field |
| 400 | "Write validation failed" | Invalid chars in key | Use only `a-z0-9_:-` in keys |
| 401/403 | identity or authority error | Envelope identity, company, or clearance is invalid | Rebuild the exact signed envelope or obtain the required signed grant |
| 403 | "SUDO PROTECTED" | Overwriting clearance 12+ | Need clearance 12+ yourself |
| 422 | "Quality gate rejected" | Content too short/generic | Write 20+ chars with substance |
| 500 | Server error | Something broke | Check server logs |
