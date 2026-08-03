# Aimos Guide — Tier 1: Boot (ALWAYS LOADED)

> Base URL: `http://127.0.0.1:9100/aimos` | Auth: cryptographic envelope (Phase 10B+ — bearer tokens removed)
> Truth: Aimos > Files > Session. Aimos wins conflicts.

## Authentication (envelope-only)

Every protected request is signed by an agent identity. There is no bearer token. Each request carries four headers:

| Header | Source |
|---|---|
| `Aimos-Agent-Cert` | `agent_identity.cert` for the calling enrolled agent |
| `Aimos-Agent-Signature` | Ed25519 signature of `(method:path:nonce:ts:body)` using the agent's private key |
| `Aimos-Agent-Nonce` | Random 16-byte base64url, unique per request |
| `Aimos-Agent-Timestamp` | Unix seconds at signing time |

There is no hard-coded user identity. A clean installation has the autonomous
`housekeeper` system identity; human-directed calls use whichever agent the
operator explicitly enrolled. The auth gate derives that identity from the
verified certificate, never from a body field or environment variable.

To enroll a new agent (e.g. for a different LLM):

```bash
cd <repo-root>
node scripts/identity/enroll-agent.js <agent_id> --validity-days=30
```

This populates `agent_identity` (cert + pubkey) and writes the private key to `~/.aimos/agents/<agent_id>.key`.

**Never** copy or paste cert/private-key contents in logs, prompts, commit messages, or guide files.

## MANDATORY: Before You Act, Load the Right Tier

```
BEFORE YOUR FIRST RECALL  → GET /aimos/guide?tier=2  (pipeline, ranking, confidence)
BEFORE YOUR FIRST SAVE    → GET /aimos/guide?tier=3  (quality gate, types, clearance)
BEFORE DEBUGGING ANYTHING → GET /aimos/guide?tier=4  (services, papers, speed config)
```

**This is not optional.** If you skip a tier and your action fails, the error response will tell you which tier to load. Load it, then retry.

## Core API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/status` | Health check + memory count |
| `POST` | `/save` | Write memory (quality-gated, 10-stage pipeline) |
| `POST` | `/recall` | Signed search (native pipeline + cryptographic receipt) |
| `POST` | `/heartbeat` | System pulse + corrections |
| `POST` | `/event` | Log event to ledger |
| `GET` | `/guide?tier=N` | Load guide tier 1-4 |

## Recall — Minimum Viable

```http
POST /aimos/recall
Content-Type: application/json

{"query":"your search query","limit":10,"clearance_level":10}
```

Returns: `{ memories: [...], working_memory: "...", recall_meta: {...} }`

Key body fields: `query` (required unless `key`/`memory_id` is used), `limit` (1-200), optional clearance cap, `memory_type_filter`, `sort`.

Identity and company come from the verified certificate context. A master-signed recall grant sets the maximum clearance; request fields cannot raise it.

**Two recall modes:**
- Default (semantic): `"What's inside this drawer?"` — best-matching content, grouped by day
- `sort=chronological` (temporal-first): `"Which room was I in?"` — newest memories first by day

Both modes return `timem` envelopes on every memory showing day/session coordinates.

**Stage Zero** runs before embeddings: a lightweight SQL pass identifies relevant days/sessions and feeds them as `source_boost` into the hybrid query. Check `recall_meta.temporal_scope.dayBuckets` to see which days matched.

## Save — Minimum Viable

```
POST /aimos/save
{ "key": "type:topic", "value": "Min 20 chars of real content", "memory_type": "declarative" }
```

Returns: `{ success: true, memory_id: "uuid" }` or error with reason.

**Key must be namespaced** (`type:topic:detail`). **Value must be >= 20 chars** with substance. `"ok"`, `"test"`, `"null"` are instant-rejected.

## Memory Types (Quick)

| High Value | Medium Value | Low Value (dampened in recall) |
|------------|-------------|-------------------------------|
| `procedural_seed` | `directive` | `event_log` |
| `procedural` | `identity` | `heartbeat` |
| `tacit_knowledge` | `declarative` | `conversation_feed` |
| `book_extract` | `session_debrief` | |
| `framework` | `after_action_review` | |

## Aladdin Law (3 Rules)

1. Everything is `long-term`. Nothing expires. Nothing deletes.
2. No `is_active=false`, including quarantine. Quarantine is a retained trust
   label and low-frequency state, never deactivation.
3. Garbage never enters (quality gate rejects). What enters, stays.

## Error Quick-Fix

| Error | Fix |
|-------|-----|
| 400 "Missing key/value" | Both `key` and `value` are required |
| 403 "SUDO PROTECTED" | Memory has clearance 12+, you need 12+ too |
| 422 "Quality gate rejected" | Content too short, too generic, or a kill pattern |
| 400 "Empty query" | `query`, `key`, or `memory_id` is required for recall |
