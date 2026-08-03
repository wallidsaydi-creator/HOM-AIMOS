# AIMOS public architecture map

Status: source-derived public runtime map
Service census: 275 JavaScript services across 17 groups

This document describes the released AIMOS backend. It contains no deployment
state, retained memory, private product roadmap, machine path, operator record,
or live-run transcript. The exact file inventory is
`hom-architecture-manifest.json`; code imports, callers, tests, migrations, and
live endpoints remain authoritative for runtime behavior.

## Authority order

1. Live AIMOS endpoints and retained, cryptographically admitted evidence.
2. Generated `architecture-authority.json` on the installed machine.
3. `hom-architecture-manifest.json`.
4. The manifest-bound `Guide/` corpus.
5. This navigation document.

The portable `architecture-authority.template.json` is distributed publicly.
The generated machine-local authority, identities, credentials, memories, and
receipts are never release inputs.

## Runtime topology

```text
signed client or local housekeeper
              |
              v
        authentication gate
              |
       +------+-------+
       |              |
       v              v
 native save       native recall
       |              |
       v              v
 quality, write,   provenance admission,
 epistemic and     retrieval, epistemic
 lineage checks    selection and calibration
       |              |
       +------+-------+
              v
 PostgreSQL memory, provenance, identity,
 authorization, credential and event ledgers
              |
       +------+-------+
       |              |
       v              v
 housekeeper      signed receipts and
 maintenance      portable verification
```

PostgreSQL is the canonical store. The filesystem carries source code,
machine-local keys protected by file permissions and Keychain custody, and
generated authority metadata; it is not a second memory authority.

## Public entrypoints

`server.js` mounts these runtime surfaces:

- `/aimos` — signed save, recall, status, lineage, cognition, and diagnostics.
- `/agents` — enrolled-agent management and execution.
- `/tools` — tool and integration execution.
- `/status` and `/stats` — runtime state and event projections.
- `/governance` — governed policy and improvement-cycle operations.
- `/integrations` — provider and application connection surfaces.
- `/security` — security diagnostics, red-team, and canary surfaces.
- `/v1` — compatible ingestion and recall contracts.
- `/mcp` and `/mcp/bridge` — MCP protocol translation surfaces.

`services/security/auth-gate.js` and the server middleware order enforce the
single HTTP authentication boundary. Protected requests use signed certificate
envelopes; bearer-only authentication is not an AIMOS authority path.

## Canonical pipelines

`services/pipeline-manifest.js` declares the critical wiring for six pipelines.
It declares 146 service connections across 6 pipelines.

| Pipeline | Entrypoint | Responsibility |
|---|---|---|
| Save | `routes/aimos.js` | Admission, quality, write validation, epistemic classification, immutable persistence, provenance and lineage |
| Recall | `routes/aimos.js` | Query planning, retrieval, provenance admission, epistemic selection, calibration, bounded evidence and signed receipt |
| Agent run | `services/orchestration/agent-runner.js` | Constitution, governance, model/tool execution, learning and evidence recording |
| Dream | `jobs/nightly-dream.js` | Governed, non-destructive consolidation and learning projections |
| Heartbeat | `jobs/heartbeat.js` | Database, memory, event, process and retention health |
| Governance | `services/orchestration/governance-resolver.js` | Policy, rule, trust and decision resolution |

The manifest is a critical-connection map, not a substitute for import and
caller analysis.

## Service inventory

The census counts top-level `services/<group>/*.js`, excluding `index.js`
barrels, hidden directories, and the root infrastructure file
`services/pipeline-manifest.js`.

| Group | Files | Public responsibility |
|---|---:|---|
| retrieval | 55 | Query modes, vector/sparse retrieval, temporal and graph paths, epistemic selection and calibration |
| orchestration | 43 | Agent execution, tools, governance, scheduling, model selection and run state |
| security | 36 | Identity, signed envelopes, authorization, provenance, credentials, canaries and epistemic labels |
| temporal | 25 | Freshness, event order, supersession, time-aware retrieval and retained frequency |
| learning | 23 | Calibration, reflection, skill consolidation, STDP and bounded plasticity |
| observe | 22 | Event ledger, explanation, drift, routing, quantitative gates and diagnostics |
| core | 15 | Constitution, providers, permissions, embeddings, graph and runtime authority |
| write | 13 | Canonical persistence, quality, intent, credential and validation lanes |
| context | 9 | Scoped state, workspace partitions, continuity and active-memory policy |
| integrations | 9 | Provider, search, messaging and application integrations |
| governance | 7 | Retention law, configuration, valence and governance evidence |
| dream | 5 | Consolidation, feedback, consensus and delta projections |
| ingestion | 4 | Entity, relationship and temporal observation |
| shared | 4 | Shared native LLM, schema, scale and session helpers |
| answering | 2 | Prompt variants and answer ensembles |
| runtime | 2 | Serving and local-inference control |
| caching | 1 | Semantic cache support |

File count alone does not prove activation. Activation claims require an
import/caller path, focused tests, and when applicable a native live-fire proof.

## Memory and save plane

All durable product writes converge on `services/write/persist-memory.js`.
The native save path composes:

- certificate-envelope authentication and request receipt;
- write authorization and session ownership;
- quality and intent classification;
- retained-memory epistemic classification;
- immutable memory/version persistence;
- content-hash and provenance-chain commitments;
- lineage and supersession topology where applicable;
- event-ledger and response evidence.

Quarantine and epistemic labels do not delete or suppress canonical evidence.
Irrelevant or unsafe material remains retained and distinguishable while its
retrieval frequency and contextual eligibility are governed by signed state.

## Recall plane

`services/retrieval/native-recall-pipeline.js` is the canonical execution path.
It combines:

- mode planning and query decomposition;
- exact-identifier, semantic, temporal, graph, procedural and lineage paths;
- provenance and authorization admission;
- retained-memory epistemic state;
- trust-aware selection and calibration;
- bounded context construction and source attribution;
- signed recall receipts and diagnostic projections.

Memory evidence is reference material, never an instruction channel. Recall
does not expose hidden chain-of-thought; it returns bounded evidence and
verifiable decision metadata.

## Identity, signing and authorization

The security plane uses Ed25519 certificates and request signatures, nonce and
timestamp replay controls, append-only identity epochs, revocation events,
signed authorization, and hash-linked action ledgers. The `housekeeper` is the
autonomous system-maintenance identity created by Genesis. User-directed agents
are separately enrolled and cannot inherit housekeeper authority.

Credentials are kept in platform custody and represented in AIMOS by signed,
append-only lifecycle evidence. Plaintext credentials, private keys, live
certificates, and account identifiers are excluded from the repository.

## Cognitive mutation and retention

Cognitive weight is bounded and bidirectional. Every admitted transition is
signed and chained; a memory can move down or up as evidence changes, but its
canonical existence is unaffected. The public specifications and migrations
define the commitment and verification contracts.

AIMOS has no ordinary decay, selective deletion, suppression, or deactivation
authority. The only destructive path is the explicit, authenticated
whole-brain legal purge ceremony. That ceremony inventories the complete target
and emits a signed terminal receipt; it is never invoked by normal runtime
behavior.

## Autonomous maintenance

The housekeeper runs system maintenance without borrowing an enrolled user
agent. Heartbeat records health and retention evidence. Dream and learning
jobs append governed projections and evidence; they do not create a parallel
memory store or an unledgered deletion path.

## First-run Genesis

`scripts/genesis-install.mjs` verifies the Genesis manifest and locked native
dependency metadata before creating state. It then creates the database and
restricted runtime role, applies ordered migrations, generates machine-local
authority, provisions the housekeeper, and ingests every manifest-bound Guide
file through the signed native save path.

The installer rejects `.env` authority, reserved Oracle ports, unsafe database
names, missing dependency proofs, changed Guide bytes, and partial Genesis
state. A new installation therefore starts with a cryptographically bound
operating corpus rather than a blank brain.

## Verification surfaces

Public verification includes:

- source, architecture, security and benchmark-contract tests;
- Genesis-manifest and dependency-lock verification;
- package, license, SBOM, secret and private-path gates;
- portable cognitive and epistemic-chain verifiers;
- sanitized, self-hashed benchmark aggregates;
- reproducible dataset downloaders with pinned revisions and hashes.

Raw benchmark corpus, provider payloads, live memories, run directories,
identity-bearing receipts, internal plans and private audit notes are not
distributed.

## Change discipline

Before modifying a service, inspect its imports, callers, pipeline edge,
database contract, tests, and cited paper header where mathematical technique is
involved. The release forbids wrappers, hooks, placeholders, stubs, fake-green
tests, unledgered authority, and selective memory deletion.

Regenerate the service inventory after file-set changes. Regenerate the Genesis
manifest after any Guide-byte change. Build public releases only in an empty
directory with fresh Git history and verify the complete tree before publishing.
