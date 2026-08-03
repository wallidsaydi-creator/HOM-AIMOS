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

The manifest is the source of truth for these six critical-connection maps,
not a substitute for the complete import graph or caller analysis. Its
validator dynamically imports every declared service and checks the named
exports. Architecture tests and the release-source gate fail when this wiring,
the service census, and the public documentation diverge.

### Native save path

All durable product writes converge on `services/write/persist-memory.js`.
The external save route composes eight principal execution boundaries:

| # | Stage | Native owner |
|---:|---|---|
| 1 | Signed request and authorization | `routes/aimos.js` |
| 2 | Write validation | `services/write/write-validator.js` |
| 3 | Prediction-error routing gate | `services/write/rpe-gate.js` |
| 4 | Mnemonic encoding | `services/context/mnemonic-encoder.js` |
| 5 | Quality gate | `services/write/quality-gate.js` |
| 6 | Embedding | `services/core/embeddings.js` |
| 7 | Canonical persistence and provenance | `services/write/persist-memory.js` |
| 8 | Signed retained-memory epistemic label | `services/security/memory-epistemic-classifier.js` |

`persistMemory()` is the canonical transaction owner. It repeats the quality
gate for internal callers, creates an immutable version, commits provenance in
the same transaction, and commits the retained-memory epistemic classification
before returning the admitted memory.

### Native recall path

`services/retrieval/native-recall-pipeline.js` is the canonical execution
owner. The externally visible path has eight principal stages:

| # | Stage | Native owner |
|---:|---|---|
| 1 | Query understanding and path selection | `services/retrieval/native-recall-pipeline.js` |
| 2 | Embedding and candidate opening | `services/core/embeddings.js` |
| 3 | Similarity statistics | `services/retrieval/similarity-stats.js` |
| 4 | Trust scoring | `services/learning/trust-score.js` |
| 5 | Concept-graph retrieval | `services/core/concept-graph.js` |
| 6 | Verified epistemic projection and selection | `services/retrieval/epistemic-trust-retrieval.js` |
| 7 | Pre-disclosure calibration | `services/retrieval/recall-calibrator.js` |
| 8 | Bounded evidence and signed receipt | `services/retrieval/native-recall.js` |

The 68 declared recall connections span exact-identifier, semantic, temporal,
graph, procedural, lineage, cache, instrumentation, and ingestion-assisted
paths. Candidate evidence passes provenance and authorization admission before
epistemic selection and bounded disclosure.

### Native cognitive-mutation plane

Canonical memory content and existence are immutable. Cognitive mutation
changes only `retrieval_weight`, bidirectionally within `[0.1, 3.0]`, so a low
frequency never becomes deletion or ineligibility.

The implemented signal owners are distinct and explicit:

| Lane | Signal and update | Native owner |
|---|---|---|
| Outcome adaptation | Signed positive/negative outcome → cumulative age-neutral valence → bounded reference-point update | `services/learning/stdp-kernel.js` |
| Valence evidence | Append-only signed reward evidence and `tanh(sum rewards)` judge | `services/governance/valence-ledger.js`, `services/governance/valence-judge.js` |
| Consolidation | Governed positive SPICED strengthening of eligible retained memories | `services/dream/spiced-consolidator.js` |
| Relational consensus | Optional symmetric elevation or attenuation from semantic-neighborhood support | `services/dream/hebbian-consensus.js` |

Hebbian consensus is shadow-first and disabled unless its signed governor flag
is enabled. The three mutation owners call the same restricted persistence
boundary; no service receives direct authority to rewrite a weight.

Every changed target follows this certified path:

1. the owning restricted transaction takes the per-memory advisory lock;
2. `services/governance/governor-provenance.js` appends a housekeeper-signed
   `REWEIGHT` provenance node;
3. `services/security/housekeeper-signer.js` signs a separate fixed-width
   transition commitment;
4. migration 091's `apply_signed_cognitive_reweight` verifies scope, active
   signer epoch, old/new milliscaled state, provenance, continuity, bounds, and
   no-fork predecessor;
5. the same transaction appends the cognitive projection and updates only
   `retrieval_weight`; and
6. SQL and `services/security/cognitive-weight-verifier.js` independently
   replay the per-memory chain and whole-corpus proof root.

If the quantized target equals the current state, signed outcome evidence and a
signed unchanged event remain retained, but no fictitious projection is
appended. The complete byte layout, proofs, and verification contract are in
`docs/security/cognitive-weight-chain-SPEC.md`.

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

Beyond the principal stages above, the native save path composes:

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

Beyond the principal stages above, native recall combines:

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

## Cryptographic boundaries

Cryptographic accountability is additive to the memory engine and enters at
four explicit boundaries:

- admitted memories receive signed, reversible epistemic labels bound to live
  content hashes;
- recall verifies and consumes those projections, applies a verified
  calibration snapshot, and returns bounded evidence under an RFC 6962-style
  domain-separated Merkle receipt;
- cognitive-weight changes require housekeeper-authorized signed transitions
  bound to the terminal provenance node, signer epoch, quantized old and new
  weights, and no-fork predecessor; and
- the database mutation boundary and independent portable verifier both verify
  Ed25519 evidence.

These commitments prove authorization, ordering, integrity, and decision
history. They do not prove that an authorized assertion is factually true.

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

## Canonical measured evidence

| Result | Value |
|---|---:|
| LongMemEval, LLM-judged | 459/500 — 91.8% |
| LoCoMo, LLM-judged | 1472/1986 — 74.12% |
| LoCoMo, separate upstream-compatible token F1 | 58.20 |
| PoisonedRAG N=100, poison in attacked top-5 disclosures | 0/100 |
| Same target set, epistemic policy bypassed | 94/100 |
| Mutation authorization rejection cases | 7/7 |
| Cognitive tamper cases detected | 4/4 |
| SQL/portable cognitive verifier parity | 9/9 records |
| Signed cognitive-transition latency, median | 4.865 ms |

The protocols are distinct and are not averaged. The sanitized, self-hashed
`eval/publication/verified-benchmark-results.json` binds the promoted run
artifacts by SHA-256 and is the public numerical authority.

## Change discipline

Before modifying a service, inspect its imports, callers, pipeline edge,
database contract, tests, and cited paper header where mathematical technique is
involved. The release forbids wrappers, hooks, placeholders, stubs, fake-green
tests, unledgered authority, and selective memory deletion.

Regenerate the service inventory after file-set changes. Regenerate the Genesis
manifest after any Guide-byte change. Build public releases only in an empty
directory with fresh Git history and verify the complete tree before publishing.
