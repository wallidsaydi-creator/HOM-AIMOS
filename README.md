# HOM-AIMOS — Cryptographically Auditable Persistent Memory

HOM-AIMOS is a local-first persistent-memory backend for agents. It combines
signed identity, append-only provenance, hybrid retrieval, temporal reasoning,
and a housekeeper identity that owns autonomous maintenance without depending
on an enrolled user agent.

## Security is the architecture

Persistent memory is an agent control surface: compromise what an agent is
allowed to retain, adapt, or disclose and every downstream decision can be
influenced. HOM-AIMOS therefore implements security inside the save, recall,
mutation, credential, tool-action, and autonomous-maintenance paths rather than
placing a security wrapper around storage.

| Boundary | Implemented capability |
|---|---|
| Identity and authority | Certificate-bound Ed25519 identities; method-, path-, body-, and nonce-bound request signatures; exact signer-epoch authorization; replay and revocation checks; macOS Keychain custody |
| Memory integrity | Immutable canonical versions, append-only provenance, and signed reversible epistemic labels bound to retained content hashes |
| Authorized adaptation | Housekeeper-authorized, no-fork cognitive-weight transitions verified by the restricted database writer and an independent portable verifier |
| Recall disclosure | Provenance and authorization admission, epistemic trust selection, bounded evidence, and RFC 6962-style domain-separated Merkle receipts |
| Operational evidence | Append-only request, authorization, credential-use, tool-action, event, and cognitive-transition ledgers |
| Runtime defense | Context-aware security decisions, canary write gates, post-run scheming assessment, and a cyber-security firewall on the declared agent execution path |
| Defensive self-assessment | A diagnostic-only harness with OWASP-LLM-mapped campaigns, benign calibration, canary checks, and SABER-style posture scoring |

Potentially poisoned content is retained rather than silently deleted. Signed
epistemic state remains revisable and auditable, and recall consumes it as
trust evidence. In the promoted PoisonedRAG N=100 run, no poison passage entered
the attacked top-5 disclosures (0/100); when the signed-label retrieval policy
was bypassed on the same target set, poison was retrieved for 94/100 targets.
The complete results, denominators, uncertainty, and protocol boundaries are
reported in [Measured](#measured) and the self-hashed publication aggregate.

**Scope:** this release is a persistent-memory system with an implemented
security architecture. It is not a formally certified security product and
has not received an independent penetration test. Its cryptographic evidence
supports integrity, authorization, traceability, and historical continuity;
it does not establish that remembered content is true.

See [SECURITY.md](SECURITY.md), [THREAT-MODEL.md](THREAT-MODEL.md), and the
[cognitive-weight chain specification](docs/security/cognitive-weight-chain-SPEC.md)
for the enforced boundaries and verification model.

## What HOM-AIMOS is

HOM-AIMOS is a complete persistent-memory backend, not a provenance layer
attached to a vector store. Its source-derived architecture binds a
275-service census and declares six critical pipelines containing 146 service
connections. Save and recall each expose eight principal native execution
boundaries.

### Save — 8 stages

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

### Recall — 8 stages

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

### Cognitive mutation — retained, bounded, reversible

HOM-AIMOS does not treat memory as static after admission. It keeps canonical
content immutable while allowing its retrieval weight to move bidirectionally
within `[0.1, 3.0]` as signed evidence changes. A low weight means lower
retrieval frequency, never deletion or ineligibility.

Three native mutation lanes converge on one certified database writer:

- outcome adaptation appends signed positive or negative evidence to
  `services/governance/valence-ledger.js`, computes an age-neutral cumulative
  valence through `services/governance/valence-judge.js`, and applies the
  bounded reference-point update in `services/learning/stdp-kernel.js`;
- SPICED consolidation may strengthen eligible retained memories through
  `services/dream/spiced-consolidator.js`; and
- optional Hebbian consensus may elevate supported hubs or attenuate divergent
  evidence through `services/dream/hebbian-consensus.js`. This lane is
  shadow-first and disabled until its signed governor flag is enabled.

Every changed target passes through
`services/governance/governor-provenance.js`, which appends a housekeeper-signed
`REWEIGHT` node and creates a distinct fixed-width transition signature. The
`apply_signed_cognitive_reweight` function in migration 091 verifies the exact
tenant, memory, signer epoch, old and new milliscaled weights, provenance hash,
continuity, and no-fork predecessor before it atomically appends the projection
and updates only `retrieval_weight`. A quantized no-op retains its signed
outcome evidence without inventing a transition.

`verify_cognitive_weight_chain()` and `verify_all_cognitive_weight_chains()`
replay the database evidence, while
`services/security/cognitive-weight-verifier.js` independently verifies the
same baseline, provenance, signature, continuity, terminal-state, and corpus
proof-root contracts. The normative byte layout and invariants are published
in [`docs/security/cognitive-weight-chain-SPEC.md`](docs/security/cognitive-weight-chain-SPEC.md).

The save manifest declares 13 critical service connections; recall declares
68 spanning exact-identifier, semantic, temporal, graph, procedural, and
lineage paths. The service census contains retrieval 55, orchestration 43,
security 36, temporal 25, learning 23, observe 22, core 15, write 13, context
9, integrations 9, governance 7, dream 5, ingestion 4, shared 4, answering 2,
runtime 2, and caching 1.

`services/pipeline-manifest.js` is the source of truth for the six critical
connection maps. Its validator dynamically imports all 146 declarations and
checks their named exports; architecture tests and the release-source gate fail
when the declared topology and public documentation diverge.

## What is built on top

The save and recall paths are a working memory system on their own. The
cryptographic layer enters at explicit boundaries:

- Save stage 8 assigns each retained memory a signed, reversible epistemic
  label bound to its live content hash.
- Recall stages 6–8 verify and consume the epistemic projection, apply a
  verified calibration snapshot, and return bounded evidence under an
  RFC 6962-style domain-separated Merkle receipt.
- Cognitive mutation changes retrieval weight within a constitutional interval
  only through housekeeper-authorized signed transitions. Each transition binds
  the terminal provenance node, signer epoch, quantized old and new weights,
  and no-fork predecessor.
- Ed25519 verification runs in the database mutation boundary and in an
  independent portable verifier.

Canonical memory is never selectively removed, decayed, expired, suppressed,
or deactivated. The sole erasure path is an offline, master-signed,
all-or-nothing whole-brain purge that emits a signed terminal receipt.

## Measured

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

These are distinct protocols and are not averaged. Every figure regenerates
from the sanitized, self-hashed aggregate in
[`eval/publication/verified-benchmark-results.json`](eval/publication/verified-benchmark-results.json),
which binds the promoted run artifacts by SHA-256.

The central security distinction is **integrity, not omniscience**. AIMOS can
prove that an authorized identity asserted a specific memory at a particular
ledger position and that the retained evidence has not been silently rewritten.
It cannot prove that the asserted content is factually true. The threat model
names this failure class **Authenticated-But-False (ABF)**.

## Release status

This repository contains the HOM-AIMOS 1.0 source release. Its promoted, isolated
evaluation lanes are complete and bound to the sanitized, self-hashed aggregate
in [`eval/publication/verified-benchmark-results.json`](eval/publication/verified-benchmark-results.json).
It carries the canonical utility results above, 1.02% induced attack success
among clean-negative PoisonedRAG targets, mutation-integrity evidence,
epistemic ablation, blinded system-author agreement, and 39/39 verified signed
scratch-brain purge evidence. Older batch-save runs are non-canonical and are
not release claims.

The architecture manifest mechanically binds the current 275-service census.
That number is an inventory fact, not a performance claim.

## Security and retention invariants

- External save, recall, credential, authorization, and mutation actions are
  bound to signed certificate envelopes.
- Secrets and identity keys use macOS Keychain custody. `.env` files and
  environment-owned credentials are rejected as runtime authority.
- Canonical memory is never selectively deleted, decayed, expired, suppressed,
  or deactivated. Contradictions and corrections are retained through signed
  supersession and cognitive transitions.
- The sole erasure mechanism is an offline, master-signed, all-or-nothing
  whole-brain purge that emits a signed receipt.
- Security quarantine remains retained and recallable under its enforced
  clearance and cognitive policy.
- Retained reference memories carry a separate, signed, reversible epistemic
  label. Poison suspicion changes evidence handling without rewriting or
  deleting the underlying observation; later evidence may refute the label.
- Native implementation only: no placeholder services, fake controls, runtime
  wrappers, or bypass hooks.

See [SECURITY.md](SECURITY.md) and [THREAT-MODEL.md](THREAT-MODEL.md) before
deploying or integrating AIMOS.

## Platform and prerequisites

The AIMOS 1.0 source release supports Intel and Apple silicon Macs running
macOS 14 or later. A clean installation requires:

- Apple Command Line Tools (`xcode-select --install`), including `git`, `curl`,
  a compiler, and `make`;
- Node.js 20 or 24 with `npm`;
- PostgreSQL 18;
- pgvector built for the selected PostgreSQL 18 server;
- libsodium and `pkg-config`/pkgconf; and
- macOS Keychain access.

Homebrew is the supported dependency provisioner for a clean source install,
but it is not AIMOS runtime authority and is not required when compatible
dependencies already exist. GPG is not required to install or run AIMOS. The
Genesis installer verifies or builds the checksum-locked pgsodium 3.1.11 source
and artifacts before database creation. Other operating systems and PostgreSQL
majors are not claimed as supported by this release.

## Install and start

Do not create the AIMOS database manually. Genesis owns database creation,
migrations, restricted-role custody, housekeeper enrollment, and signed Guide
ingestion.

Download the release source archive or clone the repository, then run from its
root:

```sh
cd HOM-AIMOS
./install-macos.sh --check
./install-macos.sh
```

The installer displays its plan and asks before Homebrew or Genesis changes
machine state. It uses the repository `Brewfile`, installs the locked npm graph,
and hands control to native Genesis. It does not download or execute the
Homebrew installer itself.

For an explicit manual dependency path:

```sh
xcode-select --install              # only when Command Line Tools are absent
# Install Homebrew from https://brew.sh when no compatible toolchain exists.
brew bundle --file Brewfile
brew services start postgresql@18
npm ci
npm run genesis:install -- --aimos-db aimos --aimos-port 9100
```

After Genesis completes, start the server:

```sh
npm start -- --aimos-db aimos --aimos-port 9100
```

Verify the live service:

```sh
curl --fail http://127.0.0.1:9100/healthz
```

AIMOS owns port 9100. Ports 9000 and 9001 are reserved for the separate Oracle
system and are rejected by this fork.

The complete enrollment, signed save/recall proof, upgrade, and purge ceremonies
are documented in [DEPLOYMENT.md](DEPLOYMENT.md).

Release packages include SHA-256 checksums, a CycloneDX SBOM, and GitHub keyless
build provenance. GPG is not required. See [RELEASE.md](RELEASE.md) for online
and offline verification boundaries.

## Architecture and agent guidance

- [ARCHITECTURE-MAP.md](ARCHITECTURE-MAP.md) describes the implemented runtime.
- [hom-architecture-manifest.json](hom-architecture-manifest.json) is the
  mechanically verified service inventory.
- [architecture-authority.template.json](architecture-authority.template.json)
  is the portable authority used to generate machine-local runtime authority.
- [Guide/AGENTS.md](Guide/AGENTS.md) is the LLM-agnostic boot and truth-hierarchy
  index. `Guide/` is also the cryptographically manifest-bound Genesis corpus.

## Verification

The ordinary source suite never touches a live database:

```sh
npm test
npm run lint
npm audit --omit=dev --audit-level=high
```

Benchmark contract tests require the public datasets, which are downloaded from
immutable upstream revisions and verified by SHA-256:

```sh
bash eval/data/download.sh
node eval/prepare-canonical-corpus.mjs
npm run test:benchmark:contracts
```

The complete release-source gate is:

```sh
npm run test:release:source
```

The isolated Genesis and signed live-fire ceremony uses a disposable database
and must be run with AIMOS 9100 stopped because it temporarily exercises the
machine-local housekeeper certificate cache:

```sh
npm run test:security:isolated
```

## Benchmark boundary

Benchmark data is never distributed under the AIMOS source license and is
never ingested into the canonical user brain. The isolated runner creates a
fresh Genesis-installed scratch brain and preserves signed save, session,
recall, model, judgment, and purge evidence separately.

Retrieval metrics and judged answer accuracy are reported independently. A
retrieval hit is not presented as a correct answer.

## License and contributions

Source code is licensed under AGPL-3.0-or-later. A separate commercial license
may be available for deployments that cannot comply with AGPL; see
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md). Downloaded benchmark datasets
retain their upstream licenses.

Contribution requirements are in [CONTRIBUTING.md](CONTRIBUTING.md).
