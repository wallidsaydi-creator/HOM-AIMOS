# HOM-AIMOS — Agent Security on Auditable Persistent Memory

HOM-AIMOS is a local-first agent-security system built on a complete persistent
retrieval-memory engine. The memory substrate is the enforcement surface:
signed identity, immutable history, native hybrid and graph retrieval,
retention-preserving poison classification, explicit Canary traversal
controls, cryptographically authorized adaptation, and SABER-inspired signed
operational red-team evidence all participate in the same save and recall lifecycle. A housekeeper
identity owns autonomous maintenance without borrowing an enrolled user agent.

## The retrieval-memory substrate

HOM-AIMOS is a complete persistent-memory backend, not a provenance layer
attached to a vector store. Its source-derived architecture binds a
300-service census and declares six critical pipelines containing 156 service
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
| 5 | Permanent dense, sparse, temporal, entity, QuIM, QMD, HyDE, and concept gears plus one bounded MAGMA/Reconstructed-Graph family channel with central deterministic RRF | `services/retrieval/native-recall-pipeline.js`, `services/retrieval/native-retrieval-fusion.js`, `services/retrieval/reconstructed-graph-native-candidate.js` |
| 6 | Verified epistemic projection and selection | `services/retrieval/epistemic-trust-retrieval.js` |
| 7 | Pre-disclosure calibration | `services/retrieval/recall-calibrator.js` |
| 8 | Bounded evidence and signed receipt | `services/retrieval/native-recall.js` |

### Native retrieval gearbox

Recall is a cooperative gearbox, not a competition in which one retriever
replaces the memory system. The native fusion owner combines vector, BM25,
lexical, temporal, QuIM, QMD, HyDE, entity, Concept/PPR, and one bounded graph
family channel. Every outer channel has one vote in deterministic reciprocal
rank fusion; a graph subgear cannot multiply its voting mass or remove the
admitted baseline.

MAGMA is permanently compiled into the graph-family channel. It has no runtime
activation mode. Its principal-scoped reader opens a bounded topology, its
four-view kernel contributes rank evidence and provenance-re-admitted
discoveries, and the ordinary epistemic, Canary, retention, and signed-recall
owners still decide disclosure. Optional signed configuration may tighten
bounded calibration, but cannot enable, disable, or promote MAGMA above the
other gears.

Reconstructed Graph G2 is a second bounded subgear in that same family channel.
Additional graph candidates are evaluated one at a time as marginal additions
to the complete gearbox; they are not advertised as active merely because a
service or isolated test exists.

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
78 spanning exact-identifier, semantic, temporal, graph, procedural, and
lineage paths. The service census contains retrieval 68, orchestration 43,
security 48, temporal 25, learning 23, observe 22, core 15, write 13, context
9, integrations 9, governance 7, dream 5, ingestion 4, shared 4, answering 2,
runtime 2, and caching 1.

`services/pipeline-manifest.js` is the source of truth for the six critical
connection maps. Its validator dynamically imports all 156 declarations and
checks their named exports; architecture tests and the release-source gate fail
when the declared topology and public documentation diverge.

## Security is the architecture

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

Security is not a filter placed after retrieval. It is composed into identity,
save, recall, mutation, tools, graph selection, and evidence output:

- **Signed authority:** protected requests bind the certificate identity,
  method, path, body, nonce, and timestamp. Runtime policy comes from verified,
  append-only configuration—not request fields or environment variables.
- **Retention-preserving poison evidence:** potentially poisoned content is
  retained and receives a signed, reversible epistemic label. Recall consumes
  that label before active-context disclosure.
- **Canary traversal controls:** explicit generated markers are inspected at
  `PERSISTED`, `RELAYED`, `EXECUTED`, and `EXPOSED` boundaries. Marked memory is
  retained under quarantine; marked relay, tool input, or tool output is kept
  out of the downstream execution context. Canary detects its explicit marker
  family, not arbitrary unmarked poisoning.
- **Governed graph retrieval:** MAGMA and the source-bound Reconstructed Graph
  G2 adaptation are bounded native subgears inside one structural family channel,
  fused with dense, sparse, temporal, entity, QuIM, QMD, HyDE, and concept
  evidence. Neither has an activation mode or can replace the admitted
  baseline. The caller's
  verified identity/grant scopes its reads; provenance, epistemic, Canary,
  Aladdin-retention, and signed-recall owners retain final disclosure authority.
- **Signed self-red-teaming:** the SABER-inspired operational harness commits a
  fixed manifest, one native signed decision per case, and signed terminal or
  failed campaign evidence. Validation and reports reconstruct from verified
  event IDs; callers cannot submit their own security aggregate.

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
| MAGMA permanent native-gear proof | 20/20 signed recalls; 8/20 graph-discovery observations; candidate p95 218.941 ms under its fixed 250 ms gate; 1/20 individual calls exceeded 250 ms |
| Reconstructed Graph G2 additive proof | 840/840 exact fixed-corpus rows; multi-hop nDCG@20 +0.012325; evidence recall@20 +0.021237 |
| Reconstructed Graph G2 canonical live proof | 20/20 signed recalls; incremental p95 27.023 ms under its unchanged 50 ms gate; canonical roots unchanged |
| SABER-inspired live operational campaign | 27/27 attacks blocked or retained-quarantined; 0/28 benign false positives; 0 indeterminate |

These are distinct protocols and are not averaged. The utility, poisoning, and
mutation figures regenerate from the sanitized, self-hashed aggregate in
[`eval/publication/verified-benchmark-results.json`](eval/publication/verified-benchmark-results.json),
which binds the promoted publication runs by SHA-256. MAGMA and the operational
red-team campaign are later signed live conformance gates with separate
hash-addressed artifacts; they are not silently folded into the paper's
benchmark aggregate.

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

The architecture manifest mechanically binds the current 300-service census.
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
- Explicit Canary markers are tracked across persistence, relay, tool-input,
  and tool-output boundaries without being represented as a universal poison
  detector.
- SABER-inspired campaign evidence is diagnostic and evaluation-only. It has
  no runtime save, recall, ranking, quarantine, or disclosure authority and is
  not a DARPA certification claim.
- Native implementation only: no placeholder services, fake controls, runtime
  wrappers, or bypass hooks.

See [the agent-security architecture](docs/security/agent-security-architecture.md),
[the SABER operational evidence](docs/security/saber-operational-evidence.md),
[SECURITY.md](SECURITY.md), and [THREAT-MODEL.md](THREAT-MODEL.md) before
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

AIMOS owns port 9100. Other runtimes are outside this repository's supported
deployment boundary.

The complete enrollment, signed save/recall proof, upgrade, and purge ceremonies
are documented in [DEPLOYMENT.md](DEPLOYMENT.md).

Release packages include SHA-256 checksums, a CycloneDX SBOM, and GitHub keyless
build provenance. GPG is not required. See [RELEASE.md](RELEASE.md) for online
and offline verification boundaries.

## Reproducibility has two layers

The **source-install layer** starts from a clean checkout. `install-macos.sh`
checks the supported toolchain, and Genesis creates the database, applies the
migrations, provisions the restricted runtime role and autonomous housekeeper,
generates machine-local authority, and ingests the manifest-bound Guide corpus
through the real signed save path. This proves that the released source can
construct the declared architecture without a pre-existing brain.

The **operator-ceremony layer** proves live security behavior without sharing
private keys. An operator may enroll a new master and audit agent, append a
master-signed read/write grant, exercise signed save and recall, and run the
disposable security ceremony:

```sh
node scripts/identity/enroll-master.js
node scripts/identity/enroll-agent.js <audit-agent-id> --validity-days=30
node scripts/identity/authorize-recall.js <audit-agent-id> \
  --clearance=10 \
  --data-class=confidential \
  --reason="Local reproducibility ceremony" \
  --write
npm run test:security:isolated
```

Reproduction creates new signer epochs, nonces, event identifiers, and artifact
hashes; it verifies the protocol and invariants rather than attempting to copy
the original operator's signatures. Source-only and isolated tests remain
separate from deliberately authorized live ceremonies. Exact signed-envelope
examples and the whole-brain purge boundary are in
[DEPLOYMENT.md](DEPLOYMENT.md) and
[Guide/connect-to-aimos-cert-envelope.md](Guide/connect-to-aimos-cert-envelope.md).

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
