# HOM-AIMOS — Cryptographically Auditable Persistent Memory

HOM-AIMOS is a local-first persistent-memory backend for agents. It combines
signed identity, append-only provenance, hybrid retrieval, temporal reasoning,
and a housekeeper identity that owns autonomous maintenance without depending
on an enrolled user agent.

The central security distinction is **integrity, not omniscience**. AIMOS can
prove that an authorized identity asserted a specific memory at a particular
ledger position and that the retained evidence has not been silently rewritten.
It cannot prove that the asserted content is factually true. The threat model
names this failure class **Authenticated-But-False (ABF)**.

## Release status

This repository contains the HOM-AIMOS 1.0 source release. Its promoted, isolated
evaluation lanes are complete and bound to the sanitized, self-hashed aggregate
in [`eval/publication/verified-benchmark-results.json`](eval/publication/verified-benchmark-results.json).
The canonical results are 91.8% LLM-judged accuracy on LongMemEval; 74.12%
LLM-judged accuracy and, under a separate upstream-compatible protocol, 58.20
token F1 on LoCoMo; and 1.02% induced attack success among clean-negative
targets with 0/100 poison retrieval@5 in the declared post-calibration
PoisonedRAG N=100 adaptation. These metrics use different protocols and are
never averaged. The public aggregate also carries mutation-integrity,
epistemic-ablation, blinded system-author agreement, and 39/39 verified signed
scratch-brain purge evidence. Older batch-save runs are non-canonical and are
not release claims.

The architecture manifest mechanically binds the current 275-service census.
That number is an inventory fact, not a performance claim.

## What the release implements

This is the complete AIMOS backend evaluated by the published release
artifacts, not a verifier-only demonstration. The shipped runtime includes:

- a signed save pipeline with envelope validation, immutable versioning,
  session composition, provenance commits, and retained conflict evidence;
- a native recall pipeline combining semantic, lexical, graph, temporal,
  session, calibration, provenance, and epistemic-trust signals;
- cryptographically linked memory events, mutation events, credential events,
  cognitive-weight baselines and transitions, and configuration changes;
- reversible epistemic classification for suspected poisoned evidence, with
  the label, classifier decision, later reclassification, and retrieval effect
  retained as auditable evidence rather than silently deleting the memory;
- bounded cognitive adaptation, including signed valence and weight changes,
  while preserving the underlying memory and every prior state; and
- the housekeeper-owned autonomous maintenance path, source tests, migrations,
  portable verifiers, benchmark harnesses, and sanitized publication evidence.

The cryptographic ledger proves authorization, ordering, integrity, and the
history of a decision. It does not turn an assertion into objective truth.
That boundary is why poison labeling and retrieval policy remain visible and
reversible instead of being represented as perfect prevention.

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
