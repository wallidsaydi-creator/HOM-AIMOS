# HOM-AIMOS public deployment and first-run ceremony

This is the canonical public-install flow for the AIMOS fork. Oracle is a
different system: ports `9000` and `9001` are reserved and must never be used by
AIMOS. AIMOS defaults to `127.0.0.1:9100`.

There is no `.env` configuration lane. Bootstrap facts come from versioned
source or explicit non-secret CLI arguments; mutable policy is master-signed in
the database; secrets are stored in macOS Keychain and referenced by signed
lifecycle evidence.

The housekeeper is the autonomous system operational identity. Genesis creates
its Ed25519 identity and `T1_SYSTEM_SELF` certificate before Guide ingestion.
Heartbeat, scheduling, dreams, calibration, and maintenance do not depend on a
user agent. Master and user-agent enrollment are optional additions for
human-directed work; they never replace the housekeeper.

## Supported platform and prerequisites

The AIMOS 1.0 clean source-install contract is Intel or Apple silicon macOS 14
or later with:

- macOS Keychain access;
- Apple Command Line Tools, including `git`, `curl`, a compiler, and `make`;
- Node.js 20 or 24 and `npm`;
- PostgreSQL 18, reachable through the current OS account on port `5432`; the
  account must be allowed to create the `aimos` database and restricted
  `agent_runtime` role;
- pgvector installed for that PostgreSQL 18 server; and
- libsodium plus `pkg-config`/pkgconf.

Genesis creates the `vector` and `pg_trgm` extensions but does not substitute
an incompatible PostgreSQL installation. For pgsodium, Genesis verifies or
builds the checksum-locked `3.1.11` source before database creation. The
selected PostgreSQL extension directories must be writable by the invoking
operator, or the locked pgsodium artifact set must already be installed through
an administrator-controlled package lane.

Homebrew is the supported clean-machine provisioner, not AIMOS configuration,
identity, credential, or policy authority. It is optional when the compatible
dependencies above already exist. GPG is not required for installation,
Genesis, runtime operation, or evidence verification.

Do not create the AIMOS database manually. Genesis owns its creation, schema,
housekeeper identity, calibration genesis, dependency receipt, and initial
corpus.

## 1. Verify or provision dependencies

From the repository root, the non-mutating preflight reports the selected
toolchain and exits nonzero when anything is missing:

```sh
./install-macos.sh --check
```

The clean-machine installation path is:

```sh
./install-macos.sh
```

It displays the provisioning and Genesis plan and asks before changing machine
state. It never downloads or executes the Homebrew installer. When Homebrew is
absent and provisioning is required, it prints the official informational
command and stops so the operator can review the Homebrew trust boundary at
<https://brew.sh>.

The equivalent explicit manual path is:

```sh
xcode-select --install              # only when Command Line Tools are absent
# Install Homebrew from https://brew.sh when no compatible toolchain exists.
brew bundle --file Brewfile
brew services start postgresql@18
npm ci
```

`Brewfile` selects the supported major-version contract and Homebrew resolves
current compatible patch releases. Genesis later signs a dependency receipt
that records the exact observed Node.js, PostgreSQL, pgvector, libsodium, and
pgsodium versions and cryptographic artifact facts. The npm dependency graph
and pgsodium source archive are independently lock-bound. Do not add a `.env`
file.

## 2. Run Genesis

```sh
npm run genesis:install -- --aimos-db aimos --aimos-port 9100
```

Before creating the database, Genesis:

1. verifies every byte in `Guide/GENESIS-MANIFEST.json` and its deterministic
   corpus root;
2. rejects `.env*`, dotenv, and environment-owned runtime authority;
3. verifies Node.js 20 or 24, PostgreSQL 18, and pgvector availability; and
4. verifies or installs the checksum-locked pgsodium `3.1.11` artifact set.

It then creates the database and restricted role, applies every migration,
generates `architecture-authority.json`, provisions the housekeeper, appends
the signed dependency/runtime-credential/calibration evidence, and ingests the
eight Guide files through the real signed `/aimos/save` path.

Genesis is successful only if all eight current Guide heads are manifest-bound,
provenance-verifiable, recallable to the housekeeper, and non-quarantined.

## 3. Start AIMOS

```sh
npm start -- --aimos-db aimos --aimos-port 9100
```

Expected topology:

- AIMOS: `127.0.0.1:9100`.
- Oracle, if installed separately: outside this runtime and never an AIMOS target.
- no ART sidecar and no second AIMOS authority server.

The server verifies signed configuration and credentials, checks Guide and
housekeeper readiness, listens on 9100, and only then starts autonomous
background services. A missing user agent does not disable the housekeeper.
The post-listen verifier is `jobs/boot-integrity.js`.

## 4. Optionally enroll a master and user agent

Human-directed signed calls require an enrolled user identity. The autonomous
housekeeper does not.

```sh
node scripts/identity/enroll-master.js
node scripts/identity/enroll-agent.js <agent-id> --validity-days=30
```

Use the same Keychain account name in both prompts. The master private key is
encrypted in Keychain. The agent private key is written to
`~/.aimos/agents/<agent-id>.key` with mode `0600`; its master-signed certificate
is cached beside it.

Agent privileges come from append-only master-signed grants. Setting
`OPERATOR_AGENT_ID` may delegate user-facing executive behavior, but it is not
required for heartbeat, scheduling, dreams, calibration, or maintenance and is
not an autonomous-system bootstrap step.

## 5. Prove signed save and recall

Every external request uses the certificate envelope and a method/path-bound
signature. Caller-supplied company, identity, or clearance cannot override the
verified execution context.

The live ceremony must perform:

1. signed `GET /aimos/status`;
2. signed `POST /aimos/recall` for a Guide key or explicit `memory_id`;
3. signed `POST /aimos/save` for a unique retained memory;
4. signed exact recall of the returned `memory_id`.

A successful save returns `memory_id`, `content_hash`, `chain_hash`, and
`chain_kind`. A successful recall returns provenance-admitted memories and a
signed `recall_receipt` containing the evidence Merkle root and event receipt.
Exact proof should use `memory_id` or exact key; free-text retrieval quality is
measured separately by the benchmark.

## 6. Verify autonomous and cryptographic state

Confirm that:

- the Guide has nine current manifest-bound heads and zero quarantined rows;
- the housekeeper identity epoch and certificate verify;
- heartbeat and scheduler events are housekeeper-signed;
- every returned memory has a valid SAVE or honest retrospective attestation
  plus a current portable BIND;
- every superseding memory has signed D2 lineage;
- all cognitive chains verify and remain within `[0.1, 3.0]`;
- no canonical memory is deleted, deactivated, expired, or suppressed.

## 7. Run release gates

The ordinary source gates can run while AIMOS is live:

```sh
npm run lint
npm test
npm audit --omit=dev --audit-level=high
npm run test:architecture-authority
node scripts/identity/init-architecture-authority.js --dry-run
node scripts/test/gate-reserved-ports.mjs
```

Benchmark contract tests additionally require the checksum-verified public
fixtures:

```sh
bash eval/data/download.sh
node eval/prepare-canonical-corpus.mjs
npm run test:benchmark:contracts
npm run test:release:source
```

For the disposable full Genesis/security ceremony, stop AIMOS 9100 first so the
test can replace and restore the shared housekeeper certificate cache without a
live process observing the temporary identity. Oracle remains untouched.

```sh
npm run test:security:isolated
```

The runner creates a disposable `aimos_test_security_*` database, uses port
`9202`, runs the complete installer and live-fire assertions, verifies that the
canonical database fingerprint did not change, and drops the scratch database.

## 8. Upgrade ceremonies

Fresh installs do not need these commands. Existing retained brains use them
append-only:

```sh
node scripts/ceremony/attest-orphaned-memories.mjs --aimos-db aimos
node scripts/ceremony/attest-orphaned-memories.mjs --aimos-db aimos --live

node scripts/ceremony/upgrade-guide-corpus.mjs --aimos-db aimos
node scripts/ceremony/upgrade-guide-corpus.mjs --aimos-db aimos --live

node scripts/ceremony/attest-cognitive-weight-baselines.mjs --company-id=hom
node scripts/ceremony/attest-cognitive-weight-baselines.mjs --live --company-id=hom
node scripts/ceremony/verify-cognitive-weight-corpus.mjs --company-id=hom

# Retained legacy/system scope, when present:
node scripts/ceremony/attest-cognitive-weight-baselines.mjs --company-id=system
node scripts/ceremony/attest-cognitive-weight-baselines.mjs --live --company-id=system
node scripts/ceremony/verify-cognitive-weight-corpus.mjs --company-id=system
```

The first command pair appends honest retained-memory attestations, portable
bindings, and signed lineage without fabricating original SAVE authorization.
The second appends the current manifest-bound Guide version through Genesis A6;
older Guide versions remain retained.

The cognitive commands append honest housekeeper-signed observations for
non-default weights that predate the certified transition chain. They do not
fabricate `REWEIGHT` history or change memory content. The portable verifier
must report zero rejected memories, SQL parity, and a non-empty corpus proof
root for every retained company scope. A live rerun must attest zero rows and
append no empty batch event.

The only deletion mechanism is the offline whole-brain legal purge ceremony:

```sh
npm run ceremony:purge:dry -- --aimos-db aimos
npm run ceremony:purge -- --aimos-db aimos
```

It requires master step-up and exact typed confirmation. No server route, job,
tool, or runtime role imports the purge owner.

Fresh enrollment stores the Keychain locator in the signed identity database,
so the production interaction is deliberately bounded: one command, one master
passphrase prompt, and one exact destructive confirmation. A multi-target
scratch cleanup uses `--all-scratch` and one SHA-256 manifest-bound aggregate
confirmation; it never prompts once per database. The implementation destroys
its retained PostgreSQL client, waits up to ten seconds for PostgreSQL to prove
zero target sessions, and only then issues a non-forced drop. Any failure before
drop restores `ALLOW_CONNECTIONS` and aborts. Before the drop, the ceremony
master-signs the frozen categorical inventory and planned terminal state, then
durably writes and `fsync`s that intent and its parent directory. The final
signed receipt binds the intent SHA-256 and is persisted with the same
write-once durability. A process or power interruption therefore cannot leave
a destroyed brain without retained, independently verifiable authorization
evidence.

## Publication boundary

Passing the cryptographic and installer gates proves integrity, retention, and
traceability. It does not by itself prove retrieval quality. Publish retrieval
claims only with the isolated benchmark artifacts, declared judge protocol,
per-category metrics, confidence intervals, failure ledger, and SHA-256 files.
The public source package is externally anchored by GitHub's keyless workflow
attestation; it does not require GPG and the mutable checkout cannot create that
attestation for itself. See [RELEASE.md](RELEASE.md).
