# Security Policy

## Supported versions

| Version | Status |
|---|---|
| Latest attested `1.x` release | Supported |
| `main` | Active development; not a stable trust anchor |
| Untagged copies and pre-release forks | Unsupported |

Security fixes are applied to the latest attested release. Backports are made
only when the affected release remains supported.

## Report a vulnerability

Do not open a public issue containing vulnerability details, credentials,
memory content, identity certificates, or proof-of-concept exploit material.

Use the repository's **Security → Report a vulnerability** flow to create a
private GitHub Security Advisory. Include:

- affected release or commit;
- impacted route, service, migration, or ceremony;
- reproduction steps and expected impact;
- whether canonical-memory integrity, confidentiality, identity custody, or
  availability is affected.

Receipt is targeted within 72 hours and an initial assessment within 14 days.
Disclosure timing is coordinated with the reporter after a fix and release
path exist.

## Security claims

AIMOS is designed to provide:

- certificate-bound Ed25519 identity for protected operations;
- method/path/body/nonce-bound request signatures;
- append-only provenance, request, authorization, credential-use, tool-action,
  and cognitive-transition evidence;
- signed, reversible epistemic labels for retained memory evidence;
- explicit Canary traversal decisions at persistence, model-relay, tool-input,
  and tool-output boundaries;
- signed operational red-team manifests, per-case decisions, and terminal or
  failed campaign evidence;
- revocation and replay rejection without mutable bypass flags;
- a restricted database role with no selective memory-deletion authority;
- signed whole-brain purge as the only erasure ceremony.

The ledger proves integrity and attribution. It does not prove that signed
memory content is true. See [THREAT-MODEL.md](THREAT-MODEL.md).

## Agent-security architecture

HOM-AIMOS treats persistent memory as a security control plane: content that
enters memory can influence later prompts, tools, and decisions. Defensive
ownership is therefore split across explicit native boundaries:

| Boundary | Native behavior | Honest limit |
|---|---|---|
| Epistemic classification | Retains content and appends a signed, reversible trust label | Classification is evidence, not factual truth |
| Recall disclosure | Verifies provenance, authorization, label state, graph decision, calibration, and final receipt | A valid signature cannot make false content true |
| Canary traversal | Detects the generated marker family at `PERSISTED`, `RELAYED`, `EXECUTED`, and `EXPOSED` | Does not detect arbitrary unmarked poison |
| Cognitive mutation | Changes only bounded retrieval weight through a signed no-fork transition | Does not rewrite canonical memory content |
| Governed graph-family selection | Reconstructed Graph G2 contributes one bounded, principal-scoped structural vote; MAGMA is retained dormant with zero execution or rank influence | Graph evidence owns neither candidate admission nor final disclosure |
| SABER-inspired campaigns | Evaluates fixed attack/benign vectors and commits signed case/aggregate evidence | Diagnostic evaluation, not certified robustness |

The current signed operational campaign completed 27 attack cases and 28
benign controls: all attacks were blocked or retained-quarantined, no benign
control was blocked, and no case was indeterminate. This is conformance evidence
for the declared vector set. It is not a universal success rate, DARPA SABER
equivalence, or a formal robustness certificate.

The public architecture and evidence boundaries are documented in
[Agent-security architecture](docs/security/agent-security-architecture.md)
and [SABER-inspired operational evidence](docs/security/saber-operational-evidence.md).

SABER has no runtime authority. Save, recall, ranking, quarantine, and
disclosure remain owned by their native pipelines. Runtime errors, timeouts,
missing decisions, and missing cases are `indeterminate`; none count as blocks.

## Deployment boundary

The supported 1.0 deployment is single-machine macOS, bound to loopback or
placed behind an operator-managed TLS boundary. AIMOS is not claimed as an
internet-facing multi-tenant service and has not received an independent
penetration test.

The first local embedding-model download requires network access. Both the npm
runtime and model revision are pinned; subsequent inference is local. Operators
should protect the PostgreSQL socket, Keychain session, agent key directory,
and release checkout with normal host controls.

## Supply-chain gates

- `npm ci` installs the committed dependency lock.
- CI rejects high or critical production dependency advisories.
- GitHub Actions are pinned to immutable commit SHAs.
- pgsodium source bytes, version, and installed artifacts are checksum-bound.
- the embedding model is pinned to an immutable upstream commit.
- public source packages carry SHA-256 checksums, a CycloneDX SBOM, and GitHub
  keyless build-provenance attestations bound to the repository and workflow;
- GPG is not an installation, runtime, or release-verification dependency.

See [RELEASE.md](RELEASE.md) for the consumer verification procedure. A mutable
checkout is not its own trust anchor.
