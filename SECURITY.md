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
- revocation and replay rejection without mutable bypass flags;
- a restricted database role with no selective memory-deletion authority;
- signed whole-brain purge as the only erasure ceremony.

The ledger proves integrity and attribution. It does not prove that signed
memory content is true. See [THREAT-MODEL.md](THREAT-MODEL.md).

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
