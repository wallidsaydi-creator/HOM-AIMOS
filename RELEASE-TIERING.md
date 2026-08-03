# Release boundary — public AIMOS backend

Status: release policy approved for the first public backend release.

The public repository is a complete, runnable, inspectable AIMOS backend under
AGPL-3.0-or-later. A separate commercial license may be available from the
copyright holder; that option does not narrow the rights granted by the AGPL
copy. This is not a verifier-only demonstration and no core native service is
replaced by a source-available shell, wrapper, hook, disabled path, placeholder,
or stub. A reader must be able to install the system, follow the Genesis
ceremony, exercise native save and recall, run the published benchmark
harnesses, and inspect every enforcement path behind a published claim.

Publishing signing and verification code does not publish signing authority.
Private keys, enrolled identities, credentials, live memories, and database
state remain outside the repository and are created or enrolled locally.

## Ships under AGPL-3.0-or-later

- The runnable server, routes, middleware, database layer, schema migrations,
  jobs, and all native AIMOS services required by the architecture manifest.
- Native save, recall, ingestion, retrieval, cognitive mutation, learning,
  dream, governance, security, identity, signing, and verification code.
- The housekeeper implementation and first-run Genesis installer. The public
  `Guide/` corpus ships because a fresh installation must not start blank.
- Benchmark protocols, runners, fetchers, target-manifest builders, public
  aggregate exporters, portable verifiers, and sanitized publication evidence.
- Public architecture, security, installation, troubleshooting, dataset-rights,
  and reproduction documentation.
- `LICENSE`, `NOTICE`, the CycloneDX SBOM, release manifest, and source hashes.

## Never ships

- Real private keys, certificates tied to a person or machine, Keychain
  contents, credentials, OAuth material, enrolled live identities, or bearer
  material of any kind.
- Live or benchmark brain contents, PostgreSQL data directories, database dumps,
  retained memories, machine authority files, runtime receipts that expose
  identities, or unpublished provider payloads.
- `architecture-authority.json` from a live machine. The public
  `architecture-authority.template.json` ships instead.
- Internal plans, remediation history, scratchpads, private audit notes,
  personal correspondence, private Oracle material, or machine-specific paths.
- Upstream benchmark text or datasets when redistribution is not explicitly
  permitted. The repository ships fetchers, pinned revisions, hashes, and
  derived aggregate evidence only.
- Unreleased mathematical and defensive research extensions, until each has
  its own measured and independently scoped release.
- Customer-specific deployments, integrations, operating data, and future
  services that are not imported by the released architecture manifest and are
  not required to reproduce a published claim.

## Native removal before release

The following personal/financial signal files were introduced into AIMOS by
builder drift and are not AIMOS product components. They have been removed from
the native architecture together with every caller, manifest edge, test
expectation, and current documentation reference. The public source gate fails
if they return. They are not hidden with a package ignore rule or replaced with
wrappers, hooks, stubs, or placeholders.

- `jobs/signal-generators.js`
- `jobs/hourly-signal-scan.js`
- `jobs/sunday-signal-scan.js`
- `jobs/weekly-reflection.js`
- `services/integrations/x-stream-intelligence.js`

## Upstream-governed evidence

Benchmark questions, conversations, poison passages, and other upstream corpus
bytes follow their original licenses and terms. Public evidence may contain
protocol identifiers, pinned source revisions, cryptographic hashes, aggregate
statistics, sanitized per-case identifiers, and verification receipts, but not
redistributed source text unless the upstream license expressly allows it.

## Repository construction

The public repository is created in an empty directory with a fresh `git init`
and a single initial release commit. It is never made from a filtered clone of
the private vault. Before the first push:

1. the native removal list above is absent from both imports and the source tree;
2. installation, Genesis, source, security, benchmark-evidence, license, SBOM,
   private-path, dataset, and secret-scanning gates pass from the fresh tree;
3. `git log --all --oneline` contains exactly one commit;
4. the release manifest binds every shipped file and the clean commit;
5. the final TeX manuscript binds the release commit and evidence-manifest root.

The release uses SHA-256 manifests, the public verifiers, the SBOM, and GitHub
keyless artifact attestation. It does not require contributors or users to have
GPG installed.

## Commercial licensing and contribution provenance

The AGPL release remains open source. A separately negotiated commercial
license is an alternative grant for code whose copyright is controlled by the
licensor; it is not an exception silently attached to the AGPL copy. The first
public release contains only code for which that grant can be made.

Every external contribution requires a Developer Certificate of Origin sign-off
as described in `DCO.md`. A DCO records provenance but does not assign copyright
or automatically grant commercial relicensing rights. Third-party code is not
incorporated into a commercial edition unless the copyright holder has obtained
a separate written grant covering that use.
