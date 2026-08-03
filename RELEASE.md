# Release artifact verification

AIMOS does not require GPG for installation or release verification. Public
source releases use three independent, reproducible records:

1. a SHA-256 checksum file for the source package and CycloneDX SBOM;
2. a GitHub keyless build-provenance attestation for the source package; and
3. the Git commit and tag recorded by the GitHub Actions attestation identity.

The release workflow runs the complete source gates and disposable Genesis
ceremony before it packages or attests an artifact. A tag is a release
coordinate; the attestation is the external provenance proof for the exact
package bytes.

## Verify the downloaded files

Download the `.tgz`, `.cdx.json`, and `SHA256SUMS` files from the same release,
place them in one directory, and run:

```sh
shasum -a 256 -c SHA256SUMS
```

For GitHub provenance verification, install GitHub CLI and identify the public
repository that published the release:

```sh
gh attestation verify aimos-backend-1.0.0.tgz --repo OWNER/REPOSITORY
```

The command verifies the artifact digest, Sigstore certificate, GitHub Actions
workflow identity, and repository association. The GitHub CLI is a verifier,
not an AIMOS runtime dependency. Offline attestation verification is also
possible with a downloaded attestation bundle and trusted root.

## Local reproducibility

From the exact release checkout:

```sh
npm ci
npm run test:release:source
npm pack --dry-run
npm sbom --package-lock-only --omit=dev --sbom-format cyclonedx
```

Local reproduction can confirm package contents and dependency structure. It
cannot recreate GitHub's external workflow identity, and therefore cannot
manufacture the release attestation.
