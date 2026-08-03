# Contributing to AIMOS

Contributions are welcome when they preserve the system's security and
retention contracts.

## Development setup

The supported release environment is macOS 14 or later with Node.js 20 or 24,
PostgreSQL 18, pgvector, libsodium, and Apple Command Line Tools. Verify the
machine without changing it, then install the locked JavaScript dependencies:

```sh
./install-macos.sh --check
npm ci
npm test
```

`npm test` is database-free. Database-backed security tests are intentionally
owned by the disposable Genesis ceremony and must never be redirected to a
canonical brain.

Before submitting a change, run:

```sh
bash eval/data/download.sh
node eval/prepare-canonical-corpus.mjs
npm run test:release:source
```

Changes to identity, signing, migrations, persistence, recall admission, or
cognitive mutation must also pass `npm run test:security:isolated` against its
disposable database.

## Architectural rules

- Inspect every caller and callee before changing an interconnected service.
- Make the smallest native change that solves the verified problem.
- Do not add wrappers, bypass hooks, placeholder services, stubs, or fake-green
  tests.
- Do not introduce `.env`, environment-owned credentials, or mutable unsigned
  policy authority.
- Do not selectively delete, decay, expire, suppress, or deactivate canonical
  memory. The offline whole-brain ceremony is the only erasure authority.
- Preserve signed provenance and transaction atomicity for every state change.
- Review the cited academic paper and the service header before changing a
  mathematical service. Tests must exercise the stated formula and boundaries.

## Pull requests

Keep pull requests focused. Explain the failure or requirement, the native
integration points inspected, the security/retention impact, and the evidence
that verifies the result. Never include secrets, private memories, benchmark
datasets, local database dumps, identity keys, or machine-specific authority.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.

## Developer Certificate of Origin

Every commit in a contribution must include a `Signed-off-by` trailer certifying
the [Developer Certificate of Origin](DCO.md):

```sh
git commit -s
```

The sign-off must use a name and email address you are authorized to place in
the permanent public history. The DCO establishes contribution provenance; it
does not transfer copyright or grant the project commercial relicensing rights.
If a contribution is intended for a separately licensed commercial edition,
the copyright holder may require an additional written agreement before merge.
