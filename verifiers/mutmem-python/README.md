# MutMem independent Python verifier

This package verifies these MutMem evidence schemas offline:

- `hom.aimos.mutmem-cognitive-evidence/v1`;
- `hom.aimos.mutmem-recall-evidence/v1`; and
- `hom.aimos.mutmem-recall-corpus/v1`.

It is a verification-only implementation written from the public protocol
specification and evidence schemas. It does not import AIMOS production code
and has no database, server, network, Keychain, signing, policy, model, save,
recall, mutation, classification, or deletion authority.

Run:

```text
python3 verify.py verify-bundle /path/to/bundle.json
python3 verify.py verify-recall /path/to/recall-bundle.json
python3 verify.py verify-corpus /path/to/intended-n-corpus.json
python3 verify.py inspect /path/to/bundle.json
python3 verify.py version
```

Exit codes are `0` valid, `1` invalid, `2` missing evidence, `3` malformed CLI,
and `4` internal failure. The only non-standard dependency is the pinned
`cryptography` package for Ed25519 verification; its CPython transitive
dependencies are also pinned in `requirements.lock` and recorded in
`SBOM.spdx.json`. Private keys are neither accepted nor requested.

Hostile JSON parsing rejects duplicate keys, non-finite numbers, canonical
nesting deeper than 32 levels, and bundles larger than 512 MiB. The finite size
bound admits the current complete cognitive corpus without permitting
unbounded hostile input.

The focused corpora can be verified without database, Keychain, server, or
network access. On macOS, the release check uses a deny-by-default sandbox that
permits only process execution and file reads:

```text
sandbox-exec -p '(version 1) (deny default) (allow process*) (allow file-read*)' \
  python3 verify.py verify-bundle fixtures/S4-CV-001.json
```

Recall verification binds the exact signed request and normalized command to
the ordered disclosed memories, RFC-6962-style Merkle evidence, signed event
receipt, certificate epoch, and explicit public trust anchor. Corpus
verification binds every ordered bundle identity and hash to an intended-N
denominator and rejects omission, reordering, duplicate identity, extra member,
or root divergence. Missing mandatory evidence returns `indeterminate`, never
`valid`.
