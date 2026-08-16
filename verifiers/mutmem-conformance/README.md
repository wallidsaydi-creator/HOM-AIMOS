# MutMem conformance corpus

`v1/` is the complete V2-S5 synthetic, hash-addressed conformance corpus.
It contains 28 required protocol classes and 14 boundary/replay expansions
(`intended_n = observed_n = 42`). No live memory, credential, private key, or
operator identity is included.

Verify the retained corpus and its Node/Python parity report without writing:

```sh
npm run verify:mutmem:v2-s5
```

Trust boundary:

- the fixtures are generated with purpose-bound ephemeral identities;
- the production Node owners and independent Python verifier must agree on
  terminal verdict and protocol reason;
- `manifest.json` binds member order, intended-N, fixture hashes, producer
  verdicts, and the corpus root;
- `verification-report.json` binds the independent results;
- source custody and the signed purge receipt belong to the private production
  run evidence, not to this redistributable fixture directory; and
- verification grants no save, recall, signing, mutation, classification,
  deletion, Canary, SABER, or runtime-policy authority.

The one-shot generator refuses to overwrite an existing manifest unless its
exact predecessor hash is supplied. Updating fixtures therefore requires a new
reviewed corpus transition; expected answers are never silently rewritten.
