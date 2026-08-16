# MutMem standalone Node recall verifier

`recall-verifier.mjs` independently verifies
`hom.aimos.mutmem-recall-evidence/v1` bundles and
`hom.aimos.mutmem-recall-corpus/v1` intended-N manifests. It imports only the
Node.js cryptography built-in and has no AIMOS runtime or operational authority.

The Node implementation is used for clean-room parity with the production pure
protocol owner and the independent Python implementation. The Python package
provides the bounded command-line interface for external reviewers.

The verifier accepts only explicit public trust anchors carried by the evidence
bundle. It cannot sign, enroll, write, recall, rank, classify, mutate, delete,
connect to AIMOS, or read a credential store.
