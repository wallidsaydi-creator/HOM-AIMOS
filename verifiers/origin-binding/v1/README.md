# HOM-AIMOS Origin Binding V1 — OB-1 verifier

Status: OB-1 protocol frozen after independent byte/predicate verification and
full source regression. Nothing in this directory grants runtime, database,
signing, SAVE, RECALL, classification, or action authority. Native activation
remains owned by OB-2 and later work items.

## Scope

OB-1 freezes and verifies:

- four exact protocol schemas;
- actual NUL-terminated domain bytes;
- the versioned 30-family classification profile;
- deterministic multi-family ancestry closure and UTF-8 lexical ordering;
- safe-integer canonical JSON framed by an unsigned 32-bit big-endian length;
- origin, confidentiality, integrity, action-class, derivation, corroboration,
  and verdict predicates;
- positive and negative cross-language vectors;
- the complete current source root; and
- an executable census of every direct production `aimos_memories` read.

The object commitment is:

```text
SHA-256(UTF8(schema) || 0x00 || U32BE(length(canonical_body)) || canonical_body)
```

The pure JavaScript protocol owner is:

```text
services/security/protocol/origin-binding-v1.js
```

The independent verifier is `verify.py`. It uses only the Python standard
library and imports no HOM-AIMOS JavaScript, database owner, signer, runtime,
or generated implementation code.

## Run

From the repository root:

```bash
node scripts/verification/generate-origin-binding-ob1-artifacts.mjs
python3 verifiers/origin-binding/v1/verify.py
node --test tests/security/origin-binding-v1.test.mjs
node --test tests/security/origin-binding-ob1-artifacts.test.mjs
```

The generator must be byte-reproducible. `verify.py` independently verifies
the profile, vectors, artifact checksums, protocol manifest, source-file hashes,
source root, and source-census commitment.

## Classification boundary

Family is a policy-selection dimension. It is not origin, confidentiality,
integrity, action authority, scope, or a route. A memory may have multiple
families, and derived values retain the complete closure of all parent
families. The trusted monitor may conservatively add a family; a caller or
model cannot assign authoritative classification.

## Non-claims

- OB-1 does not add a database table or writer.
- OB-1 does not activate the protocol in production.
- OB-1 does not repair the direct-read sites found by the census.
- OB-1 does not inherit NMIFC or TMA-NM theorems automatically.
- OB-1 does not close Phase 1.

Those responsibilities belong to OB-2 through OB-6 in the execution ledger.
