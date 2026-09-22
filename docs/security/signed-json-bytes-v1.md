# Exact signed JSON bytes — encoding profile v1

Status: AUD-018 implemented and live-qualified on 2026-09-12; independent R5
review remains pending. The native event owner emits payload v2 by default and
has no legacy-emission fallback. Canonical SQL and native/independent readers
support the exact bytes; historical signatures retain their original verifier.

## Boundary

This profile binds a versioned object type and exact bytes. It is not a new
permission source, signer, event ledger, SAVE route or JSON canonicalizer.
Historical signature forms and serializers retain their existing meanings.

Let `S` be an ASCII versioned type identifier matching
`[a-z][a-z0-9._/-]*/v[1-9][0-9]*`, at most 200 bytes. Let `W` be nonempty
UTF-8 JSON wire bytes, at most 67,108,864 bytes (the existing independent
verification input bound). Root depth is zero and maximum value depth is 32.
Decoded member names must be unique within each object. Unicode normalization
is not performed. Invalid UTF-8, BOM, NUL and unpaired surrogates are rejected.

Numbers are JSON lexical tokens at this encoding layer. They are never rounded,
reformatted or promoted into authorization facts by the commitment operation.
NaN/Infinity literals are not JSON and fail. A syntactically valid large numeric
token can be committed without being an admissible application numeric value.
Each versioned typed object still enforces its own integer, range, finite-value,
identity, epoch, scope, reference and policy predicates before any effect.
The profile test corpus labels large numeric cases as opaque wire tokens for
this reason; it does not certify those tokens as valid occurrence integers.

Native producers may generate `W` using their existing deterministic serializer.
Verifiers must use the supplied `W`; they must not regenerate it from JSONB or
a parsed JavaScript/Python object. Equal JSON values can have different wire
commitments: whitespace, member order and `1` versus `1.0` remain significant.

## Commitment and mathematical scope

`D = UTF8("hom.aimos.signed-json-bytes/v1") || 00`

`preimage(S,W) = D || u32be(|S|) || S || u32be(|W|) || W`

`commitment(S,W) = SHA256(preimage(S,W))`

Lengths count bytes, not characters. Both lengths fit u32 under the bounds.
Given the fixed domain, the first length uniquely determines the type boundary;
the second uniquely determines the wire boundary. Therefore equal preimages
imply equal `(S,W)`. Different pairs having equal digests would be a SHA-256
collision, not a consequence of ambiguous concatenation. This does not prove
content truth, signature validity or authority: those are separate predicates.

Hashing and byte scans are linear in input bytes. Duplicate detection uses
bounded per-object sets (expected linear work); parsed storage is O(input size)
and nesting is bounded. The 64-MiB ceiling is not a throughput benchmark claim.

Sources: local Cryptography Engineering §6.7 (Horton/unique interpretation),
[RFC8259](https://www.rfc-editor.org/rfc/rfc8259), and
[RFC8785](https://www.rfc-editor.org/rfc/rfc8785) for the distinction between
canonicalization and signing exact encoded data. This native profile is not
a claim to implement full JCS, JOSE or any third-party protocol stack.

## Event payload v2, within the existing linkage ledger

The type is `hom.aimos.event/v2`. Its signed body contains
`payload_schema: "hom.aimos.event/v2"` and the exact `nonce`, in addition to
the existing event fields. The nonce is inside these committed bytes; time,
signer epoch, company, event identity, sequence and predecessor are also bound.

- `content_hash` is the new type-bound exact-byte commitment.
- Ed25519 signs the 32 commitment bytes, not hexadecimal text.
- The existing event-link v1 mutation formula and sequence ownership remain.
- `ledger_version=1` continues to describe that linkage structure; the explicit
  signed `payload_schema` selects payload v2. Unknown payload schemas are denied.
- `signed_body_bytes` stores exactly the signed serialization alongside the
  existing JSONB projection. Only the event's already-sanitized body is included.
- Native and SQL verifiers compare the parsed body with its stored projection,
  bind the event's denormalized fields, and verify commitment/link/signature.
- The new-payload insert trigger rejects invalid evidence before commit.
- Runtime ACL extension is only SELECT/INSERT for the new column. No table-wide
  write permission or new cryptographic-helper EXECUTE grant is introduced.

Legacy event payloads have no `payload_schema` or byte column. Their old
preimages remain unchanged. New bytes cannot be silently accepted as legacy.

## Request privacy and remaining integration

For payload v2, the portable event can carry `signed_body_bytes_b64u` without
duplicating `signed_body` or its metadata in the outer JSON object. Those bytes
contain the explicit payload version and the complete metadata; nothing is
removed from the retained event. Readers derive the body from the byte field,
validate its type and numeric authority fields, and verify the original-byte
commitment. A supplied redundant body or metadata projection must agree and
cannot override the decoded signed body. Non-finite application numbers fail.
Legacy events still require their original body/projection fields.

This avoids running arbitrary event metadata through the portable envelope's
different canonical-number domain. Integer epoch and sequence fields retain
their safe-integer/range checks; accepting finite metadata is not an authority
grant. New-format signature verification does not serialize floating-point
values to reconstruct signed bytes. Historical signature encodings are unchanged.

Portable event consumers carry `signed_body_bytes_b64u` without regenerating
it from the parsed body. The encoding must round-trip exactly as unpadded
base64url. The native cognitive exporter, recall/mutation witness exporters,
and independent event consumers dispatch the signed `payload_schema`; legacy
objects omit the byte field. Missing bytes or unknown versions fail, and
decoded body/nonce equality is checked in addition to hashing the original
wire. Full new-format recall/mutation bundle qualification and wider typed-value
parity remain open; the qualified mixed-format cognitive event stream has no
memory records and must not be reported as a cognitive mutation proof.

The request receipt table remains hash-only: no plaintext request-body column
is introduced by this work. Request byte handoff, explicit request form and
portable export/readback propagation remain integration requirements. The
event implementation and its SQL qualification do not close those requirements.
No private key is given to a pure exporter or verifier.

## Current RECALL disclosure envelope (AUD-018, 12 September 2026)

The current system emits `hom-aimos/recall-merkle/v4-origin-family-disclosure`.
Its portable envelope is explicitly `hom.aimos.mutmem-portable-evidence/v3`.
Historical envelope v2 still describes native receipt v3; neither is relabeled.
This versioning is current-system verification work, not a revision to a
published paper or its artifacts.

Object membership remains exactly `13 + 5 * result_count`, at most 200 results.
The `native_recall_receipt` and `receipt_evidence` object schemas advance to
`hom.aimos.mutmem-native-recall-receipt/v3` and
`hom.aimos.mutmem-recall-evidence-entry/v3`; other schemas and object framing
remain unchanged. The bundle hash uses the existing length-framed formula with
the distinct UTF-8 domain `hom.aimos.mutmem-portable-evidence/v3` followed by
one `00` byte. Exact format/schema/version membership is required.

The native receipt object carries the public origin-family profile body. The
verifier checks `SHA256(UTF8(profile.schema) || 00 || u32be(byte_length) ||
canonical_bytes)` against the version-1 protocol commitment
`49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24`.
An artifact cannot choose its own accepted taxonomy or trust anchor.

For each result, the exact native label keys, schema, memory UUID and content
hash must agree with that result. Family IDs must be known, sorted, unique and
parent-closed; their ordered `{ordinal, family_id}` Merkle root must match.
The four origin reference arrays must be sorted unique lowercase hashes/UUIDs.
They must each be nonempty for a bound label and empty for a legacy-unbound
label. Their cardinalities are not required to equal each other: native
construction independently deduplicates them. Confidentiality cannot be below
the selected memory's data class. Integrity/action values must be members of
the pinned profile. Both status flags are Boolean and agree. Legacy-unbound
means exactly `unknown_protected`, restricted, untrusted, action class `none`.

Each label commitment hashes its body without `disclosure_label_sha256`, using
the UTF-8 domain `hom.aimos.native-recall-origin-disclosure/v1`, one `00` byte,
u32be body byte length and canonical body bytes. The aggregate uses ordered
Merkle leaves `{ordinal, memory_id, live_content_hash, disclosure_label_sha256}`.
The labels/root must equal the receipt evidence, aggregate fields and signed
event metadata; the native receipt Merkle schema also equals the signed one.
The normal receipt commitment, identity, grant and signature checks still apply.

| New failure code | Exact predicate class |
| --- | --- |
| `ORIGIN_FAMILY_PROFILE_INVALID` | Missing/malformed profile, wrong schema or mismatched fixed profile commitment. |
| `ORIGIN_DISCLOSURE_LABEL_INVALID` | Any per-result label shape, subject/content, taxonomy closure, reference ordering, enum/status, legacy rule or label commitment check above fails. |
| `ORIGIN_DISCLOSURE_ROOT_INVALID` | Aggregate labels missing/not a list, ordered list mismatch or recomputed root mismatch. |
| `ORIGIN_DISCLOSURE_EVENT_BINDING_INVALID` | Signed event metadata omits or disagrees with the verified labels/root. |

These checks are linear in bounded input bytes/reference count; family-parent
membership uses sets against the fixed 30-family profile. Receipt authenticity
does not prove the complete origin ancestry, independent corroboration, content
truth, or permission to execute an action. The independent result states these
limits explicitly. No production SAVE/RECALL route is added or changed.

The initial qualification covered genuine bound/unbound labels with v3
occurrences. Its two additional portability limits are addressed below;
that initial checkpoint is retained as historical evidence, not overwritten.

## Retained provenance bytes and legacy occurrences (AUD-018)

Current export uses `hom.aimos.mutmem-provenance-chain/v3` and
`hom.aimos.mutmem-occurrence-evidence/v3`. Envelope v3 also continues accepting
the preceding v2 shapes for these two objects. The shapes must be paired per
result; changing an object schema does not enable signature-version fallback.
The native receipt, evidence, family profile and all existing hash domains
remain unchanged. Historical envelope v2 remains unchanged.

Each new retained provenance row carries `body_json_encoding` equal to
`hom-aimos/canonical-json/v1` and `body_json_bytes_b64u`, without a redundant
`body_json` projection. These are the existing body's native signing bytes,
reconstructed from retained data, not newly signed history. Their SHA-256 must
match the historical content commitment before they can verify. The original
signature is checked over these bytes, not over a Python/Node reserialization.
Numbers in the body therefore do not pass through the portable envelope's
safe-integer restriction. Invalid UTF-8, duplicate decoded JSON members,
non-finite interpreted values, invalid encoding and excessive depth still fail.
This cannot recover precision lost before the original signature or recreate
an absent signed body. No plaintext request column is added to the database.

The row also carries the already-retained request-signature form, method,
path, claims, origin time, genesis flag, signer epoch certificate and revocation
evidence. Nullable context fields are explicit. Provenance form 1 and request
form 3/4 are distinct concepts. Version dispatch preserves these native bytes:

- Provenance form 1 / request form 1: body bytes, nonce, signed time, separated
  by LF bytes.
- Provenance form 1 / request form 3: body bytes, uppercase method, historical
  pathname, nonce and signed time, separated by LF bytes.
- Provenance form 1 / request form 4: the form-3 layout with canonical signed
  chain/device claims between pathname and nonce.
- Provenance form 2: body bytes, nonce, signed time and originated-at Unix
  seconds, separated by LF bytes. Its mutation hash additionally includes the
  original origin-time suffix. It is not request signature form 2.

The old content-first mutation-hash formula is reproduced exactly. The legacy
occurrence reference uses the existing domain and u16-tag/u32-length fields,
binding company, memory UUID, provenance UUID, mutation hash, signer, epoch,
certificate fingerprint, event type and provenance version. Unknown forms
fail; no verifier tries other forms until a signature passes. Historical
pathname-only signing is preserved; full request-target binding remains AUD-008.

For a new-shape legacy occurrence, both independent verifiers check all
provided chain nodes' original signatures and commitments, certificate issuer,
exact signer epoch, validity at signing, supplied signed revocation evidence
and any retained revocation timestamp. A post-signature expiry is not a reason
to invalidate historical evidence. A hash map, successor map and visited set
require one connected, non-forking chain containing the selected occurrence.
The signed Housekeeper BIND must bind the current memory UUID/content hash to
the exact SAVE content hash, mutation hash, signature hash and signer epoch.
The current row's content hash is independently recomputed. Original signing
bodies are not changed to fit normalized SAVE classifications.

| Legacy verification failure | Predicate class |
| --- | --- |
| `PROVENANCE_BYTES_INVALID` | Missing/mixed body representation, invalid byte encoding/JSON, non-finite body value, excessive depth/size. |
| `PROVENANCE_CONTEXT_INVALID` | Missing/invalid explicit context, unsupported forms, unsafe/fractional authority integers, malformed origin time or claims. |
| `PROVENANCE_COMMITMENT_INVALID` | Original body content hash or version-selected mutation hash does not recompute. |
| `PROVENANCE_CERTIFICATE_INVALID` | Signer, exact epoch, fingerprint, issuer, certificate signature or validity-at-signing check fails. |
| `PROVENANCE_REVOCATION_INVALID` | Required revocation data missing/malformed, supplied proof fails, or revocation is effective at signing. |
| `PROVENANCE_SIGNATURE_INVALID` | Original signature does not verify over its selected native preimage. |
| `PROVENANCE_CHAIN_INVALID` | Wrong subject, duplicate node, multiple genesis/successors, disconnected predecessor or cycle. |
| `PROVENANCE_SAVE_BINDING_INVALID` | Selected occurrence, signed BIND, SAVE identity/commitments or current-memory content binding disagrees. |

The exporter fetches relevant revocations in one joined read and attaches them
with an epoch map, not an identity-by-history nested scan. Chain traversal and
byte hashing are linear in the supplied rows and bytes; certificate verification
is cached by fingerprint within that traversal. Existing result-count,
per-object byte and depth limits remain. No million-memory load test or
unbounded export capability is claimed by these repairs.

The qualification uses both previously failing memories and a genuine native
form-4 SAVE/RECALL of a factual R5 session note. Form-1 request variants 1, 3
and 4 and current v3 occurrences verify; altered copies are rejected without
creating new signatures. The current canonical database has no provenance-form-2
rows, so that historical branch is not described as live-qualified. Sparse
historical records without original signed bodies cannot become verified
originals; the existing retained-attestation distinction is not erased.
Verification of supplied revocation evidence is not a proof of an exhaustive
external revocation history. Origin ancestry, independent corroboration and
permission to execute actions remain separate claims. Event-payload-v2
deployment and full new-payload bundle qualification remain open in AUD-018.
