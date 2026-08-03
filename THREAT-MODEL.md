# AIMOS Threat Model

## The core distinction: Integrity ≠ Veracity

This is the single most important thing to understand about AIMOS.

**Integrity** (what the ledger proves): a memory with a given content hash was
written at a specific chain position by an agent whose certificate was valid at
that time. The chain is unbroken. The mutation hash matches the content. The
signature was produced by the key bound to the certificate.

**Veracity** (what the ledger does NOT prove): the *content* of the memory is
factually true. A signed memory that says "the sky is green" has full ledger
integrity. The ledger proves *who said it and when*, not *that it is correct*.

**Authenticated-But-False (ABF):** the primary threat to a provenance system is
not forgery — it is a legitimate, correctly-signed agent asserting false
content. The ledger makes this *detectable and attributable* but cannot prevent
it. This is by design: the ledger is an evidence layer, not a truth oracle.

## What the ledger guarantees

| Property | Guaranteed? | Mechanism |
|----------|-------------|-----------|
| Author attribution | ✅ | Ed25519 cert envelope; identity from verified cert, never from headers |
| Write immutability | ✅ | Aladdin law: no DELETE, no TTL, no soft-delete, no decay of an *individual* memory. Supersession only. The sole deletion authority is the offline, master-signed **whole-brain purge** (§7) — all-or-nothing, never selective |
| Chain integrity | ✅ | Each mutation hash references its predecessor; breakage is detectable |
| Replay resistance | ✅ | Nonce store rejects reused nonces; timestamp window enforced |
| Revocation | ✅ | Revoked agents are rejected (fail-closed kill-switch) |
| **Certified order** (chain position) | ✅ | The hash chain induces an unforgeable **total order**: a row cannot be inserted mid-chain without recomputing every successor hash. This is the strong temporal claim — an *ordinal*, not a clock |
| Content truth | ❌ | The ledger cannot certify factual correctness |
| Wall-clock accuracy | ⚠️ Partial | A timestamp is only an *attested assertion* by whoever signed it — signed, but not externally notarized. Rely on the chain ordinal above, not the clock |

## Attack surfaces and mitigations

### 1. Identity spoofing
**Threat:** an attacker forges an agent identity to write memories under someone
else's name.
**Mitigation:** Ed25519 certificate chain. The acting identity is derived from
the verified certificate in `auth-tier.js`, not from any request header, body
field, or environment variable. Form-3 signatures include method + path in the
preimage, preventing cross-endpoint replay.

### 2. Provenance forgery
**Threat:** an attacker modifies a memory after the fact and re-hashes the chain.
**Mitigation:** content hashes are computed over the memory value; mutation
hashes chain to predecessors. A modified memory produces a content-hash mismatch
detectable on recall.

### 3. Unauthorized recall (data leak)
**Threat:** a low-clearance agent recalls memories above its clearance level.
**Mitigation:** REST and MCP recall converge on the native recall pipeline.
Clearance, tenant, ownership, data-class, quarantine, authorization, and
provenance admission are enforced before evidence leaves the backend. Alternate
retrieval modes may rank candidates but cannot bypass native admission.

### 4. Prompt-injection in stored content
**Threat:** a memory contains text designed to manipulate the agent that recalls
it ("ignore previous instructions").
**Mitigation:** the context-aware security decision owner distinguishes
descriptive security material from executable attack intent. Explicit attacks
are blocked at prompt and tool boundaries; unsafe saves remain retained in
active quarantine with signed disposition evidence.

### 5. Canonical brain contamination
**Threat:** benchmark data or test artifacts pollute the production memory corpus.
**Mitigation:** the isolated benchmark runner operates on a disposable scratch
database on port 9200. Canonical AIMOS (port 9100) is observed before/after but
never written to by the benchmark. The runner aborts if the canonical footprint
changes.

### 6. Aladdin violation (unauthorized deletion)
**Threat:** code or migration that hard-deletes or TTL-expires a memory.
**Mitigation:** `REVOKE DELETE` on the restricted runtime role (migration 041) is
the enforcement boundary. The string-scan in `db/connection.js` is *developer
convenience only* — it is bypassable and is explicitly not a security control.
Fresh Genesis verifies the restricted runtime role and migration-owned ACLs
before readiness. Release ceremonies exercise the real restricted write path;
operators should still include `\dp` evidence in deployment audits.

### 7. Erasure — the one deletion authority (and why it is shaped this way)

A right-to-erasure regime (GDPR Art. 17 and equivalents) means a memory system cannot
offer *no* erasure path. AIMOS offers exactly one, and it is deliberately the bluntest
one possible.

**There is no selective deletion. There never will be.** A surgical "remove this one
memory" authority is precisely the capability an attacker wants: excise an inconvenient
memory, leave a chain that still verifies, and the ledger now attests a false history
*with full integrity*. That authority would falsify this project's central claim on the
day it shipped.

**What exists instead is a whole-brain purge** — the same posture end-to-end-encrypted
messaging apps take: not "delete this message from the history," but "destroy the
account." It is:

- **offline** — not reachable from any route, tool, job, or scheduler (zero live callers);
- **master-signed** — requires the enrolled master key, decrypted from the OS keychain
  with a passphrase, with fingerprint and public key both matching;
- **all-or-nothing** — it drops the database, purges credentials and identity keys, and
  then *proves* the brain is empty before it will report success;
- **attested** — it emits an Ed25519-signed receipt (ceremony id, actor fingerprint,
  pre-purge row counts, migration count) that is written to disk and **survives the brain
  it destroyed**.

So the honest statement of the invariant is:

> The ledger is **append-only for its entire lifetime**. It admits no edit, no decay, no
> individual deletion. Its only exit is **total destruction**, which is itself signed and
> attested.

Erasure is not a hole in the ledger. It is a terminal, attested event. See
`docs/security/whole-brain-purge-amendment.md`.

## Out of scope

- Network-level attacks (DDoS, MITM) — assume loopback or TLS-terminated transport.
- Side-channel attacks on the embedding model.
- Key compromise recovery — if an agent's Ed25519 private key is stolen, the
  revocation mechanism marks the agent as revoked, but memories signed before
  revocation remain valid (by design — they were legitimately signed at the time).
