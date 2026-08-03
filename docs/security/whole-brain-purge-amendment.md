# Amendment 1 — The Whole-Brain Purge (the sole deletion authority)

**Status:** **RATIFIED** by the operator, 2026-07-11.
**Authority:** H9 (*new trust tiers require an explicit amendment*). This document is
that amendment. Absent it, `services/security/whole-brain-purge.js` would be an
unauthorized deletion authority and must have been removed.
**Amends:** the Aladdin Retention Law.

---

## 1. What changed

The Aladdin Law previously admitted **no** deletion authority of any kind. It now reads:

> **MEMORY_PERMANENCE** — Never delete, decay, suppress, deactivate, or expire an
> **individual** memory. The only deletion authority is the offline whole-brain purge
> ceremony.

The word *individual* is the amendment. One — and only one — destructive path now
exists, and it can destroy everything or nothing.

## 2. Rationale

**Right-to-erasure compliance.** A memory system cannot ship into any jurisdiction with
a right of erasure (GDPR Art. 17 and equivalents) while offering *no* erasure path at
all. That is not a philosophical position; it is a legal one.

**But selective erasure is the thing we must never build.** The precedent is the
end-to-end-encrypted messaging apps: they do not offer surgical, server-side removal of
one message from one conversation's history. They offer *destroy the account / destroy
the device*. All or nothing.

The same logic binds here, and it binds *harder*, because our claim is cryptographic:

- A **selective** delete authority is precisely the capability an attacker wants. Excise
  one inconvenient memory, leave a chain that still verifies, and the ledger now attests
  a false history *with full integrity*. That authority would **falsify Paper 1's central
  claim** the day it shipped.
- A **whole-brain** purge cannot be used to lie. It does not edit history; it ends it.
  There is no surviving chain to be quietly wrong.

So the amendment does not weaken the integrity claim. **It is the only shape of erasure
that preserves it.**

## 3. The invariant, restated precisely

> The ledger is **append-only for its entire lifetime**. It admits no edit, no decay, no
> individual deletion. Its only exit is **total destruction of the whole brain**, which is
> itself **master-signed and attested** by a receipt that survives the brain it destroyed.

Erasure is therefore not a hole in the ledger. It is a **terminal, attested event**.

## 4. The controls that make this safe (verified in code, 2026-07-11)

| Control | Mechanism | Evidence |
|---|---|---|
| Not reachable at runtime | Not imported by `server.js`, any route, MCP surface, tool registry, job, scheduler, or housekeeper loop | zero live callers, grep-verified |
| Ordinary roles cannot delete | Runtime roles hold no `DELETE`/`TRUNCATE`/`DROP` (migration 041) | `REVOKE DELETE` |
| Master identity required | Master privkey decrypted from the keychain with the passphrase; public key **and** fingerprint must match the enrolled `aimos_master_identity` row | `scripts/ceremony/purge-brain.mjs` |
| Canonical brain double-locked | The library **refuses** the canonical `aimos` database unless `allowCanonical: true`, which only the offline CLI sets. Any other target must match `aimos_(test\|benchmark\|purge)_*` | `whole-brain-purge.js:160-167` |
| Dry-run by default | `--live` is required; without it the ceremony only inventories | `scripts/ceremony/purge-brain.mjs` |
| Typed confirmation | A single target requires exactly `PURGE AIMOS hom <database>`. A multi-target scratch ceremony inventories every target first, commits the ordered target list to SHA-256, and requires one exact aggregate confirmation containing the target count and manifest digest. | `scripts/ceremony/purge-brain.mjs` |
| Multi-target scratch cleanup | `--all-scratch` discovers only names in the bounded `aimos_(test\|benchmark\|purge)_*` namespace. It reuses one verified master session and one manifest-bound operator confirmation while preserving native per-database validation and one signed receipt per destroyed scratch brain. Explicit repeated `--aimos-db` targets remain supported. Canonical `aimos` is forbidden in a multi-target ceremony. | `scripts/ceremony/purge-brain.mjs` |
| Writers frozen first | `ALLOW_CONNECTIONS false` + `pg_terminate_backend`; the retained inventory connection is destroyed, the owner proves zero remaining sessions, and only then issues non-forced `DROP DATABASE` | `services/security/whole-brain-purge.js` |
| Destruction has durable write-ahead evidence | Before `DROP DATABASE`, the master signs the frozen categorical inventory, target, release, and planned terminal state. The CLI writes this intent with exclusive creation, file `fsync`, and parent-directory `fsync`; failure to prove durable persistence aborts before destruction. | `services/security/whole-brain-purge.js`, `scripts/ceremony/purge-brain.mjs` |
| Blast radius bounded | Filesystem purge refuses symlinks, path escapes, and any unexpected entry — it aborts rather than over-delete | `:113-124, :219-221` |
| Completeness proven | After recreate + migrate, `verifyEmptyBrain()` asserts **12 sensitive tables** are empty and the migration count matches — otherwise the ceremony fails | `:312-327` |
| The destruction is attested | Ed25519-signed receipt `aimos-whole-brain-purge-receipt/v1`: ceremony id, master fingerprint + epoch, pre-purge row counts by class, credentials deleted, files deleted, migration count | `:273-298` |
| The receipt outlives the brain | The final signed receipt binds the write-ahead intent SHA-256. Both artifacts are written once, mode `0600`, and durably `fsync`ed below `artifacts/purge-receipts/`, at `--receipt-file` plus its `.intent.json` companion, or as one pair per target below `--receipt-dir`; existing artifacts are never overwritten. | `scripts/ceremony/purge-brain.mjs` |
| Fails closed | Any error before the drop restores `ALLOW_CONNECTIONS` | `:299-303` |

## 5. What the purge destroys

Database (dropped and recreated empty), keychain credential items, and the owned
filesystem scope: agent identity keys (`~/.aimos/agents`), meta-improvement state, DB
backups, command-center session/config, model preferences, golem findings.

**It is a brain death, not a memory edit.** The system afterward is a virgin install.

## 6. Obligations this amendment creates

1. **Disclose it publicly.** `THREAT-MODEL.md` and `SECURITY.md` must state that exactly
   one deletion authority exists, what it is, and why it is whole-brain-only. A repo that
   claims "no deletion" while shipping a `DROP DATABASE` is dishonest — and the honesty is
   the product.
2. **Paper 1 must state it too**, in the same breath as the integrity claim. Framed
   correctly it *strengthens* the paper: selective erasure would break the claim; terminal
   attested erasure does not.
3. **`artifacts/purge-receipts/` must never be committed** (it carries master fingerprints).
4. **No second deletion authority may be added under this amendment.** It authorizes one
   ceremony, of one shape. Anything selective requires a new amendment and would be
   rejected on the reasoning in §2.

---

**Status:** incorporated into the public security doctrine on 2026-07-11.
