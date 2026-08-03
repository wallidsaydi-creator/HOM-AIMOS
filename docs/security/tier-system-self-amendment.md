# H9 Amendment — T1_SYSTEM_SELF Tier

**Date:** 2026-07-10
**Status:** Active

---

## 1. Tier name

`T1_SYSTEM_SELF`

## 2. Purpose

Bootstrap-time + persistent system-write identity for the **housekeeper** when its cert is self-signed (pre-master-enroll, or any system-operational write lane that must not depend on a user being present).

This closes the architectural gap surfaced in the HOM-AIMOS genesis installer: on a fresh clone, before the reviewer enrolls their master, the housekeeper must ingest the Guide corpus through the real `/aimos/save` pipeline so the system "does not fire blank" — but `auth-tier.js` had a hard gate (`if (!masterPubkey) return t0('no_master_enrolled')`) that made every signed request 401 pre-master. The housekeeper's self-signed cert also fails `verifyCertChain(cert, masterPubkey)` post-master because the cert was not signed by the user master.

`T1_SYSTEM_SELF` is the narrow lane that admits the housekeeper's self-signed cert by verifying it against the **housekeeper's own pubkey** (loaded from `agent_identity`), not the user master.

## 3. Issuance

Self-signed by the housekeeper during `genesis-install.mjs` Phase A5:

- `agent_id: 'housekeeper'`
- `issuer: 'housekeeper'`
- `valid_until: 9999-12-31` (perpetual)
- `is_system_role: true` on the `agent_identity` row

The privkey lives at `~/.aimos/agents/housekeeper.key` (mode 0600). The cert is stored both in `agent_identity.cert` and in `~/.aimos/agents/housekeeper.cert-cache.json`.

## 4. Verification path

`services/security/auth-tier.js → deriveTierSystemSelf`:

1. **Cert-peek** at top of `deriveTier`: parse the envelope body (no verify). If `body.agent_id === 'housekeeper' && body.issuer === 'housekeeper'` → route to `deriveTierSystemSelf`.
2. **Housekeeper pubkey lookup** via `housekeeper-pubkey-cache.js` → `SELECT pubkey FROM agent_identity WHERE agent_id='housekeeper' AND revoked_at IS NULL ORDER BY valid_from DESC LIMIT 1`. Null → `t0('housekeeper_not_provisioned')`.
3. **Cert verify** via `verifyCertChain(cert, housekeeperPubkey, { nowFn })`. Self-signed means issuer pubkey == subject pubkey == stored housekeeper pubkey. Invalid → `t0('system_self_invalid_cert')`.
4. **Body schema**: `certBody.agent_id === 'housekeeper'`, `valid_from` integer. Else → `t0('cert_schema')` / `t0('system_self_invalid_cert')`.
5. **Revocation lookup** via `agentRevocationCache.lookup('housekeeper', validFromIso)`. Not found → `t0('housekeeper_not_enrolled')`. Revoked → `t0('agent_revoked')` (**enforce, not shadow** — the lane is narrow and must fail-closed).
6. **Sig verify** via `verifyPayloadSig(housekeeperPubkey, body, nonce, ts, sig, { skewSeconds, nowFn })`. Invalid → `t0(sigResult.reason)` (structural, matching the T1 body-signature rule).
7. **Nonce replay** via `nonceWindow.seenAndRecord('housekeeper', nonce)`. Replay → `t0('replay_detected')` (**enforce, not shadow**).
8. Return `{ tier: 'T1_SYSTEM_SELF', cert, prevChainHash: null, ... }`.

## 5. Capabilities

| Action | Allowed |
|---|---|
| Write to `aimos_memories` via `/aimos/save` (system-scope genesis rows) | YES |
| `/aimos/heartbeat` | YES |
| `/aimos/log-event` | YES |
| `/aimos/reasoning-state` | YES |
| `/aimos/dream`, `/aimos/dream/state` | YES |
| Signed `/aimos/recall` with a durable request and recall receipt | YES |
| Append raw session turns via `/aimos/session/turn` | YES |
| Finalize housekeeper-owned session composition via `/aimos/session/finalize` | YES |
| Read through any unsigned or non-allow-listed route | NO |
| Elevate to T2 (chain advancement) | NO |
| Elevate to T3 (device_fp bind) | NO |
| Hit any route not in the allow-list | NO (401 `system_self_unauthorized_route`) |

## 6. Route allow-list

Enforced in `services/security/auth-gate.js` after `deriveTier` returns and before non-T0 admission:

```
/aimos/save
/aimos/heartbeat
/aimos/log-event
/aimos/reasoning-state
/aimos/dream
/aimos/dream/state
/aimos/recall
/aimos/session/turn
/aimos/session/finalize
```

Any other path → `401 system_self_unauthorized_route`.

## 7. Hard invariants

1. **No chain advancement.** `T1_SYSTEM_SELF` returns `prevChainHash: null`. It cannot supply a `prev_chain_hash` to become T2. The check in `deriveTier` (`if (env.prevChainHash) ...`) is downstream of the system-self return, so the elevation branch never runs.
2. **No device_fp bind.** Same — the T3 branch never runs for system-self.
3. **Fail-closed revocation + nonce.** Unlike operational signals on T1 (which are flag-gated shadow-first per the security wiring plan), the system-self lane enforces revocation and nonce-replay unconditionally. Rationale: the lane is narrow (9 exact routes), the caller is the system itself (not a user agent whose behavior we want to observe), and a compromised or replayed housekeeper envelope must not write to the ledger.
4. **Native session ownership only.** The two session routes admit only the exact verified `T1_SYSTEM_SELF` principal whose `agent_id` is `housekeeper`. The general agent-envelope helper still rejects that tier for compaction and all other callers. Session writes remain subject to the signed request-receipt ledger, company binding, clearance validation, raw-turn provenance, and immutable finalization proofs.
5. **Self-signed only.** If the cert body has `agent_id='housekeeper'` but `issuer !== 'housekeeper'`, it falls through to the normal T1 path (verified against the user master). This is the post-master-enroll transition state.

## 8. Revocation / transition

When the user enrolls their master, the housekeeper **may** be re-signed under the user master (a deferred ceremony — out of scope for this amendment). After re-sign:

- New `agent_identity` row for `housekeeper` with `issuer = <master fingerprint>`, `valid_from = now`.
- Old self-signed row superseded via `revoked_at` (append-only law preserved).
- `housekeeper-pubkey-cache` returns the new pubkey (same keypair, new cert).
- `detectTierFromCert` in `housekeeper-signer.js` returns `T1` (not `T1_SYSTEM_SELF`) because `issuer !== 'housekeeper'`.
- Genesis rows already written stay attributed to `housekeeper` at `T1_SYSTEM_SELF` (audit evidence — the rows were written pre-master, and the tier records that fact).

## 9. No migration needed

- `identity_tier` is plain TEXT (migration 018). Accepts any string; no CHECK constraint.
- `is_genesis` column exists on `aimos_memory_provenance` with CHECK `is_genesis ⟺ prev_mutation_hash IS NULL` (migration 021). Each Guide file's first row is automatically genesis via this constraint; no `is_genesis_body` body field needed.

## 10. Test coverage

`tests/security/auth-tier-system-self.test.mjs` verifies state transitions,
durable evidence, and non-empty cryptographic outputs:

1. Valid self-signed housekeeper cert + valid sig → `T1_SYSTEM_SELF` (stateful: cache query count > 0; non-empty: tier string).
2. Tampered cert body → `t0('system_self_invalid_cert')` (stateful: verifyCertChain rejected).
3. Replay nonce → second call `t0('replay_detected')` (stateful: nonceWindow has the nonce).
4. Real `/aimos/save` via genesis-mode HTTP → 200; provenance row has 64-byte sig + `identity_tier='T1'` (disk: real DB row; non-empty: sig bytes).
5. Housekeeper-self signed POST `/aimos/recall` → 200 with nonblank, provenance-admitted Genesis Guide memory and a cryptographic recall receipt. Unsigned/GET recall remains rejected.
6. Housekeeper-self signed POST `/aimos/session/turn` and `/aimos/session/finalize` pass the central allow-list and the session-specific principal check; the same tier remains rejected by the general compaction route boundary.

## 11. Audit implication

`T1_SYSTEM_SELF` is the AUTHENTICATION lane, not the stored provenance tier.
`memory-provenance.js` `_validate` accepts only `T1 / T2 / T3`; at the
save→provenance boundary the housekeeper's `T1_SYSTEM_SELF` tier is normalized to
`T1` before the provenance row is written (R11b: `provenanceTierFor` in
`routes/aimos.js` for the HTTP `/aimos/save` path; the same normalization is
required at the `commitProvenance` boundary in `memory-provenance.js` so the
in-process cognitive jobs — heartbeat and nightly-dream — that
write as `housekeeper` at `T1_SYSTEM_SELF` also store `T1`). This is HOM-AIMOS's
own rule, following directly from §8 (a re-signed housekeeper reports `T1`) and
the strict `_validate` contract — it is NOT derived from any other system's ledger.

Every genesis row written by the housekeeper therefore carries:

- `agent_id = 'housekeeper'`
- `identity_tier = 'T1'` (the AUTH lane is `T1_SYSTEM_SELF`; the STORED provenance tier is `T1`)
- `source = 'guide:genesis-install'`
- Non-null `sig` (64-byte Ed25519), `nonce`, `ts_signed`
- Valid `content_hash`, `chain_hash`, `mutation_hash`
- `is_genesis = true` (auto-derived via the CHECK constraint on `prev_mutation_hash IS NULL`)

The HTTP response and the auth lane still report `T1_SYSTEM_SELF` (the fact that
the row was written by the self-signed system root pre-master); only the ledger's
strict `identity_tier` column stores `T1`. The ledger is complete and traceable
from the first row. This is the "everything is ledgered from boot" proof for the
academic paper.

---

The housekeeper private-key path is derived from `os.homedir()` and never from
environment-owned authority. New identity tiers require a normative security
amendment and corresponding tests.
