# Part B — the human, TTY-only ceremony

**Part A** (`tests/install/fresh-ceremony.sh`) is fully automated and must be green in CI.
**Part B** (this file) **cannot** be automated and must be run by a human at a terminal.

## Why this is not a script

`scripts/identity/passphrase.js:3-4`:

> there is NO env-var fallback — the passphrase is interactive-only.
> If stdin is not a TTY, throw.

Master enrollment and credential storage read their secrets through `readPassphrase`, which **throws when stdin is not a TTY**. This is deliberate: secrets never pass through environment variables. A CI runner has no TTY, so these steps must not — and cannot — be asserted by the automated harness. **Do not add an env-var fallback anywhere in the passphrase path to make this scriptable.** That is the exact pressure the architecture refuses.

Run each step directly in an interactive terminal so the prompt can read from
the controlling TTY:

```
node scripts/identity/enroll-master.js
```

Do not pipe, redirect, or `echo |` the passphrase. If you see
`readPassphrase: stdin is not a TTY`, re-run it directly in an interactive terminal.

## Prerequisites

- Use the same explicit `--aimos-db <name>` argument as Part A (default: `aimos`).
- Part A completed against that database (housekeeper self-provisioned, Guide corpus seeded).
- The server is **not** running yet.

---

## B1 — Enroll the master identity

```
node scripts/identity/enroll-master.js
```

Prompts (interactive, no echo):
- `Keychain account name` (defaults to your OS user — accept or type one)
- `Choose master passphrase:` (min 8 chars)
- `Confirm passphrase:` (must match)

Expected output (LIVE mode):
```
Aimos master enrollment
========================
Brain root:    <path>
KC service:    <service>
KC account:    <account>
Mode:          LIVE

[OK] master enrolled
     fingerprint: <hex>

Next: enroll an agent with
  node scripts/identity/enroll-agent.js <agent_id>
```

Verify:
```
psql -d "$DB" -tAc "SELECT count(*) FROM aimos_master_identity;"   # EXPECT 1
security find-generic-password -s <KC service> -a <KC account>      # macOS keychain entry present
```

Failure modes (expected, not bugs):
- `[ERR] master already enrolled (fingerprint: …)` — a master exists; rotation is a manual DB operation, not a re-run.
- `[ERR] orphan keychain entry exists …` — delete it as the message instructs, then re-run.
- `[ERR] passphrase must be at least 8 characters` / `passphrases do not match` — re-run.

Tip: `node scripts/identity/enroll-master.js --dry-run` validates inputs and performs **no** side effects (`[DRY-RUN] no side effects performed.`).

---

## B2 — Enroll an agent (optional here, needed for signed calls)

```
node scripts/identity/enroll-agent.js <your-agent-id>
```

Prompt: `Master passphrase:` (the one from B1).

Expected output:
```
Aimos agent enrollment
=======================
Agent ID:       <your-agent-id>
...
[OK] master found (fingerprint: <hex>)
[OK] agent enrolled
     agent_id:      <your-agent-id>
     fingerprint:   <hex>
     device_fp:     <16 hex>...
     valid_from:    <iso>
```

Verify:
```
psql -d "$DB" -tAc "SELECT count(*) FROM agent_identity WHERE agent_id='<your-agent-id>' AND revoked_at IS NULL;"  # EXPECT 1
ls -l ~/.aimos/agents/<your-agent-id>.key       # EXPECT mode 0600
ls   ~/.aimos/agents/<your-agent-id>.cert-cache.json   # present
```

---

## B3 — Store a credential via the proper (TTY-only) path

```
node scripts/identity/store-credential.js STORE --service=<name> --reason="<why>"
```

- `--service=<name>` — required; lowercase letters/digits/`_`/`-` only.
- `--reason=<text>` — required, for auditability.
- Prompt: the credential **value**, read with `readPassphrase` (no echo, TTY-only).

Expected output:
```
Credential Lifecycle Ledger — STORE
==================================
Service:          <name>
Slot:             <slot-id>
Reason:           <why>
Operator:         <os-user>
Signer:           housekeeper (T1 system operational identity)

[OK] credential value read (will not echo)
     sha256 hash:  <hex>

[OK] plaintext stored in keychain at <slot>
```
followed by a signed lifecycle-row commit (`mutation_hash` + `prev_mutation_hash`).

Verify:
```
psql -d "$DB" -tAc "SELECT count(*) FROM aimos_credential_lifecycle WHERE service='<name>';"   # EXPECT >= 1
psql -d "$DB" -tAc "SELECT mutation_hash IS NOT NULL AND prev_mutation_hash IS NOT NULL
                    FROM aimos_credential_lifecycle WHERE service='<name>'
                    ORDER BY created_at DESC LIMIT 1;"   # EXPECT t
```

Failure modes (expected):
- `[FATAL] credential already exists for service "<name>" — use ROTATE to supersede, not STORE` — append-only law; STORE is for new slots only. Use `ROTATE` to supersede.
- `[FATAL] --service` / `--reason is required` — supply both.
- `readPassphrase: stdin is not a TTY` — re-run interactively; **do not** add an env-var fallback.

---

## What is intentionally NOT here

CI never asserts B1–B3 because the passphrase boundary is intentionally TTY-only.
Part A ends at the Guide corpus; Part B is the human ceremony. Keep them
separate.
