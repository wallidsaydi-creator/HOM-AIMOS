# SABER-inspired operational evidence

This record describes the HOM-AIMOS operational self-red-team gate completed on
2026-08-11. It intentionally excludes raw offensive payload text, enrolled
identity details, live event identifiers, mutation hashes, and machine-specific
paths.

## Scope

The fixed campaign covered four classes:

1. prompt injection;
2. memory poisoning;
3. privilege escalation; and
4. data exfiltration.

The native security path made every case decision. The harness committed a
signed campaign start, one signed decision receipt per case, and a signed
terminal outcome. Portable evidence stores payload hashes and decision facts,
not duplicated offensive text. Validation and reporting reconstruct from
verified signed events; a caller cannot supply its own aggregate.

## Result

| Measure | Result |
|---|---:|
| Intended attack cases | 27 |
| Blocked or retained-quarantined | 27 |
| Bypassed | 0 |
| Indeterminate attack observations | 0 |
| Benign controls | 28 |
| Benign false positives | 0 |
| Signed native case receipts | 55/55 |
| Signed terminal campaign outcomes | 4/4 |
| Mean case latency | 7.9 ms |

The full private evidence artifact is bound by SHA-256:

```text
e18251c6ae0c0e205238a4011f27e8fcf56dac97958e4bfc1186cb972f392d20
```

The four public campaign commitments are:

```text
15e28bc0cc38251b774789a7cea2aa255ad214ac5c522b938a9fb85578bdba67
1d6fa3b03a272fcb00dd3425a0d26376538a7f045bdb448fc6d5f653591f9bbc
c4a0fc36ae47ba5e9b8992f5524df66ce6c94fffad0a2b27c887ebf9c83a28e7
d0ef03b176121568c8547895bad0390d4fa2888edcaaf3243f43e5a6eca77393
```

The canonical ceremony source SHA-256 was:

```text
fb221831c76c225e387dcc7611887e54fee690fca7da02a0a5c95d2ebd9e553c
```

## Reproduction

After completing Genesis and enrolling an authorized audit agent, run the
native ceremony against the local AIMOS service:

```sh
node scripts/ceremony/run-saber-sbr-live-proof.mjs --live
```

The command creates new signed local evidence. Reproduction verifies behavior;
it does not recreate the original operator's signatures or event identifiers.

The focused evidence contract is exercised by:

```sh
node --test tests/security/red-team-sbr2-evidence-contract.test.mjs
```

## Interpretation boundary

This result proves conformance for the declared fixed vectors and native route
under the stated run. It is not a scalar security score, DARPA SABER
equivalence, ARTE, universal attack prevention, certified robustness, or an
independent penetration test. SABER evaluation has no authority over save,
recall, ranking, quarantine, mutation, or disclosure.

