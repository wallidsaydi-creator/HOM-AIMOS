# CR7 R8 file-write successor — 2026-10-06

## Scope and result

The file-tool hardening replaced two legacy lexical write sites with four
durable sites: temporary-file write, atomic rename, failed-write cleanup, and
boot orphan cleanup. The frozen CR7 R0–R7 verifiers were left unchanged. Their
103-site local baseline remains historical; the current whole-tree scanner
finds 105 sites, exactly `103 − 2 + 4`. The other 101 effect IDs, classes,
ownership statuses, and source anchors retain their frozen commitment.

The R8 successor verifies the complete current census and source ordering. Its
isolated tests pass, but **release closure remains false** until a signed
native write and process-restart recovery are exercised against a disposable
installation and the full source gate passes on a qualified host.

## Safety conditions

Let `A` be a verified `write_file` tool action, `M` a signed material-effect
start, `F` one filesystem mutation, and `T` its terminal. The required order is
`A ≺ M ≺ F ≺ T`. A terminal that cannot be written leaves a detectable open
start; no success is inferred. Recovery may remove a temporary file only when
its action ID and reconstructed target match a separately reread, verified
Housekeeper start. Recovery never repeats the requested file write.

The effecting writer is private to `purpose-authorization.js`. Its exported
native owner re-verifies the signed action, exact actor and certificate epoch,
company, and request receipt before appending the material start. The target
parent must already exist, be owned by the process or root, and have no
group/world write bit or symlink component. This removes directory creation
and its unprovable crash residue from the runtime effect set. The owner writes
a mode-0600 no-follow temporary inode named with the signed action ID, fsyncs
the inode, renames it, and fsyncs the parent directory. Existing hard links
are replaced with a new inode rather than modified in place.

During pre-listen CR7 recovery, the fixed native roots are scanned only for
the temporary-file name shape. Before unlink, the owner rereads the signed
start by event ID and checks its mutation hash, action ID, signer, company,
operation, and target hash. The cleanup itself receives a signed material
start and terminal. A failed cleanup terminal remains open for the ordinary
CR7 indeterminate reconciliation. The factory used by isolated tests does
not appear in a route; the production export fixes roots, event verification,
and material owner to native implementations.

## Historical source fixture

The source runner executes original R0–R7 and CR8 tests from the already
public Git commit `678af3c8766b200f9d61d44f153f0198bf147edc`. The
sanitized archive is [cr7-r7-public-main-678af3c.tar.gz](../../scripts/verification/fixtures/cr7-r7-public-main-678af3c.tar.gz),
SHA-256 `5a878f566a00226c17722012c9092c3417889bd651bb33366427c294747f3890`.
It was made with:

```sh
git archive --format=tar.gz --output=cr7-r7-public-main-678af3c.tar.gz 678af3c8766b200f9d61d44f153f0198bf147edc -- . ':(exclude)verifiers/mutmem-conformance/v2/p3-clean-installer-qualification.json'
```

The excluded qualification JSON was unrelated to R0–R7 and contained retained
key fingerprints that a secret scanner identified as generic API keys. The
original historical test suite still passes 40/40 without it. The runner
checks the archive hash and member paths before extraction to a
private temporary directory, executes the original 40 historical assertions,
and checks R7 and CR8 proof roots. The current source suite separately runs
R8 and the current CR8 scheduler successor. The archived public branch had a
104-site census; R8's 103-site local baseline is a different, retained
pre-change state. The R8 proof checks its 101 surviving effect commitments
directly, so the public fixture is not presented as the 103-site snapshot.

## Evidence and open release gates

- R8/purpose focused tests: 12/12 passed, including forged and mismatched
  orphan traces, crash before and after rename, and failed cleanup terminal.
- Historical public R0–R7/CR8 fixture: 40/40 passed and both proof roots matched.
- Current CR8 scheduler successor: 4/4 passed.
- Release cleanup source contract: 17/17 passed after moving the export-root
  assertion to the native owner.
- `npm run lint` and `git diff --check` passed after the native changes.
- `npm run test:source` remains red in the restricted host: local TCP listeners,
  PostgreSQL connections, and Keychain access receive `EPERM`. This is an
  incomplete host qualification, not a green release result.
- A real signed write, forced process death with a retained temporary file,
  restart cleanup, and second-pass no-op have not run against a disposable
  PostgreSQL/identity installation. The successor proof records those facts
  as unexecuted and `release_closed: false`.

The same macOS user can still race or directly access its own files outside
the AIMOS process. A market deployment requiring local hostile-process
resistance needs an OS user/container boundary in addition to these native
checks.
