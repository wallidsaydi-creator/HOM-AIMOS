# CR7 R8 file-write successor — 2026-10-06

## Scope and result

The file-tool hardening replaced two legacy lexical write sites with four
durable sites: temporary-file write, atomic rename, failed-write cleanup, and
boot orphan cleanup. The frozen CR7 R0–R7 verifiers were left unchanged. Their
103-site local baseline remains historical; the current whole-tree scanner
finds 105 sites across 367 runtime source files, exactly `103 − 2 + 4`. The other 101 effect IDs, classes,
ownership statuses, and source anchors retain their frozen commitment.

The R8 successor verifies the complete current census and source ordering. Its
17 focused tests pass. Master-signed native writes, forced completed-write
restarts, and an OS-caught pre-rename crash with signed orphan cleanup passed
in a disposable installation. The public candidate's full source gate passed
1,218 tests with zero failures and one skip. **Release closure remains false**
because an OS-timed post-rename/pre-terminal crash has not been observed; the
independent red-team rerun is also outstanding.

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

During pre-listen CR7 recovery, new writes use their signed exact target path
to inspect one deterministic temporary-file name. Historical starts without
that locator scan the fixed native roots conservatively. Before unlink, the
owner rereads the signed start by event ID and checks its mutation hash,
action ID, signer, company, operation, and target hash. The cleanup itself
receives a signed material start and terminal. A failed cleanup terminal
remains open for the ordinary CR7 indeterminate reconciliation. The factory
used by isolated tests does not appear in a route; the production export fixes roots, event verification,
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
- The published draft candidate passed its full source suite on a qualified
  local run. The later unpushed file-read admission adds one runtime source
  file but no durable effect site; its updated complete source suite remains
  to be rerun locally. This does not close the signed write gate.
- Isolated `secqual` qualification used AIMOS port 9203 and PostgreSQL port
  55442/database `aimos_secqual`; the live 9100/5432 service was not used. A
  Housekeeper-signed `POST /aimos/recall` for the scoped R8 scratch-write
  purpose returned HTTP 200, two memories, and a recall receipt. No recall
  content or signing material was printed.
- A direct native Housekeeper `executeTool('write_file')` attempt targeting a
  unique, initially absent hidden file beneath the existing owner-only
  `~/Documents` directory returned `blocked: true` with
  `KNOWLEDGE_ACQUISITION_REQUIRED`. The target remained absent. The signed
  HTTP recall did not create knowledge evidence inside that native tool run;
  its receipt was not transplanted into the run or treated as write approval.
  The consequential action also requires master-signed operator approval,
  for which no fixture was available. No authority was inferred or bypassed.
- In the earlier `secqual` attempt no authorized signed native write was
  committed. The subsequent `fileproofqualb` run below supersedes that part
  of the evidence; the pre-rename orphan recovery gate remains open.

## Executed isolated approval ceremony

The `fileproofqualb` installation is a fresh, separate AIMOS instance with
PostgreSQL `55444`, database `aimos_fileproofqualb`, HTTP `9204`, and a
master-signed `fileproof_operator` certificate and clearance-10 memory grant.
Its server and PostgreSQL were stopped after qualification. The test-only
passphrase was entered only into TTY prompts and was not written to this
document or a file.

The existing production approval path was exercised without constructing a
fake execution context or a fake knowledge record:

1. Run `scripts/verification/request-r8-scratch-write.mjs` with the four
   `fileproofqualb` CLI selectors. It signed `POST /tools/approvals/request` as
   `fileproof_operator`, selecting a unique absent target beneath the
   existing owner-only `~/Documents` directory. The request contains a
   harmless fixed marker. It returned `202`, pending approval
   `4ca07213-1fb0-4464-a7f1-54cd592f37d0`, and the target was absent. This
   test-only requester did not approve or execute the write.
2. Run the existing production
   `scripts/identity/authorize-tool-action.js <approval_id>` with the same
   instance selectors in a TTY. The operator entered the test-only master
   passphrase. The CLI verified the pending exact action, decrypted the
   enrolled master key, signs the action projection, and sends the agent's
   signed `POST /tools/approvals/:id/approve` request. The route verifies the
   master proof, reserves the single execution, and calls `executeTool` with
   `approvalEvidence`. This is the native contract's explicit operator
   step-up branch; no knowledge state is fabricated or transplanted from a
   separate run. `executeTool` independently derives the exact-epoch
   clearance grant from the signed request before its level-5 write gate. It
   returned `OPERATOR_ACTION_AUTHORIZED_AND_EXECUTED` and the native write
   result reported SHA-256
   `54d4cb274c9ba2abb359e667cbe3c579e80347737f5fb04632a621fff71c312e`.
3. Independent verified-history inspection found approval status `executed`,
   exactly one completed `local_file_write` material action
   `dbe949ed-d656-4c7f-9e6b-9a728c722a15`, its `SUCCEEDED` terminal, and
   zero open material actions. The target was a regular non-symlink inode
   `931127597` on device `16777234`, one link, mode `0600`, 60 bytes, with
   the exact SHA-256 above. A missing or indeterminate terminal would not be
   success.
4. The scratch server was force-stopped with `SIGKILL` and restarted twice.
   Each boot reached integrity `19/19` and reported `material_effect=0` in
   CR7 action recovery. After each restart, independent history and filesystem
   checks still found the same single material action, inode, mode, and hash.
   The second pass was a no-op with no filesystem replay.

The first two commands, run only while the isolated service is deliberately
online, are:

```sh
node scripts/verification/request-r8-scratch-write.mjs \
  --aimos-instance=fileproofqualb --aimos-postgres-port=55444 \
  --aimos-port=9204 --aimos-db=aimos_fileproofqualb

node scripts/identity/authorize-tool-action.js <approval_id> \
  --aimos-instance=fileproofqualb --aimos-postgres-port=55444 \
  --aimos-port=9204 --aimos-db=aimos_fileproofqualb
```

The first command prints the pending approval ID, target, arguments hash,
and marker hash. The second requires a TTY and prints the approved action's
result. Both commands were run once against the disposable scratch instance.

The later bounded OS timing run below captured and recovered an actual
pre-rename orphan. New starts now carry an exact signed recovery locator for
the no-temp/unsafe-directory edge; the separate live post-rename crash
observation is still open, so `release_closed: false` remains conservative.

### Bounded OS timing attempt — missed, 2026-10-06

An external scratch-only `fs.watch` observer validated the exact HTTP `9204`
server PID, unique Documents target, and expected temporary name. It would
`SIGSTOP` that PID on a temp-file event, require the final target to be absent,
independently reread the signed `material_effect_started` event and target
hash, and only then `SIGKILL`. It never treated a filename alone as authority.

The three-attempt budget produced no verified pre-rename state:

1. A 700,000-byte harmless marker was rejected at pending-request creation
   with `event_metadata_too_large`; the approval owner retains exact arguments
   twice and the event limit is 1 MiB. No approval or file effect occurred.
2. A 400,000-byte master-approved write completed normally. A 45-second
   watcher reported `MISSED_WINDOW`, `observed_candidates: 0`. It sent no
   `SIGKILL`.
3. A second 400,000-byte master-approved write completed normally. The
   improved 120-second watcher observed one exact temporary-name event, but
   the temporary inode was gone by inspection. It resumed the scratch server
   and reported `MISSED_WINDOW`, `observed_candidates: 1`. It sent no
   `SIGKILL`.

No fourth attempt was made in that first budget. A separately authorized
follow-up used the same production approval ceremony and the scratch-only OS
timing observer described next.

### Captured pre-rename crash and verified recovery

The second bounded method polled `~/Documents` for at most three seconds after
the signed `tool_approval_execution_claimed` event, with only the isolated
HTTP server at nice `+10`. The observer required the exact server PID and
`9204` listener, approval ID, unique target, signed material start, target
hash, and regular owner-only temp inode before stopping and killing that PID.
It added no production hook. The first new approval was
`635d53fd-0a9b-43eb-998e-515f19cfc2f0`; the observer returned
`CAUGHT_PRE_RENAME` for material action
`443f1be6-471b-4c7d-94cc-501041a298e5` and signed start event
`0b8a4af6-562b-4a70-9be0-aa62b16fbee7`. The exact temp held 400,000
bytes, mode `0600`, one link; the final target was absent. The signed approval
CLI saw `fetch failed` because the scratch server was deliberately killed.

The first recovery pass signed one successful `local_file_orphan_cleanup`
action `ed805263-ce54-4896-a368-1507edf3d645` and removed the temp. A
subsequent recovery invocation encountered an unrelated unsafe nested
directory because the original write start was still open. The reconciler
now recognizes a prior completed cleanup through its exact signed input
projection, verifying both cleanup events and terminal result before scanning
the filesystem. On restart, scratch boot reported
`material_effect=1 tool_action=1`, checkpointed recovery, reached
`ready:true`, and passed integrity `19/19`. Independent verified-ledger
inspection found the original write terminal `INDETERMINATE`, the cleanup
terminal `SUCCEEDED`, zero open material actions, and both exact temp and
final target absent. A second restart reported `material_effect=0
tool_action=0`, reached `ready:true`, and passed integrity `19/19`; no write
or cleanup replay occurred. The independent check is in
`/private/tmp/aimos-r8-fileproofqualb-caught-verify.mjs` and prints IDs and
dispositions only.

A distinct edge arose when an open write had no temp and no signed cleanup
terminal: the original start retained a target hash but no pathname. New
`local_file_write` starts now include a canonical absolute
`recovery_target_path` inside the Housekeeper-signed, RLS-bound material event.
The owner checks that the path hashes to the committed target and was already
admitted under an allowed root before signing. Recovery re-verifies the start
and checks only that exact parent and deterministic temp name. An unrelated
unsafe directory no longer blocks recovery of a new write; an unsafe or
symlinked exact parent, symlink temp, duplicate temp name, or path/hash
mismatch fails closed. Historical starts without the locator retain the broad
conservative scan and may still fail closed on an unrelated unsafe directory.
The pathname is visible to principals that can read the signed event ledger;
no file content or credential is added to material metadata.

One additional master-signed scratch approval exercised the new production
write path: approval `8b667d40-1602-4c4a-bdf9-2f1efa2df93f` executed once;
material action `a7828449-e586-4dd4-9877-bb9021bdb682` has a verified
`SUCCEEDED` terminal and signed exact recovery locator. Independent inspection
found a regular one-link mode-`0600` 60-byte target, inode `931142599`, SHA-256
`54d4cb274c9ba2abb359e667cbe3c579e80347737f5fb04632a621fff71c312e`,
and zero open material actions. A clean restart reported
`material_effect=0 tool_action=0`, boot integrity `19/19`, and the same inode
and hash. The focused R8 tests passed `17/17`; the CR7 successor scanner kept
the frozen 101 surviving historical effects and 105 current sites. This is a
signed locator round trip and no-replay proof, not an OS-timed post-rename
crash observation. `release_closed: false` remains truthful for that remaining
live observation and the legacy-start availability limit.

An additional bounded OS-timed post-rename observation was started after the
full source gate. The delegated attempt was halted by a cybersecurity access
gate before it produced a verified crash state. Its isolated HTTP `9204` and
PostgreSQL `55444` processes were then stopped by exact PID and data-directory
checks; both ports were confirmed unbound. Canonical HTTP `9100` remained
`200` with `ready:true` on PostgreSQL `55432`. The unobserved case stays open;
the isolated after-rename recovery tests are evidence for code behavior, not
an interrupted-process observation.

The same macOS user can still race or directly access its own files outside
the AIMOS process. A market deployment requiring local hostile-process
resistance needs an OS user/container boundary in addition to these native
checks.
