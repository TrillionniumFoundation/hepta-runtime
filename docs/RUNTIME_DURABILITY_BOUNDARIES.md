# Runtime execution durability and recovery boundaries

This document describes the x230 A18/A19 improvements and the A20 terminal
publication protocol in [jobs.rs](../src/mcp/runtime/jobs.rs),
[ssh_observation_pool.rs](../src/mcp/runtime/ssh_observation_pool.rs), and their
sibling tests.
Qualification and measured performance belong in the dated x230 evidence files;
the design alone is not proof of a physical power-loss test.

The execution persistence sequence below concerns the embedded operator helper
and its supervisor. The separately administered isolated `system_jobctl` backend
does not use this staging/runner code and is not qualified by these tests.

## Execution identity is the recovery anchor

A request is bound to a host, one job ID, the full SHA256 of its canonical
serialized request, and a launch nonce. The historical short fingerprint remains
metadata, not the authority for comparing a new idempotent request. Recovery
queries the original host and ID. It must not convert an unavailable observation
or an ambiguous launch into a new launch under a different key.

The controller and target supervisor have different lifetimes. An acknowledged
operator job runs under the target's supervisor, with its own job directory and
owner binding. Restarting a controller therefore restores observation and
same-key lookup; it does not require replaying the workload. This is not a
distributed consensus protocol or a guarantee of exactly-once external business
effects.

## Persistence order

| Boundary | Evidence and required order | Failure interpretation and recovery |
| --- | --- | --- |
| Input staging | Exclusive `stdin.bin` creation, exact mode, file flush/fsync, then pinned job-directory fsync | A partial artifact is retained. Without a bound request, its presence prevents another launch. |
| Request binding | New `request.json` with original identity, nonce, stdin path and integer `terminal_publication_protocol=1`; file and directory synchronization | A later attempt must inspect this same binding. An incomplete or uncertain launch is not automatically replayed. Existing requests are not rewritten to add the protocol. |
| Supervisor staging | Exclusive `runner.py` archive creation and file/directory synchronization before launcher submission | Failure leaves the original request and staging tombstone; neither systemd nor detached launch is submitted. The current launcher passes supervisor code inline, so this archive is not its executable-loading dependency. |
| Supervisor ownership | Lifetime lock, exclusive `owner-intent.json` and `started.json`, synchronized owner identity | An interrupted owner publication still prevents another supervisor from replaying the workload. |
| Child spawn | `Popen` creates the workload; `child.json` records the child identity | This crosses the effect boundary. A failure to publish the child receipt cannot truthfully be reported as an error before launch. |
| Output completion | Drain stdout/stderr, preserve seen/stored counts, join drainers, flush/fsync each completed log once | Incomplete drain, truncation, write failure or sync failure must not claim durable successful output. |
| Terminal publication | Exact `exit.json` bytes include the protocol, original job ID and launch nonce; temporary-file fsync, rename, then pinned job-directory fsync | The file can become visible before the directory barrier returns. Visibility alone does not confirm a new-protocol terminal state. |
| Terminal witness | Only after the preceding exit barriers return successfully, publish `exit.witness.json` with the protocol, job ID, nonce and full SHA256 of those exact exit bytes | A matching visible witness permits terminal confirmation. Missing, invalid or mismatched evidence remains unconfirmed and never authorizes replay. |

These barriers protect ordering at the operating-system/filesystem interface.
They do not prove a storage device honored flushes, that a remote replica exists,
or that a workload's external side effects are transactional. Output while a job
is still running is not fsynced on every chunk; the log synchronization result is
recorded when the supervisor publishes its terminal receipt.

## A20 terminal publication witness

A18/A19 could expose a successful `exit.json` after rename even when the following
directory fsync failed. A20 closes that status-confirmation gap for marked
requests and receipts: the supervisor cannot begin publishing the witness until
the exit file fsync, rename and job-directory fsync have all returned
successfully. All three supervisor terminal paths use this sequence, including
a workload spawn error and an error publishing the child receipt after spawn.

New `START_CODE` requests carry integer `terminal_publication_protocol=1`, and
the new runner adds the same field to its exit receipt. If either the request or
the exit contains the protocol field, STATUS requires the supported integer
value and a matching witness; booleans, null and unknown versions do not pass as
version 1. A marked request with an unmarked exit cannot fall back to the legacy
interpretation. The witness must bind the original request's job ID and 32-digit
hexadecimal launch nonce, and its `exit_sha256` must match the complete raw exit
bytes. Parsing and hashing use the same snapshot, not a reserialized JSON value.

Terminal files are read relative to the already pinned job-directory descriptor.
The reader rejects symlinks, nonregular files, multiple hard links, incorrect
ownership or permissions, excessive length, and changes in the descriptor/path
stamps during reading. The limits are 1 MiB for the exit and 4 KiB for the
witness. STATUS performs no repairs or writes. It imports SHA256 support only
after the legacy terminal path has been excluded.

A missing, corrupt, unsafe or mismatched witness produces `finalizing` with
`terminal_publication_confirmed=false`, `status_authoritative=false` and
`automatic_retry=false`. The wait loop preserves that unconfirmed state even
when its wait deadline is zero; it does not turn it into a terminal result. If a
marked request has no exit yet and its bound supervisor is still running,
STATUS continues to report `running`. Otherwise, systemd exit codes or a
disappeared supervisor cannot substitute for a new-protocol confirmed receipt.
An unavailable owner binding retains its separate nonauthoritative
`owner_unknown` result. Same-key operator lookup observes the original job
without resubmitting it. Orphan witness files, including their temporary files,
are refusal evidence for both staging and supervisor ownership admission.

The witness itself is published with temporary-file fsync, rename and directory
fsync. Its visibility proves that the **preceding exit publication barriers**
completed; it does not prove that the witness's own last directory fsync
completed or that the witness will survive power loss. Consequently, a readable
matching witness can confirm the exit even if the later witness-directory fsync
fails. If the witness is subsequently lost, STATUS conservatively returns an
unconfirmed result. Neither case permits a replacement workload.

When both request and exit lack the protocol field, existing terminal-state
semantics remain available for valid legacy receipts. Legacy systemd observation
also retains its previous fallback behavior. A20 does not rewrite old jobs or
retroactively establish a publication barrier for their receipts. The observer
adds `terminal_publication_confirmed=true` after validating a new witness.

## Honest terminal states

`output_complete` describes successful capture. `output_durable` additionally
requires both log synchronization results in `log_synced`. A log synchronization
error also conservatively sets `output_complete=false`; `log_errors` and
`log_synced` retain the reason. `terminal_publication_confirmed` describes the
separate exit-publication proof, not the workload's effects or the success of
output capture. Existing receipts without the additive fields remain readable;
their age must not be mistaken for new evidence that their logs were synchronized.

If a workload exits zero without a cancellation or timeout, but output
synchronization fails, its real child exit code remains zero in the receipt.
When publication of that receipt and its witness succeeds, `process_status`
reports `failed` and the supervisor exits with 74. If a publication failure
prevents a matching witness from becoming visible, the terminal state remains
unconfirmed. The child exit code is not rewritten to hide the output failure.

If child creation succeeded but `child.json` publication fails, the supervisor
signals only its still-owned, unreaped child process group, then attempts a
bounded reap. Its receipt records the group-signal result, whether the child was
reaped, and the observed child exit code when available. A confirmed failure
receipt reports `effect_unknown`, with `automatic_retry=false` and
`status_authoritative=false`; validating the witness does not raise its effect
authority. Terminating the child cannot undo effects it may already have
performed. If the failure receipt or its witness cannot be published, the
remaining owner/request artifacts still do not authorize replay.

## Bounded multi-host observation

The opted-in SSH observation transport has an eight-entry channel, eight global
session/output permits, two sessions per host, and at most eight masters. A
permit remains charged while a completed captured response awaits parsing by
its original caller. A18 reserves that budget before dequeuing, so saturation
waits in the bounded channel rather than prematurely rejecting an already
dequeued request. Cancellation, deadline expiry, closed replies and shutdown
remain explicit paths.

Pinned profile/configuration/credential files are revalidated across admission,
lease and response authority boundaries. Revalidation SHA256 now streams through
one 16 KiB buffer using the already-present ring implementation; initial loading
still reads the bounded file contents. No hash cache or partial-file sampling is
introduced. File identity, permissions, ownership, link count, capability
attributes and before/after stamps remain checked.

On Linux, OpenSSH first binds a temporary ControlPath with a 17-byte suffix.
A19 caps the final path at 90 bytes, reserving that suffix and the terminating
NUL within the 108-byte address field. It checks the shortest initial path
before making a private directory, and checks complete sequence-specific paths
before initial creation and renewal.

Current global admission precedes the per-host permit. A sufficiently skewed
queue can therefore spend global capacity waiting on one host. The balanced
six-host benchmark does not prove fairness under that load. A future fair
scheduler should select eligible hosts from one bounded pending budget, retain
the captured-output budget through parsing, expire/cancel pending requests
without launching them, and preserve all master-generation ownership rules.
Increasing channel or session limits alone would not establish that property.

## Recovery validation and its limits

The x230 validation procedure uses fresh private controller/target state and an
existing authorized forwarded agent. No production runtime service is replaced
or restarted. The following checks describe the procedure; their actual results
must be read from the dated evidence files.

- Six-host observation compares the same six original completed job records,
  complete output hashes and exact status counts through normal controller
  restart. A separate abrupt-death check kills only its directly owned
  controller and reads the same originals again. It records surviving observed
  children and residual socket artifacts separately from data recovery.
- The running-job canary creates one private x230 workload with 4 KiB stdin.
  The workload writes an execution marker, emits `BEGIN`, and waits for a
  private release marker. The test kills only its own controller, restarts it
  with the same state, and requires the original job still to be running and
  the same key to reuse the same ID without a new launch. Only then is the
  release marker published. Completion must have exact stdout/stderr bytes,
  complete output synchronization receipts, unchanged stdin and one execution
  marker. The A20 canary additionally requires terminal publication confirmation
  and reads the private request, exit and witness files to verify strict protocol
  types, their shared original identity, the exact exit-byte digest and agreement
  between the status response and every exit field.
- Fault-injection tests execute the real staging/runner code around controlled
  failure points. The systemd and detached staging branches are exercised in
  the Linux fixture; this is not a physical macOS power-loss experiment.

The A20 regression module,
[jobs_terminal_publication_tests.rs](../src/mcp/runtime/jobs_terminal_publication_tests.rs),
contains four Rust tests with 27 STATUS cases, five staging/ownership cases and
five full-runner variants. The runner variants exercise normal publication,
exit-directory fsync failure after the exit is visible, witness write failure,
witness-file fsync failure, and witness-directory fsync failure. They check the
actual ordering and distinguish an unconfirmed exit from a confirmed exit whose
later witness-directory sync failed. Observer fixtures also verify that the
original files remain unchanged.

The dated [A20 x230 qualification](evidence/x230-a20-qualification-20261023.json)
passed formatting, clippy, the all-feature test suite and the release build:
1,088 runtime tests, 18 ownerctl tests and eight jobctl tests passed, with 21
existing ignored tests. This includes the 27 STATUS cases, five staging/ownership
cases and five full-runner variants on x230. The tested source-map SHA256 is
`ad734d2154e5e329467ba3d4c0f48d415ae3c4594a490a7aa1c7721ae780d8bc`;
the release binary SHA256 is
`727c4661450fdb2a2a44b63f7f9442a5cd20ad854f1c26b043ac710b6fa2ea06`.
The source remained unchanged during qualification.

The [A20 running-job canary](evidence/x230-a20-lifecycle-20261023.json) observed
the original job running before and after SIGKILL of its owned controller, then
reused the same key and original ID without relaunch. The private release gate
was opened only after those checks. The job completed with one execution marker,
matching complete stdout/stderr, synchronized output and a validated publication
witness. The [A17/A20 observation ABBA](evidence/x230-a20-observation-20261023.json)
passed all 1,152 measured calls, 24 initial full-output checks and 48 checks of
the same jobs after normal controller restart. Its seven recorded resource
sampling errors remain in the evidence; they are separate from RPC results.

The separate [A20 completed-job abrupt-death check](evidence/x230-a20-recovery-20261023.json)
passed all 24 observations of the six original completed jobs across controller
death and restart, with zero new job starts, remote mutation calls or automatic
RPC retries. All 14 sampled descendant process generations exited. One private
directory containing six stale sockets remained after both death and recovery,
and the check preserved those artifacts. Thus read-only recovery passed while
`abrupt_cleanup_complete=false`; the restarted controller's normal shutdown
passed separately. Sampled process exit is not exhaustive process containment
proof, and data recovery does not establish complete abrupt-death cleanup.

Controller SIGKILL tests do not demonstrate target reboot recovery, power-loss
recovery, WAN partition behavior, production ownership transfer, or transactional
exactly-once effects. Missing authority or ambiguous effects require inspection
of the original identity and evidence. They do not authorize an automatic
replacement job.
