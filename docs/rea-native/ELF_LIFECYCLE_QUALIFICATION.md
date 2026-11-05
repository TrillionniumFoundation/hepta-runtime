# ELF notes lifecycle qualification

`scripts/rea_lifecycle_qualification.py` runs the frozen original npm REA MCP and
the selected native MCP binary as new, owned Linux sessions. It records original
requests, responses, cancellation notifications, process identities, file
descriptors, pidfds, retained Evidence and EOF observations. The independent
consumer is `scripts/rea_lifecycle_evidence.py`.

This is the finite profile
`rea-agents-6.8.0/inspect_elf_notes/linux-owned-lifecycle/v1`. It does not mark the
entire `inspect_elf_notes` operation, the other 228 tools, a provider installation,
or another platform qualified. In particular, the original `ElfNotesProvider`
reads and parses within Node. There is no separate original parser process on
which this profile can inject the native worker deadline. That combined deadline
gate remains OPEN even when the native deadline observation passes.

## What the profile observes

| Scenario | Original REA | Native MCP | Required facts |
| --- | --- | --- | --- |
| Active file capture cancellation | Actual npm MCP | Actual Rust MCP | Observe the target's device/inode through a live process FD before sending `notifications/cancelled`; then observe complete negative FD/process inventories, unchanged retained Evidence for five seconds, and a successful call in the same session. |
| Unknown and completed request cancellation | Actual npm MCP | Actual Rust MCP | Send cancellation for an unused ID and an already completed ID, then verify the same public operation and retained Evidence remain usable. |
| Isolated worker cancellation and slot recovery | No corresponding process boundary | Actual `rea-elf-notes-worker` children | Observe and stop two owned workers with pidfds, verify a third request reports the two-slot capacity boundary, cancel and observe both workers reaped; repeat with two new workers to prove both slots became available. |
| Fixed worker deadline | OPEN | Actual stopped native worker | No cancellation notification is sent. The native operation must return its 30,000 ms provider timeout, reap the stopped child, retain no cancelled/failed artifact, and accept a later call in the same session. |
| Active EOF | Actual file capture | Actual stopped worker | Close stdin only after a positive active observation; observe normal EOF, reader completion, exited owner pidfd, absent process group and no forced harness cleanup. |

The target files are independently encoded ELF images. The small baseline is
156 bytes. The active capture fixture is a 512 MiB sparse regular file, and the
worker fixture is a 32 MiB sparse regular file. They contain the same reviewed ELF
header and note, followed by zero bytes. No target is executed and no device,
network provider or user file is involved. Source/package/executable identities
are checked before and after the run. The native runtime config grants only the
new private fixture workspace and includes an unconnectable, disabled host.

An absent response to a cancellation notification is valid. The consumer accepts
an optional cancelled terminal response but rejects a successful result or an
unrelated error as proof of cancellation. If the operation completed before the
notification, or the observer missed the active phase, the trace remains OPEN.

## Ownership and observation boundaries

Each client starts in a new session. Only direct native parser children with the
selected executable, the expected `rea-elf-notes-worker` argument, the original
parent/group and the same process start time can receive `SIGSTOP`. The runner
opens a pidfd and repeats the identity check before signalling. It never freezes
the MCP controller. The controller must kill and reap its stopped children during
cancellation, deadline or EOF handling.

The observer walks the owned process tree through every observed task's Linux
`children` file. FD identity uses device/inode and a regular-file `fdinfo`
observation. Missing threads, unreadable descriptors, process races and incomplete
inventories are explicit unknowns. They cannot establish an empty descriptor or
process set. An exited worker pidfd is insufficient if its process still exists
as a zombie. Negative observations require both pidfd exit and disappearance of
the original process.

`q.Mcp.close()` retains any forced SIGTERM/SIGKILL cleanup as a failing lifecycle
fact. Harness cleanup never changes a missed native lifecycle into PASS. All
signals target sessions/children created by this run; other checkouts and running
jobs are outside its authority.

These are local functional observations under a trusted operator. Linux procfs
snapshots are not atomic across the whole process tree and are not cryptographic
execution attestation against a malicious same-UID actor. The original build
receipt is retained verbatim and the binary digest is pinned, but compilation
provenance must be validated by the separate build receipt consumer. A declared
Git commit is expressly not sufficient build proof.

## Run and replay

Use absolute paths and a new output directory. The selected binary need not be
built from the lifecycle producer's checkout; this permits truthful examination
of an older immutable binary while the next build is in progress. Keep its actual
build/source receipt and declared commit distinct from the producer source.

```sh
python3 scripts/rea_lifecycle_qualification.py \
  --repo /absolute/producer-checkout \
  --binary /absolute/immutable/hepta-runtime \
  --binary-sha256 ACTUAL_BINARY_SHA256 \
  --binary-source-commit ACTUAL_BUILD_COMMIT \
  --binary-source-receipt /absolute/original-build-source-receipt.json \
  --reference-package /absolute/install/node_modules/rea-agents \
  --reference-tarball /absolute/rea-agents-6.8.0.tgz \
  --node /usr/bin/node \
  --output-dir /absolute/new-lifecycle-evidence
```

The reviewed Node version is `v22.23.4`. The tarball and all original package files
are authenticated by the existing operation qualification package boundary. No
install or download is performed. The `--binary-source-commit` option may be
omitted when there is no exact committed build revision; do not substitute the
producer's HEAD for a different binary's revision.

The main output is `qualification.json`, with separate `assessment.json`, source
snapshots/monitor, fixture identities, runtime config, original source receipt,
six process-session traces and their raw MCP wires. The assessment always reports
`qualified: false`. A successful execution may return exit code 0 while overall
status remains OPEN. INVALID means the receipt cannot be authenticated/replayed;
FAILED means a reviewed finite observation failed. Both return nonzero.

Replay is read-only:

```sh
python3 scripts/rea_lifecycle_evidence.py \
  --repo /absolute/exact-producer-checkout \
  --receipt /absolute/new-lifecycle-evidence/qualification.json \
  --sha256 ORIGINAL_RECEIPT_SHA256
```

The integration API is
`validate_lifecycle_receipt(repo, absolute_receipt_path, expected_sha256)`. It
returns independently derived scoped gates and session results. The enclosing
operation consumer must also validate its full format/contract/retention corpus,
build provenance, the selected binary identity and any additional platform gates.
This module deliberately does not change `rea_operation_qualification.py` or
`rea_operation_evidence.py`.

## Verification

```sh
python3 -m unittest discover -s tests -p rea_lifecycle_qualification_tests.py -v
```

The stdlib suite checks real owned-process FD acquisition/drain plus deliberate
receipt errors: PID reuse, zombies, incomplete descriptor/children inventories,
wrong owner groups, duplicate wire responses, unbound process controls,
cancellation without an acknowledgement, racing cancellation, unknown state and
handwritten PASS flags that must not hide forced cleanup. Synthetic test rows are
consumer tests, not substitute provider qualification evidence.
