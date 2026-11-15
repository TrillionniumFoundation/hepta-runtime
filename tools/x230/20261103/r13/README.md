# X230 R13 measurement preparation

Copyright 2026 TrillionniumFoundation. SPDX-License-Identifier: Apache-2.0.

These files are measurement preparation only. Creating fixtures and checking
Python syntax do not execute the Rust benchmark, cancellation campaign, native
observation campaign or recovery canary. The R13 source tree is unchanged.

## Local projection comparison

run_operation_projection_abba.py uses one independently qualified R13 library
test binary, with the exact ignored benchmark named in its TEST constant.
Provide the preserved libtest path and its qualification-bound SHA256 explicitly.
The owned arm calls the original full-record loader inside that same binary.
It is an algorithm comparison, not an R11/R12 release-vs-release comparison.

The prepared plain and escaped receipts are each 4,194,272 encoded bytes,
0700 directories, 0600 single-link files, and carry no valid remote destination.
The escaped payload is repeated JSON newline escapes, not the earlier cancel
fixture. Both routes have identical small public fields. The manifest freezes
byte hashes, lengths and file identity. Each measured child verifies the
fixture hash and routing equality; the driver verifies files and executables
before and after each sample.

The fixed campaign is plain/escaped x pins 8/32 x ABBA, for 16 fresh Rust
processes. With two rounds this contains 640 guarded reads. The largest owned
retained payload is below 128 MiB. Processes run serially. GNU time directly
parents each Rust child; Python's inherited getrusage high-water floor is not
used as the RSS metric. Current cohort VmRSS is retained separately. The
observed child peak must remain below 300 MiB; this is a post-run budget check,
not an OS cap or a claim about the complete process tree.

The benchmark itself pre-reads one owned receipt before timing, so both
baseline RSS and whole-process peak include that preconditioning. No clean
allocator, cold-disk or single-request incremental-memory claim is supported.

analyze_operation_projection.py reads the original stdout, stderr and GNU time
receipts and checks their SHA256 against the campaign, independently recomputes
CPU/rate, and checks all sixteen positions and both arm identities. CPU and
rate are pooled within each two-process arm; RSS values are medians with the
individual native peaks retained. Failed or incomplete campaigns are refused.

See commands.json for the exact argv arrays. Replace only the qualified
libtest path/SHA placeholders after qualification. qualification-03 is the
planned R13 release artifact directory; verify it against the completed report
before running any command. Output directories must be new.

## Release cancellation comparisons

Reuse the existing R12 run_cancel_responsiveness.py unchanged. commands.json
contains separate R12-to-R13 and R11-to-R13 campaigns, both with workers 1/2,
receipt sizes 1,024 and 4,194,272, escaped payload, concurrency 8 and 24 waves.
These are wrong-host refusal/responsiveness tests, not remote cancel throughput.
Keep each report, its negative cases and raw VmHWM. Do not pool the two baselines.

## Six-host execution entry

The exact retained template and six-record directory are in launcher-inputs.json.
The template is only an input: the existing driver derives a fresh profile
bound to the current forwarded agent and never reuses the old socket identity.

Use the configured main host and a foreground ssh -A -T connection to x230-ts
with BatchMode=yes and ConnectTimeout=10. Keep that SSH process alive until the
remote campaign ends; do not detach the remote Python child. The read-only
preflight observed a connectable main agent; x230-ts defaults ForwardAgent=no,
so explicit -A is necessary. No credential or agent key material is written here.

Create each named private socket-parent directory at 0700 before its campaign.
Do not reuse one between independently reported campaigns. The existing recovery
driver restricts output to a new direct child of the R12 root, so its proposed
R13-named output remains under that root. No driver policy is patched.

The native observation command is read-only and uses the six original completed
jobs. The recovery command creates six private bounded jobs and interrupts only
its proved private ROG SSH master and owned controller. These commands are
prepared but have not been executed as part of this preparation task.


## Qualification-03 orchestration

The retained qualification launch source is `qualification-launch-03.py`.
Its candidate output is `qualification-03`. This preparation bundle makes no
qualification or benchmark completion claim.

`run_local_campaigns_v2.py` waits for that qualification, binds the complete
compiler-input map and recorded binary hashes, and writes `local-campaigns-02`.
It runs the projection comparison and the two independent cancellation
comparisons serially.

`run_remote_campaigns_v2.py --wait-seconds 3600` waits for the successful local
report, checks that both runners bind the same qualification report hash, and
writes `remote-campaigns-02`. Launch it through the held foreground `ssh -A`
connection described above. The runner creates its fresh private socket-parent
directories. The exact runner argv arrays are in `commands.json`.

The v1 runner files preserve the earlier qualification-02 attempt. Its failed
gate stopped before any campaign; the v2 runners retain the previously unused
campaign output names. The original measurement tools and old publication
staging remain unchanged.
